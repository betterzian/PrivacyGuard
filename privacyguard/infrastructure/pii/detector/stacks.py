"""新 detector 主链的属性栈与属性语义工具。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.address.event_stream_scanner import scan_address_and_organization
from privacyguard.infrastructure.pii.address.input_adapter import build_text_input
from privacyguard.infrastructure.pii.address.seed_extractor import collect_component_matches
from privacyguard.infrastructure.pii.address.span_parse import parse_results_from_spans
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, StreamEvent, StreamInput
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

_NAME_PRONOUNS = {
    "pronouns",
    "he",
    "him",
    "she",
    "her",
    "they",
    "them",
    "we",
    "us",
    "you",
    "me",
    "i",
    "myself",
}
_NAME_BLOCKLIST_ZH = {"本人", "未知", "匿名", "姓名", "名字"}
_ADDRESS_UNIT_RE = re.compile(r"(?i)\b(?:apt|apartment|suite|ste|unit|room|rm|floor|fl|#)\s*[A-Za-z0-9\-]+\b|(?:\d+[号楼栋幢座单元室层])")
_ADDRESS_SIGNAL_RE = re.compile(
    r"(?i)(\d|省|市|区|县|镇|乡|村|路|街|大道|巷|弄|号|室|单元|小区|公寓|大厦|花园|社区"
    r"|street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|lane|ln\.?|drive|dr\.?|court|ct\.?|suite|ste\.?|apt\.?|zip)"
)
_ORG_SUFFIX_RE = re.compile(
    r"(?i)(股份有限公司|有限责任公司|有限公司|研究院|实验室|公司|集团|大学|学院|银行|酒店|医院|中心|工作室|事务所"
    r"|incorporated|corporation|company|limited|inc\.?|corp\.?|co\.?|ltd\.?|llc|plc|gmbh|pte|bank|hotel|hospital|clinic|university|college|labs?)"
)
_EN_NAME_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z.'\-]{0,30}$")
_ZH_NAME_RE = re.compile(r"^[\u4e00-\u9fff·]{2,8}$")
_TRAILING_ZH_HOUSE_NUMBER_RE = re.compile(r"^\s*\d{1,6}(?:号|號)(?!\d)")
_STRUCTURED_PROMPT_PATTERNS: dict[PIIAttributeType, tuple[re.Pattern[str], ...]] = {
    PIIAttributeType.EMAIL: (
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
    ),
    PIIAttributeType.PHONE: (
        re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
        re.compile(r"(?<!\w)(?:\(\d{3}\)\s*|\d{3}[-. ]?)\d{3}[-. ]\d{4}(?!\w)"),
    ),
    PIIAttributeType.ID_NUMBER: (
        re.compile(r"(?<![\w\d])\d{17}[\dXx](?![\w\d])"),
    ),
    PIIAttributeType.PASSPORT_NUMBER: (
        re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{8}(?![A-Za-z0-9])"),
    ),
    PIIAttributeType.DRIVER_LICENSE: (
        re.compile(r"(?<![A-Za-z0-9])[A-Z0-9][A-Z0-9\-]{4,23}(?![A-Za-z0-9])"),
    ),
}
_STRUCTURED_LABEL_MAX_CHARS: dict[PIIAttributeType, int] = {
    PIIAttributeType.EMAIL: 120,
    PIIAttributeType.PHONE: 48,
    PIIAttributeType.ID_NUMBER: 40,
    PIIAttributeType.PASSPORT_NUMBER: 40,
    PIIAttributeType.DRIVER_LICENSE: 40,
}


class StackContextLike(Protocol):
    stream: StreamInput
    locale_profile: str

    def next_boundary(self, start: int, *, ignore_event_id: str | None = None) -> int: ...


@dataclass(slots=True)
class BaseAttrStack:
    event: StreamEvent
    context: StackContextLike
    stack_id: str

    def extract(self) -> list[CandidateDraft]:
        raise NotImplementedError


@dataclass(slots=True)
class StructuredValueStack(BaseAttrStack):
    def extract(self) -> list[CandidateDraft]:
        if self.event.kind.value == "label":
            value = _read_rhs_structured_value(self.context, self.event)
            if value is None:
                return []
            return [
                CandidateDraft(
                    attr_type=self.event.attr_type,
                    start=value.start,
                    end=value.end,
                    text=value.text,
                    source=self.context.stream.source,
                    confidence=_structured_confidence(self.event.attr_type, "prompt"),
                    matched_by=self.event.matched_by,
                    claim_strength=ClaimStrength.HARD,
                    metadata={
                        "matched_by": [self.event.matched_by],
                        "hard_source": ["prompt"],
                    },
                    label_event_ids={self.event.event_id},
                )
            ]
        text = str(self.event.payload.get("text") or self.context.stream.raw_text[self.event.start : self.event.end]).strip()
        if not text:
            return []
        metadata = _copy_metadata(self.event.payload.get("metadata"))
        metadata["matched_by"] = [self.event.matched_by]
        return [
            CandidateDraft(
                attr_type=self.event.attr_type,
                start=self.event.start,
                end=self.event.end,
                text=text,
                source=self.context.stream.source,
                confidence=float(self.event.payload.get("confidence") or _structured_confidence(self.event.attr_type, self.event.matched_by)),
                matched_by=self.event.matched_by,
                claim_strength=ClaimStrength.HARD,
                metadata=metadata,
            )
        ]


@dataclass(slots=True)
class AddressStack(BaseAttrStack):
    def extract(self) -> list[CandidateDraft]:
        trigger_kind = str(self.event.payload.get("trigger_kind") or "")
        if self.event.kind.value == "label" or trigger_kind == "label":
            bounds = _address_label_segment_bounds(self.context, self.event, max_chars=180)
            if bounds is None:
                return []
            return _build_address_drafts_with_legacy_flow(
                source=self.context.stream.source,
                raw_text=self.context.stream.raw_text,
                segment_start=bounds[0],
                segment_end=bounds[1],
                locale_profile=self.context.locale_profile,
                matched_by=self.event.matched_by,
                label_event_id=self.event.event_id,
                anchor_start=self.event.start,
                anchor_end=self.event.end,
            )
        bounds = _address_component_segment_bounds(self.context, self.event)
        if bounds is None:
            return []
        return _build_address_drafts_with_legacy_flow(
            source=self.context.stream.source,
            raw_text=self.context.stream.raw_text,
            segment_start=bounds[0],
            segment_end=bounds[1],
            locale_profile=self.context.locale_profile,
            matched_by=self.event.matched_by,
            anchor_start=self.event.start,
            anchor_end=self.event.end,
            component_type=str(self.event.payload.get("component_type") or ""),
            trigger_kind=trigger_kind or "component_name",
        )


@dataclass(slots=True)
class OrganizationStack(BaseAttrStack):
    def extract(self) -> list[CandidateDraft]:
        if self.event.kind.value == "label":
            value = _read_rhs_value(self.context, self.event, max_chars=96)
            if value is None:
                return []
            draft = build_organization_candidate_from_value(
                source=self.context.stream.source,
                value_text=value.text,
                value_start=value.start,
                value_end=value.end,
                matched_by=self.event.matched_by,
                label_event_id=self.event.event_id,
                label_driven=True,
            )
            return [draft] if draft is not None else []
        value = _expand_anchor_region(self.context, self.event, max_left=60, max_right=24)
        if value is None:
            return []
        draft = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=value.text,
            value_start=value.start,
            value_end=value.end,
            matched_by=self.event.matched_by,
        )
        return [draft] if draft is not None else []


@dataclass(slots=True)
class NameStack(BaseAttrStack):
    def extract(self) -> list[CandidateDraft]:
        if self.event.kind.value == "label":
            value = _read_rhs_value(self.context, self.event, max_chars=72)
            if value is None:
                return []
            draft = build_name_candidate_from_value(
                source=self.context.stream.source,
                value_text=value.text,
                value_start=value.start,
                value_end=value.end,
                matched_by=self.event.matched_by,
                component_hint=str(self.event.payload.get("component_hint") or "full"),
                label_event_id=self.event.event_id,
                confidence=0.92,
            )
            return [draft] if draft is not None else []
        value = _read_rhs_value(self.context, self.event, max_chars=56)
        if value is None:
            return []
        draft = build_name_candidate_from_value(
            source=self.context.stream.source,
            value_text=value.text,
            value_start=value.start,
            value_end=value.end,
            matched_by=self.event.matched_by,
            component_hint=str(self.event.payload.get("component_hint") or "full"),
            confidence=0.76 if "self_intro" in self.event.matched_by else 0.72,
        )
        return [draft] if draft is not None else []


@dataclass(frozen=True, slots=True)
class ExtractedValue:
    text: str
    start: int
    end: int


class _LegacyAddressOrgNoopDetector:
    """旧地址流里的组织探测占位。

    这里只复用旧地址 span 构造与地址边界回退，不复用旧组织直接入库逻辑。
    """

    def _clean_organization_candidate(self, text: str) -> str:
        return text

    def _extract_match(self, *_args, **_kwargs):
        return None

    def _is_organization_candidate(self, *_args, **_kwargs) -> bool:
        return False

    def _organization_confidence(self, *_args, **_kwargs) -> float:
        return 0.0

    def _upsert_candidate(self, **_kwargs) -> None:
        return None


_LEGACY_ADDRESS_NOOP_DETECTOR = _LegacyAddressOrgNoopDetector()


def build_name_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    matched_by: str,
    component_hint: str,
    label_event_id: str | None = None,
    confidence: float = 0.92,
) -> CandidateDraft | None:
    del value_end
    cleaned = _clean_value(value_text)
    if not _is_plausible_name(cleaned, component_hint=component_hint):
        return None
    offset = value_text.find(cleaned)
    metadata = {
        "matched_by": [matched_by],
        "name_component": [component_hint or "full"],
    }
    label_ids = {label_event_id} if label_event_id else set()
    return CandidateDraft(
        attr_type=PIIAttributeType.NAME,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        text=cleaned,
        source=source,
        confidence=confidence,
        matched_by=matched_by,
        claim_strength=ClaimStrength.SOFT,
        metadata=metadata,
        label_event_ids=label_ids,
    )


def rebuild_candidate_from_span(candidate: CandidateDraft, raw_text: str, *, start: int, end: int) -> CandidateDraft | None:
    """按同一属性语义重新构建裁剪后的候选。"""
    if start >= end:
        return None
    segment = raw_text[start:end]
    if candidate.attr_type == PIIAttributeType.NAME:
        rebuilt = build_name_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            matched_by=candidate.matched_by,
            component_hint=name_component_hint(candidate),
            confidence=candidate.confidence,
        )
        if rebuilt is None:
            return None
        rebuilt.claim_strength = candidate.claim_strength
        rebuilt.metadata = _merge_candidate_metadata(candidate.metadata, rebuilt.metadata)
        rebuilt.label_event_ids = set(candidate.label_event_ids)
        return rebuilt
    if candidate.attr_type == PIIAttributeType.ORGANIZATION:
        rebuilt = build_organization_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            matched_by=candidate.matched_by,
            label_driven=_is_label_driven(candidate),
        )
        if rebuilt is None:
            return None
        rebuilt.claim_strength = candidate.claim_strength
        rebuilt.metadata = _merge_candidate_metadata(candidate.metadata, rebuilt.metadata)
        rebuilt.label_event_ids = set(candidate.label_event_ids)
        return rebuilt
    if candidate.attr_type == PIIAttributeType.ADDRESS:
        rebuilt = build_address_candidates_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            matched_by=candidate.matched_by,
            label_event_id=next(iter(candidate.label_event_ids), None),
        )
        if not rebuilt:
            return None
        primary = rebuilt[0]
        primary.claim_strength = candidate.claim_strength
        primary.metadata = _merge_candidate_metadata(candidate.metadata, primary.metadata)
        primary.label_event_ids = set(candidate.label_event_ids)
        return primary
    if candidate.attr_type == PIIAttributeType.DETAILS:
        cleaned = _clean_value(segment)
        if not cleaned:
            return None
        offset = segment.find(cleaned)
        return CandidateDraft(
            attr_type=PIIAttributeType.DETAILS,
            start=start + max(0, offset),
            end=start + max(0, offset) + len(cleaned),
            text=cleaned,
            source=candidate.source,
            confidence=candidate.confidence,
            matched_by=candidate.matched_by,
            claim_strength=candidate.claim_strength,
            metadata=_copy_metadata(candidate.metadata),
            label_event_ids=set(candidate.label_event_ids),
        )
    if candidate.claim_strength == ClaimStrength.HARD:
        cleaned = _clean_value(segment)
        if not cleaned:
            return None
        offset = segment.find(cleaned)
        return CandidateDraft(
            attr_type=candidate.attr_type,
            start=start + max(0, offset),
            end=start + max(0, offset) + len(cleaned),
            text=cleaned,
            source=candidate.source,
            confidence=candidate.confidence,
            matched_by=candidate.matched_by,
            claim_strength=candidate.claim_strength,
            metadata=_copy_metadata(candidate.metadata),
            label_event_ids=set(candidate.label_event_ids),
        )
    return None


def has_organization_suffix(text: str) -> bool:
    return _ORG_SUFFIX_RE.search(str(text or "")) is not None


def has_address_signal(text: str) -> bool:
    return _ADDRESS_SIGNAL_RE.search(str(text or "")) is not None


def name_component_hint(candidate: CandidateDraft) -> str:
    values = candidate.metadata.get("name_component")
    if values:
        return str(values[0] or "full")
    return "full"


def build_organization_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    matched_by: str,
    label_event_id: str | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _clean_value(value_text)
    if not _is_plausible_organization(cleaned, label_driven=label_driven):
        return None
    offset = value_text.find(cleaned)
    label_ids = {label_event_id} if label_event_id else set()
    return CandidateDraft(
        attr_type=PIIAttributeType.ORGANIZATION,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        text=cleaned,
        source=source,
        confidence=0.9 if label_driven else 0.78,
        matched_by=matched_by,
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": [matched_by]},
        label_event_ids=label_ids,
    )


def build_address_candidates_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    matched_by: str,
    label_event_id: str | None = None,
) -> list[CandidateDraft]:
    del value_end
    cleaned = _clean_value(value_text)
    if not _is_plausible_address(cleaned):
        return []
    offset = value_text.find(cleaned)
    absolute_start = value_start + max(0, offset)
    absolute_end = absolute_start + len(cleaned)
    label_ids = {label_event_id} if label_event_id else set()
    drafts: list[CandidateDraft] = [
        CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_end,
            text=cleaned,
            source=source,
            confidence=0.93 if label_event_id else 0.82,
            matched_by=matched_by,
            claim_strength=ClaimStrength.SOFT,
            metadata={
                "matched_by": [matched_by],
                "address_kind": ["private_address"],
            },
            label_event_ids=label_ids,
        )
    ]
    if label_event_id:
        drafts.extend(_address_components_from_text(source, cleaned, absolute_start))
    return drafts


def _build_address_drafts_with_legacy_flow(
    *,
    source,
    raw_text: str,
    segment_start: int,
    segment_end: int,
    locale_profile: str,
    matched_by: str,
    label_event_id: str | None = None,
    anchor_start: int | None = None,
    anchor_end: int | None = None,
    component_type: str = "",
    trigger_kind: str = "component_name",
) -> list[CandidateDraft]:
    if segment_start >= segment_end:
        return []
    segment_text = raw_text[segment_start:segment_end]
    address_input = build_text_input(segment_text)
    component_matches = collect_component_matches(address_input, locale_profile=locale_profile)
    if not component_matches:
        return []
    config = AddressParseConfig(
        locale_profile=locale_profile,
        protection_level=ProtectionLevel.STRONG,
        min_confidence=0.0,
        emit_component_candidates=True,
    )
    spans = scan_address_and_organization(
        _LEGACY_ADDRESS_NOOP_DETECTOR,
        {},
        raw_text=address_input.text,
        component_matches=component_matches,
        source=source,
        bbox=None,
        block_id=None,
        skip_spans=[],
        config=config,
        original_text=None,
        shadow_index_map=None,
    )
    if not spans:
        return []
    results = parse_results_from_spans(
        spans,
        locale_profile=locale_profile,
        config=config,
        component_matches=component_matches,
    )
    if not results:
        return []
    filtered = _filter_address_results_for_event(
        results,
        label_event_id=label_event_id,
        segment_start=segment_start,
        anchor_start=anchor_start,
        anchor_end=anchor_end,
        component_type=component_type,
        trigger_kind=trigger_kind,
    )
    drafts: list[CandidateDraft] = []
    for result in filtered:
        drafts.extend(
            _address_result_to_drafts(
                result,
                source=source,
                segment_text=segment_text,
                segment_start=segment_start,
                matched_by=matched_by,
                label_event_id=label_event_id,
            )
        )
    return drafts


def _filter_address_results_for_event(
    results: tuple[AddressParseResult, ...],
    *,
    label_event_id: str | None,
    segment_start: int,
    anchor_start: int | None,
    anchor_end: int | None,
    component_type: str,
    trigger_kind: str,
) -> tuple[AddressParseResult, ...]:
    if label_event_id is not None:
        label_candidates = tuple(result for result in results if result.span.matched_by == "context_address_field")
        if label_candidates:
            return label_candidates
        return tuple(results[:1])
    if anchor_start is None or anchor_end is None:
        return results
    local_anchor_start = max(0, anchor_start - segment_start)
    local_anchor_end = max(local_anchor_start, anchor_end - segment_start)
    overlapping = tuple(
        result
        for result in results
        if not (result.span.end <= local_anchor_start or result.span.start >= local_anchor_end)
    )
    if overlapping:
        ranked = _rank_address_results_for_anchor(
            overlapping,
            component_type=component_type,
            trigger_kind=trigger_kind,
        )
        return ranked
    containing = tuple(
        result
        for result in results
        if result.span.start <= local_anchor_start < result.span.end
    )
    if containing:
        ranked = _rank_address_results_for_anchor(
            containing,
            component_type=component_type,
            trigger_kind=trigger_kind,
        )
        return ranked
    return ()


def _rank_address_results_for_anchor(
    results: tuple[AddressParseResult, ...],
    *,
    component_type: str,
    trigger_kind: str,
) -> tuple[AddressParseResult, ...]:
    preferred = [
        result
        for result in results
        if any(component.component_type == component_type for component in result.components)
    ]
    target = preferred or list(results)
    ordered = sorted(
        target,
        key=lambda item: (
            trigger_kind == "component_attr" and any(component.component_type == component_type for component in item.components),
            item.confidence,
            item.span.end - item.span.start,
        ),
        reverse=True,
    )
    return tuple(ordered)


def _address_result_to_drafts(
    result: AddressParseResult,
    *,
    source,
    segment_text: str,
    segment_start: int,
    matched_by: str,
    label_event_id: str | None,
) -> list[CandidateDraft]:
    whole_text, absolute_start, absolute_end = _extend_address_whole_span(
        result,
        segment_text=segment_text,
        segment_start=segment_start,
    )
    label_ids = {label_event_id} if label_event_id else set()
    component_types = _ordered_unique(component.component_type for component in result.components)
    privacy_levels = _ordered_unique(component.privacy_level for component in result.components)
    component_trace = [f"{component.component_type}:{component.text}" for component in result.components]
    base_metadata = {
        "matched_by": [matched_by],
        "address_kind": [result.address_kind],
        "address_terminated_by": [result.span.terminated_by],
        "address_component_type": component_types,
        "address_privacy_level": privacy_levels,
        "address_component_trace": component_trace,
        "address_match_origin": [result.span.matched_by],
    }
    drafts = [
        CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_end,
            text=whole_text,
            source=source,
            confidence=result.confidence,
            matched_by=matched_by,
            claim_strength=ClaimStrength.SOFT,
            metadata=base_metadata,
            label_event_ids=set(label_ids),
        )
    ]
    for component in result.components:
        component_draft = _address_component_to_draft(
            component,
            source=source,
            matched_by=matched_by,
            label_ids=label_ids,
            result=result,
            absolute_span_start=absolute_start,
        )
        if component_draft is not None:
            drafts.append(component_draft)
    return drafts


def _extend_address_whole_span(
    result: AddressParseResult,
    *,
    segment_text: str,
    segment_start: int,
) -> tuple[str, int, int]:
    absolute_start = segment_start + result.span.start
    absolute_end = segment_start + result.span.end
    whole_text = result.span.text
    if not result.components:
        return whole_text, absolute_start, absolute_end
    tail_component = result.components[-1]
    if tail_component.component_type not in {"road", "street"}:
        return whole_text, absolute_start, absolute_end
    trailing = segment_text[result.span.end :]
    match = _TRAILING_ZH_HOUSE_NUMBER_RE.match(trailing)
    if match is None:
        return whole_text, absolute_start, absolute_end
    suffix = trailing[: match.end()]
    return whole_text + suffix, absolute_start, absolute_end + len(suffix)


def _address_component_to_draft(
    component: AddressComponent,
    *,
    source,
    matched_by: str,
    label_ids: set[str],
    result: AddressParseResult,
    absolute_span_start: int,
) -> CandidateDraft | None:
    if component.start_offset >= component.end_offset:
        return None
    attr_type = PIIAttributeType.DETAILS if component.component_type in {"building", "unit", "floor", "room"} else PIIAttributeType.ADDRESS
    return CandidateDraft(
        attr_type=attr_type,
        start=absolute_span_start + component.start_offset,
        end=absolute_span_start + component.end_offset,
        text=component.text,
        source=source,
        confidence=max(0.0, min(result.confidence - 0.04, component.confidence)),
        matched_by=f"address_component_{component.component_type}",
        claim_strength=ClaimStrength.SOFT,
        metadata={
            "matched_by": [f"address_component_{component.component_type}"],
            "address_kind": [result.address_kind],
            "address_component_type": [component.component_type],
            "address_privacy_level": [component.privacy_level],
            "address_match_origin": [result.span.matched_by],
            "address_component_trace": [f"{component.component_type}:{component.text}"],
        },
        label_event_ids=set(label_ids),
    )


def _ordered_unique(values) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _address_components_from_text(source, text: str, absolute_start: int) -> list[CandidateDraft]:
    drafts: list[CandidateDraft] = []
    unit_match = _ADDRESS_UNIT_RE.search(text)
    if unit_match is not None:
        unit_text = unit_match.group(0).strip(" ,")
        if unit_text:
            unit_start = absolute_start + unit_match.start()
            drafts.append(
                CandidateDraft(
                    attr_type=PIIAttributeType.DETAILS,
                    start=unit_start,
                    end=unit_start + len(unit_text),
                    text=unit_text,
                    source=source,
                    confidence=0.88,
                    matched_by="address_component_unit",
                    claim_strength=ClaimStrength.SOFT,
                    metadata={"matched_by": ["address_component_unit"]},
                )
            )
        street_text = text[: unit_match.start()].strip(" ,")
        if street_text and _ADDRESS_SIGNAL_RE.search(street_text):
            street_offset = text.find(street_text)
            drafts.append(
                CandidateDraft(
                    attr_type=PIIAttributeType.ADDRESS,
                    start=absolute_start + street_offset,
                    end=absolute_start + street_offset + len(street_text),
                    text=street_text,
                    source=source,
                    confidence=0.9,
                    matched_by="address_component_street",
                    claim_strength=ClaimStrength.SOFT,
                    metadata={"matched_by": ["address_component_street"]},
                )
            )
        return drafts
    comma_index = text.find(",")
    if comma_index > 0:
        head = text[:comma_index].strip()
        if head and _ADDRESS_SIGNAL_RE.search(head):
            drafts.append(
                CandidateDraft(
                    attr_type=PIIAttributeType.ADDRESS,
                    start=absolute_start,
                    end=absolute_start + len(head),
                    text=head,
                    source=source,
                    confidence=0.86,
                    matched_by="address_component_street",
                    claim_strength=ClaimStrength.SOFT,
                    metadata={"matched_by": ["address_component_street"]},
                )
            )
    return drafts


def _structured_confidence(attr_type: PIIAttributeType, matched_by: str) -> float:
    if matched_by == "dictionary_local":
        return 0.99
    if matched_by == "dictionary_session":
        return 0.97
    if matched_by == "prompt":
        return 0.96
    if attr_type == PIIAttributeType.EMAIL:
        return 0.98
    if attr_type == PIIAttributeType.PHONE:
        return 0.97
    return 0.95


def _copy_metadata(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    copied: dict[str, list[str]] = {}
    for key, items in value.items():
        if isinstance(items, list):
            copied[key] = [str(item) for item in items if str(item)]
        elif items:
            copied[key] = [str(items)]
    return copied


def _merge_candidate_metadata(left: dict[str, list[str]], right: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = _copy_metadata(left)
    for key, values in _copy_metadata(right).items():
        merged[key] = list(dict.fromkeys([*merged.get(key, []), *values]))
    return merged


def _clean_value(text: str) -> str:
    cleaned = str(text or "")
    cleaned = cleaned.replace(_OCR_SEMANTIC_BREAK_TOKEN, " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" \t\r\n:：-—|,，;；/\\")
    cleaned = re.sub(r"[。！!？?]+$", "", cleaned).strip()
    return cleaned


def _is_plausible_name(text: str, *, component_hint: str) -> bool:
    if not text or len(text) > 80 or "@" in text:
        return False
    if any(char.isdigit() for char in text):
        return False
    compact_lower = re.sub(r"\s+", " ", text).strip().lower()
    if compact_lower in _NAME_PRONOUNS:
        return False
    if text in _NAME_BLOCKLIST_ZH:
        return False
    compact_no_space = re.sub(r"\s+", "", text)
    if _ZH_NAME_RE.fullmatch(compact_no_space):
        return True
    tokens = [token for token in re.split(r"\s+", text) if token]
    if component_hint in {"family", "given", "middle"}:
        return len(tokens) == 1 and _EN_NAME_TOKEN_RE.fullmatch(tokens[0]) is not None
    if not (1 <= len(tokens) <= 4):
        return False
    return all(_EN_NAME_TOKEN_RE.fullmatch(token) is not None for token in tokens)


def _is_plausible_address(text: str) -> bool:
    if not text or len(text) < 4 or len(text) > 180:
        return False
    if "@" in text or _ORG_SUFFIX_RE.search(text):
        return False
    return _ADDRESS_SIGNAL_RE.search(text) is not None


def _is_plausible_organization(text: str, *, label_driven: bool) -> bool:
    if not text or len(text) < 2 or len(text) > 120:
        return False
    if "@" in text or any(char.isdigit() for char in text[:3]):
        return False
    if _ADDRESS_SIGNAL_RE.search(text) and not _ORG_SUFFIX_RE.search(text):
        return False
    if label_driven:
        return True
    return _ORG_SUFFIX_RE.search(text) is not None


def _is_label_driven(candidate: CandidateDraft) -> bool:
    return candidate.matched_by.startswith("context_") or candidate.matched_by.startswith("ocr_label_")


def _read_rhs_value(context: StackContextLike, event: StreamEvent, *, max_chars: int) -> ExtractedValue | None:
    text = context.stream.raw_text
    start = _skip_separators(text, event.end)
    if start >= len(text):
        return None
    end = min(context.next_boundary(start, ignore_event_id=event.event_id), start + max_chars)
    segment = text[start:end]
    hard_stop = _hard_stop_offset(segment)
    segment = segment[:hard_stop]
    cleaned = _clean_value(segment)
    if not cleaned:
        return None
    cleaned_offset = segment.find(cleaned)
    absolute_start = start + max(0, cleaned_offset)
    return ExtractedValue(cleaned, absolute_start, absolute_start + len(cleaned))


def _address_label_segment_bounds(
    context: StackContextLike,
    event: StreamEvent,
    *,
    max_chars: int,
) -> tuple[int, int] | None:
    text = context.stream.raw_text
    value_start = _skip_separators(text, event.end)
    if value_start >= len(text):
        return None
    boundary = min(context.next_boundary(value_start, ignore_event_id=event.event_id), value_start + max_chars)
    segment = text[event.start:boundary]
    stop = _hard_stop_offset(segment)
    segment_end = event.start + stop
    if segment_end <= event.end:
        return None
    return (event.start, segment_end)


def _read_rhs_structured_value(context: StackContextLike, event: StreamEvent) -> ExtractedValue | None:
    max_chars = _STRUCTURED_LABEL_MAX_CHARS.get(event.attr_type, 48)
    raw_value = _read_rhs_value(context, event, max_chars=max_chars)
    if raw_value is None:
        return None
    patterns = _STRUCTURED_PROMPT_PATTERNS.get(event.attr_type, ())
    for pattern in patterns:
        match = pattern.search(raw_value.text)
        if match is None:
            continue
        text = match.group(0).strip()
        if not text:
            continue
        absolute_start = raw_value.start + match.start()
        return ExtractedValue(text, absolute_start, absolute_start + len(text))
    return None


def _expand_anchor_region(
    context: StackContextLike,
    event: StreamEvent,
    *,
    max_left: int,
    max_right: int,
) -> ExtractedValue | None:
    text = context.stream.raw_text
    left = max(0, event.start - max_left)
    right = min(len(text), event.end + max_right)
    for index in range(event.start - 1, left - 1, -1):
        if _is_hard_stop_char(text[index]):
            left = index + 1
            break
    boundary = context.next_boundary(event.end, ignore_event_id=event.event_id)
    right = min(right, boundary)
    segment = text[left:right]
    segment = segment[: _hard_stop_offset(segment)]
    cleaned = _clean_value(segment)
    if not cleaned:
        return None
    offset = segment.find(cleaned)
    absolute_start = left + max(0, offset)
    return ExtractedValue(cleaned, absolute_start, absolute_start + len(cleaned))


def _address_component_segment_bounds(
    context: StackContextLike,
    event: StreamEvent,
) -> tuple[int, int] | None:
    text = context.stream.raw_text
    trigger_kind = str(event.payload.get("trigger_kind") or "component_name")
    component_type = str(event.payload.get("component_type") or "")
    if trigger_kind == "component_attr":
        left = _expand_attr_left_boundary(text, event.start)
        max_right = 132
    elif component_type in {"building", "unit", "floor", "room", "postal_code"}:
        left = max(0, event.start - 28)
        max_right = 72
    else:
        left = max(0, event.start - 40)
        max_right = 140
        for index in range(event.start - 1, left - 1, -1):
            if _is_hard_stop_char(text[index]):
                left = index + 1
                break
    right = min(len(text), event.end + max_right)
    boundary = context.next_boundary(event.end, ignore_event_id=event.event_id)
    right = min(right, boundary)
    segment = text[left:right]
    stop = _hard_stop_offset(segment)
    right = min(right, left + stop)
    if right <= left:
        return None
    return (left, right)


def _expand_attr_left_boundary(text: str, anchor_start: int) -> int:
    left = anchor_start
    taken = 0
    index = anchor_start - 1
    while index >= 0:
        char = text[index]
        if _is_hard_stop_char(char):
            break
        if char.isspace():
            if taken > 0:
                break
            index -= 1
            continue
        if taken >= 3:
            break
        if not (char.isalnum() or "\u4e00" <= char <= "\u9fff"):
            break
        left = index
        taken += 1
        index -= 1
    return left


def _hard_stop_offset(segment: str) -> int:
    break_index = segment.find(_OCR_SEMANTIC_BREAK_TOKEN)
    limit = len(segment) if break_index < 0 else break_index
    for marker in ("\n\n", "\r\n\r\n"):
        index = segment.find(marker)
        if 0 <= index < limit:
            limit = index
    for index, char in enumerate(segment[:limit]):
        if char in {";", "；", "。", "!", "！", "?", "？"}:
            return index
    return limit


def _skip_separators(text: str, index: int) -> int:
    while index < len(text) and text[index] in {" ", "\t", "\r", "\n", ":", "：", "-", "—", "|"}:
        index += 1
    return index


def _is_hard_stop_char(char: str) -> bool:
    return char in {"\n", "\r", "。", "！", "?", "？", "!", ";", "；"}
