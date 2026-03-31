"""Detector 的边界优先 stack 实现。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    NameComponentHint,
    StreamInput,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

_ORG_SUFFIX_RE = re.compile(
    r"(?i)(股份有限公司|有限责任公司|有限公司|研究院|实验室|工作室|事务所|集团|公司|大学|学院|银行|酒店|医院|中心"
    r"|incorporated|corporation|company|limited|inc\.?|corp\.?|co\.?|ltd\.?|llc|plc|gmbh|pte|university|college|bank|hotel|hospital|clinic|labs?)"
)
_ADDRESS_SIGNAL_RE = re.compile(
    r"(?i)(省|市|区|县|旗|镇|乡|村|路|街|道|巷|弄|小区|公寓|大厦|园区|花园|家园|苑|庭|府|湾|宿舍|栋|幢|座|楼|单元|层|室|房|户"
    r"|street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct|suite|ste|apt|unit|zip)"
)
_LEADING_ADDRESS_LABEL_RE = re.compile(r"^(?:收货地址|家庭住址|联系地址|住址|地址)\s*[:：]?\s*")
_NAME_PRONOUNS = {
    "he", "him", "she", "her", "they", "them", "we", "us", "you", "me", "i", "myself", "pronouns",
}
_NAME_BLOCKLIST_ZH = {"本人", "未知", "匿名", "姓名", "名字"}
_EN_NAME_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z.'\-]{0,30}$")
_ZH_NAME_RE = re.compile(r"^[\u4e00-\u9fff·]{2,8}$")
_HARD_BREAK_RE = re.compile(r"[;；。！？!?]")

_ADDRESS_COMPONENT_ORDER = {
    AddressComponentType.PROVINCE: 1,
    AddressComponentType.CITY: 2,
    AddressComponentType.DISTRICT: 3,
    AddressComponentType.STREET_ADMIN: 4,
    AddressComponentType.TOWN: 5,
    AddressComponentType.VILLAGE: 6,
    AddressComponentType.ROAD: 7,
    AddressComponentType.STREET: 7,
    AddressComponentType.COMPOUND: 8,
    AddressComponentType.BUILDING: 9,
    AddressComponentType.UNIT: 10,
    AddressComponentType.FLOOR: 11,
    AddressComponentType.ROOM: 12,
    AddressComponentType.STATE: 13,
    AddressComponentType.POSTAL_CODE: 14,
}
_DETAIL_COMPONENTS = {
    AddressComponentType.BUILDING,
    AddressComponentType.UNIT,
    AddressComponentType.FLOOR,
    AddressComponentType.ROOM,
}
_PREFIX_EN_KEYWORDS = {"apt", "apartment", "suite", "ste", "unit", "#", "floor", "fl", "room", "rm"}


class StackContextLike(Protocol):
    stream: StreamInput
    locale_profile: str
    clues: tuple[Clue, ...]

    def has_negative_at(self, start: int, end: int) -> bool: ...


@dataclass(slots=True)
class StackRun:
    family: ClueFamily
    candidate: CandidateDraft
    consumed_ids: set[str]
    handled_label_clue_ids: set[str] = field(default_factory=set)
    next_index: int = 0


@dataclass(slots=True)
class BaseStack:
    clue: Clue
    clue_index: int
    context: StackContextLike

    def run(self) -> StackRun | None:
        raise NotImplementedError


@dataclass(slots=True)
class StructuredValueStack(BaseStack):
    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            candidate = _build_hard_candidate(self.clue, self.context.stream.source)
            return StackRun(ClueFamily.STRUCTURED, candidate, {self.clue.clue_id}, next_index=self.clue_index + 1)
        if self.clue.role != ClueRole.LABEL:
            return None
        hard_clue, hard_index = _find_next_same_attr_hard(self.context.clues, self.clue_index + 1, self.clue.attr_type)
        if hard_clue is None:
            return None
        if _blocked_between(self.context.stream.raw_text, self.context.clues, self.clue.end, hard_clue.start, allow_family=ClueFamily.STRUCTURED):
            return None
        candidate = _build_hard_candidate(hard_clue, self.context.stream.source)
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata, {"bound_label_clue_ids": [self.clue.clue_id]})
        return StackRun(
            family=ClueFamily.STRUCTURED,
            candidate=candidate,
            consumed_ids={self.clue.clue_id, hard_clue.clue_id},
            handled_label_clue_ids={self.clue.clue_id},
            next_index=hard_index + 1,
        )


@dataclass(slots=True)
class NameStack(BaseStack):
    def run(self) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        start = self._resolve_left_boundary()
        if start is None:
            return None
        end, next_index, consumed_ids = _resolve_family_boundary(
            self.context.stream.raw_text,
            self.context.clues,
            self.clue_index,
            family=ClueFamily.NAME,
            initial_end=self.clue.end,
        )
        # 名字 clue 只覆盖姓氏，需向右扩展以捕获完整姓名（如"张"→"张三"）。
        end = _extend_name_boundary(self.context.stream.raw_text, start, end, self.context.clues, next_index)
        if end <= start:
            return None
        text = _clean_value(self.context.stream.raw_text[start:end])
        if not _is_plausible_name(text, component_hint=self._component_hint()):
            return None
        offset = self.context.stream.raw_text[start:end].find(text)
        absolute_start = start + max(0, offset)
        # 非 label-driven 时，若候选区间被负向 clue 覆盖则拒绝。
        if not is_label_seed and self.context.has_negative_at(absolute_start, absolute_start + len(text)):
            return None
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.NAME,
            start=absolute_start,
            end=absolute_start + len(text),
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata={"matched_by": [self.clue.source_kind], "name_component": [self._component_hint().value]},
            label_clue_ids={self.clue.clue_id} if is_label_seed else set(),
            label_driven=is_label_seed,
        )
        return StackRun(ClueFamily.NAME, candidate, consumed_ids, {self.clue.clue_id} if is_label_seed else set(), next_index)

    def _resolve_left_boundary(self) -> int | None:
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            return _skip_separators(self.context.stream.raw_text, self.clue.end)
        if self.clue.role == ClueRole.SURNAME:
            return self.clue.start
        return None

    def _component_hint(self) -> NameComponentHint:
        if self.clue.role == ClueRole.SURNAME:
            return NameComponentHint.FAMILY
        return self.clue.component_hint or NameComponentHint.FULL


@dataclass(slots=True)
class OrganizationStack(BaseStack):
    def run(self) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        if is_label_seed:
            start = _skip_separators(self.context.stream.raw_text, self.clue.end)
            end, next_index, consumed_ids = _resolve_family_boundary(
                self.context.stream.raw_text,
                self.context.clues,
                self.clue_index,
                family=ClueFamily.ORGANIZATION,
                initial_end=self.clue.end,
            )
            handled = {self.clue.clue_id}
        elif self.clue.role == ClueRole.SUFFIX:
            start = _left_expand_text_boundary(self.context.stream.raw_text, self.context.clues, self.clue.start)
            end = self.clue.end
            next_index = self.clue_index + 1
            consumed_ids = {self.clue.clue_id}
            handled = set()
        else:
            return None
        if end <= start:
            return None
        text = _strip_leading_address_label(_clean_value(self.context.stream.raw_text[start:end]))
        if not _is_plausible_organization(text, label_driven=is_label_seed):
            return None
        offset = self.context.stream.raw_text[start:end].find(text)
        absolute_start = start + max(0, offset)
        # 非 label-driven 的 suffix 触发，若被负向 clue 覆盖则拒绝。
        if not is_label_seed and self.context.has_negative_at(absolute_start, absolute_start + len(text)):
            return None
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ORGANIZATION,
            start=absolute_start,
            end=absolute_start + len(text),
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata={"matched_by": [self.clue.source_kind]},
            label_clue_ids={self.clue.clue_id} if is_label_seed else set(),
            label_driven=is_label_seed,
        )
        return StackRun(ClueFamily.ORGANIZATION, candidate, consumed_ids, handled, next_index)


@dataclass(slots=True)
class AddressStack(BaseStack):
    def run(self) -> StackRun | None:
        raw_text = self.context.stream.raw_text
        is_label_seed = self.clue.role == ClueRole.LABEL
        if is_label_seed:
            address_start = _skip_separators(raw_text, self.clue.end)
            first_index = _next_address_index(self.context.clues, self.clue_index + 1)
            if first_index is None:
                return None
            index = first_index
            consumed_ids = {self.clue.clue_id}
            handled_labels = {self.clue.clue_id}
        else:
            address_start = self._seed_left_boundary()
            index = self.clue_index
            consumed_ids = set()
            handled_labels = set()
        if address_start is None:
            return None
        components: list[dict[str, object]] = []
        pending_names: dict[AddressComponentType, Clue] = {}
        segment_cursor = address_start
        last_end = address_start
        last_component_order = 0
        i = index
        while i < len(self.context.clues):
            clue = self.context.clues[i]
            if clue.family == ClueFamily.BREAK:
                break
            if clue.family != ClueFamily.ADDRESS or clue.role == ClueRole.LABEL:
                break
            if clue.start < address_start:
                i += 1
                continue
            gap_text = raw_text[last_end:clue.start]
            # 断句符或非地址 clue 阻断，或 component 间距超过 30 字符。
            if clue.start > last_end and (_address_gap_blocked(gap_text) or len(gap_text.strip()) > 30):
                break
            component_type = clue.component_type
            if component_type is None:
                i += 1
                continue
            component_order = _ADDRESS_COMPONENT_ORDER.get(component_type, 999)
            if last_component_order and component_order < last_component_order:
                break
            consumed_ids.add(clue.clue_id)
            if clue.role == ClueRole.VALUE:
                if component_type == AddressComponentType.POSTAL_CODE:
                    component = _build_standalone_address_component(clue, component_type)
                    if component is not None:
                        components.append(component)
                        segment_cursor = clue.end
                        last_end = clue.end
                        last_component_order = component_order
                    i += 1
                    continue
                pending_names[component_type] = clue
                last_end = max(last_end, clue.end)
                i += 1
                continue
            component = _build_address_component_from_attr(
                raw_text,
                clue=clue,
                component_type=component_type,
                segment_cursor=segment_cursor,
                pending_name=pending_names.get(component_type),
                clues=self.context.clues,
                clue_index=i,
            )
            if component is None:
                break
            components.append(component)
            segment_cursor = int(component["end"])
            last_end = segment_cursor
            last_component_order = component_order
            pending_names = {
                key: value
                for key, value in pending_names.items()
                if value.end > segment_cursor
            }
            i += 1
        if not components:
            return None
        final_start = int(components[0]["start"])
        final_end = int(components[-1]["end"])
        text = _clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_start + len(text),
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata=_address_metadata(self.clue, components),
            label_clue_ids=handled_labels,
            label_driven=is_label_seed,
        )
        return StackRun(ClueFamily.ADDRESS, candidate, consumed_ids, handled_labels, i)

    def _seed_left_boundary(self) -> int | None:
        raw_text = self.context.stream.raw_text
        if self.clue.role == ClueRole.VALUE:
            return self.clue.start
        if self.clue.role == ClueRole.KEY:
            floor = _left_family_floor(self.context.clues, self.clue_index)
            return _left_expand_value(raw_text, self.clue.start, floor=floor)
        return None


def _build_hard_candidate(clue: Clue, source: PIISourceType) -> CandidateDraft:
    metadata = {key: list(values) for key, values in clue.source_metadata.items()}
    metadata = merge_metadata(metadata, {"matched_by": [clue.source_kind], "hard_source": [str(clue.hard_source or "regex")]})
    return CandidateDraft(
        attr_type=clue.attr_type,
        start=clue.start,
        end=clue.end,
        text=clue.text,
        source=source,
        source_kind=clue.source_kind,
        claim_strength=ClaimStrength.HARD,
        metadata=metadata,
    )


def build_name_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    component_hint: NameComponentHint,
    label_clue_id: str | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _clean_value(value_text)
    if not _is_plausible_name(cleaned, component_hint=component_hint):
        return None
    offset = value_text.find(cleaned)
    return CandidateDraft(
        attr_type=PIIAttributeType.NAME,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": [source_kind], "name_component": [component_hint.value]},
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def build_organization_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    label_clue_id: str | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _strip_leading_address_label(_clean_value(value_text))
    if not _is_plausible_organization(cleaned, label_driven=label_driven):
        return None
    offset = value_text.find(cleaned)
    return CandidateDraft(
        attr_type=PIIAttributeType.ORGANIZATION,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": [source_kind]},
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def has_organization_suffix(text: str) -> bool:
    return _ORG_SUFFIX_RE.search(str(text or "")) is not None


def has_address_signal(text: str) -> bool:
    return _ADDRESS_SIGNAL_RE.search(str(text or "")) is not None


def looks_like_name_value(text: str, *, component_hint: NameComponentHint = NameComponentHint.FULL) -> bool:
    return _is_plausible_name(_clean_value(text), component_hint=component_hint)


def looks_like_organization_value(text: str, *, label_driven: bool = False) -> bool:
    return _is_plausible_organization(_strip_leading_address_label(_clean_value(text)), label_driven=label_driven)


def name_component_hint(candidate: CandidateDraft) -> NameComponentHint:
    values = candidate.metadata.get("name_component")
    return NameComponentHint(str(values[0])) if values else NameComponentHint.FULL


def build_address_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    label_clue_id: str | None = None,
    metadata: dict[str, list[str]] | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    cleaned = _clean_value(value_text)
    if not cleaned:
        return None
    offset = value_text.find(cleaned)
    candidate_metadata = {"matched_by": [source_kind], "address_kind": ["private_address"]}
    if metadata:
        candidate_metadata = merge_metadata(candidate_metadata, metadata)
    return CandidateDraft(
        attr_type=PIIAttributeType.ADDRESS,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata=candidate_metadata,
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def _slice_candidate(candidate: CandidateDraft, raw_text: str, *, start: int, end: int) -> CandidateDraft | None:
    if start >= end:
        return None
    segment = raw_text[start:end]
    metadata_base = candidate.metadata
    if candidate.attr_type == PIIAttributeType.NAME:
        rebuilt = build_name_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            component_hint=name_component_hint(candidate),
            label_driven=candidate.label_driven,
        )
    elif candidate.attr_type == PIIAttributeType.ORGANIZATION:
        rebuilt = build_organization_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            label_driven=candidate.label_driven,
        )
    elif candidate.attr_type == PIIAttributeType.ADDRESS:
        metadata_base = {
            key: values
            for key, values in candidate.metadata.items()
            if not key.startswith("address_component") and not key.startswith("address_details")
        }
        rebuilt = build_address_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            metadata=merge_metadata(metadata_base, {"address_match_origin": ["trimmed"]}),
            label_driven=candidate.label_driven,
        )
    else:
        rebuilt = None
    if rebuilt is None:
        return None
    rebuilt.claim_strength = candidate.claim_strength
    rebuilt.metadata = merge_metadata(metadata_base, rebuilt.metadata)
    rebuilt.label_clue_ids = set(candidate.label_clue_ids)
    rebuilt.label_driven = candidate.label_driven
    return rebuilt


@dataclass(slots=True)
class ConflictOutcome:
    incoming: CandidateDraft | None
    drop_existing: bool = False
    replace_existing: CandidateDraft | None = None


class StackManager:
    def score(self, candidate: CandidateDraft) -> float:
        score = 0.0
        if candidate.claim_strength == ClaimStrength.HARD:
            score += 0.4
            score += 0.02 * _candidate_hard_source_rank(candidate)
        if candidate.source_kind.startswith("dictionary_"):
            score += 0.25
        elif candidate.label_driven:
            score += 0.08
        return score

    def resolve_conflict(self, context, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if existing.attr_type == incoming.attr_type:
            return self._resolve_same_attr(existing, incoming)
        if existing.claim_strength == ClaimStrength.HARD and incoming.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream.raw_text, incoming, existing)
            return ConflictOutcome(incoming=trimmed)
        if incoming.claim_strength == ClaimStrength.HARD and existing.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream.raw_text, existing, incoming)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        attr_pair = frozenset({existing.attr_type, incoming.attr_type})
        if attr_pair == {PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION}:
            return self._resolve_address_organization(context.stream.raw_text, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
            return self._resolve_name_organization(context.stream.raw_text, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ADDRESS}:
            return self._resolve_name_address(context.stream.raw_text, existing, incoming)
        return self._resolve_by_score(existing, incoming)

    def _resolve_same_attr(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        if (incoming.end - incoming.start) > (existing.end - existing.start):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _resolve_address_organization(self, raw_text: str, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        if not has_organization_suffix(organization.text):
            return self._resolve_by_score(existing, incoming)
        if organization is incoming:
            trimmed = self._trim_candidate(raw_text, address, organization)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = self._trim_candidate(raw_text, address, organization)
        return ConflictOutcome(incoming=trimmed)

    def _resolve_name_organization(self, raw_text: str, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        if not has_organization_suffix(organization.text):
            return ConflictOutcome(incoming=incoming if incoming.attr_type == PIIAttributeType.NAME else None)
        suffix_start = _organization_suffix_start(organization.text)
        if suffix_start <= 0:
            return ConflictOutcome(incoming=organization if incoming is organization else None, drop_existing=name is existing)
        if organization is incoming:
            trimmed = _slice_candidate(name, raw_text, start=name.start, end=min(name.end, organization.start + suffix_start))
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = _slice_candidate(name, raw_text, start=name.start, end=min(name.end, organization.start + suffix_start))
        return ConflictOutcome(incoming=trimmed)

    def _resolve_name_address(self, raw_text: str, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        """Name vs Address：address 优先，name 做 trim；trim 后无效则丢弃 name。"""
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        if name is incoming:
            trimmed = self._trim_candidate(raw_text, name, address)
            return ConflictOutcome(incoming=trimmed)
        # name 是 existing，address 是 incoming。
        trimmed = self._trim_candidate(raw_text, name, address)
        return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)

    def _resolve_by_score(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _trim_candidate(self, raw_text: str, candidate: CandidateDraft, blocker: CandidateDraft) -> CandidateDraft | None:
        if blocker.start <= candidate.start and blocker.end >= candidate.end:
            return None
        if blocker.start <= candidate.start:
            return _slice_candidate(candidate, raw_text, start=blocker.end, end=candidate.end)
        return _slice_candidate(candidate, raw_text, start=candidate.start, end=blocker.start)


def _resolve_family_boundary(raw_text: str, clues: tuple[Clue, ...], start_index: int, *, family: ClueFamily, initial_end: int) -> tuple[int, int, set[str]]:
    end = initial_end
    consumed = {clues[start_index].clue_id}
    index = start_index + 1
    while index < len(clues):
        clue = clues[index]
        if clue.family == ClueFamily.BREAK or clue.family != family:
            break
        if _blocked_between(raw_text, clues, end, clue.start, allow_family=family):
            break
        end = max(end, clue.end)
        consumed.add(clue.clue_id)
        index += 1
    return (end, index, consumed)


def _blocked_between(raw_text: str, clues: tuple[Clue, ...], start: int, end: int, *, allow_family: ClueFamily) -> bool:
    if start >= end:
        return False
    gap = raw_text[start:end]
    if _HARD_BREAK_RE.search(gap) or _OCR_SEMANTIC_BREAK_TOKEN in gap:
        return True
    for clue in clues:
        if clue.family == ClueFamily.BREAK and clue.start < end and clue.end > start:
            return True
        if clue.family not in {allow_family, ClueFamily.BREAK} and clue.start < end and clue.end > start:
            return True
    return False


def _find_next_same_attr_hard(clues: tuple[Clue, ...], start_index: int, attr_type: PIIAttributeType | None) -> tuple[Clue | None, int]:
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if clue.family == ClueFamily.BREAK:
            break
        if clue.role == ClueRole.HARD and clue.attr_type == attr_type:
            return (clue, index)
        if clue.role == ClueRole.LABEL and clue.attr_type != attr_type:
            break
    return (None, -1)


def _next_address_index(clues: tuple[Clue, ...], start_index: int) -> int | None:
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if clue.family == ClueFamily.BREAK:
            return None
        if clue.family == ClueFamily.ADDRESS and clue.role != ClueRole.LABEL:
            return index
        if clue.family not in {ClueFamily.ADDRESS, ClueFamily.BREAK}:
            return None
    return None


def _address_gap_blocked(gap: str) -> bool:
    if not gap:
        return False
    return bool(_HARD_BREAK_RE.search(gap) or _OCR_SEMANTIC_BREAK_TOKEN in gap)


def _build_standalone_address_component(clue: Clue, component_type: AddressComponentType) -> dict[str, object] | None:
    value = _normalize_address_value(component_type, clue.text)
    if not value:
        return None
    return {"component_type": component_type, "start": clue.start, "end": clue.end, "value": value, "key": "", "is_detail": component_type in _DETAIL_COMPONENTS}


def _build_address_component_from_attr(
    raw_text: str,
    *,
    clue: Clue,
    component_type: AddressComponentType,
    segment_cursor: int,
    pending_name: Clue | None,
    clues: tuple[Clue, ...],
    clue_index: int,
) -> dict[str, object] | None:
    key_text = clue.text
    affix = "prefix" if key_text.lower() in _PREFIX_EN_KEYWORDS else "suffix"
    if affix == "prefix":
        value_start = _skip_separators(raw_text, clue.end)
        next_start = _next_clue_start(clues, clue_index + 1, default=len(raw_text))
        value_end = _scan_forward_value_end(raw_text, value_start, next_start)
        if value_end <= value_start:
            return None
        value = _normalize_address_value(component_type, raw_text[value_start:value_end])
        if not value:
            return None
        return {"component_type": component_type, "start": clue.start, "end": value_end, "value": value, "key": key_text, "is_detail": component_type in _DETAIL_COMPONENTS}
    if pending_name is not None and segment_cursor <= pending_name.start < clue.start:
        component_start = pending_name.start
        raw_value = raw_text[pending_name.start:pending_name.end]
    else:
        component_start = segment_cursor
        raw_value = raw_text[segment_cursor:clue.start]
        if not raw_value.strip():
            component_start = _left_expand_value(raw_text, clue.start, floor=_left_family_floor(clues, clue_index))
            raw_value = raw_text[component_start:clue.start]
    value = _normalize_address_value(component_type, raw_value)
    if not value:
        return None
    component_end = clue.end
    if component_type in {AddressComponentType.ROAD, AddressComponentType.STREET}:
        component_end = _extend_street_tail(raw_text, component_end)
    return {"component_type": component_type, "start": component_start, "end": component_end, "value": value, "key": key_text, "is_detail": component_type in _DETAIL_COMPONENTS}


def _left_family_floor(clues: tuple[Clue, ...], clue_index: int) -> int:
    for index in range(clue_index - 1, -1, -1):
        clue = clues[index]
        if clue.family == ClueFamily.BREAK:
            return clue.end
        if clue.family != ClueFamily.ADDRESS:
            return clue.end
    return 0


def _left_expand_value(raw_text: str, attr_start: int, *, floor: int) -> int:
    index = attr_start
    while index > floor:
        previous = raw_text[index - 1]
        if previous.isspace() or previous in ",，:：;；|/\\()（）":
            break
        if _HARD_BREAK_RE.match(previous):
            break
        index -= 1
    return index


def _next_clue_start(clues: tuple[Clue, ...], start_index: int, *, default: int) -> int:
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if clue.family == ClueFamily.BREAK:
            return clue.start
        return clue.start
    return default


def _scan_forward_value_end(raw_text: str, start: int, upper_bound: int) -> int:
    index = start
    while index < upper_bound:
        current = raw_text[index]
        if current in ",，;；|/\\()（）":
            break
        if _HARD_BREAK_RE.match(current):
            break
        index += 1
    return index


def _extend_street_tail(raw_text: str, end: int) -> int:
    """扩展路/街后的门牌号，支持：123号、甲1号、之2、3-5号 等变体。"""
    tail = raw_text[end:]
    match = re.match(r"\s*[甲乙丙丁]?\d{1,6}(?:[之\-]\d{1,4})?(?:号|號)?", tail)
    if match is None:
        return end
    return end + match.end()


def _address_metadata(origin_clue: Clue, components: list[dict[str, object]]) -> dict[str, list[str]]:
    component_types: list[str] = []
    component_trace: list[str] = []
    component_key_trace: list[str] = []
    detail_types: list[str] = []
    detail_values: list[str] = []
    for component in components:
        component_type = component["component_type"].value
        value = str(component["value"])
        key = str(component["key"])
        component_types.append(component_type)
        component_trace.append(f"{component_type}:{value}")
        if key:
            component_key_trace.append(f"{component_type}:{key}")
        if bool(component["is_detail"]):
            detail_types.append(component_type)
            detail_values.append(value)
    return {
        "matched_by": [origin_clue.source_kind],
        "address_kind": ["private_address"],
        "address_match_origin": [origin_clue.text if origin_clue.role == ClueRole.LABEL else origin_clue.source_kind],
        "address_component_type": component_types,
        "address_component_trace": component_trace,
        "address_component_key_trace": component_key_trace,
        "address_details_type": detail_types,
        "address_details_text": detail_values,
    }


def _normalize_address_value(component_type: AddressComponentType, raw_value: str) -> str:
    cleaned = _clean_value(raw_value)
    if component_type in _DETAIL_COMPONENTS:
        alnum = "".join(re.findall(r"[A-Za-z0-9]+", cleaned))
        if re.search(r"[A-Za-z]", alnum):
            return alnum
        digits = "".join(re.findall(r"\d+", cleaned))
        if digits:
            return digits
    return cleaned


def _candidate_hard_source_rank(candidate: CandidateDraft) -> int:
    values = candidate.metadata.get("hard_source")
    if not values:
        return 0
    source = str(values[0])
    return {"session": 4, "local": 3, "prompt": 2, "regex": 1}.get(source, 0)


def _organization_suffix_start(text: str) -> int:
    match = _ORG_SUFFIX_RE.search(text)
    return match.start() if match else -1


def _skip_separators(text: str, start: int) -> int:
    index = start
    while index < len(text) and text[index] in " \t\r\n:：-—|,，":
        index += 1
    return index


def _left_expand_text_boundary(raw_text: str, clues: tuple[Clue, ...], start: int) -> int:
    floor = 0
    for clue in reversed(clues):
        if clue.end <= start:
            if clue.family == ClueFamily.BREAK:
                floor = clue.end
                break
            if clue.role == ClueRole.LABEL:
                floor = clue.end
                break
    index = start
    while index > floor:
        previous = raw_text[index - 1]
        if previous in ",，;；|/\\()（）":
            break
        if _HARD_BREAK_RE.match(previous):
            break
        index -= 1
    return index


_ZH_CHAR_RE = re.compile(r"[\u4e00-\u9fff·]")
_EN_NAME_CHAR_RE = re.compile(r"[A-Za-z.'\- ]")


def _extend_name_boundary(raw_text: str, start: int, end: int, clues: tuple[Clue, ...], next_clue_index: int) -> int:
    """从 end 向右扩展，捕获紧邻的姓名字符。

    中文名：从 start 算起最多 4 个汉字（含姓氏），覆盖绝大多数中文姓名。
    英文名：扩展连续英文 token，最多 80 字符。
    """
    # 下一个 non-name clue 的起始位置作为上界。
    upper = len(raw_text)
    for i in range(next_clue_index, len(clues)):
        c = clues[i]
        if c.family == ClueFamily.BREAK:
            upper = min(upper, c.start)
            break
        if c.family != ClueFamily.NAME:
            upper = min(upper, c.start)
            break
    # 判断是中文名还是英文名。
    is_zh = start < len(raw_text) and _ZH_CHAR_RE.match(raw_text[start])
    if is_zh:
        # 中文名：从 start 算起最多 4 个汉字（覆盖复姓 + 双字名）。
        max_end = start
        zh_count = 0
        while max_end < upper and zh_count < 4:
            if _ZH_CHAR_RE.match(raw_text[max_end]):
                zh_count += 1
                max_end += 1
            elif raw_text[max_end] == '·':
                # 少数民族名中的间隔号。
                max_end += 1
            else:
                break
        return max(end, max_end)
    # 英文名：扩展连续英文 token。
    cursor = end
    while cursor < upper:
        ch = raw_text[cursor]
        if _HARD_BREAK_RE.match(ch) or ch in ",，;；|/\\()（）":
            break
        if _EN_NAME_CHAR_RE.match(ch):
            cursor += 1
            continue
        break
    if cursor - start > 80:
        cursor = start + 80
    return cursor


def _clean_value(text: str) -> str:
    cleaned = str(text or "")
    cleaned = cleaned.replace(_OCR_SEMANTIC_BREAK_TOKEN, " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" \t\r\n:：-—|,，;；/\\")
    cleaned = re.sub(r"[。！!？?]+$", "", cleaned).strip()
    return cleaned


def _is_plausible_name(text: str, *, component_hint: NameComponentHint) -> bool:
    if not text or len(text) > 80 or "@" in text:
        return False
    if any(char.isdigit() for char in text):
        return False
    compact_lower = re.sub(r"\s+", " ", text).strip().lower()
    if compact_lower in _NAME_PRONOUNS or text in _NAME_BLOCKLIST_ZH:
        return False
    compact_no_space = re.sub(r"\s+", "", text)
    if _ZH_NAME_RE.fullmatch(compact_no_space):
        return True
    tokens = [token for token in re.split(r"\s+", text) if token]
    if component_hint in {NameComponentHint.FAMILY, NameComponentHint.GIVEN, NameComponentHint.MIDDLE}:
        return len(tokens) == 1 and _EN_NAME_TOKEN_RE.fullmatch(tokens[0]) is not None
    return 1 <= len(tokens) <= 4 and all(_EN_NAME_TOKEN_RE.fullmatch(token) is not None for token in tokens)


def _is_plausible_organization(text: str, *, label_driven: bool) -> bool:
    if not text or len(text) < 2 or len(text) > 120 or "@" in text:
        return False
    if _ADDRESS_SIGNAL_RE.search(text) and not _ORG_SUFFIX_RE.search(text):
        return False
    if label_driven:
        return True
    return _ORG_SUFFIX_RE.search(text) is not None


def _strip_leading_address_label(text: str) -> str:
    stripped = str(text or "")
    while True:
        updated = _LEADING_ADDRESS_LABEL_RE.sub("", stripped, count=1)
        if updated == stripped:
            return stripped
        stripped = updated.strip()
