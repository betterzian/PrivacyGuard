"""Detector 的边界优先 stack 实现。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.infrastructure.pii.detector.candidate_utils import (
    build_address_candidate_from_value,
    build_name_candidate_from_value,
    build_organization_candidate_from_value,
    clean_value,
    has_organization_suffix,
    name_component_hint,
    organization_suffix_start,
    trim_candidate,
)
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    NameComponentHint,
    NegativeDecision,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.negative_utils import evaluate_negative_effect, overlapping_negative_clues
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

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
    negative_clues: tuple[Clue, ...]

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
        hard_clue, hard_index = self._find_bound_hard_clue()
        if hard_clue is None:
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

    def _find_bound_hard_clue(self) -> tuple[Clue | None, int]:
        raw_text = self.context.stream.raw_text
        cursor = self.clue.end
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.family == ClueFamily.BREAK:
                return (None, -1)
            gap_text = raw_text[cursor:clue.start]
            if gap_text and (_HARD_BREAK_RE.search(gap_text) or _OCR_SEMANTIC_BREAK_TOKEN in gap_text):
                return (None, -1)
            if gap_text.strip():
                return (None, -1)
            if clue.role == ClueRole.HARD and clue.attr_type == self.clue.attr_type:
                return (clue, index)
            if clue.role == ClueRole.LABEL and clue.attr_type != self.clue.attr_type:
                return (None, -1)
            if clue.family != ClueFamily.STRUCTURED:
                return (None, -1)
            cursor = max(cursor, clue.end)
        return (None, -1)


@dataclass(slots=True)
class NameStack(BaseStack):
    def run(self) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        start = self._resolve_left_boundary()
        if start is None:
            return None
        end, next_index, consumed_ids = self._resolve_right_boundary()
        # 名字 clue 只覆盖姓氏，需向右扩展以捕获完整姓名（如"张"→"张三"）。
        end = _extend_name_boundary(self.context.stream.raw_text, start, end, self.context.clues, next_index)
        if end <= start:
            return None
        candidate = build_name_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.raw_text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            component_hint=self._component_hint(),
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None
        # 非 label-driven 时，若候选区间被负向 clue 覆盖则拒绝。
        if not is_label_seed:
            effect = evaluate_negative_effect(
                ClueFamily.NAME,
                overlapping_negative_clues(self.context.negative_clues, candidate.start, candidate.end),
            )
            if effect.decision == NegativeDecision.VETO:
                return None
            if effect.decision == NegativeDecision.PENALTY:
                candidate.metadata = merge_metadata(candidate.metadata, {"negative_signals": list(effect.reasons)})
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

    def _resolve_right_boundary(self) -> tuple[int, int, set[str]]:
        raw_text = self.context.stream.raw_text
        end = self.clue.end
        consumed = {self.clue.clue_id}
        index = self.clue_index + 1
        while index < len(self.context.clues):
            clue = self.context.clues[index]
            if clue.family == ClueFamily.BREAK:
                break
            gap_text = raw_text[end:clue.start]
            if gap_text and (_HARD_BREAK_RE.search(gap_text) or _OCR_SEMANTIC_BREAK_TOKEN in gap_text):
                break
            if gap_text.strip():
                break
            if clue.family != ClueFamily.NAME:
                break
            end = max(end, clue.end)
            consumed.add(clue.clue_id)
            index += 1
        return (end, index, consumed)


@dataclass(slots=True)
class OrganizationStack(BaseStack):
    def run(self) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        if is_label_seed:
            start = _skip_separators(self.context.stream.raw_text, self.clue.end)
            end, next_index, consumed_ids = self._resolve_right_boundary()
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
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.raw_text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None
        # 非 label-driven 的 suffix 触发，若被负向 clue 覆盖则拒绝。
        if not is_label_seed:
            effect = evaluate_negative_effect(
                ClueFamily.ORGANIZATION,
                overlapping_negative_clues(self.context.negative_clues, candidate.start, candidate.end),
            )
            if effect.decision == NegativeDecision.VETO:
                return None
            if effect.decision == NegativeDecision.PENALTY:
                candidate.metadata = merge_metadata(candidate.metadata, {"negative_signals": list(effect.reasons)})
        return StackRun(ClueFamily.ORGANIZATION, candidate, consumed_ids, handled, next_index)

    def _resolve_right_boundary(self) -> tuple[int, int, set[str]]:
        raw_text = self.context.stream.raw_text
        end = self.clue.end
        consumed = {self.clue.clue_id}
        index = self.clue_index + 1
        while index < len(self.context.clues):
            clue = self.context.clues[index]
            if clue.family == ClueFamily.BREAK:
                break
            gap_text = raw_text[end:clue.start]
            if gap_text and (_HARD_BREAK_RE.search(gap_text) or _OCR_SEMANTIC_BREAK_TOKEN in gap_text):
                break
            if gap_text.strip():
                break
            if clue.family != ClueFamily.ORGANIZATION:
                break
            end = max(end, clue.end)
            consumed.add(clue.clue_id)
            index += 1
        return (end, index, consumed)


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
        text = clean_value(raw_text[final_start:final_end])
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
        effect = evaluate_negative_effect(
            ClueFamily.ADDRESS,
            overlapping_negative_clues(self.context.negative_clues, candidate.start, candidate.end),
        )
        if effect.decision == NegativeDecision.VETO:
            return None
        if effect.decision == NegativeDecision.PENALTY:
            candidate.metadata = merge_metadata(candidate.metadata, {"negative_signals": list(effect.reasons)})
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
        suffix_start = organization_suffix_start(organization.text)
        if suffix_start <= 0:
            return ConflictOutcome(incoming=organization if incoming is organization else None, drop_existing=name is existing)
        if organization is incoming:
            trimmed = trim_candidate(name, raw_text, start=name.start, end=min(name.end, organization.start + suffix_start))
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = trim_candidate(name, raw_text, start=name.start, end=min(name.end, organization.start + suffix_start))
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
            return trim_candidate(candidate, raw_text, start=blocker.end, end=candidate.end)
        return trim_candidate(candidate, raw_text, start=candidate.start, end=blocker.start)


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
    cleaned = clean_value(raw_value)
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
    is_zh = start < len(raw_text) and re.match(r"[\u4e00-\u9fff·]", raw_text[start])
    if is_zh:
        # 中文名：从 start 算起最多 4 个汉字（覆盖复姓 + 双字名）。
        max_end = start
        zh_count = 0
        while max_end < upper and zh_count < 4:
            if re.match(r"[\u4e00-\u9fff·]", raw_text[max_end]):
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
        if re.match(r"[A-Za-z.'\- ]", ch):
            cursor += 1
            continue
        break
    if cursor - start > 80:
        cursor = start + 80
    return cursor
