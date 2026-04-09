"""地址 stack 与地址专属 helper。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value, has_address_signal, trim_candidate
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, CandidateDraft, ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_keyword_groups,
    load_zh_address_keyword_groups,
 )
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _is_stop_control_clue,
    _skip_separators,
    _unit_index_at_or_after,
    _unit_index_left_of,
    _unit_char_end,
    _unit_char_start,
    is_break_clue,
    is_control_clue,
    is_negative_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCR_INLINE_GAP_TOKEN,
    OCR_BREAK,
    is_any_break,
    is_hard_break,
    is_soft_break,
)

_TIER_ADMIN = 1
_TIER_STREET = 2
_TIER_DETAIL = 3
_TIER_POSTAL = 4

_COMPONENT_TIER: dict[AddressComponentType, int] = {
    AddressComponentType.PROVINCE: _TIER_ADMIN,
    AddressComponentType.STATE: _TIER_ADMIN,
    AddressComponentType.CITY: _TIER_ADMIN,
    AddressComponentType.DISTRICT: _TIER_ADMIN,
    AddressComponentType.STREET_ADMIN: _TIER_ADMIN,
    AddressComponentType.TOWN: _TIER_ADMIN,
    AddressComponentType.VILLAGE: _TIER_ADMIN,
    AddressComponentType.ROAD: _TIER_STREET,
    AddressComponentType.STREET: _TIER_STREET,
    AddressComponentType.COMPOUND: _TIER_STREET,
    AddressComponentType.BUILDING: _TIER_DETAIL,
    AddressComponentType.UNIT: _TIER_DETAIL,
    AddressComponentType.FLOOR: _TIER_DETAIL,
    AddressComponentType.ROOM: _TIER_DETAIL,
    AddressComponentType.POSTAL_CODE: _TIER_POSTAL,
}

_MAX_TIER_BACKTRACK = 1
_DETAIL_COMPONENTS = {
    AddressComponentType.BUILDING,
    AddressComponentType.UNIT,
    AddressComponentType.FLOOR,
    AddressComponentType.ROOM,
}
def _en_prefix_keywords() -> set[str]:
    """从外部 lexicon 派生英文前缀关键字集合（unit/floor/room/# 等）。"""
    keywords: set[str] = set()
    for group in load_en_address_keyword_groups():
        if group.component_type not in {AddressComponentType.UNIT, AddressComponentType.FLOOR, AddressComponentType.ROOM}:
            continue
        for kw in group.keywords:
            text = str(kw or "").strip().lower()
            if text:
                keywords.add(text)
    # 兼容 unit 组里可能存在的 '#'
    keywords.add("#")
    return keywords


_PREFIX_EN_KEYWORDS = _en_prefix_keywords()
_EN_VALUE_KEY_GAP_RE = re.compile(r"^[ ]*$")
_SINGLE_EVIDENCE_ADMIN = {
    AddressComponentType.PROVINCE,
    AddressComponentType.STATE,
    AddressComponentType.CITY,
}

# 地址内可吸收的非 ADDRESS attr_type——数字片段和字母数字片段。
_ABSORBABLE_DIGIT_ATTR_TYPES = frozenset({PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM})


def _is_absorbable_digit_clue(clue: Clue) -> bool:
    """判断非 ADDRESS clue 是否为可被地址栈吸收的数字片段。"""
    return clue.attr_type in _ABSORBABLE_DIGIT_ATTR_TYPES


@dataclass(slots=True)
class AddressStack(BaseStack):
    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """地址回缩：截断后若失去地址信号则放弃。"""
        candidate = run.candidate
        stream = self.context.stream
        if blocker_start <= candidate.unit_start:
            new_unit_start, new_unit_end = blocker_end, candidate.unit_end
        elif blocker_end >= candidate.unit_end:
            new_unit_start, new_unit_end = candidate.unit_start, blocker_start
        else:
            new_unit_start, new_unit_end = candidate.unit_start, blocker_start
        trimmed = trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_end),
            unit_start=new_unit_start,
            unit_end=new_unit_end,
        )
        if trimmed is None:
            return None
        if not has_address_signal(trimmed.text) and not trimmed.label_driven:
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def run(self) -> StackRun | None:
        """地址 stack 主入口。"""
        if self.clue.strength == ClaimStrength.HARD:
            return self._build_direct_run()

        raw_text = self.context.stream.text
        stream = self.context.stream
        locale = self._value_locale()
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}

        if is_label_seed:
            address_start = _skip_separators(raw_text, self.clue.end)
            start_unit = _unit_index_at_or_after(stream, address_start)
            seed_index = _label_seed_address_index(self.context.clues, start_unit, max_units=6)
            if seed_index is None:
                return None
            scan_index = seed_index
            consumed_ids: set[str] = {self.clue.clue_id}
            handled_labels: set[str] = {self.clue.clue_id}
            evidence_count = 1
        else:
            address_start = self._seed_left_boundary()
            scan_index = self.clue_index
            consumed_ids = set()
            handled_labels = set()
            evidence_count = 0
        if address_start is None:
            return None

        components: list[dict[str, object]] = []
        last_end = address_start
        last_tier = 0
        pending_value: dict[AddressComponentType, Clue] = {}
        index = scan_index
        negative_spans: list[tuple[int, int]] = []
        last_consumed_address_clue: Clue | None = None
        last_value_clue: Clue | None = None
        # 记录已吸收的数字 clue 的最远 unit_end，用于 gap 锚点。
        absorbed_digit_unit_end: int = 0

        while index < len(self.context.clues):
            clue = self.context.clues[index]

            if is_break_clue(clue):
                break
            if is_negative_clue(clue):
                negative_spans.append((clue.start, clue.end))
                index += 1
                continue
            if clue.attr_type is None:
                index += 1
                continue
            if clue.attr_type != PIIAttributeType.ADDRESS:
                # 数字/字母数字片段不终止地址扫描——地址常含门牌号、楼号等数字。
                if _is_absorbable_digit_clue(clue):
                    absorbed_digit_unit_end = max(absorbed_digit_unit_end, clue.unit_end)
                    last_end = max(last_end, clue.end)
                    index += 1
                    continue
                break
            if clue.role == ClueRole.LABEL:
                index += 1
                continue
            if clue.start < address_start:
                index += 1
                continue

            # 6 个 unit 之内没有新的 clue 则截止（按 unit 差计数，含空格 unit）。
            # gap 锚点取 last_consumed_address_clue 与已吸收数字位置的较远者。
            if last_consumed_address_clue is not None:
                gap_anchor = max(last_consumed_address_clue.unit_end, absorbed_digit_unit_end)
                if clue.unit_start - gap_anchor > 6:
                    break

            comp_type = clue.component_type
            if comp_type is None:
                index += 1
                continue
            tier = _COMPONENT_TIER.get(comp_type, 999)
            if last_tier and tier < last_tier - _MAX_TIER_BACKTRACK:
                pass

            consumed_ids.add(clue.clue_id)
            last_consumed_address_clue = clue

            if clue.role == ClueRole.VALUE:
                if comp_type in pending_value:
                    # 同层级连续 VALUE：旧 VALUE 不再继续 pending，直接按其层级落成 component，并自动补一个默认 key。
                    previous = pending_value[comp_type]
                    default_key = _default_key_for_component_type(comp_type, locale)
                    standalone = _build_standalone_address_component_with_key(previous, comp_type, key=default_key)
                    if standalone is not None:
                        components.append(standalone)
                        evidence_count += 1
                        last_end = max(last_end, int(standalone["end"]))
                    del pending_value[comp_type]
                self._flush_pending_values(pending_value, tier, components)
                pending_value[comp_type] = clue
                last_value_clue = clue
                last_end = max(last_end, clue.end)
                last_tier = tier
                index += 1
                continue

            same_tier_value = pending_value.pop(comp_type, None)
            flushed = self._flush_pending_values(pending_value, tier, components)
            evidence_count += flushed

            if same_tier_value is not None:
                component, merged = _build_value_key_component(
                    raw_text,
                    same_tier_value,
                    clue,
                    comp_type,
                    locale=locale,
                )
                if merged:
                    if component is not None:
                        components.append(component)
                        evidence_count += 1
                        last_end = max(last_end, int(component["end"]))
                        last_tier = tier
                else:
                    standalone = _build_standalone_address_component(same_tier_value, comp_type)
                    if standalone is not None:
                        components.append(standalone)
                        evidence_count += 1
                        last_end = max(last_end, int(standalone["end"]))
                    key_comp = self._build_key_component(raw_text, clue, comp_type, index, locale)
                    if key_comp is not None:
                        components.append(key_comp)
                        evidence_count += 1
                        last_end = max(last_end, int(key_comp["end"]))
                    last_tier = tier
            else:
                component = None
                if last_value_clue is not None and clue.unit_start - last_value_clue.unit_end <= 1:
                    component = _build_cross_tier_value_key_component(raw_text, last_value_clue, clue, comp_type)
                if component is None:
                    component = self._build_key_component(raw_text, clue, comp_type, index, locale)
                if component is not None:
                    components.append(component)
                    evidence_count += 1
                    last_end = max(last_end, int(component["end"]))
                    last_tier = tier
            index += 1

        evidence_count += self._flush_all_pending(pending_value, components)

        if not components:
            return None
        if negative_spans:
            components = _pop_components_overlapping_negative(components, negative_spans)
            if not components:
                return None

        components = _extend_components_with_digit_tail(components, stream)
        if not _meets_commit_threshold(
            evidence_count,
            components,
            locale,
            protection_level=self.context.protection_level,
        ):
            return None

        final_start = min(int(component["start"]) for component in components)
        final_end = max(int(component["end"]) for component in components)
        text = clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        unit_start, unit_end = _char_span_to_unit_span(
            self.context.stream,
            absolute_start,
            absolute_start + len(text),
        )
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_start + len(text),
            unit_start=unit_start,
            unit_end=unit_end,
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata=_address_metadata(self.clue, components),
            label_clue_ids=handled_labels,
            label_driven=(self.clue.role == ClueRole.LABEL),
        )
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=handled_labels,
            next_index=index,
        )

    def _flush_pending_values(
        self,
        pending: dict[AddressComponentType, Clue],
        current_tier: int,
        components: list[dict[str, object]],
    ) -> int:
        flushed = 0
        to_remove: list[AddressComponentType] = []
        for comp_type, value_clue in pending.items():
            value_tier = _COMPONENT_TIER.get(comp_type, 999)
            if value_tier == current_tier:
                continue
            component = _build_standalone_address_component(value_clue, comp_type)
            if component is not None:
                components.append(component)
                flushed += 1
            to_remove.append(comp_type)
        for comp_type in to_remove:
            del pending[comp_type]
        return flushed

    def _flush_all_pending(
        self,
        pending: dict[AddressComponentType, Clue],
        components: list[dict[str, object]],
    ) -> int:
        flushed = 0
        for comp_type, value_clue in pending.items():
            component = _build_standalone_address_component(value_clue, comp_type)
            if component is not None:
                components.append(component)
                flushed += 1
        pending.clear()
        return flushed

    def _build_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        locale: str,
    ) -> dict[str, object] | None:
        key_text = clue.text
        if key_text.lower() in _PREFIX_EN_KEYWORDS:
            value_start = _skip_separators(raw_text, clue.end)
            value_end = _scan_forward_value_end(
                raw_text,
                value_start,
                upper_bound=min(len(raw_text), clue.end + 30),
            )
            if value_end <= value_start:
                return None
            value = _normalize_address_value(comp_type, raw_text[value_start:value_end])
            if not value:
                return None
            return {
                "component_type": comp_type,
                "start": clue.start,
                "end": value_end,
                "value": value,
                "key": key_text,
                "is_detail": comp_type in _DETAIL_COMPONENTS,
            }

        floor = _left_address_floor(self.context.clues, clue_index)
        if locale.startswith("en"):
            expand_start = _left_expand_en_word(raw_text, clue.start, floor)
        else:
            # 中文 key：优先吸收 key 左侧紧邻的 digit_run unit（如 “100号”“3楼”“201室”）。
            stream = self.context.stream
            left_ui = _unit_index_left_of(stream, clue.start)
            if 0 <= left_ui < len(stream.units) and stream.units[left_ui].kind == "digit_run":
                expand_start = stream.units[left_ui].char_start
            else:
                expand_start = _left_expand_zh_chars(raw_text, clue.start, floor, max_chars=2)

        value = _normalize_address_value(comp_type, raw_text[expand_start:clue.start])
        if not value:
            return None
        return {
            "component_type": comp_type,
            "start": expand_start,
            "end": clue.end,
            "value": value,
            "key": key_text,
            "is_detail": comp_type in _DETAIL_COMPONENTS,
        }

    def _seed_left_boundary(self) -> int | None:
        if self.clue.role in {ClueRole.VALUE, ClueRole.KEY}:
            return self.clue.start
        return None


def _next_address_index(
    clues: tuple[Clue, ...],
    start_index: int,
    *,
    locale: str,
    raw_text: str,
) -> int | None:
    last_pos = clues[start_index - 1].end if start_index > 0 else 0
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if is_break_clue(clue) or is_negative_clue(clue):
            return None
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role == ClueRole.LABEL:
            continue
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            return index
        if is_control_clue(clue):
            continue
        gap_text = raw_text[last_pos:clue.start]
        if locale.startswith("en"):
            if len(gap_text.split()) > 5:
                return None
        else:
            if len(gap_text) > 10:
                return None
    return None


def _has_nearby_address_clue(
    clues: tuple[Clue, ...],
    start_index: int,
    last_end: int,
    *,
    locale: str,
    raw_text: str | None = None,
) -> bool:
    for index in range(start_index, len(clues)):
        clue = clues[index]
        gap_chars = clue.start - last_end
        if gap_chars > 30:
            return False
        if is_break_clue(clue) or is_negative_clue(clue):
            return False
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            if locale.startswith("en") and raw_text is not None:
                gap_text = raw_text[last_end:clue.start]
                if len(gap_text.split()) > 3:
                    return False
            elif gap_chars > 6:
                return False
            return True
    return False


def _address_gap_too_wide(gap_text: str, locale: str) -> bool:
    if not gap_text:
        return False
    if OCR_BREAK in gap_text or _OCR_INLINE_GAP_TOKEN in gap_text:
        return True
    if any(is_hard_break(ch) for ch in gap_text):
        return True
    punct_count = sum(1 for ch in gap_text if is_soft_break(ch))
    if punct_count > 1:
        return True
    if locale.startswith("en"):
        return len(gap_text.split()) > 3
    return len(gap_text) > 6


def _build_value_key_component(
    raw_text: str,
    value_clue: Clue,
    key_clue: Clue,
    comp_type: AddressComponentType,
    locale: str,
) -> tuple[dict[str, object] | None, bool]:
    if value_clue.end <= key_clue.start:
        gap = raw_text[value_clue.end:key_clue.start]
    elif key_clue.end <= value_clue.start:
        gap = raw_text[key_clue.end:value_clue.start]
    else:
        gap = ""

    if gap:
        if locale.startswith("en"):
            if not _EN_VALUE_KEY_GAP_RE.fullmatch(gap):
                return None, False
        else:
            return None, False

    start = min(value_clue.start, key_clue.start)
    end = max(value_clue.end, key_clue.end)
    value = _normalize_address_value(comp_type, value_clue.text)
    if not value:
        return None, True
    return {
        "component_type": comp_type,
        "start": start,
        "end": end,
        "value": value,
        "key": key_clue.text,
        "is_detail": comp_type in _DETAIL_COMPONENTS,
    }, True


def _label_seed_address_index(clues: tuple[Clue, ...], start_unit: int, *, max_units: int) -> int | None:
    """label 起栈：start_unit 覆盖的 VALUE 优先，否则 max_units 内必须有 KEY。"""
    key_index: int | None = None
    for idx, clue in enumerate(clues):
        if clue.attr_type != PIIAttributeType.ADDRESS:
            continue
        if clue.role == ClueRole.LABEL:
            continue
        if clue.role == ClueRole.VALUE and clue.unit_start <= start_unit < clue.unit_end:
            return idx
        if clue.role == ClueRole.KEY and clue.unit_start >= start_unit and clue.unit_start - start_unit <= max_units:
            if key_index is None or clue.unit_start < clues[key_index].unit_start:
                key_index = idx
    return key_index


def _build_cross_tier_value_key_component(
    raw_text: str,
    value_clue: Clue,
    key_clue: Clue,
    comp_type: AddressComponentType,
) -> dict[str, object] | None:
    del raw_text
    start = min(value_clue.start, key_clue.start)
    end = max(value_clue.end, key_clue.end)
    value = _normalize_address_value(comp_type, value_clue.text)
    if not value:
        return None
    return {
        "component_type": comp_type,
        "start": start,
        "end": end,
        "value": value,
        "key": key_clue.text,
        "is_detail": comp_type in _DETAIL_COMPONENTS,
    }


def _overlaps_any_span(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _pop_components_overlapping_negative(
    components: list[dict[str, object]],
    negative_spans: list[tuple[int, int]],
) -> list[dict[str, object]]:
    """仅按最右组件判断 negative，避免中间命中连坐整个右尾。"""
    ordered = sorted(components, key=lambda c: (int(c["end"]), int(c["start"])))
    while ordered:
        last = ordered[-1]
        if not _overlaps_any_span(int(last["start"]), int(last["end"]), negative_spans):
            return ordered
        ordered.pop()
    return []


_DIGIT_TAIL_RE = re.compile(r"^\s*(\d{1,4})(?:-(\d{1,4}))?(?:-(\d{1,4}))?\s*$")


def _parse_digit_tail(text: str) -> tuple[str, ...] | None:
    """解析 digit_run unit.text（允许含 '-'），最多 3 段，每段 ≤4 位。"""
    cleaned = str(text or "").strip()
    match = _DIGIT_TAIL_RE.fullmatch(cleaned)
    if match is None:
        return None
    parts = tuple(p for p in match.groups() if p is not None)
    if not parts:
        return None
    if cleaned.count("-") > 2:
        return None
    return parts


def _digit_tail_next_component_type(prev: AddressComponentType, first_segment: str) -> AddressComponentType:
    """由前一 component_type 推导尾随数字的第一个层级。"""
    if prev in {AddressComponentType.ROAD, AddressComponentType.STREET, AddressComponentType.COMPOUND}:
        return AddressComponentType.BUILDING
    if prev == AddressComponentType.NUMBER:
        return AddressComponentType.BUILDING
    if prev == AddressComponentType.BUILDING:
        return AddressComponentType.ROOM if len(first_segment) >= 3 else AddressComponentType.UNIT
    if prev == AddressComponentType.UNIT:
        return AddressComponentType.ROOM if len(first_segment) >= 3 else AddressComponentType.FLOOR
    if prev == AddressComponentType.FLOOR:
        return AddressComponentType.ROOM
    return AddressComponentType.BUILDING


def _digit_tail_step_down(comp_type: AddressComponentType) -> AddressComponentType:
    if comp_type == AddressComponentType.BUILDING:
        return AddressComponentType.UNIT
    if comp_type == AddressComponentType.UNIT:
        return AddressComponentType.ROOM
    if comp_type == AddressComponentType.FLOOR:
        return AddressComponentType.ROOM
    if comp_type == AddressComponentType.NUMBER:
        return AddressComponentType.BUILDING
    return AddressComponentType.ROOM


def _extend_components_with_digit_tail(components: list[dict[str, object]], stream) -> list[dict[str, object]]:
    if not components or not getattr(stream, "units", None):
        return components
    last = max(components, key=lambda c: (int(c["end"]), int(c["start"])))
    end_char = int(last["end"])
    # 以 end_char 为锚点，取“起始位置在 end_char 或其右侧”的第一个 unit 作为紧邻候选。
    if end_char >= len(stream.text):
        return components
    next_ui = _unit_index_at_or_after(stream, end_char)
    if next_ui >= len(stream.units):
        return components
    next_unit = stream.units[next_ui]
    if next_unit.kind != "digit_run":
        return components
    parts = _parse_digit_tail(next_unit.text)
    if parts is None:
        return components
    prev_type = last.get("component_type")
    if not isinstance(prev_type, AddressComponentType):
        return components
    current_type = _digit_tail_next_component_type(prev_type, parts[0])
    new_components: list[dict[str, object]] = []
    cursor = next_unit.char_start
    for idx, seg in enumerate(parts):
        seg_start = stream.text.find(seg, cursor, next_unit.char_end)
        if seg_start < 0:
            seg_start = cursor
        seg_end = seg_start + len(seg)
        new_components.append(
            {
                "component_type": current_type,
                "start": seg_start,
                "end": seg_end,
                "value": seg,
                "key": "",
                "is_detail": current_type in _DETAIL_COMPONENTS,
            }
        )
        cursor = seg_end
        if idx < len(parts) - 1:
            current_type = _digit_tail_step_down(current_type)
    return [*components, *new_components]


def _left_expand_en_word(raw_text: str, pos: int, floor: int) -> int:
    cursor = pos
    while cursor > floor and raw_text[cursor - 1] in " \t":
        cursor -= 1
    while cursor > floor and raw_text[cursor - 1].isalnum():
        cursor -= 1
    return cursor


def _left_expand_zh_chars(raw_text: str, pos: int, floor: int, *, max_chars: int) -> int:
    cursor = pos
    count = 0
    while cursor > floor and count < max_chars:
        ch = raw_text[cursor - 1]
        if "\u4e00" <= ch <= "\u9fff":
            cursor -= 1
            count += 1
        else:
            break
    return cursor


def _meets_commit_threshold(
    evidence_count: int,
    components: list[dict[str, object]],
    locale: str,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
) -> bool:
    del locale
    if evidence_count <= 0:
        return False
    if protection_level == ProtectionLevel.STRONG:
        return True
    if protection_level == ProtectionLevel.BALANCED:
        if evidence_count >= 2:
            return True
        return any(component["component_type"] in _SINGLE_EVIDENCE_ADMIN for component in components)
    return evidence_count >= 2


def _build_standalone_address_component(clue: Clue, component_type: AddressComponentType) -> dict[str, object] | None:
    value = _normalize_address_value(component_type, clue.text)
    if not value:
        return None
    return {
        "component_type": component_type,
        "start": clue.start,
        "end": clue.end,
        "value": value,
        "key": "",
        "is_detail": component_type in _DETAIL_COMPONENTS,
    }


def _build_standalone_address_component_with_key(
    clue: Clue,
    component_type: AddressComponentType,
    *,
    key: str,
) -> dict[str, object] | None:
    component = _build_standalone_address_component(clue, component_type)
    if component is None:
        return None
    component["key"] = str(key or "")
    return component


@lru_cache(maxsize=1)
def _default_zh_address_keys() -> dict[AddressComponentType, str]:
    """从 `zh_address_keywords.json` 推导每个 component_type 的默认 key（用于 value-only 的自动补全）。"""
    keys: dict[AddressComponentType, str] = {}
    for group in load_zh_address_keyword_groups():
        if not group.keywords:
            continue
        # 选择更通用的短 key（如 “区”“路”“号”），避免 “新区/大道/街道” 这类更具体后缀。
        keys[group.component_type] = min(group.keywords, key=len)
    return keys


@lru_cache(maxsize=1)
def _default_en_address_keys() -> dict[AddressComponentType, str]:
    """从 `en_address_keywords.json` 推导每个 component_type 的默认 key。"""
    keys: dict[AddressComponentType, str] = {}
    for group in load_en_address_keyword_groups():
        if not group.keywords:
            continue
        keys[group.component_type] = min(group.keywords, key=len)
    return keys


def _default_key_for_component_type(component_type: AddressComponentType, locale: str) -> str:
    if locale.startswith("en"):
        return _default_en_address_keys().get(component_type, "")
    return _default_zh_address_keys().get(component_type, "")


def _left_address_floor(clues: tuple[Clue, ...], clue_index: int) -> int:
    for index in range(clue_index - 1, -1, -1):
        clue = clues[index]
        if _is_stop_control_clue(clue):
            return clue.end
        if is_control_clue(clue):
            continue
        if clue.attr_type != PIIAttributeType.ADDRESS:
            return clue.end
    return 0


def _scan_forward_value_end(raw_text: str, start: int, upper_bound: int) -> int:
    index = start
    while index < upper_bound:
        if is_any_break(raw_text[index]):
            break
        index += 1
    return index


def _extend_street_tail(raw_text: str, end: int) -> int:
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
