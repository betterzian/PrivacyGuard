"""地址 stack 的共享策略辅助。

这里只放中英文地址 stack 都会使用、且不表达具体 grammar 偏向的规则：
1. clue 间距、search stop 与 LABEL 起栈。
2. 链式可接性与共享上下文结构。
3. 数字尾补全与 bridge 判定。
4. 通用 value 归一与扫描边界。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    Clue,
    ClueFamily,
    ClueRole,
    PIIAttributeType,
    StreamInput,
    StreamUnit,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _DETAIL_COMPONENTS,
    _DIGIT_TAIL_TRIGGER_TYPES,
    _DraftComponent,
    _ParseState,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_index_at_or_after, is_break_clue, is_negative_clue
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK, is_any_break, is_soft_break

_SENTINEL_STOP = object()
_SENTINEL_IGNORE = object()

_ABSORBABLE_DIGIT_ATTR_TYPES = frozenset({PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM})


def _is_absorbable_digit_clue(clue: Clue) -> bool:
    if clue.attr_type not in _ABSORBABLE_DIGIT_ATTR_TYPES:
        return False
    digits = (clue.source_metadata.get("pure_digits") or [""])[0]
    return len(digits) <= 5


def _clue_unit_gap(left: Clue, right: Clue, stream: StreamInput | None = None) -> int:
    """两个 clue 之间的有效非空白 unit 数。"""
    if stream is not None and stream.units:
        gap_start = left.unit_end
        gap_end = right.unit_start
        count = 0
        for ui in range(gap_start, min(gap_end, len(stream.units))):
            if stream.units[ui].kind not in {"space", "inline_gap"}:
                count += 1
        return count
    return max(0, right.unit_start - left.unit_end)


def _is_inline_gap_unit(unit: StreamUnit) -> bool:
    return unit.kind == "inline_gap"


def _is_space_unit(unit: StreamUnit) -> bool:
    return unit.kind == "space"


def _is_comma_unit(unit: StreamUnit) -> bool:
    return unit.text in ",，"


def _is_soft_break_unit(unit: StreamUnit) -> bool:
    return len(unit.text) == 1 and is_soft_break(unit.text)


def _is_search_stop_unit(unit: StreamUnit) -> bool:
    if _is_inline_gap_unit(unit):
        return False
    if unit.kind in {"space", "ocr_break"}:
        return True
    return any(is_any_break(char) for char in unit.text)


def _skip_from_char_by_units(
    stream: StreamInput,
    start_char: int,
    *,
    allow_space: bool,
    allow_comma: bool,
    allow_soft_break: bool,
    allow_inline_gap: bool,
) -> int:
    """从给定字符位置开始，只连续跳过允许的 unit。"""
    if not stream.units:
        return max(0, start_char)
    cursor = max(0, start_char)
    ui = _unit_index_at_or_after(stream, cursor)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start < cursor:
            ui += 1
            continue
        if allow_inline_gap and _is_inline_gap_unit(unit):
            cursor = unit.char_end
            ui += 1
            continue
        if allow_space and _is_space_unit(unit):
            cursor = unit.char_end
            ui += 1
            continue
        if allow_comma and _is_comma_unit(unit):
            cursor = unit.char_end
            ui += 1
            continue
        if allow_soft_break and _is_soft_break_unit(unit):
            cursor = unit.char_end
            ui += 1
            continue
        break
    return cursor


def _label_seed_start_char(stream: StreamInput, start_char: int) -> int:
    """LABEL/START 首次起栈时允许跳过的分隔。"""
    return _skip_from_char_by_units(
        stream,
        start_char,
        allow_space=True,
        allow_comma=True,
        allow_soft_break=True,
        allow_inline_gap=True,
    )


def _label_start_route_locale(
    clues: tuple[Clue, ...],
    stream: StreamInput,
    start_char: int,
    start_unit: int,
    *,
    max_units: int,
) -> str:
    """按固定短窗口路由 LABEL/START 场景的中英文地址栈。"""
    probe_unit_end = min(len(stream.units), max(0, start_unit) + max_units)
    for clue in clues:
        if clue.family != ClueFamily.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        if clue.unit_start >= probe_unit_end or clue.unit_end <= start_unit:
            continue
        raw_text = stream.text[max(start_char, clue.start):clue.end]
        clue_text = clue.text or ""
        if any("\u4e00" <= char <= "\u9fff" for char in raw_text) or any(
            "\u4e00" <= char <= "\u9fff" for char in clue_text
        ):
            return "zh"
    return "en"


def _first_address_clue_index_after(clues: tuple[Clue, ...], start_char: int) -> int | None:
    """返回给定起点之后第一个地址 clue，下游自行决定如何消费。"""
    for index, clue in enumerate(clues):
        if clue.family != ClueFamily.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        if clue.end <= start_char:
            continue
        return index
    return None


def _start_after_component_end(stream: StreamInput, component_end: int) -> int:
    """已有 component 后的新起点。"""
    return _skip_from_char_by_units(
        stream,
        component_end,
        allow_space=True,
        allow_comma=True,
        allow_soft_break=False,
        allow_inline_gap=True,
    )


def _normalize_address_value(component_type: AddressComponentType, raw_value: str) -> str:
    cleaned = clean_value(raw_value)
    if component_type == AddressComponentType.HOUSE_NUMBER:
        return "".join(char for char in cleaned if char.isalnum())
    if component_type == AddressComponentType.POSTAL_CODE:
        return re.sub(r"[^0-9-]", "", cleaned)
    if component_type == AddressComponentType.COUNTRY:
        return cleaned
    if component_type in _DETAIL_COMPONENTS:
        alnum = "".join(char for char in cleaned if char.isalnum())
        if any(char.isalpha() for char in alnum):
            return alnum
        digits = "".join(char for char in cleaned if char.isdigit())
        if digits:
            return digits
        return ""
    return cleaned


def _span_has_search_stop_unit(stream: StreamInput, start_char: int, end_char: int) -> bool:
    """原始文本区间内是否出现会截断 component 搜索的 unit。"""
    if end_char <= start_char or not stream.units:
        return False
    ui = _unit_index_at_or_after(stream, start_char)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= end_char:
            break
        if _is_search_stop_unit(unit):
            return True
        ui += 1
    return False


def _span_has_non_comma_search_stop_unit(stream: StreamInput, start_char: int, end_char: int) -> bool:
    """区间内是否存在除逗号外的停止分隔。"""
    if end_char <= start_char or not stream.units:
        return False
    ui = _unit_index_at_or_after(stream, start_char)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= end_char:
            break
        if _is_inline_gap_unit(unit):
            ui += 1
            continue
        if unit.kind in {"space", "ocr_break"}:
            return True
        if _is_comma_unit(unit):
            ui += 1
            continue
        if any(is_any_break(char) for char in unit.text):
            return True
        ui += 1
    return False


def _clue_gap_has_search_stop(left: Clue, right: Clue, stream: StreamInput | None) -> bool:
    if stream is None:
        return False
    return _span_has_search_stop_unit(stream, left.end, right.start)


def _state_next_component_start(
    state: _ParseState,
    stream: StreamInput,
    *,
    address_start: int | None = None,
) -> int | None:
    if state.deferred_chain:
        return state.deferred_chain[-1][1].end
    if state.components:
        return _start_after_component_end(stream, state.components[-1].end)
    return address_start


def _is_key_key_gap_text_unit_allowed(unit: StreamUnit) -> bool:
    if unit.kind == "cjk_char":
        return True
    if unit.kind == "ascii_word":
        return len(unit.text) >= 3
    return False


def _last_non_space_unit_in_span(clue: Clue, stream: StreamInput) -> StreamUnit | None:
    for ui in range(min(clue.unit_end, len(stream.units)) - 1, clue.unit_start - 1, -1):
        unit = stream.units[ui]
        if unit.kind not in {"space", "inline_gap"}:
            return unit
    return None


def _first_non_space_unit_in_span(clue: Clue, stream: StreamInput) -> StreamUnit | None:
    for ui in range(clue.unit_start, min(clue.unit_end, len(stream.units))):
        unit = stream.units[ui]
        if unit.kind not in {"space", "inline_gap"}:
            return unit
    return None


def _key_key_chain_gap_allowed(left: Clue, right: Clue, stream: StreamInput | None) -> bool:
    if left.text == right.text:
        return False
    if _clue_gap_has_search_stop(left, right, stream):
        return False
    gap = _clue_unit_gap(left, right, stream)
    if gap == 0:
        return True
    if gap != 1:
        return False
    if stream is None or not stream.units:
        return False
    non_space = [
        stream.units[ui]
        for ui in range(left.unit_end, min(right.unit_start, len(stream.units)))
        if stream.units[ui].kind != "space"
    ]
    if len(non_space) != 1:
        return False
    gap_unit = non_space[0]
    if not _is_key_key_gap_text_unit_allowed(gap_unit):
        return False
    left_tail = _last_non_space_unit_in_span(left, stream)
    right_head = _first_non_space_unit_in_span(right, stream)
    if left_tail is None or right_head is None:
        return False
    if left_tail.kind == right_head.kind == "ascii_word":
        return gap_unit.kind == "ascii_word"
    if left_tail.kind == right_head.kind == "cjk_char":
        return gap_unit.kind in {"cjk_char", "ascii_word"}
    return False


@dataclass(slots=True)
class _RoutingContext:
    chain: list[Clue]
    previous_component_type: AddressComponentType | None
    previous_component_end: int | None
    ignored_key_indices: set[int]
    clues: tuple[Clue, ...]
    raw_text: str
    stream: StreamInput


def _scan_forward_value_end(
    raw_text: str,
    start: int,
    upper_bound: int,
    stream: StreamInput | None = None,
) -> int:
    if stream is None or not stream.units:
        index = start
        while index < upper_bound:
            if raw_text.startswith(OCR_BREAK, index):
                break
            if raw_text[index].isspace() or is_any_break(raw_text[index]):
                break
            index += 1
        return index

    cursor = start
    ui = _unit_index_at_or_after(stream, start)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= upper_bound:
            break
        if unit.char_end <= cursor:
            ui += 1
            continue
        if _is_search_stop_unit(unit):
            break
        cursor = min(unit.char_end, upper_bound)
        ui += 1
    return cursor


def _chain_can_accept(chain: list[Clue], clue: Clue, stream: StreamInput) -> bool:
    """判断 clue 能否加入当前 deferred chain。"""
    if not chain:
        return False
    last = chain[-1]
    if _clue_gap_has_search_stop(last, clue, stream):
        return False
    gap = _clue_unit_gap(last, clue, stream)
    if last.role == ClueRole.KEY and clue.role == ClueRole.VALUE:
        return False
    if last.role == ClueRole.KEY and clue.role == ClueRole.KEY:
        return _key_key_chain_gap_allowed(last, clue, stream)
    if last.role == ClueRole.VALUE and clue.role == ClueRole.KEY:
        return gap <= 6
    return gap <= 1


def _label_seed_address_index(
    clues: tuple[Clue, ...],
    stream: StreamInput,
    start_char: int,
    start_unit: int,
    *,
    max_units: int,
) -> int | None:
    key_index: int | None = None
    for index, clue in enumerate(clues):
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        if clue.start < start_char:
            continue
        if _span_has_search_stop_unit(stream, start_char, clue.start):
            return None
        if clue.role == ClueRole.VALUE and clue.unit_start <= start_unit < clue.unit_end:
            return index
        if clue.role == ClueRole.KEY and clue.unit_start >= start_unit and clue.unit_start - start_unit <= max_units:
            if key_index is None or clue.unit_start < clues[key_index].unit_start:
                key_index = index
    return key_index


def _next_address_clue_index_after(clues: tuple[Clue, ...], after_index: int) -> int | None:
    """从给定下标之后找第一个可消费的 ADDRESS 线索。"""
    for index in range(after_index + 1, len(clues)):
        clue = clues[index]
        if is_break_clue(clue):
            return None
        if is_negative_clue(clue) or clue.attr_type is None:
            continue
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            return index
    return None


def _bridge_last_address_to_next_within_units(
    state: _ParseState,
    next_address_clue: Clue,
    stream: StreamInput,
) -> bool:
    """上一地址 clue 与下一地址 clue 是否仍处在同一短窗口内。"""
    if state.last_consumed is None:
        return False
    if _clue_gap_has_search_stop(state.last_consumed, next_address_clue, stream):
        return False
    gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
    return next_address_clue.unit_start - gap_anchor <= 6


_DIGIT_TAIL_MAX_LEN: dict[AddressComponentType, tuple[int, int]] = {
    AddressComponentType.BUILDING: (5, 4),
    AddressComponentType.DETAIL: (5, 4),
}
_DIGIT_TAIL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9]+$")
_DETAIL_HIERARCHY = (AddressComponentType.BUILDING, AddressComponentType.DETAIL)


@dataclass(slots=True)
class DigitTailResult:
    new_components: list[_DraftComponent]
    unit_text: str
    pure_digits: str
    followed_by_address_key: bool
    challenge_clue_index: int | None
    consumed_clue_ids: set[str]
    consumed_clue_indices: set[int]


def _max_dashes_for_prev_type(prev_type: AddressComponentType) -> int:
    if prev_type in {AddressComponentType.ROAD, AddressComponentType.POI, AddressComponentType.NUMBER}:
        return 3
    if prev_type == AddressComponentType.BUILDING:
        return 2
    if prev_type == AddressComponentType.DETAIL:
        return 1
    return 0


def _parse_digit_tail(text: str, max_dashes: int) -> tuple[str, ...] | None:
    cleaned = str(text or "").strip()
    if not cleaned:
        return None
    dash_count = cleaned.count("-")
    if dash_count > max_dashes:
        return None
    if dash_count == 0:
        if not _DIGIT_TAIL_SEGMENT_RE.fullmatch(cleaned):
            return None
        return (cleaned,)
    segments: list[str] = []
    for part in cleaned.split("-"):
        segment = part.strip()
        if not segment or not _DIGIT_TAIL_SEGMENT_RE.fullmatch(segment):
            return None
        segments.append(segment)
    return tuple(segments) if segments else None


def _digit_tail_segment_valid(seg: str, comp_type: AddressComponentType) -> bool:
    limits = _DIGIT_TAIL_MAX_LEN.get(comp_type)
    if limits is None:
        return False
    alnum_max, digit_max = limits
    max_len = digit_max if seg.isdigit() else alnum_max
    return len(seg) <= max_len


def _available_types_after(prev: AddressComponentType) -> list[AddressComponentType]:
    if prev in {AddressComponentType.ROAD, AddressComponentType.POI, AddressComponentType.NUMBER}:
        return list(_DETAIL_HIERARCHY)
    if prev == AddressComponentType.BUILDING:
        return [AddressComponentType.DETAIL]
    if prev == AddressComponentType.DETAIL:
        return [AddressComponentType.DETAIL]
    return list(_DETAIL_HIERARCHY)


def _greedy_assign_types(
    segments: tuple[str, ...],
    available: list[AddressComponentType],
) -> list[AddressComponentType] | None:
    result: list[AddressComponentType] = []
    avail = list(available)
    for seg in segments:
        assigned = False
        while avail:
            candidate_type = avail[0]
            if _digit_tail_segment_valid(seg, candidate_type):
                result.append(candidate_type)
                avail.pop(0)
                assigned = True
                break
            avail.pop(0)
        if not assigned:
            return None
    return result


def _find_clue_for_digit_run(
    clues: tuple[Clue, ...],
    unit_char_start: int,
    unit_char_end: int,
    from_index: int = 0,
) -> int | None:
    for index in range(from_index, len(clues)):
        clue = clues[index]
        if clue.start > unit_char_end:
            break
        if clue.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}:
            if clue.start <= unit_char_start and clue.end >= unit_char_end:
                return index
    return None


def _has_following_address_key(
    clues: tuple[Clue, ...],
    digit_char_end: int,
    stream: StreamInput,
    from_index: int = 0,
) -> bool:
    for index in range(from_index, len(clues)):
        clue = clues[index]
        if clue.start > digit_char_end + 6:
            break
        if clue.start < digit_char_end:
            continue
        if _span_has_search_stop_unit(stream, digit_char_end, clue.start):
            return False
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role == ClueRole.KEY:
            return True
    return False


def _materialize_digit_tail_before_comma(
    state: _ParseState,
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
    *,
    commit,
) -> None:
    """逗号左侧切段前，先把可确认的 digit tail 物化进组件链。"""
    if not state.components or not getattr(stream, "units", None):
        return
    last = max(state.components, key=lambda component: (component.end, component.start))
    if last.component_type not in _DIGIT_TAIL_TRIGGER_TYPES:
        return
    tail = _analyze_digit_tail(state.components, stream, clues, clue_scan_index)
    if tail is None or tail.followed_by_address_key:
        return
    for component in tail.new_components:
        if not commit(component):
            return


def _analyze_digit_tail(
    components: list[_DraftComponent],
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
) -> DigitTailResult | None:
    if not components or not getattr(stream, "units", None):
        return None
    last = max(components, key=lambda component: (component.end, component.start))
    if last.component_type not in _DIGIT_TAIL_TRIGGER_TYPES:
        return None
    end_char = last.end
    if end_char >= len(stream.text):
        return None
    next_ui = _unit_index_at_or_after(stream, end_char)
    if next_ui >= len(stream.units):
        return None
    next_unit = stream.units[next_ui]
    if next_unit.kind != "digit_run":
        return None

    parts = _parse_digit_tail(next_unit.text, _max_dashes_for_prev_type(last.component_type))
    if parts is None:
        return None
    assigned_types = _greedy_assign_types(parts, _available_types_after(last.component_type))
    if assigned_types is None:
        return None

    clue_idx = _find_clue_for_digit_run(clues, next_unit.char_start, next_unit.char_end, clue_scan_index)
    consumed_clue_indices = {clue_idx} if clue_idx is not None else set()
    consumed_clue_ids = {clues[clue_idx].clue_id} if clue_idx is not None else set()
    new_components: list[_DraftComponent] = []
    cursor = next_unit.char_start
    for segment, comp_type in zip(parts, assigned_types):
        seg_start = stream.text.find(segment, cursor, next_unit.char_end)
        if seg_start < 0:
            seg_start = cursor
        seg_end = seg_start + len(segment)
        new_components.append(_DraftComponent(
            component_type=comp_type,
            start=seg_start,
            end=seg_end,
            value=segment,
            key="",
            is_detail=comp_type in _DETAIL_COMPONENTS,
            clue_ids=set(consumed_clue_ids),
            clue_indices=set(consumed_clue_indices),
        ))
        cursor = seg_end

    followed_by_address_key = _has_following_address_key(clues, next_unit.char_end, stream, clue_scan_index)
    return DigitTailResult(
        new_components=new_components,
        unit_text=next_unit.text,
        pure_digits=re.sub(r"\D", "", next_unit.text),
        followed_by_address_key=followed_by_address_key,
        challenge_clue_index=None if followed_by_address_key else clue_idx,
        consumed_clue_ids=consumed_clue_ids,
        consumed_clue_indices=consumed_clue_indices,
    )
