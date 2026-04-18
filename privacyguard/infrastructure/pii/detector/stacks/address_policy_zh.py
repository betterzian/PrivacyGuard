"""中文地址 stack 的专用规则。

这里只保留为中文地址 grammar 服务的策略：
1. suspect 冻结与中文 KEY 路由。
2. 中文左扩，以及中文地址里允许吸收的相邻英数字片段。
3. 中文逗号尾预演与后继前瞻。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Callable

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    Clue,
    ClueRole,
    PIIAttributeType,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _SENTINEL_STOP,
    _chain_can_accept,
    _clue_gap_has_search_stop,
    _clue_unit_gap,
    _normalize_address_value,
    _span_has_search_stop_unit,
    _start_after_component_end,
    key_levels,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_RANK,
    _ADMIN_TYPES,
    _COMMA_TAIL_ADMIN_TYPES,
    _DETAIL_COMPONENTS,
    _DraftComponent,
    _ParseState,
    _SUSPECT_KEY_TYPES,
    _SuspectEntry,
    _VALID_SUCCESSORS,
    _make_comma_tail_checkpoint,
    _remove_pending_suspect_group_by_span,
    _segment_admit,
)
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _unit_index_at_or_after,
    _unit_index_left_of,
    examine_left_numeral,
    is_ascii_alnum_like_unit,
    is_control_number_value_clue,
    is_negative_clue,
)

_NUMBERISH_KEY_COMPONENTS = frozenset({
    AddressComponentType.NUMBER,
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
})


def _address_should_break(clue: Clue) -> bool:
    return clue.role == ClueRole.BREAK


@dataclass(frozen=True, slots=True)
class _AdminValueSpan:
    """同一 value span 上的中文行政层级集合。"""

    start: int
    end: int
    text: str
    levels: tuple[AddressComponentType, ...]
    resolved_level: AddressComponentType | None = None
    first_index: int = -1
    last_index: int = -1


def _is_admin_value_clue(clue: Clue) -> bool:
    return (
        clue.role == ClueRole.VALUE
        and clue.attr_type == PIIAttributeType.ADDRESS
        and clue.component_type in _ADMIN_TYPES
    )


def _same_admin_value_span(left: Clue, right: Clue) -> bool:
    return (
        _is_admin_value_clue(left)
        and _is_admin_value_clue(right)
        and left.start == right.start
        and left.end == right.end
    )


def _ordered_admin_levels(levels: Iterable[AddressComponentType]) -> tuple[AddressComponentType, ...]:
    seen: list[AddressComponentType] = []
    for level in levels:
        if level not in _ADMIN_TYPES or level in seen:
            continue
        seen.append(level)
    return tuple(sorted(seen, key=lambda item: _ADMIN_RANK.get(item, 0), reverse=True))


def _ordered_component_types(levels: Iterable[AddressComponentType]) -> tuple[AddressComponentType, ...]:
    seen: list[AddressComponentType] = []
    for level in levels:
        if level in seen:
            continue
        seen.append(level)
    admins = [level for level in seen if level in _ADMIN_TYPES]
    non_admins = [level for level in seen if level not in _ADMIN_TYPES]
    admins.sort(key=lambda item: _ADMIN_RANK.get(item, 0), reverse=True)
    return tuple(admins + non_admins)


def _build_admin_value_span(
    clues: Sequence[Clue],
    *,
    first_index: int = -1,
    last_index: int = -1,
) -> _AdminValueSpan | None:
    if not clues:
        return None
    first = clues[0]
    if not _is_admin_value_clue(first):
        return None
    if any(not _same_admin_value_span(first, current) for current in clues):
        return None
    levels = _ordered_admin_levels(
        current.component_type
        for current in clues
        if current.component_type is not None
    )
    if not levels:
        return None
    return _AdminValueSpan(
        start=first.start,
        end=first.end,
        text=first.text,
        levels=levels,
        first_index=first_index,
        last_index=last_index,
    )


def collect_admin_value_span(
    clues: Sequence[Clue],
    clue_index: int,
) -> _AdminValueSpan | None:
    """按 clue 下标收集其所在的同 span 行政 VALUE 组。"""
    if not (0 <= clue_index < len(clues)):
        return None
    anchor = clues[clue_index]
    if not _is_admin_value_clue(anchor):
        return None
    left = clue_index
    while left - 1 >= 0 and _same_admin_value_span(clues[left - 1], anchor):
        left -= 1
    right = clue_index
    while right + 1 < len(clues) and _same_admin_value_span(anchor, clues[right + 1]):
        right += 1
    return _build_admin_value_span(clues[left:right + 1], first_index=left, last_index=right)


def _collect_chain_edge_admin_value_span(
    chain: Sequence[Clue],
    *,
    edge: str,
    anchor: Clue | None = None,
    stream: StreamInput | None = None,
    max_gap_units: int = 0,
    require_entire_chain_same_span: bool = False,
) -> _AdminValueSpan | None:
    """从 deferred/preview 链一端提取同 span 行政 VALUE 组。"""
    if not chain:
        return None
    if edge == "right":
        reference_index = len(chain) - 1
    elif edge == "left":
        reference_index = 0
    else:
        return None
    reference = chain[reference_index]
    if not _is_admin_value_clue(reference):
        return None
    if anchor is not None and stream is not None:
        if _clue_gap_has_search_stop(reference, anchor, stream):
            return None
        if _clue_unit_gap(reference, anchor, stream) > max_gap_units:
            return None
    if edge == "right":
        left = reference_index
        while left - 1 >= 0 and _same_admin_value_span(chain[left - 1], reference):
            left -= 1
        if require_entire_chain_same_span and left != 0:
            return None
        return _build_admin_value_span(chain[left:], first_index=left, last_index=reference_index)
    right = reference_index
    while right + 1 < len(chain) and _same_admin_value_span(reference, chain[right + 1]):
        right += 1
    if require_entire_chain_same_span and right != len(chain) - 1:
        return None
    return _build_admin_value_span(chain[:right + 1], first_index=reference_index, last_index=right)


def match_admin_levels(
    preferred_levels: Iterable[AddressComponentType],
    candidate_levels: Iterable[AddressComponentType],
) -> AddressComponentType | None:
    """按优先顺序匹配行政层级，命中任一层级即返回该层级。"""
    candidate_set = set(_ordered_component_types(candidate_levels))
    if not candidate_set:
        return None
    for level in _ordered_component_types(preferred_levels):
        if level in candidate_set:
            return level
    return None


def _available_admin_levels_for_state(
    state: _ParseState,
    span: _AdminValueSpan,
    *,
    origin: str,
    key_text: str = "",
    value_text: str | None = None,
    require_segment_admit: bool,
    valid_successors: dict[AddressComponentType, frozenset[AddressComponentType]] = _VALID_SUCCESSORS,
) -> tuple[AddressComponentType, ...]:
    value = span.text if value_text is None else value_text
    available: list[AddressComponentType] = []
    for level in span.levels:
        if level in state.occupancy:
            continue
        if _pending_level_exists_on_other_group(
            state.pending_suspects,
            level,
            start=span.start,
            end=span.end,
            value=value,
            key=key_text,
            origin=origin,
        ):
            continue
        if require_segment_admit and not _segment_admit(
            state,
            level,
            valid_successors=valid_successors,
        ):
            continue
        available.append(level)
    return tuple(available)


def resolve_admin_value_span(
    state: _ParseState,
    span: _AdminValueSpan,
    *,
    valid_successors: dict[AddressComponentType, frozenset[AddressComponentType]] = _VALID_SUCCESSORS,
) -> _AdminValueSpan | None:
    """按当前状态选择同 span 行政 VALUE 的最终真实层级。"""
    available = _available_admin_levels_for_state(
        state,
        span,
        origin="value",
        require_segment_admit=True,
        valid_successors=valid_successors,
    )
    if not available:
        return None
    return replace(span, levels=available, resolved_level=available[0])


def _resolve_admin_key_chain_levels(
    state: _ParseState,
    value_entries: tuple[tuple[int, Clue], ...],
    key_clue: Clue,
    *,
    valid_successors: dict[AddressComponentType, frozenset[AddressComponentType]] = _VALID_SUCCESSORS,
) -> _AdminSpanView | None:
    """§3.5 KEY-driven admin 链层级解析。

    输入：last KEY 之前的 VALUE 条目（需全部在同 admin VALUE span），以及 last KEY clue。
    流程：span.levels ∩ key_levels(key_clue) → 再按 state 做 occupancy + segment_admit 过滤。

    返回值语义（与 standalone 统一为 `_AdminSpanView`）：
    - `None`：非 admin 链或 value_entries 构不成 span；上游走非 admin KEY 路径或 split。
    - `_AdminSpanView` with empty `available_levels`：交集存在但全部被 occupancy/admit 拦下；
       上游应尝试 §5.1 collision 以重用 `all_levels` / `text`。
    - `available_levels` 长度 >= 1：可直接落库（len==1 单层；len>=2 MULTI_ADMIN）。
    """
    if not value_entries:
        return None
    span = _build_admin_value_span(tuple(clue for _, clue in value_entries))
    if span is None:
        return None
    candidate = _ordered_component_types(
        lvl for lvl in span.levels if lvl in set(key_levels(key_clue))
    )
    if not candidate:
        # 无交集：视为 `_AdminSpanView(available_levels=(), all_levels=span.levels, text=...)`
        # 让上游尝试 collision（例如同值 MULTI_ADMIN 降解）。
        return _AdminSpanView(
            available_levels=(),
            all_levels=tuple(span.levels),
            text=span.text,
        )
    available: list[AddressComponentType] = []
    for lvl in candidate:
        if lvl in state.occupancy:
            continue
        if not _segment_admit(state, lvl, valid_successors=valid_successors):
            continue
        available.append(lvl)
    return _AdminSpanView(
        available_levels=tuple(available),
        all_levels=tuple(candidate),
        text=span.text,
    )


@dataclass(frozen=True, slots=True)
class _AdminSpanView:
    """供 commit 路径使用的 admin VALUE span 视图。

    - `available_levels`：经 occupancy + segment_admit 过滤后剩余的可落层级（按 rank 降序）。
    - `all_levels`：scanner/词典赋予该 span 的全部 admin 候选层级，用于 collision 路径。
    - `text`：span 原文，供 collision 同值比较使用。
    """

    available_levels: tuple[AddressComponentType, ...]
    all_levels: tuple[AddressComponentType, ...]
    text: str


def _resolve_standalone_admin_value_group(
    state: _ParseState,
    clue_entries: tuple[tuple[int, Clue], ...],
    *,
    valid_successors: dict[AddressComponentType, frozenset[AddressComponentType]] = _VALID_SUCCESSORS,
) -> _AdminSpanView | None:
    """将 standalone 链上的同 span 行政 VALUE 组解析为视图结构。

    返回值语义（与 PR #1/#2/#3b 的 MULTI_ADMIN / collision 对齐）：
    - `None`：非行政 VALUE span（不是 admin 族或 clue 间 span 不同），上游走非 admin 分支。
    - `_AdminSpanView(available_levels=(), all_levels=(...), text=...)`：
      span 存在但全部被 occupancy/suspect/admit 拦下，上游应尝试 collision；失败再 split。
    - `available_levels` 长度 >= 1：可直接落库（len==1 单层；len>=2 MULTI_ADMIN）。
    """
    span = _build_admin_value_span(tuple(clue for _, clue in clue_entries))
    if span is None:
        return None
    resolved = resolve_admin_value_span(state, span, valid_successors=valid_successors)
    available: tuple[AddressComponentType, ...] = ()
    if resolved is not None:
        available = tuple(resolved.levels)
    return _AdminSpanView(
        available_levels=available,
        all_levels=tuple(span.levels),
        text=span.text,
    )


def _suspect_eligible_after_last_piece(
    state: _ParseState,
    clue: Clue,
    stream: StreamInput,
) -> bool:
    if state.last_piece_end is None:
        return not state.components
    return clue.start == _start_after_component_end(stream, state.last_piece_end)


def _same_pending_suspect_group(
    entry: _SuspectEntry,
    *,
    start: int,
    end: int,
    value: str,
    key: str,
    origin: str,
) -> bool:
    return (
        entry.start == start
        and entry.end == end
        and entry.value == value
        and entry.key == key
        and entry.origin == origin
    )


def _pending_group_exists(
    entries: list[_SuspectEntry],
    *,
    start: int,
    end: int,
    value: str,
    key: str,
    origin: str,
) -> bool:
    return any(
        _same_pending_suspect_group(
            entry,
            start=start,
            end=end,
            value=value,
            key=key,
            origin=origin,
        )
        for entry in entries
    )


def _pending_level_exists_on_other_group(
    entries: list[_SuspectEntry],
    level: AddressComponentType,
    *,
    start: int,
    end: int,
    value: str,
    key: str,
    origin: str,
) -> bool:
    return any(
        # entry.level 已改为 tuple[AddressComponentType, ...]，用 `in` 而非 `==` 匹配目标层。
        level in entry.level
        and not _same_pending_suspect_group(
            entry,
            start=start,
            end=end,
            value=value,
            key=key,
            origin=origin,
        )
        for entry in entries
    )


def _freeze_value_suspect_for_mismatched_admin_key(
    state: _ParseState,
    key_clue: Clue,
    *,
    stream: StreamInput,
) -> bool:
    """仅当 admin key 与左侧纯行政 value 层级失配时，冻结 standalone suspect。"""
    if key_clue.role != ClueRole.KEY or key_clue.component_type not in _SUSPECT_KEY_TYPES:
        return False

    span = _collect_chain_edge_admin_value_span(
        [deferred for _, deferred in state.deferred_chain],
        edge="right",
        anchor=key_clue,
        stream=stream,
        max_gap_units=0,
        require_entire_chain_same_span=True,
    )
    if span is None:
        return False
    if match_admin_levels((key_clue.component_type,), span.levels) is not None:
        return False

    same_group_exists = _pending_group_exists(
        state.pending_suspects,
        start=span.start,
        end=span.end,
        value=span.text,
        key="",
        origin="value",
    )
    if not same_group_exists and not _suspect_eligible_after_last_piece(state, key_clue, stream):
        return False

    available_levels = _available_admin_levels_for_state(
        state,
        span,
        origin="value",
        require_segment_admit=False,
    )
    appended = False
    for level in available_levels:
        if _pending_group_exists(
            state.pending_suspects,
            start=span.start,
            end=span.end,
            value=span.text,
            key="",
            origin="value",
        ) and any(
            # entry.level 为 tuple；判断本 level 是否已登记。
            level in entry.level
            and _same_pending_suspect_group(
                entry,
                start=span.start,
                end=span.end,
                value=span.text,
                key="",
                origin="value",
            )
            for entry in state.pending_suspects
        ):
            continue
        state.pending_suspects.append(_SuspectEntry(
            # 单层 suspect：level 传 tuple；后续若有其他层同 span 加入也会作为另一条 entry，
            # 由 canonical 比较或上游合并处理（tuple 合并在 §3 MULTI_ADMIN 阶段引入）。
            level=(level,),
            value=span.text,
            key="",
            origin="value",
            start=span.start,
            end=span.end,
        ))
        appended = True
    if appended:
        state.last_piece_end = span.end
    return appended


def _freeze_key_suspect_from_previous_key(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    key_clue: Clue,
) -> bool:
    level = key_clue.component_type
    if level not in _SUSPECT_KEY_TYPES or level is None:
        return False
    if state.chain_left_anchor is None:
        return False
    value_start = state.chain_left_anchor
    if state.pending_suspects:
        value_start = _start_after_component_end(stream, state.pending_suspects[-1].end)
    value_text = _normalize_address_value(level, raw_text[value_start:key_clue.start])
    if not value_text:
        return False
    span = _AdminValueSpan(
        start=value_start,
        end=key_clue.end,
        text=value_text,
        levels=(level,),
    )
    # 与存储端对齐：新建 key-driven suspect 时 key 置空（KEY 由 span 推导，不存入 entry），
    # 查询 pending 组是否已存在也用 key="" 做 key 维度的对齐。
    same_group_exists = _pending_group_exists(
        state.pending_suspects,
        start=span.start,
        end=span.end,
        value=value_text,
        key="",
        origin="key",
    )
    available_levels = _available_admin_levels_for_state(
        state,
        span,
        origin="key",
        key_text=key_clue.text,
        value_text=value_text,
        require_segment_admit=False,
    )
    if not available_levels:
        return False
    if same_group_exists and any(
        # 只要 tuple 中已含第一候选层，即视为重复登记。
        available_levels[0] in entry.level
        and _same_pending_suspect_group(
            entry,
            start=span.start,
            end=span.end,
            value=value_text,
            key="",
            origin="key",
        )
        for entry in state.pending_suspects
    ):
        return False
    # 按 §9.5：surface = entry.value + entry.key 要与 ROAD/POI 主 value 兼容地 trim；
    # 把 KEY（"市"/"省"/"区"）从 entry.key 挪出（置空），所有候选层放进 level 元组——
    # 这样 _fixup_suspected_info 用 "北京" 而非 "北京市" 去 trim "北京中山"。
    state.pending_suspects.append(_SuspectEntry(
        level=tuple(available_levels),
        value=value_text,
        key="",
        origin="key",
        start=span.start,
        end=span.end,
    ))
    state.last_piece_end = span.end
    return True


def _remove_last_value_suspect(
    state: _ParseState,
    key_clue: Clue,
    stream: StreamInput,
) -> None:
    adjacent = _collect_chain_edge_admin_value_span(
        [deferred for _, deferred in state.deferred_chain],
        edge="right",
        anchor=key_clue,
        stream=stream,
        max_gap_units=1,
    )
    if adjacent is None or key_clue.component_type is None:
        return
    if match_admin_levels((key_clue.component_type,), adjacent.levels) is not None:
        _remove_pending_suspect_group_by_span(state, adjacent.start, adjacent.end, origin="value")


def _extend_start_with_adjacent_ignored_keys(
    clues: tuple[Clue, ...],
    clue_index: int,
    start: int,
    ignored_key_indices: set[int] | None,
) -> int:
    """若左侧存在连续退化的地址 key，则把取值起点扩回最左端。"""
    if not ignored_key_indices:
        return start
    cursor = clues[clue_index].start
    for index in range(clue_index - 1, -1, -1):
        if index not in ignored_key_indices:
            continue
        clue = clues[index]
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.role != ClueRole.KEY:
            continue
        if clue.end != cursor:
            break
        cursor = clue.start
    return min(start, cursor)


def _skip_inline_gap_left(stream: StreamInput, pos: int, floor: int) -> tuple[int, int]:
    """向左穿过 inline_gap，返回新的光标和左侧相邻 unit 下标。"""
    cursor = pos
    left_ui = _unit_index_left_of(stream, cursor)
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor or unit.kind != "inline_gap":
            break
        cursor = unit.char_start
        left_ui -= 1
    return cursor, left_ui


def _left_expand_adjacent_alnum_for_zh(pos: int, floor: int, stream: StreamInput) -> int:
    """中文地址左扩时，吸收紧邻的英数字片段。"""
    cursor, left_ui = _skip_inline_gap_left(stream, pos, floor)
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor:
            break
        if unit.kind == "inline_gap":
            cursor = unit.char_start
            left_ui -= 1
            continue
        if is_ascii_alnum_like_unit(unit):
            cursor = unit.char_start
            left_ui -= 1
            continue
        break
    return cursor


def _left_expand_zh_chars(
    pos: int,
    floor: int,
    *,
    stream: StreamInput,
    max_chars: int,
) -> int:
    cursor = pos
    count = 0
    left_ui = _unit_index_left_of(stream, cursor)
    while 0 <= left_ui < len(stream.units) and count < max_chars:
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor:
            break
        if unit.kind == "inline_gap":
            cursor = unit.char_start
            left_ui -= 1
            continue
        if (
            unit.kind == "cjk_char"
            and len(unit.text) == 1
            and "\u4e00" <= unit.text <= "\u9fff"
            and unit.char_start >= floor
        ):
            cursor = unit.char_start
            count += 1
            left_ui -= 1
            continue
        break
    return cursor


def _left_expand_zh(pos: int, floor: int, stream: StreamInput) -> int:
    """中文左扩：数字前缀走精确路径，非数字 CJK 走宽松吸收。"""
    prefix = examine_left_numeral(stream, pos)
    if prefix.kind == "ascii_alnum":
        return _left_expand_adjacent_alnum_for_zh(pos, floor, stream)
    if prefix.kind != "none":
        # 中文数字 / 天干地支 → 直接用前缀起点。
        return max(prefix.char_start, floor)
    # 非数字 CJK（地名等）→ 仍用宽松的 max_chars 吸收。
    cursor, _ = _skip_inline_gap_left(stream, pos, floor)
    return _left_expand_zh_chars(cursor, floor, stream=stream, max_chars=2)


def _routing_context_type(context: _RoutingContext) -> AddressComponentType | None:
    for clue in reversed(context.chain):
        if clue.component_type is not None:
            return clue.component_type
    return context.previous_component_type


def _find_control_value_clue_ending_at(context: _RoutingContext, char_end: int) -> Clue | None:
    candidate: Clue | None = None
    for clue in context.clues:
        if clue.end != char_end or not is_control_number_value_clue(clue):
            continue
        if candidate is None or clue.start < candidate.start:
            candidate = clue
    return candidate


def _numberish_left_expand_start(
    context: _RoutingContext,
    clue: Clue,
) -> int:
    if context.chain:
        return context.chain[-1].end
    floor = 0
    if context.previous_component_end is not None:
        floor = _start_after_component_end(context.stream, context.previous_component_end)
    elif context.search_start is not None and context.search_start < clue.start:
        return context.search_start
    cursor, left_ui = _skip_inline_gap_left(context.stream, clue.start, floor)
    if left_ui < 0 or left_ui >= len(context.stream.units):
        return clue.start
    left_unit = context.stream.units[left_ui]
    if is_ascii_alnum_like_unit(left_unit):
        start = _left_expand_adjacent_alnum_for_zh(clue.start, floor, context.stream)
    else:
        control_clue = _find_control_value_clue_ending_at(context, clue.start)
        if control_clue is None:
            return clue.start
        start = control_clue.start
    while True:
        control_clue = _find_control_value_clue_ending_at(context, start)
        if control_clue is None:
            break
        start = control_clue.start
    return start


def _left_value_text_for_routing(context: _RoutingContext, clue: Clue, left_start: int) -> tuple[str, str]:
    raw_left_value_text = clean_value(context.raw_text[left_start:clue.start])
    if clue.component_type in _NUMBERISH_KEY_COMPONENTS:
        return raw_left_value_text, _normalize_address_value(clue.component_type, context.raw_text[left_start:clue.start])
    return raw_left_value_text, raw_left_value_text


def _adjacent_value_span(
    context: _RoutingContext,
    clue: Clue,
) -> _AdminValueSpan | None:
    """返回 key 左侧紧邻且纯 value 的行政 span。"""
    if clue.component_type not in {
        AddressComponentType.PROVINCE,
        AddressComponentType.CITY,
        AddressComponentType.DISTRICT,
    }:
        return None
    return _collect_chain_edge_admin_value_span(
        context.chain,
        edge="right",
        anchor=clue,
        stream=context.stream,
        max_gap_units=0,
        require_entire_chain_same_span=True,
    )


def _successor_candidate_levels(
    admin_levels: Iterable[AddressComponentType],
) -> tuple[AddressComponentType, ...]:
    ordered: list[AddressComponentType] = []
    for level in _ordered_component_types(admin_levels):
        if level not in ordered:
            ordered.append(level)
        for successor in _ordered_component_types(_VALID_SUCCESSORS.get(level, frozenset())):
            if successor not in ordered:
                ordered.append(successor)
    return tuple(ordered)


def _routing_left_value_start(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
) -> int:
    """按中文地址路由规则推导左侧 value 的起点。"""
    if context.chain:
        return context.chain[-1].end
    if context.previous_component_end is not None:
        return _start_after_component_end(context.stream, context.previous_component_end)
    expand_start = _left_expand_zh(clue.start, 0, context.stream)
    return _extend_start_with_adjacent_ignored_keys(
        context.clues,
        clue_index,
        expand_start,
        context.ignored_key_indices,
    )


def _effective_left_value_start(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
) -> int:
    if clue.component_type in _NUMBERISH_KEY_COMPONENTS:
        return _numberish_left_expand_start(context, clue)
    return _routing_left_value_start(context, clue_index, clue)


def _route_dynamic_key_type(
    clue: Clue,
    *,
    previous_component_type: AddressComponentType | None,
    raw_left_value_text: str,
    left_value_text: str,
    followed_by_detail_key: bool,
) -> AddressComponentType | None:
    """对精确歧义 key 做上下文重路由。"""
    comp_type = clue.component_type
    if clue.role != ClueRole.KEY or comp_type is None:
        return comp_type
    if clue.text == "社区" and comp_type == AddressComponentType.SUBDISTRICT:
        return AddressComponentType.POI
    if clue.text == "楼" and comp_type == AddressComponentType.DETAIL:
        if not raw_left_value_text:
            return comp_type
        if left_value_text:
            if followed_by_detail_key:
                return AddressComponentType.DETAIL
            if previous_component_type == AddressComponentType.BUILDING:
                return AddressComponentType.DETAIL
            return AddressComponentType.BUILDING
        return AddressComponentType.POI
    return comp_type


def _has_following_detail_key(
    clues: tuple[Clue, ...],
    clue_index: int,
    stream: StreamInput,
    *,
    should_break: Callable[[Clue], bool] = _address_should_break,
) -> bool:
    anchor = clues[clue_index]
    for index in range(clue_index + 1, len(clues)):
        clue = clues[index]
        if should_break(clue):
            return False
        if is_negative_clue(clue):
            continue
        if _clue_gap_has_search_stop(anchor, clue, stream):
            return False
        if _clue_unit_gap(anchor, clue, stream) > 6:
            return False
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        if clue.role != ClueRole.KEY or clue.component_type is None:
            continue
        return clue.component_type in _DETAIL_COMPONENTS
    return False


def _routed_key_clue(context: _RoutingContext, clue_index: int, clue: Clue) -> Clue | None:
    """把当前 KEY clue 重映射为真正参与中文状态机的类型。

    §4.2 KEY 多层级 intersection 路由：
    - adjacent VALUE span 存在：与 `key_levels(clue)` 求有序交集。
        空→ None；单层→ 该 level；≥2 层→ MULTI_ADMIN（交集信息后续在 flush 路径重算）。
    - 无 adjacent：按非纯 value 降级规则处理——
        "省" PROVINCE → None（裸"省"字无法独立成值）；
        "市" CITY → DISTRICT_CITY（县级市是"市" KEY 唯一可独立存在的语义落点）；
        其他保持不变。
    """
    if clue.role != ClueRole.KEY or clue.component_type is None:
        return clue
    adjacent_span = _adjacent_value_span(context, clue)
    if adjacent_span is not None:
        intersection = _ordered_component_types(
            level for level in adjacent_span.levels if level in set(key_levels(clue))
        )
        if not intersection:
            return None
        if len(intersection) == 1:
            if intersection[0] != clue.component_type:
                clue = replace(clue, component_type=intersection[0])
        else:
            # 多层未消歧 → MULTI_ADMIN；_route_dynamic_key_type 对 MULTI_ADMIN 为 pass-through，
            # 直接早退避免后续动态重路由覆盖该决策。
            return replace(clue, component_type=AddressComponentType.MULTI_ADMIN)
    else:
        if clue.text == "省" and clue.component_type == AddressComponentType.PROVINCE:
            return None
        if clue.text == "市" and clue.component_type == AddressComponentType.CITY:
            clue = replace(clue, component_type=AddressComponentType.DISTRICT_CITY)
    left_start = _effective_left_value_start(context, clue_index, clue)
    raw_left_start = left_start
    if clue.text == "楼" and clue.component_type == AddressComponentType.DETAIL and raw_left_start == clue.start:
        raw_left_start = _routing_left_value_start(context, clue_index, clue)
    raw_left_value_text, left_value_text = _left_value_text_for_routing(context, clue, raw_left_start)
    if raw_left_start != left_start and clue.component_type in _NUMBERISH_KEY_COMPONENTS:
        left_value_text = _normalize_address_value(clue.component_type, context.raw_text[left_start:clue.start])
    routed_type = _route_dynamic_key_type(
        clue,
        previous_component_type=_routing_context_type(context),
        raw_left_value_text=raw_left_value_text,
        left_value_text=left_value_text,
        followed_by_detail_key=_has_following_detail_key(
            context.clues,
            clue_index,
            context.stream,
            should_break=context.should_break_clue or _address_should_break,
        ),
    )
    if routed_type == clue.component_type:
        return clue
    return replace(clue, component_type=routed_type)


def _key_has_left_value(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> bool:
    """判断中文 KEY 是否真的有左值。"""
    expand_start = _effective_left_value_start(context, clue_index, clue)
    return bool(_normalize_address_value(comp_type, context.raw_text[expand_start:clue.start]))


def _key_left_expand_start_if_deferrable(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> int | None:
    """判断中文 KEY 左侧是否存在可延迟提交的 value。"""
    expand_start = _effective_left_value_start(context, clue_index, clue)
    value = _normalize_address_value(comp_type, context.raw_text[expand_start:clue.start])
    if not value:
        return None
    return expand_start


def _non_space_units_to_unit_start(stream: StreamInput, char_pos: int, unit_start: int) -> int:
    """从 char_pos 到目标 unit 起点的非空白、非 inline_gap unit 数。"""
    start_ui = _unit_index_at_or_after(stream, char_pos)
    if start_ui >= len(stream.units):
        return 0
    count = 0
    for ui in range(start_ui, min(unit_start + 1, len(stream.units))):
        if stream.units[ui].kind not in {"space", "inline_gap"}:
            count += 1
    return count


def _comma_char_index_in_gap(raw_text: str, last_end: int, clue_start: int) -> int | None:
    """gap [last_end, clue_start) 内第一个逗号下标。"""
    for offset, char in enumerate(raw_text[last_end:clue_start]):
        if char in ",，":
            return last_end + offset
    return None


def _prior_max_admin_from_components(components: list[_DraftComponent]) -> AddressComponentType | None:
    """已提交 component 中行政类型的最高一层。"""
    types = [component.component_type for component in components if component.component_type in _ADMIN_TYPES]
    if not types:
        return None
    return max(types, key=lambda component_type: _ADMIN_RANK.get(component_type, 0))


def _comma_tail_first_admits(
    prior_max: AddressComponentType | None,
    first_component_levels: tuple[AddressComponentType, ...],
) -> bool:
    """逗号后首个真正 component 必须是区及以上行政层，且要高于左侧最高层。"""
    for first_component_type in first_component_levels:
        if first_component_type not in _COMMA_TAIL_ADMIN_TYPES:
            continue
        if prior_max is None:
            return True
        if _ADMIN_RANK[first_component_type] > _ADMIN_RANK[prior_max]:
            return True
    return False


def _preview_first_component_levels_from_chain(
    chain: list[Clue],
    previous_component_type: AddressComponentType | None,
) -> tuple[AddressComponentType, ...]:
    """把预演链映射为首个真正会提交的 component 类型。"""
    if not chain:
        return ()
    for clue in reversed(chain):
        if clue.role != ClueRole.KEY:
            continue
        comp_type = clue.component_type or AddressComponentType.POI
        if comp_type == AddressComponentType.NUMBER and previous_component_type in _DETAIL_COMPONENTS:
            return (AddressComponentType.DETAIL,)
        return (comp_type,)
    first_span = _collect_chain_edge_admin_value_span(chain, edge="left")
    if first_span is not None:
        return first_span.levels
    if chain[0].component_type is None:
        return ()
    return (chain[0].component_type,)


def _preview_comma_tail_first_component_levels(
    clues: tuple[Clue, ...],
    start_index: int,
    stream: StreamInput,
    previous_component_type: AddressComponentType | None,
    previous_component_end: int | None,
    raw_text: str,
    *,
    should_break: Callable[[Clue], bool] = _address_should_break,
) -> tuple[tuple[AddressComponentType, ...], bool]:
    """预演逗号尾首段，返回首个 component 类型及是否需保持链打开。"""
    chain: list[Clue] = []
    ignored_key_indices: set[int] = set()
    search_anchor = _start_after_component_end(stream, previous_component_end) if previous_component_end is not None else None
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if not chain and search_anchor is not None and clue.start > search_anchor:
            if _span_has_search_stop_unit(stream, search_anchor, clue.start):
                break
        if should_break(clue):
            break
        if is_negative_clue(clue):
            continue
        if clue.attr_type is None or clue.role == ClueRole.LABEL:
            continue
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.component_type is None:
            continue
        context = _RoutingContext(
            chain=chain,
            previous_component_type=previous_component_type,
            previous_component_end=previous_component_end,
            ignored_key_indices=ignored_key_indices,
            clues=clues,
            raw_text=raw_text,
            stream=stream,
            search_start=search_anchor,
            should_break_clue=should_break,
        )
        effective = clue
        if clue.role == ClueRole.KEY:
            routed_key = _routed_key_clue(context, index, clue)
            if routed_key is None:
                ignored_key_indices.add(index)
                continue
            effective = routed_key
            eff_type = effective.component_type
            if eff_type is not None and not chain and not _key_has_left_value(context, index, effective, eff_type):
                ignored_key_indices.add(index)
                continue
        if chain and not _chain_can_accept(chain, effective, stream):
            break
        chain.append(effective)
    component_levels = _preview_first_component_levels_from_chain(chain, previous_component_type)
    needs_open_chain = any(clue.role == ClueRole.KEY for clue in chain)
    return component_levels, needs_open_chain


def _comma_value_scan_upper_bound(
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    stream: StreamInput,
    raw_text_len: int,
    *,
    should_break: Callable[[Clue], bool] = _address_should_break,
) -> int:
    """逗号后 VALUE 右扩上界。"""
    upper_bound = min(raw_text_len, clue.end + 48)
    for index in range(clue_index + 1, len(clues)):
        nxt = clues[index]
        if should_break(nxt):
            return min(upper_bound, nxt.start)
        if is_negative_clue(nxt):
            continue
        if nxt.attr_type != PIIAttributeType.ADDRESS or nxt.role == ClueRole.LABEL:
            continue
        if _clue_unit_gap(clue, nxt, stream) > 1:
            return clue.end
        return min(upper_bound, nxt.start)
    return upper_bound


def _has_reasonable_successor_key(
    state: _ParseState,
    clues: tuple[Clue, ...],
    index: int,
    admin_levels: tuple[AddressComponentType, ...],
    stream: StreamInput,
    raw_text: str,
    *,
    should_break: Callable[[Clue], bool] = _address_should_break,
) -> bool:
    """后置 admin VALUE 的前瞻。"""
    anchor = clues[index]
    current_span = collect_admin_value_span(clues, index)
    preview_chain: list[Clue] = []
    ignored_key_indices = set(state.ignored_address_key_indices)
    previous_component_end = state.components[-1].end if state.components else None
    start_index = current_span.last_index + 1 if current_span is not None else index + 1
    for clue_index in range(start_index, len(clues)):
        nxt = clues[clue_index]
        if should_break(nxt):
            break
        if is_negative_clue(nxt) or nxt.role == ClueRole.LABEL:
            continue
        gap_anchor = preview_chain[-1] if preview_chain else anchor
        if _clue_gap_has_search_stop(gap_anchor, nxt, stream) or _clue_unit_gap(gap_anchor, nxt, stream) > 6:
            break
        if nxt.attr_type != PIIAttributeType.ADDRESS or nxt.component_type is None:
            continue
        context = _RoutingContext(
            chain=preview_chain,
            previous_component_type=state.last_component_type,
            previous_component_end=previous_component_end,
            ignored_key_indices=ignored_key_indices,
            clues=clues,
            raw_text=raw_text,
            stream=stream,
            search_start=_start_after_component_end(stream, previous_component_end) if previous_component_end is not None else None,
            should_break_clue=should_break,
        )
        effective = nxt
        if nxt.role == ClueRole.KEY:
            routed_key = _routed_key_clue(context, clue_index, nxt)
            if routed_key is None:
                ignored_key_indices.add(clue_index)
                continue
            effective = routed_key
            eff_type = effective.component_type
            if eff_type is not None and not preview_chain and not _key_has_left_value(context, clue_index, effective, eff_type):
                ignored_key_indices.add(clue_index)
                continue
        if preview_chain and not _chain_can_accept(preview_chain, effective, stream):
            break
        preview_chain.append(effective)
    component_levels = _preview_first_component_levels_from_chain(preview_chain, state.last_component_type)
    if not component_levels:
        return False
    return match_admin_levels(_successor_candidate_levels(admin_levels), component_levels) is not None


def _comma_tail_prehandle(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    *,
    flush_chain,
    materialize_digit_tail_before_comma,
    should_break: Callable[[Clue], bool] = _address_should_break,
) -> object | None:
    """gap 内若有逗号，先断开左链，再按首个真实 component 做准入判定。"""
    comma_pos = _comma_char_index_in_gap(raw_text, state.last_end, clue.start)
    if comma_pos is None:
        return None

    if state.deferred_chain:
        flush_chain(clue_index)
        if state.split_at is not None:
            return _SENTINEL_STOP

    materialize_digit_tail_before_comma(clue_index)
    comma_pos = _comma_char_index_in_gap(raw_text, state.last_end, clue.start)
    if comma_pos is None:
        return None

    after_comma = comma_pos + 1
    if _non_space_units_to_unit_start(stream, after_comma, clue.unit_start) > 6:
        state.split_at = comma_pos
        return _SENTINEL_STOP

    first_component_levels, needs_open_chain = _preview_comma_tail_first_component_levels(
        clues,
        clue_index,
        stream,
        state.last_component_type,
        state.components[-1].end if state.components else None,
        raw_text,
        should_break=should_break,
    )
    if not first_component_levels:
        state.split_at = comma_pos
        return _SENTINEL_STOP

    prior_max = _prior_max_admin_from_components(state.components)
    if not _comma_tail_first_admits(prior_max, first_component_levels):
        state.split_at = comma_pos
        return _SENTINEL_STOP

    state.comma_tail_checkpoint = _make_comma_tail_checkpoint(state, comma_pos)
    state.segment_state.reset()
    state.segment_state.comma_tail_active = True
    state.pending_comma_value_right_scan = True
    state.pending_comma_first_component = needs_open_chain
    return None
