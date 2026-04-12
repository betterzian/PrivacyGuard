"""中文地址 stack 的专用规则。

这里只保留为中文地址 grammar 服务的策略：
1. suspect 冻结与中文 KEY 路由。
2. 中文左扩，以及中文地址里允许吸收的相邻英数字片段。
3. 中文逗号尾预演与后继前瞻。
4. 中文 HARD clue 子分词。
"""

from __future__ import annotations

import re
from dataclasses import replace

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueFamily,
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
    _remove_pending_suspect_by_level,
)
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_break_clue,
    is_negative_clue,
)

_PLAIN_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")


def _suspect_eligible_after_last_piece(
    state: _ParseState,
    clue: Clue,
    stream: StreamInput,
) -> bool:
    if state.last_piece_end is None:
        return not state.components
    return clue.start == _start_after_component_end(stream, state.last_piece_end)


def _has_pending_suspect_level(entries: list[_SuspectEntry], level: AddressComponentType) -> bool:
    return any(entry.level == level.value for entry in entries)


def _freeze_value_suspect(
    state: _ParseState,
    clue: Clue,
    stream: StreamInput,
) -> bool:
    level = clue.component_type
    if level not in _ADMIN_TYPES or level is None:
        return False
    if level in state.occupancy or _has_pending_suspect_level(state.pending_suspects, level):
        return False
    if not _suspect_eligible_after_last_piece(state, clue, stream):
        return False
    state.pending_suspects.append(_SuspectEntry(
        level=level.value,
        value=clue.text,
        key="",
        origin="value",
        start=clue.start,
        end=clue.end,
    ))
    state.last_piece_end = clue.end
    return True


def _freeze_key_suspect_from_previous_key(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    key_clue: Clue,
) -> bool:
    level = key_clue.component_type
    if level not in _SUSPECT_KEY_TYPES or level is None:
        return False
    if level in state.occupancy or _has_pending_suspect_level(state.pending_suspects, level):
        return False
    if state.chain_left_anchor is None:
        return False
    value_start = state.chain_left_anchor
    if state.pending_suspects:
        value_start = _start_after_component_end(stream, state.pending_suspects[-1].end)
    value_text = _normalize_address_value(level, raw_text[value_start:key_clue.start])
    if not value_text:
        return False
    state.pending_suspects.append(_SuspectEntry(
        level=level.value,
        value=value_text,
        key=key_clue.text,
        origin="key",
        start=value_start,
        end=key_clue.end,
    ))
    state.last_piece_end = key_clue.end
    return True


def _remove_last_value_suspect(
    state: _ParseState,
    key_clue: Clue,
    stream: StreamInput,
) -> None:
    if not state.deferred_chain:
        return
    _, last = state.deferred_chain[-1]
    if last.role != ClueRole.VALUE:
        return
    if _clue_unit_gap(last, key_clue, stream) > 1:
        return
    level = last.component_type
    if level in _ADMIN_TYPES and level is not None and key_clue.component_type == level:
        _remove_pending_suspect_by_level(state, level)


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
        if unit.text and all(char.isalnum() for char in unit.text):
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
    """中文左扩只允许穿过 inline_gap，再吸收紧邻英数字块或少量汉字。"""
    cursor, left_ui = _skip_inline_gap_left(stream, pos, floor)
    if 0 <= left_ui < len(stream.units):
        kind = stream.units[left_ui].kind
        if kind in {"digit_run", "alpha_run", "alnum_run", "ascii_word"}:
            return _left_expand_adjacent_alnum_for_zh(pos, floor, stream)
    return _left_expand_zh_chars(cursor, floor, stream=stream, max_chars=2)


def _routing_context_type(context: _RoutingContext) -> AddressComponentType | None:
    for clue in reversed(context.chain):
        if clue.component_type is not None:
            return clue.component_type
    return context.previous_component_type


def _single_adjacent_value_level(context: _RoutingContext, clue: Clue) -> AddressComponentType | None:
    """返回 key 左侧是否刚好只有一个紧邻的地址 VALUE clue。"""
    if clue.component_type not in {
        AddressComponentType.PROVINCE,
        AddressComponentType.CITY,
        AddressComponentType.DISTRICT,
    }:
        return None
    if len(context.chain) != 1:
        return None
    last_clue = context.chain[-1]
    if (
        last_clue.role == ClueRole.VALUE
        and last_clue.attr_type == PIIAttributeType.ADDRESS
        and last_clue.component_type is not None
        and not _clue_gap_has_search_stop(last_clue, clue, context.stream)
        and _clue_unit_gap(last_clue, clue, context.stream) == 0
    ):
        return last_clue.component_type
    return None


def _key_should_degrade_from_non_pure_value(clue: Clue) -> AddressComponentType | None:
    """非纯 value 场景下的 key 降级规则。"""
    if clue.text == "省" and clue.component_type == AddressComponentType.PROVINCE:
        return None
    if clue.text == "市" and clue.component_type == AddressComponentType.CITY:
        return AddressComponentType.DISTRICT
    return clue.component_type


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


def _route_dynamic_key_type(
    clue: Clue,
    *,
    previous_component_type: AddressComponentType | None,
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
        if not left_value_text:
            return comp_type
        if _PLAIN_ALNUM_RE.fullmatch(left_value_text):
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
) -> bool:
    anchor = clues[clue_index]
    for index in range(clue_index + 1, len(clues)):
        clue = clues[index]
        if is_break_clue(clue):
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
    """把当前 KEY clue 重映射为真正参与中文状态机的类型。"""
    if clue.role != ClueRole.KEY or clue.component_type is None:
        return clue
    single_value_level = _single_adjacent_value_level(context, clue)
    if single_value_level is not None:
        if single_value_level != clue.component_type:
            return None
    else:
        downgraded_type = _key_should_degrade_from_non_pure_value(clue)
        if downgraded_type is None:
            return None
        if downgraded_type != clue.component_type:
            clue = replace(clue, component_type=downgraded_type)
    left_start = _routing_left_value_start(context, clue_index, clue)
    left_value_text = clean_value(context.raw_text[left_start:clue.start])
    routed_type = _route_dynamic_key_type(
        clue,
        previous_component_type=_routing_context_type(context),
        left_value_text=left_value_text,
        followed_by_detail_key=_has_following_detail_key(context.clues, clue_index, context.stream),
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
    expand_start = _routing_left_value_start(context, clue_index, clue)
    return bool(_normalize_address_value(comp_type, context.raw_text[expand_start:clue.start]))


def _key_left_expand_start_if_deferrable(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> int | None:
    """判断中文 KEY 左侧是否存在可延迟提交的 value。"""
    expand_start = _routing_left_value_start(context, clue_index, clue)
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
    first_component_type: AddressComponentType,
) -> bool:
    """逗号后首个真正 component 必须是区及以上行政层，且要高于左侧最高层。"""
    if first_component_type not in _COMMA_TAIL_ADMIN_TYPES:
        return False
    if prior_max is None:
        return True
    return _ADMIN_RANK[first_component_type] > _ADMIN_RANK[prior_max]


def _preview_first_component_type_from_chain(
    chain: list[Clue],
    previous_component_type: AddressComponentType | None,
) -> AddressComponentType | None:
    """把预演链映射为首个真正会提交的 component 类型。"""
    if not chain:
        return None
    for clue in reversed(chain):
        if clue.role != ClueRole.KEY:
            continue
        comp_type = clue.component_type or AddressComponentType.POI
        if comp_type == AddressComponentType.NUMBER and previous_component_type in _DETAIL_COMPONENTS:
            return AddressComponentType.DETAIL
        return comp_type
    return chain[0].component_type


def _preview_comma_tail_first_component_type(
    clues: tuple[Clue, ...],
    start_index: int,
    stream: StreamInput,
    previous_component_type: AddressComponentType | None,
    previous_component_end: int | None,
    raw_text: str,
) -> tuple[AddressComponentType | None, bool]:
    """预演逗号尾首段，返回首个 component 类型及是否需保持链打开。"""
    chain: list[Clue] = []
    ignored_key_indices: set[int] = set()
    search_anchor = _start_after_component_end(stream, previous_component_end) if previous_component_end is not None else None
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if not chain and search_anchor is not None and clue.start > search_anchor:
            if _span_has_search_stop_unit(stream, search_anchor, clue.start):
                break
        if is_break_clue(clue):
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
    component_type = _preview_first_component_type_from_chain(chain, previous_component_type)
    needs_open_chain = any(clue.role == ClueRole.KEY for clue in chain)
    return component_type, needs_open_chain


def _comma_value_scan_upper_bound(
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    stream: StreamInput,
    raw_text_len: int,
) -> int:
    """逗号后 VALUE 右扩上界。"""
    upper_bound = min(raw_text_len, clue.end + 48)
    for index in range(clue_index + 1, len(clues)):
        nxt = clues[index]
        if is_break_clue(nxt):
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
    admin_type: AddressComponentType,
    stream: StreamInput,
    raw_text: str,
) -> bool:
    """后置 admin VALUE 的前瞻。"""
    anchor = clues[index]
    preview_chain: list[Clue] = []
    ignored_key_indices = set(state.ignored_address_key_indices)
    previous_component_end = state.components[-1].end if state.components else None
    for clue_index in range(index + 1, len(clues)):
        nxt = clues[clue_index]
        if is_break_clue(nxt):
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
    component_type = _preview_first_component_type_from_chain(preview_chain, state.last_component_type)
    if component_type is None:
        return False
    if component_type == admin_type:
        return True
    return component_type in _VALID_SUCCESSORS.get(admin_type, frozenset())


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

    first_component_type, needs_open_chain = _preview_comma_tail_first_component_type(
        clues,
        clue_index,
        stream,
        state.last_component_type,
        state.components[-1].end if state.components else None,
        raw_text,
    )
    if first_component_type is None:
        state.split_at = comma_pos
        return _SENTINEL_STOP

    prior_max = _prior_max_admin_from_components(state.components)
    if not _comma_tail_first_admits(prior_max, first_component_type):
        state.split_at = comma_pos
        return _SENTINEL_STOP

    state.comma_tail_checkpoint = _make_comma_tail_checkpoint(state, comma_pos)
    state.segment_state.reset()
    state.segment_state.comma_tail_active = True
    state.pending_comma_value_right_scan = True
    state.pending_comma_first_component = needs_open_chain
    return None


def _sub_tokenize(stream: StreamInput, hard_clue: Clue) -> list[Clue]:
    """在 HARD clue span 内扫描中文地址关键词，产出 sub-clue 列表。"""
    from privacyguard.infrastructure.pii.detector.scanner import (
        _zh_address_key_matcher,
        _zh_address_value_matcher,
    )

    span_start = hard_clue.start
    span_end = hard_clue.end
    text = stream.text[span_start:span_end]
    if not text.strip():
        return []

    folded = text.lower()
    sub_clues: list[Clue] = []
    clue_counter = 0

    def _make_id() -> str:
        nonlocal clue_counter
        clue_counter += 1
        return f"sub_{hard_clue.clue_id}_{clue_counter}"

    for matcher in (_zh_address_value_matcher(),):
        for match in matcher.find_matches(text, folded_text=folded):
            abs_start = span_start + match.start
            abs_end = span_start + match.end
            payload = match.payload
            unit_start, unit_end = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=payload.canonical_text,
                unit_start=unit_start,
                unit_end=unit_end,
                source_kind="sub_tokenize_value",
                component_type=payload.component_type,
            ))

    for matcher in (_zh_address_key_matcher(),):
        for match in matcher.find_matches(text, folded_text=folded):
            abs_start = span_start + match.start
            abs_end = span_start + match.end
            payload = match.payload
            unit_start, unit_end = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=payload.canonical_text,
                unit_start=unit_start,
                unit_end=unit_end,
                source_kind="sub_tokenize_key",
                component_type=payload.component_type,
            ))

    sub_clues.sort(key=lambda clue: (clue.start, -(clue.end - clue.start)))
    deduped: list[Clue] = []
    for clue in sub_clues:
        if any(
            kept.start <= clue.start and clue.end <= kept.end
            and kept.role == clue.role
            and kept.component_type == clue.component_type
            for kept in deduped
        ):
            continue
        deduped.append(clue)

    deduped.sort(key=lambda clue: (clue.start, clue.end))
    return deduped
