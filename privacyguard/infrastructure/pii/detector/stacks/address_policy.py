"""地址 stack 的**纯规则与扫描策略**（尽量不持有 `AddressStack` 自身状态）。

与另两文件的关系：
- **address.py**：组织 clue 扫描循环，把本模块函数当作「黑盒判定」调用。
- **address_state.py**：维护 `_ParseState`、执行 `_commit` / `_flush_chain`；本模块只**读取**
  state 字段或通过回调提交。

建议阅读顺序：本文件顶部的分组索引 → `_RoutingContext` / `_routed_key_clue`（KEY 如何变型）
→ `_comma_tail_prehandle`（逆序地址与逗号）→ `_analyze_digit_tail`（门牌扩展）。

函数分组（文件内大致自上而下）：
1. **单位与 gap**：`_clue_unit_gap`、`_skip_from_char_by_units`、`_span_has_search_stop_unit`、
   `_span_has_non_comma_search_stop_unit`、`_state_next_component_start`
2. **KEY-KEY 链式间距**：`_key_key_chain_gap_allowed` 及辅助
3. **Suspect 冻结**（写入 `pending_suspects`）：`_freeze_value_suspect`、`_freeze_key_suspect_from_previous_key`、`_remove_last_value_suspect`
4. **KEY 左边界与左扩**：`_routing_left_value_start`、`_left_expand_zh` / `_left_expand_en_word`、`_extend_start_with_adjacent_ignored_keys`
5. **动态路由**：`_RoutingContext`、`_route_dynamic_key_type`、`_routed_key_clue`、`_key_has_left_value`、`_key_left_expand_start_if_deferrable`
6. **deferred_chain 可接性**：`_chain_can_accept`
7. **LABEL 起栈与前瞻**：`_label_seed_address_index`、`_preview_comma_tail_first_component_type`、`_has_reasonable_successor_key`
8. **逗号尾**：`_comma_char_index_in_gap`、`_comma_tail_prehandle`、`_comma_value_scan_upper_bound`
9. **跨人名桥接与数字尾**：`_bridge_last_address_to_next_within_units`、`_analyze_digit_tail` 及其解析子函数
10. **HARD 子分词**：`_sub_tokenize`

哨兵：`_SENTINEL_STOP` / `_SENTINEL_IGNORE` 与 `address.py` 中 `_handle_address_clue` 的返回值约定一致。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.lexicon_loader import load_en_address_keyword_groups
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    PIIAttributeType,
    StreamInput,
    StreamUnit,
)
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _skip_separators,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_break_clue,
    is_negative_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    OCR_BREAK,
    is_any_break,
    is_soft_break,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_RANK,
    _ADMIN_TYPES,
    _COMMA_TAIL_ADMIN_TYPES,
    _DETAIL_COMPONENTS,
    _DIGIT_TAIL_TRIGGER_TYPES,
    _DraftComponent,
    _IndexedClue,
    _ParseState,
    _SUSPECT_KEY_TYPES,
    _SuspectEntry,
    _VALID_SUCCESSORS,
    _make_comma_tail_checkpoint,
    _remove_pending_suspect_by_level,
)

# ---------------------------------------------------------------------------
# 哨兵与可吸收数字 clue（主循环中非 ADDRESS 的短数字可并入地址跨度）
# ---------------------------------------------------------------------------
_SENTINEL_STOP = object()
_SENTINEL_IGNORE = object()

_ABSORBABLE_DIGIT_ATTR_TYPES = frozenset({PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM})
_PLAIN_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")


def _is_absorbable_digit_clue(clue: Clue) -> bool:
    if clue.attr_type not in _ABSORBABLE_DIGIT_ATTR_TYPES:
        return False
    digits = (clue.source_metadata.get("pure_digits") or [""])[0]
    return len(digits) <= 5


# ---------------------------------------------------------------------------
# 一、单位流：gap、逗号/空白、search_stop（决定 clue 是否可连、扫描窗是否截断）
# ---------------------------------------------------------------------------
def _clue_unit_gap(left: Clue, right: Clue, stream: StreamInput | None = None) -> int:
    """两个 clue 之间的有效（非空白、非 inline_gap）unit 数。"""
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
    """LABEL/START 首次起栈：允许跳过空格、soft break 与 inline_gap。"""
    return _skip_from_char_by_units(
        stream,
        start_char,
        allow_space=True,
        allow_comma=True,
        allow_soft_break=True,
        allow_inline_gap=True,
    )


def _start_after_component_end(stream: StreamInput, component_end: int) -> int:
    """已有真实 component 后的新起点：只允许跳过空格、逗号与 inline_gap。"""
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
    """区间内是否存在除逗号外、会截断搜索窗口的停止分隔。"""
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


def _skip_inline_gap_left(stream: StreamInput, pos: int, floor: int) -> tuple[int, int]:
    """向左穿过 inline_gap，返回新的光标和左侧相邻 unit 下标。"""
    cursor = pos
    left_ui = _unit_index_left_of(stream, cursor)
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor or not _is_inline_gap_unit(unit):
            break
        cursor = unit.char_start
        left_ui -= 1
    return cursor, left_ui


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


# ---------------------------------------------------------------------------
# 二、KEY-KEY 链：允许行政 key 在受控单 unit 间隔下串联到同一 deferred_chain
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# 三、Suspect 与 KEY 路由（动态改 component_type、忽略无效 KEY）
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _RoutingContext:
    chain: list[Clue]
    previous_component_type: AddressComponentType | None
    previous_component_end: int | None
    ignored_key_indices: set[int]
    clues: tuple[Clue, ...]
    raw_text: str
    stream: StreamInput
    locale: str


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


# ---------------------------------------------------------------------------
# 四、KEY 左侧取值起点：左扩中英文字符 + 连续被忽略的退化 KEY
# ---------------------------------------------------------------------------
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


def _left_expand_en_word(raw_text: str, pos: int, floor: int, stream: StreamInput) -> int:
    """英文左扩展：只能跨 inline_gap，不能跨空格或任何分隔。"""
    del raw_text
    cursor, left_ui = _skip_inline_gap_left(stream, pos, floor)
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor:
            break
        if _is_inline_gap_unit(unit):
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
    raw_text: str,
    pos: int,
    floor: int,
    *,
    stream: StreamInput,
    max_chars: int,
) -> int:
    del raw_text
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
        if _is_inline_gap_unit(unit):
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


def _left_expand_zh(
    raw_text: str,
    pos: int,
    floor: int,
    stream: StreamInput,
    comp_type: AddressComponentType,
) -> int:
    """中文左扩展：仅允许跨 inline_gap，先吸收左邻英数块，再最多回退两个汉字。"""
    del comp_type
    cursor, left_ui = _skip_inline_gap_left(stream, pos, floor)
    if 0 <= left_ui < len(stream.units):
        kind = stream.units[left_ui].kind
        if kind in ("digit_run", "alpha_run", "alnum_run", "ascii_word"):
            return _left_expand_en_word(raw_text, pos, floor, stream)
    return _left_expand_zh_chars(raw_text, cursor, floor, stream=stream, max_chars=2)


# ---------------------------------------------------------------------------
# 五、VALUE 右边界扫描（逗号后右扩、前缀英文 key 取值等共用）
# ---------------------------------------------------------------------------
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
    comp_type: AddressComponentType | None = None,
) -> int:
    """按统一上下文推导动态路由要看的左侧 value 片段起点。"""
    target_type = comp_type or clue.component_type or AddressComponentType.DETAIL
    if context.chain:
        return context.chain[-1].end
    if context.previous_component_end is not None:
        return _start_after_component_end(context.stream, context.previous_component_end)
    floor = 0
    if context.locale.startswith("en"):
        return _left_expand_en_word(context.raw_text, clue.start, floor, context.stream)
    expand_start = _left_expand_zh(context.raw_text, clue.start, floor, context.stream, target_type)
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
    """把当前 KEY clue 按统一上下文重映射到实际参与状态机的类型。"""
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
    left_start = _routing_left_value_start(context, clue_index, clue, clue.component_type)
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


# ---------------------------------------------------------------------------
# 六、deferred_chain 可接性（与 clue role、unit gap、search_stop 相关）
# ---------------------------------------------------------------------------
def _chain_can_accept(chain: list[Clue], clue: Clue, stream: StreamInput) -> bool:
    """判断 clue 能否加入当前链。"""
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


def _key_has_left_value(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> bool:
    """判断 KEY 是否真的有左值；无则按普通文字忽略。"""
    if clue.text.lower() in _PREFIX_EN_KEYWORDS:
        return True
    expand_start = _routing_left_value_start(context, clue_index, clue, comp_type)
    return bool(_normalize_address_value(comp_type, context.raw_text[expand_start:clue.start]))


def _key_left_expand_start_if_deferrable(
    context: _RoutingContext,
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> int | None:
    """判断 KEY 左侧是否存在可延迟提交的 value。"""
    if clue.text.lower() in _PREFIX_EN_KEYWORDS:
        return None
    expand_start = _routing_left_value_start(context, clue_index, clue, comp_type)
    value = _normalize_address_value(comp_type, context.raw_text[expand_start:clue.start])
    if not value:
        return None
    return expand_start


# ---------------------------------------------------------------------------
# 七、LABEL 起栈与逗号尾预演、后继 KEY 前瞻（跨 clue 向前看）
# ---------------------------------------------------------------------------
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
    """从 after_index 之后找第一个可消费的 ADDRESS 线索。"""
    for index in range(after_index + 1, len(clues)):
        clue = clues[index]
        if is_break_clue(clue):
            return None
        if is_negative_clue(clue) or clue.attr_type is None:
            continue
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            return index
    return None


def _non_space_units_to_unit_start(stream: StreamInput, char_pos: int, unit_start: int) -> int:
    """从 char_pos 到目标 unit 起点（含目标 unit）的非空白、非 inline_gap unit 数。"""
    start_ui = _unit_index_at_or_after(stream, char_pos)
    if start_ui >= len(stream.units):
        return 0
    count = 0
    for ui in range(start_ui, min(unit_start + 1, len(stream.units))):
        if stream.units[ui].kind not in {"space", "inline_gap"}:
            count += 1
    return count


def _comma_char_index_in_gap(raw_text: str, last_end: int, clue_start: int) -> int | None:
    """gap [last_end, clue_start) 内第一个逗号下标；无则 None。"""
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
    """逗号后首个真正 component 必须是区及以上行政层，且要高于左侧最高 admin。"""
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
    locale: str,
) -> tuple[AddressComponentType | None, bool]:
    """预演逗号尾首段，返回首个 component 类型及是否需要保持链打开等待 KEY。"""
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
            locale=locale,
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
    """逗号后 VALUE 右扩上界：与下一 ADDRESS 非 LABEL 间距 ≤1 unit 时才扩到其起点前。"""
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


def _bridge_last_address_to_next_within_units(
    state: _ParseState,
    next_address_clue: Clue,
    stream: StreamInput,
) -> bool:
    """上一 ADDRESS clue 与下一 ADDRESS clue 的 unit 起点间距是否 ≤6。"""
    if state.last_consumed is None:
        return False
    if _clue_gap_has_search_stop(state.last_consumed, next_address_clue, stream):
        return False
    gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
    return next_address_clue.unit_start - gap_anchor <= 6


def _has_reasonable_successor_key(
    state: _ParseState,
    clues: tuple[Clue, ...],
    index: int,
    admin_type: AddressComponentType,
    stream: StreamInput,
    raw_text: str,
    locale: str,
) -> bool:
    """后置 admin VALUE 的前瞻：按最终链路落成的 component 判断是否有合理后继。"""
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
            locale=locale,
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


# ---------------------------------------------------------------------------
# 八、逗号尾门控（flush + digit_tail 物化 + 快照 + segment_state）
# ---------------------------------------------------------------------------
def _comma_tail_prehandle(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    locale: str,
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    *,
    flush_chain,
    materialize_digit_tail_before_comma,
) -> object | None:
    """gap 内若有逗号：先断开左链，再按首个真实 component 做准入判定。"""
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
        locale,
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


def _en_prefix_keywords() -> set[str]:
    keywords: set[str] = set()
    for group in load_en_address_keyword_groups():
        if group.component_type != AddressComponentType.DETAIL:
            continue
        for keyword in group.keywords:
            text = str(keyword or "").strip().lower()
            if text:
                keywords.add(text)
    keywords.add("#")
    return keywords


_PREFIX_EN_KEYWORDS = _en_prefix_keywords()

# ---------------------------------------------------------------------------
# 九、数字尾（最后一个组件后的 digit_run → BUILDING/DETAIL 等）
# ---------------------------------------------------------------------------
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
    """逗号左侧在切段前先补一次 digit_tail，避免 detail 落到逗号后被漏掉。"""
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

    if _has_following_address_key(clues, next_unit.char_end, stream, clue_scan_index):
        return DigitTailResult(
            new_components=new_components,
            unit_text=next_unit.text,
            pure_digits=re.sub(r"\D", "", next_unit.text),
            followed_by_address_key=True,
            challenge_clue_index=None,
            consumed_clue_ids=consumed_clue_ids,
            consumed_clue_indices=consumed_clue_indices,
        )

    return DigitTailResult(
        new_components=new_components,
        unit_text=next_unit.text,
        pure_digits=re.sub(r"\D", "", next_unit.text),
        followed_by_address_key=False,
        challenge_clue_index=clue_idx,
        consumed_clue_ids=consumed_clue_ids,
        consumed_clue_indices=consumed_clue_indices,
    )


# ---------------------------------------------------------------------------
# 十、HARD clue span 内子分词（供 `_run_hard` 使用）
# ---------------------------------------------------------------------------
def _sub_tokenize(stream: StreamInput, hard_clue: Clue, locale: str) -> list[Clue]:
    """在 HARD clue span 内扫描地址关键词，产出 sub-clue 列表。"""
    from privacyguard.infrastructure.pii.detector.scanner import (
        _en_address_key_matcher,
        _en_address_value_matcher,
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

    matchers_value = []
    matchers_key = []
    if locale in ("zh", "zh_cn", "mixed") or not locale.startswith("en"):
        matchers_value.append(_zh_address_value_matcher())
        matchers_key.append(_zh_address_key_matcher())
    if locale.startswith("en") or locale == "mixed":
        matchers_value.append(_en_address_value_matcher())
        matchers_key.append(_en_address_key_matcher())

    for matcher in matchers_value:
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

    for matcher in matchers_key:
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
