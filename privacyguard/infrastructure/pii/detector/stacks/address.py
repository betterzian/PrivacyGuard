"""地址 stack：基于 clue 状态机的地址解析。

核心流程：seed → 主循环（deferred_chain + segment_admit）→ fixup_suspected → digit_tail → build_run。
参见 docs/address.md。
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value, has_address_signal, trim_candidate
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    StreamInput,
    StreamUnit,
)
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_keyword_groups,
)
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, PendingChallenge, StackRun
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
    is_any_break,
    is_hard_break,
)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 单占位类型：同一地址实例内最多出现一次。
SINGLE_OCCUPY = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.SUBDISTRICT,
    AddressComponentType.ROAD,
    AddressComponentType.NUMBER,
})

_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.SUBDISTRICT,
})

# 逗号尾只允许区及以上行政层参与；街道、道路、POI 等一律视为非法回滚。
_COMMA_TAIL_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
})

# 行政层级全序：逗号逆序判定时「高于」用（数值大表示层级高）。
_ADMIN_RANK: dict[AddressComponentType, int] = {
    AddressComponentType.SUBDISTRICT: 1,
    AddressComponentType.DISTRICT: 2,
    AddressComponentType.CITY: 3,
    AddressComponentType.PROVINCE: 4,
}

# 后继图（段内正向检查用）。
_VALID_SUCCESSORS: dict[AddressComponentType, frozenset[AddressComponentType]] = {
    AddressComponentType.PROVINCE:    frozenset({AddressComponentType.CITY, AddressComponentType.DISTRICT,
                                                 AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI}),
    AddressComponentType.CITY:        frozenset({AddressComponentType.DISTRICT, AddressComponentType.SUBDISTRICT,
                                                 AddressComponentType.ROAD, AddressComponentType.POI}),
    AddressComponentType.DISTRICT:    frozenset({AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI}),
    AddressComponentType.SUBDISTRICT: frozenset({AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI, AddressComponentType.NUMBER}),
    AddressComponentType.ROAD:        frozenset({AddressComponentType.NUMBER, AddressComponentType.POI,
                                                 AddressComponentType.BUILDING, AddressComponentType.DETAIL}),
    AddressComponentType.NUMBER:      frozenset({AddressComponentType.POI, AddressComponentType.BUILDING,
                                                 AddressComponentType.DETAIL}),
    AddressComponentType.POI:         frozenset({AddressComponentType.NUMBER, AddressComponentType.BUILDING,
                                                 AddressComponentType.DETAIL}),
    AddressComponentType.BUILDING:    frozenset({AddressComponentType.DETAIL}),
    AddressComponentType.DETAIL:      frozenset({AddressComponentType.DETAIL}),
}

# 链式吸收时，这些 KEY 类型可作为链的终端消费者。
_POI_COMBINABLE_TYPES = frozenset({
    AddressComponentType.ROAD,
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
    AddressComponentType.SUBDISTRICT,
    AddressComponentType.POI,
})

_DETAIL_COMPONENTS = frozenset({
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
})

_DIGIT_TAIL_TRIGGER_TYPES = frozenset({
    AddressComponentType.ROAD,
    AddressComponentType.POI,
    AddressComponentType.NUMBER,
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
})

_SINGLE_EVIDENCE_ADMIN = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
})

_ABSORBABLE_DIGIT_ATTR_TYPES = frozenset({PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM})

_SENTINEL_STOP = object()


def _compute_reachable(
    successors: dict[AddressComponentType, frozenset[AddressComponentType]],
) -> dict[AddressComponentType, frozenset[AddressComponentType]]:
    """传递闭包：从每个节点出发可多步到达的所有节点集合。"""
    reachable: dict[AddressComponentType, set[AddressComponentType]] = {}
    for node in successors:
        visited: set[AddressComponentType] = set()
        stack = list(successors.get(node, frozenset()))
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            stack.extend(successors.get(cur, frozenset()))
        reachable[node] = visited
    return {k: frozenset(v) for k, v in reachable.items()}


_REACHABLE = _compute_reachable(_VALID_SUCCESSORS)
_ALL_TYPES = frozenset(AddressComponentType)
_IndexedClue = tuple[int, Clue]

# ---------------------------------------------------------------------------
# 内部数据结构
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _DraftComponent:
    """主循环产出的草稿 component。fixup 阶段可写入 suspected。"""

    component_type: AddressComponentType
    start: int
    end: int
    value: str | list[str]
    key: str | list[str]
    is_detail: bool = False
    raw_chain: list[Clue] = field(default_factory=list)
    suspected: dict[str, str] = field(default_factory=dict)
    clue_ids: set[str] = field(default_factory=set)
    clue_indices: set[int] = field(default_factory=set)
    suspect_demoted: bool = False


@dataclass(slots=True)
class _CommaSegmentState:
    """逗号尾部分组状态。"""

    direction: str | None = None
    group_first_type: AddressComponentType | None = None
    group_last_type: AddressComponentType | None = None
    #: True 表示当前处于「上一逗号之后、下一逗号之前」的尾段；方向在**第二个已提交 component** 上锁定。
    comma_tail_active: bool = False

    def reset(self) -> None:
        self.direction = None
        self.group_first_type = None
        self.group_last_type = None
        self.comma_tail_active = False


@dataclass(slots=True)
class _CommaTailCheckpoint:
    """最近一个逗号左侧的可回滚快照。"""

    comma_pos: int
    components: list[_DraftComponent]
    occupancy: dict[AddressComponentType, int]
    component_counts: dict[AddressComponentType, int]
    segment_state: _CommaSegmentState
    last_component_type: AddressComponentType | None
    last_end: int
    committed_clue_ids: set[str]
    consumed_clue_indices: set[int]
    last_consumed_clue_index: int
    pending_community_poi_index: int | None
    evidence_count: int
    suppress_challenger_clue_ids: set[str]
    extra_consumed_clue_ids: set[str]
    absorbed_digit_unit_end: int


@dataclass(slots=True)
class _ParseState:
    """run_with_clues 的可变解析状态。"""

    components: list[_DraftComponent] = field(default_factory=list)
    occupancy: dict[AddressComponentType, int] = field(default_factory=dict)
    deferred_chain: list[_IndexedClue] = field(default_factory=list)
    suspect_chain: list[_IndexedClue] = field(default_factory=list)
    chain_left_anchor: int | None = None
    segment_state: _CommaSegmentState = field(default_factory=_CommaSegmentState)
    last_consumed: Clue | None = None
    last_value: Clue | None = None
    evidence_count: int = 0
    last_end: int = 0
    split_at: int | None = None
    absorbed_digit_unit_end: int = 0
    last_component_type: AddressComponentType | None = None
    committed_clue_ids: set[str] = field(default_factory=set)
    extra_consumed_clue_ids: set[str] = field(default_factory=set)
    consumed_clue_indices: set[int] = field(default_factory=set)
    last_consumed_clue_index: int = -1
    #: NAME/ORG 在「上一 ADDRESS clue 与下一 ADDRESS clue」unit 间距 ≤6 内被跨过时登记，供 StackRun 告知 parser 勿作挑战栈。
    suppress_challenger_clue_ids: set[str] = field(default_factory=set)
    #: 逗号尾成功准入后，下一条 VALUE 可做一次右向 raw 扩展（clue_id → char end）。
    value_char_end_override: dict[str, int] = field(default_factory=dict)
    pending_comma_value_right_scan: bool = False
    #: True 表示逗号尾的首个 component 尚未真正提交，需先按链规则完成后再恢复 eager flush。
    pending_comma_first_component: bool = False
    #: 组件出现次数，用于模拟地址数组中的占位计数。
    component_counts: dict[AddressComponentType, int] = field(default_factory=dict)
    #: 最近一个被临时当成 poi 的“社区”组件索引；等 road 到来时再判是否回退为 subdistrict。
    pending_community_poi_index: int | None = None
    #: 最近一个逗号左侧的回滚快照；仅在逗号尾行政链中使用。
    comma_tail_checkpoint: _CommaTailCheckpoint | None = None


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _is_absorbable_digit_clue(clue: Clue) -> bool:
    if clue.attr_type not in _ABSORBABLE_DIGIT_ATTR_TYPES:
        return False
    digits = (clue.source_metadata.get("pure_digits") or [""])[0]
    return len(digits) <= 5


def _clue_unit_gap(left: Clue, right: Clue, stream: StreamInput | None = None) -> int:
    """两个 clue 之间的有效（非空白）unit 数。"""
    if stream is not None and stream.units:
        gap_start = left.unit_end
        gap_end = right.unit_start
        count = 0
        for ui in range(gap_start, min(gap_end, len(stream.units))):
            if stream.units[ui].kind != "space":
                count += 1
        return count
    return max(0, right.unit_start - left.unit_end)


def _is_key_key_gap_text_unit_allowed(unit: StreamUnit) -> bool:
    """判断 gap=1 时中间正文 unit 是否允许触发 KEY→KEY 传导。

    规则：
    1. 中文 `cjk_char` 允许。
    2. 英文 `ascii_word` 仅当长度至少为 3 时允许。
    """
    if unit.kind == "cjk_char":
        return True
    if unit.kind == "ascii_word":
        return len(unit.text) >= 3
    return False


def _last_non_space_unit_in_span(clue: Clue, stream: StreamInput) -> StreamUnit | None:
    """返回 clue 覆盖范围内最后一个非空白 unit。"""
    for ui in range(min(clue.unit_end, len(stream.units)) - 1, clue.unit_start - 1, -1):
        unit = stream.units[ui]
        if unit.kind != "space":
            return unit
    return None


def _first_non_space_unit_in_span(clue: Clue, stream: StreamInput) -> StreamUnit | None:
    """返回 clue 覆盖范围内第一个非空白 unit。"""
    for ui in range(clue.unit_start, min(clue.unit_end, len(stream.units))):
        unit = stream.units[ui]
        if unit.kind != "space":
            return unit
    return None


def _key_key_chain_gap_allowed(left: Clue, right: Clue, stream: StreamInput | None) -> bool:
    """KEY→KEY 是否允许挂链：gap=0；或 gap=1 且只允许指定正文穿透。

    gap=1 时：
    1. 中间 unit 若是中文 `cjk_char`，允许。
    2. 中间 unit 若是英文 `ascii_word`，仅长度至少为 3 时允许。
    3. 若左右边界都是英文 `ascii_word`，中间 unit 不允许是中文。
    4. 若左右边界都是中文 `cjk_char`，中间 unit 可以是中文或长英文。
    """
    gap = _clue_unit_gap(left, right, stream)
    if gap == 0:
        return True
    if gap != 1:
        return False
    if stream is None or not stream.units:
        return False
    gap_start = left.unit_end
    gap_end = right.unit_start
    non_space = [
        stream.units[ui]
        for ui in range(gap_start, min(gap_end, len(stream.units)))
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


def _clone_component_value(value: str | list[str]) -> str | list[str]:
    if isinstance(value, list):
        return list(value)
    return value


def _clone_component_key(key: str | list[str]) -> str | list[str]:
    if isinstance(key, list):
        return list(key)
    return key


def _clone_draft_component(component: _DraftComponent) -> _DraftComponent:
    """复制组件，避免回滚快照与实时状态共享可变容器。"""
    return _DraftComponent(
        component_type=component.component_type,
        start=component.start,
        end=component.end,
        value=_clone_component_value(component.value),
        key=_clone_component_key(component.key),
        is_detail=component.is_detail,
        raw_chain=list(component.raw_chain),
        suspected=dict(component.suspected),
        clue_ids=set(component.clue_ids),
        clue_indices=set(component.clue_indices),
        suspect_demoted=component.suspect_demoted,
    )


def _make_comma_tail_checkpoint(
    state: _ParseState,
    comma_pos: int,
) -> _CommaTailCheckpoint:
    """记录最近一个逗号左侧的解析快照。"""
    return _CommaTailCheckpoint(
        comma_pos=comma_pos,
        components=[_clone_draft_component(component) for component in state.components],
        occupancy=dict(state.occupancy),
        component_counts=dict(state.component_counts),
        segment_state=replace(state.segment_state),
        last_component_type=state.last_component_type,
        last_end=state.last_end,
        committed_clue_ids=set(state.committed_clue_ids),
        consumed_clue_indices=set(state.consumed_clue_indices),
        last_consumed_clue_index=state.last_consumed_clue_index,
        pending_community_poi_index=state.pending_community_poi_index,
        evidence_count=state.evidence_count,
        suppress_challenger_clue_ids=set(state.suppress_challenger_clue_ids),
        extra_consumed_clue_ids=set(state.extra_consumed_clue_ids),
        absorbed_digit_unit_end=state.absorbed_digit_unit_end,
    )


def _restore_comma_tail_checkpoint(
    state: _ParseState,
    checkpoint: _CommaTailCheckpoint,
) -> None:
    """回滚到最近一个逗号左侧状态。"""
    state.components = [_clone_draft_component(component) for component in checkpoint.components]
    state.occupancy = dict(checkpoint.occupancy)
    state.component_counts = dict(checkpoint.component_counts)
    state.deferred_chain.clear()
    state.suspect_chain.clear()
    state.chain_left_anchor = None
    state.segment_state = replace(checkpoint.segment_state)
    state.last_component_type = checkpoint.last_component_type
    state.last_end = checkpoint.last_end
    state.committed_clue_ids = set(checkpoint.committed_clue_ids)
    state.extra_consumed_clue_ids = set(checkpoint.extra_consumed_clue_ids)
    state.consumed_clue_indices = set(checkpoint.consumed_clue_indices)
    state.last_consumed_clue_index = checkpoint.last_consumed_clue_index
    state.suppress_challenger_clue_ids = set(checkpoint.suppress_challenger_clue_ids)
    state.value_char_end_override.clear()
    state.pending_comma_value_right_scan = False
    state.pending_comma_first_component = False
    state.pending_community_poi_index = checkpoint.pending_community_poi_index
    state.evidence_count = checkpoint.evidence_count
    state.absorbed_digit_unit_end = checkpoint.absorbed_digit_unit_end
    state.comma_tail_checkpoint = None


def _rollback_invalid_comma_tail_component(
    state: _ParseState,
    component: _DraftComponent,
) -> bool:
    """逗号尾一旦落到区以下层级，就回滚到最近逗号左侧并停止。"""
    if not state.segment_state.comma_tail_active:
        return False
    if component.component_type in _COMMA_TAIL_ADMIN_TYPES:
        return False
    checkpoint = state.comma_tail_checkpoint
    if checkpoint is None:
        state.deferred_chain.clear()
        state.suspect_chain.clear()
        state.chain_left_anchor = None
        state.value_char_end_override.clear()
        state.pending_comma_value_right_scan = False
        state.pending_comma_first_component = False
        state.segment_state.reset()
        state.split_at = component.start
        return True
    _restore_comma_tail_checkpoint(state, checkpoint)
    state.split_at = checkpoint.comma_pos
    return True


def _en_prefix_keywords() -> set[str]:
    keywords: set[str] = set()
    for group in load_en_address_keyword_groups():
        if group.component_type != AddressComponentType.DETAIL:
            continue
        for kw in group.keywords:
            text = str(kw or "").strip().lower()
            if text:
                keywords.add(text)
    keywords.add("#")
    return keywords


_PREFIX_EN_KEYWORDS = _en_prefix_keywords()
_EN_VALUE_KEY_GAP_RE = re.compile(r"^[ ]*$")
_PLAIN_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")

# ---------------------------------------------------------------------------
# 链式吸收
# ---------------------------------------------------------------------------


def _chain_can_accept(state: _ParseState, clue: Clue, stream: StreamInput) -> bool:
    """判断 clue 能否加入当前 deferred_chain。

    只允许三种链接：
    1. VALUE→VALUE: gap ≤ 1 non-space unit。
    2. VALUE→KEY: gap ≤ 1 non-space unit。
    3. KEY→KEY: gap=0；或 gap=1 且中间唯一的非 space unit 非 digit 类。

    KEY→VALUE 不允许继续挂链。
    """
    if not state.deferred_chain:
        return False
    _, last = state.deferred_chain[-1]
    gap = _clue_unit_gap(last, clue, stream)
    if last.role == ClueRole.KEY and clue.role == ClueRole.VALUE:
        return False
    if last.role == ClueRole.KEY and clue.role == ClueRole.KEY:
        return _key_key_chain_gap_allowed(last, clue, stream)
    if last.role == ClueRole.VALUE and clue.role == ClueRole.KEY:
        return gap <= 6
    return gap <= 1


def _mark_consumed_indices(state: _ParseState, clue_indices: Iterable[int]) -> None:
    """记录当前 run 已实际消费的 clue 索引。"""
    indices = {idx for idx in clue_indices if idx >= 0}
    if not indices:
        return
    state.consumed_clue_indices |= indices
    state.last_consumed_clue_index = max(
        state.last_consumed_clue_index,
        max(indices),
    )


def _append_deferred(
    state: _ParseState,
    clue_index: int,
    clue: Clue,
    *,
    record_suspect: bool,
) -> None:
    """把 clue 放进当前链，并按语义决定是否进入 suspect 候选。"""
    state.deferred_chain.append((clue_index, clue))
    if record_suspect and clue.role == ClueRole.VALUE and clue.component_type in _ADMIN_TYPES:
        state.suspect_chain.append((clue_index, clue))
    if state.chain_left_anchor is None:
        state.chain_left_anchor = clue.start


def _remove_suspect_by_clue_id(state: _ParseState, clue_id: str) -> None:
    """从 suspect 候选里删除指定 clue。"""
    state.suspect_chain = [
        indexed for indexed in state.suspect_chain
        if indexed[1].clue_id != clue_id
    ]


def _remove_last_value_suspect(
    state: _ParseState,
    key_clue: Clue,
    stream: StreamInput,
) -> None:
    """仅当 VALUE 与 KEY 紧邻时，前一个 VALUE 才视为 KEY 自身 value。"""
    if not state.deferred_chain:
        return
    _, last = state.deferred_chain[-1]
    if last.role != ClueRole.VALUE:
        return
    if _clue_unit_gap(last, key_clue, stream) > 1:
        return
    _remove_suspect_by_clue_id(state, last.clue_id)


def _prune_prior_component_suspects(
    state: _ParseState,
    new_component: _DraftComponent,
) -> None:
    """后续真实组件一旦落地，只删除旧组件里同层级的 suspect。"""
    new_type = new_component.component_type
    if new_type not in _ADMIN_TYPES:
        return
    for prior in state.components[:-1]:
        kept = [
            clue for clue in prior.raw_chain
            if clue.component_type != new_type
        ]
        if len(kept) != len(prior.raw_chain):
            prior.raw_chain = kept
            prior.suspect_demoted = True


def _recompute_last_consumed_index(state: _ParseState) -> None:
    """按当前 surviving 的消费集合重算最后消费位置。"""
    if state.consumed_clue_indices:
        state.last_consumed_clue_index = max(state.consumed_clue_indices)
    else:
        state.last_consumed_clue_index = -1


def _increment_component_count(state: _ParseState, component_type: AddressComponentType) -> None:
    """增加组件占位计数。"""
    state.component_counts[component_type] = state.component_counts.get(component_type, 0) + 1


def _decrement_component_count(state: _ParseState, component_type: AddressComponentType) -> None:
    """减少组件占位计数。"""
    count = state.component_counts.get(component_type, 0)
    if count <= 1:
        state.component_counts.pop(component_type, None)
        return
    state.component_counts[component_type] = count - 1


def _mark_pending_community_poi(state: _ParseState, component: _DraftComponent) -> None:
    """记录最近一个被临时视为 poi 的“社区”组件。"""
    if component.component_type != AddressComponentType.POI:
        return
    if isinstance(component.key, list):
        return
    if component.key != "社区":
        return
    state.pending_community_poi_index = len(state.components) - 1


def _clear_pending_community_poi(state: _ParseState) -> None:
    """清空临时社区开关。"""
    state.pending_community_poi_index = None


def _pending_community_blocks_road(state: _ParseState) -> bool:
    """判断当前 road 是否必须在前一个已提交组件处 stop。"""
    if state.component_counts.get(AddressComponentType.POI, 0) > 1:
        return True
    for component_type in (
        AddressComponentType.PROVINCE,
        AddressComponentType.CITY,
        AddressComponentType.DISTRICT,
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
    ):
        if state.component_counts.get(component_type, 0) > 0:
            return True
    return False


def _reroute_pending_community_poi_to_subdistrict(state: _ParseState) -> None:
    """把最近一个临时社区 poi 回退成 subdistrict。"""
    index = state.pending_community_poi_index
    if index is None or index >= len(state.components):
        _clear_pending_community_poi(state)
        return
    component = state.components[index]
    if component.component_type != AddressComponentType.POI:
        _clear_pending_community_poi(state)
        return
    component.component_type = AddressComponentType.SUBDISTRICT
    component.is_detail = False
    _decrement_component_count(state, AddressComponentType.POI)
    _increment_component_count(state, AddressComponentType.SUBDISTRICT)
    state.occupancy[AddressComponentType.SUBDISTRICT] = index
    if state.last_component_type == AddressComponentType.POI and index == len(state.components) - 1:
        state.last_component_type = AddressComponentType.SUBDISTRICT
    if state.segment_state.group_last_type == AddressComponentType.POI:
        state.segment_state.group_last_type = AddressComponentType.SUBDISTRICT
    if state.segment_state.group_first_type == AddressComponentType.POI and len(state.components) == 1:
        state.segment_state.group_first_type = AddressComponentType.SUBDISTRICT
    _clear_pending_community_poi(state)


def _state_routing_context_type(state: _ParseState) -> AddressComponentType | None:
    """返回当前地址实例里最近一个可用于动态路由的组件类型。"""
    if state.deferred_chain:
        for _, clue in reversed(state.deferred_chain):
            if clue.component_type is not None:
                return clue.component_type
    return state.last_component_type


def _preview_routing_context_type(
    chain: list[Clue],
    previous_component_type: AddressComponentType | None,
) -> AddressComponentType | None:
    """返回逗号尾预演链里最近一个可用于动态路由的组件类型。"""
    for clue in reversed(chain):
        if clue.component_type is not None:
            return clue.component_type
    return previous_component_type


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


def _routing_left_value_start_for_state(
    state: _ParseState,
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    raw_text: str,
    stream: StreamInput,
    locale: str,
) -> int:
    """按当前状态推导动态路由要看的左侧 value 片段起点。"""
    if state.deferred_chain:
        return state.deferred_chain[-1][1].end
    if state.components:
        return state.last_end
    floor = _left_address_floor(clues, clue_index)
    prev_key_end = _left_prev_address_key_end(clues, clue_index)
    if prev_key_end is not None:
        floor = max(floor, prev_key_end)
    if locale.startswith("en"):
        return _left_expand_en_word(raw_text, clue.start, floor)
    return _left_expand_zh(raw_text, clue.start, floor, stream, clue.component_type or AddressComponentType.DETAIL)


def _routing_left_value_start_for_preview(
    chain: list[Clue],
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    raw_text: str,
    stream: StreamInput,
    locale: str,
) -> int:
    """按逗号尾预演状态推导动态路由要看的左侧 value 片段起点。"""
    if chain:
        return chain[-1].end
    floor = _left_address_floor(clues, clue_index)
    prev_key_end = _left_prev_address_key_end(clues, clue_index)
    if prev_key_end is not None:
        floor = max(floor, prev_key_end)
    if locale.startswith("en"):
        return _left_expand_en_word(raw_text, clue.start, floor)
    return _left_expand_zh(raw_text, clue.start, floor, stream, clue.component_type or AddressComponentType.DETAIL)


def _has_following_detail_key(
    clues: tuple[Clue, ...],
    clue_index: int,
    stream: StreamInput,
) -> bool:
    """判断当前 KEY 右侧是否还有更细的 detail KEY。"""
    anchor = clues[clue_index]
    for index in range(clue_index + 1, len(clues)):
        clue = clues[index]
        if is_break_clue(clue):
            return False
        if is_negative_clue(clue):
            continue
        if _clue_unit_gap(anchor, clue, stream) > 6:
            return False
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        if clue.role != ClueRole.KEY or clue.component_type is None:
            continue
        return clue.component_type in _DETAIL_COMPONENTS
    return False


def _routed_key_clue_for_state(
    state: _ParseState,
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    raw_text: str,
    stream: StreamInput,
    locale: str,
) -> Clue:
    """把当前 KEY clue 按地址上下文重映射到实际参与状态机的类型。"""
    if clue.role != ClueRole.KEY or clue.component_type is None:
        return clue
    previous_component_type = _state_routing_context_type(state)
    left_start = _routing_left_value_start_for_state(
        state, clues, clue_index, clue, raw_text, stream, locale,
    )
    left_value_text = clean_value(raw_text[left_start:clue.start])
    routed_type = _route_dynamic_key_type(
        clue,
        previous_component_type=previous_component_type,
        left_value_text=left_value_text,
        followed_by_detail_key=_has_following_detail_key(clues, clue_index, stream),
    )
    if routed_type == clue.component_type:
        return clue
    return replace(clue, component_type=routed_type)


def _routed_key_clue_for_preview(
    chain: list[Clue],
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    raw_text: str,
    stream: StreamInput,
    locale: str,
    previous_component_type: AddressComponentType | None,
) -> Clue:
    """把逗号尾预演中的 KEY clue 按预演上下文重映射。"""
    if clue.role != ClueRole.KEY or clue.component_type is None:
        return clue
    context_type = _preview_routing_context_type(chain, previous_component_type)
    left_start = _routing_left_value_start_for_preview(
        chain, clues, clue_index, clue, raw_text, stream, locale,
    )
    left_value_text = clean_value(raw_text[left_start:clue.start])
    routed_type = _route_dynamic_key_type(
        clue,
        previous_component_type=context_type,
        left_value_text=left_value_text,
        followed_by_detail_key=_has_following_detail_key(clues, clue_index, stream),
    )
    if routed_type == clue.component_type:
        return clue
    return replace(clue, component_type=routed_type)


def _flush_chain(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    locale: str,
    *,
    clues: tuple[Clue, ...] | None = None,
    clue_index: int = 0,
) -> None:
    """冲洗 deferred_chain。

    若链中含 KEY，用最后一个 KEY 消费链（build_chain_component）。
    否则逐个 standalone（flush_chain_as_standalone）。
    """
    if not state.deferred_chain:
        return

    last_key_idx: int | None = None
    for i in range(len(state.deferred_chain) - 1, -1, -1):
        if state.deferred_chain[i][1].role == ClueRole.KEY:
            last_key_idx = i
            break

    if last_key_idx is not None:
        used_entries = state.deferred_chain[:last_key_idx + 1]
        used_indices = {idx for idx, _ in used_entries}
        key_clue = used_entries[-1][1]
        comp_type = key_clue.component_type or AddressComponentType.POI
        # NUMBER 上下文重映射。
        if comp_type == AddressComponentType.NUMBER and state.last_component_type in _DETAIL_COMPONENTS:
            comp_type = AddressComponentType.DETAIL

        raw_chain_clues = [
            clue for idx, clue in state.suspect_chain
            if idx in used_indices
        ]
        # 组件取值边界以 component_start 为准，不在组件阶段做左扩展补课。
        component_start = state.chain_left_anchor if state.chain_left_anchor is not None else key_clue.start
        expand_start = component_start

        value_text = raw_text[expand_start:key_clue.start]
        value = _normalize_address_value(comp_type, value_text)

        if value:
            component = _DraftComponent(
                component_type=comp_type,
                start=expand_start,
                end=key_clue.end,
                value=value,
                key=key_clue.text,
                is_detail=comp_type in _DETAIL_COMPONENTS,
                raw_chain=raw_chain_clues,
                clue_ids={clue.clue_id for _, clue in used_entries},
                clue_indices=used_indices,
            )
            _commit(state, component)
        else:
            # value 为空 → 丢弃此组件。穿透的中间 KEY 也丢弃。
            pass
    else:
        _flush_chain_as_standalone(state, raw_text)

    state.deferred_chain.clear()
    state.suspect_chain.clear()
    state.chain_left_anchor = None
    state.value_char_end_override.clear()


def _flush_chain_as_standalone(state: _ParseState, raw_text: str) -> None:
    """链中无 KEY 时，逐个 VALUE 作为独立 component 提交。"""
    for clue_index, clue in state.deferred_chain:
        comp_type = clue.component_type
        if comp_type is None:
            continue
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            state.split_at = clue.start
            break
        value_end = state.value_char_end_override.get(clue.clue_id, clue.end)
        value = _normalize_address_value(comp_type, raw_text[clue.start:value_end])
        if not value:
            continue
        component = _DraftComponent(
            component_type=comp_type,
            start=clue.start,
            end=value_end,
            value=value,
            key="",
            is_detail=comp_type in _DETAIL_COMPONENTS,
            raw_chain=[],
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )
        if not _commit(state, component):
            break


def _apply_comma_tail_segment_after_commit(
    state: _ParseState,
    committed: _DraftComponent,
) -> None:
    """逗号尾内：方向在**第二个新提交的 component** 上锁定；非逗号尾只维护 group_last_type。"""
    seg = state.segment_state
    ct = committed.component_type
    if not seg.comma_tail_active:
        seg.group_last_type = ct
        return
    if seg.group_first_type is None:
        seg.group_first_type = ct
        seg.group_last_type = ct
        return
    if seg.direction is None:
        first = seg.group_first_type
        if ct == first:
            seg.group_last_type = ct
            return
        if ct in _VALID_SUCCESSORS.get(first, _ALL_TYPES):
            seg.direction = "forward"
        elif first in _VALID_SUCCESSORS.get(ct, _ALL_TYPES):
            seg.direction = "reverse"
        seg.group_last_type = ct
        return
    seg.group_last_type = ct


def _commit(state: _ParseState, component: _DraftComponent) -> bool:
    """提交 component 到 state，更新 occupancy / segment / evidence。"""
    if not _segment_admit(state, component.component_type):
        state.split_at = component.start
        return False
    if _rollback_invalid_comma_tail_component(state, component):
        return False
    comp_type = component.component_type
    if comp_type == AddressComponentType.POI:
        committed = _commit_poi(state, component)
        is_fresh_component = committed is component
    else:
        state.components.append(component)
        committed = component
        is_fresh_component = True
    if is_fresh_component:
        _increment_component_count(state, comp_type)
    idx = len(state.components) - 1
    if comp_type in SINGLE_OCCUPY:
        state.occupancy[comp_type] = idx
    if is_fresh_component:
        _apply_comma_tail_segment_after_commit(state, committed)
    else:
        state.segment_state.group_last_type = committed.component_type
    if state.segment_state.comma_tail_active and state.pending_comma_first_component:
        state.pending_comma_first_component = False
    state.last_component_type = committed.component_type
    state.last_end = max(state.last_end, committed.end)
    state.evidence_count += 1
    state.committed_clue_ids |= committed.clue_ids
    _mark_consumed_indices(state, committed.clue_indices)
    _prune_prior_component_suspects(state, committed)
    if is_fresh_component:
        _mark_pending_community_poi(state, committed)
    return True


def _commit_poi(state: _ParseState, component: _DraftComponent) -> _DraftComponent:
    """POI 列表化：同一地址内多个 POI 合并到一个 component。"""
    for existing in state.components:
        if existing.component_type == AddressComponentType.POI:
            if not isinstance(existing.value, list):
                existing.value = [existing.value]
            if not isinstance(existing.key, list):
                existing.key = [existing.key]
            val = component.value[0] if isinstance(component.value, list) else component.value
            key = component.key[0] if isinstance(component.key, list) else component.key
            existing.value.append(val)
            existing.key.append(key)
            existing.end = max(existing.end, component.end)
            existing.clue_ids |= component.clue_ids
            existing.clue_indices |= component.clue_indices
            if state.pending_community_poi_index is not None:
                try:
                    pending = state.components[state.pending_community_poi_index]
                except IndexError:
                    _clear_pending_community_poi(state)
                else:
                    if pending is existing:
                        _clear_pending_community_poi(state)
            return existing
    state.components.append(component)
    return component


# ---------------------------------------------------------------------------
# 段内检查
# ---------------------------------------------------------------------------

def _segment_admit(
    state: _ParseState,
    comp_type: AddressComponentType,
) -> bool:
    """按最终 component 类型判断占位与直接后继合法性。"""
    if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
        return False

    segment = state.segment_state

    if segment.comma_tail_active:
        if segment.group_first_type is None:
            return True
        if segment.direction is None:
            first_type = segment.group_first_type
            if comp_type == first_type:
                return True
            ok_fwd = comp_type in _VALID_SUCCESSORS.get(first_type, _ALL_TYPES)
            ok_rev = first_type in _VALID_SUCCESSORS.get(comp_type, _ALL_TYPES)
            return ok_fwd or ok_rev
        last_type = segment.group_last_type
        if last_type is None:
            return True
        if segment.direction == "forward":
            return comp_type in _VALID_SUCCESSORS.get(last_type, _ALL_TYPES)
        return last_type in _VALID_SUCCESSORS.get(comp_type, _ALL_TYPES)

    # 非逗号尾：正序链（group_first 仅用于 comma_tail_active 段内）。
    if segment.group_last_type is None:
        return True
    return comp_type in _VALID_SUCCESSORS.get(segment.group_last_type, _ALL_TYPES)


def _has_reasonable_successor_key(
    state: _ParseState,
    clues: tuple[Clue, ...],
    index: int,
    admin_type: AddressComponentType,
    stream: StreamInput,
    raw_text: str,
    locale: str,
) -> bool:
    """后置 admin VALUE 的前瞻：仅检查右侧是否存在可连接的后继 KEY。

    这里不做右边界裁决，也不在此处让 negative / NAME / ORGANIZATION 直接截断地址。
    这些 clue 只影响最终 address 提交阶段，不影响“后面是否还存在一个可连接 KEY”的判断。
    """
    anchor = clues[index]
    preview_chain: list[Clue] = []
    for i in range(index + 1, len(clues)):
        nxt = clues[i]
        if is_break_clue(nxt):
            return False
        if is_negative_clue(nxt):
            continue
        if nxt.role == ClueRole.LABEL:
            continue
        # 前瞻窗口上限：6 unit。
        if _clue_unit_gap(anchor, nxt, stream) > 6:
            return False
        if nxt.attr_type != PIIAttributeType.ADDRESS:
            continue
        if nxt.component_type is None:
            continue
        effective = nxt
        if nxt.role == ClueRole.KEY:
            effective = _routed_key_clue_for_preview(
                preview_chain,
                clues,
                i,
                nxt,
                raw_text,
                stream,
                locale,
                _state_routing_context_type(state),
            )
        if effective.role == ClueRole.KEY and effective.component_type is not None:
            if effective.component_type == admin_type:
                return True
            if effective.component_type in _REACHABLE.get(admin_type, _ALL_TYPES):
                return True
        preview_chain.append(effective)
    return False


# ---------------------------------------------------------------------------
# fixup: suspected 信息
# ---------------------------------------------------------------------------

def _fixup_suspected_info(state: _ParseState, raw_text: str) -> None:
    """后处理：为链式 component 计算 suspected admin 信息。"""
    del raw_text

    for component in state.components:
        admin_clues = _leading_admin_value_clues(component.raw_chain)
        component.suspected = {}
        if not admin_clues:
            continue

        suspected: dict[str, str] = {}
        surviving: list[Clue] = []
        for clue in admin_clues:
            level = clue.component_type
            if level is None:
                continue
            level_key = level.value
            if level_key in suspected:
                continue
            suspected[level_key] = clue.text
            surviving.append(clue)
        component.suspected = suspected
        if suspected:
            component.value = _recompute_text(component, surviving)


def _leading_admin_value_clues(raw_chain: list[Clue]) -> list[Clue]:
    """取 raw_chain 里仍然有效的 admin VALUE clue。"""
    return [
        clue for clue in raw_chain
        if clue.role == ClueRole.VALUE and clue.component_type in _ADMIN_TYPES
    ]


def _recompute_text(
    component: _DraftComponent,
    suspected_clues: list[Clue],
) -> str:
    """从 component.value 中删除 suspected 文字，保留剩余。"""
    if isinstance(component.value, list):
        return component.value
    value = component.value
    for clue in suspected_clues:
        value = value.replace(clue.text, "", 1)
    return value.strip() or component.value


# ---------------------------------------------------------------------------
# HARD sub-tokenize
# ---------------------------------------------------------------------------

def _sub_tokenize(
    stream: StreamInput,
    hard_clue: Clue,
    locale: str,
) -> list[Clue]:
    """在 HARD clue span 内扫描地址关键词，产出 sub-clue 列表。"""
    from privacyguard.infrastructure.pii.detector.scanner import (
        _zh_address_key_matcher,
        _zh_address_value_matcher,
        _en_address_key_matcher,
        _en_address_value_matcher,
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
            us, ue = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=payload.canonical_text,
                unit_start=us,
                unit_end=ue,
                source_kind="sub_tokenize_value",
                component_type=payload.component_type,
            ))

    for matcher in matchers_key:
        for match in matcher.find_matches(text, folded_text=folded):
            abs_start = span_start + match.start
            abs_end = span_start + match.end
            payload = match.payload
            us, ue = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=payload.canonical_text,
                unit_start=us,
                unit_end=ue,
                source_kind="sub_tokenize_key",
                component_type=payload.component_type,
            ))

    # 去重：长匹配覆盖短匹配（同 role+component_type）。
    sub_clues.sort(key=lambda c: (c.start, -(c.end - c.start)))
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

    deduped.sort(key=lambda c: (c.start, c.end))
    return deduped


# ---------------------------------------------------------------------------
# AddressStack
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AddressStack(BaseStack):

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
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
            suppress_challenger_clue_ids=run.suppress_challenger_clue_ids,
        )

    # ------------------------------------------------------------------ run
    def run(self) -> StackRun | None:
        """地址 stack 主入口。"""
        if self.clue.strength == ClaimStrength.HARD:
            return self._run_hard()

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
            address_start = self.clue.start if self.clue.role in {ClueRole.VALUE, ClueRole.KEY} else None
            scan_index = self.clue_index
            consumed_ids = set()
            handled_labels = set()
            evidence_count = 0
        if address_start is None:
            return None

        return self._run_with_clues(
            clues=self.context.clues,
            mode="normal",
            scan_index=scan_index,
            address_start=address_start,
            consumed_ids=consumed_ids,
            handled_labels=handled_labels,
            evidence_count=evidence_count,
            locale=locale,
        )

    def _run_hard(self) -> StackRun | None:
        """HARD clue：子分词后走 run_with_clues。"""
        stream = self.context.stream
        locale = self._value_locale()
        sub_clues = _sub_tokenize(stream, self.clue, locale)
        if not sub_clues:
            return None

        sub_tuple = tuple(sub_clues)
        return self._run_with_sub_clues(sub_tuple, locale)

    def _run_with_sub_clues(
        self,
        sub_clues: tuple[Clue, ...],
        locale: str,
    ) -> StackRun | None:
        """hard_local 模式：用 sub_clues 走主循环。"""
        if not sub_clues:
            return None
        raw_text = self.context.stream.text
        stream = self.context.stream

        state = _ParseState()
        state.last_end = sub_clues[0].start

        negative_spans: list[tuple[int, int]] = []
        index = 0

        while index < len(sub_clues):
            clue = sub_clues[index]
            if clue.start >= self.clue.end:
                break
            if is_break_clue(clue):
                break
            if is_negative_clue(clue):
                negative_spans.append((clue.start, clue.end))
                index += 1
                continue

            if clue.attr_type != PIIAttributeType.ADDRESS:
                index += 1
                continue

            # 6-unit gap。
            if state.last_consumed is not None:
                gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
                if clue.unit_start - gap_anchor > 6:
                    break

            result = self._handle_address_clue(state, clue, raw_text, stream, locale, sub_clues, index)
            if result is _SENTINEL_STOP:
                break
            state.last_consumed = clue
            index += 1

        _flush_chain(state, raw_text, stream, locale, clues=sub_clues, clue_index=index)

        if not state.components:
            return None
        if negative_spans:
            state.components, removed_clue_ids, removed_clue_indices = _pop_components_overlapping_negative(
                state.components,
                negative_spans,
            )
            state.committed_clue_ids -= removed_clue_ids
            state.consumed_clue_indices -= removed_clue_indices
            _recompute_last_consumed_index(state)
            if not state.components:
                return None

        consumed_ids = set(state.committed_clue_ids)
        _fixup_suspected_info(state, raw_text)
        return self._build_address_run_from_state(
            state,
            consumed_ids,
            set(),
            locale,
            self.clue_index + 1,
            use_precise_next_index=False,
        )

    # -------------------------------------------------------- run_with_clues
    def _run_with_clues(
        self,
        clues: tuple[Clue, ...],
        mode: str,
        scan_index: int,
        address_start: int,
        consumed_ids: set[str],
        handled_labels: set[str],
        evidence_count: int,
        locale: str,
    ) -> StackRun | None:
        raw_text = self.context.stream.text
        stream = self.context.stream

        state = _ParseState()
        state.last_end = address_start
        state.evidence_count = evidence_count

        negative_spans: list[tuple[int, int]] = []
        index = scan_index

        while index < len(clues):
            clue = clues[index]

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
                if _is_absorbable_digit_clue(clue):
                    state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_end)
                    state.extra_consumed_clue_ids.add(clue.clue_id)
                    _mark_consumed_indices(state, {index})
                    index += 1
                    continue
                if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
                    nxt_addr = _next_address_clue_index_after(clues, index)
                    if nxt_addr is not None and _bridge_last_address_to_next_within_units(
                        state, clues[nxt_addr]
                    ):
                        state.suppress_challenger_clue_ids.add(clue.clue_id)
                        state.absorbed_digit_unit_end = max(
                            state.absorbed_digit_unit_end, clue.unit_end
                        )
                        index += 1
                        continue
                    break
                break
            if clue.role == ClueRole.LABEL:
                index += 1
                continue
            if clue.start < address_start:
                index += 1
                continue

            # 6-unit gap。
            if state.last_consumed is not None:
                gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
                if clue.unit_start - gap_anchor > 6:
                    break

            result = self._handle_address_clue(state, clue, raw_text, stream, locale, clues, index)
            if result is _SENTINEL_STOP:
                break

            state.last_consumed = clue
            index += 1

        # 循环结束 → flush 残留 chain。
        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=index)

        if state.split_at is not None:
            pass

        if not state.components:
            return None
        if negative_spans:
            state.components, removed_clue_ids, removed_clue_indices = _pop_components_overlapping_negative(
                state.components,
                negative_spans,
            )
            state.committed_clue_ids -= removed_clue_ids
            state.consumed_clue_indices -= removed_clue_indices
            _recompute_last_consumed_index(state)
            if not state.components:
                return None

        consumed_ids |= state.extra_consumed_clue_ids
        consumed_ids |= state.committed_clue_ids
        _fixup_suspected_info(state, raw_text)

        # digit_tail 三路分支。
        tail = _analyze_digit_tail(state.components, stream, clues, index)
        if tail is None:
            pass
        elif tail.followed_by_address_key:
            for tc in tail.new_components:
                state.components.append(tc)
            consumed_ids |= tail.consumed_clue_ids
            _mark_consumed_indices(state, tail.consumed_clue_indices)
        else:
            conservative_run = self._build_address_run_from_state(
                state, consumed_ids, handled_labels, locale, index,
            )
            if conservative_run is None:
                return None
            extended_components = list(state.components) + tail.new_components
            state_ext = _ParseState()
            state_ext.components = extended_components
            state_ext.evidence_count = state.evidence_count
            state_ext.suppress_challenger_clue_ids = set(state.suppress_challenger_clue_ids)
            state_ext.consumed_clue_indices = set(state.consumed_clue_indices) | set(tail.consumed_clue_indices)
            _recompute_last_consumed_index(state_ext)
            extended_consumed_ids = set(consumed_ids) | set(tail.consumed_clue_ids)
            extended_run = self._build_address_run_from_state(
                state_ext, extended_consumed_ids, handled_labels, locale, index,
            )
            if extended_run is None:
                return conservative_run
            if tail.challenge_clue_index is None:
                return extended_run
            conservative_run.pending_challenge = PendingChallenge(
                clue_index=tail.challenge_clue_index,
                cached_digit_text=tail.unit_text,
                cached_pure_digits=tail.pure_digits,
                extended_candidate=extended_run.candidate,
                extended_consumed_ids=extended_run.consumed_ids,
                extended_next_index=extended_run.next_index,
            )
            return conservative_run

        return self._build_address_run_from_state(
            state, consumed_ids, handled_labels, locale, index,
        )

    # ------------------------------------------------- handle_address_clue
    def _handle_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        raw_text: str,
        stream: StreamInput,
        locale: str,
        clues: tuple[Clue, ...],
        clue_index: int,
    ) -> object | None:
        effective_clue = clue
        if clue.role == ClueRole.KEY:
            effective_clue = _routed_key_clue_for_state(
                state,
                clues,
                clue_index,
                clue,
                raw_text,
                stream,
                locale,
            )
        comp_type = effective_clue.component_type
        if comp_type is None:
            return None

        # NUMBER 上下文重映射。
        if comp_type == AddressComponentType.NUMBER:
            if state.last_component_type in _DETAIL_COMPONENTS:
                comp_type = AddressComponentType.DETAIL

        comma_gate = _comma_tail_prehandle(
            state, raw_text, stream, locale, clues, clue_index, effective_clue, comp_type
        )
        if comma_gate is _SENTINEL_STOP:
            return _SENTINEL_STOP

        # ---- VALUE ----
        if effective_clue.role == ClueRole.VALUE:
            if state.pending_comma_value_right_scan:
                state.pending_comma_value_right_scan = False
                ub = _comma_value_scan_upper_bound(
                    clues, clue_index, effective_clue, stream, len(raw_text)
                )
                fwd = _scan_forward_value_end(raw_text, effective_clue.end, ub)
                if fwd > effective_clue.end:
                    merged = raw_text[effective_clue.start:fwd]
                    if _normalize_address_value(comp_type, merged):
                        state.value_char_end_override[effective_clue.clue_id] = fwd
            # 逗号尾内：连续 VALUE 各自成 component；先 flush 链尾 VALUE 再收本条，以便方向按 component 锁定。
            seg_ct = state.segment_state
            if (
                seg_ct.comma_tail_active
                and not state.pending_comma_first_component
                and state.deferred_chain
                and state.deferred_chain[-1][1].role == ClueRole.VALUE
            ):
                _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP
            # 当前链尾若是 KEY，则 VALUE 不能继续挂链，需先结算前一个组件。
            if state.deferred_chain and not _chain_can_accept(state, clue, stream):
                _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP

            # 后置 admin VALUE：先做「疑似新地址」前瞻，不立即切分。
            if state.components or state.deferred_chain:
                if (
                    not state.pending_comma_first_component
                    and not state.segment_state.comma_tail_active
                    and not _segment_admit(state, comp_type)
                ):
                    if (
                        comp_type in _ADMIN_TYPES
                        and _has_reasonable_successor_key(
                            state,
                            clues,
                            clue_index,
                            comp_type,
                            stream,
                            raw_text,
                            locale,
                        )
                    ):
                        # 有合理后继 KEY：先提交前一个正序链，再以当前 admin VALUE 作为新链起点。
                        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                        if state.split_at is not None:
                            return _SENTINEL_STOP
                        _append_deferred(state, clue_index, effective_clue, record_suspect=False)
                        state.last_value = effective_clue
                        state.last_end = max(state.last_end, effective_clue.end)
                        return None
                    else:
                        # 无合理后继 KEY：从该 admin 处切分为下一地址 run。
                        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                        state.split_at = effective_clue.start
                        return _SENTINEL_STOP
            if state.deferred_chain:
                if not _chain_can_accept(state, effective_clue, stream):
                    _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                    if state.split_at is not None:
                        return _SENTINEL_STOP
            _append_deferred(state, clue_index, effective_clue, record_suspect=True)
            state.last_value = effective_clue
            state.last_end = max(state.last_end, effective_clue.end)
            return None

        # ---- KEY ----
        if effective_clue.role == ClueRole.KEY:
            state.pending_comma_value_right_scan = False
            # KEY 仍走段规则（admin 后置前瞻仅作用于 VALUE 分支）。
            if state.components or state.deferred_chain:
                if (
                    not state.pending_comma_first_component
                    and not state.segment_state.comma_tail_active
                    and not _segment_admit(state, comp_type)
                ):
                    _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                    state.split_at = effective_clue.start
                    return _SENTINEL_STOP
            if state.deferred_chain and _chain_can_accept(state, effective_clue, stream):
                _remove_last_value_suspect(state, effective_clue, stream)
                _append_deferred(state, clue_index, effective_clue, record_suspect=False)
                state.last_end = max(state.last_end, effective_clue.end)
                return None

            # 链非空但不能接受此 KEY → flush 现有 chain。
            if state.deferred_chain:
                _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP

            if comp_type == AddressComponentType.ROAD and state.pending_community_poi_index is not None:
                if _pending_community_blocks_road(state):
                    _clear_pending_community_poi(state)
                    state.split_at = effective_clue.start
                    return _SENTINEL_STOP
                _reroute_pending_community_poi_to_subdistrict(state)
                if (
                    state.components
                    and not state.pending_comma_first_component
                    and not state.segment_state.comma_tail_active
                    and not _segment_admit(state, comp_type)
                ):
                    state.split_at = effective_clue.start
                    return _SENTINEL_STOP

            # 链空 → 尝试构建独立 KEY component。
            # 栈上尚无已提交组件时：左扩得到的前缀 value 只入 deferred_chain，不立刻 commit，
            # 以便右侧严格相邻的 KEY 走 KEY→KEY 传导（flush 时由最后一个 KEY 定 comp_type）。
            expand_defer: int | None = None
            if not state.components:
                expand_defer = self._key_left_expand_start_if_deferrable(
                    raw_text,
                    effective_clue,
                    clue_index,
                    locale,
                    comp_type,
                )
            if expand_defer is not None:
                state.chain_left_anchor = expand_defer
                _append_deferred(state, clue_index, effective_clue, record_suspect=False)
                state.last_end = max(state.last_end, effective_clue.end)
                return None

            component = self._build_key_component(
                raw_text,
                effective_clue,
                comp_type,
                clue_index,
                locale,
                component_start=state.last_end,
                allow_left_expand=not state.components,
            )
            if component is not None:
                if not _commit(state, component):
                    return _SENTINEL_STOP
            else:
                # 空 value → KEY 作为新 chain 的种子。
                _append_deferred(state, clue_index, effective_clue, record_suspect=False)
            state.last_end = max(state.last_end, effective_clue.end)
            return None

        return None

    # ------------------------------------------------- build helpers

    def _key_left_expand_start_if_deferrable(
        self,
        raw_text: str,
        clue: Clue,
        clue_index: int,
        locale: str,
        comp_type: AddressComponentType,
    ) -> int | None:
        """若 KEY 的 value 在左侧且可规范化非空，返回左扩起点供先入链 defer；否则 None。

        仅用于栈起始（调用方保证尚无已提交组件）。英文前缀类（value 在 KEY 右侧）不参与 defer。"""
        if clue.text.lower() in _PREFIX_EN_KEYWORDS:
            return None
        floor = _left_address_floor(self.context.clues, clue_index)
        prev_key_end = _left_prev_address_key_end(self.context.clues, clue_index)
        if prev_key_end is not None:
            floor = max(floor, prev_key_end)
        if locale.startswith("en"):
            expand_start = _left_expand_en_word(raw_text, clue.start, floor)
        else:
            expand_start = _left_expand_zh(
                raw_text, clue.start, floor, self.context.stream, comp_type
            )
        value = _normalize_address_value(comp_type, raw_text[expand_start : clue.start])
        if not value:
            return None
        return expand_start

    def _build_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        locale: str,
        *,
        component_start: int,
        allow_left_expand: bool,
    ) -> _DraftComponent | None:
        key_text = clue.text
        if key_text.lower() in _PREFIX_EN_KEYWORDS:
            value_start = _skip_separators(raw_text, clue.end)
            value_end = _scan_forward_value_end(
                raw_text, value_start, upper_bound=min(len(raw_text), clue.end + 30),
            )
            if value_end <= value_start:
                return None
            value = _normalize_address_value(comp_type, raw_text[value_start:value_end])
            if not value:
                return None
            return _DraftComponent(
                component_type=comp_type,
                start=clue.start,
                end=value_end,
                value=value,
                key=key_text,
                is_detail=comp_type in _DETAIL_COMPONENTS,
                clue_ids={clue.clue_id},
                clue_indices={clue_index},
            )

        if allow_left_expand:
            # 左扩展只允许在栈起始组件使用。
            floor = _left_address_floor(self.context.clues, clue_index)
            prev_key_end = _left_prev_address_key_end(self.context.clues, clue_index)
            if prev_key_end is not None:
                floor = max(floor, prev_key_end)
            if locale.startswith("en"):
                expand_start = _left_expand_en_word(raw_text, clue.start, floor)
            else:
                stream = self.context.stream
                expand_start = _left_expand_zh(raw_text, clue.start, floor, stream, comp_type)
        else:
            expand_start = component_start

        value = _normalize_address_value(comp_type, raw_text[expand_start:clue.start])
        if not value:
            return None
        return _DraftComponent(
            component_type=comp_type,
            start=expand_start,
            end=clue.end,
            value=value,
            key=key_text,
            is_detail=comp_type in _DETAIL_COMPONENTS,
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )

    def _build_address_run_from_state(
        self,
        state: _ParseState,
        consumed_ids: set[str],
        handled_labels: set[str],
        locale: str,
        next_index: int,
        *,
        use_precise_next_index: bool = True,
    ) -> StackRun | None:
        components = state.components
        if not _meets_commit_threshold(
            state.evidence_count,
            components,
            locale,
            protection_level=self.context.protection_level,
        ):
            return None
        raw_text = self.context.stream.text
        final_start = min(c.start for c in components)
        final_end = max(c.end for c in components)
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
            label_clue_ids=set(handled_labels),
            label_driven=(self.clue.role == ClueRole.LABEL),
        )
        if use_precise_next_index and state.last_consumed_clue_index >= 0:
            final_next_index = state.last_consumed_clue_index + 1
        else:
            final_next_index = next_index
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            consumed_ids=set(consumed_ids),
            handled_label_clue_ids=set(handled_labels),
            next_index=final_next_index,
            suppress_challenger_clue_ids=frozenset(state.suppress_challenger_clue_ids),
        )


# ---------------------------------------------------------------------------
# 独立 helper 函数（大部分沿用旧版，适配 _DraftComponent）
# ---------------------------------------------------------------------------

def _label_seed_address_index(clues: tuple[Clue, ...], start_unit: int, *, max_units: int) -> int | None:
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


def _next_address_clue_index_after(
    clues: tuple[Clue, ...],
    after_index: int,
) -> int | None:
    """从 after_index 之后找第一个可消费的 ADDRESS 线索；遇 break 放弃；negative 跳过。"""
    for j in range(after_index + 1, len(clues)):
        c = clues[j]
        if is_break_clue(c):
            return None
        if is_negative_clue(c):
            continue
        if c.attr_type is None:
            continue
        if c.attr_type == PIIAttributeType.ADDRESS and c.role != ClueRole.LABEL:
            return j
    return None


def _non_space_units_to_unit_start(
    stream: StreamInput,
    char_pos: int,
    unit_start: int,
) -> int:
    """从 char_pos 到目标 unit 起点（含目标 unit）的非空白 unit 数。"""
    start_ui = _unit_index_at_or_after(stream, char_pos)
    if start_ui >= len(stream.units):
        return 0
    count = 0
    for ui in range(start_ui, min(unit_start + 1, len(stream.units))):
        if stream.units[ui].kind != "space":
            count += 1
    return count


def _first_address_clue_index_from_char_within_units(
    clues: tuple[Clue, ...],
    stream: StreamInput,
    char_pos: int,
    *,
    max_units: int,
) -> int | None:
    """逗号后在 max_units 个非空白 unit 内查找第一个 ADDRESS 非 LABEL。"""
    for j, c in enumerate(clues):
        if c.start < char_pos:
            continue
        if _non_space_units_to_unit_start(stream, char_pos, c.unit_start) > max_units:
            return None
        if is_break_clue(c):
            return None
        if is_negative_clue(c):
            continue
        if c.attr_type is None:
            continue
        if c.attr_type == PIIAttributeType.ADDRESS and c.role != ClueRole.LABEL:
            return j
    return None


def _comma_char_index_in_gap(raw_text: str, last_end: int, clue_start: int) -> int | None:
    """gap [last_end, clue_start) 内第一个逗号下标；无则 None。"""
    gap = raw_text[last_end:clue_start]
    for off, ch in enumerate(gap):
        if ch in ",，":
            return last_end + off
    return None


def _prior_max_admin_from_occupancy(state: _ParseState) -> AddressComponentType | None:
    """occupancy 中已占位行政层的最高一层（suspect 不占 occupancy）。"""
    present = [t for t in state.occupancy if t in _ADMIN_TYPES]
    if not present:
        return None
    return max(present, key=lambda t: _ADMIN_RANK.get(t, 0))


def _prior_max_admin_from_components(
    components: list[_DraftComponent],
) -> AddressComponentType | None:
    """已提交 component 中行政类型的最高一层（仅看 component_type，不含 suspected）。"""
    types = [c.component_type for c in components if c.component_type in _ADMIN_TYPES]
    if not types:
        return None
    return max(types, key=lambda t: _ADMIN_RANK.get(t, 0))


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


def _preview_chain_can_accept(
    chain: list[Clue],
    clue: Clue,
    stream: StreamInput,
) -> bool:
    """预演逗号尾首个 component 时复用真实链规则。"""
    if not chain:
        return True
    last = chain[-1]
    gap = _clue_unit_gap(last, clue, stream)
    if last.role == ClueRole.KEY and clue.role == ClueRole.VALUE:
        return False
    if last.role == ClueRole.KEY and clue.role == ClueRole.KEY:
        return _key_key_chain_gap_allowed(last, clue, stream)
    if last.role == ClueRole.VALUE and clue.role == ClueRole.KEY:
        return gap <= 6
    return gap <= 1


def _preview_first_component_type_from_chain(
    chain: list[Clue],
    previous_component_type: AddressComponentType | None,
) -> AddressComponentType | None:
    """把预演链映射为首个真正会提交的 component 类型。"""
    if not chain:
        return None
    for clue in reversed(chain):
        if clue.role == ClueRole.KEY:
            comp_type = clue.component_type or AddressComponentType.POI
            if (
                comp_type == AddressComponentType.NUMBER
                and previous_component_type in _DETAIL_COMPONENTS
            ):
                return AddressComponentType.DETAIL
            return comp_type
    return chain[0].component_type


def _preview_comma_tail_first_component_type(
    clues: tuple[Clue, ...],
    start_index: int,
    stream: StreamInput,
    previous_component_type: AddressComponentType | None,
    raw_text: str,
    locale: str,
) -> tuple[AddressComponentType | None, bool]:
    """预演逗号尾首段，返回首个 component 类型及是否需要保持链打开等待 KEY。"""
    chain: list[Clue] = []
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if is_break_clue(clue):
            break
        if is_negative_clue(clue):
            continue
        if clue.attr_type is None or clue.role == ClueRole.LABEL:
            continue
        if clue.attr_type != PIIAttributeType.ADDRESS:
            continue
        if clue.component_type is None:
            continue
        effective = clue
        if clue.role == ClueRole.KEY:
            effective = _routed_key_clue_for_preview(
                chain,
                clues,
                index,
                clue,
                raw_text,
                stream,
                locale,
                previous_component_type,
            )
        if chain and not _preview_chain_can_accept(chain, effective, stream):
            break
        chain.append(effective)
    component_type = _preview_first_component_type_from_chain(chain, previous_component_type)
    needs_open_chain = any(clue.role == ClueRole.KEY for clue in chain)
    return component_type, needs_open_chain


def _comma_tail_prehandle(
    state: _ParseState,
    raw_text: str,
    stream: StreamInput,
    locale: str,
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    comp_type: AddressComponentType,
) -> object | None:
    """gap 内若有逗号：先断开左链，再按首个真实 component 做准入判定。"""
    comma_pos = _comma_char_index_in_gap(raw_text, state.last_end, clue.start)
    if comma_pos is None:
        return None

    if state.deferred_chain:
        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
        if state.split_at is not None:
            return _SENTINEL_STOP

    _materialize_digit_tail_before_comma(
        state,
        stream,
        clues,
        clue_index,
    )
    comma_pos = _comma_char_index_in_gap(raw_text, state.last_end, clue.start)
    if comma_pos is None:
        return None

    after_comma = comma_pos + 1
    first_idx = _first_address_clue_index_from_char_within_units(
        clues,
        stream,
        after_comma,
        max_units=6,
    )
    if first_idx is None:
        state.split_at = comma_pos
        return _SENTINEL_STOP
    if first_idx != clue_index:
        state.split_at = comma_pos
        return _SENTINEL_STOP

    first_component_type, needs_open_chain = _preview_comma_tail_first_component_type(
        clues,
        clue_index,
        stream,
        state.last_component_type,
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


def _comma_value_scan_upper_bound(
    clues: tuple[Clue, ...],
    clue_index: int,
    clue: Clue,
    stream: StreamInput,
    raw_text_len: int,
) -> int:
    """逗号后 VALUE 右扩上界：与下一 ADDRESS 非 LABEL 间距 ≤1 unit 时才扩到其起点前。"""
    ub = min(raw_text_len, clue.end + 48)
    for j in range(clue_index + 1, len(clues)):
        nxt = clues[j]
        if is_break_clue(nxt):
            return min(ub, nxt.start)
        if is_negative_clue(nxt):
            continue
        if nxt.attr_type != PIIAttributeType.ADDRESS or nxt.role == ClueRole.LABEL:
            continue
        if _clue_unit_gap(clue, nxt, stream) > 1:
            return clue.end
        return min(ub, nxt.start)
    return ub


def _bridge_last_address_to_next_within_units(
    state: _ParseState,
    next_address_clue: Clue,
) -> bool:
    """上一 ADDRESS clue 与下一 ADDRESS clue 的 unit 起点间距是否 ≤6（与主循环 gap 规则一致）。"""
    if state.last_consumed is None:
        return False
    gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
    return next_address_clue.unit_start - gap_anchor <= 6


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


def _left_prev_address_key_end(clues: tuple[Clue, ...], clue_index: int) -> int | None:
    """返回当前 clue 左侧最近 ADDRESS KEY 的 end。"""
    for index in range(clue_index - 1, -1, -1):
        clue = clues[index]
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role == ClueRole.KEY:
            return clue.end
    return None


def _left_expand_zh(
    raw_text: str,
    pos: int,
    floor: int,
    stream: StreamInput,
    comp_type: AddressComponentType,
) -> int:
    """中文左扩展：先检查左邻 unit 是否是 digit_run 或 alpha_run，再回退到 CJK 扩展。"""
    left_ui = _unit_index_left_of(stream, pos)
    if 0 <= left_ui < len(stream.units):
        kind = stream.units[left_ui].kind
        # digit_run 或 alpha_run 直接吸收。
        if kind in ("digit_run", "alpha_run", "ascii_word"):
            return stream.units[left_ui].char_start
    return _left_expand_zh_chars(raw_text, pos, floor, max_chars=2)


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


def _scan_forward_value_end(raw_text: str, start: int, upper_bound: int) -> int:
    index = start
    while index < upper_bound:
        if is_any_break(raw_text[index]):
            break
        index += 1
    return index


def _normalize_address_value(component_type: AddressComponentType, raw_value: str) -> str:
    cleaned = clean_value(raw_value)
    if component_type in _DETAIL_COMPONENTS:
        alnum = "".join(re.findall(r"[A-Za-z0-9]+", cleaned))
        if re.search(r"[A-Za-z]", alnum):
            return alnum
        digits = "".join(re.findall(r"\d+", cleaned))
        if digits:
            return digits
        return ""
    return cleaned


def _meets_commit_threshold(
    evidence_count: int,
    components: list[_DraftComponent],
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
        return any(c.component_type in _SINGLE_EVIDENCE_ADMIN for c in components)
    return evidence_count >= 2


def _address_metadata(origin_clue: Clue, components: list[_DraftComponent]) -> dict[str, list[str]]:
    component_types: list[str] = []
    component_trace: list[str] = []
    component_key_trace: list[str] = []
    detail_types: list[str] = []
    detail_values: list[str] = []
    # 与 components 顺序一一对应：每项为该组件的 suspected dict 序列化，无则空串。
    component_suspected_trace: list[str] = []

    for component in components:
        ct = component.component_type.value
        values = component.value if isinstance(component.value, list) else [component.value]
        keys = component.key if isinstance(component.key, list) else [component.key]

        for v in values:
            component_types.append(ct)
            component_trace.append(f"{ct}:{v}")
        for k in keys:
            if k:
                component_key_trace.append(f"{ct}:{k}")
        if component.is_detail:
            for v in values:
                detail_types.append(ct)
                detail_values.append(v)
        if component.suspected:
            part = ";".join(
                f"{level}:{text}"
                for level, text in component.suspected.items()
            )
            component_suspected_trace.append(part)
        else:
            component_suspected_trace.append("")

    metadata: dict[str, list[str]] = {
        "matched_by": [origin_clue.source_kind],
        "address_kind": ["private_address"],
        "address_match_origin": [origin_clue.text if origin_clue.role == ClueRole.LABEL else origin_clue.source_kind],
        "address_component_type": component_types,
        "address_component_trace": component_trace,
        "address_component_key_trace": component_key_trace,
        "address_details_type": detail_types,
        "address_details_text": detail_values,
        "address_component_suspected": component_suspected_trace,
    }
    return metadata


def _overlaps_any_span(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _pop_components_overlapping_negative(
    components: list[_DraftComponent],
    negative_spans: list[tuple[int, int]],
) -> tuple[list[_DraftComponent], set[str], set[int]]:
    ordered = sorted(components, key=lambda c: (c.end, c.start))
    removed_clue_ids: set[str] = set()
    removed_clue_indices: set[int] = set()
    while ordered:
        last = ordered[-1]
        if not _overlaps_any_span(last.start, last.end, negative_spans):
            return ordered, removed_clue_ids, removed_clue_indices
        removed = ordered.pop()
        removed_clue_ids |= removed.clue_ids
        removed_clue_indices |= removed.clue_indices
    return [], removed_clue_ids, removed_clue_indices


# ---------------------------------------------------------------------------
# digit_tail（沿用旧版逻辑，适配 _DraftComponent）
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
        seg = part.strip()
        if not seg or not _DIGIT_TAIL_SEGMENT_RE.fullmatch(seg):
            return None
        segments.append(seg)
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
    for i in range(from_index, len(clues)):
        c = clues[i]
        if c.start > unit_char_end:
            break
        if c.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}:
            if c.start <= unit_char_start and c.end >= unit_char_end:
                return i
    return None


def _has_following_address_key(
    clues: tuple[Clue, ...],
    digit_char_end: int,
    raw_text: str,
    from_index: int = 0,
) -> bool:
    gap = raw_text[digit_char_end:digit_char_end + 6] if digit_char_end < len(raw_text) else ""
    if any(is_hard_break(ch) for ch in gap):
        return False
    for i in range(from_index, len(clues)):
        c = clues[i]
        if c.start > digit_char_end + 6:
            break
        if c.start < digit_char_end:
            continue
        if c.attr_type == PIIAttributeType.ADDRESS and c.role == ClueRole.KEY:
            return True
    return False


def _materialize_digit_tail_before_comma(
    state: _ParseState,
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
) -> None:
    """逗号左侧在切段前先补一次 digit_tail，避免 detail 落到逗号后被漏掉。"""
    if not state.components or not getattr(stream, "units", None):
        return
    last = max(state.components, key=lambda c: (c.end, c.start))
    if last.component_type not in _DIGIT_TAIL_TRIGGER_TYPES:
        return
    tail = _analyze_digit_tail(state.components, stream, clues, clue_scan_index)
    if tail is None or tail.followed_by_address_key:
        return
    for component in tail.new_components:
        if not _commit(state, component):
            return


def _analyze_digit_tail(
    components: list[_DraftComponent],
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
) -> DigitTailResult | None:
    if not components or not getattr(stream, "units", None):
        return None
    last = max(components, key=lambda c: (c.end, c.start))
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
    prev_type = last.component_type

    max_dashes = _max_dashes_for_prev_type(prev_type)
    parts = _parse_digit_tail(next_unit.text, max_dashes)
    if parts is None:
        return None

    available = _available_types_after(prev_type)
    assigned_types = _greedy_assign_types(parts, available)
    if assigned_types is None:
        return None

    cached_text = next_unit.text
    cached_digits = re.sub(r"\D", "", cached_text)
    clue_idx = _find_clue_for_digit_run(
        clues, next_unit.char_start, next_unit.char_end, clue_scan_index,
    )
    consumed_clue_indices = {clue_idx} if clue_idx is not None else set()
    consumed_clue_ids = {clues[clue_idx].clue_id} if clue_idx is not None else set()

    new_components: list[_DraftComponent] = []
    cursor = next_unit.char_start
    for seg, comp_type in zip(parts, assigned_types):
        seg_start = stream.text.find(seg, cursor, next_unit.char_end)
        if seg_start < 0:
            seg_start = cursor
        seg_end = seg_start + len(seg)
        new_components.append(_DraftComponent(
            component_type=comp_type,
            start=seg_start,
            end=seg_end,
            value=seg,
            key="",
            is_detail=comp_type in _DETAIL_COMPONENTS,
            clue_ids=set(consumed_clue_ids),
            clue_indices=set(consumed_clue_indices),
        ))
        cursor = seg_end

    raw_text = stream.text
    if _has_following_address_key(clues, next_unit.char_end, raw_text, clue_scan_index):
        return DigitTailResult(
            new_components=new_components,
            unit_text=cached_text,
            pure_digits=cached_digits,
            followed_by_address_key=True,
            challenge_clue_index=None,
            consumed_clue_ids=consumed_clue_ids,
            consumed_clue_indices=consumed_clue_indices,
        )

    return DigitTailResult(
        new_components=new_components,
        unit_text=cached_text,
        pure_digits=cached_digits,
        followed_by_address_key=False,
        challenge_clue_index=clue_idx,
        consumed_clue_ids=consumed_clue_ids,
        consumed_clue_indices=consumed_clue_indices,
    )
