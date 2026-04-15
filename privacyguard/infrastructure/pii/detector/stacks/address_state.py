"""地址 stack 的**可变状态**与组件提交逻辑（与 policy 互补）。

`address.py` 的主循环只负责「何时往 `deferred_chain` 塞 clue、何时冲洗」；真正写入
`state.components` 的路径集中在 `_commit` 与 `_flush_chain`。

状态机要点：
1. **deferred_chain**：尚未落盘的 VALUE/KEY 序列；冲洗时要么「最后一个 KEY 吃掉左段值」，
   要么 `_flush_chain_as_standalone` 逐段 VALUE 独立提交。
2. **occupancy / segment_state**：`_segment_admit` 用 `_VALID_SUCCESSORS` 与逗号尾方向约束
   下一个 component 是否可接；失败则 `split_at`。
3. **pending_suspects**：行政 VALUE 在链上冻结的疑似子层；提交带 KEY 的 component 时并入
   `suspected`，最终 `_fixup_suspected_info` 从主 value 中剔除表面文本。
4. **comma_tail_checkpoint**：逗号尾模式下若首个真实组件落到区以下非法层级，回滚到逗号左快照。

主要符号与调用方：
- `_ParseState` / `_DraftComponent`：被 `AddressStack._scan_components` 与负向修复重放共享。
- `_flush_chain`：由 `AddressStack._flush_chain` 传入 `normalize_value=_normalize_address_value`。
- `_commit`：`_flush_chain`、`_materialize_digit_tail_before_comma`、`_build_key_component` 间接触发。

函数分组（便于跳转）：
- 数据模型：`_DraftComponent`、`_SuspectEntry`、`_CommaSegmentState`、`_CommaTailCheckpoint`、`_ParseState`
- 克隆与快照：`_clone_draft_component`、`_make_comma_tail_checkpoint`、`_restore_comma_tail_checkpoint`
- suspect：`_freeze_*` 在 policy 侧；此处 `_fixup_suspected_info`、`_recompute_text`、`_trim_once`
- 提交与链：`_append_deferred`、`_commit`、`_flush_chain`、`_flush_chain_as_standalone`
- 逗号尾与社区 POI：`_rollback_invalid_comma_tail_component`、`_pending_community_*`、`_reroute_*`
- 负向修复辅助：`_ordered_component_clue_entries`、`_rightmost_component_key_overlaps_negative`、`_rebuild_component_derived_state`
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueRole,
    StreamInput,
    strength_ge,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_index_at_or_after

SINGLE_OCCUPY = frozenset({
    AddressComponentType.COUNTRY,
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.SUBDISTRICT,
    AddressComponentType.ROAD,
    AddressComponentType.HOUSE_NUMBER,
    AddressComponentType.NUMBER,
    AddressComponentType.POSTAL_CODE,
})

_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.SUBDISTRICT,
})

_COMMA_TAIL_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
})

_SUSPECT_KEY_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
})

_ADMIN_RANK: dict[AddressComponentType, int] = {
    AddressComponentType.SUBDISTRICT: 1,
    AddressComponentType.DISTRICT: 2,
    AddressComponentType.CITY: 3,
    AddressComponentType.PROVINCE: 4,
}

_VALID_SUCCESSORS: dict[AddressComponentType, frozenset[AddressComponentType]] = {
    AddressComponentType.PROVINCE: frozenset({
        AddressComponentType.CITY,
        AddressComponentType.DISTRICT,
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    AddressComponentType.CITY: frozenset({
        AddressComponentType.DISTRICT,
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    AddressComponentType.DISTRICT: frozenset({
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    AddressComponentType.SUBDISTRICT: frozenset({
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
        AddressComponentType.NUMBER,
    }),
    AddressComponentType.ROAD: frozenset({
        AddressComponentType.NUMBER,
        AddressComponentType.POI,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.NUMBER: frozenset({
        AddressComponentType.POI,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.POI: frozenset({
        AddressComponentType.NUMBER,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.BUILDING: frozenset({AddressComponentType.DETAIL}),
    AddressComponentType.DETAIL: frozenset({AddressComponentType.DETAIL}),
}

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

_ALL_TYPES = frozenset(AddressComponentType)
_SuccessorMap = Mapping[AddressComponentType, frozenset[AddressComponentType]]
_CommitFn = Callable[["_DraftComponent"], bool]
_IndexedClue = tuple[int, Clue]


@dataclass(slots=True)
class _DraftComponent:
    """主循环产出的草稿 component。"""

    component_type: AddressComponentType
    start: int
    end: int
    value: str | list[str]
    key: str | list[str]
    is_detail: bool = False
    raw_chain: list[Clue] = field(default_factory=list)
    suspected: list["_SuspectEntry"] = field(default_factory=list)
    clue_ids: set[str] = field(default_factory=set)
    clue_indices: set[int] = field(default_factory=set)
    suspect_demoted: bool = False


@dataclass(slots=True)
class _SuspectEntry:
    """主循环冻结的疑似行政子组件。"""

    level: str
    value: str
    key: str
    origin: str
    start: int
    end: int


@dataclass(slots=True)
class _CommaSegmentState:
    """逗号尾分组状态。"""

    direction: str | None = None
    group_first_type: AddressComponentType | None = None
    group_last_type: AddressComponentType | None = None
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
    ignored_address_key_indices: set[int]
    pending_suspects: list[_SuspectEntry]
    last_piece_end: int | None


@dataclass(slots=True)
class _ParseState:
    """主解析状态。

    主循环不变式：`components` 为已提交片段；`deferred_chain` 为进行中的「软」缓冲；
    `split_at` 非空表示地址窗口被截断，上层应停止继续合并。
    """

    components: list[_DraftComponent] = field(default_factory=list)
    occupancy: dict[AddressComponentType, int] = field(default_factory=dict)
    deferred_chain: list[_IndexedClue] = field(default_factory=list)
    suspect_chain: list[_IndexedClue] = field(default_factory=list)
    pending_suspects: list[_SuspectEntry] = field(default_factory=list)
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
    suppress_challenger_clue_ids: set[str] = field(default_factory=set)
    value_char_end_override: dict[str, int] = field(default_factory=dict)
    pending_comma_value_right_scan: bool = False
    pending_comma_first_component: bool = False
    component_counts: dict[AddressComponentType, int] = field(default_factory=dict)
    pending_community_poi_index: int | None = None
    comma_tail_checkpoint: _CommaTailCheckpoint | None = None
    ignored_address_key_indices: set[int] = field(default_factory=set)
    last_piece_end: int | None = None
    max_clue_strength: ClaimStrength = ClaimStrength.WEAK


_StandaloneAdminResolver = Callable[
    [_ParseState, tuple[_IndexedClue, ...]],
    tuple[AddressComponentType, tuple[AddressComponentType, ...]] | None,
]


def _clone_component_value(value: str | list[str]) -> str | list[str]:
    return list(value) if isinstance(value, list) else value


def _clone_component_key(key: str | list[str]) -> str | list[str]:
    return list(key) if isinstance(key, list) else key


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
        suspected=[
            _SuspectEntry(
                level=entry.level,
                value=entry.value,
                key=entry.key,
                origin=entry.origin,
                start=entry.start,
                end=entry.end,
            )
            for entry in component.suspected
        ],
        clue_ids=set(component.clue_ids),
        clue_indices=set(component.clue_indices),
        suspect_demoted=component.suspect_demoted,
    )


def _suspect_surface_text(entry: _SuspectEntry) -> str:
    """返回用于删除与比较的 suspect 表面文本。"""
    if entry.origin == "key":
        return f"{entry.value}{entry.key}".strip()
    return entry.value.strip()


def _suspect_group_key(entry: _SuspectEntry) -> tuple[int, int, str, str, str]:
    """按同一 value 歧义组聚合 suspect。"""
    return (entry.start, entry.end, entry.value, entry.key, entry.origin)


def _suspect_sort_key(entry: _SuspectEntry) -> tuple[int, int, int, str]:
    """同组内按行政层级从高到低稳定排序。"""
    level = _pending_suspect_level(entry)
    rank = _ADMIN_RANK.get(level, 0) if level is not None else 0
    return (entry.start, entry.end, -rank, entry.level)


def _group_suspected_entries(entries: list[_SuspectEntry]) -> list[list[_SuspectEntry]]:
    """把同一 value、同一来源的多层级 suspect 聚合成组。"""
    grouped: dict[tuple[int, int, str, str, str], list[_SuspectEntry]] = {}
    ordered_keys: list[tuple[int, int, str, str, str]] = []
    for entry in entries:
        group_key = _suspect_group_key(entry)
        if group_key not in grouped:
            grouped[group_key] = []
            ordered_keys.append(group_key)
        group = grouped[group_key]
        if any(existing.level == entry.level for existing in group):
            continue
        group.append(entry)
    return [
        sorted(grouped[group_key], key=_suspect_sort_key)
        for group_key in ordered_keys
    ]


def _serialize_suspected_entries(entries: list[_SuspectEntry]) -> str:
    """把一个组件上的 suspect 列表序列化到 metadata。"""
    if not entries:
        return ""
    payload = [
        {
            "levels": [group_entry.level for group_entry in group],
            "value": group[0].value,
            "key": group[0].key,
            "origin": group[0].origin,
        }
        for group in _group_suspected_entries(entries)
        if group
    ]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _recompute_last_piece_end(state: _ParseState) -> None:
    """根据已提交 component / pending suspect 重算最近地址片段结束位置。"""
    if state.pending_suspects:
        state.last_piece_end = state.pending_suspects[-1].end
        return
    if state.components:
        state.last_piece_end = state.components[-1].end
        return
    state.last_piece_end = None


def _pending_suspect_level(entry: _SuspectEntry) -> AddressComponentType | None:
    try:
        return AddressComponentType(entry.level)
    except ValueError:
        return None


def _remove_pending_suspect_by_level(
    state: _ParseState,
    level: AddressComponentType,
) -> _SuspectEntry | None:
    """移除当前链上最近一个同层级 suspect。"""
    removed: _SuspectEntry | None = None
    kept: list[_SuspectEntry] = []
    for entry in state.pending_suspects:
        if _pending_suspect_level(entry) == level:
            removed = entry
            continue
        kept.append(entry)
    state.pending_suspects = kept
    _recompute_last_piece_end(state)
    return removed


def _remove_pending_suspect_group_by_span(
    state: _ParseState,
    start: int,
    end: int,
    *,
    origin: str | None = None,
) -> list[_SuspectEntry]:
    """移除同一 span 上的一整组 pending suspect。"""
    removed: list[_SuspectEntry] = []
    kept: list[_SuspectEntry] = []
    for entry in state.pending_suspects:
        if entry.start == start and entry.end == end and (origin is None or entry.origin == origin):
            removed.append(entry)
            continue
        kept.append(entry)
    state.pending_suspects = kept
    _recompute_last_piece_end(state)
    return removed


def _has_pending_suspect_level(entries: list[_SuspectEntry], level: AddressComponentType) -> bool:
    return any(_pending_suspect_level(entry) == level for entry in entries)


def _trim_once(text: str, token: str) -> str:
    """按从左到右顺序删除首个完整匹配片段。"""
    if not token:
        return text
    index = text.find(token)
    if index < 0:
        return text
    return f"{text[:index]}{text[index + len(token):]}"


def _make_comma_tail_checkpoint(state: _ParseState, comma_pos: int) -> _CommaTailCheckpoint:
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
        ignored_address_key_indices=set(state.ignored_address_key_indices),
        pending_suspects=[
            _SuspectEntry(
                level=entry.level,
                value=entry.value,
                key=entry.key,
                origin=entry.origin,
                start=entry.start,
                end=entry.end,
            )
            for entry in state.pending_suspects
        ],
        last_piece_end=state.last_piece_end,
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
    state.pending_suspects = [
        _SuspectEntry(
            level=entry.level,
            value=entry.value,
            key=entry.key,
            origin=entry.origin,
            start=entry.start,
            end=entry.end,
        )
        for entry in checkpoint.pending_suspects
    ]
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
    state.ignored_address_key_indices = set(checkpoint.ignored_address_key_indices)
    state.last_piece_end = checkpoint.last_piece_end
    state.comma_tail_checkpoint = None


def _mark_consumed_indices(state: _ParseState, clue_indices: Iterable[int]) -> None:
    """记录当前 run 已实际消费的 clue 索引。"""
    indices = {idx for idx in clue_indices if idx >= 0}
    if not indices:
        return
    state.consumed_clue_indices |= indices
    state.last_consumed_clue_index = max(state.last_consumed_clue_index, max(indices))


def _append_deferred(
    state: _ParseState,
    clue_index: int,
    clue: Clue,
    *,
    record_suspect: bool,
    anchor_start: int | None = None,
) -> None:
    """把 clue 放进当前链。suspect 是否冻结由主循环单独判定。"""
    del record_suspect
    state.deferred_chain.append((clue_index, clue))
    if state.chain_left_anchor is None:
        state.chain_left_anchor = clue.start if anchor_start is None else anchor_start


def _recompute_last_consumed_index(state: _ParseState) -> None:
    state.last_consumed_clue_index = max(state.consumed_clue_indices) if state.consumed_clue_indices else -1


def _increment_component_count(state: _ParseState, component_type: AddressComponentType) -> None:
    state.component_counts[component_type] = state.component_counts.get(component_type, 0) + 1


def _decrement_component_count(state: _ParseState, component_type: AddressComponentType) -> None:
    count = state.component_counts.get(component_type, 0)
    if count <= 1:
        state.component_counts.pop(component_type, None)
        return
    state.component_counts[component_type] = count - 1


def _mark_pending_community_poi(state: _ParseState, component: _DraftComponent) -> None:
    if component.component_type != AddressComponentType.POI:
        return
    if isinstance(component.key, list) or component.key != "社区":
        return
    state.pending_community_poi_index = len(state.components) - 1


def _clear_pending_community_poi(state: _ParseState) -> None:
    state.pending_community_poi_index = None


def _pending_community_blocks_road(state: _ParseState) -> bool:
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


def _rollback_invalid_comma_tail_component(state: _ParseState, component: _DraftComponent) -> bool:
    """逗号尾一旦落到区以下层级，就回滚到最近逗号左侧并停止。"""
    if not state.segment_state.comma_tail_active:
        return False
    if component.component_type in _COMMA_TAIL_ADMIN_TYPES:
        return False
    checkpoint = state.comma_tail_checkpoint
    if checkpoint is None:
        state.deferred_chain.clear()
        state.suspect_chain.clear()
        state.pending_suspects.clear()
        state.chain_left_anchor = None
        state.value_char_end_override.clear()
        state.pending_comma_value_right_scan = False
        state.pending_comma_first_component = False
        state.segment_state.reset()
        _recompute_last_piece_end(state)
        state.split_at = component.start
        return True
    _restore_comma_tail_checkpoint(state, checkpoint)
    state.split_at = checkpoint.comma_pos
    return True


def _apply_comma_tail_segment_after_commit(
    state: _ParseState,
    committed: _DraftComponent,
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
) -> None:
    """逗号尾内：方向在第二个 component 上锁定；非逗号尾只维护 group_last_type。"""
    seg = state.segment_state
    component_type = committed.component_type
    if not seg.comma_tail_active:
        seg.group_last_type = component_type
        return
    if seg.group_first_type is None:
        seg.group_first_type = component_type
        seg.group_last_type = component_type
        return
    if seg.direction is None:
        first = seg.group_first_type
        if component_type == first:
            seg.group_last_type = component_type
            return
        if component_type in valid_successors.get(first, _ALL_TYPES):
            seg.direction = "forward"
        elif first in valid_successors.get(component_type, _ALL_TYPES):
            seg.direction = "reverse"
        seg.group_last_type = component_type
        return
    seg.group_last_type = component_type


def _segment_admit(
    state: _ParseState,
    comp_type: AddressComponentType,
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
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
            ok_fwd = comp_type in valid_successors.get(first_type, _ALL_TYPES)
            ok_rev = first_type in valid_successors.get(comp_type, _ALL_TYPES)
            return ok_fwd or ok_rev
        last_type = segment.group_last_type
        if last_type is None:
            return True
        if segment.direction == "forward":
            return comp_type in valid_successors.get(last_type, _ALL_TYPES)
        return last_type in valid_successors.get(comp_type, _ALL_TYPES)

    if segment.group_last_type is None:
        return True
    return comp_type in valid_successors.get(segment.group_last_type, _ALL_TYPES)


def _commit_poi(state: _ParseState, component: _DraftComponent) -> _DraftComponent:
    """POI 列表化：同一地址内多个 POI 合并到一个 component。"""
    for existing in state.components:
        if existing.component_type != AddressComponentType.POI:
            continue
        if not isinstance(existing.value, list):
            existing.value = [existing.value]
        if not isinstance(existing.key, list):
            existing.key = [existing.key]
        existing.value.append(component.value[0] if isinstance(component.value, list) else component.value)
        existing.key.append(component.key[0] if isinstance(component.key, list) else component.key)
        existing.end = max(existing.end, component.end)
        existing.clue_ids |= component.clue_ids
        existing.clue_indices |= component.clue_indices
        existing.suspected.extend(component.suspected)
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


def _prune_prior_component_suspects(state: _ParseState, new_component: _DraftComponent) -> None:
    """后续真实组件一旦落地，只删除旧组件里同层级的 suspect。"""
    new_type = new_component.component_type
    if new_type not in _ADMIN_TYPES:
        return
    for prior in state.components[:-1]:
        kept = [entry for entry in prior.suspected if _pending_suspect_level(entry) != new_type]
        if len(kept) != len(prior.suspected):
            prior.suspected = kept
            prior.suspect_demoted = True


def _commit(
    state: _ParseState,
    component: _DraftComponent,
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
) -> bool:
    """提交 component 到 state，更新 occupancy / segment / evidence。"""
    if not _segment_admit(state, component.component_type, valid_successors=valid_successors):
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
    index = len(state.components) - 1
    if comp_type in SINGLE_OCCUPY:
        state.occupancy[comp_type] = index
    if is_fresh_component:
        _apply_comma_tail_segment_after_commit(
            state,
            committed,
            valid_successors=valid_successors,
        )
    else:
        state.segment_state.group_last_type = committed.component_type
    if state.segment_state.comma_tail_active and state.pending_comma_first_component:
        state.pending_comma_first_component = False
    state.last_component_type = committed.component_type
    state.last_end = max(state.last_end, committed.end)
    state.last_piece_end = committed.end
    state.evidence_count += 1
    for clue in committed.raw_chain:
        if not strength_ge(state.max_clue_strength, clue.strength):
            state.max_clue_strength = clue.strength
    state.committed_clue_ids |= committed.clue_ids
    _mark_consumed_indices(state, committed.clue_indices)
    _prune_prior_component_suspects(state, committed)
    if is_fresh_component:
        _mark_pending_community_poi(state, committed)
    return True


def _flush_chain(
    state: _ParseState,
    raw_text: str,
    *,
    normalize_value,
    commit_component: _CommitFn | None = None,
    resolve_standalone_admin_group: _StandaloneAdminResolver | None = None,
) -> None:
    """冲洗 deferred_chain。若链中含 KEY，用最后一个 KEY 消费；否则逐个 standalone。"""
    if not state.deferred_chain:
        return
    before_component_count = len(state.components)
    commit = commit_component or (lambda component: _commit(state, component))

    last_key_idx: int | None = None
    for i in range(len(state.deferred_chain) - 1, -1, -1):
        if state.deferred_chain[i][1].role == ClueRole.KEY:
            last_key_idx = i
            break

    if last_key_idx is not None:
        used_entries = state.deferred_chain[: last_key_idx + 1]
        key_clue = used_entries[-1][1]
        comp_type = key_clue.component_type or AddressComponentType.POI
        if comp_type == AddressComponentType.NUMBER and state.last_component_type in _DETAIL_COMPONENTS:
            comp_type = AddressComponentType.DETAIL
        component_start = state.chain_left_anchor if state.chain_left_anchor is not None else key_clue.start
        value = normalize_value(comp_type, raw_text[component_start:key_clue.start])
        if value:
            component = _DraftComponent(
                component_type=comp_type,
                start=component_start,
                end=key_clue.end,
                value=value,
                key=key_clue.text,
                is_detail=comp_type in _DETAIL_COMPONENTS,
                raw_chain=[clue for _, clue in used_entries],
                suspected=[
                    _SuspectEntry(
                        level=entry.level,
                        value=entry.value,
                        key=entry.key,
                        origin=entry.origin,
                        start=entry.start,
                        end=entry.end,
                    )
                    for entry in state.pending_suspects
                ],
                clue_ids={clue.clue_id for _, clue in used_entries},
                clue_indices={index for index, _ in used_entries},
            )
            commit(component)
    else:
        _flush_chain_as_standalone(
            state,
            raw_text,
            normalize_value=normalize_value,
            commit_component=commit,
            resolve_standalone_admin_group=resolve_standalone_admin_group,
        )

    state.deferred_chain.clear()
    state.suspect_chain.clear()
    state.pending_suspects.clear()
    state.chain_left_anchor = None
    state.value_char_end_override.clear()
    _recompute_last_piece_end(state)
    # 若本轮冲洗没有产出新组件，回退 last_end 到已提交组件末端，避免失败链污染后续 search_start。
    if len(state.components) == before_component_count and state.components:
        state.last_end = max(component.end for component in state.components)


def _flush_chain_as_standalone(
    state: _ParseState,
    raw_text: str,
    *,
    normalize_value,
    commit_component: _CommitFn | None = None,
    resolve_standalone_admin_group: _StandaloneAdminResolver | None = None,
) -> None:
    """链中无 KEY 时，按 standalone 规则提交 VALUE 组件。"""
    commit = commit_component or (lambda component: _commit(state, component))
    cursor = 0
    while cursor < len(state.deferred_chain):
        clue_index, clue = state.deferred_chain[cursor]
        comp_type = clue.component_type
        if comp_type is None:
            cursor += 1
            continue
        if (
            resolve_standalone_admin_group is not None
            and clue.role == ClueRole.VALUE
            and clue.attr_type == PIIAttributeType.ADDRESS
            and comp_type in _ADMIN_TYPES
        ):
            group_end = cursor + 1
            while (
                group_end < len(state.deferred_chain)
                and state.deferred_chain[group_end][1].role == ClueRole.VALUE
                and state.deferred_chain[group_end][1].attr_type == PIIAttributeType.ADDRESS
                and state.deferred_chain[group_end][1].component_type in _ADMIN_TYPES
                and state.deferred_chain[group_end][1].start == clue.start
                and state.deferred_chain[group_end][1].end == clue.end
            ):
                group_end += 1
            group_entries = tuple(state.deferred_chain[cursor:group_end])
            resolved_group = resolve_standalone_admin_group(state, group_entries)
            if resolved_group is None:
                state.split_at = clue.start
                break
            comp_type, available_levels = resolved_group
            if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
                state.split_at = clue.start
                break
            value_end = max(
                state.value_char_end_override.get(entry_clue.clue_id, entry_clue.end)
                for _, entry_clue in group_entries
            )
            value = normalize_value(comp_type, raw_text[clue.start:value_end])
            if value:
                remaining_levels = {level.value for level in available_levels if level != comp_type}
                removed_suspects = _remove_pending_suspect_group_by_span(
                    state,
                    clue.start,
                    clue.end,
                    origin="value",
                )
                component = _DraftComponent(
                    component_type=comp_type,
                    start=clue.start,
                    end=value_end,
                    value=value,
                    key="",
                    is_detail=comp_type in _DETAIL_COMPONENTS,
                    raw_chain=[entry_clue for _, entry_clue in group_entries],
                    suspected=[
                        _SuspectEntry(
                            level=entry.level,
                            value=entry.value,
                            key=entry.key,
                            origin=entry.origin,
                            start=entry.start,
                            end=entry.end,
                        )
                        for entry in removed_suspects
                        if entry.level in remaining_levels
                    ],
                    clue_ids={entry_clue.clue_id for _, entry_clue in group_entries},
                    clue_indices={entry_index for entry_index, _ in group_entries},
                )
                if not commit(component):
                    break
            cursor = group_end
            continue
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            state.split_at = clue.start
            break
        value_end = state.value_char_end_override.get(clue.clue_id, clue.end)
        value = normalize_value(comp_type, raw_text[clue.start:value_end])
        if not value:
            continue
        component = _DraftComponent(
            component_type=comp_type,
            start=clue.start,
            end=value_end,
            value=value,
            key="",
            is_detail=comp_type in _DETAIL_COMPONENTS,
            raw_chain=[clue],
            suspected=[],
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )
        if not commit(component):
            break
        cursor += 1
    state.pending_suspects.clear()
    _recompute_last_piece_end(state)


def _fixup_suspected_info(state: _ParseState) -> None:
    """后处理：按最终幸存的 suspect 顺序裁剪父 component 的 value。"""
    for component in state.components:
        if not component.suspected:
            continue
        unique: list[_SuspectEntry] = []
        seen: set[str] = set()
        for entry in component.suspected:
            surface = _suspect_surface_text(entry)
            dedupe_key = f"{entry.level}|{entry.origin}|{surface}"
            if not surface or dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            unique.append(entry)
        component.suspected = sorted(unique, key=_suspect_sort_key)
        component.value = _recompute_text(component)


def _recompute_text(component: _DraftComponent) -> str | list[str]:
    """从 component.value 中按顺序删除 suspect 表面文本。"""
    if isinstance(component.value, list):
        return component.value
    value = component.value
    for group in _group_suspected_entries(component.suspected):
        if not group:
            continue
        value = _trim_once(value, _suspect_surface_text(group[0]))
    return value.strip() or component.value


def _meets_commit_threshold(
    evidence_count: int,
    components: list[_DraftComponent],
    locale: str,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
    max_clue_strength: ClaimStrength = ClaimStrength.SOFT,
) -> bool:
    """strength 感知的地址提交阈值。

    STRONG：SOFT 及以上单 evidence 即通过；WEAK only 需 >=2 evidence。
    BALANCED：HARD 单 evidence 通过；SOFT 需 >=2 或含省/市 admin；WEAK 不通过。
    WEAK（保护等级最宽松）：HARD 单 evidence 通过；SOFT + >=2 通过；其余不通过。
    """
    del locale
    if evidence_count <= 0:
        return False
    if protection_level == ProtectionLevel.STRONG:
        if strength_ge(max_clue_strength, ClaimStrength.SOFT):
            return True
        return evidence_count >= 2
    if protection_level == ProtectionLevel.BALANCED:
        if max_clue_strength == ClaimStrength.HARD:
            return True
        if max_clue_strength == ClaimStrength.SOFT:
            if evidence_count >= 2:
                return True
            return any(c.component_type in _SINGLE_EVIDENCE_ADMIN for c in components)
        return False
    # ProtectionLevel.WEAK
    if max_clue_strength == ClaimStrength.HARD:
        return True
    return max_clue_strength == ClaimStrength.SOFT and evidence_count >= 2


def _address_metadata(origin_clue: Clue, components: list[_DraftComponent]) -> dict[str, list[str]]:
    component_types: list[str] = []
    component_trace: list[str] = []
    component_key_trace: list[str] = []
    detail_types: list[str] = []
    detail_values: list[str] = []
    component_suspected_trace: list[str] = []

    for component in components:
        component_type = component.component_type.value
        values = component.value if isinstance(component.value, list) else [component.value]
        keys = component.key if isinstance(component.key, list) else [component.key]
        for value in values:
            component_types.append(component_type)
            component_trace.append(f"{component_type}:{value}")
        for key in keys:
            if key:
                component_key_trace.append(f"{component_type}:{key}")
        if component.is_detail:
            for value in values:
                detail_types.append(component_type)
                detail_values.append(value)
        component_suspected_trace.append(_serialize_suspected_entries(component.suspected))

    return {
        "matched_by": [origin_clue.source_kind],
        "address_kind": ["private_address"],
        "address_match_origin": [
            origin_clue.text if origin_clue.role == ClueRole.LABEL else origin_clue.source_kind
        ],
        "address_component_type": component_types,
        "address_component_trace": component_trace,
        "address_component_key_trace": component_key_trace,
        "address_details_type": detail_types,
        "address_details_text": detail_values,
        "address_component_suspected": component_suspected_trace,
    }


def _ordered_component_clue_entries(
    component: _DraftComponent,
    clues: tuple[Clue, ...],
) -> list[_IndexedClue]:
    """返回 component 对应的有序 clue 列表。"""
    entries: list[_IndexedClue] = []
    for clue_index in sorted(index for index in component.clue_indices if index >= 0):
        if clue_index >= len(clues):
            continue
        clue = clues[clue_index]
        if clue.attr_type != PIIAttributeType.ADDRESS or clue.role == ClueRole.LABEL:
            continue
        entries.append((clue_index, clue))
    return entries


def _rightmost_component_key_overlaps_negative(
    component: _DraftComponent,
    clues: tuple[Clue, ...],
    has_negative_cover: Callable[[int, int], bool],
) -> bool:
    """仅当最右组件的最终 key clue 与负向 span 重叠时，才触发尾修复。"""
    clue_entries = _ordered_component_clue_entries(component, clues)
    for _, clue in reversed(clue_entries):
        if clue.role != ClueRole.KEY:
            continue
        return has_negative_cover(clue.unit_start, clue.unit_end)
    return False


def _rebuild_component_derived_state(
    state: _ParseState,
    clues: tuple[Clue, ...],
    *,
    base_evidence_count: int = 0,
) -> None:
    """按 surviving components 重建组件派生状态。"""
    ordered = sorted(state.components, key=lambda component: (component.end, component.start))
    state.components = ordered
    state.occupancy = {}
    state.deferred_chain.clear()
    state.suspect_chain.clear()
    state.pending_suspects.clear()
    state.chain_left_anchor = None
    state.segment_state = _CommaSegmentState()
    state.last_consumed = None
    state.last_value = None
    state.evidence_count = max(0, base_evidence_count)
    state.last_end = 0
    state.last_component_type = None
    state.committed_clue_ids = set()
    state.consumed_clue_indices = set()
    state.last_consumed_clue_index = -1
    state.value_char_end_override.clear()
    state.pending_comma_value_right_scan = False
    state.pending_comma_first_component = False
    state.component_counts = {}
    state.pending_community_poi_index = None
    state.comma_tail_checkpoint = None
    state.last_piece_end = None
    state.max_clue_strength = ClaimStrength.WEAK

    for index, component in enumerate(state.components):
        component_type = component.component_type
        _increment_component_count(state, component_type)
        if component_type in SINGLE_OCCUPY:
            state.occupancy[component_type] = index
        if (
            component_type == AddressComponentType.POI
            and not isinstance(component.key, list)
            and component.key == "社区"
        ):
            state.pending_community_poi_index = index
        state.evidence_count += 1
        state.committed_clue_ids |= component.clue_ids
        state.consumed_clue_indices |= component.clue_indices
        state.last_component_type = component_type
        state.last_end = max(state.last_end, component.end)
        state.last_piece_end = component.end
        state.segment_state.group_last_type = component_type
        for clue in component.raw_chain:
            if not strength_ge(state.max_clue_strength, clue.strength):
                state.max_clue_strength = clue.strength

    _recompute_last_consumed_index(state)
    if 0 <= state.last_consumed_clue_index < len(clues):
        state.last_consumed = clues[state.last_consumed_clue_index]
