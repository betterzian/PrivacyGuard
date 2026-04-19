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
    # DISTRICT_CITY 与 DISTRICT 共享行政层级语义（同 rank=2，SINGLE_OCCUPY 条目互斥）。
    AddressComponentType.DISTRICT_CITY,
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
    AddressComponentType.DISTRICT_CITY,
    AddressComponentType.SUBDISTRICT,
})

_COMMA_TAIL_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.DISTRICT_CITY,
})

_SUSPECT_KEY_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
    AddressComponentType.DISTRICT_CITY,
})

_ADMIN_RANK: dict[AddressComponentType, int] = {
    AddressComponentType.SUBDISTRICT: 1,
    AddressComponentType.DISTRICT: 2,
    # 县级市与 DISTRICT 同 rank；二者互斥占用同一槽位。
    AddressComponentType.DISTRICT_CITY: 2,
    AddressComponentType.CITY: 3,
    AddressComponentType.PROVINCE: 4,
}

_VALID_SUCCESSORS: dict[AddressComponentType, frozenset[AddressComponentType]] = {
    AddressComponentType.PROVINCE: frozenset({
        AddressComponentType.CITY,
        AddressComponentType.DISTRICT,
        # PROVINCE 后继开放 DISTRICT_CITY，支持"江苏省→张家港市"跳层场景。
        AddressComponentType.DISTRICT_CITY,
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    AddressComponentType.CITY: frozenset({
        AddressComponentType.DISTRICT,
        # CITY 后继开放 DISTRICT_CITY，支持"苏州市→张家港市"。
        AddressComponentType.DISTRICT_CITY,
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    AddressComponentType.DISTRICT: frozenset({
        AddressComponentType.SUBDISTRICT,
        AddressComponentType.ROAD,
        AddressComponentType.POI,
    }),
    # DISTRICT_CITY 的后继集合与 DISTRICT 一致。
    AddressComponentType.DISTRICT_CITY: frozenset({
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
_ValidateKeyComponentFn = Callable[
    ["_ParseState", tuple["_IndexedClue", ...], Clue, int, AddressComponentType],
    bool,
]


def _ordered_component_level(
    level: tuple[AddressComponentType, ...] | list[AddressComponentType] | Iterable[AddressComponentType],
) -> tuple[AddressComponentType, ...]:
    """把 level 元组按 `_ADMIN_RANK` 降序排列；非 admin 层与未入 rank 表的层排在其后，保持原相对顺序。

    入口契约（不变式）：
    - 至少一元素；`_DraftComponent.__post_init__` / `_SuspectEntry.__post_init__` 负责非空校验。
    - 去重：同层只保留一次（以首次出现为准）。
    """
    seen: set[AddressComponentType] = set()
    deduped: list[AddressComponentType] = []
    for lvl in level:
        if lvl in seen:
            continue
        seen.add(lvl)
        deduped.append(lvl)
    if len(deduped) <= 1:
        return tuple(deduped)
    # 稳定排序：rank 高者在前；rank 相同或缺失者按原始相对顺序保留。
    indexed = list(enumerate(deduped))
    indexed.sort(key=lambda pair: (-_ADMIN_RANK.get(pair[1], 0), pair[0]))
    return tuple(lvl for _, lvl in indexed)


@dataclass(slots=True)
class _DraftComponent:
    """主循环产出的草稿 component。

    `level` 元组是 component 的真实层级载体；`component_type` 是它的 derived 视图：
    - `len(level) == 1` → `component_type = level[0]`
    - `len(level) >= 2` → `component_type = MULTI_ADMIN`
    单层 component 构造时可省略 `level`，`__post_init__` 自动从 `component_type` 反填为 `(component_type,)`。
    """

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
    level: tuple[AddressComponentType, ...] = ()

    def __post_init__(self) -> None:
        if not self.level:
            # 单层构造路径：component_type 必须是具体 admin 枚举（不是 MULTI_ADMIN）。
            assert self.component_type is not None
            assert self.component_type != AddressComponentType.MULTI_ADMIN, (
                "MULTI_ADMIN 只能通过显式 level 元组构造，不能依赖 component_type 反填"
            )
            self.level = (self.component_type,)
        else:
            self.level = _ordered_component_level(self.level)
        self._sync_component_type()

    def _sync_component_type(self) -> None:
        if len(self.level) == 1:
            self.component_type = self.level[0]
        else:
            assert len(self.level) >= 2
            self.component_type = AddressComponentType.MULTI_ADMIN


def _set_component_level(
    component: _DraftComponent,
    new_level: tuple[AddressComponentType, ...],
) -> None:
    """统一更新 component.level 并同步 component_type，保持 derived 视图一致。"""
    component.level = _ordered_component_level(new_level)
    component._sync_component_type()


def _is_admin_component(component: _DraftComponent) -> bool:
    """是否承担任一行政层级（PROVINCE / CITY / DISTRICT / DISTRICT_CITY / SUBDISTRICT）。"""
    return any(lvl in _ADMIN_TYPES for lvl in component.level)


def _admin_rank_max(component: _DraftComponent) -> int:
    """返回 component 覆盖的最高 admin rank；无 admin 层返回 0。"""
    return max((_ADMIN_RANK.get(lvl, 0) for lvl in component.level), default=0)


def _admin_levels_of(component: _DraftComponent) -> tuple[AddressComponentType, ...]:
    """返回 component.level 中属于 _ADMIN_TYPES 的子集（顺序保留）。"""
    return tuple(lvl for lvl in component.level if lvl in _ADMIN_TYPES)


def _effective_successors(
    prev: _DraftComponent | None,
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
) -> frozenset[AddressComponentType]:
    """返回 `prev` 可接的后继集合。

    - `prev is None`：无约束，允许所有类型。
    - prev 为 MULTI_ADMIN：后继为 `level` 中**各层后继的交集**（严格语义：前一段 MULTI_ADMIN
      要求同时满足所有可能解释下的接续合法性）。
    - 其他：直接查 `valid_successors[prev.component_type]`。
    """
    if prev is None:
        return _ALL_TYPES
    if prev.component_type == AddressComponentType.MULTI_ADMIN:
        sets = [
            frozenset(valid_successors.get(lvl, _ALL_TYPES))
            for lvl in prev.level
        ]
        if not sets:
            return _ALL_TYPES
        return frozenset.intersection(*sets)
    return frozenset(valid_successors.get(prev.component_type, _ALL_TYPES))


def _component_can_follow(
    prev: _DraftComponent | None,
    next_level: tuple[AddressComponentType, ...],
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
) -> bool:
    """后一段（可能是 MULTI_ADMIN）相对前一段是否合法：next_level 任一层落在有效后继集即可。"""
    valid = _effective_successors(prev, valid_successors=valid_successors)
    return any(lvl in valid for lvl in next_level)


def _occupies_level(state: "_ParseState", level: AddressComponentType) -> bool:
    """level 是否已在 SINGLE_OCCUPY 语义下被占用（DISTRICT / DISTRICT_CITY 互斥也在此生效）。"""
    if level not in SINGLE_OCCUPY:
        return False
    return level in state.occupancy


def _segment_occupancy_conflict(
    state: "_ParseState",
    level_tuple: tuple[AddressComponentType, ...],
) -> bool:
    """level 元组中任一层已被占用即冲突。"""
    return any(_occupies_level(state, lvl) for lvl in level_tuple)


@dataclass(slots=True)
class _SuspectEntry:
    """主循环冻结的疑似行政子组件。

    `level` 元组表示同一 value 可能承担的多个候选行政层级（例："北京" → (P, C)）。
    元组非空且按 `_ADMIN_RANK` 降序排列；同值多层 suspect 使用单条 entry 表达。
    """

    level: tuple[AddressComponentType, ...]
    value: str
    key: str
    origin: str
    start: int
    end: int

    def __post_init__(self) -> None:
        assert self.level, "_SuspectEntry.level 必须非空"
        self.level = _ordered_component_level(self.level)


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
    seed_floor: int | None = None
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


# §3.4 resolver 返回视图；此处不显式 import 以避免与 policy 的循环依赖，
# 运行时 duck-type 访问 `available_levels` / `all_levels` / `text` 三个字段。
# 契约见 `privacyguard.infrastructure.pii.detector.stacks.address_policy_zh._AdminSpanView`。
_StandaloneAdminResolver = Callable[
    [_ParseState, tuple[_IndexedClue, ...]],
    "object | None",
]

# §3.5：KEY-driven admin chain 的层级解析回调。给定 last KEY 之前的 VALUE 条目 +
# last KEY clue，返回可落 admin 组件的层级元组（见 policy_zh._resolve_admin_key_chain_levels）。
_AdminKeyChainResolver = Callable[
    [_ParseState, tuple[_IndexedClue, ...], Clue],
    tuple[AddressComponentType, ...] | None,
]


def _clone_component_value(value: str | list[str]) -> str | list[str]:
    return list(value) if isinstance(value, list) else value


def _clone_component_key(key: str | list[str]) -> str | list[str]:
    return list(key) if isinstance(key, list) else key


def _clone_draft_component(component: _DraftComponent) -> _DraftComponent:
    """复制组件，避免回滚快照与实时状态共享可变容器。"""
    return _DraftComponent(
        component_type=AddressComponentType.MULTI_ADMIN
        if len(component.level) >= 2
        else component.component_type,
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
        # 显式传递 level，避免 __post_init__ 走 component_type 反填；MULTI_ADMIN 组件
        # 必须依赖 level 元组恢复形态。
        level=tuple(component.level),
    )


def _suspect_surface_text(entry: _SuspectEntry) -> str:
    """返回用于删除与比较的 suspect 表面文本。"""
    if entry.origin == "key":
        return f"{entry.value}{entry.key}".strip()
    return entry.value.strip()


def _suspect_sort_key(entry: _SuspectEntry) -> tuple[int, int, int, str]:
    """同组内按行政层级从高到低稳定排序。

    以 `entry.level[0]` 为主排序层（已由 `_ordered_component_level` 确保是最高 rank）；
    次键用 level 元组的 value 字符串表示形式作稳定 tiebreaker。
    """
    primary = entry.level[0] if entry.level else None
    rank = _ADMIN_RANK.get(primary, 0) if primary is not None else 0
    level_key = "|".join(lvl.value for lvl in entry.level)
    return (entry.start, entry.end, -rank, level_key)


def _serialize_suspected_entries(entries: list[_SuspectEntry]) -> str:
    """把一个组件上的 suspect 列表序列化到 metadata。

    输出形如 `[{"levels":["province","city"],"value":"北京","key":"","origin":"key"}]`；
    `levels` 直接来自 `entry.level` 元组的 `.value` 投影。
    """
    if not entries:
        return ""
    payload = [
        {
            "levels": [lvl.value for lvl in entry.level],
            "value": entry.value,
            "key": entry.key,
            "origin": entry.origin,
        }
        for entry in sorted(entries, key=_suspect_sort_key)
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


def _remove_pending_suspect_by_level(
    state: _ParseState,
    level: AddressComponentType,
) -> _SuspectEntry | None:
    """从当前链 pending suspects 中扣除指定 level。

    语义（与 tuple 化 level 配套）：
    - 若 `level in entry.level`，把该层从元组中移除；元组为空则整条 entry 删除。
    - 每次调用最多只处理一条 entry（"最近一个同层级 suspect"），与改造前保持一致。
    - 返回被移除或缩短的原 entry（供上游需要引用原层级信息时使用）；无命中返回 None。
    """
    removed: _SuspectEntry | None = None
    kept: list[_SuspectEntry] = []
    for entry in state.pending_suspects:
        if removed is None and level in entry.level:
            removed = entry
            shrunk = tuple(lvl for lvl in entry.level if lvl != level)
            if shrunk:
                # 保留 entry，仅缩短 level；其余字段不变。
                kept.append(_SuspectEntry(
                    level=shrunk,
                    value=entry.value,
                    key=entry.key,
                    origin=entry.origin,
                    start=entry.start,
                    end=entry.end,
                ))
            # shrunk 空 → 整条删除（即不 append）
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
    # 通过 _set_component_level 同步更新 level 元组与 component_type，保持 derived 视图一致。
    _set_component_level(component, (AddressComponentType.SUBDISTRICT,))
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
    if any(level in _COMMA_TAIL_ADMIN_TYPES for level in component.level):
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
    """后续真实组件一旦落地，移除旧 suspect 中同级或更高的行政层。"""
    new_admin_levels = _admin_levels_of(new_component)
    if not new_admin_levels:
        return
    cutoff_rank = min((_ADMIN_RANK.get(level, 0) for level in new_admin_levels), default=0)
    if cutoff_rank <= 0:
        return
    for prior in state.components[:-1]:
        changed = False
        kept: list[_SuspectEntry] = []
        for entry in prior.suspected:
            remaining_levels = tuple(
                lvl
                for lvl in entry.level
                if _ADMIN_RANK.get(lvl, 0) < cutoff_rank
            )
            if len(remaining_levels) == len(entry.level):
                kept.append(entry)
                continue
            changed = True
            if not remaining_levels:
                continue
            kept.append(_SuspectEntry(
                level=remaining_levels,
                value=entry.value,
                key=entry.key,
                origin=entry.origin,
                start=entry.start,
                end=entry.end,
            ))
        if changed:
            prior.suspected = kept
            prior.suspect_demoted = True


def _resolve_multi_admin_collision(
    state: _ParseState,
    raw_text: str,
    incoming_start: int,
    incoming_value: str,
    incoming_levels: tuple[AddressComponentType, ...],
    *,
    admin_rank: Mapping[AddressComponentType, int] = None,  # type: ignore[assignment]
) -> tuple[AddressComponentType, ...] | None:
    """§5.1 MULTI_ADMIN 同值降解。

    仅供 admin commit 路径调用（`_flush_chain_as_standalone` / KEY-driven admin flush /
    进入 `_segment_admit` 前）。若 incoming_value 与某已提交的 MULTI_ADMIN 同值且
    level 有交集，按 pair 之间的逗号方向把 existing MULTI_ADMIN 原地降解，
    返回 incoming 应取的 level 子集；无碰撞 / 无交集返回 None。

    方向规则：
    - 无逗号（顺向）：existing 保留最高层（"北京市" = P），incoming 取最低层（= C）
    - 有逗号（逆向）：existing 保留最低层（= C），incoming 取最高层（= P）

    suspect 是旁注元数据、不占 occupancy，`_freeze_*` 路径**不**触发 collision。
    """
    rank = admin_rank if admin_rank is not None else _ADMIN_RANK
    target_idx: int | None = None
    for lvl in incoming_levels:
        idx = state.occupancy.get(lvl)
        if idx is None:
            continue
        comp = state.components[idx]
        if (
            comp.component_type == AddressComponentType.MULTI_ADMIN
            and not isinstance(comp.value, list)
            and comp.value == incoming_value
        ):
            target_idx = idx
            break
    if target_idx is None:
        return None

    existing = state.components[target_idx]
    overlap = [lvl for lvl in existing.level if lvl in incoming_levels]
    if not overlap:
        return None

    has_comma = any(char in ",，" for char in raw_text[existing.end:incoming_start])
    if has_comma:
        incoming_take = max(overlap, key=lambda item: rank.get(item, 0))
    else:
        incoming_take = min(overlap, key=lambda item: rank.get(item, 0))

    # 原地降解 existing：把 incoming_take 这一层从 existing.level 中移除。
    state.occupancy.pop(incoming_take, None)
    new_level = tuple(lvl for lvl in existing.level if lvl != incoming_take)
    if not new_level:
        # 理论上 overlap 不会覆盖 existing.level 全部（否则 incoming 等价于 existing），
        # 留一个防御性退路：无法降解就不动，返回 None。
        return None
    prev_type = existing.component_type
    _set_component_level(existing, new_level)
    new_type = existing.component_type

    if prev_type != new_type:
        # existing 从 MULTI_ADMIN 退回具体 admin 层：修正 component_counts 与 segment 视图。
        if prev_type == AddressComponentType.MULTI_ADMIN:
            count = state.component_counts.get(AddressComponentType.MULTI_ADMIN, 0)
            if count <= 1:
                state.component_counts.pop(AddressComponentType.MULTI_ADMIN, None)
            else:
                state.component_counts[AddressComponentType.MULTI_ADMIN] = count - 1
            _increment_component_count(state, new_type)
        if state.last_component_type == prev_type:
            state.last_component_type = new_type
        if state.segment_state.group_last_type == prev_type:
            state.segment_state.group_last_type = new_type
        if state.segment_state.group_first_type == prev_type:
            state.segment_state.group_first_type = new_type
        # 原地降解改变了段序推导基础，方向需要重新评估。
        state.segment_state.direction = None

    return (incoming_take,)


def _commit(
    state: _ParseState,
    component: _DraftComponent,
    *,
    valid_successors: _SuccessorMap = _VALID_SUCCESSORS,
) -> bool:
    """提交 component 到 state，更新 occupancy / segment / evidence。"""
    # 只有 key 没有 value 的组件不允许提交。
    if component.key and not component.value:
        return False
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
    # 按 component.level 元组逐层写 occupancy：MULTI_ADMIN(P,C) 会同时占住 P 和 C 槽位，
    # 指向同一 index；不为 MULTI_ADMIN 本身设单独槽位。
    for lvl in committed.level:
        if lvl in SINGLE_OCCUPY:
            state.occupancy[lvl] = index
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
    resolve_admin_key_chain_levels: _AdminKeyChainResolver | None = None,
    validate_key_component: _ValidateKeyComponentFn | None = None,
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
        used_entries = tuple(state.deferred_chain[: last_key_idx + 1])
        key_clue = used_entries[-1][1]
        comp_type = key_clue.component_type or AddressComponentType.POI
        if comp_type == AddressComponentType.NUMBER and state.last_component_type in _DETAIL_COMPONENTS:
            comp_type = AddressComponentType.DETAIL
        component_start = state.chain_left_anchor if state.chain_left_anchor is not None else key_clue.start

        # §3.5：MULTI_ADMIN routed KEY 必须通过 admin-key-chain 解析器拿到 level 元组才能构造组件。
        if comp_type == AddressComponentType.MULTI_ADMIN:
            value_entries = tuple(used_entries[:-1])
            resolution = None
            if resolve_admin_key_chain_levels is not None:
                resolution = resolve_admin_key_chain_levels(state, value_entries, key_clue)
            if resolution is None:
                # 非 admin 链或无法 build span：MULTI_ADMIN 类型无法构造，split。
                state.split_at = component_start
            else:
                resolved_levels: tuple[AddressComponentType, ...] = resolution.available_levels
                if not resolved_levels:
                    # §5.2.3 collision 触发点：available 为空时，先尝试同值 MULTI_ADMIN 降解。
                    forced = _resolve_multi_admin_collision(
                        state,
                        raw_text,
                        component_start,
                        resolution.text,
                        resolution.all_levels,
                    )
                    if forced is None:
                        state.split_at = component_start
                    else:
                        resolved_levels = forced
                if resolved_levels:
                    primary_level = resolved_levels[0]
                    value = normalize_value(primary_level, raw_text[component_start:key_clue.start])
                    if value:
                        component = _DraftComponent(
                            component_type=AddressComponentType.MULTI_ADMIN
                            if len(resolved_levels) >= 2
                            else primary_level,
                            start=component_start,
                            end=key_clue.end,
                            value=value,
                            key=key_clue.text,
                            is_detail=primary_level in _DETAIL_COMPONENTS,
                            raw_chain=[clue for _, clue in used_entries],
                            suspected=[],
                            level=tuple(resolved_levels),
                            clue_ids={clue.clue_id for _, clue in used_entries},
                            clue_indices={index for index, _ in used_entries},
                        )
                        commit(component)
        else:
            if (
                validate_key_component is not None
                and not validate_key_component(state, used_entries, key_clue, component_start, comp_type)
            ):
                if state.components:
                    state.split_at = component_start
            else:
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
            resolution = resolve_standalone_admin_group(state, group_entries)
            if resolution is None:
                state.split_at = clue.start
                break
            # 契约：`resolution` 是 policy 侧 `_AdminSpanView`（duck-typed 访问字段）。
            resolved_levels: tuple[AddressComponentType, ...] = resolution.available_levels
            raw_levels: tuple[AddressComponentType, ...] = resolution.all_levels
            span_text: str = resolution.text
            value_end = max(
                state.value_char_end_override.get(entry_clue.clue_id, entry_clue.end)
                for _, entry_clue in group_entries
            )
            if not resolved_levels:
                # §5.2.2 collision 触发点：available 为空时，若存在同值 MULTI_ADMIN 则原地降解，
                # 让 incoming 取互补层继续落库；否则 split。
                forced = _resolve_multi_admin_collision(
                    state,
                    raw_text,
                    clue.start,
                    span_text,
                    raw_levels,
                )
                if forced is None:
                    state.split_at = clue.start
                    break
                resolved_levels = forced
            # §3.4：len>=2 直接构造 MULTI_ADMIN 组件；len==1 退回单层 admin 组件。
            # SINGLE_OCCUPY 占位冲突检查改为逐层：任一层被占用即视为冲突。
            occupancy_conflict = any(
                lvl in SINGLE_OCCUPY and lvl in state.occupancy
                for lvl in resolved_levels
            )
            if occupancy_conflict:
                state.split_at = clue.start
                break
            # normalize_value 仍按最高 rank 的 admin 类型做归一化（与历史行为对齐）。
            primary_level = resolved_levels[0]
            value = normalize_value(primary_level, raw_text[clue.start:value_end])
            if value:
                # MULTI_ADMIN 直接承载全部 resolved_levels；不再保留未消化 suspect 候选。
                _remove_pending_suspect_group_by_span(
                    state,
                    clue.start,
                    clue.end,
                    origin="value",
                )
                component = _DraftComponent(
                    component_type=AddressComponentType.MULTI_ADMIN
                    if len(resolved_levels) >= 2
                    else primary_level,
                    start=clue.start,
                    end=value_end,
                    value=value,
                    key="",
                    is_detail=primary_level in _DETAIL_COMPONENTS,
                    raw_chain=[entry_clue for _, entry_clue in group_entries],
                    suspected=[],
                    level=tuple(resolved_levels),
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
            dedupe_key = f"{'|'.join(lvl.value for lvl in entry.level)}|{entry.origin}|{surface}"
            if not surface or dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            unique.append(entry)
        component.suspected = sorted(unique, key=_suspect_sort_key)
        component.value = _recompute_text(component)


def _recompute_text(component: _DraftComponent) -> str | list[str]:
    """从 component.value 中按顺序删除 suspect 表面文本。

    tuple 化 level 后，同一 span 的候选层级合并到单条 entry；此处按 suspect entry
    自然顺序依次剥离表面文本即可，不再需要按 group_key 合桶。
    """
    if isinstance(component.value, list):
        return component.value
    value = component.value
    for entry in component.suspected:
        surface = _suspect_surface_text(entry)
        if not surface:
            continue
        value = _trim_once(value, surface)
    return value.strip() or component.value


def _meets_commit_threshold(
    evidence_count: int,
    components: list[_DraftComponent],
    locale: str,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
    claim_strength: ClaimStrength = ClaimStrength.SOFT,
) -> bool:
    """地址提交阈值只看 `claim_strength`。"""
    del evidence_count, components, locale
    if protection_level == ProtectionLevel.STRONG:
        return strength_ge(claim_strength, ClaimStrength.SOFT)
    return claim_strength == ClaimStrength.HARD


def _sum_strength(parts: Iterable[ClaimStrength]) -> ClaimStrength:
    """按统一升级规则聚合强度。"""
    soft_count = 0
    weak_count = 0
    for strength in parts:
        if strength == ClaimStrength.HARD:
            return ClaimStrength.HARD
        if strength == ClaimStrength.SOFT:
            soft_count += 1
            continue
        if strength == ClaimStrength.WEAK:
            weak_count += 1
    if soft_count >= 2:
        return ClaimStrength.HARD
    if soft_count == 1:
        return ClaimStrength.SOFT
    if weak_count >= 2:
        return ClaimStrength.SOFT
    return ClaimStrength.WEAK


def _component_strength(component: _DraftComponent) -> ClaimStrength:
    """按 VALUE / KEY 两侧证据聚合单个 component 的强度。"""
    parts: list[ClaimStrength] = []
    value_strength: ClaimStrength | None = None
    for clue in component.raw_chain:
        if clue.role != ClueRole.VALUE:
            continue
        if value_strength is None or not strength_ge(value_strength, clue.strength):
            value_strength = clue.strength
    if value_strength is not None:
        parts.append(value_strength)
    for clue in reversed(component.raw_chain):
        if clue.role == ClueRole.KEY:
            parts.append(clue.strength)
            break
    return _sum_strength(parts)


def _address_strength(components: list[_DraftComponent]) -> ClaimStrength:
    """按 component 聚合整段地址的 claim_strength。"""
    return _sum_strength(_component_strength(component) for component in components)


def _address_metadata(origin_clue: Clue, components: list[_DraftComponent]) -> dict[str, list[str]]:
    component_types: list[str] = []
    component_levels: list[str] = []
    component_trace: list[str] = []
    component_key_trace: list[str] = []
    detail_types: list[str] = []
    detail_values: list[str] = []
    component_suspected_trace: list[str] = []

    for component in components:
        component_type = component.component_type.value
        level_tuple = component.level if component.level else (component.component_type,)
        # 多层级（MULTI_ADMIN）按 _ADMIN_RANK 降序 `|` 分隔；单层级直接取该层 value。
        if len(level_tuple) >= 2:
            sorted_levels = sorted(
                level_tuple,
                key=lambda ct: _ADMIN_RANK.get(ct, 0),
                reverse=True,
            )
            level_str = "|".join(ct.value for ct in sorted_levels)
        else:
            level_str = level_tuple[0].value
        values = component.value if isinstance(component.value, list) else [component.value]
        keys = component.key if isinstance(component.key, list) else [component.key]
        for value in values:
            component_types.append(component_type)
            component_levels.append(level_str)
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
        "address_component_level": component_levels,
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

    for index, component in enumerate(state.components):
        component_type = component.component_type
        _increment_component_count(state, component_type)
        # 与 `_commit` 一致：按 level 元组逐层写 occupancy，兼容 MULTI_ADMIN。
        for lvl in component.level:
            if lvl in SINGLE_OCCUPY:
                state.occupancy[lvl] = index
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

    _recompute_last_consumed_index(state)
    if 0 <= state.last_consumed_clue_index < len(clues):
        state.last_consumed = clues[state.last_consumed_clue_index]
