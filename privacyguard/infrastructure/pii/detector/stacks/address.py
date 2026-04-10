"""地址 stack：基于 clue 状态机的地址解析。

核心流程：seed → 主循环（deferred_chain + segment_admit）→ fixup_suspected → digit_tail → build_run。
参见 docs/address.md。
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

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
class _ForwardSegmentState:
    """段内正向状态；逗号重置。"""

    last_type: AddressComponentType | None = None

    def reset(self) -> None:
        self.last_type = None


@dataclass(slots=True)
class _ParseState:
    """run_with_clues 的可变解析状态。"""

    components: list[_DraftComponent] = field(default_factory=list)
    occupancy: dict[AddressComponentType, int] = field(default_factory=dict)
    deferred_chain: list[_IndexedClue] = field(default_factory=list)
    suspect_chain: list[_IndexedClue] = field(default_factory=list)
    chain_left_anchor: int | None = None
    segment_state: _ForwardSegmentState = field(default_factory=_ForwardSegmentState)
    last_consumed: Clue | None = None
    last_value: Clue | None = None
    evidence_count: int = 0
    last_end: int = 0
    split_at: int | None = None
    absorbed_digit_unit_end: int = 0
    last_component_type: AddressComponentType | None = None
    committed_clue_ids: set[str] = field(default_factory=set)
    consumed_clue_indices: set[int] = field(default_factory=set)
    last_consumed_clue_index: int = -1


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

# ---------------------------------------------------------------------------
# 链式吸收
# ---------------------------------------------------------------------------


def _chain_can_accept(state: _ParseState, clue: Clue, stream: StreamInput) -> bool:
    """判断 clue 能否加入当前 deferred_chain。

    只允许三种链接：
    1. VALUE→VALUE: gap ≤ 1 non-space unit。
    2. VALUE→KEY: gap ≤ 1 non-space unit。
    3. KEY→KEY: gap 必须为 0（严格相邻）。

    KEY→VALUE 不允许继续挂链。
    """
    if not state.deferred_chain:
        return False
    _, last = state.deferred_chain[-1]
    gap = _clue_unit_gap(last, clue, stream)
    if last.role == ClueRole.KEY and clue.role == ClueRole.VALUE:
        return False
    if last.role == ClueRole.KEY and clue.role == ClueRole.KEY:
        return gap == 0
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
        _flush_chain_as_standalone(state)

    state.deferred_chain.clear()
    state.suspect_chain.clear()
    state.chain_left_anchor = None


def _flush_chain_as_standalone(state: _ParseState) -> None:
    """链中无 KEY 时，逐个 VALUE 作为独立 component 提交。"""
    for clue_index, clue in state.deferred_chain:
        comp_type = clue.component_type
        if comp_type is None:
            continue
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            state.split_at = clue.start
            break
        value = _normalize_address_value(comp_type, clue.text)
        if not value:
            continue
        component = _DraftComponent(
            component_type=comp_type,
            start=clue.start,
            end=clue.end,
            value=value,
            key="",
            is_detail=comp_type in _DETAIL_COMPONENTS,
            raw_chain=[],
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )
        _commit(state, component)


def _commit(state: _ParseState, component: _DraftComponent) -> None:
    """提交 component 到 state，更新 occupancy / segment / evidence。"""
    comp_type = component.component_type
    if comp_type == AddressComponentType.POI:
        committed = _commit_poi(state, component)
    else:
        state.components.append(component)
        committed = component
    idx = len(state.components) - 1
    if comp_type in SINGLE_OCCUPY:
        state.occupancy[comp_type] = idx
    state.segment_state.last_type = comp_type
    state.last_component_type = comp_type
    state.last_end = max(state.last_end, committed.end)
    state.evidence_count += 1
    state.committed_clue_ids |= committed.clue_ids
    _mark_consumed_indices(state, committed.clue_indices)
    _prune_prior_component_suspects(state, committed)


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
            return existing
    state.components.append(component)
    return component


# ---------------------------------------------------------------------------
# 段内检查
# ---------------------------------------------------------------------------

def _segment_admit(
    state: _ParseState,
    clue: Clue,
    comp_type: AddressComponentType,
    raw_text: str,
) -> bool:
    """逗号分段 + 占位检查。返回 False 时外层应 STOP。"""
    gap_text = raw_text[state.last_end:clue.start]
    has_comma = "," in gap_text or "，" in gap_text

    if has_comma:
        state.segment_state.reset()
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            return False
        return True

    # 无逗号 → 段内严格正向。
    if state.segment_state.last_type is None:
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            return False
        return True
    if comp_type in _REACHABLE.get(state.segment_state.last_type, _ALL_TYPES):
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            return False
        return True
    return False


def _has_reasonable_successor_key(
    clues: tuple[Clue, ...],
    index: int,
    admin_type: AddressComponentType,
    stream: StreamInput,
) -> bool:
    """后置 admin VALUE 的前瞻：仅检查右侧是否存在可连接的后继 KEY。

    这里不做右边界裁决，也不在此处让 negative / NAME / ORGANIZATION 直接截断地址。
    这些 clue 只影响最终 address 提交阶段，不影响“后面是否还存在一个可连接 KEY”的判断。
    """
    anchor = clues[index]
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
        if nxt.role == ClueRole.KEY and nxt.component_type is not None:
            if nxt.component_type in _REACHABLE.get(admin_type, _ALL_TYPES):
                return True
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

    if not sub_clues:
        us, ue = _char_span_to_unit_span(stream, span_start, span_end)
        return [Clue(
            clue_id=_make_id(),
            family=ClueFamily.ADDRESS,
            role=ClueRole.VALUE,
            attr_type=PIIAttributeType.ADDRESS,
            strength=ClaimStrength.SOFT,
            start=span_start,
            end=span_end,
            text=text,
            unit_start=us,
            unit_end=ue,
            source_kind="sub_tokenize_fallback_poi",
            component_type=AddressComponentType.POI,
        )]

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
            return self._build_direct_run()

        sub_tuple = tuple(sub_clues)
        result = self._run_with_sub_clues(sub_tuple, locale)
        if result is not None:
            return result
        return self._build_direct_run()

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
            if is_break_clue(clue) or is_negative_clue(clue):
                break

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
                    consumed_ids.add(clue.clue_id)
                    _mark_consumed_indices(state, {index})
                    index += 1
                    continue
                if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
                    if _has_nearby_address_clue(clues, index + 1, clue.end, locale=locale, raw_text=raw_text):
                        state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_end)
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
        comp_type = clue.component_type
        if comp_type is None:
            return None

        # NUMBER 上下文重映射。
        if comp_type == AddressComponentType.NUMBER:
            if state.last_component_type in _DETAIL_COMPONENTS:
                comp_type = AddressComponentType.DETAIL

        # ---- VALUE ----
        if clue.role == ClueRole.VALUE:
            # 当前链尾若是 KEY，则 VALUE 不能继续挂链，需先结算前一个组件。
            if state.deferred_chain and not _chain_can_accept(state, clue, stream):
                _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP

            # 后置 admin VALUE：先做「疑似新地址」前瞻，不立即切分。
            if state.components or state.deferred_chain:
                if not _segment_admit(state, clue, comp_type, raw_text):
                    if (
                        comp_type in _ADMIN_TYPES
                        and _has_reasonable_successor_key(clues, clue_index, comp_type, stream)
                    ):
                        # 有合理后继 KEY：先提交前一个正序链，再以当前 admin VALUE 作为新链起点。
                        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                        if state.split_at is not None:
                            return _SENTINEL_STOP
                        _append_deferred(state, clue_index, clue, record_suspect=False)
                        state.last_value = clue
                        state.last_end = max(state.last_end, clue.end)
                        return None
                    else:
                        # 无合理后继 KEY：从该 admin 处切分为下一地址 run。
                        _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                        state.split_at = clue.start
                        return _SENTINEL_STOP
            if state.deferred_chain:
                if not _chain_can_accept(state, clue, stream):
                    _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                    if state.split_at is not None:
                        return _SENTINEL_STOP
            _append_deferred(state, clue_index, clue, record_suspect=True)
            state.last_value = clue
            state.last_end = max(state.last_end, clue.end)
            return None

        # ---- KEY ----
        if clue.role == ClueRole.KEY:
            # KEY 仍走段规则（admin 后置前瞻仅作用于 VALUE 分支）。
            if state.components or state.deferred_chain:
                if not _segment_admit(state, clue, comp_type, raw_text):
                    _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                    state.split_at = clue.start
                    return _SENTINEL_STOP
            if state.deferred_chain and _chain_can_accept(state, clue, stream):
                _remove_last_value_suspect(state, clue, stream)
                _append_deferred(state, clue_index, clue, record_suspect=False)
                state.last_end = max(state.last_end, clue.end)
                return None

            # 链非空但不能接受此 KEY → flush 现有 chain。
            if state.deferred_chain:
                _flush_chain(state, raw_text, stream, locale, clues=clues, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP

            # 链空 → 尝试构建独立 KEY component。
            component = self._build_key_component(
                raw_text,
                clue,
                comp_type,
                clue_index,
                locale,
                component_start=state.last_end,
                allow_left_expand=not state.components,
            )
            if component is not None:
                _commit(state, component)
            else:
                # 空 value → KEY 作为新 chain 的种子。
                _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        return None

    # ------------------------------------------------- build helpers

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
                for level, text in sorted(component.suspected.items(), key=lambda x: x[0])
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


def _analyze_digit_tail(
    components: list[_DraftComponent],
    stream: StreamInput,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
) -> DigitTailResult | None:
    if not components or not getattr(stream, "units", None):
        return None
    last = max(components, key=lambda c: (c.end, c.start))
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
