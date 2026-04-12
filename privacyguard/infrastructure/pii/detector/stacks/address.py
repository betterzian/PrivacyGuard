"""地址 stack：基于 clue 流的状态机解析，把 ADDRESS 线索组装为候选。

处理总览（与 tests/test_address_stack.py 的对应关系）：
1. **入口**：`AddressStack.run` — LABEL/START 起栈时先 `_label_seed_*` 找首个 VALUE 或近邻 KEY；
   HARD 则 `_sub_tokenize` 后在子线索上跑同一套扫描。
2. **主扫描**：`_scan_components` 顺序消费 clue；遇 gap 内「强截断」或逗号尾规则失败时 `split_at` 结束窗口。
3. **单条 ADDRESS clue**：`_handle_address_clue` — KEY 先 `_routed_key_clue` 动态改型/忽略；VALUE/KEY 写入
   `deferred_chain`，由 `_flush_chain`（state 模块）落成 `_DraftComponent`。
4. **负向修复**：扫描收集 `negative_spans`，`_repair_negative_tail_components` 仅在**最右组件的 KEY**
   与负向重叠时尝试截断前缀并重放。
5. **数字尾**：`_analyze_digit_tail` 在最后一个 ROAD/POI/… 后吸收 `digit_run`；若后面还有地址 KEY，
   可能构造 `PendingChallenge`（保守 run + 扩展 run）。

模块分工：
- **本文件**：`AddressStack`  orchestrate 扫描循环、调用 policy/state 的纯函数、产出 `StackRun`。
- **address_policy.py**：单位边界、KEY 路由、链可接性、逗号尾预检、数字尾解析等**无状态规则**。
- **address_state.py**：`_ParseState` / `_DraftComponent`、`_commit`、`_flush_chain`、阈值与 metadata。

调用层级（自顶向下，省略部分工具函数）::

    AddressStack.run
    ├── _run_hard → _run_with_sub_clues → _scan_components → _build_address_run_from_state
    └── _run_with_clues
        ├── _scan_components
        │   ├── _flush_chain (address_state._flush_chain)
        │   ├── _consume_non_address_clue
        │   └── _handle_address_clue
        │       ├── _prepare_effective_clue → _routed_key_clue
        │       ├── _comma_tail_prehandle
        │       ├── _handle_value_clue → _append_deferred / _flush_chain / policy._segment_admit …
        │       └── _handle_key_clue → _flush_chain / _build_key_component …
        ├── _repair_negative_tail_components（可选）
        ├── _fixup_suspected_info
        ├── _analyze_digit_tail（可选，挑战路径）
        └── _build_address_run_from_state
"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value, has_address_signal, trim_candidate
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueRole,
    PIIAttributeType,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _skip_separators,
    _unit_char_end,
    _unit_char_start,
    _unit_index_at_or_after,
    is_break_clue,
    is_negative_clue,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy import (
    DigitTailResult,
    _ADMIN_TYPES,
    _DETAIL_COMPONENTS,
    _PREFIX_EN_KEYWORDS,
    _RoutingContext,
    _SENTINEL_IGNORE,
    _SENTINEL_STOP,
    _analyze_digit_tail,
    _bridge_last_address_to_next_within_units,
    _chain_can_accept,
    _clue_gap_has_search_stop,
    _clue_unit_gap,
    _comma_tail_prehandle,
    _comma_value_scan_upper_bound,
    _has_reasonable_successor_key,
    _is_absorbable_digit_clue,
    _key_has_left_value,
    _key_left_expand_start_if_deferrable,
    _label_seed_address_index,
    _label_seed_start_char,
    _materialize_digit_tail_before_comma,
    _next_address_clue_index_after,
    _normalize_address_value,
    _routed_key_clue,
    _scan_forward_value_end,
    _span_has_non_comma_search_stop_unit,
    _span_has_search_stop_unit,
    _start_after_component_end,
    _state_next_component_start,
    _sub_tokenize,
    _suspect_eligible_after_last_piece,
    _freeze_key_suspect_from_previous_key,
    _freeze_value_suspect,
    _remove_last_value_suspect,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _DraftComponent,
    _ParseState,
    _SUSPECT_KEY_TYPES,
    _address_metadata,
    _append_deferred,
    _clear_pending_community_poi,
    _clone_draft_component,
    _commit,
    _fixup_suspected_info,
    _flush_chain,
    _mark_consumed_indices,
    _meets_commit_threshold,
    _ordered_component_clue_entries,
    _pending_community_blocks_road,
    _rebuild_component_derived_state,
    _recompute_last_consumed_index,
    _reroute_pending_community_poi_to_subdistrict,
    _rightmost_component_key_overlaps_negative,
    _segment_admit,
)


def _state_routing_context(
    state: _ParseState,
    clues: tuple[Clue, ...],
    raw_text: str,
    stream: StreamInput,
    locale: str,
) -> _RoutingContext:
    """从当前解析状态构造 KEY 路由所需的只读上下文（链、占位、已忽略 KEY 索引等）。"""
    return _RoutingContext(
        chain=[clue for _, clue in state.deferred_chain],
        previous_component_type=state.last_component_type,
        previous_component_end=state.components[-1].end if state.components else None,
        ignored_key_indices=state.ignored_address_key_indices,
        clues=clues,
        raw_text=raw_text,
        stream=stream,
        locale=locale,
    )


@dataclass(slots=True)
class AddressStack(BaseStack):
    """把流上的 ADDRESS clue 收敛为单个地址 `CandidateDraft` 的 stack 实现。"""

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

    def run(self) -> StackRun | None:
        """地址 stack 主入口。"""
        if self.clue.strength == ClaimStrength.HARD:
            return self._run_hard()

        stream = self.context.stream
        locale = self._value_locale()
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}

        if is_label_seed:
            address_start = _label_seed_start_char(stream, self.clue.end)
            start_unit = _unit_index_at_or_after(stream, address_start)
            seed_index = _label_seed_address_index(
                self.context.clues, stream, address_start, start_unit, max_units=6,
            )
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
            scan_index=scan_index,
            address_start=address_start,
            consumed_ids=consumed_ids,
            handled_labels=handled_labels,
            evidence_count=evidence_count,
            locale=locale,
        )

    def _run_hard(self) -> StackRun | None:
        locale = self._value_locale()
        sub_clues = tuple(_sub_tokenize(self.context.stream, self.clue, locale))
        if not sub_clues:
            return None
        return self._run_with_sub_clues(sub_clues, locale)

    def _run_with_clues(
        self,
        clues: tuple[Clue, ...],
        scan_index: int,
        address_start: int,
        consumed_ids: set[str],
        handled_labels: set[str],
        evidence_count: int,
        locale: str,
    ) -> StackRun | None:
        """SOFT 路径：扫描 clue → 可选负向尾修 → suspect 修正 → 数字尾挑战 → 组装 `StackRun`。"""
        state, negative_spans, index = self._scan_components(
            clues=clues,
            scan_index=scan_index,
            address_start=address_start,
            evidence_count=evidence_count,
            locale=locale,
        )
        if not state.components:
            return None
        if negative_spans:
            self._repair_negative_tail_components(state, negative_spans, clues, locale)
            if not state.components:
                return None
        consumed_ids |= state.extra_consumed_clue_ids
        consumed_ids |= state.committed_clue_ids
        _fixup_suspected_info(state)

        tail = _analyze_digit_tail(state.components, self.context.stream, clues, index)
        if tail is not None and not tail.followed_by_address_key:
            conservative_run = self._build_address_run_from_state(
                state, consumed_ids, handled_labels, locale, index,
            )
            if conservative_run is None:
                return None
            state_ext = _ParseState()
            state_ext.components = list(state.components) + tail.new_components
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

    def _run_with_sub_clues(self, sub_clues: tuple[Clue, ...], locale: str) -> StackRun | None:
        state, negative_spans, _ = self._scan_components(
            clues=sub_clues,
            scan_index=0,
            address_start=sub_clues[0].start,
            evidence_count=0,
            locale=locale,
            stop_char_end=self.clue.end,
            absorb_non_address=False,
        )
        if not state.components:
            return None
        if negative_spans:
            self._repair_negative_tail_components(state, negative_spans, sub_clues, locale)
            if not state.components:
                return None
        _fixup_suspected_info(state)
        return self._build_address_run_from_state(
            state,
            set(state.committed_clue_ids),
            set(),
            locale,
            self.clue_index + 1,
            use_precise_next_index=False,
        )

    def _scan_components(
        self,
        *,
        clues: tuple[Clue, ...],
        scan_index: int,
        address_start: int,
        evidence_count: int,
        locale: str,
        stop_char_end: int | None = None,
        absorb_non_address: bool = True,
    ) -> tuple[_ParseState, list[tuple[int, int]], int]:
        """从 `scan_index` 起线性扫描 `clues`，维护 `_ParseState` 并记录负向 span。

        循环外会再 `_flush_chain` 一次，避免链尾未提交。
        """
        raw_text = self.context.stream.text
        stream = self.context.stream
        state = _ParseState()
        state.last_end = address_start
        state.evidence_count = evidence_count
        negative_spans: list[tuple[int, int]] = []
        index = scan_index

        while index < len(clues):
            clue = clues[index]
            if stop_char_end is not None and clue.start >= stop_char_end:
                break

            search_anchor = _state_next_component_start(state, stream, address_start=address_start)
            if search_anchor is not None and clue.start > search_anchor:
                if _span_has_search_stop_unit(stream, search_anchor, clue.start):
                    if state.deferred_chain:
                        self._flush_chain(state, clue_index=index)
                        if state.split_at is not None:
                            break
                        continue
                    if _span_has_non_comma_search_stop_unit(stream, search_anchor, clue.start):
                        break

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
                if absorb_non_address and self._consume_non_address_clue(state, clue, clues, index, stream):
                    index += 1
                    continue
                index += 1
                continue
            if clue.role == ClueRole.LABEL or clue.start < address_start:
                index += 1
                continue
            if state.last_consumed is not None:
                gap_anchor = max(state.last_consumed.unit_end, state.absorbed_digit_unit_end)
                if clue.unit_start - gap_anchor > 6:
                    break

            result = self._handle_address_clue(state, clue, clues, index, locale)
            if result is _SENTINEL_STOP:
                break
            if result is _SENTINEL_IGNORE:
                index += 1
                continue
            state.last_consumed = clue
            index += 1

        self._flush_chain(state, clue_index=index)
        return state, negative_spans, index

    def _consume_non_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        index: int,
        stream: StreamInput,
    ) -> bool:
        if _is_absorbable_digit_clue(clue):
            state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_end)
            state.extra_consumed_clue_ids.add(clue.clue_id)
            _mark_consumed_indices(state, {index})
            return True
        if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
            nxt_addr = _next_address_clue_index_after(clues, index)
            if nxt_addr is not None and _bridge_last_address_to_next_within_units(state, clues[nxt_addr], stream):
                state.suppress_challenger_clue_ids.add(clue.clue_id)
                state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_end)
        return False

    def _handle_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        locale: str,
    ) -> object | None:
        """单条地址 clue 的分派：逗号门控 → VALUE 链累积 / KEY 提交或忽略。

        返回值：None 表示已消费；`_SENTINEL_STOP` 停止扫描；`_SENTINEL_IGNORE` 跳过本 clue。
        """
        raw_text = self.context.stream.text
        stream = self.context.stream
        effective_clue = self._prepare_effective_clue(state, clue, clues, clue_index, raw_text, stream, locale)
        if effective_clue is _SENTINEL_IGNORE:
            return _SENTINEL_IGNORE
        comp_type = effective_clue.component_type
        if comp_type is None:
            return None
        if comp_type == AddressComponentType.NUMBER and state.last_component_type in _DETAIL_COMPONENTS:
            comp_type = AddressComponentType.DETAIL

        comma_gate = _comma_tail_prehandle(
            state,
            raw_text,
            stream,
            locale,
            clues,
            clue_index,
            effective_clue,
            flush_chain=lambda idx: self._flush_chain(state, clue_index=idx),
            materialize_digit_tail_before_comma=lambda idx: self._materialize_digit_tail_before_comma(state, clues, idx),
        )
        if comma_gate is _SENTINEL_STOP:
            return _SENTINEL_STOP

        if effective_clue.role == ClueRole.VALUE:
            return self._handle_value_clue(state, effective_clue, clues, clue_index, locale, comp_type)
        if effective_clue.role == ClueRole.KEY:
            return self._handle_key_clue(state, effective_clue, clues, clue_index, locale, comp_type)
        return None

    def _prepare_effective_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        raw_text: str,
        stream: StreamInput,
        locale: str,
    ) -> Clue | object:
        if clue.role != ClueRole.KEY:
            return clue
        routed_key = _routed_key_clue(_state_routing_context(state, clues, raw_text, stream, locale), clue_index, clue)
        if routed_key is None:
            state.ignored_address_key_indices.add(clue_index)
            return _SENTINEL_IGNORE
        return routed_key

    def _handle_value_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        locale: str,
        comp_type: AddressComponentType,
    ) -> object | None:
        raw_text = self.context.stream.text
        stream = self.context.stream
        if state.pending_comma_value_right_scan:
            state.pending_comma_value_right_scan = False
            upper_bound = _comma_value_scan_upper_bound(clues, clue_index, clue, stream, len(raw_text))
            value_end = _scan_forward_value_end(raw_text, clue.end, upper_bound, stream=stream)
            if value_end > clue.end:
                merged = raw_text[clue.start:value_end]
                if _normalize_address_value(comp_type, merged):
                    state.value_char_end_override[clue.clue_id] = value_end

        if (
            state.segment_state.comma_tail_active
            and not state.pending_comma_first_component
            and state.deferred_chain
            and state.deferred_chain[-1][1].role == ClueRole.VALUE
        ):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if state.components or state.deferred_chain:
            if (
                not state.pending_comma_first_component
                and not state.segment_state.comma_tail_active
                and not _segment_admit(state, comp_type)
            ):
                if comp_type in _ADMIN_TYPES and _has_reasonable_successor_key(
                    state, clues, clue_index, comp_type, stream, raw_text, locale,
                ):
                    self._flush_chain(state, clue_index=clue_index)
                    if state.split_at is not None:
                        return _SENTINEL_STOP
                    _append_deferred(state, clue_index, clue, record_suspect=False)
                    state.last_value = clue
                    state.last_end = max(state.last_end, clue.end)
                    return None
                self._flush_chain(state, clue_index=clue_index)
                state.split_at = clue.start
                return _SENTINEL_STOP

        anchor_start: int | None = None
        if (
            not state.deferred_chain
            and comp_type in _ADMIN_TYPES
            and (state.components or state.last_piece_end is not None)
            and not _suspect_eligible_after_last_piece(state, clue, stream)
        ):
            anchor_base = state.last_piece_end if state.last_piece_end is not None else state.last_end
            anchor_start = _start_after_component_end(stream, anchor_base)
        _append_deferred(state, clue_index, clue, record_suspect=False, anchor_start=anchor_start)
        if comp_type in _ADMIN_TYPES:
            _freeze_value_suspect(state, clue, stream)
        state.last_value = clue
        state.last_end = max(state.last_end, clue.end)
        return None

    def _handle_key_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        locale: str,
        comp_type: AddressComponentType,
    ) -> object | None:
        raw_text = self.context.stream.text
        stream = self.context.stream
        state.pending_comma_value_right_scan = False
        chain = [item for _, item in state.deferred_chain]
        if chain and _chain_can_accept(chain, clue, stream):
            last_chain_clue = chain[-1]
            if last_chain_clue.role == ClueRole.KEY and last_chain_clue.component_type in _SUSPECT_KEY_TYPES:
                _freeze_key_suspect_from_previous_key(state, raw_text, stream, last_chain_clue)
            _remove_last_value_suspect(state, clue, stream)
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        if state.deferred_chain:
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if comp_type == AddressComponentType.ROAD and state.pending_community_poi_index is not None:
            if _pending_community_blocks_road(state):
                _clear_pending_community_poi(state)
                state.split_at = clue.start
                return _SENTINEL_STOP
            _reroute_pending_community_poi_to_subdistrict(state)

        context = _state_routing_context(state, clues, raw_text, stream, locale)
        expand_defer = _key_left_expand_start_if_deferrable(context, clue_index, clue, comp_type)
        if expand_defer is not None:
            state.chain_left_anchor = expand_defer
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        if clue.text.lower() in _PREFIX_EN_KEYWORDS:
            component = self._build_key_component(raw_text, clue, comp_type, clue_index, locale, component_start=state.last_end)
            if component is not None and not _commit(state, component):
                return _SENTINEL_STOP
            state.last_end = max(state.last_end, clue.end)
            return None

        state.ignored_address_key_indices.add(clue_index)
        return _SENTINEL_IGNORE

    def _repair_negative_tail_components(
        self,
        state: _ParseState,
        negative_spans: list[tuple[int, int]],
        clues: tuple[Clue, ...],
        locale: str,
    ) -> None:
        if not negative_spans or not state.components:
            return
        base_evidence_count = max(0, state.evidence_count - len(state.components))
        state.components = self._repair_components_overlapping_negative(
            state.components, negative_spans, clues, locale, state.ignored_address_key_indices,
        )
        _rebuild_component_derived_state(state, clues, base_evidence_count=base_evidence_count)

    def _repair_components_overlapping_negative(
        self,
        components: list[_DraftComponent],
        negative_spans: list[tuple[int, int]],
        clues: tuple[Clue, ...],
        locale: str,
        ignored_address_key_indices: set[int],
    ) -> list[_DraftComponent]:
        ordered = sorted(
            (_clone_draft_component(component) for component in components),
            key=lambda component: (component.end, component.start),
        )
        while ordered:
            last = ordered[-1]
            if not _rightmost_component_key_overlaps_negative(last, clues, negative_spans):
                return ordered
            repaired = self._repair_rightmost_component_prefix(
                prefix_components=ordered[:-1],
                component=last,
                negative_spans=negative_spans,
                clues=clues,
                locale=locale,
                ignored_address_key_indices=ignored_address_key_indices,
            )
            if repaired is not None:
                ordered = repaired
                continue
            ordered.pop()
        return []

    def _repair_rightmost_component_prefix(
        self,
        *,
        prefix_components: list[_DraftComponent],
        component: _DraftComponent,
        negative_spans: list[tuple[int, int]],
        clues: tuple[Clue, ...],
        locale: str,
        ignored_address_key_indices: set[int],
    ) -> list[_DraftComponent] | None:
        clue_entries = _ordered_component_clue_entries(component, clues)
        if not clue_entries:
            return None
        last_affected_index = -1
        for index, (_, clue) in enumerate(clue_entries):
            if any(not (clue.end <= s or clue.start >= e) for s, e in negative_spans):
                last_affected_index = index
        if last_affected_index <= 0:
            return None
        for cut in range(last_affected_index, 0, -1):
            replay_state = self._replay_component_clue_prefix(
                prefix_components=prefix_components,
                clue_entries=clue_entries[:cut],
                clues=clues,
                locale=locale,
                ignored_address_key_indices=ignored_address_key_indices,
            )
            if replay_state is None or not replay_state.components:
                continue
            if _rightmost_component_key_overlaps_negative(replay_state.components[-1], clues, negative_spans):
                continue
            return replay_state.components
        return None

    def _replay_component_clue_prefix(
        self,
        *,
        prefix_components: list[_DraftComponent],
        clue_entries: list[tuple[int, Clue]],
        clues: tuple[Clue, ...],
        locale: str,
        ignored_address_key_indices: set[int],
    ) -> _ParseState | None:
        if not clue_entries:
            return None
        replay_state = _ParseState()
        replay_state.components = [_clone_draft_component(component) for component in prefix_components]
        replay_state.ignored_address_key_indices = set(ignored_address_key_indices)
        _rebuild_component_derived_state(replay_state, clues)
        for clue_index, clue in clue_entries:
            result = self._handle_address_clue(replay_state, clue, clues, clue_index, locale)
            if result is _SENTINEL_STOP:
                return None
            if result is _SENTINEL_IGNORE:
                continue
            replay_state.last_consumed = clue
        self._flush_chain(replay_state, clue_index=clue_entries[-1][0] + 1)
        if replay_state.split_at is not None:
            return None
        return replay_state

    def _flush_chain(self, state: _ParseState, *, clue_index: int) -> None:
        _flush_chain(state, self.context.stream.text, normalize_value=_normalize_address_value)

    def _materialize_digit_tail_before_comma(
        self,
        state: _ParseState,
        clues: tuple[Clue, ...],
        clue_index: int,
    ) -> None:
        _materialize_digit_tail_before_comma(
            state,
            self.context.stream,
            clues,
            clue_index,
            commit=lambda component: _commit(state, component),
        )

    def _build_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        locale: str,
        *,
        component_start: int,
    ) -> _DraftComponent | None:
        del locale
        key_text = clue.text
        if key_text.lower() in _PREFIX_EN_KEYWORDS:
            value_start = _skip_separators(raw_text, clue.end)
            value_end = _scan_forward_value_end(
                raw_text,
                value_start,
                upper_bound=min(len(raw_text), clue.end + 30),
                stream=self.context.stream,
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
        value = _normalize_address_value(comp_type, raw_text[component_start:clue.start])
        if not value:
            return None
        return _DraftComponent(
            component_type=comp_type,
            start=component_start,
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
        """证据阈值通过后，用 component 并集 span 构造 `CandidateDraft` 与 `StackRun`。"""
        components = state.components
        if not _meets_commit_threshold(
            state.evidence_count,
            components,
            locale,
            protection_level=self.context.protection_level,
        ):
            return None
        raw_text = self.context.stream.text
        final_start = min(component.start for component in components)
        final_end = max(component.end for component in components)
        text = clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, absolute_start, absolute_start + len(text))
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
        final_next_index = state.last_consumed_clue_index + 1 if use_precise_next_index and state.last_consumed_clue_index >= 0 else next_index
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            consumed_ids=set(consumed_ids),
            handled_label_clue_ids=set(handled_labels),
            next_index=final_next_index,
            suppress_challenger_clue_ids=frozenset(state.suppress_challenger_clue_ids),
        )
