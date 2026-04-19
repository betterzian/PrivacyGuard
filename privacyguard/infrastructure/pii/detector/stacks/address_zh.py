"""中文地址 stack。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    Clue,
    ClueRole,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_base import BaseAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _SENTINEL_IGNORE,
    _SENTINEL_STOP,
    _chain_can_accept,
    _clue_unit_gap,
    _normalize_address_value,
    _scan_forward_value_end,
    _start_after_component_end,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_zh import (
    _comma_tail_prehandle,
    _comma_value_scan_upper_bound,
    _has_valid_left_numeral_for_numberish_key,
    _is_left_numeral_bound_numberish_key,
    _resolve_admin_key_chain_levels,
    _resolve_standalone_admin_value_group,
    collect_admin_value_span,
    _freeze_key_suspect_from_previous_key,
    _freeze_value_suspect,
    _freeze_value_suspect_for_mismatched_admin_key,
    _has_reasonable_successor_key,
    _key_has_admin_levels,
    _key_left_expand_start_if_deferrable,
    _remove_last_value_suspect,
    _routed_key_clue,
    _suspect_eligible_after_last_piece,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_TYPES,
    _ParseState,
    _VALID_SUCCESSORS,
    _append_deferred,
    _clear_pending_community_poi,
    _flush_chain,
    _pending_community_blocks_road,
    _reroute_pending_community_poi_to_subdistrict,
    _resolve_multi_admin_collision,
    _segment_admit,
)


def _state_routing_context(
    stack: BaseAddressStack,
    state: _ParseState,
    clues: tuple[Clue, ...],
    raw_text: str,
    stream: StreamInput,
) -> _RoutingContext:
    """从当前解析状态构造中文 KEY 路由所需的只读上下文。"""
    return _RoutingContext(
        chain=[clue for _, clue in state.deferred_chain],
        previous_component_type=state.last_component_type,
        previous_component_end=state.components[-1].end if state.components else None,
        ignored_key_indices=state.ignored_address_key_indices,
        clues=clues,
        raw_text=raw_text,
        stream=stream,
        seed_floor=state.seed_floor,
        # 仅在已有已提交组件时才提供 search_start，避免未提交失败链污染 numberish 左扩起点。
        search_start=state.last_end if state.components else None,
        should_break_clue=lambda clue: stack.need_break(clue),
    )


@dataclass(slots=True)
class ZhAddressStack(BaseAddressStack):
    """中文地址专用 stack。"""

    @property
    def valid_successors(self):
        return _VALID_SUCCESSORS

    def _flush_chain(self, state: _ParseState, *, clue_index: int) -> None:
        _flush_chain(
            state,
            self.context.stream.text,
            normalize_value=_normalize_address_value,
            commit_component=lambda component: self._commit_component(state, component),
            resolve_standalone_admin_group=_resolve_standalone_admin_value_group,
            resolve_admin_key_chain_levels=_resolve_admin_key_chain_levels,
            validate_key_component=self._validate_key_component_before_commit,
        )

    def _validate_key_component_before_commit(
        self,
        state: _ParseState,
        used_entries: tuple[tuple[int, Clue], ...],
        key_clue: Clue,
        component_start: int,
        comp_type: AddressComponentType,
    ) -> bool:
        del state, used_entries
        return _has_valid_left_numeral_for_numberish_key(
            self.context.stream,
            key_clue,
            component_start=component_start,
            comp_type=comp_type,
        )

    def _prepare_effective_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        raw_text: str,
        stream: StreamInput,
    ) -> Clue | object:
        if clue.role != ClueRole.KEY:
            return clue
        routed_key = _routed_key_clue(
            _state_routing_context(self, state, clues, raw_text, stream),
            clue_index,
            clue,
        )
        if routed_key is None:
            _freeze_value_suspect_for_mismatched_admin_key(
                state,
                clue,
                stream=stream,
            )
            state.ignored_address_key_indices.add(clue_index)
            return _SENTINEL_IGNORE
        return routed_key

    def _prehandle_clue(
        self,
        state: _ParseState,
        raw_text: str,
        stream: StreamInput,
        clues: tuple[Clue, ...],
        clue_index: int,
        clue: Clue,
    ) -> object | None:
        return _comma_tail_prehandle(
            state,
            raw_text,
            stream,
            clues,
            clue_index,
            clue,
            flush_chain=lambda idx: self._flush_chain(state, clue_index=idx),
            materialize_digit_tail_before_comma=lambda idx: self._materialize_digit_tail_before_comma(state, clues, idx),
            should_break=self.need_break,
        )

    def _handle_value_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        raw_text = self.context.stream.text
        stream = self.context.stream
        admin_span = collect_admin_value_span(clues, clue_index) if comp_type in _ADMIN_TYPES else None

        if state.pending_comma_value_right_scan:
            state.pending_comma_value_right_scan = False
            upper_bound = _comma_value_scan_upper_bound(
                clues,
                clue_index,
                clue,
                stream,
                len(raw_text),
                should_break=self.need_break,
            )
            value_end = _scan_forward_value_end(raw_text, clue.end, upper_bound, stream=stream)
            if value_end > clue.end:
                merged = raw_text[clue.start:value_end]
                if _normalize_address_value(comp_type, merged):
                    state.value_char_end_override[clue.clue_id] = value_end

        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if state.components or state.deferred_chain:
            admin_levels = admin_span.levels if admin_span is not None else (comp_type,)
            # MULTI_ADMIN 探针：resolve 返回的每一层都要做 _segment_admit 探测，
            # 任一层可接纳即视为可挂；全部失败才走 split/寻后继的降级路径。
            probe_levels: tuple[AddressComponentType, ...] = (comp_type,)
            resolved_group = None
            if admin_span is not None:
                resolved_group = _resolve_standalone_admin_value_group(
                    state,
                    tuple((index, clues[index]) for index in range(admin_span.first_index, admin_span.last_index + 1)),
                )
                if resolved_group is not None and resolved_group.available_levels:
                    probe_levels = resolved_group.available_levels
            probe_failed = (
                not state.pending_comma_first_component
                and not state.segment_state.comma_tail_active
                and not any(
                    _segment_admit(state, lvl, valid_successors=self.valid_successors)
                    for lvl in probe_levels
                )
            )
            # §5.2.1 collision 触发点：admin_span 存在、无 deferred_chain、probe 全失败时，
            # 尝试同值 MULTI_ADMIN 原地降解以让 incoming 取互补层继续 admit。降解后占位被释放，
            # 再重跑一次探针；若任一层能 admit 则跳过 split。
            if (
                probe_failed
                and admin_span is not None
                and resolved_group is not None
                and not state.deferred_chain
            ):
                forced = _resolve_multi_admin_collision(
                    state,
                    raw_text,
                    clue.start,
                    resolved_group.text,
                    resolved_group.all_levels,
                )
                if forced is not None:
                    probe_levels = forced
                    probe_failed = not any(
                        _segment_admit(state, lvl, valid_successors=self.valid_successors)
                        for lvl in probe_levels
                    )
            if probe_failed:
                if comp_type in _ADMIN_TYPES and _has_reasonable_successor_key(
                    state,
                    clues,
                    clue_index,
                    admin_levels,
                    stream,
                    raw_text,
                    should_break=self.need_break,
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
            _freeze_value_suspect(state, clues, clue_index, stream)
        state.last_value = clue
        state.last_end = max(state.last_end, clue.end)
        return None

    def _handle_key_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        raw_text = self.context.stream.text
        stream = self.context.stream
        state.pending_comma_value_right_scan = False
        chain = [item for _, item in state.deferred_chain]
        allow_chain_append = (
            bool(chain)
            and _chain_can_accept(chain, clue, stream)
            and not _is_left_numeral_bound_numberish_key(clue, comp_type=comp_type)
        )
        # 需要左侧编号前缀的中文 numberish key 不能继续吸收前链，必须先冲洗再单独验左值。
        if allow_chain_append:
            last_chain_clue = chain[-1]
            should_freeze_previous_key = (
                last_chain_clue.role == ClueRole.KEY
                and _key_has_admin_levels(last_chain_clue)
                and (
                    _key_has_admin_levels(clue)
                    or _clue_unit_gap(last_chain_clue, clue, stream) > 0
                )
            )
            if should_freeze_previous_key:
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

        context = _state_routing_context(self, state, clues, raw_text, stream)
        expand_defer = _key_left_expand_start_if_deferrable(context, clue_index, clue, comp_type)
        if expand_defer is not None:
            state.chain_left_anchor = expand_defer
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        state.ignored_address_key_indices.add(clue_index)
        return _SENTINEL_IGNORE

