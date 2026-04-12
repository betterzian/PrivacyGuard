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
    _normalize_address_value,
    _scan_forward_value_end,
    _start_after_component_end,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_zh import (
    _comma_tail_prehandle,
    _comma_value_scan_upper_bound,
    _resolve_standalone_admin_value_group,
    collect_admin_value_span,
    _freeze_key_suspect_from_previous_key,
    _freeze_value_suspect,
    _has_reasonable_successor_key,
    _key_left_expand_start_if_deferrable,
    _remove_last_value_suspect,
    _routed_key_clue,
    _sub_tokenize,
    _suspect_eligible_after_last_piece,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_TYPES,
    _ParseState,
    _SUSPECT_KEY_TYPES,
    _VALID_SUCCESSORS,
    _append_deferred,
    _clear_pending_community_poi,
    _flush_chain,
    _pending_community_blocks_road,
    _reroute_pending_community_poi_to_subdistrict,
    _segment_admit,
)


def _state_routing_context(
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
            _state_routing_context(state, clues, raw_text, stream),
            clue_index,
            clue,
        )
        if routed_key is None:
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
        trailing_deferred = state.deferred_chain[-1][1] if state.deferred_chain else None
        same_trailing_admin_span = (
            admin_span is not None
            and trailing_deferred is not None
            and trailing_deferred.role == ClueRole.VALUE
            and trailing_deferred.attr_type == clue.attr_type
            and trailing_deferred.component_type in _ADMIN_TYPES
            and trailing_deferred.start == admin_span.start
            and trailing_deferred.end == admin_span.end
        )

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
            and not same_trailing_admin_span
        ):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if state.components or state.deferred_chain:
            admin_levels = admin_span.levels if admin_span is not None else (comp_type,)
            admitted_level = comp_type
            if admin_span is not None:
                resolved_group = _resolve_standalone_admin_value_group(
                    state,
                    tuple((index, clues[index]) for index in range(admin_span.first_index, admin_span.last_index + 1)),
                )
                if resolved_group is not None:
                    admitted_level = resolved_group[0]
            if (
                not state.pending_comma_first_component
                and not state.segment_state.comma_tail_active
                and not _segment_admit(state, admitted_level, valid_successors=self.valid_successors)
            ):
                if comp_type in _ADMIN_TYPES and _has_reasonable_successor_key(
                    state,
                    clues,
                    clue_index,
                    admin_levels,
                    stream,
                    raw_text,
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

        context = _state_routing_context(state, clues, raw_text, stream)
        expand_defer = _key_left_expand_start_if_deferrable(context, clue_index, clue, comp_type)
        if expand_defer is not None:
            state.chain_left_anchor = expand_defer
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        state.ignored_address_key_indices.add(clue_index)
        return _SENTINEL_IGNORE

    def _sub_tokenize_hard(self, stream: StreamInput, hard_clue: Clue) -> list[Clue]:
        return _sub_tokenize(stream, hard_clue)
