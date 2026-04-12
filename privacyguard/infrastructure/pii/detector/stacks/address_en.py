"""英文地址 stack。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    Clue,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_base import BaseAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _SENTINEL_IGNORE,
    _SENTINEL_STOP,
    _chain_can_accept,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_en import (
    EN_VALID_SUCCESSORS,
    is_prefix_en_key,
    key_left_expand_start_if_deferrable_en,
    sub_tokenize_en,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ParseState,
    _append_deferred,
    _segment_admit,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_char_end


def _state_routing_context(
    state: _ParseState,
    clues: tuple[Clue, ...],
    raw_text: str,
    stream: StreamInput,
) -> _RoutingContext:
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
class EnAddressStack(BaseAddressStack):
    """英文地址专用 stack。"""

    @property
    def valid_successors(self):
        return EN_VALID_SUCCESSORS

    def _run_hard(self):
        sub_clues = tuple(self._sub_tokenize_hard(self.context.stream, self.clue))
        if not sub_clues:
            return None
        return self._run_with_sub_clues(sub_clues, relaxed=True)

    def _handle_value_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        del clues
        stream = self.context.stream
        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if (state.components or state.deferred_chain) and not _segment_admit(
            state,
            comp_type,
            valid_successors=self.valid_successors,
        ):
            if state.deferred_chain:
                self._flush_chain(state, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP
            if state.components and not _segment_admit(
                state,
                comp_type,
                valid_successors=self.valid_successors,
            ):
                state.split_at = clue.start
                return _SENTINEL_STOP

        _append_deferred(state, clue_index, clue, record_suspect=False)
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
        chain = [item for _, item in state.deferred_chain]
        if chain and _chain_can_accept(chain, clue, stream):
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        if state.deferred_chain:
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if is_prefix_en_key(clue.text):
            component = self._build_prefix_key_component(raw_text, clue, comp_type, clue_index)
            if component is None:
                state.ignored_address_key_indices.add(clue_index)
                return _SENTINEL_IGNORE
            if not self._commit_component(state, component):
                return _SENTINEL_STOP
            state.last_end = max(state.last_end, component.end)
            return None

        context = _state_routing_context(state, clues, raw_text, stream)
        expand_defer = key_left_expand_start_if_deferrable_en(context, clue, comp_type)
        if expand_defer is not None:
            state.chain_left_anchor = expand_defer
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        state.ignored_address_key_indices.add(clue_index)
        return _SENTINEL_IGNORE

    def _sub_tokenize_hard(self, stream: StreamInput, hard_clue: Clue) -> list[Clue]:
        return sub_tokenize_en(stream, hard_clue)

    def _candidate_start_end(self, state: _ParseState) -> tuple[int, int]:
        final_start, final_end = BaseAddressStack._candidate_start_end(self, state)
        if state.absorbed_digit_unit_end > 0:
            final_end = max(final_end, _unit_char_end(self.context.stream, state.absorbed_digit_unit_end))
        return final_start, final_end
