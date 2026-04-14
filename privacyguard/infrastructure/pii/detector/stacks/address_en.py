"""英文地址 stack。"""

from __future__ import annotations

from dataclasses import dataclass
import re

from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    ClueFamily,
    Clue,
    ClueRole,
    PIIAttributeType,
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
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_en import (
    EN_VALID_SUCCESSORS,
    en_key_chain_allowed,
    is_prefix_en_key,
    is_suffix_en_component,
    is_prefix_en_component,
    key_left_expand_start_if_deferrable_en,
    sub_tokenize_en,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _DraftComponent,
    _ParseState,
    _append_deferred,
    _clone_draft_component,
    _segment_admit,
)
from privacyguard.infrastructure.pii.detector.stacks.base import PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import _skip_separators


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

    _disable_house_number_promotion: bool = False
    _FALLBACK_HOUSE_NUMBER_RE = re.compile(r"\d{1,6}[A-Za-z]?$")

    @property
    def valid_successors(self):
        return EN_VALID_SUCCESSORS

    def run(self) -> StackRun | None:
        if (
            self.clue.strength != ClaimStrength.HARD
            and self.clue.role == ClueRole.VALUE
            and self.clue.attr_type == PIIAttributeType.ADDRESS
        ):
            value_seed_run = self._build_suffix_road_from_value_seed()
            if value_seed_run is not None:
                return value_seed_run
        return super(EnAddressStack, self).run()

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
        if chain:
            last_chain_clue = chain[-1]
            if last_chain_clue.role == ClueRole.KEY:
                if (
                    en_key_chain_allowed(last_chain_clue.component_type, clue.component_type)
                    and _chain_can_accept(chain, clue, stream)
                ):
                    _append_deferred(state, clue_index, clue, record_suspect=False)
                    state.last_end = max(state.last_end, clue.end)
                    return None
            elif _chain_can_accept(chain, clue, stream):
                if state.chain_left_anchor is None and is_suffix_en_component(clue.component_type):
                    first_value = next(
                        (entry_clue for _, entry_clue in state.deferred_chain if entry_clue.role == ClueRole.VALUE),
                        None,
                    )
                    if first_value is not None:
                        state.chain_left_anchor = first_value.start
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
        return BaseAddressStack._candidate_start_end(self, state)

    def _build_address_run_from_state(
        self,
        state: _ParseState,
        consumed_ids: set[str],
        handled_labels: set[str],
        next_index: int,
        *,
        use_precise_next_index: bool = True,
    ) -> StackRun | None:
        if self._disable_house_number_promotion:
            return super(EnAddressStack, self)._build_address_run_from_state(
                state,
                consumed_ids,
                handled_labels,
                next_index,
                use_precise_next_index=use_precise_next_index,
            )

        promotion = self._plan_house_number_promotion(state)
        if promotion is None:
            return super(EnAddressStack, self)._build_address_run_from_state(
                state,
                consumed_ids,
                handled_labels,
                next_index,
                use_precise_next_index=use_precise_next_index,
            )

        conservative_state = self._clone_state_with_components(
            state,
            promotion["conservative_components"],
            evidence_count=state.evidence_count,
        )
        extended_state = self._clone_state_with_components(
            state,
            promotion["extended_components"],
            evidence_count=state.evidence_count + 1,
        )
        extended_consumed_ids = set(consumed_ids)
        challenge_clue_id = promotion["challenge_clue_id"]
        if challenge_clue_id:
            extended_consumed_ids.add(challenge_clue_id)

        self._disable_house_number_promotion = True
        try:
            conservative_run = super(EnAddressStack, self)._build_address_run_from_state(
                conservative_state,
                consumed_ids,
                handled_labels,
                next_index,
                use_precise_next_index=use_precise_next_index,
            )
            extended_run = super(EnAddressStack, self)._build_address_run_from_state(
                extended_state,
                extended_consumed_ids,
                handled_labels,
                next_index,
                use_precise_next_index=use_precise_next_index,
            )
        finally:
            self._disable_house_number_promotion = False

        if extended_run is None:
            return conservative_run
        if conservative_run is None or promotion["challenge_clue_index"] is None:
            return extended_run

        conservative_run.pending_challenge = PendingChallenge(
            clue_index=promotion["challenge_clue_index"],
            challenge_kind="house_number",
            cached_fragment_text=promotion["house_number_text"],
            cached_normalized_fragment=promotion["house_number_value"],
            extended_candidate=extended_run.candidate,
            extended_consumed_ids=extended_run.consumed_ids,
            extended_next_index=extended_run.next_index,
        )
        return conservative_run

    def _clone_state_with_components(
        self,
        state: _ParseState,
        components: list[_DraftComponent],
        *,
        evidence_count: int,
    ) -> _ParseState:
        cloned = _ParseState()
        cloned.components = components
        cloned.evidence_count = evidence_count
        cloned.last_consumed_clue_index = state.last_consumed_clue_index
        cloned.suppress_challenger_clue_ids = set(state.suppress_challenger_clue_ids)
        return cloned

    def _plan_house_number_promotion(self, state: _ParseState) -> dict[str, object] | None:
        raw_text = self.context.stream.text
        for index, component in enumerate(state.components):
            if component.component_type != AddressComponentType.ROAD:
                continue
            road_key_clue = self._find_component_key_clue(component)
            if road_key_clue is not None:
                road_key_start = road_key_clue.start
            else:
                key_text = str(component.key or "")
                road_key_start = component.end - len(key_text) if key_text else -1
            if road_key_start <= component.start:
                continue
            challenge_info = self._find_leading_house_number_challenge(component, road_key_start)
            challenge_clue_index: int | None = None
            challenge_clue_id: str | None = None
            house_number_start: int
            house_number_end: int
            if challenge_info is None:
                fallback_span = self._fallback_house_number_span(component, road_key_start)
                if fallback_span is None:
                    continue
                house_number_start, house_number_end = fallback_span
            else:
                challenge_clue_index, challenge_clue = challenge_info
                challenge_clue_id = challenge_clue.clue_id
                house_number_start, house_number_end = challenge_clue.start, challenge_clue.end
            road_start = _skip_separators(raw_text, house_number_end)
            if road_start >= road_key_start:
                continue
            road_value = _normalize_address_value(
                AddressComponentType.ROAD,
                raw_text[road_start:road_key_start],
            )
            house_number_text = raw_text[house_number_start:house_number_end]
            house_number_value = _normalize_address_value(AddressComponentType.HOUSE_NUMBER, house_number_text)
            if not road_value or not house_number_value:
                continue

            conservative_road = _clone_draft_component(component)
            conservative_road.start = road_start
            conservative_road.value = road_value

            house_number_component = _DraftComponent(
                component_type=AddressComponentType.HOUSE_NUMBER,
                start=house_number_start,
                end=house_number_end,
                value=house_number_value,
                key="",
                is_detail=False,
                raw_chain=[],
                suspected=[],
                clue_ids={challenge_clue_id} if challenge_clue_id else set(),
                clue_indices={challenge_clue_index} if challenge_clue_index is not None else set(),
            )

            conservative_components = [
                _clone_draft_component(item) if item is not component else conservative_road
                for item in state.components
            ]
            extended_components: list[_DraftComponent] = []
            for item in state.components:
                if item is component:
                    extended_components.append(house_number_component)
                    extended_components.append(_clone_draft_component(conservative_road))
                    continue
                extended_components.append(_clone_draft_component(item))
            extended_components.sort(key=lambda item: (item.start, item.end))
            return {
                "challenge_clue_index": challenge_clue_index,
                "challenge_clue_id": challenge_clue_id,
                "house_number_text": house_number_text,
                "house_number_value": house_number_value,
                "conservative_components": conservative_components,
                "extended_components": extended_components,
            }
        return None

    def _build_suffix_road_from_value_seed(self) -> StackRun | None:
        if self.clue.component_type not in {
            AddressComponentType.PROVINCE,
            AddressComponentType.CITY,
            AddressComponentType.DISTRICT,
            AddressComponentType.SUBDISTRICT,
        }:
            return None
        raw_text = self.context.stream.text
        road_key_index, road_key = self._find_suffix_road_key_after_value_seed()
        if road_key is None:
            return None

        road_start = self.clue.start
        house_number_clue_index: int | None = None
        house_number_clue_id: str | None = None
        if self.clue_index > 0:
            previous = self.context.clues[self.clue_index - 1]
            if (
                previous.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}
                and previous.end <= self.clue.start
                and _clue_unit_gap(previous, self.clue, self.context.stream) <= 2
            ):
                road_start = previous.start
                house_number_clue_index = self.clue_index - 1
                house_number_clue_id = previous.clue_id

        road_value = _normalize_address_value(AddressComponentType.ROAD, raw_text[road_start:road_key.start])
        if not road_value:
            return None
        state = _ParseState()
        state.components = [
            _DraftComponent(
                component_type=AddressComponentType.ROAD,
                start=road_start,
                end=road_key.end,
                value=road_value,
                key=road_key.text,
                is_detail=False,
                raw_chain=[],
                suspected=[],
                clue_ids={self.clue.clue_id, road_key.clue_id},
                clue_indices={self.clue_index, road_key_index},
            )
        ]
        state.evidence_count = 1
        state.last_consumed_clue_index = road_key_index
        consumed_ids = {self.clue.clue_id, road_key.clue_id}
        return self._build_address_run_from_state(
            state,
            consumed_ids,
            set(),
            road_key_index + 1,
        )

    def _find_component_key_clue(self, component: _DraftComponent) -> Clue | None:
        for clue_index in sorted(component.clue_indices, reverse=True):
            if clue_index < 0 or clue_index >= len(self.context.clues):
                continue
            clue = self.context.clues[clue_index]
            if clue.role != ClueRole.KEY:
                continue
            if clue.attr_type != PIIAttributeType.ADDRESS:
                continue
            if clue.component_type != component.component_type:
                continue
            return clue
        return None

    def _find_suffix_road_key_after_value_seed(self) -> tuple[int, Clue] | tuple[None, None]:
        raw_text = self.context.stream.text
        ci = self.context.clue_index
        addr_starts = ci.family_starts.get(ClueFamily.ADDRESS)
        if addr_starts is None:
            return None, None
        start_unit = self.clue.unit_end
        clues = self.context.clues
        for u in range(start_unit, ci.unit_count):
            for idx in addr_starts[u]:
                if idx <= self.clue_index:
                    continue
                clue = clues[idx]
                if clue.attr_type is None or clue.attr_type != PIIAttributeType.ADDRESS:
                    continue
                if clue.role != ClueRole.KEY or clue.component_type != AddressComponentType.ROAD:
                    continue
                if _clue_unit_gap(self.clue, clue, self.context.stream) > 3:
                    return None, None
                between = raw_text[self.clue.end:clue.start]
                if any(char in ",，\r\n" for char in between):
                    return None, None
                return idx, clue
        return None, None

    def _find_leading_house_number_challenge(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> tuple[int, Clue] | None:
        raw_text = self.context.stream.text
        component_value_start = _skip_separators(raw_text, component.start)
        ci = self.context.clue_index
        stream = self.context.stream
        if not stream.char_to_unit or component_value_start >= len(stream.char_to_unit):
            return None
        target_unit = stream.char_to_unit[component_value_start]
        if target_unit >= ci.unit_count:
            return None
        struct_starts = ci.family_starts.get(ClueFamily.STRUCTURED)
        if struct_starts is None:
            return None
        clues = self.context.clues
        for idx in struct_starts[target_unit]:
            clue = clues[idx]
            if clue.start != component_value_start:
                continue
            if clue.end > road_key_start:
                continue
            if clue.attr_type not in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}:
                continue
            if is_prefix_en_component(component.component_type):
                continue
            return idx, clue
        return None

    def _fallback_house_number_span(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> tuple[int, int] | None:
        raw_text = self.context.stream.text
        start = _skip_separators(raw_text, component.start)
        if start >= road_key_start:
            return None
        cursor = start
        while cursor < road_key_start and raw_text[cursor].isalnum():
            cursor += 1
        token = raw_text[start:cursor]
        if not token or not self._FALLBACK_HOUSE_NUMBER_RE.fullmatch(token):
            return None
        if _skip_separators(raw_text, cursor) >= road_key_start:
            return None
        return start, cursor
