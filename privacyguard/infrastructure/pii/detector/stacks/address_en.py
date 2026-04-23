"""英文地址 stack。"""

from __future__ import annotations

from dataclasses import dataclass
import re

from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClueFamily,
    Clue,
    ClueRole,
    PIIAttributeType,
    StreamInput,
    bucket_family_clues,
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
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_en import (
    EN_VALID_SUCCESSORS,
    en_key_chain_allowed,
    is_prefix_en_key,
    is_suffix_en_component,
    is_prefix_en_component,
    key_left_expand_start_if_deferrable_en,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_zh import (
    _comma_tail_prehandle,
    _comma_value_scan_upper_bound,
    _resolve_admin_key_chain_levels,
    _resolve_standalone_admin_value_group,
    collect_admin_value_span,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_TYPES,
    _DraftComponent,
    _ParseState,
    _append_deferred,
    _clone_draft_component,
    _flush_chain,
    _resolve_multi_admin_collision,
    _segment_admit,
)
from privacyguard.infrastructure.pii.detector.stacks.base import PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import _skip_separators


def _state_routing_context(
    state: _ParseState,
    clues: tuple[Clue, ...],
    raw_text: str,
    stream: StreamInput,
    *,
    value_floor: int,
) -> _RoutingContext:
    return _RoutingContext(
        chain=[clue for _, clue in state.deferred_chain],
        previous_component_type=state.last_component_type,
        previous_component_end=state.components[-1].end if state.components else None,
        ignored_key_indices=state.ignored_address_key_indices,
        clues=clues,
        raw_text=raw_text,
        stream=stream,
        seed_floor=state.seed_floor,
        value_floor=value_floor,
    )


def _clue_admin_levels(clue: Clue) -> tuple[AddressComponentType, ...]:
    """读取 clue 上携带的行政层级，兼容 MULTI_ADMIN derived 视图。"""
    if clue.component_levels:
        return tuple(level for level in clue.component_levels if level in _ADMIN_TYPES)
    if clue.component_type in _ADMIN_TYPES:
        return (clue.component_type,)
    return ()


def _iter_family_clues_from_unit(
    clues: tuple[Clue, ...],
    unit_index,
    family: ClueFamily,
    *,
    start_unit: int,
    min_clue_index: int,
):
    """按 unit 起点顺序枚举 family clue，避免回退到旧 clue-index 导航。"""
    for unit_cursor in range(max(0, start_unit), len(unit_index)):
        for clue_index in bucket_family_clues(unit_index[unit_cursor], family):
            if clue_index < min_clue_index:
                continue
            yield clue_index, clues[clue_index]


@dataclass(slots=True)
class EnAddressStack(BaseAddressStack):
    """英文地址专用 stack。"""

    _disable_house_number_promotion: bool = False
    _FALLBACK_HOUSE_NUMBER_RE = re.compile(r"\d{1,6}[A-Za-z]?$")

    @property
    def valid_successors(self):
        return EN_VALID_SUCCESSORS

    def _flush_chain(self, state: _ParseState, *, clue_index: int) -> None:
        # §6.2：EN 冲洗链接入与 ZH 对等的 admin 解析器，但闭包到 EN_VALID_SUCCESSORS。
        en_valid = self.valid_successors
        _flush_chain(
            state,
            self.context.stream.text,
            normalize_value=_normalize_address_value,
            commit_component=lambda component: self._commit_component(state, component),
            resolve_standalone_admin_group=lambda s, entries: _resolve_standalone_admin_value_group(
                s, entries, valid_successors=en_valid,
            ),
            resolve_admin_key_chain_levels=lambda s, value_entries, key_clue: _resolve_admin_key_chain_levels(
                s, value_entries, key_clue, valid_successors=en_valid,
            ),
        )

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
            should_break=self.should_break_clue,
        )

    def run(self) -> StackRun | None:
        if (
            self.clue.role == ClueRole.VALUE
            and self.clue.attr_type == PIIAttributeType.ADDRESS
            and _clue_admin_levels(self.clue)
        ):
            value_seed_run = self._build_suffix_road_from_value_seed()
            if value_seed_run is not None:
                return value_seed_run
        return super(EnAddressStack, self).run()

    def _handle_value_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        stream = self.context.stream
        raw_text = self.context.stream.text
        admin_levels = _clue_admin_levels(clue)
        if state.pending_comma_value_right_scan:
            state.pending_comma_value_right_scan = False
            upper_bound = _comma_value_scan_upper_bound(
                clues,
                clue_index,
                clue,
                stream,
                len(raw_text),
                should_break=self.should_break_clue,
            )
            value_end = _scan_forward_value_end(raw_text, clue.end, upper_bound, stream=stream)
            if value_end > clue.end:
                merged = raw_text[clue.start:value_end]
                if _normalize_address_value(comp_type, merged):
                    state.value_char_end_override[clue.clue_id] = value_end
        # §6.2：EN 同 span 多层 admin VALUE 组 —— dual-emit 后按相同 start/end 聚成一个 admin span，
        # 用于 resolver / collision 决策；非 admin 类型继续走单层路径。
        admin_span = collect_admin_value_span(clues, clue_index) if admin_levels else None
        trailing_deferred = state.deferred_chain[-1][1] if state.deferred_chain else None
        same_trailing_admin_span = (
            admin_span is not None
            and trailing_deferred is not None
            and trailing_deferred.role == ClueRole.VALUE
            and trailing_deferred.attr_type == clue.attr_type
            and bool(_clue_admin_levels(trailing_deferred))
            and trailing_deferred.start == admin_span.start
            and trailing_deferred.end == admin_span.end
        )

        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
        # 新的 admin VALUE 组进入时若链尾是另一个 admin 组，先冲洗（触发 §5.1 collision 的前置条件）。
        if (
            admin_span is not None
            and trailing_deferred is not None
            and trailing_deferred.role == ClueRole.VALUE
            and trailing_deferred.attr_type == clue.attr_type
            and bool(_clue_admin_levels(trailing_deferred))
            and not same_trailing_admin_span
        ):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP

        if state.components or state.deferred_chain:
            # MULTI_ADMIN 探针：admin_span 存在时逐层用 _segment_admit 试探，任一层通过即可挂。
            probe_levels: tuple[AddressComponentType, ...] = admin_levels or (comp_type,)
            resolved_group = None
            if admin_span is not None:
                resolved_group = _resolve_standalone_admin_value_group(
                    state,
                    tuple(
                        (index, clues[index])
                        for index in range(admin_span.first_index, admin_span.last_index + 1)
                    ),
                    valid_successors=self.valid_successors,
                )
                if resolved_group is not None and resolved_group.available_levels:
                    probe_levels = resolved_group.available_levels
            probe_failed = not any(
                _segment_admit(state, lvl, valid_successors=self.valid_successors)
                for lvl in probe_levels
            )
            # §5.2.1：admin_span + 无 deferred_chain + 探针全失败时，尝试同值 MULTI_ADMIN 原地降解。
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
                if state.deferred_chain:
                    self._flush_chain(state, clue_index=clue_index)
                    if state.split_at is not None:
                        return _SENTINEL_STOP
                if state.components and not any(
                    _segment_admit(state, lvl, valid_successors=self.valid_successors)
                    for lvl in probe_levels
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

        context = _state_routing_context(state, clues, raw_text, stream, value_floor=self._value_floor_char())
        expand_defer = key_left_expand_start_if_deferrable_en(context, clue, comp_type)
        if expand_defer is not None:
            state.chain_left_anchor = expand_defer
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
            return None

        state.ignored_address_key_indices.add(clue_index)
        return _SENTINEL_IGNORE

    def _candidate_start_end(self, state: _ParseState) -> tuple[int, int]:
        return BaseAddressStack._candidate_start_end(self, state)

    def _build_address_run_from_state(
        self,
        state: _ParseState,
        handled_labels: set[str],
    ) -> StackRun | None:
        if self._disable_house_number_promotion:
            return super(EnAddressStack, self)._build_address_run_from_state(
                state,
                handled_labels,
            )

        promotion = self._plan_house_number_promotion(state)
        if promotion is None:
            return super(EnAddressStack, self)._build_address_run_from_state(
                state,
                handled_labels,
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
        self._disable_house_number_promotion = True
        try:
            conservative_run = super(EnAddressStack, self)._build_address_run_from_state(
                conservative_state,
                handled_labels,
            )
            extended_run = super(EnAddressStack, self)._build_address_run_from_state(
                extended_state,
                handled_labels,
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
            extended_last_unit=extended_run.frontier_last_unit,
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
        cloned.consumed_clue_indices = {
            clue_index
            for component in components
            for clue_index in component.clue_indices
            if clue_index >= 0
        }
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
            challenge_clue: Clue | None = None
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
                raw_chain=[challenge_clue] if challenge_clue is not None else [],
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
        if not _clue_admin_levels(self.clue):
            return None
        raw_text = self.context.stream.text
        road_key_index, road_key = self._find_suffix_road_key_after_value_seed()
        if road_key is None:
            return None

        road_start = self.clue.start
        house_number_clue_index: int | None = None
        house_number_clue_id: str | None = None
        house_number_clue: Clue | None = None
        if self.clue_index > 0:
            previous = self.context.clues[self.clue_index - 1]
            if (
                previous.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}
                and previous.end <= self.clue.start
                and _clue_unit_gap(previous, self.clue, self.context.stream) <= 2
            ):
                road_start = previous.start
                house_number_clue_index = self.clue_index - 1
                house_number_clue_id = previous.clue_id
                house_number_clue = previous

        road_value = _normalize_address_value(AddressComponentType.ROAD, raw_text[road_start:road_key.start])
        if not road_value:
            return None
        road_raw_chain = [self.clue, road_key]
        if house_number_clue is not None:
            road_raw_chain.insert(0, house_number_clue)
        state = _ParseState()
        state.components = [
            _DraftComponent(
                component_type=AddressComponentType.ROAD,
                start=road_start,
                end=road_key.end,
                value=road_value,
                key=road_key.text,
                is_detail=False,
                raw_chain=road_raw_chain,
                suspected=[],
                clue_ids={
                    clue.clue_id
                    for clue in road_raw_chain
                },
                clue_indices={
                    index
                    for index in (
                        house_number_clue_index,
                        self.clue_index,
                        road_key_index,
                    )
                    if index is not None
                },
            )
        ]
        state.evidence_count = 1
        state.consumed_clue_indices = {self.clue_index, road_key_index}
        return self._build_address_run_from_state(
            state,
            set(),
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
        for index, clue in _iter_family_clues_from_unit(
            self.context.clues,
            self.context.unit_index,
            ClueFamily.ADDRESS,
            start_unit=self.clue.unit_last,
            min_clue_index=self.clue_index + 1,
        ):
            if clue.attr_type == PIIAttributeType.ADDRESS and clue.role == ClueRole.KEY and clue.component_type == AddressComponentType.ROAD:
                if _clue_unit_gap(self.clue, clue, self.context.stream) > 3:
                    return None, None
                between = raw_text[self.clue.end:clue.start]
                if any(char in ",，\r\n" for char in between):
                    return None, None
                return index, clue
        return None, None

    def _find_leading_house_number_challenge(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> tuple[int, Clue] | None:
        raw_text = self.context.stream.text
        component_value_start = _skip_separators(raw_text, component.start)
        stream = self.context.stream
        if not stream.char_to_unit or component_value_start >= len(stream.char_to_unit):
            return None
        target_unit = stream.char_to_unit[component_value_start]
        if target_unit >= len(self.context.unit_index):
            return None
        clues = self.context.clues
        for idx in bucket_family_clues(self.context.unit_index[target_unit], ClueFamily.STRUCTURED):
            clue = clues[idx]
            if clue.start != component_value_start:
                continue
            if clue.end > road_key_start:
                continue
            if clue.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
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

