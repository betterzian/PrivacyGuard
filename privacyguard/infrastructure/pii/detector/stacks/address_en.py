"""英文地址 stack。"""

from __future__ import annotations

from dataclasses import dataclass, replace
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
    bucket_family_clues,
)
from privacyguard.infrastructure.pii.detector.stacks.address_base import BaseAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _SENTINEL_IGNORE,
    _SENTINEL_STOP,
    _chain_can_accept,
    _clue_unit_gap,
    _is_comma_boundary_span,
    _normalize_address_value,
    _scan_forward_value_end,
    _unit_frontier_after_last,
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
    _resolve_admin_key_chain_levels,
    _resolve_standalone_admin_value_group,
    collect_admin_value_span,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ComponentPathSpan,
    _ADMIN_TYPES,
    _DraftComponent,
    _ParseState,
    _apply_component_level_path_resolution,
    _append_deferred,
    _clone_draft_component,
    _deferred_admin_path_can_accept,
    _flush_chain,
    _resolve_component_level_path,
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


_PREFIX_KEY_HARD_FLOOR = frozenset({"apartment", "apt", "suite", "ste", "room", "rm", "#"})
_PREFIX_KEY_SOFT_CAP = frozenset({"unit"})


def _pending_prefix_key_entry(state: _ParseState) -> tuple[int, Clue] | None:
    if len(state.deferred_chain) != 1:
        return None
    clue_index, clue = state.deferred_chain[0]
    if clue.role != ClueRole.KEY or not is_prefix_en_key(clue.text):
        return None
    return clue_index, clue


def _prefix_gap_allows_value(prefix_key: Clue, value_clue: Clue, stream: StreamInput) -> bool:
    if value_clue.start < prefix_key.end:
        return False
    for unit in stream.units[_unit_frontier_after_last(prefix_key.unit_last): value_clue.unit_start]:
        if unit.kind not in {"space", "inline_gap"}:
            return False
    return True


def _prefix_value_token(prefix_key: Clue, value_clue: Clue, stream: StreamInput) -> str | None:
    if value_clue.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
        return None
    if not _prefix_gap_allows_value(prefix_key, value_clue, stream):
        return None
    units = [
        unit
        for unit in stream.units[value_clue.unit_start: _unit_frontier_after_last(value_clue.unit_last)]
        if unit.kind not in {"space", "inline_gap"}
    ]
    if len(units) != 1:
        return None
    token = units[0].text.strip()
    if not token or not token.isalnum():
        return None
    return token if _prefix_token_allowed(prefix_key, token, source_attr_type=value_clue.attr_type) else None


def _prefix_token_allowed(
    prefix_key: Clue,
    token: str,
    *,
    source_attr_type: PIIAttributeType | None = None,
) -> bool:
    """判断 prefix-key 右侧单 token 是否可作为英文 detail/building 值。"""
    cleaned = str(token or "").strip()
    if not cleaned or not cleaned.isalnum():
        return False
    if source_attr_type == PIIAttributeType.NUM:
        return cleaned.isdigit()
    if any(char.isdigit() for char in cleaned):
        return True
    component_type = prefix_key.component_type or AddressComponentType.DETAIL
    if component_type == AddressComponentType.BUILDING:
        return cleaned.isalpha() and len(cleaned) <= 2
    if component_type in {
        AddressComponentType.UNIT,
        AddressComponentType.ROOM,
        AddressComponentType.SUITE,
        AddressComponentType.DETAIL,
    }:
        return cleaned.isalpha() and len(cleaned) == 1
    return False


def _prefix_value_fragment_from_text(prefix_key: Clue, stream: StreamInput) -> tuple[str, int] | None:
    """当 scanner 没有产出 NUM/ALNUM clue 时，直接从 key 右侧取一个紧邻 token。"""
    cursor = prefix_key.end
    for unit in stream.units[_unit_frontier_after_last(prefix_key.unit_last):]:
        if unit.char_end <= cursor:
            continue
        if unit.kind in {"space", "inline_gap"}:
            cursor = max(cursor, unit.char_end)
            continue
        token = unit.text.strip()
        if not _prefix_token_allowed(prefix_key, token):
            return None
        return token, unit.char_end
    return None


@dataclass(slots=True)
class EnAddressStack(BaseAddressStack):
    """英文地址专用 stack。"""

    _disable_number_promotion: bool = False
    _FALLBACK_NUMBER_RE = re.compile(r"\d{1,6}[A-Za-z]?$")

    @property
    def valid_successors(self):
        return EN_VALID_SUCCESSORS

    def _flush_chain(self, state: _ParseState, *, clue_index: int) -> None:
        prefix_entry = _pending_prefix_key_entry(state)
        if prefix_entry is not None:
            before_component_count = len(state.components)
            key_index, key_clue = prefix_entry
            value_entry = state.pending_prefix_value
            token: str | None = None
            component_end = key_clue.end
            raw_chain = [key_clue]
            clue_ids = {key_clue.clue_id}
            clue_indices = {key_index}
            if value_entry is not None:
                value_index, value_clue = value_entry
                token = _prefix_value_token(key_clue, value_clue, self.context.stream)
                if token is not None:
                    component_end = value_clue.end
                    raw_chain.append(value_clue)
                    clue_ids.add(value_clue.clue_id)
                    clue_indices.add(value_index)
            if token is None:
                raw_fragment = _prefix_value_fragment_from_text(key_clue, self.context.stream)
                if raw_fragment is not None:
                    token, component_end = raw_fragment
            if token is not None:
                component = _DraftComponent(
                    component_type=key_clue.component_type or AddressComponentType.DETAIL,
                    start=key_clue.start,
                    end=component_end,
                    value=_normalize_address_value(
                        key_clue.component_type or AddressComponentType.DETAIL,
                        token,
                    ),
                    key=key_clue.text,
                    is_detail=(key_clue.component_type or AddressComponentType.DETAIL) in {
                        AddressComponentType.BUILDING,
                        AddressComponentType.UNIT,
                        AddressComponentType.ROOM,
                        AddressComponentType.SUITE,
                        AddressComponentType.DETAIL,
                    },
                    raw_chain=raw_chain,
                    clue_ids=clue_ids,
                    clue_indices=clue_indices,
                )
                folded_key = key_clue.text.strip().lower()
                if folded_key in _PREFIX_KEY_HARD_FLOOR:
                    component.strength_floor = ClaimStrength.HARD
                if folded_key in _PREFIX_KEY_SOFT_CAP:
                    component.strength_cap = ClaimStrength.SOFT
                self._commit_component(state, component)
            else:
                state.ignored_address_key_indices.add(key_index)
            state.deferred_chain.clear()
            state.suspect_chain.clear()
            state.pending_suspects.clear()
            state.chain_left_anchor = None
            state.value_char_end_override.clear()
            state.pending_prefix_value = None
            if len(state.components) == before_component_count and state.components:
                state.last_end = max(component.end for component in state.components)
            return
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
            valid_successors=self.valid_successors,
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
        gap_start = state.last_piece_end
        if gap_start is None and state.deferred_chain:
            gap_start = state.deferred_chain[-1][1].end
        if (
            gap_start is not None
            and clue.start > gap_start
            and _is_comma_boundary_span(stream, gap_start, clue.start)
        ):
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
            state.segment_state.reset()
        return None

    def _consume_non_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        index: int,
        stream: StreamInput,
    ) -> bool:
        prefix_entry = _pending_prefix_key_entry(state)
        if prefix_entry is not None and state.pending_prefix_value is None:
            _, key_clue = prefix_entry
            if _prefix_value_token(key_clue, clue, stream) is not None:
                state.pending_prefix_value = (index, clue)
                state.last_end = max(state.last_end, clue.end)
                return True
        return BaseAddressStack._consume_non_address_clue(self, state, clue, clues, index, stream)

    def _allow_search_stop_bridge(
        self,
        state: _ParseState,
        clue: Clue,
        *,
        search_anchor: int,
    ) -> bool:
        prefix_entry = _pending_prefix_key_entry(state)
        if prefix_entry is not None and state.pending_prefix_value is None:
            _, key_clue = prefix_entry
            if _prefix_value_token(key_clue, clue, self.context.stream) is not None:
                return True
        if not state.components:
            return False
        if (
            clue.attr_type != PIIAttributeType.ADDRESS
            or clue.role != ClueRole.KEY
            or clue.component_type != AddressComponentType.ROAD
        ):
            return False
        if not all(
            component.component_type in {
                AddressComponentType.POI,
                AddressComponentType.BUILDING,
                AddressComponentType.UNIT,
                AddressComponentType.ROOM,
                AddressComponentType.SUITE,
                AddressComponentType.DETAIL,
            }
            for component in state.components
        ):
            return False
        gap = self.context.stream.text[search_anchor:clue.start]
        compact = "".join(char for char in gap if not char.isspace() and char not in ",，")
        if not compact:
            return False
        return all(char.isalnum() or char in "-/#" for char in compact)

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
        if _pending_prefix_key_entry(state) is not None:
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
        stream = self.context.stream
        raw_text = self.context.stream.text
        admin_levels = _clue_admin_levels(clue)
        # §6.2：EN 同 span 多层 admin VALUE 组 —— dual-emit 后按相同 start/end 聚成一个 admin span，
        # 用于 resolver / collision 决策；非 admin 类型继续走单层路径。
        admin_span = collect_admin_value_span(clues, clue_index) if admin_levels else None

        incoming_admin_path = None
        if admin_span is not None:
            incoming_admin_path = _ComponentPathSpan(
                start=clue.start,
                end=state.value_char_end_override.get(clue.clue_id, admin_span.end),
                text=admin_span.text,
                levels=admin_span.levels,
            )
        admin_path_can_accept = (
            incoming_admin_path is not None
            and _deferred_admin_path_can_accept(
                state,
                raw_text,
                incoming_admin_path,
                valid_successors=self.valid_successors,
            )
        )
        if state.deferred_chain and not _chain_can_accept([c for _, c in state.deferred_chain], clue, stream):
            if not admin_path_can_accept:
                self._flush_chain(state, clue_index=clue_index)
                if state.split_at is not None:
                    return _SENTINEL_STOP

        resolved_path_levels: tuple[AddressComponentType, ...] | None = None
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
            if (
                probe_failed
                and admin_span is not None
                and resolved_group is not None
                and not state.deferred_chain
            ):
                path_resolution = _resolve_component_level_path(
                    state,
                    raw_text,
                    (_ComponentPathSpan(
                        start=clue.start,
                        end=clue.end,
                        text=resolved_group.text,
                        levels=resolved_group.all_levels,
                    ),),
                    valid_successors=self.valid_successors,
                )
                if path_resolution is not None and path_resolution.span_levels:
                    _apply_component_level_path_resolution(state, path_resolution)
                    resolved_path_levels = path_resolution.span_levels[0]
                    probe_levels = resolved_path_levels
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
        if resolved_path_levels is not None:
            primary = resolved_path_levels[0]
            clue = replace(
                clue,
                component_type=AddressComponentType.MULTI_ADMIN
                if len(resolved_path_levels) >= 2
                else primary,
                component_levels=resolved_path_levels,
            )

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
        if _pending_prefix_key_entry(state) is not None:
            self._flush_chain(state, clue_index=clue_index)
            if state.split_at is not None:
                return _SENTINEL_STOP
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
            _append_deferred(state, clue_index, clue, record_suspect=False)
            state.last_end = max(state.last_end, clue.end)
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
        if self._disable_number_promotion:
            return super(EnAddressStack, self)._build_address_run_from_state(
                state,
                handled_labels,
            )

        promotion = self._plan_number_promotion(state)
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
        self._disable_number_promotion = True
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
            self._disable_number_promotion = False

        if extended_run is None:
            return conservative_run
        if conservative_run is None or promotion["challenge_clue_index"] is None:
            return extended_run

        conservative_run.pending_challenge = PendingChallenge(
            clue_index=promotion["challenge_clue_index"],
            challenge_kind="number",
            cached_fragment_text=promotion["number_text"],
            cached_normalized_fragment=promotion["number_value"],
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

    def _plan_number_promotion(self, state: _ParseState) -> dict[str, object] | None:
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
            challenge_info = self._find_leading_number_challenge(component, road_key_start)
            challenge_clue_index: int | None = None
            challenge_clue_id: str | None = None
            challenge_clue: Clue | None = None
            number_start: int
            number_end: int
            if challenge_info is None:
                fallback_span = self._fallback_number_span(component, road_key_start)
                if fallback_span is None:
                    continue
                number_start, number_end = fallback_span
            else:
                challenge_clue_index, challenge_clue = challenge_info
                challenge_clue_id = challenge_clue.clue_id
                number_start, number_end = challenge_clue.start, challenge_clue.end
            road_start = _skip_separators(raw_text, number_end)
            if road_start >= road_key_start:
                continue
            road_value = _normalize_address_value(
                AddressComponentType.ROAD,
                raw_text[road_start:road_key_start],
            )
            number_text = raw_text[number_start:number_end]
            number_value = _normalize_address_value(AddressComponentType.NUMBER, number_text)
            if not road_value or not number_value:
                continue

            conservative_road = _clone_draft_component(component)
            conservative_road.start = road_start
            conservative_road.value = road_value

            number_component = _DraftComponent(
                component_type=AddressComponentType.NUMBER,
                start=number_start,
                end=number_end,
                value=number_value,
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
                    extended_components.append(number_component)
                    extended_components.append(_clone_draft_component(conservative_road))
                    continue
                extended_components.append(_clone_draft_component(item))
            extended_components.sort(key=lambda item: (item.start, item.end))
            return {
                "challenge_clue_index": challenge_clue_index,
                "challenge_clue_id": challenge_clue_id,
                "number_text": number_text,
                "number_value": number_value,
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
        number_clue_index: int | None = None
        number_clue_id: str | None = None
        number_clue: Clue | None = None
        if self.clue_index > 0:
            previous = self.context.clues[self.clue_index - 1]
            if (
                previous.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}
                and previous.end <= self.clue.start
                and _clue_unit_gap(previous, self.clue, self.context.stream) <= 2
            ):
                road_start = previous.start
                number_clue_index = self.clue_index - 1
                number_clue_id = previous.clue_id
                number_clue = previous

        road_value = _normalize_address_value(AddressComponentType.ROAD, raw_text[road_start:road_key.start])
        if not road_value:
            return None
        road_raw_chain = [self.clue, road_key]
        if number_clue is not None:
            road_raw_chain.insert(0, number_clue)
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
                        number_clue_index,
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

    def _find_leading_number_challenge(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> tuple[int, Clue] | None:
        raw_text = self.context.stream.text
        clues = self.context.clues
        search_floor = self._number_promotion_segment_floor(component, road_key_start)
        for idx in range(len(clues) - 1, -1, -1):
            clue = clues[idx]
            if clue.family != ClueFamily.STRUCTURED:
                continue
            if clue.start < search_floor:
                break
            if clue.end > road_key_start:
                continue
            if clue.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
                continue
            if is_prefix_en_component(component.component_type):
                continue
            road_start = _skip_separators(raw_text, clue.end)
            if road_start >= road_key_start:
                continue
            if not _normalize_address_value(
                AddressComponentType.ROAD,
                raw_text[road_start:road_key_start],
            ):
                continue
            return idx, clue
        return None

    def _fallback_number_span(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> tuple[int, int] | None:
        raw_text = self.context.stream.text
        start = self._number_promotion_segment_floor(component, road_key_start)
        if start >= road_key_start:
            return None
        cursor = start
        while cursor < road_key_start and raw_text[cursor].isalnum():
            cursor += 1
        token = raw_text[start:cursor]
        if not token or not self._FALLBACK_NUMBER_RE.fullmatch(token):
            return None
        if _skip_separators(raw_text, cursor) >= road_key_start:
            return None
        return start, cursor

    def _number_promotion_segment_floor(
        self,
        component: _DraftComponent,
        road_key_start: int,
    ) -> int:
        """英文门牌号仅在路名所在的最后一个逗号分段内查找。"""
        raw_text = self.context.stream.text
        floor = max(0, min(component.start, road_key_start))
        segment = raw_text[floor:road_key_start]
        cut = max(
            segment.rfind(","),
            segment.rfind("，"),
            segment.rfind("\n"),
            segment.rfind("\r"),
        )
        if cut >= 0:
            floor += cut + 1
        return _skip_separators(raw_text, floor)
