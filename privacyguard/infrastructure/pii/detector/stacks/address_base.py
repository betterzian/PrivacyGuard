"""地址 stack 的共享骨架。

中文与英文 stack 共用以下流程：
1. 地址 clue 起栈与 label/value seed 入口。
2. clue 主扫描、非地址 clue 吸收与 frontier 维护。
3. 负向尾修复、digit tail 挑战、最终 `StackRun` 组装。

语言差异通过钩子方法下放到子类，不在共享骨架里做 locale 分支。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value, has_address_signal, trim_candidate
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    PIIAttributeType,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    DigitTailResult,
    _SENTINEL_IGNORE,
    _SENTINEL_STOP,
    _analyze_digit_tail,
    _bridge_last_address_to_next_within_units,
    _clue_gap_has_search_stop,
    _clue_unit_gap,
    _first_address_clue_index_after,
    _is_absorbable_digit_clue,
    _materialize_digit_tail_before_comma,
    _next_address_clue_index_after,
    _normalize_address_value,
    _scan_forward_value_end,
    _span_has_non_comma_search_stop_unit,
    _span_has_search_stop_unit,
    _state_next_component_start,
    _unit_frontier_after_last,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ADMIN_TYPES,
    _DETAIL_COMPONENTS,
    _DraftComponent,
    _ParseState,
    _address_strength,
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
    _reroute_pending_community_poi_to_subdistrict,
    _rightmost_component_key_overlaps_negative,
)
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _clamp_left_boundary_to_value_floor,
    _family_value_floor_char,
    _floor_clamped_label_seed_start_char,
    _skip_separators,
    _unit_char_end,
    _unit_char_start,
)

_ADDRESS_STRONG_NEGATIVE_SCOPES = ("address", "ui")


@dataclass(slots=True)
class BaseAddressStack(BaseStack):
    """中文/英文地址 stack 的共享骨架。"""

    def _value_floor_char(self) -> int:
        """返回 ADDRESS 当前生效的 value 起点下界。"""
        return _family_value_floor_char(self.context, ClueFamily.ADDRESS)

    def _has_address_key_negative_cover(self, unit_start: int, unit_last: int) -> bool:
        """地址 key 的尾修复把显式 negative、LABEL/START 与 inspire 都视作负向。"""
        return self._has_semantic_negative_cover(
            unit_start,
            unit_last,
            scopes=_ADDRESS_STRONG_NEGATIVE_SCOPES,
            include_seed_roles=True,
            include_inspire=True,
        )

    @property
    def valid_successors(self) -> Mapping[AddressComponentType, frozenset[AddressComponentType]]:
        raise NotImplementedError

    def _prepare_effective_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        raw_text: str,
        stream: StreamInput,
    ) -> Clue | object:
        return clue

    def _prehandle_clue(
        self,
        state: _ParseState,
        raw_text: str,
        stream: StreamInput,
        clues: tuple[Clue, ...],
        clue_index: int,
        clue: Clue,
    ) -> object | None:
        return None

    def _handle_value_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        raise NotImplementedError

    def _handle_key_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
        comp_type: AddressComponentType,
    ) -> object | None:
        raise NotImplementedError

    def _candidate_start_end(self, state: _ParseState) -> tuple[int, int]:
        return (
            min(component.start for component in state.components),
            max(component.end for component in state.components),
        )

    def shrink(self, run: StackRun, blocker_start: int, blocker_last: int) -> StackRun | None:
        candidate = run.candidate
        stream = self.context.stream
        if blocker_start <= candidate.unit_start:
            new_unit_start, new_unit_last = blocker_last + 1, candidate.unit_last
        elif blocker_last >= candidate.unit_last:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        else:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        if new_unit_last < new_unit_start:
            return None
        trimmed = trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_last),
            unit_start=new_unit_start,
            unit_last=new_unit_last,
        )
        if trimmed is None:
            return None
        if not has_address_signal(trimmed.text) and not trimmed.label_driven:
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            handled_label_clue_ids=run.handled_label_clue_ids,
            frontier_last_unit=trimmed.unit_last,
            suppress_challenger_clue_ids=run.suppress_challenger_clue_ids,
        )

    def run(self) -> StackRun | None:
        """地址 stack 主入口。"""
        stream = self.context.stream
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}
        floor_char = self._value_floor_char()

        if is_label_seed:
            address_start = _floor_clamped_label_seed_start_char(self.context, ClueFamily.ADDRESS, self.clue.end)
            seed_index = _first_address_clue_index_after(
                self.context.clues,
                address_start,
            )
            if seed_index is None:
                return None
            scan_index = seed_index
            handled_labels: set[str] = {self.clue.clue_id}
            evidence_count = 1
            seed_floor = address_start
        else:
            if self.clue.role in {ClueRole.VALUE, ClueRole.KEY} and self.clue.start >= floor_char:
                address_start = self.clue.start
            else:
                address_start = None
            scan_index = self.clue_index
            handled_labels = set()
            evidence_count = 0
            seed_floor = floor_char
        if address_start is None:
            return None

        return self._run_with_clues(
            clues=self.context.clues,
            scan_index=scan_index,
            address_start=address_start,
            handled_labels=handled_labels,
            evidence_count=evidence_count,
            seed_floor=seed_floor,
        )

    def _run_with_clues(
        self,
        *,
        clues: tuple[Clue, ...],
        scan_index: int,
        address_start: int,
        handled_labels: set[str],
        evidence_count: int,
        seed_floor: int | None,
    ) -> StackRun | None:
        """统一扫描路径：扫描 clue → 尾修复 → 数字尾挑战 → 组装 `StackRun`。"""
        state, index = self._scan_components(
            clues=clues,
            scan_index=scan_index,
            address_start=address_start,
            evidence_count=evidence_count,
            seed_floor=seed_floor,
        )
        if not state.components:
            return None
        self._repair_negative_tail_components(state, clues)
        if not state.components:
            return None
        _fixup_suspected_info(state)

        tail = _analyze_digit_tail(state.components, self.context.stream, clues, index)
        if tail is not None and not tail.followed_by_address_key:
            conservative_run = self._build_address_run_from_state(
                state,
                handled_labels,
            )
            if conservative_run is None:
                return None
            state_ext = _ParseState()
            state_ext.components = list(state.components) + tail.new_components
            state_ext.evidence_count = state.evidence_count
            state_ext.suppress_challenger_clue_ids = set(state.suppress_challenger_clue_ids)
            state_ext.consumed_clue_indices = set(state.consumed_clue_indices) | set(tail.consumed_clue_indices)
            state_ext.absorbed_digit_unit_end = state.absorbed_digit_unit_end
            extended_run = self._build_address_run_from_state(
                state_ext,
                handled_labels,
            )
            if extended_run is None:
                return conservative_run
            if tail.challenge_clue_index is None:
                return extended_run
            conservative_run.pending_challenge = PendingChallenge(
                clue_index=tail.challenge_clue_index,
                challenge_kind="digit_tail",
                cached_fragment_text=tail.unit_text,
                cached_normalized_fragment=tail.pure_digits,
                extended_candidate=extended_run.candidate,
                extended_last_unit=extended_run.candidate.unit_last,
            )
            return conservative_run

        return self._build_address_run_from_state(
            state,
            handled_labels,
        )

    def _scan_components(
        self,
        *,
        clues: tuple[Clue, ...],
        scan_index: int,
        address_start: int,
        evidence_count: int,
        seed_floor: int | None,
        stop_char_end: int | None = None,
        absorb_non_address: bool = True,
        relaxed: bool = False,
    ) -> tuple[_ParseState, int]:
        """从 `scan_index` 起线性扫描 `clues`，维护 `_ParseState`。"""
        raw_text = self.context.stream.text
        stream = self.context.stream
        state = _ParseState()
        state.last_end = address_start
        state.evidence_count = evidence_count
        state.seed_floor = seed_floor
        index = scan_index

        while index < len(clues):
            clue = clues[index]
            if stop_char_end is not None and clue.start >= stop_char_end:
                break

            search_anchor = _state_next_component_start(state, stream, address_start=address_start)
            if not relaxed and search_anchor is not None and clue.start > search_anchor:
                allow_bridge = self._allow_search_stop_bridge(
                    state,
                    clue,
                    search_anchor=search_anchor,
                )
                if not allow_bridge and _span_has_search_stop_unit(stream, search_anchor, clue.start):
                    if state.deferred_chain:
                        self._flush_chain(state, clue_index=index)
                        if state.split_at is not None:
                            break
                        continue
                    if _span_has_non_comma_search_stop_unit(stream, search_anchor, clue.start):
                        break

            if self.should_break_clue(clue):
                break
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
            if not relaxed and state.last_consumed is not None:
                gap_anchor = max(
                    _unit_frontier_after_last(state.last_consumed.unit_last),
                    _unit_frontier_after_last(state.absorbed_digit_unit_end),
                )
                if clue.unit_start - gap_anchor > 6:
                    break

            result = self._handle_address_clue(state, clue, clues, index)
            if result is _SENTINEL_STOP:
                break
            if result is _SENTINEL_IGNORE:
                index += 1
                continue
            state.last_consumed = clue
            index += 1

        self._flush_chain(state, clue_index=index)
        return state, index

    def _consume_non_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        index: int,
        stream: StreamInput,
    ) -> bool:
        if _is_absorbable_digit_clue(clue):
            state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_last)
            _mark_consumed_indices(state, {index})
            return True
        if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
            nxt_addr = _next_address_clue_index_after(clues, index, should_break=self.should_break_clue)
            if nxt_addr is not None and _bridge_last_address_to_next_within_units(state, clues[nxt_addr], stream):
                state.suppress_challenger_clue_ids.add(clue.clue_id)
                state.absorbed_digit_unit_end = max(state.absorbed_digit_unit_end, clue.unit_last)
        return False

    def should_break_clue(self, subject, **kwargs) -> bool:
        del kwargs
        if isinstance(subject, Clue):
            return subject.role == ClueRole.BREAK
        return False

    def _allow_search_stop_bridge(
        self,
        state: _ParseState,
        clue: Clue,
        *,
        search_anchor: int,
    ) -> bool:
        del state, clue, search_anchor
        return False

    def _handle_address_clue(
        self,
        state: _ParseState,
        clue: Clue,
        clues: tuple[Clue, ...],
        clue_index: int,
    ) -> object | None:
        """单条地址 clue 的分派。"""
        raw_text = self.context.stream.text
        stream = self.context.stream
        effective_clue = self._prepare_effective_clue(state, clue, clues, clue_index, raw_text, stream)
        if effective_clue is _SENTINEL_IGNORE:
            return _SENTINEL_IGNORE
        comp_type = effective_clue.component_type
        if comp_type is None:
            return None
        if comp_type == AddressComponentType.NUMBER and state.last_component_type in _DETAIL_COMPONENTS:
            comp_type = AddressComponentType.DETAIL

        prehandle = self._prehandle_clue(
            state,
            raw_text,
            stream,
            clues,
            clue_index,
            effective_clue,
        )
        if prehandle is _SENTINEL_STOP:
            return _SENTINEL_STOP
        if prehandle is _SENTINEL_IGNORE:
            return _SENTINEL_IGNORE

        if effective_clue.role == ClueRole.VALUE:
            return self._handle_value_clue(state, effective_clue, clues, clue_index, comp_type)
        if effective_clue.role == ClueRole.KEY:
            return self._handle_key_clue(state, effective_clue, clues, clue_index, comp_type)
        return None

    def _repair_negative_tail_components(
        self,
        state: _ParseState,
        clues: tuple[Clue, ...],
    ) -> None:
        if not state.components:
            return
        ordered_components = sorted(state.components, key=lambda component: (component.end, component.start))
        if not ordered_components:
            return
        if not _rightmost_component_key_overlaps_negative(
            ordered_components[-1],
            clues,
            self._has_address_key_negative_cover,
        ):
            return
        base_evidence_count = max(0, state.evidence_count - len(state.components))
        state.components = self._repair_components_overlapping_negative(
            state.components,
            clues,
            state.ignored_address_key_indices,
        )
        _rebuild_component_derived_state(state, clues, base_evidence_count=base_evidence_count)

    def _repair_components_overlapping_negative(
        self,
        components: list[_DraftComponent],
        clues: tuple[Clue, ...],
        ignored_address_key_indices: set[int],
    ) -> list[_DraftComponent]:
        ordered = sorted(
            (_clone_draft_component(component) for component in components),
            key=lambda component: (component.end, component.start),
        )
        while ordered:
            last = ordered[-1]
            if not _rightmost_component_key_overlaps_negative(
                last,
                clues,
                self._has_address_key_negative_cover,
            ):
                return ordered
            repaired = self._repair_rightmost_component_prefix(
                prefix_components=ordered[:-1],
                component=last,
                clues=clues,
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
        clues: tuple[Clue, ...],
        ignored_address_key_indices: set[int],
    ) -> list[_DraftComponent] | None:
        clue_entries = _ordered_component_clue_entries(component, clues)
        if not clue_entries:
            return None
        last_affected_index = -1
        for index, (_, clue) in enumerate(clue_entries):
            if self._has_address_key_negative_cover(clue.unit_start, clue.unit_last):
                last_affected_index = index
        if last_affected_index <= 0:
            return None
        for cut in range(last_affected_index, 0, -1):
            replay_state = self._replay_component_clue_prefix(
                prefix_components=prefix_components,
                clue_entries=clue_entries[:cut],
                clues=clues,
                ignored_address_key_indices=ignored_address_key_indices,
            )
            if replay_state is None or not replay_state.components:
                continue
            if _rightmost_component_key_overlaps_negative(
                replay_state.components[-1],
                clues,
                self._has_address_key_negative_cover,
            ):
                continue
            return replay_state.components
        return None

    def _replay_component_clue_prefix(
        self,
        *,
        prefix_components: list[_DraftComponent],
        clue_entries: list[tuple[int, Clue]],
        clues: tuple[Clue, ...],
        ignored_address_key_indices: set[int],
    ) -> _ParseState | None:
        if not clue_entries:
            return None
        replay_state = _ParseState()
        replay_state.components = [_clone_draft_component(component) for component in prefix_components]
        replay_state.ignored_address_key_indices = set(ignored_address_key_indices)
        _rebuild_component_derived_state(replay_state, clues)
        for clue_index, clue in clue_entries:
            result = self._handle_address_clue(replay_state, clue, clues, clue_index)
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
        _flush_chain(
            state,
            self.context.stream.text,
            normalize_value=_normalize_address_value,
            commit_component=lambda component: self._commit_component(state, component),
        )

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
            commit=lambda component: self._commit_component(state, component),
        )

    def _commit_component(self, state: _ParseState, component: _DraftComponent) -> bool:
        return _commit(
            state,
            component,
            valid_successors=self.valid_successors,
        )

    def _build_left_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        *,
        component_start: int,
    ) -> _DraftComponent | None:
        component_start = _clamp_left_boundary_to_value_floor(component_start, self._value_floor_char())
        value = _normalize_address_value(comp_type, raw_text[component_start:clue.start])
        if not value:
            return None
        return _DraftComponent(
            component_type=comp_type,
            start=component_start,
            end=clue.end,
            value=value,
            key=clue.text,
            is_detail=comp_type in _DETAIL_COMPONENTS,
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )

    def _build_prefix_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        *,
        scan_limit: int = 30,
    ) -> _DraftComponent | None:
        value_start = _skip_separators(raw_text, clue.end)
        value_end = _scan_forward_value_end(
            raw_text,
            value_start,
            upper_bound=min(len(raw_text), clue.end + scan_limit),
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
            key=clue.text,
            is_detail=comp_type in _DETAIL_COMPONENTS,
            clue_ids={clue.clue_id},
            clue_indices={clue_index},
        )

    def _build_address_run_from_state(
        self,
        state: _ParseState,
        handled_labels: set[str],
    ) -> StackRun | None:
        """证据阈值通过后，用 component 并集 span 构造 `CandidateDraft` 与 `StackRun`。"""
        components = state.components
        claim_strength = _address_strength(components, stream=self.context.stream)
        if not _meets_commit_threshold(
            state.evidence_count,
            components,
            self._value_locale(),
            protection_level=self.context.protection_level,
            claim_strength=claim_strength,
        ):
            return None
        raw_text = self.context.stream.text
        final_start, final_end = self._candidate_start_end(state)
        text = clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        unit_start, unit_last = _char_span_to_unit_span(
            self.context.stream,
            absolute_start,
            absolute_start + len(text),
        )
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_start + len(text),
            unit_start=unit_start,
            unit_last=unit_last,
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=claim_strength,
            metadata=_address_metadata(self.clue, components),
            label_clue_ids=set(handled_labels),
            label_driven=(self.clue.role == ClueRole.LABEL),
        )
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            handled_label_clue_ids=set(handled_labels),
            frontier_last_unit=candidate.unit_last,
            suppress_challenger_clue_ids=frozenset(state.suppress_challenger_clue_ids),
        )

