"""中文姓名 stack。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_zh_compound_surnames,
    load_zh_single_surname_claim_strengths,
)
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.base import PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _label_seed_start_char,
    _unit_index_at_or_after,
    _unit_index_left_of,
)
from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack
from privacyguard.infrastructure.pii.detector.zh_name_rules import (
    NegativeOverlapKind,
    apply_negative_overlap_strength,
    claim_strength_meets_protection,
    collect_blocking_overlaps,
    compact_zh_name_text,
    dominant_negative_overlap_kind,
    upgrade_claim_strength,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner


@dataclass(frozen=True, slots=True)
class _FamilyAnchor:
    start: int
    end: int
    text: str
    claim_strength: ClaimStrength
    clue_id: str | None = None

    @property
    def char_count(self) -> int:
        return len(compact_zh_name_text(self.text))


@dataclass(frozen=True, slots=True)
class _StandaloneRange:
    start: int
    end: int
    unit_start: int
    unit_last: int

    @property
    def unit_width(self) -> int:
        return max(0, self.unit_last - self.unit_start + 1)


@lru_cache(maxsize=1)
def _zh_single_surname_strength_map() -> dict[str, ClaimStrength]:
    mapping: dict[str, ClaimStrength] = {}
    for strength, surnames in load_zh_single_surname_claim_strengths().items():
        for surname in surnames:
            mapping[surname] = strength
    return mapping


@lru_cache(maxsize=1)
def _zh_compound_surnames_set() -> frozenset[str]:
    return frozenset(load_zh_compound_surnames())


class ZhNameStack(BaseNameStack):
    """中文姓名 stack。"""

    STACK_LOCALE = "zh"

    def need_break(
        self,
        flag=None,
        *,
        next_unit=None,
        prev_unit=None,
        upper=None,
        lower=None,
        left_char=None,
        right_char=None,
    ) -> bool:
        subject = next_unit if next_unit is not None else prev_unit
        if subject is None:
            return flag is not None
        if upper is not None and subject.char_start >= upper:
            return True
        if lower is not None and subject.char_end <= lower:
            return True
        if flag == "OCR_BREAK":
            return True
        if subject.kind == "cjk_char":
            return False
        if subject.kind == "punct":
            punct = flag if flag is not None else subject.text
            return not is_name_joiner(punct, left_char, right_char)
        return True

    def run(self) -> StackRun | None:
        if self.clue.role not in {
            ClueRole.FULL_NAME,
            ClueRole.ALIAS,
            ClueRole.GIVEN_NAME,
            ClueRole.LABEL,
            ClueRole.START,
            ClueRole.FAMILY_NAME,
        }:
            return None
        return self._run_name_candidate()

    def _trimmed_candidate_has_value_beyond_family(
        self,
        *,
        candidate: CandidateDraft,
        name_clues: list[tuple[int, Clue]],
    ) -> bool:
        """中文姓名裁剪后若只剩可解析的姓，不单独提交。"""
        if not super()._trimmed_candidate_has_value_beyond_family(candidate=candidate, name_clues=name_clues):
            return False
        family_anchor = self._resolve_family_anchor(candidate.start, candidate.end)
        if family_anchor is None:
            return True
        return candidate.end > family_anchor.end

    def _run_name_candidate(self) -> StackRun | None:
        if self.clue.role in {ClueRole.FULL_NAME, ClueRole.ALIAS, ClueRole.GIVEN_NAME}:
            return self._run_single_stage_candidate(
                start=self.clue.start,
                end=self.clue.end,
                initial_strength=self.clue.strength,
                route=self.clue.role.value,
            )

        start = self._resolve_boundary_start()
        if start >= len(self.context.stream.text):
            return None

        initial_standalone = self._resolve_standalone_range(start)
        upper_bound = initial_standalone.end
        explicit_family = self._resolve_explicit_family_anchor(start, upper_bound)
        inferred_family = self._resolve_family_anchor(start, upper_bound)
        route = self._route_name()

        family_anchor_for_upgrade = inferred_family
        family_strength_before: ClaimStrength | None = None
        family_strength_after: ClaimStrength | None = None
        given_strength_before: ClaimStrength | None = None
        given_strength_after: ClaimStrength | None = None
        final_end: int | None = None

        if explicit_family is not None:
            family_anchor_for_upgrade = explicit_family
            family_strength_before = (
                ClaimStrength.HARD if self.clue.role in {ClueRole.LABEL, ClueRole.START} else explicit_family.claim_strength
            )
            family_strength_after, _family_overlaps = self._apply_negative_span(
                start=explicit_family.start,
                end=explicit_family.end,
                effective_strength=family_strength_before,
            )
            if family_strength_after is None:
                return None

            tail_clue = self._resolve_second_stage_name_clue(
                name_start=start,
                family_anchor=explicit_family,
                upper_bound=upper_bound,
            )
            tail_span = self._resolve_second_stage_tail_span(
                family_anchor=explicit_family,
                explicit_name_clue=tail_clue,
                upper_bound=upper_bound,
            )
            if tail_span is None:
                return None

            given_strength_before = family_strength_after
            given_strength_after, _tail_overlaps = self._apply_negative_span(
                start=tail_span[0],
                end=tail_span[1],
                effective_strength=given_strength_before,
            )
            if given_strength_after is None:
                return None
            final_end = tail_span[2]
            final_strength = given_strength_after
        else:
            single_stage_clue = self._resolve_explicit_name_clue(start, upper_bound)
            if single_stage_clue is not None:
                span_start = single_stage_clue.start
                span_end = single_stage_clue.end
            else:
                span_start = start
                span_end = self._resolve_required_name_chars_end(start, upper_bound=upper_bound, char_count=2)
                if span_end is None:
                    return None
            initial_strength = ClaimStrength.HARD if self.clue.role in {ClueRole.LABEL, ClueRole.START} else self.clue.strength
            final_strength, _single_overlaps = self._apply_negative_span(
                start=span_start,
                end=span_end,
                effective_strength=initial_strength,
            )
            if final_strength is None:
                return None
            final_end = span_end

        if final_end is None or final_end <= start:
            return None

        candidate_raw_text = self.context.stream.text[start:final_end]
        candidate_overlaps = self._collect_blocking_overlaps(
            candidate_start=start,
            candidate_end=final_end,
            candidate_raw_text=candidate_raw_text,
        )

        if (
            family_anchor_for_upgrade is not None
            and self._should_upgrade_by_family_candidate_boundaries(
                family_anchor=family_anchor_for_upgrade,
                candidate_end=final_end,
            )
        ):
            final_strength = upgrade_claim_strength(final_strength)

        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            final_strength = ClaimStrength.HARD

        if not claim_strength_meets_protection(final_strength, self.context.protection_level):
            return None

        extra_metadata = {
            "name_route": [route],
            "negative_overlap_kind": [dominant_negative_overlap_kind(candidate_overlaps).value],
        }
        if family_strength_before is not None and family_strength_after is not None and family_anchor_for_upgrade is not None:
            extra_metadata |= {
                "family_claim_strength_before_negative": [family_strength_before.value],
                "family_claim_strength_after_negative": [family_strength_after.value],
                "family_anchor_text": [family_anchor_for_upgrade.text],
            }
        if given_strength_before is not None:
            extra_metadata["given_claim_strength_before_negative"] = [given_strength_before.value]
        if given_strength_after is not None:
            extra_metadata["given_claim_strength_after_negative"] = [given_strength_after.value]

        candidate = self._build_candidate(
            start=start,
            end=final_end,
            claim_strength=final_strength,
            route=route,
            negative_overlap_kind=dominant_negative_overlap_kind(candidate_overlaps),
            extra_metadata=extra_metadata,
        )
        if candidate is None:
            return None
        overlap_index = self._first_address_overlap_clue_index(start, final_end)
        run = self._finalize_run(start, final_end, candidate)
        if run is None:
            return None
        if overlap_index is not None and family_anchor_for_upgrade is not None and family_anchor_for_upgrade.end > start:
            run.pending_challenge = PendingChallenge(
                clue_index=overlap_index,
                extended_candidate=candidate,
                extended_last_unit=candidate.unit_last,
                challenge_kind="name_address_conflict",
            )
        return run

    def _run_single_stage_candidate(
        self,
        *,
        start: int,
        end: int,
        initial_strength: ClaimStrength,
        route: str,
    ) -> StackRun | None:
        final_strength, overlaps = self._apply_negative_span(
            start=start,
            end=end,
            effective_strength=initial_strength,
        )
        if final_strength is None:
            return None
        if not claim_strength_meets_protection(final_strength, self.context.protection_level):
            return None

        candidate = self._build_candidate(
            start=start,
            end=end,
            claim_strength=final_strength,
            route=route,
            negative_overlap_kind=dominant_negative_overlap_kind(overlaps),
            extra_metadata={
                "name_route": [route],
            },
        )
        if candidate is None:
            return None
        return self._finalize_run(start, end, candidate)

    def _first_address_overlap_clue_index(self, start: int, end: int) -> int | None:
        for idx, clue in enumerate(self.context.clues):
            if clue.start >= end:
                break
            if clue.attr_type == PIIAttributeType.ADDRESS and clue.end > start:
                return idx
        return None

    def _resolve_boundary_start(self) -> int:
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            return _label_seed_start_char(self.context.stream, self.clue.end)
        return self.clue.start

    def _resolve_family_anchor(self, start: int, upper_bound: int) -> _FamilyAnchor | None:
        if self.clue.role == ClueRole.FAMILY_NAME and self.clue.start == start:
            return _FamilyAnchor(
                start=self.clue.start,
                end=self.clue.end,
                text=self.clue.text,
                claim_strength=self.clue.strength,
                clue_id=self.clue.clue_id,
            )

        family_clues = self._name_clues_starting_at(start, role=ClueRole.FAMILY_NAME)
        if family_clues:
            index, clue = max(
                family_clues,
                key=lambda item: (item[1].end - item[1].start, _claim_strength_rank(item[1].strength)),
            )
            del index
            return _FamilyAnchor(
                start=clue.start,
                end=clue.end,
                text=clue.text,
                claim_strength=clue.strength,
                clue_id=clue.clue_id,
            )

        compact = self._compact_name_chars(start=start, upper_bound=upper_bound, max_chars=4)
        if len(compact) >= 2 and compact[:2] in _zh_compound_surnames_set():
            end = self._char_after_name_chars(start, upper_bound=upper_bound, char_count=2)
            if end is not None:
                return _FamilyAnchor(
                    start=start,
                    end=end,
                    text=self.context.stream.text[start:end],
                    claim_strength=ClaimStrength.HARD,
                )

        single_map = _zh_single_surname_strength_map()
        if compact[:1] in single_map:
            end = self._char_after_name_chars(start, upper_bound=upper_bound, char_count=1)
            if end is not None:
                return _FamilyAnchor(
                    start=start,
                    end=end,
                    text=self.context.stream.text[start:end],
                    claim_strength=single_map[compact[:1]],
                )
        return None

    def _resolve_explicit_family_anchor(self, start: int, upper_bound: int) -> _FamilyAnchor | None:
        family_clues = [
            clue
            for _index, clue in self._name_clues_starting_at(start, role=ClueRole.FAMILY_NAME)
            if clue.end <= upper_bound
        ]
        if not family_clues:
            return None
        clue = max(family_clues, key=lambda item: (item.end - item.start, _claim_strength_rank(item.strength)))
        return _FamilyAnchor(
            start=clue.start,
            end=clue.end,
            text=clue.text,
            claim_strength=clue.strength,
            clue_id=clue.clue_id,
        )

    def _resolve_explicit_name_clue(self, start: int, upper_bound: int) -> Clue | None:
        direct_roles = {
            ClueRole.FULL_NAME: 3,
            ClueRole.ALIAS: 2,
            ClueRole.GIVEN_NAME: 1,
        }
        matches: list[Clue] = []
        for role in direct_roles:
            matches.extend(
                clue
                for _index, clue in self._name_clues_starting_at(start, role=role)
                if clue.end <= upper_bound
            )
        if not matches:
            return None
        return max(
            matches,
            key=lambda clue: (
                clue.end - clue.start,
                _claim_strength_rank(clue.strength),
                direct_roles[clue.role],
            ),
        )

    def _resolve_second_stage_name_clue(
        self,
        *,
        name_start: int,
        family_anchor: _FamilyAnchor,
        upper_bound: int,
    ) -> Clue | None:
        whole_name_clue = self._resolve_explicit_name_clue(name_start, upper_bound)
        if whole_name_clue is not None and whole_name_clue.end > family_anchor.end:
            return whole_name_clue
        return self._resolve_explicit_name_clue(family_anchor.end, upper_bound)

    def _resolve_second_stage_tail_span(
        self,
        *,
        family_anchor: _FamilyAnchor,
        explicit_name_clue: Clue | None,
        upper_bound: int,
    ) -> tuple[int, int, int] | None:
        if explicit_name_clue is not None:
            return (explicit_name_clue.start, explicit_name_clue.end, explicit_name_clue.end)
        tail_end = self._char_after_name_chars(family_anchor.end, upper_bound=upper_bound, char_count=2)
        if tail_end is None:
            return None
        tail_char_count = self._count_name_chars(family_anchor.end, tail_end)
        if tail_char_count is None or tail_char_count <= 0:
            return None
        return (family_anchor.end, tail_end, tail_end)

    def _resolve_required_name_chars_end(self, start: int, *, upper_bound: int, char_count: int) -> int | None:
        end = self._char_after_name_chars(start, upper_bound=upper_bound, char_count=char_count)
        if end is None:
            return None
        if self._count_name_chars(start, end) != char_count:
            return None
        return end

    def _resolve_standalone_range(self, start: int) -> _StandaloneRange:
        left = start
        ui = _unit_index_left_of(self.context.stream, start)
        while ui >= 0:
            unit = self.context.stream.units[ui]
            if unit.kind in {"space", "inline_gap"}:
                ui -= 1
                continue
            if self._unit_is_name_like(ui):
                left = unit.char_start
                ui -= 1
                continue
            break

        right = start
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(self.context.stream.units):
            unit = self.context.stream.units[ui]
            if unit.kind in {"space", "inline_gap"}:
                break
            if not self._unit_is_name_like(ui):
                break
            right = unit.char_end
            ui += 1

        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, left, right)
        return _StandaloneRange(start=left, end=right, unit_start=unit_start, unit_last=unit_last)

    def _should_upgrade_by_family_candidate_boundaries(
        self,
        *,
        family_anchor: _FamilyAnchor,
        candidate_end: int,
    ) -> bool:
        """按 family 左右边界与跨度判定是否提升一级 strength。"""
        stream = self.context.stream
        if not stream.units or not stream.char_to_unit:
            return False
        family_unit_start, _family_unit_end = _char_span_to_unit_span(
            stream,
            family_anchor.start,
            family_anchor.end,
        )
        candidate_unit_start, candidate_unit_last = _char_span_to_unit_span(stream, family_anchor.start, candidate_end)
        if candidate_unit_last < candidate_unit_start:
            return False
        if candidate_unit_last - family_unit_start + 1 > 4:
            return False
        if not self._left_boundary_is_break(family_unit_start):
            return False
        if not self._right_boundary_is_break(candidate_unit_last):
            return False
        return True

    def _left_boundary_is_break(self, family_unit_start: int) -> bool:
        """判断 family 起始 unit 左侧是否形成 break。"""
        units = self.context.stream.units
        raw_text = self.context.stream.text
        if family_unit_start <= 0:
            return True
        subject_index = family_unit_start - 1
        subject = units[subject_index]
        left_char = _peek_unit_last_char(units, subject_index - 1)
        right_char = raw_text[subject.char_end] if subject.char_end < len(raw_text) else None
        return self.need_break(
            flag=_unit_flag(subject),
            lower=0,
            prev_unit=subject,
            left_char=left_char,
            right_char=right_char,
        )

    def _right_boundary_is_break(self, candidate_unit_last: int) -> bool:
        """判断候选末端右侧是否形成 break。"""
        units = self.context.stream.units
        raw_text = self.context.stream.text
        if candidate_unit_last + 1 >= len(units):
            return True
        subject_index = candidate_unit_last + 1
        subject = units[subject_index]
        left_char = raw_text[subject.char_start - 1] if subject.char_start > 0 else None
        right_char = _peek_unit_first_char(units, subject_index + 1)
        return self.need_break(
            flag=_unit_flag(subject),
            upper=len(raw_text),
            next_unit=subject,
            left_char=left_char,
            right_char=right_char,
        )

    def _unit_is_name_like(self, unit_index: int) -> bool:
        if unit_index < 0 or unit_index >= len(self.context.stream.units):
            return False
        unit = self.context.stream.units[unit_index]
        if unit.kind == "cjk_char":
            return True
        if unit.kind != "punct":
            return False
        left_char = _peek_unit_last_char(self.context.stream.units, unit_index - 1)
        right_char = _peek_unit_first_char(self.context.stream.units, unit_index + 1)
        return is_name_joiner(unit.text, left_char, right_char)

    def _compact_name_chars(self, *, start: int, upper_bound: int, max_chars: int) -> str:
        end = self._char_after_name_chars(start, upper_bound=upper_bound, char_count=max_chars)
        if end is None or end <= start:
            return ""
        return compact_zh_name_text(self.context.stream.text[start:end])

    def _char_after_name_chars(self, start: int, *, upper_bound: int, char_count: int) -> int | None:
        if char_count <= 0:
            return start
        ui = _unit_index_at_or_after(self.context.stream, start)
        seen = 0
        cursor = start
        while ui < len(self.context.stream.units):
            unit = self.context.stream.units[ui]
            if unit.char_start >= upper_bound:
                break
            if unit.kind == "cjk_char":
                seen += 1
                cursor = unit.char_end
                if seen >= char_count:
                    return cursor
                ui += 1
                continue
            if unit.kind == "punct":
                left_char = self.context.stream.text[unit.char_start - 1] if unit.char_start > 0 else None
                right_char = _peek_unit_first_char(self.context.stream.units, ui + 1)
                if is_name_joiner(unit.text, left_char, right_char):
                    cursor = unit.char_end
                    ui += 1
                    continue
            break
        return cursor if seen > 0 else None

    def _count_name_chars(self, start: int, end: int) -> int | None:
        if end <= start:
            return None
        return sum(1 for char in compact_zh_name_text(self.context.stream.text[start:end]) if char not in {"·", "•", "・"})

    def _name_clues_starting_at(self, start: int, *, role: ClueRole) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.start == start and clue.role == role:
                matches.append((index, clue))
        return matches

    def _route_name(self) -> str:
        if self.clue.role == ClueRole.FAMILY_NAME:
            return "family_name"
        if self.clue.role == ClueRole.LABEL:
            return "label_seed"
        return "start_seed"

    def _apply_negative_span(
        self,
        *,
        start: int,
        end: int,
        effective_strength: ClaimStrength,
    ) -> tuple[ClaimStrength | None, tuple]:
        raw_text = self.context.stream.text[start:end]
        if not compact_zh_name_text(raw_text):
            return None, ()
        overlaps = self._collect_blocking_overlaps(
            candidate_start=start,
            candidate_end=end,
            candidate_raw_text=raw_text,
        )
        return (
            apply_negative_overlap_strength(overlaps, effective_strength=effective_strength),
            overlaps,
        )

    def _build_candidate(
        self,
        *,
        start: int,
        end: int,
        claim_strength: ClaimStrength,
        route: str,
        negative_overlap_kind: NegativeOverlapKind,
        extra_metadata: dict[str, list[str]],
    ) -> CandidateDraft | None:
        text = compact_zh_name_text(self.context.stream.text[start:end])
        if not text:
            return None
        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, start, end)
        metadata = {key: list(values) for key, values in self.clue.source_metadata.items()}
        metadata.setdefault("matched_by", [self.clue.source_kind])
        metadata["name_route"] = [route]
        metadata["negative_overlap_kind"] = [negative_overlap_kind.value]
        for key, values in extra_metadata.items():
            metadata[key] = list(values)
        return CandidateDraft(
            attr_type=PIIAttributeType.NAME,
            start=start,
            end=end,
            unit_start=unit_start,
            unit_last=unit_last,
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=claim_strength,
            metadata=metadata,
            label_clue_ids={self.clue.clue_id} if self.clue.role == ClueRole.LABEL else set(),
            label_driven=self.clue.role == ClueRole.LABEL,
        )

    def _finalize_run(self, start: int, end: int, candidate: CandidateDraft) -> StackRun:
        return StackRun(
            attr_type=PIIAttributeType.NAME,
            candidate=candidate,
            handled_label_clue_ids={self.clue.clue_id} if self.clue.role == ClueRole.LABEL else set(),
            frontier_last_unit=candidate.unit_last,
        )

    def _collect_blocking_overlaps(
        self,
        *,
        candidate_start: int,
        candidate_end: int,
        candidate_raw_text: str,
    ):
        return collect_blocking_overlaps(
            candidate_start=candidate_start,
            candidate_end=candidate_end,
            candidate_raw_text=candidate_raw_text,
            negative_clues=self.context.negative_clues,
            other_clues=tuple(
                clue
                for clue in self.context.clues
                if clue.attr_type is not None and (
                    clue.attr_type != PIIAttributeType.NAME
                    or clue.role in {ClueRole.LABEL, ClueRole.START}
                )
            ),
        )


def _peek_unit_first_char(units, ui: int) -> str | None:
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[0] if units[ui].text else None


def _peek_unit_last_char(units, ui: int) -> str | None:
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[-1] if units[ui].text else None


def _claim_strength_rank(strength: ClaimStrength) -> int:
    return {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }[strength]


def _unit_flag(unit) -> str | None:
    if unit.kind == "ocr_break":
        return "OCR_BREAK"
    if unit.kind == "inline_gap":
        return "INLINE_GAP"
    if unit.kind == "space":
        return "SPACE"
    if unit.kind == "punct":
        return unit.text
    return None

