"""中文车牌 stack。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, Clue, ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _label_seed_start_char,
    _unit_index_at_or_after,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break

_ASCII_SUFFIX_RE = re.compile(r"[!-~]{5,6}(?![!-~])")


@dataclass(frozen=True, slots=True)
class _SuffixMatch:
    kind: str
    start: int
    end: int
    text: str
    unit_start: int
    unit_end: int
    clue_id: str | None = None


class LicensePlateStack(BaseStack):
    """处理中文车牌前缀与后缀的组合吸收。"""

    def run(self) -> StackRun | None:
        if self.clue.strength == ClaimStrength.HARD and self.clue.attr_type == PIIAttributeType.LICENSE_PLATE:
            return self._build_direct_run()
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            return self._run_from_seed()
        if self.clue.role == ClueRole.VALUE and self.clue.family == ClueFamily.LICENSE_PLATE:
            return self._run_from_prefix(self.clue_index, self.clue, seed_kind="value")
        return None

    def _run_from_seed(self) -> StackRun | None:
        stream = self.context.stream
        seed_start = _label_seed_start_char(stream, self.clue.end)
        if seed_start >= len(stream.text):
            return None
        prefix_info = self._find_prefix_value(seed_start, self.clue_index + 1)
        if prefix_info is not None:
            prefix_index, prefix_clue = prefix_info
            return self._run_from_prefix(prefix_index, prefix_clue, seed_kind=self.clue.role.value)
        suffix = self._match_suffix(seed_start, self.clue_index + 1)
        if suffix is None:
            return None
        return self._build_run(seed_kind=self.clue.role.value, suffix=suffix)

    def _run_from_prefix(self, prefix_index: int, prefix_clue: Clue, *, seed_kind: str) -> StackRun | None:
        suffix = self._match_suffix(prefix_clue.end, prefix_index + 1)
        if suffix is None:
            return None
        return self._build_run(seed_kind=seed_kind, prefix=prefix_clue, suffix=suffix)

    def _build_run(
        self,
        *,
        seed_kind: str,
        suffix: _SuffixMatch,
        prefix: Clue | None = None,
    ) -> StackRun:
        stream = self.context.stream
        start = prefix.start if prefix is not None else suffix.start
        end = suffix.end
        unit_start = prefix.unit_start if prefix is not None else suffix.unit_start
        unit_end = suffix.unit_end
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.LICENSE_PLATE,
            start=start,
            end=end,
            text=stream.text[start:end],
            source=stream.source,
            source_kind="validated_license_plate_zh",
            unit_start=unit_start,
            unit_end=unit_end,
            claim_strength=ClaimStrength.SOFT,
            metadata={
                "validated_by": ["validated_license_plate_zh"],
                "seed_kind": [seed_kind],
                "license_plate_suffix_kind": [suffix.kind],
            },
        )
        consumed_ids = {self.clue.clue_id}
        if prefix is not None:
            consumed_ids.add(prefix.clue_id)
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {
                    "license_plate_prefix": [prefix.text],
                    "license_plate_prefix_clue_id": [prefix.clue_id],
                },
            )
        if suffix.clue_id is not None:
            consumed_ids.add(suffix.clue_id)
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"license_plate_suffix_clue_id": [suffix.clue_id]},
            )
        handled_labels: set[str] = set()
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            candidate.label_clue_ids.add(self.clue.clue_id)
            candidate.label_driven = self.clue.role == ClueRole.LABEL
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"bound_label_clue_ids": [self.clue.clue_id]},
            )
            handled_labels.add(self.clue.clue_id)
        return StackRun(
            attr_type=PIIAttributeType.LICENSE_PLATE,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=handled_labels,
            next_index=max(self.clue_index + 1, self._next_index_after(end)),
        )

    def _find_prefix_value(self, cursor: int, start_index: int) -> tuple[int, Clue] | None:
        for index in range(start_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.end <= cursor:
                continue
            if clue.start < cursor:
                continue
            gap_text = self.context.stream.text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return None
            if clue.family == ClueFamily.LICENSE_PLATE and clue.role == ClueRole.VALUE:
                return index, clue
            return None
        return None

    def _match_suffix(self, cursor: int, start_index: int) -> _SuffixMatch | None:
        cursor = self._skip_suffix_gap(cursor)
        hard_match = self._match_hard_suffix_clue(cursor, start_index)
        if hard_match is not None:
            return hard_match
        raw_match = _ASCII_SUFFIX_RE.match(self.context.stream.text, cursor)
        if raw_match is None:
            return None
        start, end = raw_match.span()
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        return _SuffixMatch(
            kind="ascii",
            start=start,
            end=end,
            text=raw_match.group(0),
            unit_start=unit_start,
            unit_end=unit_end,
        )

    def _match_hard_suffix_clue(self, cursor: int, start_index: int) -> _SuffixMatch | None:
        for index in range(start_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.end <= cursor:
                continue
            if clue.start < cursor:
                continue
            gap_text = self.context.stream.text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return None
            if clue.strength != ClaimStrength.HARD or clue.role != ClueRole.VALUE:
                return None
            normalized = re.sub(r"[^0-9A-Za-z]", "", clue.text or "")
            if not 5 <= len(normalized) <= 6:
                return None
            if clue.attr_type == PIIAttributeType.NUMERIC:
                return _SuffixMatch(
                    kind="digit",
                    start=clue.start,
                    end=clue.end,
                    text=clue.text,
                    unit_start=clue.unit_start,
                    unit_end=clue.unit_end,
                    clue_id=clue.clue_id,
                )
            if clue.attr_type == PIIAttributeType.ALNUM:
                return _SuffixMatch(
                    kind="alnum",
                    start=clue.start,
                    end=clue.end,
                    text=clue.text,
                    unit_start=clue.unit_start,
                    unit_end=clue.unit_end,
                    clue_id=clue.clue_id,
                )
            return None
        return None

    def _skip_suffix_gap(self, start_char: int) -> int:
        stream = self.context.stream
        if not stream.units:
            return max(0, start_char)
        cursor = max(0, start_char)
        ui = _unit_index_at_or_after(stream, cursor)
        while ui < len(stream.units):
            unit = stream.units[ui]
            if unit.char_start < cursor:
                ui += 1
                continue
            if unit.kind in {"space", "inline_gap"}:
                cursor = unit.char_end
                ui += 1
                continue
            if len(unit.text) == 1 and is_soft_break(unit.text):
                cursor = unit.char_end
                ui += 1
                continue
            break
        return cursor

    def _next_index_after(self, end_char: int) -> int:
        for index in range(self.clue_index + 1, len(self.context.clues)):
            if self.context.clues[index].start >= end_char:
                return index
        return len(self.context.clues)
