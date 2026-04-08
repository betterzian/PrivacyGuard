"""组织名 stack 与组织名专属 helper。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.candidate_utils import (
    build_organization_candidate_from_value,
    clean_value,
    has_organization_suffix,
    organization_suffix_start,
    trim_candidate,
)
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueRole, StreamInput
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _count_non_space_units,
    _is_stop_control_clue,
    _skip_separators,
    _unit_char_end,
    _unit_char_start,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_control_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_any_break, is_hard_break


@dataclass(slots=True)
class OrganizationStack(BaseStack):
    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """组织名回缩：后缀被截即放弃，前缀被截后需重新校验。"""
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
        if not _is_organization_candidate_usable(trimmed.text, label_driven=trimmed.label_driven):
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def run(self) -> StackRun | None:
        if self.clue.strength == ClaimStrength.HARD:
            return self._build_direct_run()
        is_label_seed = self.clue.role == ClueRole.LABEL
        locale = self._value_locale()
        if is_label_seed:
            start = _skip_separators(self.context.stream.text, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._resolve_label_end(start=start, locale=locale)
            handled = {self.clue.clue_id}
        elif self.clue.role == ClueRole.SUFFIX:
            start = self._resolve_suffix_start(locale=locale)
            end = self.clue.end
            handled = set()
        else:
            return None
        matches = self._organization_clues_in_span(start, end)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=unit_start,
            unit_end=unit_end,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None
        if not _organization_has_body_before_suffix(candidate.text):
            return None
        consumed_ids = {clue.clue_id for _index, clue in matches}
        consumed_ids.add(self.clue.clue_id)
        last_index = max((index for index, _clue in matches), default=self.clue_index)
        return StackRun(
            attr_type=PIIAttributeType.ORGANIZATION,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=handled,
            next_index=last_index + 1,
        )

    def _resolve_label_end(self, *, start: int, locale: str) -> int:
        upper = self._resolve_label_upper_boundary(start)
        if upper <= start:
            return start
        suffix_end = self._find_suffix_end_within_window(start=start, upper=upper)
        if suffix_end is not None:
            return suffix_end
        return _extend_organization_right_with_limit(
            self.context.stream,
            start=start,
            upper=upper,
            locale=locale,
        )

    def _resolve_suffix_start(self, *, locale: str) -> int:
        floor = _left_expand_text_boundary(self.context.stream.text, self.context.clues, self.clue.start)
        return _extend_organization_left_with_limit(
            self.context.stream,
            floor=floor,
            start=self.clue.start,
            locale=locale,
        )

    def _resolve_label_upper_boundary(self, start: int) -> int:
        blocker_start = self._next_label_blocker_start(start)
        upper = blocker_start if blocker_start is not None else len(self.context.stream.text)
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(self.context.stream.units):
            unit = self.context.stream.units[ui]
            if unit.char_start >= upper:
                break
            if unit.kind in {"inline_gap", "ocr_break"}:
                return unit.char_start
            if unit.kind == "punct" and is_hard_break(unit.text):
                return unit.char_start
            ui += 1
        return upper

    def _next_label_blocker_start(self, start: int) -> int | None:
        for clue in self.context.clues:
            if clue.clue_id == self.clue.clue_id:
                continue
            if clue.start < start < clue.end and self._is_label_right_blocker(clue):
                return start
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.end <= start:
                continue
            if self._is_label_right_blocker(clue):
                return max(start, clue.start)
        return None

    def _is_label_right_blocker(self, clue: Clue) -> bool:
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR, ClueRole.LABEL}:
            return True
        if clue.strength == ClaimStrength.HARD:
            return True
        if clue.attr_type is None:
            return False
        return clue.attr_type != PIIAttributeType.ORGANIZATION

    def _find_suffix_end_within_window(self, *, start: int, upper: int) -> int | None:
        if start >= upper or not self.context.stream.char_to_unit:
            return None
        start_ui = _unit_index_at_or_after(self.context.stream, start)
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start >= upper:
                break
            if clue.end <= start:
                continue
            if clue.attr_type != PIIAttributeType.ORGANIZATION or clue.role != ClueRole.SUFFIX:
                continue
            suffix_ui = self.context.stream.char_to_unit[clue.start]
            if _count_non_space_units(self.context.stream.units, start_ui, suffix_ui + 1) <= 10:
                return clue.end
        return None

    def _organization_clues_in_span(self, start: int, end: int) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.end <= start:
                continue
            if clue.start >= end:
                break
            if clue.attr_type != PIIAttributeType.ORGANIZATION:
                continue
            if clue.strength == ClaimStrength.HARD:
                continue
            matches.append((index, clue))
        return matches


def _left_expand_text_boundary(raw_text: str, clues: tuple[Clue, ...], start: int) -> int:
    """组织名向左扩展文本边界。遇到任何断点符号即停止。"""
    floor = 0
    for clue in reversed(clues):
        if clue.end <= start:
            if _is_stop_control_clue(clue):
                floor = clue.end
                break
            if clue.role == ClueRole.LABEL:
                floor = clue.end
                break
    index = start
    while index > floor:
        previous = raw_text[index - 1]
        if is_any_break(previous):
            break
        index -= 1
    return index


def _organization_body_limit(locale: str) -> int:
    return 6 if locale == "zh" else 4


def _is_organization_count_unit(kind: str, locale: str) -> bool:
    if locale == "zh":
        return kind == "cjk_char"
    return kind == "ascii_word"


def _extend_organization_right_with_limit(
    stream: StreamInput,
    *,
    start: int,
    upper: int,
    locale: str,
) -> int:
    """组织名右扩：优先保留主体，空格和标点可带出但不计配额。"""
    if upper <= start:
        return start
    ui = _unit_index_at_or_after(stream, start)
    if ui >= len(stream.units):
        return start
    limit = _organization_body_limit(locale)
    count = 0
    end = start
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= upper:
            break
        if unit.kind in {"space", "punct"}:
            if end > start:
                end = min(unit.char_end, upper)
                ui += 1
                continue
            break
        if _is_organization_count_unit(unit.kind, locale):
            if count >= limit:
                break
            count += 1
            end = min(unit.char_end, upper)
            ui += 1
            continue
        break
    return end


def _extend_organization_left_with_limit(
    stream: StreamInput,
    *,
    floor: int,
    start: int,
    locale: str,
) -> int:
    """组织名左扩：只限制主体长度，空格和标点可一起带出。"""
    if start <= floor:
        return start
    ui = _unit_index_left_of(stream, start)
    if ui < 0:
        return start
    limit = _organization_body_limit(locale)
    count = 0
    next_start = start
    while ui >= 0:
        unit = stream.units[ui]
        if unit.char_end <= floor:
            break
        if unit.kind in {"space", "punct"}:
            next_start = max(floor, unit.char_start)
            ui -= 1
            continue
        if _is_organization_count_unit(unit.kind, locale):
            if count >= limit:
                break
            count += 1
            next_start = max(floor, unit.char_start)
            ui -= 1
            continue
        break
    return next_start


def _organization_has_body_before_suffix(text: str) -> bool:
    suffix_start = organization_suffix_start(text)
    if suffix_start < 0:
        return bool(clean_value(text))
    return bool(clean_value(text[:suffix_start]))


def _is_organization_candidate_usable(text: str, *, label_driven: bool) -> bool:
    if not text:
        return False
    if not has_organization_suffix(text) and not label_driven:
        return False
    return _organization_has_body_before_suffix(text)
