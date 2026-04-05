"""姓名 stack 与姓名专属 helper。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import build_name_candidate_from_value
from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole, NameComponentHint, StreamInput, StreamUnit
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _is_stop_control_clue,
    _skip_separators,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_control_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _is_cjk as _shared_is_cjk,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner

_NAME_COMPONENT_ROLES = frozenset(
    {
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
    }
)


class NameStack(BaseStack):
    """姓名检测 stack。"""

    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()
        locale = self._value_locale()
        if self.clue.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
            return self._build_name_run(start=self.clue.start, end=self.clue.end)
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            start = _skip_separators(self.context.stream.text, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._expand_seed_right(
                start=start,
                end=start,
                search_index=self.clue_index + 1,
                locale=locale,
            )
            return self._build_name_run(start=start, end=end)
        if self.clue.role == ClueRole.FAMILY_NAME:
            end = self._expand_seed_right(
                start=self.clue.start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
                locale=locale,
            )
            return self._build_name_run(start=self.clue.start, end=end)
        if self.clue.role == ClueRole.GIVEN_NAME:
            if locale == "zh":
                return self._build_name_run(start=self.clue.start, end=self.clue.end)
            start = self._extend_given_left_en(self.clue.start)
            end = self._extend_given_chain_right_en(
                start=start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
            )
            return self._build_name_run(start=start, end=end)
        return None

    def _build_name_run(self, *, start: int, end: int) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        if end <= start:
            return None

        component_hint = self._effective_hint(start, end)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_name_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            component_hint=component_hint,
            unit_start=unit_start,
            unit_end=unit_end,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None

        name_clues = self._name_clues_in_span(start, end)
        unique_roles = {clue.role for _index, clue in name_clues}
        if self.clue.role in _NAME_COMPONENT_ROLES:
            unique_roles.discard(self.clue.role)
        clue_count = 1 + len(unique_roles)
        negative_count = len(self._negative_clue_ids_in_span(start, end))

        if self.clue.role not in {ClueRole.FULL_NAME, ClueRole.ALIAS} and not self._meets_commit_threshold(
            candidate_text=candidate.text,
            clue_count=clue_count,
            negative_count=negative_count,
            name_clues=name_clues,
        ):
            return None

        consumed_ids = {self.clue.clue_id}
        consumed_ids.update(clue.clue_id for _index, clue in name_clues)
        last_name_index = max((index for index, _clue in name_clues), default=self.clue_index)
        return StackRun(
            attr_type=PIIAttributeType.NAME,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids={self.clue.clue_id} if is_label_seed else set(),
            next_index=max(self.clue_index + 1, last_name_index + 1),
        )

    def _extend_given_left_en(self, start: int) -> int:
        word_span = self._previous_plain_ascii_word(start)
        if word_span is None:
            return start
        word_start, word_end = word_span
        if self._span_has_any_clue_overlap(word_start, word_end):
            return start
        if self._span_has_blocker(word_end, start):
            return start
        return word_start

    def _expand_seed_right(
        self,
        *,
        start: int,
        end: int,
        search_index: int,
        locale: str,
    ) -> int:
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor):
                return cursor

            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(cursor, next_index)

            plain_limit = len(self.context.stream.text)
            if next_component is not None:
                plain_limit = next_component[1].start
            if next_blocker is not None and next_blocker[1].start < plain_limit:
                plain_limit = next_blocker[1].start

            scanned = self._scan_plain_right(start=start, cursor=cursor, upper=plain_limit, locale=locale)
            cursor = scanned
            if cursor < plain_limit:
                return cursor

            if next_component is None or next_component[1].start != cursor:
                return cursor

            component_index, component = next_component
            cursor = component.end
            next_index = component_index + 1

            if component.role == ClueRole.FAMILY_NAME:
                continue
            if component.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
                return cursor
            if locale == "zh":
                return cursor
            return self._extend_given_chain_right_en(
                start=start,
                end=cursor,
                search_index=next_index,
            )

    def _extend_given_chain_right_en(self, start: int, end: int, search_index: int) -> int:
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor):
                return cursor
            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(cursor, next_index)
            if next_component is None:
                return cursor
            component_index, component = next_component
            if component.role != ClueRole.GIVEN_NAME:
                return cursor
            if next_blocker is not None and next_blocker[1].start < component.start:
                return cursor
            if not self._gap_allows_single_plain_word(cursor, component.start):
                return cursor
            cursor = component.end
            next_index = component_index + 1

    def _effective_hint(self, start: int, end: int) -> NameComponentHint:
        base = self._component_hint()
        if base in {NameComponentHint.FAMILY, NameComponentHint.GIVEN, NameComponentHint.MIDDLE}:
            candidate_text = self.context.stream.text[start:end].strip()
            if len(candidate_text) > len(self.clue.text):
                return NameComponentHint.FULL
        return base

    def _component_hint(self) -> NameComponentHint:
        if self.clue.role == ClueRole.FAMILY_NAME:
            return NameComponentHint.FAMILY
        if self.clue.role == ClueRole.GIVEN_NAME:
            return self.clue.component_hint or NameComponentHint.GIVEN
        if self.clue.role == ClueRole.ALIAS:
            return NameComponentHint.ALIAS
        if self.clue.role == ClueRole.FULL_NAME:
            return NameComponentHint.FULL
        return self.clue.component_hint or NameComponentHint.FULL

    def _scan_plain_right(self, *, start: int, cursor: int, upper: int, locale: str) -> int:
        if upper <= cursor:
            return cursor
        raw_text = self.context.stream.text
        units = self.context.stream.units
        if not units or cursor >= len(raw_text):
            return cursor

        if locale == "zh":
            cjk_count = sum(1 for i in range(start, cursor) if _shared_is_cjk(raw_text[i]))
            cursor_end = cursor
            ui = _unit_index_at_or_after(self.context.stream, cursor)
            while ui < len(units) and cjk_count < 4:
                unit = units[ui]
                if unit.char_start >= upper:
                    break
                if unit.kind == "cjk_char":
                    cjk_count += 1
                    cursor_end = unit.char_end
                    ui += 1
                    continue
                if unit.kind == "punct":
                    left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
                    right_char = _peek_unit_first_char(units, ui + 1)
                    if is_name_joiner(unit.text, left_char, right_char):
                        cursor_end = unit.char_end
                        ui += 1
                        continue
                break
            return max(cursor, cursor_end)

        cursor_end = cursor
        ui = _unit_index_at_or_after(self.context.stream, cursor)
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= upper:
                break
            if unit.char_end - start > 80:
                break
            if unit.kind == "ascii_word":
                cursor_end = unit.char_end
                ui += 1
                continue
            if unit.kind == "space":
                next_ui = ui + 1
                while next_ui < len(units) and units[next_ui].kind == "space":
                    next_ui += 1
                if next_ui < len(units) and units[next_ui].kind == "ascii_word" and units[next_ui].char_start <= upper:
                    cursor_end = unit.char_end
                    ui += 1
                    continue
                break
            if unit.kind == "punct":
                left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
                right_char = _peek_unit_first_char(units, ui + 1)
                if is_name_joiner(unit.text, left_char, right_char):
                    cursor_end = unit.char_end
                    ui += 1
                    continue
            break
        return max(cursor, cursor_end)

    def _find_next_component_clue(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
        for index in range(search_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start < cursor:
                continue
            if clue.attr_type == PIIAttributeType.NAME and clue.role in _NAME_COMPONENT_ROLES:
                return (index, clue)
        return None

    def _find_next_right_blocker(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
        for index in range(search_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start < cursor:
                continue
            if self._is_name_blocker(clue):
                return (index, clue)
        return None

    def _has_active_stop_overlap(self, cursor: int) -> bool:
        for clue in self.context.clues:
            if clue.start < cursor < clue.end and self._is_name_blocker(clue):
                return True
        return False

    def _is_name_blocker(self, clue: Clue) -> bool:
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR}:
            return True
        if clue.attr_type is None:
            return False
        return clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES

    def _gap_allows_single_plain_word(self, start: int, end: int) -> bool:
        if end <= start:
            return True
        if self._span_has_any_clue_overlap(start, end):
            return False
        units = self.context.stream.units
        word_count = 0
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= end:
                break
            if unit.kind == "space":
                ui += 1
                continue
            if unit.kind == "ascii_word":
                word_count += 1
                if word_count > 1:
                    return False
                ui += 1
                continue
            return False
        return True

    def _previous_plain_ascii_word(self, start: int) -> tuple[int, int] | None:
        if start <= 0 or not self.context.stream.units:
            return None
        units = self.context.stream.units
        ui = _unit_index_left_of(self.context.stream, start)
        while ui >= 0 and units[ui].kind == "space":
            ui -= 1
        if ui < 0 or units[ui].kind != "ascii_word":
            return None
        word = units[ui]
        for gap_index in range(ui + 1, len(units)):
            gap_unit = units[gap_index]
            if gap_unit.char_start >= start:
                break
            if gap_unit.kind != "space":
                return None
        return (word.char_start, word.char_end)

    def _span_has_any_clue_overlap(self, start: int, end: int) -> bool:
        for clue in self.context.clues:
            if clue.start < end and clue.end > start:
                return True
        return False

    def _span_has_blocker(self, start: int, end: int) -> bool:
        for clue in self.context.clues:
            if clue.start < end and clue.end > start and self._is_name_blocker(clue):
                return True
        return False

    def _name_clues_in_span(self, start: int, end: int) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES:
                continue
            if clue.start < end and clue.end > start:
                matches.append((index, clue))
        return matches

    def _negative_clue_ids_in_span(self, start: int, end: int) -> set[str]:
        negative_ids: set[str] = set()
        for clue in self.context.clues:
            if clue.role != ClueRole.NEGATIVE:
                continue
            if clue.start < end and clue.end > start:
                negative_ids.add(clue.clue_id)
        return negative_ids

    def _meets_commit_threshold(
        self,
        *,
        candidate_text: str,
        clue_count: int,
        negative_count: int,
        name_clues: list[tuple[int, Clue]],
    ) -> bool:
        if negative_count > 0:
            return False
        if self.context.protection_level == ProtectionLevel.STRONG:
            return clue_count >= 2 or len(candidate_text) > 1
        if self.context.protection_level == ProtectionLevel.BALANCED:
            if clue_count != 1 or len(candidate_text) <= 1 or len(name_clues) != 1:
                return False
            only_clue = name_clues[0][1]
            return only_clue.role == ClueRole.GIVEN_NAME and only_clue.source_kind.startswith("dictionary_")
        return clue_count >= 2


def _extend_name_boundary(
    stream: StreamInput,
    start: int,
    end: int,
    clues: tuple[Clue, ...],
    next_clue_index: int,
) -> int:
    raw_text = stream.text
    units = stream.units
    if not units or end >= len(raw_text):
        return end

    upper = len(raw_text)
    for index in range(next_clue_index, len(clues)):
        clue = clues[index]
        if _is_stop_control_clue(clue):
            upper = min(upper, clue.start)
            break
        if is_control_clue(clue):
            continue
        if clue.attr_type != PIIAttributeType.NAME:
            upper = min(upper, clue.start)
            break

    if start < len(raw_text) and _shared_is_cjk(raw_text[start]):
        return _extend_name_right_zh(raw_text, units, stream.char_to_unit, start, end, upper)
    return _extend_name_right_en(raw_text, units, stream.char_to_unit, start, end, upper)


def _extend_name_right_zh(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    upper: int,
) -> int:
    cjk_count = sum(1 for index in range(start, end) if _shared_is_cjk(raw_text[index]))
    cursor_end = end
    ui = char_to_unit[end - 1] + 1 if end > 0 and end <= len(char_to_unit) else len(units)
    while ui < len(units) and cjk_count < 4:
        unit = units[ui]
        if unit.char_start >= upper:
            break
        if unit.kind == "cjk_char":
            cjk_count += 1
            cursor_end = unit.char_end
            ui += 1
            continue
        if unit.kind == "punct":
            left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if is_name_joiner(unit.text, left_char, right_char):
                cursor_end = unit.char_end
                ui += 1
                continue
        break
    return max(end, cursor_end)


def _extend_name_right_en(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    upper: int,
) -> int:
    cursor_end = end
    ui = char_to_unit[end - 1] + 1 if end > 0 and end <= len(char_to_unit) else len(units)
    while ui < len(units):
        unit = units[ui]
        if unit.char_start >= upper:
            break
        if unit.char_end - start > 80:
            break
        if unit.kind == "ascii_word":
            cursor_end = unit.char_end
            ui += 1
            continue
        if unit.kind == "space":
            next_ui = ui + 1
            while next_ui < len(units) and units[next_ui].kind == "space":
                next_ui += 1
            if next_ui < len(units) and units[next_ui].kind == "ascii_word" and units[next_ui].char_start < upper:
                cursor_end = unit.char_end
                ui += 1
                continue
            break
        if unit.kind == "punct":
            left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if is_name_joiner(unit.text, left_char, right_char):
                cursor_end = unit.char_end
                ui += 1
                continue
        break
    return max(end, cursor_end)


def _extend_name_boundary_left(
    stream: StreamInput,
    start: int,
    end: int,
    clues: tuple[Clue, ...],
    clue_index: int,
) -> int:
    raw_text = stream.text
    units = stream.units
    if not units or start <= 0:
        return start

    lower = 0
    for index in range(clue_index - 1, -1, -1):
        clue = clues[index]
        if _is_stop_control_clue(clue):
            lower = clue.end
            break
        if is_control_clue(clue):
            continue
        if clue.attr_type != PIIAttributeType.NAME:
            lower = clue.end
            break

    if _shared_is_cjk(raw_text[start - 1]):
        return _extend_name_left_zh(raw_text, units, stream.char_to_unit, start, end, lower)
    return _extend_name_left_en(raw_text, units, stream.char_to_unit, start, end, lower)


def _extend_name_left_zh(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    lower: int,
) -> int:
    cjk_count = sum(1 for index in range(start, end) if _shared_is_cjk(raw_text[index]))
    cursor_start = start
    ui = char_to_unit[start] - 1 if start < len(char_to_unit) else -1
    while ui >= 0 and cjk_count < 4:
        unit = units[ui]
        if unit.char_end <= lower:
            break
        if unit.kind == "cjk_char":
            cjk_count += 1
            cursor_start = unit.char_start
            ui -= 1
            continue
        if unit.kind == "punct":
            left_char = _peek_unit_last_char(units, ui - 1)
            right_char = raw_text[unit.char_end] if unit.char_end < len(raw_text) else None
            if is_name_joiner(unit.text, left_char, right_char):
                cursor_start = unit.char_start
                ui -= 1
                continue
        break
    return min(start, cursor_start)


def _extend_name_left_en(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    lower: int,
) -> int:
    cursor_start = start
    ui = char_to_unit[start] - 1 if start < len(char_to_unit) else -1
    while ui >= 0:
        unit = units[ui]
        if unit.char_end <= lower:
            break
        if end - unit.char_start > 80:
            break
        if unit.kind == "ascii_word":
            cursor_start = unit.char_start
            ui -= 1
            continue
        if unit.kind == "space":
            prev_ui = ui - 1
            while prev_ui >= 0 and units[prev_ui].kind == "space":
                prev_ui -= 1
            if prev_ui >= 0 and units[prev_ui].kind == "ascii_word" and units[prev_ui].char_end > lower:
                cursor_start = unit.char_start
                ui -= 1
                continue
            break
        if unit.kind == "punct":
            left_char = _peek_unit_last_char(units, ui - 1)
            right_char = raw_text[unit.char_end] if unit.char_end < len(raw_text) else None
            if is_name_joiner(unit.text, left_char, right_char):
                cursor_start = unit.char_start
                ui -= 1
                continue
        break
    return min(start, cursor_start)


def _peek_unit_first_char(units: tuple[StreamUnit, ...], ui: int) -> str | None:
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[0] if units[ui].text else None


def _peek_unit_last_char(units: tuple[StreamUnit, ...], ui: int) -> str | None:
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[-1] if units[ui].text else None
