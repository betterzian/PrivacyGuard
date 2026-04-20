"""英文姓名 stack。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueFamily, ClueRole, StreamUnit
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _label_seed_start_char,
    _unit_index_at_or_after,
    _unit_index_left_of,
)
from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack, _peek_unit_first_char
from privacyguard.infrastructure.pii.detector.stacks.base import StackRun
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner


class EnNameStack(BaseNameStack):
    """英文姓名 stack。"""

    STACK_LOCALE = "en"

    def need_break(
        self,
        subject: Clue | StreamUnit,
        *,
        next_unit: StreamUnit | None = None,
        prev_unit: StreamUnit | None = None,
        upper: int | None = None,
        lower: int | None = None,
        left_char: str | None = None,
        right_char: str | None = None,
    ) -> bool:
        if isinstance(subject, Clue):
            return subject.role in {ClueRole.BREAK, ClueRole.NEGATIVE}
        if subject.kind == "ascii_word":
            return False
        if subject.kind == "space":
            if next_unit is not None:
                return not (
                    next_unit.kind == "ascii_word" and (upper is None or next_unit.char_start < upper)
                )
            if prev_unit is not None:
                return not (
                    prev_unit.kind == "ascii_word" and (lower is None or prev_unit.char_end > lower)
                )
            return True
        if subject.kind == "punct":
            return not is_name_joiner(subject.text, left_char, right_char)
        return True

    def run(self) -> StackRun | None:
        self._name_pending_challenge: tuple[int, int] | None = None
        if self.clue.strength == ClaimStrength.HARD and self.clue.role not in {
            ClueRole.FAMILY_NAME,
            ClueRole.GIVEN_NAME,
        }:
            return self._build_direct_run()
        if self.clue.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
            return self._build_name_run(start=self.clue.start, end=self.clue.end)
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            start = _label_seed_start_char(self.context.stream, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._expand_seed_right(
                start=start,
                end=start,
                search_index=self.clue_index + 1,
                ignore_negative=True,
            )
            return self._build_name_run(start=start, end=end)
        if self.clue.role == ClueRole.FAMILY_NAME:
            end = self._expand_seed_right(
                start=self.clue.start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
            )
            return self._build_name_run(start=self.clue.start, end=end)
        if self.clue.role == ClueRole.GIVEN_NAME:
            start = self._extend_given_left_en(self.clue.start)
            end = self._extend_given_chain_right_en(
                start=start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
            )
            return self._build_name_run(start=start, end=end)
        return None

    def _expand_seed_right(
        self,
        *,
        start: int,
        end: int,
        search_index: int,
        ignore_negative: bool = False,
    ) -> int:
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor, ignore_negative=ignore_negative):
                return cursor

            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(
                cursor,
                next_index,
                ignore_negative=ignore_negative,
            )
            next_negative_start = self._next_negative_start_char(cursor, ignore_negative=ignore_negative)

            plain_limit = len(self.context.stream.text)
            if next_component is not None:
                plain_limit = next_component[1].start
            if next_blocker is not None and next_blocker[1].start < plain_limit:
                plain_limit = next_blocker[1].start
            if next_negative_start is not None and next_negative_start < plain_limit:
                plain_limit = next_negative_start

            scanned = self._scan_plain_right(start=start, cursor=cursor, upper=plain_limit)
            cursor = scanned
            if cursor < plain_limit:
                return cursor

            if (
                next_blocker is not None
                and next_blocker[1].start == cursor
                and next_blocker[1].attr_type == PIIAttributeType.ADDRESS
            ):
                # 同址遇到 ADDRESS blocker：先保守停在 blocker 左侧，交由 parser 挑战裁决。
                extended_end = next_component[1].end if next_component is not None and next_component[1].start == cursor else cursor
                self._name_pending_challenge = (next_blocker[0], extended_end)
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
            return self._extend_given_chain_right_en(
                start=start,
                end=cursor,
                search_index=next_index,
                ignore_negative=ignore_negative,
            )

    def _extend_given_left_en(self, start: int) -> int:
        cursor = start
        while True:
            previous = self._find_previous_name_piece_en(cursor)
            if previous is None:
                return cursor
            piece_start, piece_end, _kind = previous
            if self._span_has_blocker(piece_end, cursor):
                return cursor
            cursor = piece_start

    def _extend_given_chain_right_en(
        self,
        start: int,
        end: int,
        search_index: int,
        *,
        ignore_negative: bool = False,
    ) -> int:
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor, ignore_negative=ignore_negative):
                return cursor
            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(
                cursor,
                next_index,
                ignore_negative=ignore_negative,
            )
            next_negative_start = self._next_negative_start_char(cursor, ignore_negative=ignore_negative)
            if next_component is None:
                return cursor
            component_index, component = next_component
            if not self._is_en_name_component_clue(component):
                return cursor
            if next_blocker is not None and next_blocker[1].start < component.start:
                return cursor
            if next_negative_start is not None and next_negative_start < component.start:
                return cursor
            if not self._gap_allows_name_piece_en(cursor, component.start):
                return cursor
            cursor = component.end
            next_index = component_index + 1

    def _scan_plain_right(self, *, start: int, cursor: int, upper: int) -> int:
        if upper <= cursor:
            return cursor
        raw_text = self.context.stream.text
        units = self.context.stream.units
        if not units or cursor >= len(raw_text):
            return cursor

        cursor_end = cursor
        ui = _unit_index_at_or_after(self.context.stream, cursor)
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= upper:
                break
            if unit.char_end - start > 80:
                break
            if unit.kind == "ascii_word":
                if not self._is_capitalized_ascii_name_unit(unit):
                    break
                cursor_end = unit.char_end
                ui += 1
                continue
            if unit.kind == "space":
                next_ui = ui + 1
                while next_ui < len(units) and units[next_ui].kind == "space":
                    next_ui += 1
                if (
                    next_ui < len(units)
                    and units[next_ui].kind == "ascii_word"
                    and units[next_ui].char_start <= upper
                    and self._is_capitalized_ascii_name_unit(units[next_ui])
                ):
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

    def _is_name_blocker(self, clue: Clue, *, ignore_negative: bool = False) -> bool:
        if self._is_en_name_control_clue(clue):
            return True
        return super()._is_name_blocker(clue, ignore_negative=ignore_negative)

    def _gap_allows_name_piece_en(self, start: int, end: int) -> bool:
        if end <= start:
            return True
        units = self.context.stream.units
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= end:
                break
            if unit.kind == "space":
                ui += 1
                continue
            if unit.kind == "punct":
                left_char = self.context.stream.text[unit.char_start - 1] if unit.char_start > 0 else None
                right_char = _peek_unit_first_char(units, ui + 1)
                if is_name_joiner(unit.text, left_char, right_char):
                    ui += 1
                    continue
                return False
            overlapping_clue = self._find_name_piece_clue_covering(unit.char_start, unit.char_end)
            if overlapping_clue is not None:
                if not self._is_en_name_component_clue(overlapping_clue):
                    return False
                ui += 1
                continue
            if unit.kind == "ascii_word":
                if not self._is_capitalized_ascii_name_unit(unit):
                    return False
                ui += 1
                continue
            return False
        return True

    def _find_previous_name_piece_en(self, start: int) -> tuple[int, int, str] | None:
        if start <= 0 or not self.context.stream.units:
            return None
        units = self.context.stream.units
        ui = _unit_index_left_of(self.context.stream, start)
        while ui >= 0 and units[ui].kind == "space":
            ui -= 1
        if ui < 0:
            return None
        unit = units[ui]
        if unit.kind == "punct":
            left_char = self.context.stream.text[unit.char_start - 1] if unit.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if is_name_joiner(unit.text, left_char, right_char):
                return None
        for gap_index in range(ui + 1, len(units)):
            gap_unit = units[gap_index]
            if gap_unit.char_start >= start:
                break
            if gap_unit.kind == "space":
                continue
            if gap_unit.kind == "punct":
                left_char = self.context.stream.text[gap_unit.char_start - 1] if gap_unit.char_start > 0 else None
                right_char = _peek_unit_first_char(units, gap_index + 1)
                if is_name_joiner(gap_unit.text, left_char, right_char):
                    continue
            return None
        overlapping_clue = self._find_name_piece_clue_covering(unit.char_start, unit.char_end)
        if overlapping_clue is not None:
            if self._is_en_name_component_clue(overlapping_clue):
                return (unit.char_start, unit.char_end, "clue")
            return None
        if unit.kind != "ascii_word":
            return None
        if not self._is_capitalized_ascii_name_unit(unit):
            return None
        return (unit.char_start, unit.char_end, "unit")

    def _find_name_piece_clue_covering(self, start: int, end: int) -> Clue | None:
        clues = self.context.clues
        best_match: Clue | None = None
        best_len = -1
        for clue in clues:
            if clue.end <= start or clue.start >= end:
                continue
            if clue.start <= start and clue.end >= end:
                if best_match is None or (clue.end - clue.start) < best_len or best_len < 0:
                    best_match = clue
                    best_len = clue.end - clue.start
        return best_match

    def _is_en_name_component_clue(self, clue: Clue) -> bool:
        return clue.attr_type == PIIAttributeType.NAME and clue.role in {
            ClueRole.GIVEN_NAME,
            ClueRole.FAMILY_NAME,
        }

    def _is_capitalized_ascii_name_unit(self, unit: StreamUnit) -> bool:
        if unit.kind != "ascii_word":
            return False
        text = unit.text.strip()
        if not text:
            return False
        first_char = text[0]
        return first_char.isascii() and first_char.isalpha() and first_char.isupper()

    def _is_en_name_control_clue(self, clue: Clue) -> bool:
        if clue.family != ClueFamily.CONTROL or clue.attr_type is not None:
            return False
        values = clue.source_metadata.get("control_kind")
        return bool(values) and values[0] == "copula_en"
