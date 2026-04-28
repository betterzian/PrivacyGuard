"""英文姓名 stack。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueFamily, ClueRole, StreamUnit
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _family_value_floor_char,
    _floor_clamped_label_seed_start_char,
    _starter_is_before_family_value_floor,
    _unit_index_at_or_after,
    _unit_index_left_of,
)
from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack, _peek_unit_first_char
from privacyguard.infrastructure.pii.detector.stacks.base import PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.zh_name_rules import (
    apply_negative_overlap_strength,
    claim_strength_meets_protection,
    collect_blocking_overlaps,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner


def _is_generic_alnum_clue(clue: Clue) -> bool:
    """英文姓名扩张只忽略 scanner 产生的通用 ALNUM 片段。"""
    return (
        clue.family == ClueFamily.STRUCTURED
        and clue.attr_type == PIIAttributeType.ALNUM
        and clue.source_kind == "extract_alnum_fragment"
        and clue.role == ClueRole.VALUE
    )


class EnNameStack(BaseNameStack):
    """英文姓名 stack。"""

    STACK_LOCALE = "en"

    def _value_floor_char(self) -> int:
        """返回 NAME 当前生效的 value 起点下界。"""
        return _family_value_floor_char(self.context, ClueFamily.NAME)

    def _starter_is_before_value_floor(self) -> bool:
        """非 LABEL/START 起栈不得从已锁住的 value 区间左侧开始。"""
        return _starter_is_before_family_value_floor(self.context, self.clue, ClueFamily.NAME)

    def run(self) -> StackRun | None:
        if self._starter_is_before_value_floor():
            return None
        if self.clue.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
            return self._attach_name_address_pending_challenge(
                self._build_name_run(start=self.clue.start, end=self.clue.end)
            )
        if self.clue.strength == ClaimStrength.HARD and self.clue.role not in {
            ClueRole.FAMILY_NAME,
            ClueRole.GIVEN_NAME,
        }:
            return self._attach_name_address_pending_challenge(self._build_direct_run())
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            start = _floor_clamped_label_seed_start_char(self.context, ClueFamily.NAME, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._expand_name_chain_right(
                start=start,
                end=start,
                search_index=self.clue_index + 1,
                ignore_negative=True,
            )
            return self._attach_name_address_pending_challenge(self._build_name_run(start=start, end=end))
        if self.clue.role in {ClueRole.GIVEN_NAME, ClueRole.FAMILY_NAME}:
            start = self._extend_name_left_en(self.clue.start)
            end = self._expand_name_chain_right(
                start=start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
            )
            return self._attach_name_address_pending_challenge(self._build_name_run(start=start, end=end))
        return None

    def _should_skip_commit_gate(self) -> bool:
        return False

    def _expand_name_chain_right(
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

            if next_component is None or next_component[1].start != cursor:
                return cursor

            component_index, component = next_component
            cursor = component.end
            next_index = component_index + 1
            continue

    def _attach_name_address_pending_challenge(self, run: StackRun | None) -> StackRun | None:
        """英文姓名与中文路径对齐：先产出完整 NAME，再交给 parser 做地址冲突裁决。"""
        if run is None:
            return None
        overlap_index = self._first_address_overlap_clue_index(run.candidate.start, run.candidate.end)
        if overlap_index is None:
            return run
        run.pending_challenge = PendingChallenge(
            clue_index=overlap_index,
            extended_candidate=run.candidate,
            extended_last_unit=run.candidate.unit_last,
            challenge_kind="name_address_conflict",
        )
        return run

    def _first_address_overlap_clue_index(self, start: int, end: int) -> int | None:
        for index, clue in enumerate(self.context.clues):
            if clue.start >= end:
                break
            if clue.attr_type == PIIAttributeType.ADDRESS and clue.end > start:
                return index
        return None

    def _extend_name_left_en(self, start: int) -> int:
        cursor = start
        floor_char = self._value_floor_char()
        while True:
            previous = self._find_previous_name_piece_en(cursor)
            if previous is None:
                return cursor
            piece_start, piece_end, _kind = previous
            if piece_start < floor_char:
                return cursor
            if self._span_has_blocker(piece_end, cursor):
                return cursor
            cursor = piece_start

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
                overlapping_clue = self._find_name_piece_clue_covering(unit.char_start, unit.char_end)
                if overlapping_clue is not None:
                    if not self._is_en_name_component_clue(overlapping_clue):
                        break
                    cursor_end = unit.char_end
                    ui += 1
                    continue
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
                ):
                    overlapping_clue = self._find_name_piece_clue_covering(
                        units[next_ui].char_start,
                        units[next_ui].char_end,
                    )
                    if overlapping_clue is not None:
                        if not self._is_en_name_component_clue(overlapping_clue):
                            break
                        cursor_end = unit.char_end
                        ui += 1
                        continue
                    if not self._is_capitalized_ascii_name_unit(units[next_ui]):
                        break
                    cursor_end = unit.char_end
                    ui += 1
                    continue
                break
            if unit.kind == "inline_gap":
                if self._inline_gap_allows_next_name_block(ui, upper):
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
        if _is_generic_alnum_clue(clue):
            return False
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
        while ui >= 0:
            while ui >= 0 and units[ui].kind == "space":
                ui -= 1
            if ui < 0:
                return None
            unit = units[ui]
            if unit.kind == "inline_gap":
                if not self._inline_gap_allows_previous_name_block(ui):
                    return None
                ui -= 1
                continue
            if unit.kind != "punct":
                break
            left_char = self.context.stream.text[unit.char_start - 1] if unit.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if not is_name_joiner(unit.text, left_char, right_char):
                return None
            ui -= 1
        if ui < 0:
            return None
        unit = units[ui]
        for gap_index in range(ui + 1, len(units)):
            gap_unit = units[gap_index]
            if gap_unit.char_start >= start:
                break
            if gap_unit.kind == "space":
                continue
            if gap_unit.kind == "inline_gap":
                if self._inline_gap_allows_next_name_block(gap_index, start):
                    continue
                return None
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
            if not _is_generic_alnum_clue(overlapping_clue):
                return None
        if unit.kind != "ascii_word":
            return None
        if not self._is_capitalized_ascii_name_unit(unit):
            return None
        return (unit.char_start, unit.char_end, "unit")

    def _inline_gap_allows_next_name_block(self, gap_unit_index: int, upper: int) -> bool:
        """跨 inline_gap 时，右侧 block 必须已经有英文 NAME clue。"""
        span = self._right_block_span_after_inline_gap(gap_unit_index, upper)
        return span is not None and self._span_contains_en_name_component_clue(*span)

    def _inline_gap_allows_previous_name_block(self, gap_unit_index: int) -> bool:
        """向左跨 inline_gap 时，左侧 block 必须已经有英文 NAME clue。"""
        span = self._left_block_span_before_inline_gap(gap_unit_index)
        return span is not None and self._span_contains_en_name_component_clue(*span)

    def _right_block_span_after_inline_gap(self, gap_unit_index: int, upper: int) -> tuple[int, int] | None:
        units = self.context.stream.units
        scan = gap_unit_index + 1
        while scan < len(units) and units[scan].kind == "space":
            scan += 1
        if scan >= len(units) or units[scan].char_start > upper:
            return None
        start = units[scan].char_start
        end = units[scan].char_end
        while scan < len(units):
            unit = units[scan]
            if unit.char_start > upper or unit.kind in {"inline_gap", "ocr_break"}:
                break
            if unit.kind != "space":
                end = unit.char_end
            scan += 1
        return (start, end) if end > start else None

    def _left_block_span_before_inline_gap(self, gap_unit_index: int) -> tuple[int, int] | None:
        units = self.context.stream.units
        scan = gap_unit_index - 1
        while scan >= 0 and units[scan].kind == "space":
            scan -= 1
        if scan < 0:
            return None
        end = units[scan].char_end
        start = units[scan].char_start
        while scan >= 0:
            unit = units[scan]
            if unit.kind in {"inline_gap", "ocr_break"}:
                break
            if unit.kind != "space":
                start = unit.char_start
            scan -= 1
        return (start, end) if end > start else None

    def _span_contains_en_name_component_clue(self, start: int, end: int) -> bool:
        return any(
            clue.end > start and clue.start < end and self._is_en_name_component_clue(clue)
            for clue in self.context.clues
        )

    def _find_name_piece_clue_covering(self, start: int, end: int) -> Clue | None:
        clues = self.context.clues
        best_match: Clue | None = None
        best_len = -1
        best_name_match: Clue | None = None
        best_name_len = -1
        for clue in clues:
            if clue.end <= start or clue.start >= end:
                continue
            if clue.start <= start and clue.end >= end:
                clue_len = clue.end - clue.start
                if self._is_en_name_component_clue(clue):
                    if best_name_match is None or clue_len < best_name_len or best_name_len < 0:
                        best_name_match = clue
                        best_name_len = clue_len
                    continue
                if best_match is None or clue_len < best_len or best_len < 0:
                    best_match = clue
                    best_len = clue_len
        return best_name_match or best_match

    def _is_en_name_component_clue(self, clue: Clue) -> bool:
        return clue.attr_type == PIIAttributeType.NAME and clue.role in {
            ClueRole.GIVEN_NAME,
            ClueRole.FAMILY_NAME,
            ClueRole.FULL_NAME,
            ClueRole.ALIAS,
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

    def _should_commit_candidate(
        self,
        *,
        start: int,
        end: int,
        candidate_unit_start: int,
        candidate_unit_last: int,
        candidate_text: str,
        name_clues: list[tuple[int, Clue]],
        has_negative_overlap: bool,
    ) -> bool:
        del candidate_unit_start, candidate_unit_last, has_negative_overlap
        if not candidate_text:
            return False
        current_strength = self._resolve_claim_strength(name_clues=name_clues)
        overlaps = collect_blocking_overlaps(
            candidate_start=start,
            candidate_end=end,
            candidate_raw_text=candidate_text,
            negative_clues=self._commit_negative_clues(),
            other_clues=(),
        )
        final_strength = apply_negative_overlap_strength(overlaps, effective_strength=current_strength)
        if final_strength is None or not claim_strength_meets_protection(final_strength, self.context.protection_level):
            return False
        if name_clues:
            return True
        return self._capitalized_body_token_count(start, end) >= 2

    def _capitalized_body_token_count(self, start: int, end: int) -> int:
        if end <= start or not self.context.stream.units or not self.context.stream.char_to_unit:
            return 0
        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, start, end)
        count = 0
        for ui in range(unit_start, unit_last + 1):
            unit = self.context.stream.units[ui]
            if unit.kind == "space":
                continue
            if unit.kind == "ascii_word" and self._is_capitalized_ascii_name_unit(unit):
                count += 1
                continue
            return 0
        return count
