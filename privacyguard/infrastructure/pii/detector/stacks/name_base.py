"""姓名 stack 基类与姓名专属 helper。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.candidate_utils import NameComponentHint, build_name_candidate_from_value
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, ClueFamily, Clue, ClueRole, StreamInput, StreamUnit, strength_ge
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    ExpansionBreakPolicy,
    _char_span_to_unit_span,
    is_control_clue,
    need_break,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _is_cjk as _shared_is_cjk,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner
from privacyguard.infrastructure.pii.detector.zh_name_rules import claim_strength_meets_protection

_NAME_COMPONENT_ROLES = frozenset(
    {
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
    }
)


class BaseNameStack(BaseStack):
    """姓名检测 stack 基类。"""

    STACK_LOCALE = "zh"

    def shrink(self, run: StackRun, blocker_start: int, blocker_last: int) -> StackRun | None:
        """姓名候选被其他类型抢占后，尝试提交裁掉冲突区后的剩余片段。"""
        shrunk = super().shrink(run, blocker_start, blocker_last)
        if shrunk is None:
            return None
        candidate = shrunk.candidate
        name_clues = self._name_clues_in_span(candidate.start, candidate.end)
        if not name_clues:
            return None
        if not self._trimmed_candidate_has_value_beyond_family(candidate=candidate, name_clues=name_clues):
            return None
        if not self._should_commit_candidate(
            start=candidate.start,
            end=candidate.end,
            candidate_unit_start=candidate.unit_start,
            candidate_unit_last=candidate.unit_last,
            candidate_text=candidate.text,
            name_clues=name_clues,
            has_negative_overlap=self.context.has_negative_cover(candidate.unit_start, candidate.unit_last),
        ):
            return None
        return shrunk

    def _build_name_run(self, *, start: int, end: int) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        if end <= start:
            return None

        component_hint = self._effective_hint(start, end)
        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_name_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            component_hint=component_hint,
            unit_start=unit_start,
            unit_last=unit_last,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None

        name_clues = self._name_clues_in_span(start, end)
        has_negative_overlap = self.context.has_negative_cover(unit_start, unit_last)
        candidate.claim_strength = self._resolve_claim_strength(name_clues=name_clues)

        if self.clue.role not in {ClueRole.FULL_NAME, ClueRole.ALIAS} and not self._should_commit_candidate(
            start=start,
            end=end,
            candidate_unit_start=unit_start,
            candidate_unit_last=unit_last,
            candidate_text=candidate.text,
            name_clues=name_clues,
            has_negative_overlap=has_negative_overlap,
        ):
            return None

        last_name_index = max((index for index, _clue in name_clues), default=self.clue_index)
        run = StackRun(
            attr_type=PIIAttributeType.NAME,
            candidate=candidate,
            handled_label_clue_ids={self.clue.clue_id} if is_label_seed else set(),
            frontier_last_unit=candidate.unit_last,
        )
        pending = getattr(self, "_name_pending_challenge", None)
        if pending is not None:
            blocker_index, extended_end = pending
            if extended_end > end:
                extended_candidate = build_name_candidate_from_value(
                    source=self.context.stream.source,
                    value_text=self.context.stream.text[start:extended_end],
                    value_start=start,
                    value_end=extended_end,
                    source_kind=self.clue.source_kind,
                    component_hint=self._effective_hint(start, extended_end),
                    unit_start=unit_start,
                    unit_last=_char_span_to_unit_span(self.context.stream, start, extended_end)[1],
                    label_clue_id=self.clue.clue_id if is_label_seed else None,
                    label_driven=is_label_seed,
                )
                if extended_candidate is not None:
                    run.pending_challenge = PendingChallenge(
                        clue_index=blocker_index,
                        extended_candidate=extended_candidate,
                        extended_last_unit=extended_candidate.unit_last,
                        challenge_kind="name_same_start_blocker",
                    )
        return run

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
            # GIVEN_NAME 可能携带 MIDDLE 提示（字典来源区分）。
            hint_values = self.clue.source_metadata.get("name_component_hint")
            if hint_values and hint_values[0] == "middle":
                return NameComponentHint.MIDDLE
            return NameComponentHint.GIVEN
        if self.clue.role == ClueRole.ALIAS:
            return NameComponentHint.ALIAS
        if self.clue.role == ClueRole.FULL_NAME:
            return NameComponentHint.FULL
        # LABEL / START：检查 source_metadata 中是否有提示。
        hint_values = self.clue.source_metadata.get("name_component_hint")
        if hint_values:
            try:
                return NameComponentHint(hint_values[0])
            except ValueError:
                pass
        return NameComponentHint.FULL

    def _find_next_component_clue(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
        clues = self.context.clues
        for idx in range(max(0, search_index), len(clues)):
            clue = clues[idx]
            if clue.start >= cursor and clue.attr_type == PIIAttributeType.NAME and clue.role in _NAME_COMPONENT_ROLES:
                return (idx, clue)
        return None

    def _find_next_right_blocker(
        self,
        cursor: int,
        search_index: int,
        *,
        ignore_negative: bool = False,
    ) -> tuple[int, Clue] | None:
        clues = self.context.clues
        for index in range(max(0, search_index), len(clues)):
            clue = clues[index]
            if clue.start >= cursor and self._is_name_blocker(clue, ignore_negative=ignore_negative):
                return (index, clue)
        return None

    def _has_active_stop_overlap(self, cursor: int, *, ignore_negative: bool = False) -> bool:
        if not ignore_negative and self.context.has_negative_cover_left_of_char(cursor):
            return True
        for clue in self.context.clues:
            if clue.start < cursor < clue.end and self._is_name_blocker(
                clue, ignore_negative=ignore_negative,
            ):
                return True
        return False

    def _next_negative_start_char(self, cursor: int, *, ignore_negative: bool = False) -> int | None:
        if ignore_negative:
            return None
        return self.context.next_negative_start_char(cursor)

    def _is_name_blocker(self, clue: Clue, *, ignore_negative: bool = False) -> bool:
        if clue.role == ClueRole.NEGATIVE:
            return not ignore_negative
        if clue.role == ClueRole.BREAK:
            return True
        if clue.attr_type is None:
            return False
        return clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES

    def _span_has_any_clue_overlap(self, start: int, end: int) -> bool:
        return any(clue.end > start and clue.start < end for clue in self.context.clues)

    def _span_has_blocker(self, start: int, end: int) -> bool:
        return any(
            clue.end > start and clue.start < end and self._is_name_blocker(clue)
            for clue in self.context.clues
        )

    def _name_clues_in_span(self, start: int, end: int) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.start >= end:
                break
            if clue.attr_type == PIIAttributeType.NAME and clue.role in _NAME_COMPONENT_ROLES and clue.end > start:
                matches.append((index, clue))
        return matches

    def _trimmed_candidate_has_value_beyond_family(
        self,
        *,
        candidate: CandidateDraft,
        name_clues: list[tuple[int, Clue]],
    ) -> bool:
        """裁剪后的姓名若只剩 family 片段，则不单独提交。"""
        family_clues = [clue for _index, clue in name_clues if clue.role == ClueRole.FAMILY_NAME]
        if not family_clues:
            return True
        if any(clue.role != ClueRole.FAMILY_NAME for _index, clue in name_clues):
            return True
        max_family_len = max(len(str(clue.text).strip()) for clue in family_clues)
        return len(candidate.text) > max_family_len

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
        """默认姓名提交判定，供英文路径复用。"""
        del start, end, candidate_unit_start, candidate_unit_last
        current_strength = self._resolve_claim_strength(name_clues=name_clues)
        if not claim_strength_meets_protection(current_strength, self.context.protection_level):
            return False
        negative_exempt = self.clue.role in {ClueRole.LABEL, ClueRole.START}
        if has_negative_overlap and not negative_exempt:
            return False
        return bool(candidate_text)

    def _resolve_claim_strength(self, *, name_clues: list[tuple[int, Clue]]) -> ClaimStrength:
        """standalone 姓名候选继承参与 clue 中的最高强度。"""
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            return ClaimStrength.SOFT
        strongest = self.clue.strength
        for _index, clue in name_clues:
            if strength_ge(clue.strength, strongest):
                strongest = clue.strength
        return strongest


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
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE}:
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
        if unit.char_end - start > 80:
            break
        next_unit = units[ui + 1] if ui + 1 < len(units) else None
        left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
        right_char = _peek_unit_first_char(units, ui + 1)
        if need_break(
            policy=ExpansionBreakPolicy.NAME_EN_RIGHT_UNIT,
            flag=_unit_flag(unit),
            upper=upper,
            next_unit=next_unit,
            left_char=left_char,
            right_char=right_char,
        ):
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
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE}:
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
        if end - unit.char_start > 80:
            break
        prev_unit = units[ui - 1] if ui - 1 >= 0 else None
        left_char = _peek_unit_last_char(units, ui - 1)
        right_char = raw_text[unit.char_end] if unit.char_end < len(raw_text) else None
        if need_break(
            policy=ExpansionBreakPolicy.NAME_EN_LEFT_UNIT,
            flag=_unit_flag(unit),
            lower=lower,
            prev_unit=prev_unit,
            left_char=left_char,
            right_char=right_char,
        ):
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


def _unit_flag(unit: StreamUnit) -> str | None:
    if unit.kind == "ocr_break":
        return "OCR_BREAK"
    if unit.kind == "inline_gap":
        return "INLINE_GAP"
    if unit.kind == "space":
        return "SPACE"
    if unit.kind == "punct":
        return unit.text
    return None

