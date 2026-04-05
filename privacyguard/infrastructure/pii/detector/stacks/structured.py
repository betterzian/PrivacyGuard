"""结构化属性 stack。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import ClueRole
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun, _build_hard_candidate
from privacyguard.infrastructure.pii.detector.stacks.common import is_control_clue
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break


class StructuredBaseStack(BaseStack):
    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()
        if self.clue.role != ClueRole.LABEL:
            return None
        hard_clue, hard_index = self._find_bound_hard_clue()
        if hard_clue is None:
            return None
        candidate = _build_hard_candidate(hard_clue, self.context.stream.source)
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata, {"bound_label_clue_ids": [self.clue.clue_id]})
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id, hard_clue.clue_id},
            handled_label_clue_ids={self.clue.clue_id},
            next_index=hard_index + 1,
        )

    def _find_bound_hard_clue(self) -> tuple[object | None, int]:
        raw_text = self.context.stream.text
        cursor = self.clue.end
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if is_control_clue(clue):
                cursor = max(cursor, clue.end)
                continue
            gap_text = raw_text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return (None, -1)
            if clue.role == ClueRole.HARD and clue.attr_type == self.clue.attr_type:
                return (clue, index)
            if clue.role in {ClueRole.LABEL, ClueRole.HARD} and clue.attr_type != self.clue.attr_type:
                return (None, -1)
            cursor = max(cursor, clue.end)
        return (None, -1)


class EmailStack(StructuredBaseStack):
    pass


class PhoneStack(StructuredBaseStack):
    pass


class IdNumberStack(StructuredBaseStack):
    pass


class CardNumberStack(StructuredBaseStack):
    pass


class BankAccountStack(StructuredBaseStack):
    pass


class PassportStack(StructuredBaseStack):
    pass


class DriverLicenseStack(StructuredBaseStack):
    pass


class NumericStack(StructuredBaseStack):
    pass
