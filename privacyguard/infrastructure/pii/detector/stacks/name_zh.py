"""中文姓名 stack。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.lexicon_loader import load_zh_name_rules
from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack
from privacyguard.infrastructure.pii.detector.zh_name_rules import ZhNameCommitScorer


class ZhNameStack(BaseNameStack):
    """中文姓名 stack。"""

    STACK_LOCALE = "zh"

    def _should_commit_candidate(
        self,
        *,
        start: int,
        end: int,
        candidate_unit_start: int,
        candidate_unit_end: int,
        candidate_text: str,
        name_clues: list[tuple[int, Clue]],
        has_negative_overlap: bool,
    ) -> bool:
        if self.clue.role not in {ClueRole.LABEL, ClueRole.START} and has_negative_overlap:
            return False
        scorer = ZhNameCommitScorer(load_zh_name_rules())
        decision = scorer.evaluate(
            candidate_text=candidate_text,
            start=start,
            end=end,
            candidate_unit_start=candidate_unit_start,
            candidate_unit_end=candidate_unit_end,
            seed_clue=self.clue,
            protection_level=self.context.protection_level,
            name_clues=name_clues,
            negative_unit_marks=self.context.negative_unit_marks,
            has_negative_start=self.context.has_negative_start,
        )
        return decision.should_commit
