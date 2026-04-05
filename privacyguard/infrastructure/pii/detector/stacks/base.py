"""所有 stack 共用的运行骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import trim_candidate
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, Clue, ClueRole, StreamInput
from privacyguard.infrastructure.pii.detector.stacks.common import _skip_separators, _unit_char_end, _unit_char_start


class StackContextLike(Protocol):
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel
    clues: tuple[Clue, ...]


@dataclass(slots=True)
class StackRun:
    attr_type: PIIAttributeType
    candidate: CandidateDraft
    consumed_ids: set[str]
    handled_label_clue_ids: set[str] = field(default_factory=set)
    next_index: int = 0


def _build_hard_candidate(clue: Clue, source: PIISourceType) -> CandidateDraft:
    metadata = {key: list(values) for key, values in clue.source_metadata.items()}
    metadata = merge_metadata(
        metadata,
        {"matched_by": [clue.source_kind], "hard_source": [str(clue.hard_source or "regex")]},
    )
    return CandidateDraft(
        attr_type=clue.attr_type,
        start=clue.start,
        end=clue.end,
        unit_start=clue.unit_start,
        unit_end=clue.unit_end,
        text=clue.text,
        source=source,
        source_kind=clue.source_kind,
        claim_strength=ClaimStrength.HARD,
        metadata=metadata,
    )


@dataclass(slots=True)
class BaseStack:
    clue: Clue
    clue_index: int
    context: StackContextLike

    def run(self) -> StackRun | None:
        raise NotImplementedError

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """被更高优先级候选抢占后，尝试做默认文本级回缩。"""
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
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def _value_locale(self) -> str:
        """按 seed 即将处理的值判断语言。"""
        raw_text = self.context.stream.text
        if self.clue.role in {ClueRole.LABEL, ClueRole.START, ClueRole.KEY}:
            pos = _skip_separators(raw_text, self.clue.end)
            if pos < len(raw_text) and "\u4e00" <= raw_text[pos] <= "\u9fff":
                return "zh"
            return "en"
        text = self.clue.text
        if text and "\u4e00" <= text[0] <= "\u9fff":
            return "zh"
        return "en"

    def _build_hard_run(self) -> StackRun | None:
        if self.clue.attr_type is None:
            return None
        candidate = _build_hard_candidate(self.clue, self.context.stream.source)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
        )
