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
class PendingChallenge:
    """AddressStack 对某段可疑片段不确定时，请求 parser 先运行 StructuredStack 判定。

    parser 根据 StructuredStack 返回的 attr_type 决定采用保守候选还是扩展候选。
    """
    clue_index: int
    """待判定 clue 在 context.clues 中的索引。"""
    extended_candidate: CandidateDraft
    """若判定为通用数字（NUMERIC/ALNUM）则使用此扩展候选。"""
    extended_consumed_ids: set[str]
    """扩展候选对应的 consumed_ids。"""
    extended_next_index: int
    """扩展候选对应的 next_index。"""
    challenge_kind: str = "digit_tail"
    """挑战类型，用于调试与后续扩展。"""
    cached_fragment_text: str = ""
    """防御性缓存的原始片段文本。"""
    cached_normalized_fragment: str = ""
    """防御性缓存的归一化片段文本。"""


@dataclass(slots=True)
class StackRun:
    attr_type: PIIAttributeType
    candidate: CandidateDraft
    consumed_ids: set[str]
    handled_label_clue_ids: set[str] = field(default_factory=set)
    next_index: int = 0
    pending_challenge: PendingChallenge | None = None
    #: 地址 run 内已「跨过」的 NAME/ORG clue：parser 不得对其再跑挑战栈，且不得写入 consumed_ids。
    suppress_challenger_clue_ids: frozenset[str] = field(default_factory=frozenset)


def _build_value_candidate(clue: Clue, source: PIISourceType) -> CandidateDraft:
    """从高置信 VALUE 线索构建候选。hard_source / placeholder 从 source_metadata 读取。"""
    metadata = {key: list(values) for key, values in clue.source_metadata.items()}
    hard_source = (metadata.get("hard_source") or ["regex"])[0]
    metadata = merge_metadata(
        metadata,
        {"matched_by": [clue.source_kind], "hard_source": [str(hard_source)]},
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
            suppress_challenger_clue_ids=run.suppress_challenger_clue_ids,
        )

    def _value_locale(self) -> str:
        """按当前 clue 自身文字判断语言。"""
        text = self.clue.text or self.context.stream.text[self.clue.start:self.clue.end]
        if any("\u4e00" <= ch <= "\u9fff" for ch in text):
            return "zh"
        return "en"

    def _build_direct_run(self) -> StackRun | None:
        """高置信 VALUE 线索直接产出候选。"""
        if self.clue.attr_type is None:
            return None
        candidate = _build_value_candidate(self.clue, self.context.stream.source)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
            suppress_challenger_clue_ids=frozenset(),
        )
