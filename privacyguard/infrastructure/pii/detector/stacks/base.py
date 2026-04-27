"""所有 stack 共用的运行骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from collections.abc import Sequence

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import trim_candidate
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    InspireEntry,
    StructuredAnchor,
    StreamInput,
    StreamUnit,
    UnitBucket,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_char_end, _unit_char_start


class StackContextLike(Protocol):
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel
    clues: tuple[Clue, ...]
    unit_index: tuple[UnitBucket, ...]
    negative_clues: tuple[Clue, ...]
    inspire_entries: tuple[InspireEntry, ...]
    recent_structured_anchor: StructuredAnchor | None

    def has_negative_cover(self, unit_start: int, unit_last: int, scopes: Sequence[str] | None = None) -> bool: ...

    def has_negative_start(self, unit_start: int, unit_last: int, scopes: Sequence[str] | None = None) -> bool: ...

    def is_negative_fully_covered(
        self,
        unit_start: int,
        unit_last: int,
        scopes: Sequence[str] | None = None,
    ) -> bool: ...

    def next_negative_start_char(self, char_index: int, scopes: Sequence[str] | None = None) -> int | None: ...

    def previous_negative_end_char(self, char_index: int, scopes: Sequence[str] | None = None) -> int | None: ...

    def has_negative_cover_left_of_char(self, char_index: int, scopes: Sequence[str] | None = None) -> bool: ...

    def effective_value_floor_char(self, family: ClueFamily) -> int: ...


@dataclass(slots=True)
class PendingChallenge:
    """AddressStack 对某段可疑片段不确定时，请求 parser 先运行 StructuredStack 判定。

    parser 根据 StructuredStack 返回的 attr_type 决定采用保守候选还是扩展候选。
    """
    clue_index: int
    """待判定 clue 在 context.clues 中的索引。"""
    extended_candidate: CandidateDraft
    """若判定为通用数字（NUM/ALNUM）则使用此扩展候选。"""
    extended_last_unit: int
    """扩展候选真实纳入路径的最右 unit。"""
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
    handled_label_clue_ids: set[str] = field(default_factory=set)
    frontier_last_unit: int = -1
    pending_challenge: PendingChallenge | None = None
    #: 地址 run 内已「跨过」的 NAME/ORG clue：parser 不得对其再跑挑战栈。
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
        unit_last=clue.unit_last,
        text=clue.text,
        source=source,
        source_kind=clue.source_kind,
        claim_strength=ClaimStrength.HARD,
        metadata=metadata,
        # 直接 hard clue 代表上游已给出明确类型；NUM/ALNUM 仍允许后续 validator/label
        # 继续细分，其余类型在 detector 主路径中视为高可信输出。
        attr_locked=clue.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM},
    )


@dataclass(slots=True)
class BaseStack:
    clue: Clue
    clue_index: int
    context: StackContextLike

    def run(self) -> StackRun | None:
        raise NotImplementedError

    def need_break(
        self,
        flag: str | None,
        *,
        next_unit: StreamUnit | None = None,
        prev_unit: StreamUnit | None = None,
        upper: int | None = None,
        lower: int | None = None,
        left_char: str | None = None,
        right_char: str | None = None,
    ) -> bool:
        """单步边界判定；仅返回是否应停止，由各 stack 覆写具体规则。"""
        del next_unit, prev_unit, upper, lower, left_char, right_char
        return flag not in {None, ",", "，", "SPACE", "INLINE_GAP"}

    def shrink(self, run: StackRun, blocker_start: int, blocker_last: int) -> StackRun | None:
        """被更高优先级候选抢占后，尝试做默认文本级回缩。"""
        candidate = run.candidate
        stream = self.context.stream
        if blocker_start <= candidate.unit_start:
            new_unit_start, new_unit_last = blocker_last + 1, candidate.unit_last
        elif blocker_last >= candidate.unit_last:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        else:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        if new_unit_last < new_unit_start:
            return None
        trimmed = trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_last),
            unit_start=new_unit_start,
            unit_last=new_unit_last,
        )
        if trimmed is None:
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            handled_label_clue_ids=run.handled_label_clue_ids,
            frontier_last_unit=trimmed.unit_last,
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
            frontier_last_unit=candidate.unit_last,
            suppress_challenger_clue_ids=frozenset(),
        )

    def _is_seed_negative_clue(self, clue: Clue) -> bool:
        """LABEL / START 视作语义负向；VALUE clue 不参与这条路径。"""
        return clue.attr_type is not None and clue.role in {ClueRole.LABEL, ClueRole.START}

    def _synthetic_inspire_negative_clues(self) -> tuple[Clue, ...]:
        """把 inspire 锚点投影成只用于重叠判定的伪 negative clue。"""
        negatives: list[Clue] = []
        raw_text = self.context.stream.text
        for inspire in self.context.inspire_entries:
            negatives.append(
                Clue(
                    clue_id=f"{inspire.clue_id}:inspire-negative",
                    family=ClueFamily.CONTROL,
                    role=ClueRole.NEGATIVE,
                    attr_type=inspire.attr_type,
                    strength=ClaimStrength.SOFT,
                    start=inspire.start,
                    end=inspire.end,
                    text=raw_text[inspire.start:inspire.end],
                    unit_start=inspire.unit_start,
                    unit_last=inspire.unit_last,
                    source_kind="inspire_negative",
                )
            )
        return tuple(negatives)

    def _semantic_negative_clues(
        self,
        *,
        include_inspire: bool,
    ) -> tuple[Clue, ...]:
        """收集 stack 级负向：显式 negative + seed，必要时再加 inspire。"""
        negatives: list[Clue] = list(self.context.negative_clues)
        negatives.extend(clue for clue in self.context.clues if self._is_seed_negative_clue(clue))
        if include_inspire:
            negatives.extend(self._synthetic_inspire_negative_clues())
        return tuple(negatives)

    def _has_semantic_negative_cover(
        self,
        unit_start: int,
        unit_last: int,
        *,
        scopes: Sequence[str] | None,
        include_seed_roles: bool,
        include_inspire: bool,
    ) -> bool:
        """统一查询显式 negative 与 seed/inspire 负向是否覆盖指定 unit 区间。"""
        if self.context.has_negative_cover(unit_start, unit_last, scopes=scopes):
            return True
        if include_seed_roles:
            for clue in self.context.clues:
                if not self._is_seed_negative_clue(clue):
                    continue
                if clue.unit_start <= unit_last and clue.unit_last >= unit_start:
                    return True
        if include_inspire:
            for inspire in self.context.inspire_entries:
                if inspire.unit_start <= unit_last and inspire.unit_last >= unit_start:
                    return True
        return False

    def _has_semantic_negative_cover_left_of_char(
        self,
        char_index: int,
        *,
        scopes: Sequence[str] | None,
        include_seed_roles: bool,
        include_inspire: bool,
    ) -> bool:
        """判断 cursor 左邻字符是否落在显式 negative 或 seed/inspire 覆盖内。"""
        if self.context.has_negative_cover_left_of_char(char_index, scopes=scopes):
            return True
        if char_index <= 0:
            return False
        left_char = char_index - 1
        if include_seed_roles:
            for clue in self.context.clues:
                if not self._is_seed_negative_clue(clue):
                    continue
                if clue.start <= left_char < clue.end:
                    return True
        if include_inspire:
            for inspire in self.context.inspire_entries:
                if inspire.start <= left_char < inspire.end:
                    return True
        return False

    def _next_semantic_negative_start_char(
        self,
        char_index: int,
        *,
        scopes: Sequence[str] | None,
        include_seed_roles: bool,
        include_inspire: bool,
    ) -> int | None:
        """返回右侧最近的显式 negative 或 seed/inspire 起点。"""
        next_start = self.context.next_negative_start_char(char_index, scopes=scopes)
        if include_seed_roles:
            for clue in self.context.clues:
                if not self._is_seed_negative_clue(clue):
                    continue
                if clue.start < char_index:
                    continue
                next_start = clue.start if next_start is None else min(next_start, clue.start)
        if include_inspire:
            for inspire in self.context.inspire_entries:
                if inspire.start < char_index:
                    continue
                next_start = inspire.start if next_start is None else min(next_start, inspire.start)
        return next_start

