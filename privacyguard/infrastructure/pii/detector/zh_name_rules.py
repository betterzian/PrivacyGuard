"""中文姓名纯规则辅助工具。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue

_CJK_NAME_JOINERS = frozenset({"·", "•", "・"})


def _is_cjk(char: str) -> bool:
    return "\u4e00" <= char <= "\u9fff"


def compact_zh_name_text(text: str) -> str:
    """压紧中文姓名文本，只保留汉字与中点连接符。"""
    compact: list[str] = []
    for char in str(text or ""):
        if char.isspace():
            continue
        if _is_cjk(char) or char in _CJK_NAME_JOINERS:
            compact.append(char)
    return "".join(compact)


class NegativeOverlapKind(str, Enum):
    NONE = "none"
    EXACT_HIT = "exact_hit"
    SAME_START_COVER = "same_start_cover"
    FULLY_COVERED = "fully_covered"
    PARTIAL_OVERLAP = "partial_overlap"
    NEGATIVE_FULLY_INSIDE = "negative_fully_inside"


_NEGATIVE_KIND_PRIORITY = {
    NegativeOverlapKind.SAME_START_COVER: 5,
    NegativeOverlapKind.FULLY_COVERED: 5,
    NegativeOverlapKind.PARTIAL_OVERLAP: 5,
    NegativeOverlapKind.EXACT_HIT: 4,
    NegativeOverlapKind.NEGATIVE_FULLY_INSIDE: 3,
    NegativeOverlapKind.NONE: 0,
}


@dataclass(frozen=True, slots=True)
class NegativeOverlap:
    """单个 negative 与姓名候选的重叠结果。"""

    kind: NegativeOverlapKind
    clue_id: str
    start: int
    end: int
    text: str


@dataclass(frozen=True, slots=True)
class ZhNameCommitDecision:
    """中文姓名规则机的最终判定结果。"""

    should_commit: bool
    final_claim_strength: ClaimStrength | None
    route: str
    negative_overlap_kind: NegativeOverlapKind = NegativeOverlapKind.NONE
    reasons: tuple[str, ...] = ()


_DIRECT_SUBMIT_ALLOWED_KINDS = frozenset(
    {
        NegativeOverlapKind.NONE,
        NegativeOverlapKind.EXACT_HIT,
        NegativeOverlapKind.NEGATIVE_FULLY_INSIDE,
    }
)

# 姓片段：完全包住或部分重叠 → 本栈立即结束，不吞名、不提交。
_FAMILY_IMMEDIATE_EXIT_KINDS = frozenset(
    {
        NegativeOverlapKind.FULLY_COVERED,
        NegativeOverlapKind.PARTIAL_OVERLAP,
    }
)

# 名或隐式尾部：同上两类 → 整段姓名候选取消提交。
_GIVEN_OR_IMPLICIT_TAIL_CANCEL_KINDS = _FAMILY_IMMEDIATE_EXIT_KINDS

# 仍仅通过降一级 strength 消化的 overlap（与 blacklist 同起点向右延伸等）。
_CLAIM_STRENGTH_DEMOTION_KINDS = frozenset(
    {
        NegativeOverlapKind.SAME_START_COVER,
    }
)


def upgrade_claim_strength(strength: ClaimStrength) -> ClaimStrength:
    """把 claim_strength 提升一级。"""
    if strength == ClaimStrength.WEAK:
        return ClaimStrength.SOFT
    return ClaimStrength.HARD


def downgrade_claim_strength(strength: ClaimStrength) -> ClaimStrength | None:
    """把 claim_strength 降一级；``WEAK`` 再降则视为失效。"""
    if strength == ClaimStrength.HARD:
        return ClaimStrength.SOFT
    if strength == ClaimStrength.SOFT:
        return ClaimStrength.WEAK
    return None


def stronger_claim_strength(a: ClaimStrength, b: ClaimStrength) -> ClaimStrength:
    """返回两个 strength 中更强的那个。"""
    order = {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }
    return a if order[a] >= order[b] else b


def claim_strength_required_for_protection(level: ProtectionLevel) -> ClaimStrength:
    """将保护级别映射为最终提交门槛。"""
    if level == ProtectionLevel.STRONG:
        return ClaimStrength.SOFT
    if level == ProtectionLevel.BALANCED:
        return ClaimStrength.HARD
    return ClaimStrength.HARD


def claim_strength_meets_protection(strength: ClaimStrength, level: ProtectionLevel) -> bool:
    """判断最终 claim_strength 是否满足保护级别门槛。"""
    required = claim_strength_required_for_protection(level)
    order = {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }
    return order[strength] >= order[required]


def classify_negative_overlap(
    *,
    candidate_start: int,
    candidate_end: int,
    candidate_raw_text: str,
    negative_start: int,
    negative_end: int,
    negative_text: str,
) -> NegativeOverlapKind:
    """按最终规则分类单个 negative 与候选的重叠关系。"""
    if candidate_end <= candidate_start or negative_end <= negative_start:
        return NegativeOverlapKind.NONE
    if negative_end <= candidate_start or negative_start >= candidate_end:
        return NegativeOverlapKind.NONE
    if (
        candidate_start == negative_start
        and candidate_end == negative_end
        and candidate_raw_text == negative_text
    ):
        return NegativeOverlapKind.EXACT_HIT
    if negative_start == candidate_start and negative_end >= candidate_end:
        return NegativeOverlapKind.SAME_START_COVER
    if negative_start <= candidate_start and negative_end >= candidate_end:
        return NegativeOverlapKind.FULLY_COVERED
    if candidate_start <= negative_start and candidate_end >= negative_end:
        return NegativeOverlapKind.NEGATIVE_FULLY_INSIDE
    return NegativeOverlapKind.PARTIAL_OVERLAP


def collect_negative_overlaps(
    *,
    candidate_start: int,
    candidate_end: int,
    candidate_raw_text: str,
    negative_clues: Sequence[Clue],
) -> tuple[NegativeOverlap, ...]:
    """收集候选与所有 negative clue 的重叠分类。"""
    overlaps: list[NegativeOverlap] = []
    for clue in negative_clues:
        kind = classify_negative_overlap(
            candidate_start=candidate_start,
            candidate_end=candidate_end,
            candidate_raw_text=candidate_raw_text,
            negative_start=clue.start,
            negative_end=clue.end,
            negative_text=clue.text,
        )
        if kind == NegativeOverlapKind.NONE:
            continue
        overlaps.append(
            NegativeOverlap(
                kind=kind,
                clue_id=clue.clue_id,
                start=clue.start,
                end=clue.end,
                text=clue.text,
            )
        )
    return tuple(overlaps)


def collect_blocking_overlaps(
    *,
    candidate_start: int,
    candidate_end: int,
    candidate_raw_text: str,
    negative_clues: Sequence[Clue],
    other_clues: Sequence[Clue],
) -> tuple[NegativeOverlap, ...]:
    """收集会阻断姓名判定的所有重叠 clue。

    规则：
    1. negative clue 维持原语义。
    2. 其他非 NAME clue 与 negative 使用同一套 span 分类与降级规则。
    """
    overlaps = list(
        collect_negative_overlaps(
            candidate_start=candidate_start,
            candidate_end=candidate_end,
            candidate_raw_text=candidate_raw_text,
            negative_clues=negative_clues,
        )
    )
    for clue in other_clues:
        kind = classify_negative_overlap(
            candidate_start=candidate_start,
            candidate_end=candidate_end,
            candidate_raw_text=candidate_raw_text,
            negative_start=clue.start,
            negative_end=clue.end,
            negative_text=clue.text,
        )
        if kind == NegativeOverlapKind.NONE:
            continue
        overlaps.append(
            NegativeOverlap(
                kind=kind,
                clue_id=clue.clue_id,
                start=clue.start,
                end=clue.end,
                text=clue.text,
            )
        )
    return tuple(overlaps)


def dominant_negative_overlap_kind(overlaps: Sequence[NegativeOverlap]) -> NegativeOverlapKind:
    """返回重叠列表中的主导 negative 类型。"""
    if not overlaps:
        return NegativeOverlapKind.NONE
    return max(overlaps, key=lambda item: _NEGATIVE_KIND_PRIORITY[item.kind]).kind


def has_any_negative_overlap(overlaps: Sequence[NegativeOverlap]) -> bool:
    """判断是否命中任意 negative。"""
    return bool(overlaps)


def direct_submit_negative_allowed(overlaps: Sequence[NegativeOverlap]) -> bool:
    """直接提交路径是否允许当前 negative 命中集合。"""
    return all(item.kind in _DIRECT_SUBMIT_ALLOWED_KINDS for item in overlaps)


def family_negative_blocks_stack_immediately(overlaps: Sequence[NegativeOverlap]) -> bool:
    """姓片段是否命中强阻断（应立刻结束本栈，不再扩张）。"""
    return any(item.kind in _FAMILY_IMMEDIATE_EXIT_KINDS for item in overlaps)


def given_or_implicit_tail_negative_cancels_candidate(overlaps: Sequence[NegativeOverlap]) -> bool:
    """显式名或隐式尾部是否命中强阻断（应取消整段姓名提交）。"""
    return any(item.kind in _GIVEN_OR_IMPLICIT_TAIL_CANCEL_KINDS for item in overlaps)


def component_negative_demotes_claim_strength(overlaps: Sequence[NegativeOverlap]) -> bool:
    """是否仅通过 claim_strength 降一级即可继续（不含强阻断类）。"""
    return any(item.kind in _CLAIM_STRENGTH_DEMOTION_KINDS for item in overlaps)


__all__ = [
    "NegativeOverlap",
    "NegativeOverlapKind",
    "ZhNameCommitDecision",
    "claim_strength_meets_protection",
    "claim_strength_required_for_protection",
    "classify_negative_overlap",
    "collect_blocking_overlaps",
    "collect_negative_overlaps",
    "compact_zh_name_text",
    "component_negative_demotes_claim_strength",
    "direct_submit_negative_allowed",
    "dominant_negative_overlap_kind",
    "downgrade_claim_strength",
    "family_negative_blocks_stack_immediately",
    "given_or_implicit_tail_negative_cancels_candidate",
    "has_any_negative_overlap",
    "stronger_claim_strength",
    "upgrade_claim_strength",
]
