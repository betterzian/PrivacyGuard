"""负向 clue 共享工具。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.models import Clue, ClueFamily, NegativeDecision, NegativeEffect


def has_negative_at(negative_clues: tuple[Clue, ...], start: int, end: int) -> bool:
    """检查指定区间是否存在负向 clue 覆盖。"""
    return any(
        not (end <= neg.start or start >= neg.end)
        for neg in negative_clues
    )


def overlapping_negative_clues(negative_clues: tuple[Clue, ...], start: int, end: int) -> tuple[Clue, ...]:
    """收集与候选区间重叠的负向 clue。"""
    return tuple(
        neg
        for neg in negative_clues
        if not (end <= neg.start or start >= neg.end)
    )


def evaluate_negative_effect(family: ClueFamily, negative_clues: tuple[Clue, ...]) -> NegativeEffect:
    """按 family 解释负向 clue，统一返回决策协议。"""
    if not negative_clues:
        return NegativeEffect(NegativeDecision.IGNORE)
    clue_ids = tuple(clue.clue_id for clue in negative_clues)
    reasons = tuple(sorted({clue.source_kind for clue in negative_clues}))
    if family == ClueFamily.NAME:
        if any(clue.source_kind in {"negative_name_word", "negative_address_word"} for clue in negative_clues):
            return NegativeEffect(NegativeDecision.VETO, matched_clue_ids=clue_ids, reasons=reasons)
        if any(clue.source_kind == "negative_ui_word" for clue in negative_clues):
            return NegativeEffect(NegativeDecision.PENALTY, matched_clue_ids=clue_ids, reasons=reasons)
        return NegativeEffect(NegativeDecision.IGNORE, matched_clue_ids=clue_ids, reasons=reasons)
    if family == ClueFamily.ORGANIZATION:
        if any(clue.source_kind == "negative_org_word" for clue in negative_clues):
            return NegativeEffect(NegativeDecision.VETO, matched_clue_ids=clue_ids, reasons=reasons)
        if any(clue.source_kind == "negative_address_word" for clue in negative_clues):
            return NegativeEffect(NegativeDecision.PENALTY, matched_clue_ids=clue_ids, reasons=reasons)
        return NegativeEffect(NegativeDecision.IGNORE, matched_clue_ids=clue_ids, reasons=reasons)
    if family == ClueFamily.ADDRESS:
        if any(clue.source_kind == "negative_numeric_context" for clue in negative_clues):
            return NegativeEffect(NegativeDecision.VETO, matched_clue_ids=clue_ids, reasons=reasons)
        if any(clue.source_kind == "negative_address_word" for clue in negative_clues):
            return NegativeEffect(NegativeDecision.PENALTY, matched_clue_ids=clue_ids, reasons=reasons)
        return NegativeEffect(NegativeDecision.IGNORE, matched_clue_ids=clue_ids, reasons=reasons)
    return NegativeEffect(NegativeDecision.IGNORE, matched_clue_ids=clue_ids, reasons=reasons)


__all__ = ["evaluate_negative_effect", "has_negative_at", "overlapping_negative_clues"]
