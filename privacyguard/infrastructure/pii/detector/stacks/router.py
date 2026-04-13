"""多语种 stack 的顶层路由。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _label_seed_start_char,
    _label_start_route_locale,
)
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackContextLike
from privacyguard.infrastructure.pii.detector.stacks.common import _skip_separators, _unit_index_at_or_after
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_hard_break


def has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def locale_from_text(text: str) -> str:
    return "zh" if has_cjk(text) else "en"


def resolve_stack_locale(
    attr_type: PIIAttributeType,
    clue: Clue,
    clue_index: int,
    context: StackContextLike,
) -> str:
    """解析当前 clue 应落到哪种语言的子栈。"""
    profile_locale = _fixed_profile_locale(context.locale_profile)
    if profile_locale is not None:
        return profile_locale
    if attr_type == PIIAttributeType.ADDRESS:
        return _resolve_address_stack_locale(clue, clue_index, context)
    return _resolve_generic_stack_locale(clue, clue_index, context)


def route_localized_stack(
    *,
    attr_type: PIIAttributeType,
    clue: Clue,
    clue_index: int,
    context: StackContextLike,
    zh_stack_cls: type[BaseStack],
    en_stack_cls: type[BaseStack],
) -> BaseStack:
    """按顶层路由结果实例化中文或英文子栈。"""
    locale = resolve_stack_locale(attr_type, clue, clue_index, context)
    stack_cls = zh_stack_cls if locale == "zh" else en_stack_cls
    return stack_cls(clue=clue, clue_index=clue_index, context=context)


def _fixed_profile_locale(locale_profile: str) -> str | None:
    profile = str(locale_profile or "mixed").strip().lower()
    if profile == "zh_cn":
        return "zh"
    if profile == "en_us":
        return "en"
    return None


def _resolve_address_stack_locale(clue: Clue, clue_index: int, context: StackContextLike) -> str:
    del clue_index
    stream = context.stream
    if clue.strength == ClaimStrength.HARD:
        return locale_from_text(stream.text[clue.start:clue.end])

    if clue.role in {ClueRole.LABEL, ClueRole.START}:
        address_start = _label_seed_start_char(stream, clue.end)
        start_unit = _unit_index_at_or_after(stream, address_start)
        return _label_start_route_locale(
            context.clues,
            stream,
            address_start,
            start_unit,
            max_units=6,
        )

    clue_text = clue.text or stream.text[clue.start:clue.end]
    if has_cjk(clue_text):
        return "zh"
    window_start = max(0, clue.start - 8)
    window_end = min(len(stream.text), clue.end + 8)
    return locale_from_text(stream.text[window_start:window_end])


def _resolve_generic_stack_locale(clue: Clue, clue_index: int, context: StackContextLike) -> str:
    del clue_index
    stream = context.stream
    if clue.strength == ClaimStrength.HARD:
        return locale_from_text(stream.text[clue.start:clue.end])

    if clue.role in {ClueRole.LABEL, ClueRole.START}:
        value_start = _skip_separators(stream.text, clue.end)
        sample = _sample_probe_text(context, start=value_start, max_units=6)
        if sample.strip():
            return locale_from_text(sample)

    clue_text = clue.text or stream.text[clue.start:clue.end]
    if clue_text.strip():
        return locale_from_text(clue_text)

    window_start = max(0, clue.start - 8)
    window_end = min(len(stream.text), clue.end + 8)
    return locale_from_text(stream.text[window_start:window_end])


def _sample_probe_text(context: StackContextLike, *, start: int, max_units: int) -> str:
    stream = context.stream
    if start >= len(stream.text) or not stream.units:
        return ""

    blocker_start = _probe_blocker_start(context.clues, start)
    ui = _unit_index_at_or_after(stream, start)
    pieces: list[str] = []
    observed_units = 0

    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= blocker_start:
            break
        if unit.kind in {"inline_gap", "ocr_break"}:
            break
        if unit.kind == "punct" and is_hard_break(unit.text):
            break

        pieces.append(unit.text)
        if unit.kind not in {"space", "punct"}:
            observed_units += 1
            if observed_units >= max_units:
                break
        ui += 1

    return "".join(pieces)


def _probe_blocker_start(clues: tuple[Clue, ...], start: int) -> int:
    for clue in clues:
        if clue.end <= start:
            continue
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.LABEL}:
            return clue.start
        if clue.strength == ClaimStrength.HARD:
            return clue.start
    return 1 << 30
