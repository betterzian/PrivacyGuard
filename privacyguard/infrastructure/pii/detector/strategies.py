"""按 attr_type 控制 stack 起栈条件。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole


@dataclass(frozen=True, slots=True)
class StackStrategy:
    """单个属性 stack 的起栈策略。"""

    should_start: Callable[[Clue], bool]


_STRUCTURED_ATTRS = (
    PIIAttributeType.EMAIL,
    PIIAttributeType.PHONE,
    PIIAttributeType.ID_NUMBER,
    PIIAttributeType.CARD_NUMBER,
    PIIAttributeType.BANK_ACCOUNT,
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
    PIIAttributeType.NUMERIC,
)


def _allow_roles(*roles: ClueRole) -> StackStrategy:
    allowed = frozenset(roles)
    return StackStrategy(should_start=lambda clue: clue.role in allowed)


def _build_level_strategies(level: ProtectionLevel) -> dict[PIIAttributeType, StackStrategy]:
    strategies = {
        attr_type: _allow_roles(ClueRole.LABEL, ClueRole.HARD)
        for attr_type in _STRUCTURED_ATTRS
    }
    if level == ProtectionLevel.STRONG:
        strategies[PIIAttributeType.NAME] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.START,
            ClueRole.SURNAME,
            ClueRole.GIVEN_NAME,
            ClueRole.HARD,
        )
        strategies[PIIAttributeType.ORGANIZATION] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.SUFFIX,
            ClueRole.HARD,
        )
        strategies[PIIAttributeType.ADDRESS] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.VALUE,
            ClueRole.KEY,
            ClueRole.HARD,
        )
        return strategies
    if level == ProtectionLevel.BALANCED:
        strategies[PIIAttributeType.NAME] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.START,
            ClueRole.HARD,
        )
        strategies[PIIAttributeType.ORGANIZATION] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.SUFFIX,
            ClueRole.HARD,
        )
        strategies[PIIAttributeType.ADDRESS] = _allow_roles(
            ClueRole.LABEL,
            ClueRole.VALUE,
            ClueRole.HARD,
        )
        return strategies
    strategies[PIIAttributeType.NAME] = _allow_roles(ClueRole.LABEL, ClueRole.HARD)
    strategies[PIIAttributeType.ORGANIZATION] = _allow_roles(ClueRole.LABEL, ClueRole.HARD)
    strategies[PIIAttributeType.ADDRESS] = _allow_roles(ClueRole.LABEL, ClueRole.HARD)
    return strategies


STACK_STRATEGIES: dict[ProtectionLevel, dict[PIIAttributeType, StackStrategy]] = {
    level: _build_level_strategies(level)
    for level in ProtectionLevel
}


def resolve_strategies(
    level: ProtectionLevel,
    overrides: dict | None = None,
) -> dict[PIIAttributeType, StackStrategy]:
    """根据 protection_level 返回最终策略集。"""

    strategies = dict(STACK_STRATEGIES.get(level, STACK_STRATEGIES[ProtectionLevel.STRONG]))
    return strategies


__all__ = ["StackStrategy", "STACK_STRATEGIES", "resolve_strategies"]
