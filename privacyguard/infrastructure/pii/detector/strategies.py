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
    name_roles = (
        ClueRole.LABEL,
        ClueRole.START,
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
        ClueRole.HARD,
    )
    if level == ProtectionLevel.STRONG:
        strategies[PIIAttributeType.NAME] = _allow_roles(*name_roles)
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
        strategies[PIIAttributeType.NAME] = _allow_roles(*name_roles)
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
    strategies[PIIAttributeType.NAME] = _allow_roles(*name_roles)
    strategies[PIIAttributeType.ORGANIZATION] = _allow_roles(ClueRole.LABEL, ClueRole.HARD)
    strategies[PIIAttributeType.ADDRESS] = _allow_roles(ClueRole.LABEL, ClueRole.HARD)
    return strategies


STACK_STRATEGIES: dict[ProtectionLevel, dict[PIIAttributeType, StackStrategy]] = {
    level: _build_level_strategies(level)
    for level in ProtectionLevel
}


def resolve_strategies(
    level: ProtectionLevel,
) -> dict[PIIAttributeType, StackStrategy]:
    """根据 protection_level 返回最终策略集。"""
    return dict(STACK_STRATEGIES.get(level, STACK_STRATEGIES[ProtectionLevel.STRONG]))


# soft 类型间冲突的静态优先级。数值越大越优先保留。
# 结构化类型（email / phone / id 等）只由 hard clue 驱动，不参与 soft 竞争。
ATTR_TYPE_PRIORITY: dict[PIIAttributeType, int] = {
    PIIAttributeType.ADDRESS: 30,
    PIIAttributeType.NAME: 20,
    PIIAttributeType.ORGANIZATION: 10,
}


def attr_priority(attr_type: PIIAttributeType) -> int:
    """返回 soft 类型的冲突优先级；未注册类型返回 0。"""
    return ATTR_TYPE_PRIORITY.get(attr_type, 0)


__all__ = ["StackStrategy", "STACK_STRATEGIES", "resolve_strategies", "ATTR_TYPE_PRIORITY", "attr_priority"]
