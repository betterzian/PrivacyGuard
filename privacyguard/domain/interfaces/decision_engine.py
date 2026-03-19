"""决策引擎抽象接口。"""

from typing import Protocol, runtime_checkable

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext


@runtime_checkable
class DecisionEngine(Protocol):
    """定义脱敏动作决策接口。"""

    def plan(self, context: DecisionContext) -> DecisionPlan:
        """根据统一决策上下文生成决策计划。"""
