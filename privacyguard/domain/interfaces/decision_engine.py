"""决策引擎抽象接口。"""

from typing import Protocol, runtime_checkable

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionModelContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate


@runtime_checkable
class DecisionEngine(Protocol):
    """定义脱敏动作决策接口。"""

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """根据候选实体和会话状态生成决策计划。"""


@runtime_checkable
class ContextAwareDecisionEngine(DecisionEngine, Protocol):
    """定义支持完整上下文输入的决策接口。"""

    def plan_with_context(self, context: DecisionModelContext) -> DecisionPlan:
        """根据完整上下文生成决策计划。"""
