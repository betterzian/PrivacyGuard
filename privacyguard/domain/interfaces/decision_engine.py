"""决策引擎抽象接口。"""

from typing import Protocol

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate


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
