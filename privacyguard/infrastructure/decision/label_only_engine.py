"""Label Only 决策引擎实现。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class LabelOnlyDecisionEngine:
    """将候选实体稳定映射为标准标签替换。"""

    def __init__(self, confidence_threshold: float = 0.0, persona_repository: PersonaRepository | None = None) -> None:
        """初始化置信度阈值与约束解析器。"""
        self.confidence_threshold = confidence_threshold
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.constraint_resolver = ConstraintResolver(self.persona_repository)

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """生成 label_only 决策计划。"""
        actions: list[DecisionAction] = []
        attr_counts: dict[PIIAttributeType, int] = {}
        for candidate in candidates:
            if candidate.confidence < self.confidence_threshold:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.KEEP,
                        attr_type=candidate.attr_type,
                        source_text=candidate.text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason="置信度低于阈值，保持原文。",
                    )
                )
                continue
            attr_type = candidate.attr_type
            attr_counts[attr_type] = attr_counts.get(attr_type, 0) + 1
            actions.append(
                DecisionAction(
                    candidate_id=candidate.entity_id,
                    action_type=ActionType.GENERICIZE,
                    attr_type=attr_type,
                    replacement_text=self._label_for_attr(attr_type, attr_counts[attr_type]),
                    source_text=candidate.text,
                    bbox=candidate.bbox,
                    block_id=candidate.block_id,
                    span_start=candidate.span_start,
                    span_end=candidate.span_end,
                    reason="label_only 统一使用标准标签。",
                )
            )
        resolved = self.constraint_resolver.resolve(actions=actions, candidates=candidates, session_binding=session_binding)
        return DecisionPlan(
            session_id=session_id,
            turn_id=turn_id,
            active_persona_id=session_binding.active_persona_id if session_binding else None,
            actions=resolved,
            summary=f"label_only 共生成 {len(resolved)} 条动作。",
            metadata={"mode": "label_only"},
        )

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        """将属性类型映射为中文标签，格式为 @姓名1、@手机号1 等（无尖括号）。"""
        mapping = {
            PIIAttributeType.NAME: "姓名",
            PIIAttributeType.PHONE: "手机号",
            PIIAttributeType.EMAIL: "邮箱",
            PIIAttributeType.ADDRESS: "地址",
            PIIAttributeType.ID_NUMBER: "身份证号",
            PIIAttributeType.ORGANIZATION: "机构",
            PIIAttributeType.OTHER: "敏感信息",
        }
        name = mapping.get(attr_type, "敏感信息")
        return f"@{name}{index}"
