"""Label Persona Mixed 决策引擎实现。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class LabelPersonaMixedDecisionEngine:
    """按属性类型混合使用 persona 槽位与通用标签。"""

    def __init__(
        self,
        confidence_threshold: float = 0.35,
        persona_repository: PersonaRepository | None = None,
    ) -> None:
        """初始化阈值、persona 仓库与约束解析器。"""
        self.confidence_threshold = confidence_threshold
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.constraint_resolver = ConstraintResolver(self.persona_repository)
        self.persona_attr_types = {
            PIIAttributeType.NAME,
            PIIAttributeType.PHONE,
            PIIAttributeType.ADDRESS,
            PIIAttributeType.EMAIL,
        }

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """生成 label_persona_mixed 决策计划。"""
        active_persona_id = self._select_persona_id(session_binding)
        actions: list[DecisionAction] = []
        for candidate in candidates:
            if candidate.confidence < self.confidence_threshold:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.KEEP,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        source_text=candidate.text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason="置信度较低，按策略 KEEP。",
                    )
                )
                continue
            if candidate.attr_type in self.persona_attr_types:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.PERSONA_SLOT,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        persona_id=active_persona_id,
                        replacement_text=None,
                        source_text=candidate.text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason="高风险字段优先使用 persona 槽位。",
                    )
                )
                continue
            actions.append(
                DecisionAction(
                    candidate_id=candidate.entity_id,
                    action_type=ActionType.GENERICIZE,
                    attr_type=candidate.attr_type,
                    source=candidate.source,
                    replacement_text=self._label_for_attr(candidate.attr_type),
                    source_text=candidate.text,
                    bbox=candidate.bbox,
                    block_id=candidate.block_id,
                    span_start=candidate.span_start,
                    span_end=candidate.span_end,
                    reason="非 persona 优先字段使用通用标签。",
                )
            )
        binding = session_binding or SessionBinding(session_id=session_id, active_persona_id=active_persona_id)
        if binding.active_persona_id is None:
            binding.active_persona_id = active_persona_id
        resolved = self.constraint_resolver.resolve(actions=actions, candidates=candidates, session_binding=binding)
        return DecisionPlan(
            session_id=session_id,
            turn_id=turn_id,
            active_persona_id=binding.active_persona_id,
            actions=resolved,
            summary=f"label_persona_mixed 共生成 {len(resolved)} 条动作。",
            metadata={"mode": "label_persona_mixed"},
        )

    def _select_persona_id(self, session_binding: SessionBinding | None) -> str | None:
        """按会话绑定优先与暴露计数策略选择 persona。"""
        if session_binding and session_binding.active_persona_id:
            return session_binding.active_persona_id
        personas = self.persona_repository.list_personas()
        if not personas:
            return None
        sorted_personas = sorted(personas, key=lambda item: int(item.stats.get("exposure_count", 0)))
        return sorted_personas[0].persona_id

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        """返回属性类型对应的中文标签，格式为 @姓名1、@手机号1 等（无尖括号）。"""
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
