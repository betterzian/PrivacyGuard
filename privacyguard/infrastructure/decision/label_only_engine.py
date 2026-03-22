"""Label Only 决策引擎实现。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan, clone_action_metadata
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.domain.policies.generic_placeholder import render_generic_replacement_text
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class LabelOnlyDecisionEngine:
    """将候选实体稳定映射为标准标签替换。

    职责：对每个候选仅决策 ``KEEP`` 或 ``GENERICIZE``；``GENERICIZE`` 的占位字符串由
    ``render_generic_replacement_text`` 统一渲染（经 ``ConstraintResolver`` 与会话占位分配补全序号）。
    """

    def __init__(self, confidence_threshold: float = 0.0, persona_repository: PersonaRepository | None = None) -> None:
        """初始化置信度阈值与约束解析器。"""
        self.confidence_threshold = confidence_threshold
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.constraint_resolver = ConstraintResolver(self.persona_repository)

    def plan(self, context: DecisionContext) -> DecisionPlan:
        """生成 label_only 决策计划。"""
        actions: list[DecisionAction] = []
        attr_counts: dict[PIIAttributeType, int] = {}
        for candidate in context.candidates:
            if candidate.confidence < self.confidence_threshold:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.KEEP,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        source_text=candidate.text,
                        canonical_source_text=candidate.canonical_source_text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason="置信度低于阈值，保持原文。",
                        metadata=clone_action_metadata(candidate.metadata),
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
                    source=candidate.source,
                    replacement_text=render_generic_replacement_text(attr_type, attr_counts[attr_type]),
                    source_text=candidate.text,
                    canonical_source_text=candidate.canonical_source_text,
                    bbox=candidate.bbox,
                    block_id=candidate.block_id,
                    span_start=candidate.span_start,
                    span_end=candidate.span_end,
                    reason="label_only 统一使用标准标签。",
                    metadata=clone_action_metadata(candidate.metadata),
                )
            )
        resolved = self.constraint_resolver.resolve(
            actions=actions,
            candidates=context.candidates,
            session_binding=context.session_binding,
        )
        return DecisionPlan(
            session_id=context.session_id,
            turn_id=context.turn_id,
            active_persona_id=context.session_binding.active_persona_id if context.session_binding else None,
            actions=resolved,
            summary=f"label_only 共生成 {len(resolved)} 条动作。",
            metadata={"mode": "label_only"},
        )
