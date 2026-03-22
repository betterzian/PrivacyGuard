"""Label Only 决策引擎实现。"""

from privacyguard.domain.enums import ActionType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan, clone_action_metadata
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class LabelOnlyDecisionEngine:
    """将候选实体稳定映射为标准标签替换。

    职责：对每个候选仅决策 ``KEEP`` 或 ``GENERICIZE``（抽象，``replacement_text`` 为空；
    由 sanitize 链路的 ``ReplacementGenerationService`` 拼字与会话占位）。
    """

    def __init__(self, confidence_threshold: float = 0.0, persona_repository: PersonaRepository | None = None) -> None:
        """初始化置信度阈值；``persona_repository`` 保留以兼容构造签名，本引擎不使用。"""
        self.confidence_threshold = confidence_threshold
        self.persona_repository = persona_repository or JsonPersonaRepository()

    def plan(self, context: DecisionContext) -> DecisionPlan:
        """生成 label_only 决策计划。"""
        actions: list[DecisionAction] = []
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
            actions.append(
                DecisionAction(
                    candidate_id=candidate.entity_id,
                    action_type=ActionType.GENERICIZE,
                    attr_type=attr_type,
                    source=candidate.source,
                    replacement_text=None,
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
        return DecisionPlan(
            session_id=context.session_id,
            turn_id=context.turn_id,
            active_persona_id=context.session_binding.active_persona_id if context.session_binding else None,
            actions=actions,
            summary=f"label_only 共生成 {len(actions)} 条动作。",
            metadata={"mode": "label_only"},
        )
