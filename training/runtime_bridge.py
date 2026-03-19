"""训练与运行时之间的桥接工具。"""

from __future__ import annotations

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionModelContext
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor, PackedDecisionFeatures
from training.types import RenderedTurnObservation, SupervisedTurnLabels, TrainingTurnExample


def pack_training_turn(
    context: DecisionModelContext,
    extractor: DecisionFeatureExtractor | None = None,
) -> tuple[TrainingTurnExample, PackedDecisionFeatures]:
    """把运行时上下文转成训练侧单轮样本。"""
    feature_extractor = extractor or DecisionFeatureExtractor()
    packed = feature_extractor.pack(context)
    example = TrainingTurnExample(
        session_id=context.session_id,
        turn_id=context.turn_id,
        prompt_text=context.prompt_text,
        ocr_texts=[block.text for block in context.ocr_blocks],
        candidate_ids=[feature.candidate_id for feature in context.candidate_features],
        candidate_texts=[feature.text for feature in context.candidate_features],
        candidate_prompt_contexts=[feature.prompt_context for feature in context.candidate_features],
        candidate_ocr_contexts=[feature.ocr_context for feature in context.candidate_features],
        candidate_attr_types=[feature.attr_type for feature in context.candidate_features],
        persona_ids=[feature.persona_id for feature in context.persona_features],
        persona_texts=[_persona_text(feature) for feature in context.persona_features],
        active_persona_id=context.session_binding.active_persona_id if context.session_binding else None,
        page_vector=packed.page_vector,
        candidate_vectors=packed.candidate_vectors,
        persona_vectors=packed.persona_vectors,
        metadata={
            "candidate_count": str(len(context.candidates)),
            "persona_count": str(len(context.persona_profiles)),
        },
    )
    return (example, packed)


def plan_to_supervision(plan: DecisionPlan) -> SupervisedTurnLabels:
    """把运行时 plan 转成 supervised finetune 标签。"""
    return SupervisedTurnLabels(
        target_persona_id=plan.active_persona_id,
        candidate_actions={action.candidate_id: action.action_type for action in plan.actions},
        metadata=dict(plan.metadata),
    )


def plan_to_observation(
    *,
    session_id: str,
    turn_id: int,
    sanitized_prompt_text: str,
    sanitized_ocr_texts: list[str],
    plan: DecisionPlan,
) -> RenderedTurnObservation:
    """把运行时 plan 和渲染结果转成 adversary 可见观测。"""
    return RenderedTurnObservation(
        session_id=session_id,
        turn_id=turn_id,
        sanitized_prompt_text=sanitized_prompt_text,
        sanitized_ocr_texts=sanitized_ocr_texts,
        chosen_persona_id=plan.active_persona_id,
        applied_action_types={action.candidate_id: action.action_type for action in plan.actions},
        metadata=dict(plan.metadata),
    )


def _persona_text(feature) -> str:
    slot_text = " ".join(str(value) for _key, value in sorted(feature.slots.items(), key=lambda item: item[0].value))
    return f"{feature.display_name} {slot_text}".strip()
