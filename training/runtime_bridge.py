"""训练与运行时之间的桥接工具。"""

from __future__ import annotations

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor, PackedDecisionFeatures
from training.types import RenderedTurnObservation, SupervisedTurnLabels, TrainingTurnExample


def pack_training_turn(
    context: DecisionContext,
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
        candidate_ids=[str(view.get("candidate_id", "")) for view in _candidate_policy_views(context)],
        candidate_texts=[_candidate_text(context, view) for view in _candidate_policy_views(context)],
        candidate_prompt_contexts=[str(view.get("_prompt_context", "")) for view in _candidate_policy_views(context)],
        candidate_ocr_contexts=[str(view.get("_ocr_context", "")) for view in _candidate_policy_views(context)],
        candidate_attr_types=[view.get("attr_type") for view in _candidate_policy_views(context)],
        persona_ids=[str(state.get("persona_id", "")) for state in _persona_policy_states(context)],
        persona_texts=[_persona_text(context, state) for state in _persona_policy_states(context)],
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


def _candidate_policy_views(context: DecisionContext) -> list[dict[str, object]]:
    views = getattr(context, "candidate_policy_views", None)
    if not isinstance(views, list):
        return []
    return [view for view in views if isinstance(view, dict)]


def _persona_policy_states(context: DecisionContext) -> list[dict[str, object]]:
    states = getattr(context, "persona_policy_states", None)
    if not isinstance(states, list):
        return []
    return [state for state in states if isinstance(state, dict)]


def _candidate_text(context: DecisionContext, view: dict[str, object]) -> str:
    candidate_id = str(view.get("candidate_id", "")).strip()
    raw_refs = getattr(context, "raw_refs", {})
    if isinstance(raw_refs, dict):
        candidate_by_id = raw_refs.get("candidate_by_id", {})
        if isinstance(candidate_by_id, dict):
            candidate = candidate_by_id.get(candidate_id)
            if candidate is not None:
                return str(getattr(candidate, "text", "") or "")
    for candidate in context.candidates:
        if candidate.entity_id == candidate_id:
            return candidate.text
    return ""


def _persona_text(context: DecisionContext, state: dict[str, object]) -> str:
    display_name = str(state.get("_display_name", "") or "")
    slots = state.get("_slots", {})
    if not isinstance(slots, dict):
        slots = {}
    slot_text = " ".join(str(value) for value in slots.values())
    if not display_name:
        persona_id = str(state.get("persona_id", "")).strip()
        for persona in context.persona_profiles:
            if persona.persona_id == persona_id:
                display_name = persona.display_name
                slot_text = " ".join(str(value) for value in persona.slots.values())
                break
    return f"{display_name} {slot_text}".strip()
