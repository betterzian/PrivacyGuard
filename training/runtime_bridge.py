"""训练与运行时之间的桥接工具。"""

from __future__ import annotations

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor, PackedDecisionFeatures
from privacyguard.infrastructure.decision.policy_context import (
    DerivedDecisionPolicyContext,
    candidate_by_id as derived_candidate_by_id,
    derive_policy_context,
)
from training.types import RenderedTurnObservation, SupervisedTurnLabels, TrainingTurnExample


def _flatten_slot_values(slots: dict[object, object]) -> str:
    fragments: list[str] = []
    for value in slots.values():
        if isinstance(value, list):
            fragments.extend(str(item).strip() for item in value if str(item).strip())
            continue
        text = str(value).strip()
        if text:
            fragments.append(text)
    return " ".join(fragments)


def pack_training_turn(
    context: DecisionContext,
    extractor: DecisionFeatureExtractor | None = None,
    *,
    policy: DerivedDecisionPolicyContext | None = None,
) -> tuple[TrainingTurnExample, PackedDecisionFeatures]:
    """把运行时上下文转成训练侧单轮样本。"""
    feature_extractor = extractor or DecisionFeatureExtractor()
    resolved_policy = policy or derive_policy_context(context)
    packed = feature_extractor.pack(context, policy=resolved_policy)
    example = TrainingTurnExample(
        session_id=context.session_id,
        turn_id=context.turn_id,
        prompt_text=context.prompt_text,
        ocr_texts=[block.text for block in context.ocr_blocks],
        candidate_ids=[str(view.get("candidate_id", "")) for view in resolved_policy.candidate_policy_views],
        candidate_texts=[_candidate_text(context, view) for view in resolved_policy.candidate_policy_views],
        candidate_prompt_contexts=[str(view.get("_prompt_context", "")) for view in resolved_policy.candidate_policy_views],
        candidate_ocr_contexts=[str(view.get("_ocr_context", "")) for view in resolved_policy.candidate_policy_views],
        candidate_attr_types=[view.get("attr_type") for view in resolved_policy.candidate_policy_views],
        persona_ids=[str(state.get("persona_id", "")) for state in resolved_policy.persona_policy_states],
        persona_texts=[_persona_text(context, state) for state in resolved_policy.persona_policy_states],
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

def _candidate_text(context: DecisionContext, view: dict[str, object]) -> str:
    candidate_id = str(view.get("candidate_id", "")).strip()
    candidate = derived_candidate_by_id(context).get(candidate_id)
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
    slot_text = _flatten_slot_values(slots)
    if not display_name:
        persona_id = str(state.get("persona_id", "")).strip()
        for persona in context.persona_profiles:
            if persona.persona_id == persona_id:
                display_name = persona.display_name
                slot_text = _flatten_slot_values(persona.slots)
                break
    return f"{display_name} {slot_text}".strip()
