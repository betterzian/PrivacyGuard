"""de_model 轻量运行时骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision_context import CandidateDecisionFeatures, DecisionModelContext, PersonaDecisionFeatures
from privacyguard.infrastructure.decision.features import PackedDecisionFeatures


@dataclass(slots=True)
class RuntimeCandidateDecision:
    """记录单个候选的动作偏好与评分。"""

    candidate_id: str
    preferred_action: ActionType
    action_scores: dict[ActionType, float]
    reason: str


@dataclass(slots=True)
class DEModelRuntimeOutput:
    """记录一次 de_model 运行时推断结果。"""

    active_persona_id: str | None
    persona_scores: dict[str, float] = field(default_factory=dict)
    candidate_decisions: list[RuntimeCandidateDecision] = field(default_factory=list)


class TinyPolicyRuntime:
    """用启发式策略模拟小参数 de_model 的运行时接口。"""

    def __init__(self, keep_threshold: float = 0.25) -> None:
        self.keep_threshold = keep_threshold
        self.persona_attr_types = {
            PIIAttributeType.NAME,
            PIIAttributeType.PHONE,
            PIIAttributeType.CARD_NUMBER,
            PIIAttributeType.BANK_ACCOUNT,
            PIIAttributeType.PASSPORT_NUMBER,
            PIIAttributeType.DRIVER_LICENSE,
            PIIAttributeType.ADDRESS,
            PIIAttributeType.EMAIL,
            PIIAttributeType.ID_NUMBER,
            PIIAttributeType.ORGANIZATION,
        }
        self._tie_priority = {
            ActionType.KEEP: 0,
            ActionType.GENERICIZE: 1,
            ActionType.PERSONA_SLOT: 2,
        }

    def predict(
        self,
        *,
        context: DecisionModelContext,
        packed: PackedDecisionFeatures,
    ) -> DEModelRuntimeOutput:
        """基于上下文与压缩特征生成占位策略输出。"""
        active_persona_id, persona_scores = self._select_persona(context=context)
        persona_slots: dict[PIIAttributeType, str] = {}
        for item in context.persona_profiles:
            if item.persona_id == active_persona_id:
                persona_slots = item.slots
                break
        candidate_decisions: list[RuntimeCandidateDecision] = []
        for feature in context.candidate_features:
            scores = self._candidate_scores(
                feature=feature,
                active_persona_id=active_persona_id,
                persona_slots=persona_slots,
                page_vector=packed.page_vector,
            )
            preferred_action = max(scores, key=lambda key: (scores[key], self._tie_priority[key]))
            candidate_decisions.append(
                RuntimeCandidateDecision(
                    candidate_id=feature.candidate_id,
                    preferred_action=preferred_action,
                    action_scores=scores,
                    reason=self._reason_for(
                        feature=feature,
                        preferred_action=preferred_action,
                        scores=scores,
                        has_persona_slot=feature.attr_type in persona_slots,
                    ),
                )
            )
        return DEModelRuntimeOutput(
            active_persona_id=active_persona_id,
            persona_scores=persona_scores,
            candidate_decisions=candidate_decisions,
        )

    def _select_persona(self, context: DecisionModelContext) -> tuple[str | None, dict[str, float]]:
        if not context.persona_features:
            return (None, {})
        active_persona_id = context.session_binding.active_persona_id if context.session_binding else None
        persona_scores = {
            feature.persona_id: self._persona_score(feature=feature, force_active=feature.persona_id == active_persona_id)
            for feature in context.persona_features
        }
        if active_persona_id:
            return (active_persona_id, persona_scores)
        selected = max(
            context.persona_features,
            key=lambda feature: (
                persona_scores[feature.persona_id],
                -feature.exposure_count,
                feature.persona_id,
            ),
        )
        return (selected.persona_id, persona_scores)

    def _persona_score(self, *, feature: PersonaDecisionFeatures, force_active: bool) -> float:
        matched_score = min(1.0, feature.matched_candidate_attr_count / 4.0)
        coverage_score = min(1.0, feature.slot_count / 6.0)
        freshness_score = 1.0 - min(1.0, feature.exposure_count / 32.0)
        active_bonus = 1.0 if force_active else 0.0
        return round(0.45 * matched_score + 0.3 * coverage_score + 0.25 * freshness_score + active_bonus, 4)

    def _candidate_scores(
        self,
        *,
        feature: CandidateDecisionFeatures,
        active_persona_id: str | None,
        persona_slots: dict[PIIAttributeType, str],
        page_vector: list[float],
    ) -> dict[ActionType, float]:
        prompt_digit_bias = page_vector[6] if len(page_vector) > 6 else 0.0
        has_persona_slot = bool(active_persona_id) and feature.attr_type in persona_slots
        keep_score = 0.12 + max(0.0, (self.keep_threshold - feature.confidence) * 1.8)
        if feature.confidence < 0.2:
            keep_score += 0.18
        if feature.history_exact_match_count == 0 and feature.same_text_page_count <= 1:
            keep_score += 0.04

        generic_score = 0.24 + feature.confidence * 0.52
        generic_score += min(0.16, feature.history_attr_exposure_count * 0.025)
        if feature.attr_type in {
            PIIAttributeType.ID_NUMBER,
            PIIAttributeType.CARD_NUMBER,
            PIIAttributeType.BANK_ACCOUNT,
            PIIAttributeType.PASSPORT_NUMBER,
            PIIAttributeType.DRIVER_LICENSE,
            PIIAttributeType.ORGANIZATION,
            PIIAttributeType.OTHER,
        }:
            generic_score += 0.12
        if feature.attr_type == PIIAttributeType.PHONE and prompt_digit_bias > 0:
            generic_score += 0.04
        if has_persona_slot:
            generic_score -= 0.08

        persona_score = 0.0
        if has_persona_slot and feature.attr_type in self.persona_attr_types:
            persona_score = 0.39 + feature.confidence * 0.38
            persona_score += min(0.12, feature.history_attr_exposure_count * 0.02)
            persona_score += 0.05 if feature.same_attr_page_count > 1 else 0.0
            persona_score += 0.04 if feature.is_ocr_source else 0.0
        if feature.confidence < self.keep_threshold:
            generic_score *= 0.82
            persona_score *= 0.7

        return {
            ActionType.KEEP: round(min(1.0, keep_score), 4),
            ActionType.GENERICIZE: round(min(1.0, generic_score), 4),
            ActionType.PERSONA_SLOT: round(min(1.0, persona_score), 4),
        }

    def _reason_for(
        self,
        *,
        feature: CandidateDecisionFeatures,
        preferred_action: ActionType,
        scores: dict[ActionType, float],
        has_persona_slot: bool,
    ) -> str:
        return (
            f"tiny_policy 选择 {preferred_action.value}；"
            f"conf={feature.confidence:.2f}，"
            f"history_attr={feature.history_attr_exposure_count}，"
            f"history_exact={feature.history_exact_match_count}，"
            f"persona_slot={'yes' if has_persona_slot else 'no'}，"
            f"scores={{KEEP:{scores[ActionType.KEEP]:.2f},GENERIC:{scores[ActionType.GENERICIZE]:.2f},"
            f"PERSONA:{scores[ActionType.PERSONA_SLOT]:.2f}}}"
        )
