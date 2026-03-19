"""de_model 轻量运行时骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision_context import CandidateDecisionFeatures, DecisionModelContext, PersonaDecisionFeatures
from privacyguard.infrastructure.decision.features import PackedDecisionFeatures

RUNTIME_ACTION_ORDER: tuple[ActionType, ActionType, ActionType] = (
    ActionType.KEEP,
    ActionType.GENERICIZE,
    ActionType.PERSONA_SLOT,
)


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


@dataclass(slots=True)
class TinyPolicyOutputDecoder:
    """将 TinyPolicyNet 前向输出解码为统一 de_model runtime 输出。"""

    keep_threshold: float = 0.25
    persona_score_threshold: float = 0.0
    action_tie_tolerance: float = 1e-6
    _tie_priority: dict[ActionType, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._tie_priority = {action: index for index, action in enumerate(RUNTIME_ACTION_ORDER)}

    def decode(self, *, batch, output, torch_module) -> DEModelRuntimeOutput:
        """将模型输出解码为 persona 选择与 candidate 动作。"""
        persona_scores = self._persona_scores(batch=batch, output=output, torch_module=torch_module)
        active_persona_id = self._active_persona_id(batch=batch, persona_scores=persona_scores)
        candidate_decisions: list[RuntimeCandidateDecision] = []
        for index, candidate_id in enumerate(batch.candidate_ids[0]):
            if not candidate_id or not bool(batch.candidate_mask[0, index].item()):
                continue
            action_probs = torch_module.softmax(output.action_logits[0, index], dim=-1)
            action_scores = {
                action: float(action_probs[action_index].item())
                for action_index, action in enumerate(RUNTIME_ACTION_ORDER)
            }
            preferred_action, decode_policy = self._decode_candidate_action(
                action_scores=action_scores,
                confidence_score=float(output.confidence_scores[0, index].item()),
            )
            candidate_decisions.append(
                RuntimeCandidateDecision(
                    candidate_id=candidate_id,
                    preferred_action=preferred_action,
                    action_scores=action_scores,
                    reason=(
                        f"torch_tiny_policy 选择 {preferred_action.value}；"
                        f"decode={decode_policy}，"
                        f"runtime_conf={float(output.confidence_scores[0, index].item()):.2f}，"
                        f"utility={float(output.utility_scores[0, index].item()):.2f}，"
                        f"scores={{KEEP:{action_scores[ActionType.KEEP]:.2f},"
                        f"GENERIC:{action_scores[ActionType.GENERICIZE]:.2f},"
                        f"PERSONA:{action_scores[ActionType.PERSONA_SLOT]:.2f}}}"
                    ),
                )
            )
        return DEModelRuntimeOutput(
            active_persona_id=active_persona_id,
            persona_scores=persona_scores,
            candidate_decisions=candidate_decisions,
        )

    def _persona_scores(self, *, batch, output, torch_module) -> dict[str, float]:
        if not bool(batch.persona_mask[0].any().item()):
            return {}
        probabilities = torch_module.softmax(output.persona_logits[0], dim=-1)
        scores: dict[str, float] = {}
        for index, persona_id in enumerate(batch.persona_ids[0]):
            if not persona_id or not bool(batch.persona_mask[0, index].item()):
                continue
            scores[persona_id] = float(probabilities[index].item())
        return scores

    def _active_persona_id(self, *, batch, persona_scores: dict[str, float]) -> str | None:
        if not persona_scores:
            return None
        valid_persona_ids = [persona_id for persona_id in batch.persona_ids[0] if persona_id]
        if not valid_persona_ids:
            return None
        selected_persona_id = max(valid_persona_ids, key=lambda persona_id: (persona_scores.get(persona_id, 0.0), persona_id))
        if persona_scores.get(selected_persona_id, 0.0) < self.persona_score_threshold:
            return None
        return selected_persona_id

    def _decode_candidate_action(
        self,
        *,
        action_scores: dict[ActionType, float],
        confidence_score: float,
    ) -> tuple[ActionType, str]:
        if confidence_score < self.keep_threshold:
            return (ActionType.KEEP, "low_conf_keep")
        max_score = max(action_scores.values())
        tied_actions = [
            action
            for action, score in action_scores.items()
            if abs(score - max_score) <= self.action_tie_tolerance
        ]
        preferred_action = max(tied_actions, key=lambda action: self._tie_priority[action])
        if len(tied_actions) > 1:
            return (preferred_action, f"tie_break:{preferred_action.value}")
        return (preferred_action, "argmax")


@runtime_checkable
class DecisionPolicyRuntime(Protocol):
    """定义 de_model runtime 的最小推理协议。"""

    def predict(
        self,
        *,
        context: DecisionModelContext,
        packed: PackedDecisionFeatures,
    ) -> DEModelRuntimeOutput:
        """根据完整上下文与压缩特征输出 runtime 决策。"""


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


class TorchTinyPolicyRuntime:
    """使用 TinyPolicyNet checkpoint 执行真实前向推理的 runtime。"""

    def __init__(
        self,
        checkpoint_path: str,
        *,
        device: str = "cpu",
        keep_threshold: float = 0.25,
        persona_score_threshold: float = 0.0,
        action_tie_tolerance: float = 1e-6,
        max_candidates: int = 32,
        max_personas: int = 8,
        max_text_length: int = 48,
        vocab_size: int = 2048,
        decoder: TinyPolicyOutputDecoder | None = None,
    ) -> None:
        self.checkpoint_path = Path(checkpoint_path)
        if not self.checkpoint_path.exists():
            raise ValueError(f"de_model checkpoint 不存在: {self.checkpoint_path}")
        self.device = str(device).strip() or "cpu"
        self.keep_threshold = keep_threshold
        self.persona_score_threshold = persona_score_threshold
        self.action_tie_tolerance = action_tie_tolerance
        self.max_candidates = max_candidates
        self.max_personas = max_personas
        self.max_text_length = max_text_length
        self.vocab_size = vocab_size
        self.decoder = decoder or TinyPolicyOutputDecoder(
            keep_threshold=self.keep_threshold,
            persona_score_threshold=self.persona_score_threshold,
            action_tie_tolerance=self.action_tie_tolerance,
        )
        self._torch, self._model, self._batch_builder = self._load_runtime_components()

    def predict(
        self,
        *,
        context: DecisionModelContext,
        packed: PackedDecisionFeatures,
    ) -> DEModelRuntimeOutput:
        """执行 TinyPolicyNet 前向，并把 logits 解码为运行时输出。"""
        _ = packed
        batch = self._batch_builder.build([context]).to(self.device)
        with self._torch.no_grad():
            output = self._model(batch)
        return self.decoder.decode(batch=batch, output=output, torch_module=self._torch)

    def _load_runtime_components(self):
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError("未安装 torch，无法启用 de_model torch runtime。") from exc

        from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig
        from training.torch_batch import TinyPolicyBatchBuilder

        try:
            payload = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)
        except TypeError:
            payload = torch.load(self.checkpoint_path, map_location=self.device)
        checkpoint_config = payload.get("model_config") if isinstance(payload, dict) else None
        state_dict = payload.get("state_dict", payload) if isinstance(payload, dict) else payload
        model_config = self._resolve_model_config(checkpoint_config, TinyPolicyNetConfig)
        model = TinyPolicyNet(model_config)
        model.load_state_dict(state_dict)
        model.to(self.device)
        model.eval()

        batch_builder = TinyPolicyBatchBuilder(
            max_candidates=self.max_candidates,
            max_personas=self.max_personas,
            max_text_length=model_config.max_text_length,
            vocab_size=model_config.vocab_size,
        )
        return (torch, model, batch_builder)

    def _resolve_model_config(self, payload, config_cls):
        if payload is None:
            return config_cls(max_text_length=self.max_text_length, vocab_size=self.vocab_size)
        if isinstance(payload, config_cls):
            return payload
        if isinstance(payload, dict):
            return config_cls(**payload)
        raise ValueError("de_model checkpoint 中的 model_config 格式非法。")
