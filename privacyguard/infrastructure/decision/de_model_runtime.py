"""de_model 轻量运行时骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.policies.action_labels import (
    ACTION_ORDER,
    PROTECT_LABEL_KEEP,
    PROTECT_LABEL_REWRITE,
    REWRITE_MODE_NONE,
)
from privacyguard.infrastructure.decision.features import PackedDecisionFeatures
from privacyguard.infrastructure.decision.policy_context import (
    DerivedDecisionPolicyContext,
    derive_policy_context,
)


@dataclass(slots=True)
class RuntimeCandidateDecision:
    """记录单个候选的统一 runtime 输出。

    正式协议收敛为两级视图：

    - `protect_decision`: `KEEP` / `REWRITE`
    - `rewrite_mode`: `GENERICIZE` / `PERSONA_SLOT` / `NONE`

    同时保留旧字段兼容：

    - `preferred_action`: 兼容旧 consumer，等价于 `final_action`
    - `reason`: 兼容旧 consumer，由 `reasons` + `fallback_reason` 汇总得到
    - `action_scores`: 兼容旧平面 action score 输出
    """

    candidate_id: str
    final_action: ActionType | str
    persona_id: str | None = None
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    fallback_reason: str | None = None
    action_scores: dict[ActionType | str, float] = field(default_factory=dict)
    protect_decision: str = field(init=False)
    rewrite_mode: str = field(init=False)
    preferred_action: ActionType = field(init=False)
    reason: str = field(init=False)

    def __post_init__(self) -> None:
        self.final_action = _normalized_action_type(self.final_action)
        self.preferred_action = self.final_action
        self.action_scores = _normalized_action_scores(self.action_scores)
        self.protect_decision, self.rewrite_mode = _hierarchical_view(self.final_action)
        self.reasons = [str(item).strip() for item in self.reasons if str(item).strip()]
        fallback_reason = str(self.fallback_reason or "").strip()
        self.fallback_reason = fallback_reason or None
        self.reason = _compose_reason(self.reasons, self.fallback_reason)


@dataclass(slots=True)
class DEModelRuntimeOutput:
    """记录一次 de_model 运行时推断结果。"""

    active_persona_id: str | None
    persona_scores: dict[str, float] = field(default_factory=dict)
    candidate_decisions: list[RuntimeCandidateDecision] = field(default_factory=list)
    protocol_version: str = "hierarchical_runtime_v1"


@dataclass(slots=True)
class TinyPolicyOutputDecoder:
    """将 TinyPolicyNet 前向输出解码为统一 de_model runtime 输出。"""

    keep_threshold: float = 0.25
    persona_score_threshold: float = 0.0
    action_tie_tolerance: float = 1e-6
    _tie_priority: dict[ActionType, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._tie_priority = {action: index for index, action in enumerate(ACTION_ORDER)}

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
                for action_index, action in enumerate(ACTION_ORDER)
            }
            final_action, decode_policy, fallback_reason = self._decode_candidate_action(
                action_scores=action_scores,
                confidence_score=float(output.confidence_scores[0, index].item()),
            )
            candidate_decisions.append(
                _build_runtime_candidate_decision(
                    candidate_id=candidate_id,
                    final_action=final_action,
                    persona_id=active_persona_id if final_action == ActionType.PERSONA_SLOT else None,
                    confidence=float(output.confidence_scores[0, index].item()),
                    reasons=[
                        f"torch_tiny_policy final_action={final_action.value}",
                        f"decode={decode_policy}",
                        f"runtime_conf={float(output.confidence_scores[0, index].item()):.2f}",
                        f"utility={float(output.utility_scores[0, index].item()):.2f}",
                        _scores_summary(action_scores),
                    ],
                    fallback_reason=fallback_reason,
                    action_scores=action_scores,
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
    ) -> tuple[ActionType, str, str | None]:
        if confidence_score < self.keep_threshold:
            return (
                ActionType.KEEP,
                "low_conf_keep",
                "runtime_conf_below_keep_threshold，已优先回退为 KEEP。",
            )
        max_score = max(action_scores.values())
        tied_actions = [
            action
            for action, score in action_scores.items()
            if abs(score - max_score) <= self.action_tie_tolerance
        ]
        preferred_action = max(tied_actions, key=lambda action: self._tie_priority[action])
        if len(tied_actions) > 1:
            return (preferred_action, f"tie_break:{preferred_action.value}", None)
        return (preferred_action, "argmax", None)


@runtime_checkable
class DecisionPolicyRuntime(Protocol):
    """定义 de_model runtime 的最小推理协议。"""

    def predict(
        self,
        *,
        context: DecisionContext,
        packed: PackedDecisionFeatures,
        policy: DerivedDecisionPolicyContext | None = None,
    ) -> DEModelRuntimeOutput:
        """根据完整上下文与压缩特征输出 runtime 决策。"""


class TinyPolicyRuntime:
    """用启发式策略模拟小参数 de_model 的运行时接口。"""

    def __init__(self, keep_threshold: float = 0.25) -> None:
        self.keep_threshold = keep_threshold
        self.persona_attr_types = {
            PIIAttributeType.NAME,
            PIIAttributeType.PHONE,
            PIIAttributeType.BANK_NUMBER,
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
        context: DecisionContext,
        packed: PackedDecisionFeatures,
        policy: DerivedDecisionPolicyContext | None = None,
    ) -> DEModelRuntimeOutput:
        """基于上下文与压缩特征生成占位策略输出。"""
        resolved_policy = policy or derive_policy_context(context)
        active_persona_id, persona_scores = self._select_persona(context=context, policy=resolved_policy)
        persona_slots: dict[PIIAttributeType, list[str]] = {}
        for item in context.persona_profiles:
            if item.persona_id == active_persona_id:
                persona_slots = item.slots
                break
        candidate_decisions: list[RuntimeCandidateDecision] = []
        for feature in resolved_policy.candidate_policy_views:
            scores = self._candidate_scores(
                feature=feature,
                active_persona_id=active_persona_id,
                persona_slots=persona_slots,
                page_vector=packed.page_vector,
            )
            final_action = max(scores, key=lambda key: (scores[key], self._tie_priority[key]))
            attr_type = _attr_type_from_view(feature)
            has_persona_slot = attr_type in persona_slots
            candidate_decisions.append(
                _build_runtime_candidate_decision(
                    candidate_id=str(feature.get("candidate_id", "")),
                    final_action=final_action,
                    persona_id=active_persona_id if final_action == ActionType.PERSONA_SLOT else None,
                    confidence=_confidence_from_view(feature),
                    reasons=self._reasons_for(
                        feature=feature,
                        final_action=final_action,
                        scores=scores,
                        has_persona_slot=has_persona_slot,
                    ),
                    fallback_reason=(
                        "candidate_conf_below_keep_threshold，启发式 runtime 对 KEEP 更保守。"
                        if final_action == ActionType.KEEP and _confidence_from_view(feature) < self.keep_threshold
                        else None
                    ),
                    action_scores=scores,
                )
            )
        return DEModelRuntimeOutput(
            active_persona_id=active_persona_id,
            persona_scores=persona_scores,
            candidate_decisions=candidate_decisions,
        )

    def _select_persona(
        self,
        *,
        context: DecisionContext,
        policy: DerivedDecisionPolicyContext,
    ) -> tuple[str | None, dict[str, float]]:
        persona_states = policy.persona_policy_states
        if not persona_states:
            return (None, {})
        active_persona_id = context.session_binding.active_persona_id if context.session_binding else None
        persona_scores = {
            str(state.get("persona_id", "")): self._persona_score(
                state=state,
                force_active=str(state.get("persona_id", "")) == active_persona_id,
            )
            for state in persona_states
            if str(state.get("persona_id", "")).strip()
        }
        if active_persona_id:
            return (active_persona_id, persona_scores)
        selected = max(
            persona_states,
            key=lambda state: (
                persona_scores[str(state.get("persona_id", ""))],
                -_exposure_count_from_state(state),
                str(state.get("persona_id", "")),
            ),
        )
        return (str(selected.get("persona_id", "")), persona_scores)

    def _persona_score(self, *, state: dict[str, object], force_active: bool) -> float:
        matched_score = min(1.0, _matched_candidate_attr_count_from_state(state) / 4.0)
        coverage_score = min(1.0, _slot_count_from_state(state) / 6.0)
        freshness_score = 1.0 - min(1.0, _exposure_count_from_state(state) / 32.0)
        active_bonus = 1.0 if force_active else 0.0
        return round(0.45 * matched_score + 0.3 * coverage_score + 0.25 * freshness_score + active_bonus, 4)

    def _candidate_scores(
        self,
        *,
        feature: dict[str, object],
        active_persona_id: str | None,
        persona_slots: dict[PIIAttributeType, list[str]],
        page_vector: list[float],
    ) -> dict[ActionType, float]:
        prompt_digit_bias = page_vector[6] if len(page_vector) > 6 else 0.0
        attr_type = _attr_type_from_view(feature)
        confidence = _confidence_from_view(feature)
        history_attr_exposure_count = _history_attr_exposure_count_from_view(feature)
        history_exact_match_count = _history_exact_match_count_from_view(feature)
        same_text_page_count = _same_text_page_count_from_view(feature)
        same_attr_page_count = _same_attr_page_count_from_view(feature)
        is_ocr_source = _is_ocr_source(feature)
        has_persona_slot = bool(active_persona_id) and attr_type in persona_slots
        keep_score = 0.12 + max(0.0, (self.keep_threshold - confidence) * 1.8)
        if confidence < 0.2:
            keep_score += 0.18
        if history_exact_match_count == 0 and same_text_page_count <= 1:
            keep_score += 0.04

        generic_score = 0.24 + confidence * 0.52
        generic_score += min(0.16, history_attr_exposure_count * 0.025)
        if attr_type in {
            PIIAttributeType.ID_NUMBER,
            PIIAttributeType.BANK_NUMBER,
            PIIAttributeType.PASSPORT_NUMBER,
            PIIAttributeType.DRIVER_LICENSE,
            PIIAttributeType.ORGANIZATION,
            PIIAttributeType.ALNUM,
            PIIAttributeType.OTHER,
        }:
            generic_score += 0.12
        if attr_type == PIIAttributeType.PHONE and prompt_digit_bias > 0:
            generic_score += 0.04
        if has_persona_slot:
            generic_score -= 0.08

        persona_score = 0.0
        if has_persona_slot and attr_type in self.persona_attr_types:
            persona_score = 0.39 + confidence * 0.38
            persona_score += min(0.12, history_attr_exposure_count * 0.02)
            persona_score += 0.05 if same_attr_page_count > 1 else 0.0
            persona_score += 0.04 if is_ocr_source else 0.0
        if confidence < self.keep_threshold:
            generic_score *= 0.82
            persona_score *= 0.7

        return {
            ActionType.KEEP: round(min(1.0, keep_score), 4),
            ActionType.GENERICIZE: round(min(1.0, generic_score), 4),
            ActionType.PERSONA_SLOT: round(min(1.0, persona_score), 4),
        }

    def _reasons_for(
        self,
        *,
        feature: dict[str, object],
        final_action: ActionType,
        scores: dict[ActionType, float],
        has_persona_slot: bool,
    ) -> list[str]:
        confidence = _confidence_from_view(feature)
        return [
            f"tiny_policy final_action={final_action.value}",
            f"candidate_conf={confidence:.2f}",
            f"history_attr={_history_attr_exposure_count_from_view(feature)}",
            f"history_exact={_history_exact_match_count_from_view(feature)}",
            f"persona_slot={'yes' if has_persona_slot else 'no'}",
            _scores_summary(scores),
        ]


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
        context: DecisionContext,
        packed: PackedDecisionFeatures,
        policy: DerivedDecisionPolicyContext | None = None,
    ) -> DEModelRuntimeOutput:
        """执行 TinyPolicyNet 前向，并把 logits 解码为运行时输出。"""
        _ = packed
        _ = policy
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


def _build_runtime_candidate_decision(
    *,
    candidate_id: str,
    final_action: ActionType | str,
    persona_id: str | None,
    confidence: float,
    reasons: list[str],
    fallback_reason: str | None,
    action_scores: dict[ActionType | str, float],
) -> RuntimeCandidateDecision:
    """构造统一 candidate runtime 输出，并兼容旧字段。"""
    return RuntimeCandidateDecision(
        candidate_id=candidate_id,
        final_action=final_action,
        persona_id=persona_id,
        confidence=round(float(confidence), 4),
        reasons=reasons,
        fallback_reason=fallback_reason,
        action_scores=action_scores,
    )


def _hierarchical_view(final_action: ActionType) -> tuple[str, str]:
    """把平面动作整理为 protect_decision + rewrite_mode 两级视图。"""
    normalized_action = _normalized_action_type(final_action)
    if normalized_action == ActionType.KEEP:
        return (PROTECT_LABEL_KEEP, REWRITE_MODE_NONE)
    if normalized_action == ActionType.PERSONA_SLOT:
        return (PROTECT_LABEL_REWRITE, ActionType.PERSONA_SLOT.value)
    return (PROTECT_LABEL_REWRITE, ActionType.GENERICIZE.value)


def _normalized_action_type(action_type: ActionType | str) -> ActionType:
    """归一化动作名：只接受工程动作（KEEP/GENERICIZE/PERSONA_SLOT）。"""
    if isinstance(action_type, ActionType):
        return action_type
    normalized = str(action_type or "").strip().upper()
    aliases = {
        "KEEP": ActionType.KEEP,
        "GENERICIZE": ActionType.GENERICIZE,
        "PERSONA_SLOT": ActionType.PERSONA_SLOT,
    }
    if normalized in aliases:
        return aliases[normalized]
    raise ValueError(f"非法 de_model 动作名: {action_type!r}")


def _normalized_action_scores(action_scores: dict[ActionType | str, float]) -> dict[ActionType, float]:
    """把旧 action score 键归一化到当前动作集合。"""
    normalized: dict[ActionType, float] = {action: 0.0 for action in ACTION_ORDER}
    for action, score in (action_scores or {}).items():
        normalized_action = _normalized_action_type(action)
        normalized[normalized_action] = max(normalized.get(normalized_action, 0.0), float(score))
    return normalized


def _compose_reason(reasons: list[str], fallback_reason: str | None) -> str:
    parts: list[str] = []
    for item in reasons:
        text = str(item).strip()
        if text and text not in parts:
            parts.append(text)
    fallback = str(fallback_reason or "").strip()
    if fallback and fallback not in parts:
        parts.append(fallback)
    return "；".join(parts)


def _attr_type_from_view(view: dict[str, object]) -> PIIAttributeType:
    attr = view.get("attr_type")
    if isinstance(attr, PIIAttributeType):
        return attr
    try:
        return PIIAttributeType(str(view.get("attr_id") or "").strip().lower())
    except Exception:
        return PIIAttributeType.OTHER


def _confidence_from_view(view: dict[str, object]) -> float:
    value = view.get("_confidence", 0.0)
    try:
        return float(value)
    except Exception:
        return 0.0


def _history_attr_exposure_count_from_view(view: dict[str, object]) -> int:
    try:
        return int(view.get("_history_attr_exposure_count", 0))
    except Exception:
        return 0


def _history_exact_match_count_from_view(view: dict[str, object]) -> int:
    try:
        return int(view.get("_history_exact_match_count", 0))
    except Exception:
        return 0


def _same_text_page_count_from_view(view: dict[str, object]) -> int:
    try:
        return int(view.get("_same_text_page_count", 0))
    except Exception:
        return 0


def _same_attr_page_count_from_view(view: dict[str, object]) -> int:
    try:
        return int(view.get("_same_attr_page_count", 0))
    except Exception:
        return 0


def _is_ocr_source(view: dict[str, object]) -> bool:
    source = view.get("source")
    value = getattr(source, "value", source)
    return str(value or "").strip().lower() == "ocr"


def _slot_count_from_state(state: dict[str, object]) -> int:
    try:
        return int(state.get("_slot_count", 0))
    except Exception:
        return 0


def _exposure_count_from_state(state: dict[str, object]) -> int:
    try:
        return int(state.get("_exposure_count", 0))
    except Exception:
        return 0


def _matched_candidate_attr_count_from_state(state: dict[str, object]) -> int:
    try:
        return int(state.get("matched_candidate_attr_count", 0))
    except Exception:
        return 0


def _scores_summary(action_scores: dict[ActionType | str, float]) -> str:
    normalized = _normalized_action_scores(action_scores)
    return (
        f"scores={{KEEP:{normalized[ActionType.KEEP]:.2f},"
        f"GENERIC:{normalized[ActionType.GENERICIZE]:.2f},"
        f"PERSONA:{normalized[ActionType.PERSONA_SLOT]:.2f}}}"
    )
