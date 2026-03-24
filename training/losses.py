"""对抗训练目标组合。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from privacyguard.domain.policies.action_labels import (
    PROTECT_LABEL_KEEP,
    PROTECT_LABEL_REWRITE,
    PROTECT_ORDER,
    REWRITE_MODE_GENERICIZE,
    REWRITE_MODE_NONE,
    REWRITE_MODE_ORDER,
    REWRITE_MODE_PERSONA_SLOT,
)
from training.adversary import AdversaryPrediction


@dataclass(slots=True)
class TrainingObjectiveWeights:
    """各训练目标的权重。"""

    privacy: float = 1.0
    utility: float = 1.0
    consistency: float = 1.0
    latency: float = 0.0


@dataclass(slots=True)
class RewardBreakdown:
    """单个 rollout 的目标分解。"""

    privacy_score: float
    utility_score: float
    consistency_score: float
    latency_score: float = 0.0


def privacy_score_from_adversary(prediction: AdversaryPrediction, true_user_id: str) -> float:
    """把 adversary 的身份后验转成越大越好的隐私分数。"""
    for posterior in prediction.posteriors:
        if posterior.identity_id == true_user_id:
            return max(0.0, 1.0 - posterior.probability)
    if prediction.most_likely_identity_id == true_user_id:
        return max(0.0, 1.0 - prediction.most_likely_probability)
    return 1.0


def combine_reward(weights: TrainingObjectiveWeights, reward: RewardBreakdown) -> float:
    """按线性组合给出一个总 reward。"""
    return (
        weights.privacy * reward.privacy_score
        + weights.utility * reward.utility_score
        + weights.consistency * reward.consistency_score
        + weights.latency * reward.latency_score
    )


IGNORE_INDEX = -100


@dataclass(slots=True)
class SupervisedLossWeights:
    """supervised 层级训练目标权重。"""

    protect: float = 1.0
    rewrite_mode: float = 1.0
    persona: float = 1.0
    cost: float = 0.25
    high_protection_keep_penalty: float = 1.0
    low_quality_keep_penalty: float = 1.0


@dataclass(slots=True)
class SupervisedLossBreakdown:
    """supervised 损失分解。"""

    protect_loss: float = 0.0
    rewrite_mode_loss: float = 0.0
    persona_loss: float = 0.0
    cost_loss: float = 0.0
    total_loss: float = 0.0


def compute_hierarchical_supervised_loss(
    *,
    output,
    batch,
    example_metadatas: Sequence[dict[str, str]] | None,
    torch_module,
    weights: SupervisedLossWeights | None = None,
):
    """计算层级 supervised finetune 损失。

    组成：

    - `L_protect`: `KEEP / REWRITE`
    - `L_rewrite_mode`: `GENERICIZE / PERSONA_SLOT`
    - `L_persona`: `persona_id`
    - `L_cost`: 针对高风险页面上误判 KEEP 的额外代价

    兼容策略：

    - 若模型已输出 `protect_logits / rewrite_mode_logits`，优先使用新 head
    - 若仍只有旧 `action_logits`，则在损失层派生两级 logits，作为兼容 fallback
    - `PERSONA_SLOT` 非法（无 persona target）时，对应 rewrite_mode 标签会被 mask
    """
    from torch.nn import functional as F

    loss_weights = weights or SupervisedLossWeights()
    protect_logits = _protect_logits(output=output)
    rewrite_mode_logits = _rewrite_mode_logits(output=output)
    device = batch.page_features.device
    zero = batch.page_features.sum() * 0.0
    total_loss = zero
    breakdown = SupervisedLossBreakdown()

    if bool((batch.target_protect_labels != IGNORE_INDEX).any().item()):
        protect_loss = F.cross_entropy(
            protect_logits.reshape(-1, protect_logits.shape[-1]),
            batch.target_protect_labels.reshape(-1),
            ignore_index=IGNORE_INDEX,
        )
        total_loss = total_loss + loss_weights.protect * protect_loss
        breakdown.protect_loss = float(protect_loss.detach().item())
    else:
        protect_loss = zero

    rewrite_targets = _masked_rewrite_targets(batch=batch, torch_module=torch_module)
    if bool((rewrite_targets != IGNORE_INDEX).any().item()):
        rewrite_mode_loss = F.cross_entropy(
            rewrite_mode_logits.reshape(-1, rewrite_mode_logits.shape[-1]),
            rewrite_targets.reshape(-1),
            ignore_index=IGNORE_INDEX,
        )
        total_loss = total_loss + loss_weights.rewrite_mode * rewrite_mode_loss
        breakdown.rewrite_mode_loss = float(rewrite_mode_loss.detach().item())
    else:
        rewrite_mode_loss = zero

    persona_target_mask = batch.target_persona_indices != IGNORE_INDEX
    if bool(persona_target_mask.any().item()):
        persona_loss = F.cross_entropy(
            output.persona_logits[persona_target_mask],
            batch.target_persona_indices[persona_target_mask],
        )
        total_loss = total_loss + loss_weights.persona * persona_loss
        breakdown.persona_loss = float(persona_loss.detach().item())
    else:
        persona_loss = zero

    if loss_weights.cost > 0.0:
        cost_loss = _keep_cost_loss(
            protect_logits=protect_logits,
            protect_targets=batch.target_protect_labels,
            example_metadatas=example_metadatas or (),
            torch_module=torch_module,
            high_protection_keep_penalty=loss_weights.high_protection_keep_penalty,
            low_quality_keep_penalty=loss_weights.low_quality_keep_penalty,
            device=device,
        )
        total_loss = total_loss + loss_weights.cost * cost_loss
        breakdown.cost_loss = float(cost_loss.detach().item())
    else:
        cost_loss = zero

    breakdown.total_loss = float(total_loss.detach().item())
    return (total_loss, breakdown)


def _protect_logits(*, output):
    logits = getattr(output, "protect_logits", None)
    if logits is None:
        raise ValueError("模型输出缺少 protect_logits，无法计算层级监督损失。")
    return logits


def _rewrite_mode_logits(*, output):
    logits = getattr(output, "rewrite_mode_logits", None)
    if logits is None:
        raise ValueError("模型输出缺少 rewrite_mode_logits，无法计算层级监督损失。")
    return logits


def _masked_rewrite_targets(*, batch, torch_module):
    targets = batch.target_rewrite_modes.clone()
    persona_slot_index = REWRITE_MODE_ORDER.index(REWRITE_MODE_PERSONA_SLOT)
    illegal_persona_mask = (
        (targets == persona_slot_index)
        & (batch.target_persona_indices.unsqueeze(1) == IGNORE_INDEX)
    )
    return targets.masked_fill(illegal_persona_mask, IGNORE_INDEX)


def _keep_cost_loss(
    *,
    protect_logits,
    protect_targets,
    example_metadatas: Sequence[dict[str, str]],
    torch_module,
    high_protection_keep_penalty: float,
    low_quality_keep_penalty: float,
    device,
):
    rewrite_index = PROTECT_ORDER.index(PROTECT_LABEL_REWRITE)
    keep_index = PROTECT_ORDER.index(PROTECT_LABEL_KEEP)
    rewrite_mask = protect_targets == rewrite_index
    if not bool(rewrite_mask.any().item()):
        return protect_logits.sum() * 0.0

    keep_probabilities = torch_module.softmax(protect_logits, dim=-1)[..., keep_index]
    row_weights = torch_module.ones(
        (protect_logits.shape[0],),
        dtype=keep_probabilities.dtype,
        device=device,
    )
    for row_index, metadata in enumerate(example_metadatas):
        protection_level = str((metadata or {}).get("protection_level", "")).strip().lower()
        page_quality_state = str((metadata or {}).get("page_quality_state", "")).strip().lower()
        if protection_level == "strong":
            row_weights[row_index] += float(high_protection_keep_penalty)
        if page_quality_state == "poor":
            row_weights[row_index] += float(low_quality_keep_penalty)

    weighted_keep_cost = keep_probabilities * row_weights.unsqueeze(1)
    return weighted_keep_cost[rewrite_mask].mean()
