"""对抗训练目标组合。"""

from __future__ import annotations

from dataclasses import dataclass

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
