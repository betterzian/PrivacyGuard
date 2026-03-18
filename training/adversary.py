"""云端对抗模型协议。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from training.types import AdversaryObservationWindow


@dataclass(slots=True)
class IdentityPosterior:
    """表示 adversary 对候选身份的后验估计。"""

    identity_id: str
    probability: float


@dataclass(slots=True)
class AdversaryPrediction:
    """表示 adversary 对当前会话的预测结果。"""

    most_likely_identity_id: str
    most_likely_probability: float
    posteriors: list[IdentityPosterior] = field(default_factory=list)
    leaked_attributes: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


class AdversaryModel(Protocol):
    """训练侧云端对抗模型接口。"""

    def predict(self, observation: AdversaryObservationWindow) -> AdversaryPrediction:
        """对多轮观测进行身份或属性推断。"""
