"""de_model 训练侧共享数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.domain.enums import ActionType, PIIAttributeType


@dataclass(slots=True)
class TrainingTurnExample:
    """表示单轮 policy 训练样本。"""

    session_id: str
    turn_id: int
    prompt_text: str
    ocr_texts: list[str]
    candidate_ids: list[str]
    candidate_texts: list[str]
    candidate_prompt_contexts: list[str]
    candidate_ocr_contexts: list[str]
    candidate_attr_types: list[PIIAttributeType]
    persona_ids: list[str]
    persona_texts: list[str]
    active_persona_id: str | None
    page_vector: list[float]
    candidate_vectors: list[list[float]]
    persona_vectors: list[list[float]]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class SupervisedTurnLabels:
    """表示单轮 supervised finetune 的目标标签。"""

    target_persona_id: str | None
    candidate_actions: dict[str, ActionType]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class TrainingTurnPrediction:
    """表示 policy 在单轮上的输出。"""

    active_persona_id: str | None
    candidate_actions: dict[str, ActionType]
    replacement_texts: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class RenderedTurnObservation:
    """表示对抗模型可见的一轮脱敏后观测。"""

    session_id: str
    turn_id: int
    sanitized_prompt_text: str
    sanitized_ocr_texts: list[str]
    chosen_persona_id: str | None
    applied_action_types: dict[str, ActionType]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AdversaryObservationWindow:
    """表示对抗模型看到的多轮窗口。"""

    session_id: str
    true_user_id: str
    turns: list[RenderedTurnObservation]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class TrainingEpisode:
    """表示一段完整的会话级训练 episode。"""

    session_id: str
    true_user_id: str
    turns: list[TrainingTurnExample]
    metadata: dict[str, str] = field(default_factory=dict)
