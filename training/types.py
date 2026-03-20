"""de_model 训练侧共享数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.domain.enums import ActionType, PIIAttributeType

PROTECT_LABEL_KEEP = "KEEP"
PROTECT_LABEL_REWRITE = "REWRITE"
REWRITE_MODE_NONE = "NONE"
REWRITE_MODE_GENERICIZE = ActionType.GENERICIZE.value
REWRITE_MODE_PERSONA_SLOT = ActionType.PERSONA_SLOT.value


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
    """表示单轮 supervised finetune 的层级目标标签。

    正式监督标签收敛为：

    - `target_persona_id`: turn 级 persona 目标
    - `target_protect_labels`: candidate 级 `KEEP / REWRITE`
    - `target_rewrite_modes`: candidate 级 `GENERICIZE / PERSONA_SLOT / NONE`

    同时保留兼容字段：

    - `candidate_actions`: 旧单层动作标签别名
    - `final_actions`: 单层 final_action 调试/兼容视图
    """

    target_persona_id: str | None
    candidate_actions: dict[str, ActionType] = field(default_factory=dict)
    final_actions: dict[str, ActionType] = field(default_factory=dict)
    target_protect_labels: dict[str, str] = field(default_factory=dict)
    target_rewrite_modes: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_candidate_actions = {
            candidate_id: normalize_action_type(action)
            for candidate_id, action in dict(self.candidate_actions).items()
        }
        normalized_final_actions = {
            candidate_id: normalize_action_type(action)
            for candidate_id, action in dict(self.final_actions).items()
        }
        if not normalized_final_actions:
            normalized_final_actions = dict(normalized_candidate_actions)
        if not normalized_candidate_actions:
            normalized_candidate_actions = dict(normalized_final_actions)

        candidate_ids = set(normalized_candidate_actions) | set(normalized_final_actions)
        candidate_ids.update(str(candidate_id) for candidate_id in self.target_protect_labels)
        candidate_ids.update(str(candidate_id) for candidate_id in self.target_rewrite_modes)

        protect_labels: dict[str, str] = {}
        rewrite_modes: dict[str, str] = {}
        final_actions: dict[str, ActionType] = {}
        for candidate_id in sorted(candidate_ids):
            provided_action = normalized_final_actions.get(candidate_id) or normalized_candidate_actions.get(candidate_id)
            provided_protect = normalize_protect_label(self.target_protect_labels.get(candidate_id))
            provided_rewrite = normalize_rewrite_mode(self.target_rewrite_modes.get(candidate_id))

            if provided_action is not None:
                derived_protect, derived_rewrite = action_to_hierarchical_labels(provided_action)
            else:
                derived_protect, derived_rewrite = (PROTECT_LABEL_KEEP, REWRITE_MODE_NONE)

            protect_label = provided_protect or derived_protect
            rewrite_mode = provided_rewrite or derived_rewrite
            final_action = provided_action or hierarchical_labels_to_action(protect_label, rewrite_mode)

            protect_labels[candidate_id] = protect_label
            rewrite_modes[candidate_id] = rewrite_mode
            final_actions[candidate_id] = final_action

        self.candidate_actions = dict(final_actions)
        self.final_actions = dict(final_actions)
        self.target_protect_labels = protect_labels
        self.target_rewrite_modes = rewrite_modes


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


def normalize_action_type(action: ActionType | str | None) -> ActionType:
    """归一化训练侧动作名，并兼容旧别名 `LABEL -> GENERICIZE`。"""
    if isinstance(action, ActionType):
        return action
    normalized = str(action or "").strip().upper()
    aliases = {
        "KEEP": ActionType.KEEP,
        "GENERICIZE": ActionType.GENERICIZE,
        "GENERIC": ActionType.GENERICIZE,
        "LABEL": ActionType.GENERICIZE,
        "PERSONA_SLOT": ActionType.PERSONA_SLOT,
        "PERSONA": ActionType.PERSONA_SLOT,
    }
    return aliases.get(normalized, ActionType.KEEP)


def normalize_protect_label(label: str | None) -> str | None:
    """归一化 protect 标签。"""
    normalized = str(label or "").strip().upper()
    if normalized in {PROTECT_LABEL_KEEP, PROTECT_LABEL_REWRITE}:
        return normalized
    return None


def normalize_rewrite_mode(mode: str | None) -> str | None:
    """归一化 rewrite_mode 标签，并兼容旧别名 `LABEL`。"""
    normalized = str(mode or "").strip().upper()
    aliases = {
        "": None,
        REWRITE_MODE_NONE: REWRITE_MODE_NONE,
        "GENERICIZE": REWRITE_MODE_GENERICIZE,
        "GENERIC": REWRITE_MODE_GENERICIZE,
        "LABEL": REWRITE_MODE_GENERICIZE,
        "PERSONA_SLOT": REWRITE_MODE_PERSONA_SLOT,
        "PERSONA": REWRITE_MODE_PERSONA_SLOT,
    }
    return aliases.get(normalized)


def action_to_hierarchical_labels(action: ActionType | str | None) -> tuple[str, str]:
    """把单层 final_action 拆成 protect_label + rewrite_mode。"""
    normalized_action = normalize_action_type(action)
    if normalized_action == ActionType.KEEP:
        return (PROTECT_LABEL_KEEP, REWRITE_MODE_NONE)
    if normalized_action == ActionType.PERSONA_SLOT:
        return (PROTECT_LABEL_REWRITE, REWRITE_MODE_PERSONA_SLOT)
    return (PROTECT_LABEL_REWRITE, REWRITE_MODE_GENERICIZE)


def hierarchical_labels_to_action(protect_label: str | None, rewrite_mode: str | None) -> ActionType:
    """把层级标签合成为单层 final_action。"""
    normalized_protect = normalize_protect_label(protect_label) or PROTECT_LABEL_KEEP
    normalized_rewrite = normalize_rewrite_mode(rewrite_mode) or REWRITE_MODE_NONE
    if normalized_protect == PROTECT_LABEL_KEEP:
        return ActionType.KEEP
    if normalized_rewrite == REWRITE_MODE_PERSONA_SLOT:
        return ActionType.PERSONA_SLOT
    return ActionType.GENERICIZE
