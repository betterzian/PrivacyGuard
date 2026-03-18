"""多轮会话 rollout 骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field

from training.types import AdversaryObservationWindow, RenderedTurnObservation, TrainingEpisode, TrainingTurnExample


@dataclass(slots=True)
class RolloutState:
    """表示一个会话 rollout 的累积状态。"""

    session_id: str
    true_user_id: str
    training_turns: list[TrainingTurnExample] = field(default_factory=list)
    rendered_turns: list[RenderedTurnObservation] = field(default_factory=list)

    def as_episode(self) -> TrainingEpisode:
        """导出训练 episode。"""
        return TrainingEpisode(
            session_id=self.session_id,
            true_user_id=self.true_user_id,
            turns=list(self.training_turns),
        )

    def as_observation_window(self) -> AdversaryObservationWindow:
        """导出 adversary 观察窗口。"""
        return AdversaryObservationWindow(
            session_id=self.session_id,
            true_user_id=self.true_user_id,
            turns=list(self.rendered_turns),
        )


class SessionRolloutBuilder:
    """负责把连续 turn 组织成对抗训练所需的多轮轨迹。"""

    def __init__(self, session_id: str, true_user_id: str) -> None:
        self.state = RolloutState(session_id=session_id, true_user_id=true_user_id)

    def append_turn(self, training_turn: TrainingTurnExample, rendered_turn: RenderedTurnObservation) -> None:
        """追加一轮训练输入与对抗观测。"""
        self.state.training_turns.append(training_turn)
        self.state.rendered_turns.append(rendered_turn)

    def build_episode(self) -> TrainingEpisode:
        """导出完整 episode。"""
        return self.state.as_episode()

    def build_observation_window(self) -> AdversaryObservationWindow:
        """导出当前多轮观察窗口。"""
        return self.state.as_observation_window()
