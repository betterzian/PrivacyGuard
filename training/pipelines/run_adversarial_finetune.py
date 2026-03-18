"""对抗式后训练入口骨架。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from training.losses import TrainingObjectiveWeights


@dataclass(slots=True)
class AdversarialFinetuneConfig:
    """对抗训练最小配置。"""

    train_jsonl: Path
    output_dir: Path
    policy_checkpoint: Path | None = None
    adversary_checkpoint: Path | None = None
    weights: TrainingObjectiveWeights = field(default_factory=TrainingObjectiveWeights)
    epochs: int = 1
    batch_size: int = 8


def run_adversarial_finetune(config: AdversarialFinetuneConfig) -> None:
    """预留给真实训练循环的入口。"""
    raise NotImplementedError(
        "这里预留给 policy vs adversary 的真实训练实现；"
        "当前仓库只先固定目录结构、输入输出边界和导出位点。"
    )
