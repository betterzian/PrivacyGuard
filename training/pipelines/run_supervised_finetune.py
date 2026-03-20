"""最小 supervised finetune 入口。"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from training.types import SupervisedTurnLabels, TrainingTurnExample, normalize_action_type


@dataclass(slots=True)
class SupervisedFinetuneConfig:
    """最小 supervised finetune 配置。"""

    train_jsonl: Path
    output_dir: Path
    base_checkpoint: Path | None = None
    epochs: int = 1
    batch_size: int = 8
    learning_rate: float = 1e-3
    device: str = "cpu"
    max_candidates: int = 32
    max_personas: int = 8
    max_text_length: int = 48
    vocab_size: int = 2048
    seed: int = 13
    cost_loss_weight: float = 0.25
    high_protection_keep_penalty: float = 1.0
    low_quality_keep_penalty: float = 1.0


@dataclass(slots=True)
class SupervisedFinetuneResult:
    """supervised finetune 的输出摘要。"""

    checkpoint_path: Path
    metrics_path: Path
    train_examples: int
    epochs: int
    final_loss: float


def run_supervised_finetune(config: SupervisedFinetuneConfig) -> SupervisedFinetuneResult:
    """使用 JSONL 监督样本对 TinyPolicyNet 做最小行为克隆训练。"""
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("未安装 torch，无法运行 supervised finetune。") from exc
    from training.losses import SupervisedLossWeights, compute_hierarchical_supervised_loss
    from training.torch_batch import TinyPolicyBatchBuilder

    records = _load_supervised_records(config.train_jsonl)
    if not records:
        raise ValueError("train_jsonl 中没有可用的 supervised 样本。")
    if config.epochs <= 0:
        raise ValueError("epochs 必须大于 0。")
    if config.batch_size <= 0:
        raise ValueError("batch_size 必须大于 0。")

    torch.manual_seed(config.seed)
    randomizer = random.Random(config.seed)

    model = _build_or_load_model(config=config, torch_module=torch)
    model.to(config.device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate)
    batch_builder = TinyPolicyBatchBuilder(
        max_candidates=config.max_candidates,
        max_personas=config.max_personas,
        max_text_length=model.config.max_text_length,
        vocab_size=model.config.vocab_size,
    )
    loss_weights = SupervisedLossWeights(
        cost=config.cost_loss_weight,
        high_protection_keep_penalty=config.high_protection_keep_penalty,
        low_quality_keep_penalty=config.low_quality_keep_penalty,
    )

    final_loss = 0.0
    final_breakdown = {
        "protect_loss": 0.0,
        "rewrite_mode_loss": 0.0,
        "persona_loss": 0.0,
        "cost_loss": 0.0,
    }
    for _epoch in range(config.epochs):
        model.train()
        order = list(range(len(records)))
        randomizer.shuffle(order)
        epoch_loss_total = 0.0
        epoch_breakdown_total = {
            "protect_loss": 0.0,
            "rewrite_mode_loss": 0.0,
            "persona_loss": 0.0,
            "cost_loss": 0.0,
        }
        epoch_steps = 0
        for start in range(0, len(order), config.batch_size):
            batch_records = [records[index] for index in order[start : start + config.batch_size]]
            batch_examples = [example for example, _labels in batch_records]
            batch_labels = [labels for _example, labels in batch_records]
            batch = batch_builder.build_supervised_examples(batch_examples, batch_labels).to(config.device)
            output = model(batch)
            loss, breakdown = compute_hierarchical_supervised_loss(
                output=output,
                batch=batch,
                example_metadatas=[example.metadata for example in batch_examples],
                torch_module=torch,
                weights=loss_weights,
            )

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            epoch_loss_total += float(loss.detach().item())
            epoch_breakdown_total["protect_loss"] += breakdown.protect_loss
            epoch_breakdown_total["rewrite_mode_loss"] += breakdown.rewrite_mode_loss
            epoch_breakdown_total["persona_loss"] += breakdown.persona_loss
            epoch_breakdown_total["cost_loss"] += breakdown.cost_loss
            epoch_steps += 1

        final_loss = epoch_loss_total / max(1, epoch_steps)
        final_breakdown = {
            key: value / max(1, epoch_steps)
            for key, value in epoch_breakdown_total.items()
        }

    config.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = config.output_dir / "tiny_policy_supervised.pt"
    metrics_path = config.output_dir / "supervised_metrics.json"
    model.eval()
    torch.save(
        {
            "state_dict": model.state_dict(),
            "model_config": asdict(model.config),
            "training_metadata": {
                "objective": "hierarchical_supervised_behavior_cloning",
                "train_examples": str(len(records)),
                "epochs": str(config.epochs),
                "batch_size": str(config.batch_size),
                "learning_rate": str(config.learning_rate),
                "final_loss": f"{final_loss:.6f}",
                "final_protect_loss": f"{final_breakdown['protect_loss']:.6f}",
                "final_rewrite_mode_loss": f"{final_breakdown['rewrite_mode_loss']:.6f}",
                "final_persona_loss": f"{final_breakdown['persona_loss']:.6f}",
                "final_cost_loss": f"{final_breakdown['cost_loss']:.6f}",
            },
        },
        checkpoint_path,
    )
    metrics_path.write_text(
        json.dumps(
            {
                "train_examples": len(records),
                "epochs": config.epochs,
                "batch_size": config.batch_size,
                "learning_rate": config.learning_rate,
                "final_loss": final_loss,
                "final_protect_loss": final_breakdown["protect_loss"],
                "final_rewrite_mode_loss": final_breakdown["rewrite_mode_loss"],
                "final_persona_loss": final_breakdown["persona_loss"],
                "final_cost_loss": final_breakdown["cost_loss"],
            },
        ),
        encoding="utf-8",
    )
    return SupervisedFinetuneResult(
        checkpoint_path=checkpoint_path,
        metrics_path=metrics_path,
        train_examples=len(records),
        epochs=config.epochs,
        final_loss=final_loss,
    )


def _build_or_load_model(*, config: SupervisedFinetuneConfig, torch_module):
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig

    if config.base_checkpoint is None:
        return TinyPolicyNet(
            TinyPolicyNetConfig(
                max_text_length=config.max_text_length,
                vocab_size=config.vocab_size,
            )
        )
    try:
        payload = torch_module.load(config.base_checkpoint, map_location=config.device, weights_only=False)
    except TypeError:
        payload = torch_module.load(config.base_checkpoint, map_location=config.device)
    checkpoint_config = payload.get("model_config") if isinstance(payload, dict) else None
    state_dict = payload.get("state_dict", payload) if isinstance(payload, dict) else payload
    model_config = _resolve_model_config(checkpoint_config, config)
    model = TinyPolicyNet(model_config)
    model.load_state_dict(state_dict)
    return model


def _resolve_model_config(payload, config: SupervisedFinetuneConfig):
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNetConfig

    if payload is None:
        return TinyPolicyNetConfig(max_text_length=config.max_text_length, vocab_size=config.vocab_size)
    if isinstance(payload, TinyPolicyNetConfig):
        return payload
    if isinstance(payload, dict):
        return TinyPolicyNetConfig(**payload)
    raise ValueError("supervised checkpoint 中的 model_config 格式非法。")


def _load_supervised_records(path: Path) -> list[tuple[TrainingTurnExample, SupervisedTurnLabels]]:
    records: list[tuple[TrainingTurnExample, SupervisedTurnLabels]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            labels_payload = payload.get("labels")
            if not isinstance(labels_payload, dict):
                raise ValueError("supervised jsonl 缺少 labels 字段。")
            metadata = dict(payload.get("metadata", {}))
            page_policy_state = payload.get("page_policy_state")
            if isinstance(page_policy_state, dict):
                if page_policy_state.get("protection_level") is not None:
                    metadata.setdefault("protection_level", str(page_policy_state.get("protection_level")))
                if page_policy_state.get("page_quality_state") is not None:
                    metadata.setdefault("page_quality_state", str(page_policy_state.get("page_quality_state")))
            example = TrainingTurnExample(
                session_id=payload["session_id"],
                turn_id=int(payload["turn_id"]),
                prompt_text=payload.get("prompt_text", ""),
                ocr_texts=list(payload.get("ocr_texts", [])),
                candidate_ids=list(payload.get("candidate_ids", [])),
                candidate_texts=list(payload.get("candidate_texts", [])),
                candidate_prompt_contexts=list(payload.get("candidate_prompt_contexts", [])),
                candidate_ocr_contexts=list(payload.get("candidate_ocr_contexts", [])),
                candidate_attr_types=[PIIAttributeType(item) for item in payload.get("candidate_attr_types", [])],
                persona_ids=list(payload.get("persona_ids", [])),
                persona_texts=list(payload.get("persona_texts", [])),
                active_persona_id=payload.get("active_persona_id"),
                page_vector=list(payload.get("page_vector", [])),
                candidate_vectors=[list(item) for item in payload.get("candidate_vectors", [])],
                persona_vectors=[list(item) for item in payload.get("persona_vectors", [])],
                metadata=metadata,
            )
            labels = SupervisedTurnLabels(
                target_persona_id=labels_payload.get("target_persona_id"),
                candidate_actions={
                    candidate_id: normalize_action_type(action_value)
                    for candidate_id, action_value in dict(labels_payload.get("candidate_actions", {})).items()
                },
                final_actions={
                    candidate_id: normalize_action_type(action_value)
                    for candidate_id, action_value in dict(labels_payload.get("final_action", {})).items()
                },
                target_protect_labels={
                    str(candidate_id): str(label_value)
                    for candidate_id, label_value in dict(labels_payload.get("target_protect_label", {})).items()
                },
                target_rewrite_modes={
                    str(candidate_id): str(mode_value)
                    for candidate_id, mode_value in dict(labels_payload.get("target_rewrite_mode", {})).items()
                },
                metadata=dict(labels_payload.get("metadata", {})),
            )
            records.append((example, labels))
    return records
