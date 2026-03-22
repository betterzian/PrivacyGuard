# de_model Training Workspace

这个目录只放 `de_model` 的离线训练、数据桥接和导出相关代码，不参与应用运行时的 `sanitize / restore` 主流程。

它当前已经能完成一条最小 supervised 闭环：

```text
DecisionContext / DecisionPlan
-> JSONL 数据导出
-> TinyPolicyNet supervised finetune
-> checkpoint
-> DEModelEngine(runtime_type="torch")
```

但它还不是完整的训练平台：对抗训练、真实 runtime bundle 导出、ONNX / TFLite 产物都还没有落地。

## 当前状态

| 能力 | 当前状态 |
| --- | --- |
| JSONL 数据导出 | 已可用 |
| 层级监督标签导出 | 已可用 |
| 最小 supervised finetune | 已可用 |
| torch runtime 回接 | 已可用 |
| runtime metadata 导出 | 已可用 |
| 对抗训练循环 | 仅保留配置与入口，未实现 |
| 真实 bundle 导出 | 仅写 metadata，不导出模型格式 |

## 边界

训练目录只负责离线侧逻辑。运行时代码仍然在主包里：

- `privacyguard/application/services/decision_context_builder.py`
- `privacyguard/infrastructure/decision/features.py`
- `privacyguard/infrastructure/decision/de_model_engine.py`
- `privacyguard/infrastructure/decision/de_model_runtime.py`
- `privacyguard/infrastructure/decision/tiny_policy_net.py`

训练侧代码集中在这里：

- `training/types.py`
- `training/runtime_bridge.py`
- `training/torch_batch.py`
- `training/session_rollout.py`
- `training/adversary.py`
- `training/losses.py`
- `training/export.py`
- `training/pipelines/`

## 目录职责

| 文件 | 当前职责 |
| --- | --- |
| `types.py` | 训练样本、层级标签、训练 episode、对抗观察窗口数据结构 |
| `runtime_bridge.py` | `DecisionContext` / `DecisionPlan` 与训练样本、监督标签、对抗观测之间的桥接 |
| `torch_batch.py` | 把 `DecisionContext` 或序列化样本打成 `TinyPolicyBatch` / `SupervisedTinyPolicyBatch` |
| `session_rollout.py` | 把连续 turn 组织成训练 episode 或 observation window |
| `adversary.py` | 对抗模型协议与预测结构 |
| `losses.py` | reward 组合逻辑，以及 supervised 层级损失 `L_protect / L_rewrite_mode / L_persona / L_cost` |
| `export.py` | `RuntimeBundleSpec` 与 runtime metadata 构造 |
| `pipelines/build_dataset.py` | 导出纯样本 JSONL 或带 supervision 的 JSONL |
| `pipelines/run_supervised_finetune.py` | 最小 supervised 行为克隆训练 |
| `pipelines/run_adversarial_finetune.py` | 对抗训练入口骨架，当前直接 `NotImplementedError` |
| `pipelines/export_runtime_bundle.py` | 写 runtime metadata JSON，不负责模型格式转换 |

## 当前可用闭环

### 1. 数据导出

当前已经可用：

- `build_jsonl_dataset()`
- `build_supervised_jsonl_dataset()`

其中 supervised JSONL 不只是旧版的 `labels.candidate_actions`，还会额外导出：

- `labels.target_persona_id`
- `labels.target_protect_label`
- `labels.target_rewrite_mode`
- `labels.final_action`
- `candidate_policy_view`
- `page_policy_state`
- `persona_policy_states`

也就是说，当前导出格式已经是“旧平面动作可兼容 + 新层级标签可训练”的双轨结构。

### 2. 最小 supervised finetune

当前已经可用：

- `run_supervised_finetune()`

它会：

1. 读取 supervised JSONL
2. 解析为 `TrainingTurnExample + SupervisedTurnLabels`
3. 构造 `SupervisedTinyPolicyBatch`
4. 训练 `TinyPolicyNet`
5. 输出 checkpoint
6. 输出 metrics JSON

### 3. 运行时回接

训练出来的 checkpoint 可以被以下运行时直接加载：

- `TorchTinyPolicyRuntime`
- `DEModelEngine(runtime_type="torch", checkpoint_path=...)`

### 4. runtime metadata 导出

`export_runtime_bundle()` 当前可用，但边界很明确：

- 会写 metadata JSON
- 不会把 PyTorch checkpoint 转成 ONNX / TFLite / 自定义 bundle

## 训练样本格式

### 通用样本字段

`build_jsonl_dataset()` 和 `build_supervised_jsonl_dataset()` 都会导出这些字段：

- `session_id`
- `turn_id`
- `prompt_text`
- `ocr_texts`
- `candidate_ids`
- `candidate_texts`
- `candidate_prompt_contexts`
- `candidate_ocr_contexts`
- `candidate_attr_types`
- `persona_ids`
- `persona_texts`
- `active_persona_id`
- `page_vector`
- `candidate_vectors`
- `persona_vectors`
- `candidate_policy_view`
- `page_policy_state`
- `persona_policy_states`
- `metadata`

其中三类策略视图是当前新格式的重点：

- `candidate_policy_view`
  以 `candidate_id -> policy_view` 的形式导出，方便训练侧直接按 candidate 对齐
- `page_policy_state`
  页面级风险和质量状态
- `persona_policy_states`
  persona 级摘要状态列表

### 监督标签字段

`build_supervised_jsonl_dataset()` 会在通用样本基础上增加 `labels`：

- `target_persona_id`
- `target_protect_label`
- `target_rewrite_mode`
- `final_action`
- `candidate_actions`
- `metadata`

语义上：

- `target_protect_label` 是 candidate 级 `KEEP / REWRITE`
- `target_rewrite_mode` 是 candidate 级 `GENERICIZE / PERSONA_SLOT / NONE`
- `final_action` 是 candidate 级最终动作
- `candidate_actions` 是兼容旧读取链路的平面动作视图

## 模型输入与训练目标

当前 `TinyPolicyNet` 的训练输入由两部分组成：

- 结构化特征
  `page_features`、`candidate_features`、`persona_features`
- 文本辅助特征
  `candidate_text`、`prompt_context`、`ocr_context`、`persona_text` 的字符级哈希编码

当前 supervised 训练目标是分层的：

- `L_protect`
  学 `KEEP / REWRITE`
- `L_rewrite_mode`
  学 `GENERICIZE / PERSONA_SLOT`
- `L_persona`
  学 turn 级 persona 选择
- `L_cost`
  对高风险页面误判 `KEEP` 的额外代价项

`L_cost` 当前至少覆盖两类附加惩罚：

- `protection_level == strong` 时误判 `KEEP`
- `page_quality_state == poor` 时误判 `KEEP`

## 最小使用方式

当前训练侧没有 CLI，推荐直接用 Python API。

### 1. 导出 supervised 数据集

```python
from pathlib import Path

from training.pipelines.build_dataset import build_supervised_jsonl_dataset

dataset_path = build_supervised_jsonl_dataset(
    samples=zip(contexts, plans),
    output_path=Path("artifacts/train.jsonl"),
)
```

这里的 `contexts` 和 `plans` 需要一一对齐：

- `contexts`: `DecisionContext` 列表
- `plans`: 与之对应的 `DecisionPlan` 列表

### 2. 运行最小 supervised finetune

```python
from pathlib import Path

from training.pipelines.run_supervised_finetune import (
    SupervisedFinetuneConfig,
    run_supervised_finetune,
)

result = run_supervised_finetune(
    SupervisedFinetuneConfig(
        train_jsonl=Path("artifacts/train.jsonl"),
        output_dir=Path("artifacts/sft"),
        epochs=1,
        batch_size=8,
        learning_rate=1e-3,
        device="cpu",
    )
)

print(result.checkpoint_path)
print(result.metrics_path)
print(result.final_loss)
```

### 3. 用 torch runtime 回接

```python
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine

engine = DEModelEngine(
    persona_repository=persona_repo,
    mapping_store=mapping_store,
    runtime_type="torch",
    checkpoint_path=str(result.checkpoint_path),
)

plan = engine.plan(context)
```

### 4. 导出 runtime metadata

```python
from pathlib import Path

from training.export import RuntimeBundleSpec
from training.pipelines.export_runtime_bundle import export_runtime_bundle

metadata_path = export_runtime_bundle(
    RuntimeBundleSpec(
        format="torch",
        model_path=Path("artifacts/sft/tiny_policy_supervised.pt"),
        metadata_path=Path("artifacts/bundle/runtime_metadata.json"),
        feature_version="decision_features_v1",
        max_candidates=32,
        max_personas=8,
    ),
    policy_name="tiny_policy_sft_v1",
)

print(metadata_path)
```

注意：这一步只会写 metadata，不会转换模型格式。

## `SupervisedFinetuneConfig` 常用项

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `train_jsonl` | 无 | supervised 数据集路径 |
| `output_dir` | 无 | 训练产物输出目录 |
| `base_checkpoint` | `None` | 可选 warm start checkpoint |
| `epochs` | `1` | 训练轮数 |
| `batch_size` | `8` | batch 大小 |
| `learning_rate` | `1e-3` | AdamW 学习率 |
| `device` | `"cpu"` | 训练设备 |
| `max_candidates` | `32` | batch 中最多保留的 candidate 数 |
| `max_personas` | `8` | batch 中最多保留的 persona 数 |
| `max_text_length` | `48` | 文本编码最大长度 |
| `vocab_size` | `2048` | 字符哈希词表大小 |
| `seed` | `13` | 随机种子 |
| `cost_loss_weight` | `0.25` | `L_cost` 的权重 |
| `high_protection_keep_penalty` | `1.0` | 高 protection 页面上误判 `KEEP` 的附加代价 |
| `low_quality_keep_penalty` | `1.0` | 低质量页面上误判 `KEEP` 的附加代价 |

## 训练产物

`run_supervised_finetune()` 默认会在 `output_dir` 下写出：

- `tiny_policy_supervised.pt`
- `supervised_metrics.json`

其中 checkpoint 当前包含：

- `state_dict`
- `model_config`
- `training_metadata`

`training_metadata` 里当前会记录：

- `objective`
- `train_examples`
- `epochs`
- `batch_size`
- `learning_rate`
- `final_loss`
- `final_protect_loss`
- `final_rewrite_mode_loss`
- `final_persona_loss`
- `final_cost_loss`

## 依赖

如果要运行训练代码，至少需要：

```bash
python3 -m pip install -e '.[train]'
```

如果还要跑测试，建议：

```bash
python3 -m pip install -e '.[dev,train]'
```

## 当前未完成项

这些边界已经固定，但功能还没有实现完：

- `run_adversarial_finetune()`
- 真正的 policy vs adversary 对抗训练循环
- ONNX / TFLite 等真实模型格式导出
- 可被 `runtime_type="bundle"` 直接消费的 runtime bundle

换句话说，训练目录当前已经能做的是：

- 导出监督样本
- 训练最小 `TinyPolicyNet`
- 把 checkpoint 接回 `de_model` 的 torch runtime
- 写出运行时 metadata

但它还不能直接产出移动端可部署的完整模型包。
