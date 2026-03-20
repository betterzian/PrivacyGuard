# de_model Training Workspace

这个目录只放 `de_model` 的离线训练、数据桥接和导出相关代码，不参与应用运行时的 `sanitize / restore` 主流程。

## 1. 当前边界

### 运行时代码仍在这里

- `privacyguard/application/services/decision_context_builder.py`
- `privacyguard/infrastructure/decision/features.py`
- `privacyguard/infrastructure/decision/de_model_engine.py`
- `privacyguard/infrastructure/decision/de_model_runtime.py`
- `privacyguard/infrastructure/decision/tiny_policy_net.py`

### 训练侧代码在这里

- `training/types.py`
- `training/runtime_bridge.py`
- `training/torch_batch.py`
- `training/session_rollout.py`
- `training/adversary.py`
- `training/losses.py`
- `training/export.py`
- `training/pipelines/`

## 2. 目录职责

| 文件 | 当前职责 |
| --- | --- |
| `types.py` | 训练侧样本、标签、预测、对抗观察窗口数据结构 |
| `runtime_bridge.py` | `DecisionContext` / `DecisionPlan` 与训练样本之间的桥接 |
| `torch_batch.py` | 把 `DecisionContext` 或训练样本打成 `TinyPolicyBatch` |
| `session_rollout.py` | 把连续 turn 组织成 episode 或 adversary observation window |
| `adversary.py` | 对抗模型协议与输出结构 |
| `losses.py` | privacy / utility / consistency / latency 的 reward 组合 |
| `export.py` | runtime bundle 描述与 metadata 生成 |
| `pipelines/build_dataset.py` | JSONL 数据集导出 |
| `pipelines/run_supervised_finetune.py` | 最小监督训练 |
| `pipelines/run_adversarial_finetune.py` | 对抗训练接口，当前未实现 |
| `pipelines/export_runtime_bundle.py` | bundle metadata 导出 |

## 3. 当前已经可用的训练闭环

### 3.1 数据导出

当前已经可用：

- `build_jsonl_dataset()`
- `build_supervised_jsonl_dataset()`

导出的 supervised JSONL 会包含：

- `TrainingTurnExample` 对应的序列化字段
- `labels.target_persona_id`
- `labels.candidate_actions`

### 3.2 最小监督训练

当前已经可用：

- `run_supervised_finetune()`

它会：

1. 读取 supervised JSONL
2. 构造 `TinyPolicyBatch`
3. 训练 `TinyPolicyNet`
4. 输出 checkpoint
5. 输出 metrics JSON

训练产物当前默认是：

- `tiny_policy_supervised.pt`
- `supervised_metrics.json`

### 3.3 运行时回接

训练出来的 checkpoint 可以被：

- `TorchTinyPolicyRuntime`
- `DEModelEngine(runtime_type="torch", checkpoint_path=...)`

直接加载。

## 4. 最小使用方式

当前训练侧没有 CLI，推荐以 Python API 方式调用。

### 4.1 导出 supervised 数据集

```python
from pathlib import Path

from training.pipelines.build_dataset import build_supervised_jsonl_dataset

dataset_path = build_supervised_jsonl_dataset(
    samples=zip(contexts, plans),
    output_path=Path("artifacts/train.jsonl"),
)
```

这里的 `contexts` 和 `plans` 分别是：

- `DecisionContext` 列表
- 与之对应的 `DecisionPlan` 列表

### 4.2 运行最小监督训练

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
```

### 4.3 用 torch runtime 回接

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

## 5. 依赖

如果要运行训练代码，至少需要：

```bash
python3 -m pip install -e '.[train]'
```

如果还要跑测试，建议：

```bash
python3 -m pip install -e '.[dev,train]'
```

## 6. 当前未完成项

这些接口已经有边界，但还没实现完整功能：

- `run_adversarial_finetune()`
- 真正的 policy vs adversary 对抗训练
- ONNX / TFLite 真正导出
- bundle runtime

`export_runtime_bundle()` 当前只负责写 metadata，不导出真实模型文件格式。

## 7. 当前结论

训练目录的当前状态可以总结为：

- 已经能导出 supervised JSONL
- 已经能完成最小行为克隆训练
- 已经能把训练产物接回 `de_model` 的 torch runtime
- 但对抗训练和移动端导出仍然只是下一阶段工作
