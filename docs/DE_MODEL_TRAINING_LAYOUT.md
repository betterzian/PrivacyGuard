# de_model 训练与运行时布局

这份文档说明当前仓库里 `de_model` 的 runtime 与 training 是怎么分层的，以及各自真实完成到了哪一步。

## 1. 分层目标

仓库当前明确区分两类职责：

- runtime inference
  端侧实际运行时会用到的上下文、特征提取、轻量推理、约束解析
- offline training
  数据导出、监督训练、对抗训练预留、bundle 导出预留

## 2. 当前放置位置

### 运行时

运行时相关代码位于：

- `privacyguard/application/services/decision_context_builder.py`
- `privacyguard/infrastructure/decision/features.py`
- `privacyguard/infrastructure/decision/de_model_engine.py`
- `privacyguard/infrastructure/decision/de_model_runtime.py`
- `privacyguard/infrastructure/decision/tiny_policy_net.py`

### 训练时

训练相关代码位于：

- `training/types.py`
- `training/runtime_bridge.py`
- `training/torch_batch.py`
- `training/session_rollout.py`
- `training/adversary.py`
- `training/losses.py`
- `training/export.py`
- `training/pipelines/build_dataset.py`
- `training/pipelines/run_supervised_finetune.py`
- `training/pipelines/run_adversarial_finetune.py`
- `training/pipelines/export_runtime_bundle.py`

## 3. 为什么不能把训练逻辑塞进 runtime 包

当前代码分层的原因很直接：

1. 训练依赖更重
   `torch`、训练数据集、对抗模型、rollout 逻辑不应该跟着端侧推理链一起打包
2. 输入输出要求不同
   runtime 要稳定、低延迟；training 要可迭代、可导出、可扩展
3. 上线边界更清晰
   端侧最终只应该依赖轻量推理边界，而不是完整训练系统

## 4. 当前已经实现的训练侧链路

### 4.1 数据桥接

当前已经实现：

- `pack_training_turn()`
  把 `DecisionContext` 变成 `TrainingTurnExample`
- `plan_to_supervision()`
  把 `DecisionPlan` 变成监督标签
- `plan_to_observation()`
  把渲染结果整理成对抗模型可见观测

### 4.2 数据集导出

当前已经实现：

- `build_jsonl_dataset()`
  导出无标签 JSONL
- `build_supervised_jsonl_dataset()`
  导出带 `labels` 的 supervised JSONL

### 4.3 监督训练

当前已经实现：

- `run_supervised_finetune()`
  从 JSONL 读取样本
- `TinyPolicyBatchBuilder.build_examples()`
  从序列化样本恢复 `TinyPolicyBatch`
- `TinyPolicyNet` 的最小行为克隆训练
- 导出 `tiny_policy_supervised.pt`
- 导出 `supervised_metrics.json`

### 4.4 运行时回接

当前已经实现：

- `TorchTinyPolicyRuntime`
  直接加载 supervised 训练产物
- `DEModelEngine(runtime_type="torch", checkpoint_path=...)`
  在 `sanitize` 主链路中执行 torch runtime

## 5. 当前仍未实现的部分

### 5.1 对抗训练

`run_adversarial_finetune()` 目前只有接口和配置对象，实际会直接抛出 `NotImplementedError`。

### 5.2 真正的 bundle 导出

`export_runtime_bundle()` 目前只写 metadata 文件，不负责：

- ONNX 导出
- TFLite 导出
- 量化
- 端侧 bundle 加载器

### 5.3 端侧 bundle runtime

`DEModelEngine(runtime_type="bundle")` 当前仍未实现，调用会报错。

## 6. 当前推荐数据流

```text
DecisionContext
  -> DecisionFeatureExtractor
  -> DecisionPlan
  -> runtime_bridge / dataset export
  -> supervised JSONL
  -> TinyPolicyNet finetune
  -> checkpoint
  -> TorchTinyPolicyRuntime
```

如果未来继续扩展，对抗训练链路应当放在训练目录里，而不是塞回 runtime 包：

```text
DecisionContext
  -> DecisionPlan / rendered turn
  -> SessionRolloutBuilder
  -> AdversaryObservationWindow
  -> AdversaryModel
  -> reward
  -> policy update
```

## 7. 当前结论

仓库现在已经具备：

- 统一的 runtime 上下文边界
- 稳定的定长特征
- PyTorch 原型网络
- 最小监督训练
- checkpoint 到 runtime 的回接

但还没有具备：

- 真正的 policy vs adversary 训练系统
- 真正的移动端模型导出产物
- 真正的 bundle runtime
