# de_model Training Workspace

这个目录只放 `de_model` 的离线训练与导出链路，不参与应用运行时的 `sanitize/restore` 主流程。

## 边界

- 运行时推理继续放在 `/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/`
- 对抗训练、会话模拟、reward 计算、模型导出放在 `/Users/vis/Documents/GitHub/PrivacyGuard/training/`
- Android 端最终只拿导出的轻量 policy 模型，不带 adversary

## 推荐目录

```text
training/
  README.md
  types.py
  torch_batch.py
  runtime_bridge.py
  session_rollout.py
  adversary.py
  losses.py
  export.py
  pipelines/
    build_dataset.py
    run_adversarial_finetune.py
    export_runtime_bundle.py
```

## 模块职责

- `types.py`
  定义训练侧的 episode、turn、policy 输出、adversary 观测结构。
- `runtime_bridge.py`
  把运行时 `DecisionModelContext` / `DecisionPlan` 转成训练样本与导出元数据。
- `torch_batch.py`
  把 `DecisionModelContext` 打成 `TinyPolicyNet` 可直接消费的 PyTorch batch。
- `session_rollout.py`
  管理多轮会话 rollout，把连续 turn 拼成 adversary 可消费的观察窗口。
- `adversary.py`
  定义云端对抗模型的输入输出协议，只在训练侧使用。
- `losses.py`
  定义 privacy / utility / consistency / latency 等目标的组合方式。
- `export.py`
  定义从训练 checkpoint 到运行时 bundle 的导出描述。
- `pipelines/build_dataset.py`
  从上下文样本构建训练数据集。
- `pipelines/run_adversarial_finetune.py`
  跑 policy vs adversary 的对抗式后训练。
- `pipelines/export_runtime_bundle.py`
  导出 ONNX/TFLite 与运行时 metadata。
- `/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/tiny_policy_net.py`
  真实的 PyTorch 模型原型，供训练与导出共用。

## 数据流

```text
DecisionModelContext
  -> DecisionFeatureExtractor
  -> policy model
  -> DecisionPlan / rendered turn
  -> session rollout
  -> adversary observation
  -> privacy / utility losses
  -> update policy
  -> export runtime bundle
  -> Android runtime
```

## 原则

- 训练侧可以很重：PyTorch、对抗模型、会话模拟都放这里。
- 运行时必须很轻：只保留特征提取、轻量 policy 推理、约束解析和回退逻辑。
- `DecisionModelContext` 与 `DecisionFeatureExtractor` 是训练和推理共享边界，尽量不要各自定义两套输入。
- 若要使用模型原型，推荐安装 `python -m pip install -e '.[train]'`。

当前这些文件只是工程骨架，还没有实现真正的训练循环。
