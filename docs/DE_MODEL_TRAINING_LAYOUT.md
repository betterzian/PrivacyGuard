# de_model Training vs Runtime Layout

## 目标

把 `de_model` 的两类职责彻底分开：

- **runtime inference**
  端侧实际运行时的特征提取、轻量模型推理、约束解析、回退逻辑
- **offline adversarial training**
  多轮会话模拟、云端对抗模型、reward 组合、后训练与导出

## 放置位置

### 运行时

继续放在：

- `/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/features.py`
- `/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/de_model_runtime.py`
- `/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/de_model_engine.py`

### 训练时

放在：

- `/Users/vis/Documents/GitHub/PrivacyGuard/training/`

## 为什么不能把对抗训练塞进 runtime 包里

1. 训练依赖会变重
   对抗模型、session simulator、实验脚本都不应该跟着 Android 推理链打包。
2. 职责会混乱
   运行时关心低延迟和稳定输入输出，训练侧关心 rollout、loss、checkpoint 和实验迭代。
3. 上线边界会变脆
   adversary 只应存在于训练系统，不应出现在端侧产物里。

## 推荐数据流

```text
sanitize pipeline
  -> DecisionContext
  -> DecisionFeatureExtractor
  -> policy model
  -> DecisionPlan
  -> rendered turn
  -> session rollout
  -> adversary prediction
  -> privacy / utility / consistency reward
  -> update policy
  -> export ONNX/TFLite bundle
  -> runtime loads exported bundle only
```

## 当前骨架

当前仓库已经具备：

- runtime 侧 `DecisionContext`
- runtime 侧 `DecisionFeatureExtractor`
- runtime 侧 `TinyPolicyRuntime`
- runtime/导出共用的 `TinyPolicyNet` PyTorch 原型
- training 侧目录骨架与导出位点

当前仓库还没有实现：

- 真实 policy 网络训练
- 真实 adversary 网络训练
- RL / PPO / GRPO / policy-gradient 训练循环
- 真正的 ONNX/TFLite 导出脚本
