# de_model 训练与运行时布局

本文档描述当前仓库中 `de_model` 的 training / runtime 分层，以及它们和当前代码的对应关系。

需要先明确两点：

- `de_model` 是**策略决策层**
- `de_model` **不是 detector**，也**不是 OCR 清洗主逻辑**，更不是复杂 linking 系统

当前运行时的正式动作术语统一为：

- `KEEP`
- `GENERICIZE`
- `PERSONA_SLOT`

同时，内部训练和 runtime 可以采用两级视角：

- `protect_decision`: `KEEP / REWRITE`
- `rewrite_mode`: `GENERICIZE / PERSONA_SLOT / NONE`

---

## 1. 当前分层

### 1.1 runtime inference

runtime 侧负责：

- 读取 `DecisionContext` 并在内部派生策略视图
- 提取轻量特征
- 通过 torch runtime 做策略推理
- 输出统一 runtime 协议
- 收敛为最终执行动作

当前相关代码主要位于：

- `privacyguard/application/services/decision_context_builder.py`
- `privacyguard/infrastructure/decision/features.py`
- `privacyguard/infrastructure/decision/de_model_runtime.py`
- `privacyguard/infrastructure/decision/de_model_engine.py`
- `privacyguard/infrastructure/decision/tiny_policy_net.py`

### 1.2 offline training

training 侧负责：

- 把 runtime 上下文与 plan 导出为训练样本
- 组织结构化特征与文本辅助通道
- 组织层级监督标签
- 执行 supervised finetune

当前相关代码主要位于：

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

---

## 2. 当前运行时输入边界

### 2.1 正式上下文：`DecisionContext`

当前 runtime 的正式上下文已经收敛为 `DecisionContext`，并在 decision 模块内部派生出四块策略视图：

- `raw_refs`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

这是当前训练与运行时共享的上游语义边界。

### 2.2 特征映射

`privacyguard/infrastructure/decision/features.py` 当前正式按三类输入构造特征：

- `candidate_policy_views -> candidate dense features`
- `page_policy_state -> page features`
- `persona_policy_states -> persona features`

文本通道仍保留，但定位为辅助输入，不是主决策载体。当前辅助文本包括：

- `candidate_text`
- `prompt_context`
- `ocr_context`

### 2.3 runtime 输出协议

当前 runtime 输出统一为 `DEModelRuntimeOutput`，每个 candidate 的输出协议为 `RuntimeCandidateDecision`，至少包含：

- `candidate_id`
- `protect_decision`
- `rewrite_mode`
- `final_action`
- `persona_id`
- `confidence`
- `reasons`
- `fallback_reason`

其中：

- `final_action` 是当前引擎执行边界
- `protect_decision + rewrite_mode` 是当前 runtime / training 更稳定的层级视角

---

## 3. 当前训练数据布局

### 3.1 基础样本：`TrainingTurnExample`

`TrainingTurnExample` 表示单轮训练样本，当前包含：

- prompt / OCR 文本
- candidate ids / candidate texts
- prompt / OCR 局部上下文文本
- persona ids / persona texts
- `page_vector`
- `candidate_vectors`
- `persona_vectors`
- metadata

也就是说，训练样本同时承载：

- 结构化特征
- 文本辅助特征

### 3.2 正式监督标签：`SupervisedTurnLabels`

当前需要区分两层：

- **内存对象**：`training/types.py` 中的 `SupervisedTurnLabels`
- **导出 JSONL**：`training/pipelines/build_dataset.py` 写出的 `labels`

`SupervisedTurnLabels` 的正式字段是：

- `target_persona_id`
- `candidate_actions`
- `final_actions`
- `target_protect_labels`
- `target_rewrite_modes`

导出到 JSONL 时，对应键名是：

- `target_persona_id`
- `candidate_actions`
- `final_action`
- `target_protect_label`
- `target_rewrite_mode`

含义如下：

#### `target_protect_labels` / `target_protect_label`

candidate 级标签：

- `KEEP`
- `REWRITE`

前者是 `SupervisedTurnLabels` 的内存字段名，后者是 JSONL 中的导出键名。

#### `target_rewrite_modes` / `target_rewrite_mode`

candidate 级标签：

- `GENERICIZE`
- `PERSONA_SLOT`
- `NONE`

其中：

- `KEEP -> rewrite_mode = NONE`

#### `target_persona_id`

turn 级 persona 目标。  
当当前轮不需要或不存在 persona 监督时，可以为空。

#### `final_actions` / `final_action`

candidate 级最终动作标签，当前作为：

- 兼容字段
- 调试字段
- 从层级标签回收敛后的单层执行视图

### 3.3 旧标签兼容

当前仓库仍兼容旧的单层动作标签读取路径：

- `candidate_actions`

兼容拆解规则是：

- `KEEP -> target_protect_label=KEEP, target_rewrite_mode=NONE`
- `GENERICIZE -> target_protect_label=REWRITE, target_rewrite_mode=GENERICIZE`
- `PERSONA_SLOT -> target_protect_label=REWRITE, target_rewrite_mode=PERSONA_SLOT`

需要特别注意：

- 当前 training / runtime 主链默认只使用三种正式动作名：`KEEP`、`GENERICIZE`、`PERSONA_SLOT`
- 历史 `LABEL` 兼容主要保留在 restore 的旧记录处理路径，不应再作为新的训练导出标签写入

---

## 4. 当前 batch 布局

### 4.1 推理 batch：`TinyPolicyBatch`

`TinyPolicyBatch` 当前承载：

- `page_features`
- `candidate_features`
- `candidate_mask`
- `persona_features`
- `persona_mask`
- `candidate_text_ids`
- `candidate_text_mask`
- `candidate_prompt_ids`
- `candidate_prompt_mask`
- `candidate_ocr_ids`
- `candidate_ocr_mask`
- `persona_text_ids`
- `persona_text_mask`
- `candidate_ids`
- `persona_ids`

这对应：

- 结构化特征
- 文本辅助特征
- batch 内有效位置掩码与样本 ID 对齐信息

其中字符序列由 `CharacterHashTokenizer` 编码，当前不是 BPE / sentencepiece 一类 tokenizer。

### 4.2 监督 batch：`SupervisedTinyPolicyBatch`

`SupervisedTinyPolicyBatch` 在 `TinyPolicyBatch` 基础上增加层级监督标签：

- `target_protect_labels`
- `target_rewrite_modes`
- `target_persona_indices`
- `final_action_targets`

当前约定：

- `KEEP` 的 rewrite mode 不参与训练时，使用 `IGNORE_INDEX`
- `PERSONA_SLOT` 非法或缺少合法 persona 目标时，也会在相应损失中被 mask

---

## 5. 当前数据导出格式

`training/pipelines/build_dataset.py` 当前已经对齐新的训练布局。

### 5.1 样本侧导出

当前 supervised JSONL 至少导出：

- `candidate_policy_view`
- `page_policy_state`
- `persona_policy_states`
- `page_vector`
- `candidate_vectors`
- `persona_vectors`
- prompt / OCR / candidate / persona 文本字段

### 5.2 标签侧导出

当前 `labels` 至少导出：

- `target_protect_label`
- `target_rewrite_mode`
- `target_persona_id`
- `final_action`

并继续保留：

- `candidate_actions`

作为旧读取链路兼容字段。

因此当前 JSONL 的目标是：

- 对旧链路仍可读
- 对新的 supervised finetune 可直接消费

---

## 6. 当前 supervised finetune 布局

`training/pipelines/run_supervised_finetune.py` 当前已经按层级训练组织损失。

### 6.1 当前损失组成

`training/losses.py` 当前支持：

- `L_protect`
- `L_rewrite_mode`
- `L_persona`
- `L_cost`

### 6.2 各项损失含义

#### `L_protect`

监督 `KEEP / REWRITE`。

#### `L_rewrite_mode`

监督：

- `GENERICIZE`
- `PERSONA_SLOT`

#### `L_persona`

监督 `persona_id`。

#### `L_cost`

当前至少支持：

- 高 `protection_level` 下误判 `KEEP` 更高惩罚
- 低 `page_quality_state` 下误判 `KEEP` 更高惩罚

### 6.3 非法 `PERSONA_SLOT` 的处理

当前 supervised loss 对非法 `PERSONA_SLOT` 采取 mask 策略，而不是强行纳入正常损失：

- 如果缺少合法 persona target
- 或当前标签不能稳定支持 `PERSONA_SLOT`

则：

- candidate 级 `rewrite_mode` 目标会被 mask 为 `IGNORE_INDEX`
- turn 级 `persona` 目标缺失时，该轮不计算 `persona_loss`

---

## 7. 当前网络头布局

`TinyPolicyNet` 当前已经逐步向层级 head 收敛，但仍保留兼容旧 head 的能力。

从实现上看，模型主体当前由：

- `CharacterHashTokenizer` + `SharedTextEncoder` 处理字符级辅助文本
- page token + candidate token 的 `TransformerEncoder` 汇总页面上下文
- persona selector 选择当前 active persona

当前相关 head 为：

- `protect_head`
- `rewrite_mode_head`
- `persona_selector`（承担 persona head 角色）
- `action_head`（兼容旧平面动作头）

当前含义是：

- 新训练主线已经可以使用层级标签
- `protect_head` / `rewrite_mode_head` 已经能被 supervised loss 直接消费
- `action_head` 仍是当前 `TorchTinyPolicyRuntime` decode `final_action` 的主要来源
- 旧 checkpoint / 旧 action head 仍尽量保持兼容

---

## 8. 当前推荐数据流

### 8.1 runtime 到训练

推理侧（sanitize，且 `decision_mode="de_model"`）：

```text
DecisionContext
-> DEModelEngine.plan（内部 DecisionFeatureExtractor.pack + runtime）
-> DecisionPlan（抽象动作）
-> apply_post_decision_steps（ConstraintResolver + 占位与替换生成）
```

训练数据与 finetune（离线）：

```text
（DecisionContext, 金标 DecisionPlan 或等价标签）
-> build_supervised_jsonl_dataset / runtime_bridge
-> supervised JSONL
-> TinyPolicyNet finetune
-> checkpoint
-> TorchTinyPolicyRuntime（可选回接）
```

### 8.2 监督训练的实际边界

```text
supervised JSONL
-> TrainingTurnExample
-> SupervisedTurnLabels
-> SupervisedTinyPolicyBatch
-> TinyPolicyNet
-> L_protect + L_rewrite_mode + L_persona + optional L_cost
```

---

## 9. 当前仍未完成的部分

当前尚未完全实现：

- 真正的 adversarial finetune
- 真正可执行的 bundle / onnx runtime
- 完整移动端导出产物

其中需要特别区分：

- `export_runtime_bundle()` 当前已经可用，但只会写 metadata JSON
- `DEModelEngine(runtime_type="bundle")` 仍会直接抛出 `NotImplementedError`

也就是说，当前仓库已经有：

- 正式上下文边界
- 层级训练标签
- 监督 batch 布局
- 层级 supervised loss
- torch checkpoint 到 runtime 的回接

但还没有形成完整的端侧 bundle 发布链路。

---

## 10. 当前代码对应关系

当前文档和代码的直接对应关系如下：

- `DecisionContext`（领域模型）：`privacyguard/domain/models/decision_context.py`
- `DecisionContextBuilder`（组装器）：`privacyguard/application/services/decision_context_builder.py`
- 策略视图派生：`privacyguard/infrastructure/decision/policy_context.py`
- 特征映射：`privacyguard/infrastructure/decision/features.py`
- runtime 协议：`privacyguard/infrastructure/decision/de_model_runtime.py`
- 决策引擎：`privacyguard/infrastructure/decision/de_model_engine.py`
- 网络头：`privacyguard/infrastructure/decision/tiny_policy_net.py`
- 轻量 tokenizer：`privacyguard/infrastructure/decision/tokenizer.py`
- 默认模式常量：`privacyguard/bootstrap/mode_config.py`
- 训练标签：`training/types.py`
- runtime/训练桥接：`training/runtime_bridge.py`
- batch 组织：`training/torch_batch.py`
- 会话 rollout：`training/session_rollout.py`
- 对抗模型协议：`training/adversary.py`
- 数据导出：`training/pipelines/build_dataset.py`
- supervised finetune：`training/pipelines/run_supervised_finetune.py`
- supervised loss：`training/losses.py`
- runtime metadata 描述：`training/export.py`
- runtime metadata 导出：`training/pipelines/export_runtime_bundle.py`
