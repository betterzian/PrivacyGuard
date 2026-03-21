# DE Model Implementation

## 1. 文档范围

本文档描述 PrivacyGuard 仓库中 `de_model` 的**当前实现**，并明确哪些部分只是**后续可扩展方向**。

本文档以代码为准，不再把理想化的三层运行时对象设计写成当前真实结构。  
尤其需要强调：

- `de_model` 是**策略决策层**
- `de_model` **不是 detector**
- `de_model` **不是 OCR 纠错器**
- 当前正式运行时**不引入 `EntityTruth`**
- 当前正式上下文统一收敛到 Pydantic 领域模型 `DecisionContext`；策略视图由 `privacyguard/infrastructure/decision/policy_context.py` 的 `derive_policy_context` 派生（不是 `DecisionContext` 的内置字段）
- 当前最终执行动作统一为：
  - `KEEP`
  - `GENERICIZE`
  - `PERSONA_SLOT`

---

## 2. 当前实现

### 2.1 核心定位

`de_model` 的输入前提是：OCR 与 detector 已经输出了候选实体。

当前代码里，`de_model` 只负责对已有 `PIICandidate` 做策略决策，不负责：

- 新建候选 span
- OCR 文本纠错
- detector 召回
- bbox 修正
- restore 反向执行

换言之，`de_model` 的职责是：

1. 读取候选、页面、persona、session 历史等信息
2. 生成策略上下文
3. 提取轻量特征
4. 通过 heuristic runtime 或 torch runtime 做策略判断
5. 收敛为可执行动作
6. 交给后续 placeholder 分配、render、mapping、restore 闭环

### 2.2 在 sanitize 主链中的位置

当前 `sanitize` 主链中的阶段边界是：

```text
OCR / prompt parse
-> detector
-> alias / session context preparation
-> local context / quality / persona state preparation
-> DecisionContextBuilder
-> DecisionFeatureExtractor
-> DEModelEngine / runtime
-> ConstraintResolver
-> placeholder allocation / replacement planning
-> render
-> mapping store
```

这里的关键边界是：

- `sanitize_pipeline.py` 负责 application 层编排
- `DecisionContextBuilder` 负责收敛正式策略上下文
- `DecisionFeatureExtractor` 负责把上下文映射为轻量特征
- `DEModelEngine` 负责驱动 runtime 并输出动作计划
- `ConstraintResolver` 负责当前默认引擎路径中的动作合法性收敛
- `SessionPlaceholderAllocator` 负责为 `GENERICIZE` 分配 session-stable placeholder
- `render + mapping store` 负责执行与闭环

说明：`DecisionFeatureExtractor` → de_model runtime → `ConstraintResolver` 这一细链**仅**在 `decision_mode="de_model"`（`DEModelEngine`）内发生。`label_only` 与 `label_persona_mixed` 同样消费 `DecisionContext` 并调用各自的 `ConstraintResolver`，但不经过 `DecisionFeatureExtractor` 与 `TinyPolicyRuntime` / `TorchTinyPolicyRuntime`。

### 2.3 正式运行时上下文：`DecisionContext` 与派生策略视图

运行时输入的“根上下文”是 `DecisionContext`（`privacyguard/domain/models/decision_context.py`），字段包括会话、候选列表、OCR、`history_records`、`persona_profiles` 等。

`privacyguard/infrastructure/decision/policy_context.py` 中的 `derive_policy_context(context)` 返回 `DerivedDecisionPolicyContext`，其中包含四块策略视图：

- `raw_refs`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

辅助函数 `raw_refs(context)` / `candidate_policy_views(context)` 等是对 `derive_policy_context` 的便捷封装；若未来在 `DecisionContext` 上挂载预构建字段，模块内的 `_prebuilt_*` 分支会优先使用。

#### `raw_refs`

`raw_refs` 保存真实工程对象的引用索引，主要用于回查，不是模型直接消费的 dense 特征。

当前主要包含：

- `prompt_text`
- `candidate_by_id`
- `ocr_block_by_id`
- `history_records`
- `persona_by_id`
- `session_binding`

#### `candidate_policy_views`

每个 candidate 对应一条 candidate 级策略视图。  
这部分是 `de_model` 的核心输入之一，当前重点字段包括：

- `candidate_id`
- `attr_type` / `attr_id`
- `source`
- `session_alias`
- `same_alias_count_in_turn`
- `cross_source_same_alias_flag`
- `history_alias_exposure_bucket`
- `history_exact_match_bucket`
- `det_conf_bucket`
- `ocr_local_conf_bucket`
- `low_ocr_flag`
- `cross_block_flag`
- `covered_block_count_bucket`
- `same_attr_page_bucket`
- `normalized_len_bucket`
- `digit_ratio_bucket`
- `mask_char_flag`
- `prompt_local_context_labelized`
- `ocr_local_context_labelized`

#### `page_policy_state`

页面级策略状态聚合当前页面的风险与质量信息。  
当前重点字段包括：

- `protection_level`
- `candidate_count_bucket`
- `unique_attr_count_bucket`
- `avg_det_conf_bucket`
- `min_det_conf_bucket`
- `avg_ocr_conf_bucket`
- `low_ocr_ratio_bucket`
- `page_quality_state`

#### `persona_policy_states`

persona 级状态用于表达当前 persona 集合对本轮候选的支持情况。  
当前重点字段包括：

- `persona_id`
- `is_active`
- `supported_attr_mask`
- `available_slot_mask`
- `attr_exposure_buckets`
- `matched_candidate_attr_count`

### 2.4 不引入 `EntityTruth`

当前实现中，`EntityTruth`、`EntityGroup`、`LabelizedEntityLite` 之类对象**不是正式运行时对象**。

当前代码没有把运行时主链建立为“真相层对象树 -> 关系层对象树 -> 策略层对象树”的重型结构。  
当前实现采用的是：

- 原始真实对象：`PIICandidate`、`OCRTextBlock`、`ReplacementRecord`、`PersonaProfile`
- 正式策略上下文：`DecisionContext` + 内部派生策略视图
- 轻量特征边界：`PackedDecisionFeatures`
- runtime 输出协议：`RuntimeCandidateDecision`
- 最终执行动作：`DecisionAction`

这也是当前仓库文档和代码必须保持一致的边界。

### 2.5 动作空间

当前最终执行动作固定为三类：

- `KEEP`
- `GENERICIZE`
- `PERSONA_SLOT`

#### `KEEP`

- 保留原值
- 不生成替换文本
- 不进入 restore 的有效映射集合

#### `GENERICIZE`

- 使用类型化 placeholder
- 当前后续会通过 `SessionPlaceholderAllocator` 分配 session-stable placeholder
- 典型形式如 `@姓名1`、`@手机号1`

#### `PERSONA_SLOT`

- 使用当前 active persona 的同类型槽位值替换
- 例如姓名映射到 `persona.name`
- 如果 persona 不存在或槽位不可用，当前默认约束层会回退到 `GENERICIZE`

### 2.6 两级视角：`protect_decision + rewrite_mode`

虽然最终执行动作只有三类，但 runtime 当前已经支持两级视角：

- 一级：`protect_decision`
  - `KEEP`
  - `REWRITE`
- 二级：`rewrite_mode`
  - `GENERICIZE`
  - `PERSONA_SLOT`
  - `NONE`

当前 runtime 输出协议中，每个 candidate 至少包含：

- `candidate_id`
- `protect_decision`
- `rewrite_mode`
- `final_action`
- `persona_id`
- `confidence`
- `reasons`
- `fallback_reason`

因此：

- 对外执行动作仍然统一为 `KEEP / GENERICIZE / PERSONA_SLOT`
- 对内 runtime 可以采用 `protect_decision + rewrite_mode` 的两级视角组织推理输出

---

## 3. 当前职责边界

### 3.1 `DecisionContextBuilder`

`DecisionContextBuilder` 是当前正式的策略上下文组装器。

它负责：

- 把候选、OCR、历史记录、persona、session binding 收敛为 `DecisionContext`
- 读取并归一化 protection level / detector overrides
- 补齐 history records 与 persona profiles

它不负责：

- detector
- 直接派生策略视图
- 最终策略推理
- restore
- placeholder 分配

### 3.2 `privacyguard/infrastructure/decision/features.py`

`features.py` 负责把 `DecisionContext` 内部派生出的策略视图映射为 runtime 可消费的轻量特征。

当前正式映射关系是：

- `candidate_policy_views -> candidate dense features`
- `page_policy_state -> page features`
- `persona_policy_states -> persona features`

文本通道当前仍保留，但定位为**辅助信号**。  
当前保留的辅助文本输入包括：

- `candidate_text`
- `prompt_context`
- `ocr_context`

它们不会取代 alias/history/quality/persona 等结构化信号，而是作为补充输入。

### 3.3 `de_model_runtime.py`

runtime 负责把特征转换为策略输出协议。

当前支持两类 runtime：

- `TinyPolicyRuntime`
- `TorchTinyPolicyRuntime`

两者都统一输出 `DEModelRuntimeOutput`，并为每个 candidate 生成 `RuntimeCandidateDecision`。

runtime 负责：

- 读取 packed features
- 输出统一协议
- 给出 `final_action`
- 给出 `protect_decision + rewrite_mode`
- 给出 `confidence / reasons / fallback_reason`

runtime 不负责：

- detector
- builder
- mapping store 写入
- restore

### 3.4 `DEModelEngine`

`DEModelEngine` 是当前 de_model 的执行骨架。

当前默认逻辑是：

1. 接收 `DecisionContext`
2. 调用 `DecisionFeatureExtractor.pack(...)`
3. 调用 runtime
4. 将 runtime 输出映射为 `DecisionAction`
5. 调用 `ConstraintResolver`
6. 产出最终 `DecisionPlan`

`DEModelEngine` 不直接承担 builder 逻辑。  
builder 在 sanitize pipeline 中先完成，engine 消费的是已经准备好的统一上下文。

### 3.5 当前默认 resolver：`ConstraintResolver`

当前默认引擎路径中，实际接线的是 `domain/policies/constraint_resolver.py` 里的 `ConstraintResolver`。

它负责：

- `KEEP` 的标准化
- `PERSONA_SLOT` 的 persona 可用性校验
- persona 缺失或槽位缺失时回退为 `GENERICIZE`
- `GENERICIZE` 缺少 replacement 时补标准 placeholder
- 非法动作回退为 `KEEP`

### 3.6 已存在但尚未成为默认引擎路径的扩展点：`resolver_service.py`

仓库中已经存在 `application/services/resolver_service.py`（核心类 `CandidateResolverService`），它把 resolver 定位为“约束与回退服务”，并定义了更强的应用层硬约束，例如：

- 高 protection + 低质量页面时对 `KEEP` 更保守
- `cross_block + low_ocr` 时对 `KEEP` 更保守
- `GENERICIZE` 缺失 alias 时补建 placeholder
- 输出 `fallback_reason / resolution_reason`

但需要明确：

- **当前 `DEModelEngine.plan(...)` 默认没有直接接入这个 service**
- 当前默认执行链仍然是 runtime -> `ConstraintResolver`

因此文档里不能把 `resolver_service.py` 写成当前引擎的既成事实，只能把它定义为已存在的扩展点。

---

## 4. 关键状态的作用

### 4.1 alias

alias 的作用是为同一 session 内的实体提供稳定的语义连续性，而不是由 `de_model` 临时决定。

当前原则是：

- alias 生命周期属于 session 层
- `SessionService` 负责 session binding 与 alias 生命周期
- 高置信才复用
- 不确定时宁可新建 alias
- 错复用比断裂更危险

因此当前边界应当是：

- session 层准备 alias / binding
- builder 与 runtime 消费 alias 信号
- `de_model` 不自己充当 alias linker

### 4.2 persona

persona 的作用是为 `PERSONA_SLOT` 提供受约束的假值来源。

当前原则是：

- session 维护 active persona
- `PERSONA_SLOT` 必须使用同类型槽位
- persona 不存在或槽位缺失时，当前默认约束层回退为 `GENERICIZE`

因此 persona 的角色不是“任意角色生成器”，而是策略层可选的受约束替换来源。

### 4.3 `page_quality_state`

`page_quality_state` 是页面级风险与质量聚合状态。  
它来自 `page_policy_state`，当前用于表达：

- detector 置信是否稳定
- OCR 平均质量是否足够
- OCR 低质量比例是否过高

它的作用是让 runtime / resolver 在以下场景更保守：

- 高 `protection_level`
- 差 OCR 质量
- candidate 本身有跨 block 或低局部 OCR 置信问题

因此 `page_quality_state` 不是渲染状态，也不是 detector 结果本身，而是策略层的页面级风险输入。

---

## 5. mapping 与 restore 的兼容原则

### 5.1 mapping 的原则

当前 mapping 闭环要求：

- `KEEP` 不产生可恢复替换记录
- `GENERICIZE` 产生 replacement record
- `PERSONA_SLOT` 产生 replacement record
- placeholder 分配在 resolver 之后完成

这保证：

- 最终动作可执行
- restore 可恢复
- session 内 placeholder 可保持稳定

### 5.2 restore 的原则

当前 restore 明确保持收敛：

- 只基于当前 turn 的 `ReplacementRecord`
- 不扩展为全会话 restore
- 不做 DSL restore
- 不对 de_model 决策做逆向推理

当前 restore 对动作语义的兼容规则是：

- `KEEP` 不参与 restore
- `GENERICIZE` 可通过 replacement record 恢复
- `PERSONA_SLOT` 可通过 replacement record 恢复
- 旧别名 `LABEL` 视作 `GENERICIZE`

因此：

- 外部 restore 仍然建立在 replacement-record 驱动模型上
- de_model 内部重构不会改变 restore 的基本闭环

### 5.3 外部 DTO 边界

当前对外 `sanitize / restore` DTO 仍保持稳定。

内部字段例如：

- `protect_decision`
- `rewrite_mode`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

都属于内部策略层对象，不应直接泄漏到 app facade 的稳定外部响应 DTO 中。

---

## 6. 后续可扩展

以下内容是当前代码已经预留方向，但**不是当前默认执行链已经完全实现的既成事实**。

### 6.1 builder 前置准备阶段进一步下沉

当前 sanitize pipeline 已经预留了这些调用点：

- alias / session context preparation
- local context / quality / persona state preparation

后续可以把内部 helper 继续下沉为更明确的模块，例如：

- `AliasLinker`
- `LocalContextBuilder`
- `QualityAggregator`
- `PersonaStateBuilder`

但当前默认实现仍主要由 `DecisionContextBuilder` 内部 helper 承接。

### 6.2 应用层 resolver_service 接线

`resolver_service.py` 已经定义了更强的动作回退与 debug 导出协议。  
后续可以把引擎默认约束链从单纯的 `ConstraintResolver` 扩展为：

```text
runtime
-> DecisionAction draft
-> resolver_service
-> final DecisionPlan
```

但当前默认主链尚未完全切换到这里。

### 6.3 runtime head 进一步层级化

当前 runtime 已经统一了输出协议，并支持：

- `protect_decision`
- `rewrite_mode`
- `final_action`

后续可以继续把训练目标与网络 head 完整收敛为：

- `protect_head`
- `rewrite_mode_head`
- `persona_head`

但当前仍保留兼容的旧平面 `action_head`。

### 6.4 bundle runtime

当前 `DEModelEngine`（`privacyguard/infrastructure/decision/de_model_engine.py`）支持归一化 `runtime_type` 为 `heuristic`、`torch` 或 `bundle`。其中：

- `heuristic` / `torch`：可执行
- `bundle`：要求提供 `bundle_path`，当前在 `_build_runtime` 中显式 `raise NotImplementedError`

代码库中**没有**名为 `onnx` 的独立 `runtime_type` 分支；若需要 ONNX，应在训练/导出与运行时集成层面另行扩展，而不是当前引擎已暴露的开关。

### 6.5 训练与导出

训练与数据导出层已经向层级标签迁移：

- `target_protect_label`
- `target_rewrite_mode`
- `target_persona_id`
- `final_action`

后续可以继续把 runtime 输出、训练标签、损失函数和评估协议完全统一，但当前仓库仍保留旧字段兼容层。

---

## 7. 当前实现一句话总结

当前 PrivacyGuard 中的 `de_model` 已经收敛为：

> 一个基于已有 `PIICandidate` 的策略决策层，以 `DecisionContext` 为正式上下文，在内部派生 policy context，以 `PackedDecisionFeatures` 为特征边界，以 `KEEP / GENERICIZE / PERSONA_SLOT` 为统一执行动作，并通过 mapping / restore 维持可恢复闭环。

它不是 detector，不是 OCR 纠错器，也不依赖 `EntityTruth` 之类的重型运行时对象。
