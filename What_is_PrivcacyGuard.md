# PrivacyGuard：基于当前代码的项目说明

这份文档不是理想设计稿，而是依据仓库当前实现整理出来的系统说明。重点回答三个问题：

1. PrivacyGuard 现在到底在做什么
2. 当前代码里已经落地到什么程度
3. 哪些能力仍然只是边界、骨架或后续方向

## 1. 项目定位

PrivacyGuard 面向的场景是：

1. 端侧采集当前页面截图
2. 用户输入 prompt
3. 图文一起发送到云端多模态模型
4. 云端返回文本结果或动作建议
5. 端侧继续执行后续流程

PrivacyGuard 插在第 2 步和第 4 步之间，负责两件事：

- 上传前脱敏：`sanitize`
- 返回后恢复：`restore`

它的目标不是“把所有隐私全部抹掉”，而是尽量减少云端看到真实 PII 的机会，同时保留 GUI Agent 的任务可执行性。

## 2. 威胁模型与非目标

### 2.1 当前威胁模型

项目默认云端是 `honest-but-curious`：

- 云端会正常处理请求
- 云端可能记录、关联和分析会话中的隐私线索
- 云端不知道本地 persona 仓库和会话映射表的真实内容

### 2.2 当前主要防御对象

- 原始姓名、手机号、地址、账号等文本型 PII 直接上传云端
- 多轮会话中由于同一身份线索重复暴露而导致的身份推断风险

### 2.3 当前不承诺解决的问题

- prompt injection
- 恶意 GUI 诱导
- 系统级权限隔离
- 非文本视觉隐私的完整防护
- 云端结构化动作规划的安全校验

## 3. 当前代码中的核心模块

| 模块 | 当前实现 | 实际状态 |
| --- | --- | --- |
| OCR | `PPOCREngineAdapter` | 已接到主链路；缺依赖时显式报错，不做静默降级 |
| Detector | `RuleBasedPIIDetector` | 已接到主链路 |
| Decision | `LabelOnlyDecisionEngine` / `LabelPersonaMixedDecisionEngine` / `DEModelEngine` | 三种模式都可用 |
| Persona Repository | `JsonPersonaRepository` | 已实现，默认支持本地仓库 + 样例回退 |
| Mapping Store | `InMemoryMappingStore` / `JsonMappingStore` | 已实现 |
| Rendering | `PromptRenderer` + `ScreenshotRenderer` | 已实现 |
| Restoration | `ActionRestorer` | 已实现，但只恢复文本、只认当前 turn |

## 4. 当前 `sanitize` 和 `restore` 的真实语义

### 4.1 `sanitize`

`PrivacyGuard.sanitize()` 当前会做这些事：

1. 解析输入 payload
2. 如有截图则执行 OCR
3. 检测 prompt 与 OCR 中的 PII 候选
4. 构造统一 `DecisionContext`
5. 输出 `DecisionPlan`
6. 为 `GENERICIZE` 动作分配 session 级稳定占位符
7. 渲染 prompt 与截图
8. 把当前 turn 的替换记录写入 mapping store
9. 若决策绑定了 persona，则更新 `SessionBinding`

### 4.2 `restore`

`PrivacyGuard.restore()` 当前语义更窄：

1. 读取当前 `session_id + turn_id` 的替换记录
2. 以 `replacement_text -> source_text` 做文本恢复
3. 返回恢复后的文本

这意味着：

- 只恢复文本，不恢复结构化动作
- 只看当前 turn，不回溯历史 turn
- 如果云端返回文本里混入上一轮占位符，默认不会自动恢复

## 5. `rule_based` detector 的实际能力

当前主链路中的 detector 是 `RuleBasedPIIDetector`。它不只是简单正则，而是把几类信号叠加在一起：

- 本地 JSON 词典
- 会话历史词典
  从前序 turn 的 `ReplacementRecord` 派生 `dictionary_session`
- 字段上下文规则
  如“姓名”“地址”“联系人”等
- 格式型规则
  手机号、邮箱、身份证、银行卡等
- 中文姓名启发式
- 地址与地理线索规则
  结合 `data/china_geo_lexicon.json`
- OCR 页面聚合
  支持跨相邻 OCR block 的号码、地址和上下文字段组合

### 5.1 保护等级

请求层支持三档 `protection_level`：

- `weak`
- `balanced`
- `strong`

它们会影响：

- 是否启用更激进的姓名/地址规则
- 地址最小置信度阈值
- 是否允许某些带遮罩文本的召回

### 5.2 请求层可覆盖的 detector 阈值

当前 payload 只允许覆盖这几个属性：

- `name`
- `location_clue`
- `address`
- `organization`
- `other`

### 5.3 当前边界

- `GLiNERAdapter` 文件存在，但没有注册到默认模式
- 当前没有真正接入 NER 模型补召回
- 当前 detector 仍以中文文本、OCR 页面和规则工程为主

## 6. 决策引擎的实际状态

### 6.1 `label_only`

- 所有高于阈值的候选统一改成通用占位符
- 实际占位符格式是 `@姓名1`、`@手机号1` 这类 session 级标签

### 6.2 `label_persona_mixed`

- 对 `name / phone / address / email / organization` 等高风险字段优先尝试 `PERSONA_SLOT`
- 没有 persona 或 persona 缺槽位时，会自动降级到 `GENERICIZE`

### 6.3 `de_model`

当前 `de_model` 已经是默认决策模式，但默认 runtime 仍然是 heuristic，不是训练好的模型权重。

它的实际结构是：

1. `DecisionContextBuilder`
2. `DecisionFeatureExtractor`
3. `DEModelEngine`
4. heuristic runtime 或 torch runtime
5. `ConstraintResolver`

`de_model` 已经支持两条运行路径：

- `runtime_type="heuristic"`
  默认路径，不依赖 torch
- `runtime_type="torch"`
  需要显式传 `checkpoint_path`

还保留了：

- `runtime_type="bundle"`
  目前未实现，调用会抛出 `NotImplementedError`

## 7. `de_model` 当前真正依赖的输入

仓库中的决策接口已经统一为：

```python
plan(context: DecisionContext) -> DecisionPlan
```

`DecisionContext` 当前已经收敛了这些信息：

- 当前 turn 的 prompt
- 当前保护等级和 detector overrides
- OCR blocks
- detector 输出的候选
- 当前 session binding
- 当前 session 历史替换记录
- persona repository 中的 persona slots（替换槽位值）与统计
- page / candidate / persona 三层摘要特征

这意味着当前代码已经不再是“只把 candidates 直接丢给 decision engine”的老形态。

## 8. 渲染与恢复语义

### 8.1 Prompt 渲染

`PromptRenderer` 当前会：

- 优先使用 `span_start / span_end` 精确替换
- 若缺少 span，则对旧式记录走保守的文本替换

### 8.2 Screenshot 渲染

`ScreenshotRenderer` 当前具备这些实际能力：

- OCR block 内局部重建，而不是整块直接盖掉
- polygon / rotation 感知
- 跨 block 文本替换
- 地址类 persona 替换按语义组件分配到不同 block
- 四种填充策略：`ring / gradient / cv / mix`

### 8.3 Placeholder 语义

`SessionPlaceholderAllocator` 只对 `GENERICIZE` 动作分配占位符，并且占位符是 session 级稳定的：

- 同一 session 中新的姓名会得到 `@姓名1`、`@姓名2` ...
- 同一 canonical source value 可跨 turn 复用已有占位符

`PERSONA_SLOT` 不走这套占位符分配，而是直接写入 persona 槽位值。

## 9. 本地隐私仓库与会话状态

### 9.1 Persona Repository

`JsonPersonaRepository` 的读取规则是：

1. 优先读取 `data/privacy_repository.json`
2. 如果本地仓库不存在，则回退读取 `data/personas.sample.json`

写入由 `PrivacyRepository.write()` 完成，支持：

- `slots`
- `metadata`
- `stats`

并且会按 `persona_id` 合并更新。

### 9.2 Mapping Store

当前 mapping store 保存两类状态：

- 每轮的 `ReplacementRecord`
- 每个 session 的 `SessionBinding`

`SessionBinding` 里会记录：

- `active_persona_id`
- `created_at`
- `updated_at`
- `last_turn_id`

## 10. 训练侧的真实完成度

当前训练目录并不只是空骨架，已经具备最小监督训练闭环：

- `pack_training_turn()`
- `plan_to_supervision()`
- `build_jsonl_dataset()`
- `build_supervised_jsonl_dataset()`
- `TinyPolicyBatchBuilder.build_examples()`
- `run_supervised_finetune()`
- `TorchTinyPolicyRuntime` 直接加载训练产物

但以下能力仍未完成：

- `run_adversarial_finetune()`
- 真正的 policy vs adversary 对抗训练
- 真正的 ONNX / TFLite 模型导出
- 移动端 bundle runtime

## 11. 当前最适合用它做什么

当前仓库最适合：

- 做 GUI Agent 隐私保护链路研究
- 跑通 `sanitize -> restore` 工程闭环
- 试验不同 detector / decision / rendering 组合
- 为后续移动端小模型决策和导出路径打底

它暂时还不适合直接当成生产级移动端 SDK 使用，因为还缺：

- 真实上线模型权重
- 完整评估指标
- 真机推理与性能验证
- 结构化动作恢复与端侧执行接线
