# PrivacyGuard：面向 GUI Agent 的端侧轻量化隐私保护框架

## 1. 项目定位

### 1.1 运行场景
当前许多手机智能助手与手机 GUI Agent（图形用户界面智能体）采用如下基本流程：

1. 获取当前手机屏幕截图；
2. 结合用户自然语言提示词（prompt，提示词）；
3. 将图文一并发送至云端多模态模型；
4. 云端返回动作建议或文本指令；
5. 端侧执行器按指令完成跨应用操作。

这种架构具备强能力与高通用性，但也带来直接的隐私暴露问题：截图与提示词中往往包含用户姓名、手机号、家庭住址、聊天片段、验证码、订单信息等文本型个人可识别信息（PII，Personally Identifiable Information）。

### 1.2 当前代码状态与项目目标
当前仓库已经具备一条可运行的端侧闭环，但仍处于“可运行骨架 + 局部强化”的阶段。

当前已实现的主干能力包括：

1. **双入口 API 闭环**
   提供 `sanitize` 与 `restore` 两条链路。
2. **OCR 主链路**
   使用 `from paddleocr import PaddleOCR` 的 PP-OCRv5 适配层，支持本地图片、PIL、numpy 与 `http(s)` URL。
3. **规则型 PII 检测**
   `rule_based` 检测器已支持 prompt 与 OCR 双来源检测，并输出可渲染的 `span / block_id / bbox`。
4. **可恢复决策与映射**
   已实现 `label_only`、`label_persona_mixed`、`de_model` 三种决策模式，其中 `de_model` 当前仍是启发式占位版。
5. **文本与截图渲染**
   已支持 prompt 精确替换、OCR 同框局部替换重建、polygon/rotation 感知的截图重绘、以及 `ring / gradient / cv / mix` 填充策略。
6. **基于映射表的文本还原**
   当前还原模块针对云端返回文本做可恢复替换。

PrivacyGuard 的总体目标仍然是：

1. **隐私最小暴露**
   尽量避免真实敏感信息直接上传云端。
2. **任务可执行性**
   尽量不破坏云端 GUI Agent 的界面理解与动作生成。
3. **轻量化部署**
   核心模块能够运行在真实手机端，而不是只在工作站或模拟器中成立。
4. **高效率运行**
   端侧处理时延尽可能低，减少对用户体验的影响。

### 1.3 基本闭环
PrivacyGuard 在云端调用前对截图与提示词进行脱敏和替换，在云端返回文本结果后于本地完成还原。当前代码中的闭环如下：

- 上传前：识别隐私实体并替换为通用标签或 persona 同槽位值；
- 上传中：云端仅看到脱敏后的截图与文本；
- 返回后：本地根据映射表将标签或 persona 替代值恢复为真实值，再交由后续执行层消费。

例如，真实地址 `北京市海淀区XX路` 可在上传前被替换为 `@地址1` 或某个 persona 的地址；云端基于替代值推理，本地执行前再恢复为真实地址。

需要说明的是，当前实现的 `restore` 入口处理的是**云端返回文本**，而不是完整的结构化动作 DSL。

---

## 2. 威胁模型与保护目标

### 2.1 威胁模型
PrivacyGuard 默认云端是 **honest-but-curious（诚实但好奇）** 的：

- 云端会按任务需要处理上传的图文；
- 云端可能记录、关联、分析整轮会话中的隐私线索；
- 云端可能知道本地采用了“标签替换 / persona 替换 / 本地恢复”的总体思路；
- 云端不知道本地 persona 仓库、会话映射表及真实恢复结果。

### 2.2 主要防御对象
本项目主要防御两类风险：

1. **cloud-side raw PII exposure（云端原始隐私暴露）**
   真实姓名、地址、手机号、验证码、聊天文本等直接上传到云端。

2. **cloud-side identity inference（云端身份推断）**
   云端根据一整轮会话里的多条证据，高置信地推断“这就是某个真实用户”。

### 2.3 不直接承诺解决的问题
PrivacyGuard 不是完整的 Agent 安全框架，不直接承诺解决：

- prompt injection（提示词注入）；
- 恶意界面诱导；
- 系统级权限隔离；
- 非文本视觉隐私（头像、证件照、二维码等）的完整防护；
- 云端结构化动作规划的安全校验。

---

## 3. 系统整体架构

### 3.1 PrivacyGuard 核心模块与当前实现

| 模块 | 当前实现 | 当前说明 |
| --- | --- | --- |
| OCR 模块 | `ppocr_v5` | 通过 `PPOCREngineAdapter` 调用 PaddleOCR；输出 `OCRTextBlock(text, bbox, block_id, polygon, rotation_degrees, score, line_id, source)` |
| PII Detector | `rule_based` | 已接入主链路；输入 `prompt_text + ocr_blocks`，输出 `PIICandidate` 列表 |
| Persona Repository | `json` | 当前主要是 `JsonPersonaRepository`，维护 `persona_id / slots / stats` |
| Local Mapping Table | `in_memory` / `json` | 会话级映射表；按 `session_id` 与 `turn_id` 保存 `ReplacementRecord` |
| Decision Engine | `label_only` / `label_persona_mixed` / `de_model` | 三种模式均已注册；其中 `de_model` 仍是规则评分占位实现 |
| Rendering Engine | `PromptRenderer + ScreenshotRenderer` | prompt 精确替换、截图局部重建、polygon/rotation 感知、默认 `mix` 填充 |
| Restoration Module | `ActionRestorer` | 基于 `ReplacementRecord` 对云端返回文本做可恢复替换 |

### 3.2 当前实际数据结构

#### OCR 输出
当前 OCR 输出使用 `OCRTextBlock` 表示，核心字段为：

- `text`
- `bbox`
- `block_id`
- `polygon`
- `rotation_degrees`
- `score`
- `line_id`
- `source`

其中 `polygon` 是更高保真的几何真相源，`bbox` 主要用于兼容旧链路与快速裁剪。

#### Detector 输出
当前 Detector 输出使用 `PIICandidate` 表示，核心字段为：

- `entity_id`
- `text`
- `normalized_text`
- `attr_type`
- `source`
- `bbox`
- `block_id`
- `span_start / span_end`
- `confidence`
- `metadata`

#### Decision 输出
当前 Decision 输出使用 `DecisionPlan` 与 `DecisionAction` 表示：

- `DecisionPlan`
  - `session_id`
  - `turn_id`
  - `active_persona_id`
  - `actions`
  - `summary`
  - `metadata`
- `DecisionAction`
  - `candidate_id`
  - `action_type`
  - `attr_type`
  - `source`
  - `replacement_text`
  - `source_text`
  - `persona_id`
  - `bbox`
  - `block_id`
  - `span_start / span_end`
  - `reason`

### 3.3 当前实际 API 与流程

PrivacyGuard 当前有两个 API 调用入口。

#### API_1：sanitize
边界层 payload 当前为：

- `session_id`
- `turn_id`
- `prompt`
- `image`

完整流程如下：

1. **API_1 入口**
   接收 `prompt` 与 `image`。
2. **OCR**
   若 `image` 不为空，则调用 `ocr.extract(image)` 得到 `ocr_blocks`。
3. **PII 检测**
   调用 `pii_detector.detect(prompt_text, ocr_blocks)` 得到 `candidates`。
4. **会话绑定读取**
   通过 `SessionService.get_or_create_binding(session_id)` 获取当前 `session_binding`。
5. **决策生成**
   调用 `decision_engine.plan(session_id, turn_id, candidates, session_binding)` 输出 `DecisionPlan`。
6. **文本与图像渲染**
   `render_text(prompt_text, plan)` 输出脱敏文本与 `ReplacementRecord`；
   `render_image(image, plan, ocr_blocks)` 输出脱敏截图。
7. **映射与绑定写回**
   将本轮 `ReplacementRecord` 写入映射表；
   若 `plan.active_persona_id` 非空，则回写会话 persona 绑定。
8. **API_1 返回**
   返回 `masked_prompt`、`masked_image`、`mapping_count`、`active_persona_id`。

#### API_2：restore
边界层 payload 当前为：

- `session_id`
- `turn_id`
- `agent_text`

完整流程如下：

1. **API_2 入口**
   接收云端返回文本。
2. **映射记录读取**
   优先读取当前 `turn_id` 的替换记录，再回溯同会话历史记录。
3. **文本还原**
   调用 `restoration_module.restore(cloud_text, records)` 执行恢复。
4. **API_2 返回**
   返回 `restored_text`。

### 3.4 模块耦合与边界

当前代码中的访问边界是：

- `Decision Engine` 可访问 `SessionBinding`；
- `de_model` 当前实现还会访问 `MappingStore` 与 `PersonaRepository`；
- `Rendering Engine` 只消费 `DecisionPlan` 与 `ocr_blocks`；
- `Restoration Module` 当前**不访问** `Persona Repository`，只依赖 `ReplacementRecord`；
- PrivacyGuard 通过模式标签从注册表中选择具体实现，不感知模块内部实现细节。

---

## 4. PII Detector 模块细节

### 4.1 当前模式状态

当前代码库中与 PII 检测相关的状态如下：

| 模式或能力 | 当前状态 | 说明 |
| --- | --- | --- |
| `rule_based` | 已实现并接入主链路 | 当前生产基线 |
| `GLiNERAdapter` | 有适配层，但未接入主链路 | 属于预留扩展位 |
| `rule-NER_based` | 未实现为可选模式 | 当前注册表中不存在该模式 |
| `llm_based` | 未实现 | 当前注册表中不存在该模式 |

因此，就当前代码而言，PrivacyGuard 的 PII Detector 主线应被描述为：

> **基于规则、字典、字段上下文与 OCR 场景启发式的本地检测器。**

### 4.2 `rule_based` 的当前输入与输出

#### 输入

- `prompt_text: str`
- `ocr_blocks: list[OCRTextBlock]`

#### 输出

- `list[PIICandidate]`

对 OCR 来源的候选，当前实现会尽量补齐：

- `bbox`
- `block_id`
- `span_start / span_end`

这使后续渲染能够在同一 OCR block 内做局部替换而不丢失其他文本。

### 4.3 `rule_based` 当前实际规则能力

当前规则能力主要包括：

1. **字典与精确匹配**
   支持从本地 JSON 词典读取敏感词条。
2. **字段上下文规则**
   如 `name:`、`姓名：`、`收货地址：`、`手机号：` 等。
3. **格式型规则**
   手机号、邮箱、身份证号、脱敏格式等。
4. **姓名启发式**
   中文姓氏、敬称、自我介绍句式等。
5. **地址高召回规则**
   支持省、市、区、县、乡镇、路街巷、小区、栋单元室等 OCR 常见碎片。
6. **OCR 局部定位**
   对命中项尽量保留原 block 的 `block_id` 与字符级 `span`。

### 4.4 当前限制

当前 `rule_based` 仍有如下限制：

1. 没有真正接入 NER 模型进行补召回；
2. 没有云端 LLM 抽取模式；
3. 对跨 OCR block 的组合实体尚未做拼接；
4. 对完全无上下文的短词仍可能存在误检与漏检权衡。

---

## 5. Decision Engine 模块细节

### 5.1 决策模式

| 模式 | 当前实现状态 | 主要作用 |
| --- | --- | --- |
| `label_only` | 已实现 | 全部替换为通用语义标签，作为最强脱敏基线 |
| `label_persona_mixed` | 已实现 | 标签与固定 persona 假值混合，作为实验基线 |
| `de_model` | 当前为启发式占位版，目标是端侧策略模型 | 生产主线方向 |

### 5.2 `de_model`：**hierarchical privacy policy model（分层隐私策略模型）**

#### 5.2.1 系统只依赖端侧真实可得信息

`de_model` 的核心决策只依赖 PrivacyGuard 本来就可获得的或产生的信息：

- 用户提示词；
- OCR 结果；
- PII Detector 识别出的候选隐私实体；
- 文本、来源、位置、置信度、几何特征；
- persona 仓库统计摘要；
- 当前会话绑定状态；
- 历史暴露统计与最近暴露时间。

`de_model` 不把以下信息作为默认主输入：

- 当前 App 名称；
- 当前页面类型；
- icon、头像等强视觉语义；
- “文本旁边是不是按钮 / 联系人卡片 / 搜索框”等强 UI 语义；
- 不可直接观测的 OCR 漏检位置。

#### 5.2.2 核心目标是会话级身份混淆

`de_model` 不将问题建模为“给每个敏感字段单独找一个假值”，而是建模为：

> 在整轮会话中维护一个或多个可控 persona，使姓名、地址、手机号、常用地点等属性保持一致映射，并尽量让云端对真实用户与若干 persona 的后验分布接近预设目标。

`de_model` 围绕三类目标优化：

- **session consistency（会话一致性）**
- **persona coherence（人设一致性）**
- **posterior flattening（后验拉平）**

#### 5.2.3 动作空间固定且可恢复

当当前轮已绑定 `active_persona = zhangsan` 时，对任一实体只允许三类动作：

1. `KEEP`：保留真实值；
2. `GENERICIZE(attr)`：替换为通用语义标签；
3. `PERSONA_SLOT(attr, zhangsan)`：替换为当前 persona 的同槽位值。

不允许：

- 地址替换成手机号；
- `address` 映射到同 persona 的 `phone`；
- 已绑定到 persona A 的同槽位又切换成 persona B；
- 任意自由生成不可恢复文本。

#### 5.2.4 采用页面级联合编码而非整页联合动作预测

`de_model` 建议固定采用：

> **页面级一次编码（page-level joint encoding，页面级联合编码） + 实体级逐项解码（per-entity factorized decoding，实体级逐项解码） + 约束解析器（constraint resolver，约束解析器）**

这样既保留实体之间的共现关系，又避免整页联合动作空间指数爆炸。

#### 5.2.5 为什么采用 persona profile，而不是独立 fake value 列表

`de_model` 的基本替换单位不是“单个独立假值”，而是 **persona profile（人设档案）**。
也就是说，**Persona Repository** 维护的是：

- `张三 -> 地址A -> 手机号A`
- `李四 -> 地址B -> 手机号B`

而不是独立的“姓名假值池、地址假值池、手机号假值池”随机拼接。

这样做有三个直接好处：

1. **语义一致性更强**
   同一会话中的姓名、地址、手机号可以保持同一 persona 内部一致。
2. **恢复链路更稳定**
   每个槽位只在合法槽位内替换，恢复更简单，出错面更小。
3. **更利于对抗身份推断**
   云端看到的是自洽的 persona 轨迹，而不是随机碎片化假值，更容易进行会话级身份混淆控制。

#### 5.2.6 形式化优化目标

设攻击者或替身攻击者（surrogate attacker，替身攻击者）输出：

\[
q_\phi(p \mid \tilde{X}_{1:T})
\]

其中：

- \(p\) 表示候选 persona（如 `real / zhangsan / lisi`）；
- \(\tilde{X}_{1:T}\) 表示整轮脱敏后的会话。

设目标后验分布为：

\[
\pi^\star(p)
\]

则 PrivacyGuard 的一个核心目标是让：

\[
q_\phi(p \mid \tilde{X}_{1:T}) \approx \pi^\star(p)
\]

这可通过如下目标实现：

\[
\mathcal{L}_{flat} = \mathrm{KL}(q_\phi \,\|\, \pi^\star)
\]

或：

\[
\mathcal{L}_{flat} = \sum_p (q_\phi(p)-\pi^\star(p))^2
\]

这意味着 `de_model` 的目标不是简单“遮掉真实值”，而是让云端对“到底是谁”的判断更加不确定。

### 5.3 从当前代码反推 `de_model` 需要的输入与输出

#### 5.3.1 当前代码中已经稳定的输出接口

无论内部模型如何实现，`de_model` 最终都应继续输出当前代码已经稳定使用的：

- `DecisionPlan`
- `DecisionAction`

也就是说，渲染与还原链路**不需要**因为真实 `de_model` 上线而整体重写。

`de_model` 的最终外部输出应仍然是：

1. `active_persona_id`
2. `list[DecisionAction]`
3. `summary`
4. `metadata`

其中每条 `DecisionAction` 至少保留：

- `candidate_id`
- `action_type`
- `attr_type`
- `source`
- `source_text`
- `replacement_text`
- `persona_id`
- `bbox`
- `block_id`
- `span_start / span_end`
- `reason`

#### 5.3.2 当前代码中已经可得、但尚未全部进入 `de_model` 的信息

当前 `sanitize` 主链路在进入 Decision 之前，实际上已经掌握了：

- `prompt_text`
- `ocr_blocks`
- `candidates`
- `session_binding`
- `mapping_store` 中的历史 `ReplacementRecord`
- `persona_repository` 中的 persona 列表与统计

但当前 `DecisionEngine.plan(...)` 接口只显式接收：

- `session_id`
- `turn_id`
- `candidates`
- `session_binding`

这意味着：

> **如果真实 `de_model` 想落实 5.2.1 中“使用 prompt 与 OCR 页面上下文”的设计目标，就不能只停留在当前 `plan(...)` 的裸输入形态。**

#### 5.3.3 推荐新增的内部输入对象：`DecisionModelContext`

建议在 application 层新增一个仅供 `de_model` 使用的内部上下文对象，例如：

```python
class DecisionModelContext(BaseModel):
    session_id: str
    turn_id: int
    prompt_text: str
    ocr_blocks: list[OCRTextBlock]
    candidates: list[PIICandidate]
    session_binding: SessionBinding | None
    history_records: list[ReplacementRecord]
    persona_profiles: list[PersonaProfile]
```

然后由 `sanitize` 流程在 Decision 前构造该对象。

这样做的好处是：

1. `label_only` 和 `label_persona_mixed` 仍可沿用旧接口；
2. `de_model` 能获得真正需要的页面级上下文；
3. 输出仍然保持 `DecisionPlan` 不变，兼容现有渲染与恢复。

#### 5.3.4 推荐给模型的实际输入张量

在 `DecisionModelContext` 基础上，建议将输入整理为三层：

1. **页面级输入**
   - prompt 压缩表示
   - OCR 页面摘要
   - turn id
   - 当前是否已有 `active_persona`
   - 历史暴露计数摘要

2. **实体级输入**
   - `candidate.text`
   - `candidate.attr_type`
   - `candidate.source`
   - `candidate.confidence`
   - `bbox / polygon` 派生几何特征
   - 是否重复出现
   - 在当前会话中是否已有同槽位替换记录
   - prompt / OCR 局部上下文文本

3. **persona 级输入**
   - 候选 persona 的 `slots`
   - persona 曝露统计
   - 与当前实体槽位是否匹配
   - 是否为当前 `active_persona`

### 5.4 推荐的 `de_model` 工程框架

#### 5.4.1 模块分层

推荐把真实 `de_model` 拆成下面几层，而不是把所有逻辑都塞进当前的 `DEModelEngine`：

1. **DecisionContextBuilder**
   负责从 `prompt_text / ocr_blocks / candidates / mapping / persona` 组装上下文。
2. **FeatureExtractor / TensorPacker**
   负责把上下文转成固定尺寸张量。
3. **TinyPolicyNet**
   负责真正的前向推理。
4. **PersonaSelector**
   负责页面级 persona 选择或维持当前绑定。
5. **ActionDecoder**
   负责对每个 candidate 输出 `KEEP / GENERICIZE / PERSONA_SLOT` 的 logits。
6. **ConstraintResolver**
   负责把模型输出修正为合法、可恢复的动作。
7. **DEModelEngine**
   作为 orchestrator，把上面几层串起来并输出 `DecisionPlan`。

#### 5.4.2 推荐的代码组织

建议未来新增或调整以下模块：

- `privacyguard/domain/models/decision_context.py`
- `privacyguard/application/services/decision_context_builder.py`
- `privacyguard/infrastructure/decision/tokenizer.py`
- `privacyguard/infrastructure/decision/features.py`
- `privacyguard/infrastructure/decision/tiny_policy_net.py`
- `privacyguard/infrastructure/decision/persona_selector.py`
- `privacyguard/infrastructure/decision/de_model_runtime.py`
- `privacyguard/infrastructure/decision/de_model_engine.py`

其中：

- `de_model_engine.py` 负责 glue code；
- 真正的神经网络结构集中在 `tiny_policy_net.py`；
- Android 侧推理适配放在 `de_model_runtime.py`，便于后续切换 ONNX Runtime Mobile / NCNN。

### 5.5 推荐的 1M 参数级模型结构

#### 5.5.1 设计原则

由于端侧部署目标明确，模型设计建议满足：

1. **参数量控制在 1M 左右**
2. **算子尽量简单**
   便于导出为 ONNX 并部署到 Android
3. **重点建模结构化决策**
   不是通用语言建模
4. **共享编码器**
   prompt、candidate、persona slot 尽量复用同一套文本编码器

#### 5.5.2 推荐结构

推荐采用：

> **共享字符级文本编码器 + 页面级轻量 Transformer + persona 选择头 + 实体动作头 + 约束解析器**

一个适合 Android 的具体方案如下：

| 子模块 | 建议配置 | 作用 | 参数量估计 |
| --- | --- | --- | --- |
| 字符嵌入层 | vocab≈2048, dim=64 | 编码中文字符、数字、常见符号 | ~0.13M |
| 共享文本编码器 | 3 层 depthwise-separable 1D CNN，hidden=96 | 编码 `candidate text / local context / persona slot text` | ~0.05M |
| 类别与数值特征投影 | attr/source/几何/history 的 embedding + MLP | 编码结构化特征 | ~0.03M |
| persona 编码器 | 对 4 个核心槽位做共享编码并池化 | 生成 persona 向量 | ~0.06M |
| 页面级编码器 | 2 层 Transformer，d_model=128, nhead=4, ff=256 | 建模实体之间共现关系 | ~0.26M |
| persona 选择头 | page summary 与 persona 向量打分 | 选择 / 保持 active persona | ~0.05M |
| 动作分类头 | 对每个 entity 输出 3 类动作 logits | 生成 `KEEP / GENERICIZE / PERSONA_SLOT` | ~0.07M |
| 置信与校准头 | 输出 action confidence / utility score | 做阈值与调试 | ~0.03M |
| 预留预算 | LayerNorm、位置编码、导出兼容层 | 工程缓冲 | ~0.10M |

总参数量可控制在：

\[
0.78M \sim 0.88M
\]

这给后续小幅加宽模型仍保留了一定余量。

#### 5.5.3 为什么推荐这个结构

这个结构适合当前项目，原因是：

1. **输入本质是结构化决策，而不是开放式生成**
   所以不需要大模型。
2. **动作空间很小**
   每个实体只有 3 种合法动作。
3. **实体数通常有限**
   页面级 encoder 的长度远小于通用 LLM 序列长度。
4. **Android 部署友好**
   Embedding、Conv1D、Linear、LayerNorm、Softmax 都比较容易导出。

#### 5.5.4 推荐的前向过程

推荐把前向过程固定为：

1. 用共享文本编码器分别编码：
   - candidate 文本
   - 候选局部上下文
   - persona 槽位文本
2. 将文本表示与结构化特征拼接，得到 `entity embedding`
3. 对所有 entity embedding 做页面级联合编码
4. 用页面摘要和 persona 向量做 `active_persona` 选择
5. 对每个 entity 做 3 分类，输出动作 logits
6. 进入 `ConstraintResolver`，生成最终 `DecisionPlan`

### 5.6 不考虑训练模块时的实现原则

本轮规划先**不考虑训练模块**，因此实现上建议分两步：

1. **先打通工程骨架**
   完成上下文构造、特征打包、模型推理接口、输出解码与约束解析。
2. **模型权重作为可替换件**
   初期可以先使用随机占位权重或简单 mock runtime，只验证输入输出与部署链路。

这样可以先把 `de_model` 从“启发式占位规则”升级为“真实模型位点”，后面再单独接训练与蒸馏流程。

---

## 6. `de_model` 分步时间计划（不含训练）

下面给出一个偏工程实现的时间计划，默认由 1 人完成，且**不包括数据集整理、训练、蒸馏与指标调优**。

### Phase 1：接口与上下文收敛（0.5 天）

目标：

- 明确 `DecisionPlan` 输出保持不变；
- 引入 `DecisionModelContext`；
- 明确 `sanitize` 流程如何把 `prompt_text / ocr_blocks / history / persona` 送入 `de_model`。

交付物：

- `decision_context.py`
- 接口变更说明
- 与当前 `DEModelEngine` 的兼容方案

### Phase 2：特征工程与张量打包（1 天）

目标：

- 实现 `DecisionContextBuilder`
- 提取 entity 级、session 级、persona 级特征
- 定义固定输入尺寸与 padding 规则

交付物：

- `decision_context_builder.py`
- `features.py`
- `tokenizer.py`
- 输入张量 schema 文档

### Phase 3：TinyPolicyNet 骨架实现（1.5 天）

目标：

- 实现共享文本编码器
- 实现页面级 encoder
- 实现 persona encoder

交付物：

- `tiny_policy_net.py`
- 前向 shape 单测
- 参数量统计脚本

### Phase 4：persona 选择头与动作头（1 天）

目标：

- 实现 `active_persona` 选择逻辑
- 实现 per-entity 3 分类动作头
- 输出中间 logits 与 confidence

交付物：

- `persona_selector.py`
- 动作解码器
- 中间调试信息结构

### Phase 5：引擎集成与约束闭环（1 天）

目标：

- 用真实模型 runtime 替换当前启发式评分器
- 接入 `ConstraintResolver`
- 失败时可回退到当前占位 `de_model`

交付物：

- 新版 `de_model_engine.py`
- `DecisionPlan` 端到端集成
- 回退机制

### Phase 6：Android 推理准备（1 天）

目标：

- 约束模型算子，保证可导出
- 提供 ONNX 导出与移动端推理适配接口
- 验证定长输入与延迟预算

交付物：

- `de_model_runtime.py`
- ONNX 导出脚本
- Android 侧输入输出对接说明

### Phase 7：测试、样例与文档收尾（1 天）

目标：

- 补单测、集成测试、假权重通路测试
- 给出 1 到 2 个 `de_model` 调用示例
- 更新 README 与请求流文档

交付物：

- 单测与集成测试
- 示例输入输出
- 文档补齐

### 总工期估算

在**不做训练模块**的前提下，推荐预估为：

\[
6 \sim 7 \text{ 个工作日}
\]

如果要加入：

- Android 真机 benchmark
- ONNX Runtime Mobile 接入
- 与当前 GUI Agent 的联调

则建议再预留：

\[
1 \sim 2 \text{ 个工作日}
\]

作为联调缓冲。
