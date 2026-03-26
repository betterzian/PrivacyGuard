# Detector Implementation

## 1. 文档范围

本文档描述 PrivacyGuard 仓库中 detector 的当前实现。

当前正式对外可用的 detector 仍然是：

- `rule_based`

本文档只讨论：

- detector 在 `sanitize` 主链中的位置
- `RuleBasedPIIDetector` 的输入、输出与分层扫描顺序
- `session dictionary -> privacy_repository -> rules` 的实现方式
- `strong / balanced / weak` 三档强度在 detector 内的作用
- `zh_cn / en_us / mixed` locale profile
- OCR 页级扫描、候选 remap、姓名 refinement
- 英文地址结构化支持如何接入 detector

本文档不讨论：

- `label_only` / `label_persona_mixed` / `de_model` 的 decision 逻辑
- placeholder 分配、render、restore 的完整实现
- OCR 引擎本身的识别算法

需要先明确：

- detector 的职责是产出 `PIICandidate`
- detector 不负责最终动作决策
- detector 不直接产出 `KEEP / GENERICIZE / PERSONA_SLOT`
- detector 和 decision 是两层

---

## 2. 在主链中的位置

当前 `sanitize` 主链的 detector 边界是：

```text
OCR / prompt parse
-> detector
-> DecisionContextBuilder
-> decision_engine.plan(...)
-> ConstraintResolver + ReplacementGenerationService
-> render
-> mapping store
```

也就是说：

1. `sanitize_pipeline` 先拿到 `prompt_text` 和 `ocr_blocks`
2. 把两路输入交给 detector
3. detector 返回 `PIICandidate` 列表
4. decision 层再对这些候选做动作规划

因此 detector 当前只关心两件事：

- 识别什么文本像隐私实体
- 给这些候选打工程置信度并附带 `metadata`

---

## 3. 核心对象

当前 detector 主实现是 `privacyguard/infrastructure/pii/rule_based_detector.py` 中的
`RuleBasedPIIDetector`。

初始化时会完成这些准备：

1. 规范 `locale_profile`
2. 解析 `privacy_repository_path`
3. 加载本地隐私词典
4. 将词典编译成索引
5. 注入 `mapping_store`，供 session 级词典复用
6. 构建 regex 规则
7. 构建字段上下文规则
8. 构建口语化自报姓名规则
9. 构建 masked text 规则
10. 初始化名字、称谓、标题等辅助 pattern

当前支持的 locale profile 是：

- `zh_cn`
- `en_us`
- `mixed`

其中：

- `zh_cn` 只启用中文相关规则
- `en_us` 只启用英文相关规则
- `mixed` 同时启用中英规则

---

## 4. 输入与输出

`detect(...)` 当前输入包括：

- `prompt_text`
- `ocr_blocks`
- `session_id`
- `turn_id`
- `protection_level`
- `detector_overrides`

当前输出是 `list[PIICandidate]`。

每个候选至少包含：

- `entity_id`
- `text`
- `normalized_text`
- `attr_type`
- `source`
- `bbox`
- `block_id`
- `span_start`
- `span_end`
- `confidence`
- `metadata`

当前 `metadata` 最重要的字段通常有：

- `matched_by`
- `local_entity_ids`
- `session_turn_ids`
- `ambiguous_binding_keys`

---

## 5. detect 的真实执行流程

`RuleBasedPIIDetector.detect(...)` 当前真实流程是：

```text
build session dictionary from mapping_store
-> build rule profile from protection_level
-> scan prompt text
-> scan OCR page document
-> resolve / deduplicate candidates
```

展开后可以写成：

1. 根据 `session_id` 与 `turn_id` 从历史 replacement records 聚合 session dictionary
2. 读取当前 `protection_level` 对应的 detector rule profile
3. 用 `_scan_text(...)` 扫描 prompt
4. 用 `_scan_ocr_page(...)` 扫描 OCR 页面拼接文本
5. 将两路候选交给 `CandidateResolverService.resolve_candidates(...)`

这里有两个关键点：

- prompt 与 OCR 共用同一套 rule engine
- OCR 不是逐 block 独立扫描，而是整页拼接后统一扫描再 remap

---

## 6. 分层扫描顺序

当前 detector 不是“把所有规则一起跑完后再排序”，而是按分层顺序逐层推进。

`_scan_text(...)` 的当前顺序是：

1. `session dictionary`
2. `local dictionary`
3. `context`
4. `regex`
5. `organization`
6. `name`
7. `address`
8. `geo fragment`
9. `generic number`
10. `masked text`

这条顺序很重要，因为它决定了 detector 的工程行为：

- 前面的阶段通常更精确
- 后面的阶段通常更弱、更启发式
- 每一层之后都会刷新 `protected_spans`
- 后续层通常会避开这些已保护区间

因此当前 detector 的行为不是“多规则公平竞争”，而是：

- 高精度证据先占位
- 弱规则只在高精度证据没覆盖的地方补召回

---

## 7. protected spans 与 shadow text

当前 detector 为了让后续弱规则还能看见上下文，但又不覆盖已经识别出的实体，会使用两套机制：

### 7.1 `protected_spans`

每一层扫描后，已接受候选的 span 会变成受保护区间。

后续层如果命中这些区间，通常会直接跳过。

这保证了：

- `session dictionary` 不会被后面的 regex 冲掉
- `privacy_repository` 命中不会被更弱的启发式规则降级
- 一个高精度电话号码不会被后面的 generic number 再识别一遍

### 7.2 `shadow text`

在 organization / name / address / geo / masked text 这些较弱层之前，
detector 会把已命中的 span 替换成类型占位符，例如：

- `<NAME>`
- `<ADDR>`
- `<PHONE>`
- `<EMAIL>`

这样做的目的不是为了给用户看，而是为了：

- 避免后续规则重复匹配已识别文本
- 保留句子结构和局部语义
- 让较弱规则还能利用剩余上下文

---

## 8. 词典系统

当前 detector 有两套词典源。

### 8.1 privacy_repository 本地词典

本地词典来自 `privacy_repository` JSON。

它会在 detector 初始化或 `reload_privacy_dictionary()` 时读取，并转成统一的
`_LocalDictionaryEntry` 列表，再进一步编译成 `_CompiledDictionaryIndex`。

本地词典命中是当前最强证据之一。

它的特点是：

- 命中稳定
- 可以带 `local_entity_ids`
- 对同一个实体支持 alias
- 结构化地址会先展开成自然匹配变体

### 8.2 session dictionary

session dictionary 来自 `mapping_store` 中的历史 `ReplacementRecord`。

当前逻辑会按：

- `session_id`
- `attr_type`
- `canonical source text`

聚合同一实体的历史暴露，再生成 session 级 `_LocalDictionaryEntry`。

它的作用是让同一 session 内已经替换过的真实隐私值，在后续 turn 中优先复用。

这也是当前 `session > privacy_repository > rules` 的第一层来源。

---

## 9. 词典匹配与结构化地址展开

当前本地词典不是简单地拿原始值做字符串包含判断，而是会先生成匹配变体。

核心做法包括：

- 对不同 `attr_type` 做 canonicalize
- 为 alias 生成额外变体
- 对结构化地址按显示粒度生成自然文本

对于地址，当前实现已经不再只适合中文地址。

英文地址现在支持将结构化字段展开成更自然的匹配文本，例如：

- `street`
- `building`
- `city`
- `province`
- `postal_code`

这意味着 privacy repository 中的英文结构化地址可以被 detector 直接命中，而不是只能把整个地址硬塞进一个字符串槽位。

---

## 10. 三类规则来源

当前 rule engine 大致分成三类。

### 10.1 regex 规则

这是格式最强的一组规则。

当前覆盖的主要类型包括：

- `PHONE`
- `EMAIL`
- `CARD_NUMBER`
- `BANK_ACCOUNT`
- `PASSPORT_NUMBER`
- `DRIVER_LICENSE`
- `ID_NUMBER`
- `TIME`

英文扩展后，regex 层已经支持：

- US / E.164 风格电话
- 英文邮箱
- 一部分英文地址 span

### 10.2 context 规则

这组规则依赖字段标签或显式上下文，例如：

- `name`
- `email`
- `address`
- `organization`
- `phone`
- `passport`

它的特点是：

- 适合表单、简历、资料页、聊天资料卡
- value 本身允许比 free-text 更宽
- 仍然会经过 validator 二次校验

### 10.3 轻启发式规则

这组规则主要补 free-text 和弱语义场景，包括：

- 自报姓名
- 机构后缀
- 地址碎片
- 地名碎片
- generic number
- masked text

这部分更依赖：

- 规则顺序
- protected spans
- rule profile
- validator 的过滤质量

---

## 11. validator 层

当前 detector 不是“命中 regex 就收下”。

多数规则命中后，还会经过 validator 过滤。

当前关键 validator 包括：

- `_is_phone_candidate(...)`
- `_is_en_phone_candidate(...)`
- `_is_email_candidate(...)`
- `_is_name_candidate(...)`
- `_is_organization_candidate(...)`
- `_looks_like_address_candidate(...)`
- `_address_confidence(...)`

它们的主要职责是：

1. 过滤形状像但语义不成立的文本
2. 对中英规则分开判定
3. 在地址、机构、姓名这类高歧义类型上做额外抑制
4. 把明显冲突的格式型命中降级为更保守的 `OTHER`

这也是为什么 detector 当前虽然是 rule-based，但并不是单纯的正则集合。

---

## 12. `strong / balanced / weak` 三档强度

当前三档强度在 detector 内部通过 `_RuleStrengthProfile` 实现。

它不是单纯的“统一加减阈值”，而是一组成体系的行为开关。

当前它主要控制：

- 各个 `attr_type` 的最小置信度
- 是否启用更激进的姓名规则
- 是否允许 standalone masked text
- 是否接受更弱的机构后缀
- 是否放开更低置信度的地址碎片
- OCR 噪声与 mask 文本容忍度

因此三档强度当前更接近：

- 一套 detector 策略配置

而不是：

- 一个简单的全局分数阈值

这也是 detector 和 decision 不完全解耦的地方之一：

- detector 自己先决定哪些候选能进下游
- decision 只能在 detector 已经放行的候选上做动作规划

---

## 13. locale profile

当前 detector 不是只有中文规则。

它已经支持：

- `zh_cn`
- `en_us`
- `mixed`

locale 的影响范围包括：

- 电话 regex
- 自报姓名 pattern
- 机构后缀
- 地址 span 规则
- 地址 validator
- 地址结构化展开
- OCR 英文时间 / preview 语义

### 13.1 `zh_cn`

启用中文姓名、中文地址、中文手机号、中文地名和中国证件类规则。

### 13.2 `en_us`

启用英语姓名、US 电话、英文地址、英文机构、英文 OCR 语义规则。

### 13.3 `mixed`

同时启用中英规则。

这是当前最适合混合场景的 profile，也是现在扩展英文能力时最稳妥的默认选择。

---

## 14. OCR 处理方式

当前 OCR 路径不是按单 block 独立执行 detector，而是：

1. 将整页 `OCRTextBlock` 拼成 page document
2. 在整页文本上执行与 prompt 相同的 `_scan_text(...)`
3. 再把命中的页级 span remap 回原始 block
4. 对姓名和地址做 OCR 场景专门后处理

这样做的原因是：

- OCR 里的实体经常跨 block
- 聊天列表、对话页、地址卡片常常一条实体拆成两三块
- 单 block 扫描会丢掉大量上下文

### 14.1 OCR name refinement

姓名候选在 remap 后不会直接结束，还会进入 OCR scene refinement。

这里会利用：

- 同行时间元信息
- preview text
- UI 标签
- 邻近 block 结构

来抑制聊天 UI 中的误识别。

### 14.2 OCR address block derivation

地址候选如果覆盖多个 OCR block，不只保留页级文本，还会进一步派生 block 级地址候选，
供后续截图替换对齐使用。

这一步对多行地址尤其重要。

---

## 15. 英文地址支持如何接入 detector

这次英文扩展后，地址不再只是中文后缀规则。

当前 detector 已经可以消费 locale-aware 的地址工具链：

1. 英文地址解析会拆成 `street / building / city / province / postal_code`
2. 结构化地址会展开成 detector 可匹配的自然文本变体
3. detector 命中地址后，`canonicalize_pii_value` 与地址渲染工具链使用同一套地址理解

这带来三个直接收益：

### 15.1 本地实体可直接命中

privacy repository 里的英文结构化地址不需要退化成一整串 `street.value` 才能被 detector 命中。

### 15.2 session 复用更稳定

同一英文地址在不同 turn 里，即使源文本粒度不同，也更容易复用同一 canonical 值。

### 15.3 下游替换更闭环

detector 识别出的英文地址，后续 persona slot replacement 和 screenshot renderer
可以按源文本粒度回渲染，而不是只能返回整个完整地址。

需要注意：

- 这部分虽然从 detector 入口接入，但真正闭环依赖 `pii_value.py`、persona repository、
  rendering 侧共享的地址组件工具
- 因此英文地址能力已经不是“detector 单文件 patch”，而是 detector 牵头、下游共用同一地址结构理解

---

## 16. 候选去重与稳定 ID

当前 detector 的最终输出不会把所有原始命中直接原样吐出。

最后一步会交给 `CandidateResolverService.resolve_candidates(...)` 做去重。

当前去重键主要由这些信息组成：

- `source`
- `normalized_text`
- `attr_type`
- `bbox`
- `block_id / span`

这意味着：

- 同一来源、同一归一化值、同一位置的重复命中会被合并
- 同文但不同 bbox 的 OCR 候选仍然可以并存
- metadata 会做并集式合并
- `candidate_id` 会保持稳定可复现

---

## 17. 当前实现的优点

从工程角度看，当前 detector 的主要优点是：

1. 分层顺序清晰，便于控制误检
2. `session > local > rules` 已经是代码级真实行为
3. prompt 与 OCR 共用一套核心 rule engine
4. OCR 采用页级扫描，跨 block 召回比单块规则强
5. 地址、姓名、机构等高歧义类型有专门 validator，不是单纯正则
6. 英文能力已经能和 session / privacy repository / address rendering 闭环结合
7. 三档强度是规则配置层，不只是一个阈值

---

## 18. 当前实现的边界

当前 detector 仍然有明显边界。

### 18.1 仍然是 rule-based 主体

它对结构化、字段化、弱自由文本的场景表现不错，但不是开放域 NER。

### 18.2 英文目前更偏 `en_us`

当前英文地址、电话和地区规则主要按 `en_us` 设计。

如果要进一步扩到：

- `en_gb`
- `en_ca`
- `en_au`

更合理的做法是继续扩 locale profile，而不是把所有英文国家的规则都硬塞进 `en_us`。

### 18.3 语义理解仍然有限

对于非常自由的英文对话、隐晦指代、长距离上下文推断，当前 detector 仍然依赖启发式规则。

这也是后续是否接入 NER / hybrid detector 的主要动力。

---

## 19. 当前回归覆盖

当前 detector 相关回归已覆盖这些方面：

- 默认 `decision_mode` 仍为 `label_only`
- 英文 `session dictionary` 优先于 `privacy_repository`
- 英文 `privacy_repository` 优先于规则识别
- 英文 `name / phone / organization / address`
- 英文结构化地址的 detector 命中
- 英文地址在 persona repository 的 round-trip
- 英文地址在 screenshot renderer 中的多 block replacement split
- 既有 stage2 detector 回归

相关测试文件包括：

- `tests/test_app_defaults.py`
- `tests/test_detector_en_locales.py`
- `tests/test_address_locale_support.py`
- `tests/test_stage2_regressions.py`

---

## 20. 一句话总结

当前 PrivacyGuard detector 的真实实现可以概括为：

> 一个以 `RuleBasedPIIDetector` 为核心、以 `session dictionary -> privacy_repository -> layered rules`
> 为主干、以 `protected spans + shadow text + validator` 控制误检、以页级 OCR remap 处理截图场景、
> 并已经具备中英混合与英文结构化地址闭环能力的工程化 PII 候选生成层。
