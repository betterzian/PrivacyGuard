de_model 代码重构任务拆解文档
1. 重构目标

本次重构目标不是“把 de_model 写得更复杂”，而是把它改成：

理论上仍符合你之前定下的策略逻辑

工程上继续兼容当前 sanitize -> render -> mapping -> restore 主链

训练上能从单层 action 标签升级到更清晰的层级标签

文档、代码、测试三者不再漂移

2. 本次重构的硬约束
2.1 不改外部 API 形态

外部接口继续保持当前 DTO：

SanitizeRequest(session_id, turn_id, prompt_text, screenshot, protection_level, detector_overrides)

SanitizeResponse(sanitized_prompt_text, sanitized_screenshot, active_persona_id, replacements, metadata)

RestoreRequest(session_id, turn_id, cloud_text)

RestoreResponse(restored_text, restored_slots, metadata)

2.2 不把 de_model 变成 detector

de_model 只处理 detector 已经产出的 candidate，不承担：

补召回

span 重建

OCR 纠错

bbox 修复

2.3 不新造 EntityTruth 作为正式运行时主对象

理论上可以继续说“真相层 / 关系层 / 策略层”，
但代码里不再新增 EntityTruth -> EntityGroup -> ... 这种正式主链对象。
正式运行时边界仍以 DecisionModelContext 及其轻量特征对象为主。这个方向与当前仓库的 DecisionContextBuilder -> DecisionFeatureExtractor 结构是一致的。

2.4 动作枚举统一到工程动作

执行层只保留：

KEEP

GENERICIZE

PERSONA_SLOT

当前 heuristic runtime 也已经围绕这三类动作打分，因此文档、训练标签、约束逻辑都应统一到这三个动作。LABEL 只作为理论别名，不再作为代码里的正式动作名。

3. 重构后目标结构
3.1 主链不变

继续保持：

OCR / detector
→ AliasLinker
→ LocalContextBuilder
→ QualityAggregator
→ PersonaStateBuilder
→ DecisionContextBuilder
→ DecisionFeatureExtractor
→ DEModelEngine
→ runtime
→ ConstraintResolver
→ DecisionPlan
→ render / mapping / restore
3.2 真正要新增或重构的是 4 个 builder

AliasLinker

LocalContextBuilder

QualityAggregator

PersonaStateBuilder

3.3 DecisionModelContext 内部改为 4 块

raw_refs

candidate_policy_views

page_policy_state

persona_policy_states

4. 分阶段任务拆解
Phase 0：语义冻结与边界收束
目标

先统一名词和边界，避免后续一边改代码一边改定义。

任务
T0.1 统一动作术语

代码、文档、训练标签统一使用：

KEEP

GENERICIZE

PERSONA_SLOT

把旧文档里的 LABEL 明确标注为“理论别名，工程名为 GENERICIZE”

T0.2 冻结模块职责

在文档中明确：

detector 负责发现 candidate

alias/linking 负责 session 稳定映射

de_model 只负责策略决策

restore 只消费 mapping，不反向干预决策

T0.3 冻结外部 API

明确本次重构不修改 sanitize/restore 的 DTO 形状

所有改动都限制在内部 pipeline、context、runtime、training 层

验收标准

所有文档中不再混用 LABEL 和 GENERICIZE

不再出现“de_model 负责检测实体”之类表述

API 层无 breaking change

产出

更新后的 docs/DE_MODEL_IMPLEMENTATION.md

一份简短的 docs/DE_MODEL_REFACTOR_SCOPE.md

Phase 1：拆出 builder 子模块
目标

把当前 DecisionContextBuilder 内可能混杂的职责拆清。

任务
T1.1 新增 AliasLinker

职责：

为 candidate 分配 session_alias

高置信时复用 alias

低置信或歧义时新建 alias

不把 alias 纠纷下放给 de_model

输出：

candidate_id -> session_alias

alias 来源标记

alias 历史暴露统计

T1.2 新增 LocalContextBuilder

职责：

构建 prompt_local_context

构建 ocr_local_context

OCR 跨 block 时生成 ocr_merged_context

生成 cross_block_flag 和 covered_block_count

T1.3 新增 QualityAggregator

职责：

聚合 detector 置信度

聚合 OCR 局部质量

生成 page 级质量状态

统一替代之前含混的“global 置信度”说法

建议输出字段：

det_conf_bucket

ocr_local_conf_bucket

low_ocr_flag

page_quality_state

T1.4 新增 PersonaStateBuilder

职责：

读取当前 session active persona

计算 persona 对各 attr 的支持情况

计算 persona 当前槽位是否可用

输出 exposure 统计

验收标准

这 4 类职责不再堆在一个大 builder 里

DecisionContextBuilder 只做组装，不再承担全部计算

新 builder 均有独立单测

产出

alias_linker 模块

local_context_builder 模块

quality_aggregator 模块

persona_state_builder 模块

Phase 2：重构 DecisionModelContext
目标

在不引入 EntityTruth 的前提下，把模型输入上下文正式收束。

任务
T2.1 增加 raw_refs

只存引用，不复制整套真值对象。

建议包含：

candidate_id -> PIICandidate

block_id -> OCRBlock

历史 mapping 引用

persona 引用

T2.2 增加 candidate_policy_views

每个 candidate 一条轻量策略视图。

建议字段：

candidate_id

attr_type

source

session_alias

same_alias_count_in_turn

cross_source_same_alias_flag

history_alias_exposure_bucket

history_exact_match_bucket

det_conf_bucket

ocr_local_conf_bucket

low_ocr_flag

cross_block_flag

covered_block_count_bucket

same_attr_page_bucket

normalized_len_bucket

digit_ratio_bucket

mask_char_flag

prompt_local_context_labelized

ocr_local_context_labelized

T2.3 增加 page_policy_state

建议字段：

protection_level

candidate_count_bucket

unique_attr_count_bucket

avg_det_conf_bucket

min_det_conf_bucket

avg_ocr_conf_bucket

low_ocr_ratio_bucket

page_quality_state

T2.4 增加 persona_policy_states

建议字段：

persona_id

is_active

supported_attr_mask

available_slot_mask

attr_exposure_buckets

matched_candidate_attr_count

验收标准

DecisionModelContext 成为唯一正式策略上下文

不再出现引入 EntityTruth 的计划残留

下游 DecisionFeatureExtractor 仅从这些字段取数

产出

新版 DecisionModelContext

context 构造单测

context 序列化 / debug dump 能力

Phase 3：重构特征提取层
目标

让 DecisionFeatureExtractor 与新的 context 结构一一对应。

任务
T3.1 重写 candidate 特征映射

输入：

candidate_policy_view

输出：

candidate structured vector

T3.2 重写 page 特征映射

输入：

page_policy_state

输出：

page vector

T3.3 重写 persona 特征映射

输入：

persona_policy_states

输出：

persona vector

T3.4 保留文本通道，但降级为辅助信号

当前模型已经有：

candidate_text

prompt_context

ocr_context
以及结构化投影通道。此次重构不删除文本通道，但要在文档和实现上明确：文本只是辅助，不应压过 alias / history / quality / persona 等结构化信号。

验收标准

DecisionFeatureExtractor 与旧字段不再强耦合

新特征对象可以直接给 heuristic runtime 和 torch runtime 复用

单测覆盖 “prompt candidate / OCR single-block / OCR cross-block” 三种输入类型

Phase 4：重构 runtime 输出协议
目标

把“最终三动作”与“内部两级决策逻辑”统一起来。

任务
T4.1 定义新的 runtime 输出结构

建议输出字段：

candidate_id

protect_decision：KEEP | REWRITE

rewrite_mode：GENERICIZE | PERSONA_SLOT | NONE

persona_id

final_action

confidence

reasons

fallback_reason

T4.2 改 heuristic runtime

当前 heuristic runtime 已经对三动作打分。先不要推翻，只做输出协议升级：

先算 KEEP vs REWRITE

再算 GENERICIZE vs PERSONA_SLOT

最后合成 final_action

T4.3 改 torch runtime

当前 torch runtime 已经能接 checkpoint 推理。第一步先兼容新的输出协议；第二步再决定是否把 TinyPolicyNet 改成真正双头。这样风险更小。

验收标准

heuristic runtime 与 torch runtime 输出协议一致

下游 ConstraintResolver 不再直接依赖旧式平面 action 输出

debug 日志能看见“两级决策过程”

Phase 5：升级 ConstraintResolver
目标

让约束层成为硬边界，而不是简单兜底。

任务
T5.1 persona 缺失回退

若输出 PERSONA_SLOT，但无 active persona：

回退到 GENERICIZE

T5.2 attr 不匹配回退

若 persona 不支持当前 attr_type：

回退到 GENERICIZE

T5.3 slot 不可用回退

若 persona 有该 attr_type，但对应槽位不可用：

回退到 GENERICIZE

T5.4 alias 缺失补建

若 GENERICIZE 需要 alias，但 alias 未分配：

先尝试补建

失败时落到安全默认 placeholder

T5.5 高 protection + 低质量页面阈值收紧

当：

protection_level 高

page_quality_state 差

则：

提高 KEEP 门槛

限制激进保留

T5.6 跨 block + 低 OCR 质量回退

当：

cross_block_flag = true

ocr_local_conf_bucket 很低

则：

降低 KEEP 优先级

验收标准

所有非法 PERSONA_SLOT 都能被稳定回退

所有 GENERICIZE 都能生成可恢复 alias

低质量页面上 KEEP 变得更保守

Phase 6：升级 TinyPolicyNet 与训练标签
目标

把训练从“平面三分类”升级为“层级标签”。

任务
T6.1 重定义监督标签

从：

单一 target_action

改为：

target_protect_label：KEEP | REWRITE

target_rewrite_mode：GENERICIZE | PERSONA_SLOT

target_persona_id

T6.2 数据导出器升级

训练导出时，把以下信息写入 JSONL：

candidate policy view

page policy state

persona policy states

target_protect_label

target_rewrite_mode

target_persona_id

final_action

T6.3 模型头升级

当前 TinyPolicyNet 已有统一文本编码器与结构化投影层。建议在不动编码器主干的情况下，逐步升级输出头：
第一阶段：

先保留现有主干

新增 protect_head

新增 rewrite_mode_head

保留 persona_head

第二阶段：

若效果稳定，再减少对旧平面 action head 的依赖

T6.4 损失函数升级

建议：

L_protect

L_rewrite_mode

L_persona

L_cost

其中：

高 protection 下误判 KEEP 增加权重

低质量页面下误判 KEEP 增加权重

persona 不可用时对 PERSONA_SLOT 直接 mask 或高惩罚

验收标准

supervised JSONL 可以导出新标签

训练脚本可以消费新标签

checkpoint 可以被 torch runtime 正常读取

Phase 7：mapping / restore 对齐检查
目标

确保新动作输出不破坏当前 restore 闭环。

任务
T7.1 GENERICIZE 映射检查

确保：

所有 generic placeholder 都可写入 ReplacementRecord

restore 能从 ReplacementRecord 反查真实值

T7.2 PERSONA_SLOT 映射检查

确保：

假值替换记录中保留原值和假值关系

restore 时优先按当前 turn replacement 回填

T7.3 KEEP 最小日志

即使 KEEP 不替换，也记录最小调试字段：

candidate_id

attr_type

confidence

decision reason

当前 README 已明确：现阶段 restore 是基于当前 turn 的 ReplacementRecord 恢复云端返回文本，因此本次重构不应突破这个边界，而是保证与它兼容。

验收标准

sanitize -> restore 闭环回归测试全通过

新动作协议不破坏当前 turn restore

Phase 8：测试与评测补齐
目标

把这次重构从“代码改动”变成“可验证迭代”。

任务
T8.1 单测补齐

至少覆盖：

alias 复用 / 新建

OCR 单 block / 跨 block

prompt source / OCR source

persona 缺失 / slot 不可用

高 protection + 低质量页面

T8.2 集成测试补齐

至少覆盖：

sanitize 主链

de_model heuristic runtime

de_model torch runtime

ConstraintResolver

render + mapping + restore

README 已说明当前测试已经覆盖 detector、pipeline、renderer、fill strategy、de_model context 和 TinyPolicyNet 原型，因此这一步应该是扩测，不是从零开始。

T8.3 评测指标补齐

至少整理出四类指标：

隐私泄露率

可用性

session 一致性

低质量鲁棒性

5. 优先级排序
必做

Phase 0

Phase 1

Phase 2

Phase 4

Phase 5

Phase 7

应做

Phase 3

Phase 6

可延后

更复杂的多 persona 选择

bundle / ONNX / TFLite runtime

adversarial finetune

跨 turn 全会话 restore

当前仓库 README 也明确说明：bundle runtime 和 adversarial finetune 仍未完成，因此它们不应进入这轮核心重构范围。

6. 推荐执行顺序

建议严格按下面顺序推进：

先统一语义，不改模型

先拆 builder，不改训练

先重构 context，不改外部 API

先升级 runtime 输出协议，不立刻大改网络结构

先强化 resolver，再升级训练标签

最后补测试和评测

这样做的原因是：

能始终保持 sanitize 主链可运行

每一步都能单独回归

不会出现“模型、文档、数据导出、恢复层一起炸”的情况

7. 不要做的事

这轮里不建议做下面这些：

不要为了概念完整性新增 EntityTruth

不要重写 sanitize/restore 对外 DTO

不要把 de_model 混成 detector 或 OCR 修复器

不要先改网络、再想标签

不要先做多 persona，再把单 persona 稳定逻辑补上