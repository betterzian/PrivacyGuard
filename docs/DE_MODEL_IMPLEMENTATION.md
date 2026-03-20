# de_model 实现说明

本文档描述的是仓库里当前已经实现出来的 `de_model`，不是理想设计稿。

## 1. 当前 `de_model` 在系统中的位置

`de_model` 已经是 `PrivacyGuard` 的默认决策模式，调用链位于 `sanitize` 主流程中：

```text
sanitize
  -> OCR + detector
  -> DecisionContextBuilder
  -> DecisionFeatureExtractor
  -> DEModelEngine
  -> heuristic runtime 或 torch runtime
  -> ConstraintResolver
  -> SessionPlaceholderAllocator
  -> render + mapping_store
```

也就是说，`de_model` 不是一个旁路实验分支，而是已经接在正式 `sanitize` 流程里的决策模式。

## 2. 接口边界

当前所有决策引擎共用同一个接口：

```python
plan(context: DecisionContext) -> DecisionPlan
```

这带来两个直接结果：

- `label_only` 和 `label_persona_mixed` 也消费统一上下文
- `de_model` 不需要特殊分支，直接吃完整页面与会话信息

## 3. `DecisionContext` 当前包含什么

`DecisionContextBuilder` 会把以下信息统一收敛到 `DecisionContext`：

- `session_id`
- `turn_id`
- `prompt_text`
- `protection_level`
- `detector_overrides`
- `ocr_blocks`
- `candidates`
- `session_binding`
- `history_records`
- `persona_profiles`
- `page_features`
- `candidate_features`
- `persona_features`

### 3.1 Page 级特征

当前 page 特征共 20 维：

1. `prompt_length`
2. `ocr_block_count`
3. `candidate_count`
4. `unique_attr_count`
5. `history_record_count`
6. `active_persona_bound`
7. `prompt_has_digits`
8. `prompt_has_address_tokens`
9. `average_candidate_confidence`
10. `min_candidate_confidence`
11. `high_confidence_candidate_ratio`
12. `low_confidence_candidate_ratio`
13. `prompt_candidate_count`
14. `ocr_candidate_count`
15. `average_ocr_block_score`
16. `min_ocr_block_score`
17. `low_confidence_ocr_block_ratio`
18. `protection_level_weak`
19. `protection_level_balanced`
20. `protection_level_strong`

### 3.2 Candidate 级特征

每个 candidate 会补齐这些信息：

- `candidate_id / text / normalized_text / attr_type / source / confidence`
- `bbox / block_id / span_start / span_end`
- `prompt_context / ocr_context`
- `history_attr_exposure_count / history_exact_match_count`
- `same_attr_page_count / same_text_page_count`
- `relative_area / aspect_ratio / center_x / center_y`
- `ocr_block_score / ocr_block_rotation_degrees / is_low_ocr_confidence`
- `is_prompt_source / is_ocr_source`

### 3.3 Persona 级特征

每个 persona 会提取：

- `persona_id / display_name`
- `slot_count`
- `exposure_count`
- `last_exposed_session_id / last_exposed_turn_id`
- `is_active`
- `supported_attr_types`
- `matched_candidate_attr_count`
- `slots`

## 4. 数值特征压缩

`DecisionFeatureExtractor` 会把 `DecisionContext` 压成 `PackedDecisionFeatures`：

- `page_vector`
- `candidate_ids`
- `candidate_vectors`
- `persona_ids`
- `persona_vectors`

当前固定维度如下：

| 向量 | 维度 |
| --- | ---: |
| `page_vector` | 20 |
| `candidate_vector` | 41 |
| `persona_vector` | 26 |

### 4.1 `candidate_vector` 组成

`candidate_vector` 的 41 维来自：

1. `attr_one_hot`
   12 维，对应完整 `PIIAttributeType`
2. `source_one_hot`
   2 维
3. `confidence`
   1 维
4. 历史与页内计数
   4 维
5. 几何特征
   4 维
6. OCR 局部质量
   3 维
7. 文本签名
   `text / prompt_context / ocr_context` 各 5 维，共 15 维

### 4.2 `persona_vector` 组成

`persona_vector` 的 26 维来自：

1. `slot_count / exposure_count / is_active / matched_candidate_attr_count`
   4 维
2. `supported_attr_types` one-hot
   12 维
3. `display_name` 文本签名
   5 维
4. `slots` 拼接文本签名
   5 维

## 5. `DEModelEngine` 的当前行为

`DEModelEngine` 负责：

1. 调用 `DecisionFeatureExtractor.pack(context)`
2. 调用 runtime 预测
3. 把 runtime 输出转成 `DecisionAction`
4. 经过 `ConstraintResolver` 做合法性校正
5. 返回 `DecisionPlan`

当前支持的 runtime 类型：

| `runtime_type` | 状态 | 说明 |
| --- | --- | --- |
| `heuristic` | 已实现 | 默认路径，不依赖 torch |
| `tiny_policy_heuristic` | 已实现 | `heuristic` 的别名 |
| `torch` | 已实现 | 需要 `checkpoint_path` |
| `bundle` | 未实现 | 需要 `bundle_path`，但当前直接抛 `NotImplementedError` |
| `onnx` | 未实现 | 归一到 `bundle` |

## 6. Runtime 层

### 6.1 统一协议

当前 runtime 统一实现这个协议：

```python
predict(context: DecisionContext, packed: PackedDecisionFeatures) -> DEModelRuntimeOutput
```

输出 `DEModelRuntimeOutput` 包含：

- `active_persona_id`
- `persona_scores`
- `candidate_decisions`

其中每个 `candidate_decisions` 项包含：

- `candidate_id`
- `preferred_action`
- `action_scores`
- `reason`

### 6.2 Heuristic runtime

`TinyPolicyRuntime` 是默认 runtime，主要做三件事：

1. 选择 active persona
2. 对每个 candidate 计算 `KEEP / GENERICIZE / PERSONA_SLOT` 分数
3. 返回可解释的评分理由

它主要依赖：

- candidate confidence
- 历史暴露次数
- 历史 exact match 次数
- 页内重复次数
- prompt 是否偏数字
- 当前是否有 active persona
- 当前 persona 是否支持对应 attr
- OCR 来源与否

### 6.3 Torch runtime

`TorchTinyPolicyRuntime` 已经可以跑真实前向推理，能力包括：

- 加载 checkpoint
- 从 `DecisionContext` 构建 `TinyPolicyBatch`
- 调用 `TinyPolicyNet.forward()`
- 使用 `TinyPolicyOutputDecoder` 解码

它支持两种 checkpoint 形态：

- 纯 `state_dict`
- `{state_dict, model_config, ...}`

## 7. `TinyPolicyOutputDecoder`

`TinyPolicyOutputDecoder` 负责把 `TinyPolicyNet` 输出解码为 runtime 结果。

当前可配置参数：

- `keep_threshold`
- `persona_score_threshold`
- `action_tie_tolerance`

当前语义是：

- 若 `confidence_score < keep_threshold`，强制回退为 `KEEP`
- persona softmax 最高分若低于 `persona_score_threshold`，则不激活 persona
- 动作分数接近时，按 tie-break 选择

当前 tie-break 顺序对应的偏好是：

```text
PERSONA_SLOT > GENERICIZE > KEEP
```

也就是分数几乎相同时，优先更强匿名化动作。

## 8. `ConstraintResolver`

runtime 输出不会直接进入渲染层，而是先经过 `ConstraintResolver`。

它当前负责：

- candidate 不存在时降级为 `KEEP`
- 跨槽位动作改写为同槽位 `GENERICIZE`
- `PERSONA_SLOT` 但没有 persona 时降级
- persona 缺少对应槽位值时降级
- `GENERICIZE` 缺失标签时自动补标准占位符

这意味着：

- runtime 负责“偏好”
- 约束层负责“合法性”和“可恢复性”

## 9. `TinyPolicyNet` 当前结构

### 9.1 默认配置

`TinyPolicyNetConfig` 当前默认值如下：

| 参数 | 默认值 |
| --- | ---: |
| `vocab_size` | 2048 |
| `max_text_length` | 48 |
| `page_feature_dim` | 20 |
| `candidate_feature_dim` | 41 |
| `persona_feature_dim` | 26 |
| `char_embedding_dim` | 64 |
| `text_hidden_dim` | 96 |
| `text_encoder_layers` | 3 |
| `struct_hidden_dim` | 64 |
| `d_model` | 128 |
| `transformer_layers` | 2 |
| `num_heads` | 4 |
| `ff_dim` | 256 |
| `dropout` | 0.1 |
| `action_size` | 3 |

### 9.2 文本编码器

文本编码依赖 `CharacterHashTokenizer`：

- 逐字符编码
- `pad_token_id = 0`
- `unk_token_id = 1`
- 其它字符稳定哈希到 `[2, vocab_size)`
- 固定裁剪或补齐到 `max_text_length`

`SharedTextEncoder` 的结构是：

1. `Embedding`
2. `Conv1d(embedding -> text_hidden_dim, kernel_size=1)`
3. 3 个 `DepthwiseSeparableConvBlock`
4. `LayerNorm`
5. masked mean pooling

### 9.3 模型主干

模型把三类输入融合起来：

- 页面结构化特征
- candidate 文本 + 结构化特征
- persona 文本 + 结构化特征

核心结构包括：

- `page_projection`
- `candidate_text_projection`
- `candidate_struct_projection`
- `persona_text_projection`
- `persona_struct_projection`
- 一个带 `page_token` 的 `TransformerEncoder`
- `persona_selector`
- `action_head`
- `confidence_head`
- `utility_head`

### 9.4 输出

`TinyPolicyNet.forward()` 当前输出：

- `persona_logits`
- `action_logits`
- `confidence_scores`
- `utility_scores`
- `page_summary`
- `persona_context`

其中：

- `action_logits` 对应 `KEEP / GENERICIZE / PERSONA_SLOT`
- `confidence_scores` 已用于 runtime 的低置信度 KEEP 回退
- `utility_scores` 已前向输出，但还没有进入正式训练目标

## 10. `TinyPolicyBatch`

`TorchTinyPolicyRuntime` 使用 `training/torch_batch.py` 里的 `TinyPolicyBatchBuilder` 将 `DecisionContext` 打成定长 batch。

当前主要张量字段有：

- `page_features`
- `candidate_features`
- `candidate_mask`
- `candidate_text_ids`
- `candidate_text_mask`
- `candidate_prompt_ids`
- `candidate_prompt_mask`
- `candidate_ocr_ids`
- `candidate_ocr_mask`
- `persona_features`
- `persona_mask`
- `persona_text_ids`
- `persona_text_mask`
- `candidate_ids`
- `persona_ids`

## 11. 训练侧当前已完成的部分

当前训练目录已经不只是骨架，已经具备最小 supervised finetune 闭环：

1. `pack_training_turn()`
2. `plan_to_supervision()`
3. `build_jsonl_dataset()`
4. `build_supervised_jsonl_dataset()`
5. `TinyPolicyBatchBuilder.build_examples()`
6. `run_supervised_finetune()`
7. 训练产物直接被 `TorchTinyPolicyRuntime` 加载

当前 supervised 目标包括：

- `action_head` 交叉熵
- `persona_selector` 交叉熵

## 12. 当前还没有完成的部分

- `run_adversarial_finetune()` 仍然直接抛 `NotImplementedError`
- 没有 RL / PPO / policy gradient 训练循环
- 没有系统化评估脚本
- `export_runtime_bundle()` 目前只写 metadata，不导出真实模型格式
- 没有真正的 bundle runtime / ONNX runtime / TFLite runtime

## 13. 一句话总结

当前 `de_model` 的状态可以概括为：

> 决策上下文、特征工程、启发式 runtime、torch runtime、PyTorch 原型网络、监督训练与 checkpoint 回接都已经打通；但默认仍是 heuristic runtime，真正的对抗训练与移动端 bundle 路径还没有落地。
