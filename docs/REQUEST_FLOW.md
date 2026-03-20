# PrivacyGuard 请求流程

本文档按当前代码说明 `sanitize` 与 `restore` 的真实请求链路。

需要先明确：

- `de_model` 是**策略决策层**
- `de_model` **不是 detector**
- `de_model` **不是 OCR 清洗主逻辑**
- `de_model` **不负责复杂 linking**

当前内部动作术语统一为：

- `KEEP`
- `GENERICIZE`
- `PERSONA_SLOT`

---

## 1. 顶层入口

用户入口通常是：

```python
from privacyguard import PrivacyGuard
```

实际类位于：

- `privacyguard/app/privacy_guard.py`

`PrivacyGuard` 的职责是：

- 接收外部 payload
- 转为边界层 request model / DTO
- 调用 sanitize / restore pipeline
- 返回外部响应字典

它不承担 detector、OCR、runtime、restore 规则的内部细节。

---

## 2. `PrivacyGuard.__init__` 的装配

如果调用方没有显式注入依赖，`PrivacyGuard` 当前会装配：

1. `persona_repo`
2. `mapping_table`
3. `ocr`
4. `renderer`
5. `restoration`
6. `detector`
7. `decision_engine`
8. `SanitizePipeline`
9. `RestorePipeline`

也就是说：

- 顶层 facade 负责装配
- 具体 sanitize / restore 主链交给 pipeline

---

## 3. `sanitize` 请求流

## 3.1 外部 payload

调用入口：

```python
guard.sanitize(payload)
```

当前外部 payload 主要字段是：

- `session_id`
- `turn_id`
- `prompt`
- `image`
- `protection_level`
- `detector_overrides`

## 3.2 边界层转换

当前边界层顺序是：

1. `SanitizeRequestModel.from_payload(payload)`
2. `SanitizePayloadModel.model_validate(payload)`
3. `SanitizeRequestModel.to_dto()`
4. `SanitizePipeline.run(request)`

这里完成的是：

- 外部 payload 校验
- DTO 转换

不是策略推理。

## 3.3 当前 sanitize 主链

`SanitizePipeline.run()` 最终调用 `run_sanitize_pipeline(...)`。  
当前真实链路可以收敛为：

```text
OCR / detector
-> context build
-> features
-> runtime
-> resolver
-> render
-> mapping
```

展开到当前代码，对应顺序是：

1. OCR / prompt parse
2. detector
3. alias / session context preparation
4. local context / quality / persona state preparation
5. `DecisionContextBuilder`
6. `DecisionFeatureExtractor`
7. `DEModelEngine / runtime`
8. `ConstraintResolver`
9. placeholder allocation / replacement planning
10. render
11. mapping store

### 3.3.1 OCR / detector

当前主链先做：

- 如果有截图，`ocr_engine.extract(request.screenshot)`
- 调用 detector 生成 `PIICandidate`

这里 detector 负责：

- 候选发现

而不是 `de_model` 负责。

### 3.3.2 context build

在当前链路里，context build 包括：

- `SessionService.get_or_create_binding(session_id)`
- `DecisionContextBuilder.build(...)`

`DecisionContextBuilder` 当前会把数据收敛为 `DecisionContext`，随后 decision 模块内部派生出核心四块：

- `raw_refs`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

### 3.3.3 features

`DecisionFeatureExtractor` 当前负责把内部派生的策略视图映射为 runtime 可消费的特征：

- `candidate_policy_views -> candidate features`
- `page_policy_state -> page features`
- `persona_policy_states -> persona features`

文本通道仍存在，但定位为辅助输入：

- `candidate_text`
- `prompt_context`
- `ocr_context`

### 3.3.4 runtime

`DEModelEngine.plan(...)` 内部会：

1. `DecisionFeatureExtractor.pack(context)`
2. 调用 heuristic runtime 或 torch runtime
3. 得到统一 runtime 输出协议

当前 runtime 输出会整理为两级视角：

- `protect_decision`
- `rewrite_mode`

但最终执行动作仍统一为：

- `KEEP`
- `GENERICIZE`
- `PERSONA_SLOT`

### 3.3.5 resolver

当前默认引擎路径中，runtime 之后会进入 `ConstraintResolver`。

它当前负责：

- 规范 `KEEP`
- 检查 `PERSONA_SLOT` 的 persona 可用性
- persona 缺失时回退为 `GENERICIZE`
- 为缺失 replacement 的 `GENERICIZE` 补标准 placeholder

也就是说：

- runtime 给出策略倾向
- resolver 收敛为当前可执行动作

### 3.3.6 render

当前 render 包括：

- `rendering_engine.render_text(...)`
- 如果有截图，`rendering_engine.render_image(...)`

render 阶段使用的是已经收敛好的动作计划，而不是再去做 detector 或策略判断。

### 3.3.7 mapping

渲染完成后，当前主链会：

- 写入当前 turn 的 replacement records
- 更新 session binding

这里的关键闭环是：

- `KEEP` 不进入有效 replacement record
- `GENERICIZE` 会进入 mapping
- `PERSONA_SLOT` 会进入 mapping

因此后续 restore 仍然建立在 replacement-record 驱动模型上。

## 3.4 sanitize 对外响应

application 层内部返回的是 `SanitizeResponse`，但顶层 facade 最终对外返回的稳定字段是：

- `status`
- `masked_prompt`
- `masked_image`
- `session_id`
- `turn_id`
- `mapping_count`
- `active_persona_id`

内部字段例如：

- `protect_decision`
- `rewrite_mode`
- `page_policy_state`

不会直接暴露到外部 facade 响应里。

---

## 4. `restore` 请求流

## 4.1 外部 payload

调用入口：

```python
guard.restore(payload)
```

当前外部 payload 主要字段是：

- `session_id`
- `turn_id`
- `agent_text`

## 4.2 边界层转换

当前顺序是：

1. `RestoreRequestModel.from_payload(payload)`
2. `RestorePayloadModel.model_validate(payload)`
3. `RestoreRequestModel.to_dto()`
4. `RestorePipeline.run(request)`

## 4.3 当前 restore 主链

当前 restore 主链非常收敛：

```text
current turn replacement record
-> text restore
```

具体来说：

1. 从 `mapping_store` 读取当前 `session_id + turn_id` 的 replacement records
2. 只保留可恢复记录
3. 调用 `restoration_module.restore(cloud_text, records)`
4. 返回 `RestoreResponse`

### 4.3.1 当前 turn replacement record

restore 当前明确只使用：

- 当前 turn 的 `ReplacementRecord`

不做：

- 全会话 restore
- DSL restore
- 对 de_model 决策做逆向推理

### 4.3.2 动作兼容规则

当前 restore 对动作语义的兼容规则是：

- `KEEP` 不参与 restore
- `GENERICIZE` 可以通过 replacement record 恢复
- `PERSONA_SLOT` 可以通过 replacement record 恢复
- 旧别名 `LABEL` 视作 `GENERICIZE`

因此 restore 的边界很清楚：

- 它不关心内部 runtime 怎么得出策略
- 它只依赖 replacement record

## 4.4 restore 对外响应

顶层 facade 当前对外返回：

- `status`
- `restored_text`
- `session_id`

restore 内部的 `restored_slots` 和 metadata 当前不作为 facade 稳定响应的主要字段暴露。

---

## 5. 当前代码对应关系

### sanitize

- 顶层入口：`privacyguard/app/privacy_guard.py`
- pipeline 封装：`privacyguard/app/pipelines.py`
- application 主链：`privacyguard/application/pipelines/sanitize_pipeline.py`
- 上下文组装：`privacyguard/application/services/decision_context_builder.py`
- 特征提取：`privacyguard/infrastructure/decision/features.py`
- runtime：`privacyguard/infrastructure/decision/de_model_runtime.py`
- 引擎：`privacyguard/infrastructure/decision/de_model_engine.py`
- 默认约束收敛：`privacyguard/domain/policies/constraint_resolver.py`
- placeholder 分配：`privacyguard/application/services/placeholder_allocator.py`

### restore

- 顶层入口：`privacyguard/app/privacy_guard.py`
- pipeline 封装：`privacyguard/app/pipelines.py`
- application 主链：`privacyguard/application/pipelines/restore_pipeline.py`
- mapping store：`privacyguard/domain/interfaces/mapping_store.py` 及其实现
- restoration module：`privacyguard/domain/interfaces/restoration_module.py` 及其实现

---

## 6. 当前实现一句话总结

当前请求链路可以概括为：

- `sanitize`: `OCR/detector -> context build -> features -> runtime -> resolver -> render -> mapping`
- `restore`: `current turn replacement record -> text restore`

其中 `de_model` 只是中间的策略决策层，不负责检测、OCR 清洗主逻辑或复杂 linking。
