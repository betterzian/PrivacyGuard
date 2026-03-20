# PrivacyGuard 请求全流程说明

本文档按当前代码梳理一次完整的 `sanitize -> restore` 调用链，目标是帮助你从顶层 API 一路跳到实际实现。

## 1. 顶层入口

用户入口通常是：

```python
from privacyguard import PrivacyGuard
```

包导出位于：

- `privacyguard/__init__.py`

实际类位于：

- `privacyguard/app/privacy_guard.py`

另一个顶层入口是：

```python
from privacyguard import PrivacyRepository
```

它负责写入本地 persona 仓库，位于：

- `privacyguard/app/privacy_repository.py`

## 2. `PrivacyGuard.__init__` 的真实装配顺序

### 2.1 注册表与默认模式

`PrivacyGuard.__init__()` 先做三件事：

1. `get_or_create_registry()`
2. `normalize_detector_mode()`
3. `normalize_decision_mode()`

当前默认值来自 `privacyguard/bootstrap/mode_config.py`：

- `DEFAULT_DETECTOR_MODE = "rule_based"`
- `DEFAULT_DECISION_MODE = "de_model"`
- `DEFAULT_FILL_MODE = "mix"`

### 2.2 注册到默认 registry 的组件

默认 registry 会注册这些实现：

| 类别 | 注册键 |
| --- | --- |
| OCR | `placeholder`、`ppocr_v5` |
| detector | `placeholder`、`rule_based` |
| decision | `placeholder`、`label_only`、`label_persona_mixed`、`de_model` |
| mapping store | `placeholder`、`in_memory`、`json` |
| persona repository | `placeholder`、`in_memory`、`json` |
| rendering | `placeholder`、`prompt_renderer` |
| restoration | `placeholder`、`action_restorer` |
| screenshot fill | `ring`、`gradient`、`cv`、`mix` |

### 2.3 依赖构建顺序

如果调用方没有显式注入依赖，`PrivacyGuard` 会依次构建：

1. `persona_repo`
   默认 `JsonPersonaRepository`
2. `mapping_table`
   默认 `InMemoryMappingStore`
3. `ocr`
   默认 `PPOCREngineAdapter`
4. `renderer`
   默认 `PromptRenderer`
   如果显式传了 `screenshot_fill_mode`，会先构建对应 `ScreenshotFillStrategy`
5. `restoration`
   默认 `ActionRestorer`
6. `detector`
   通过 `build_detector(...)`
7. `decision_engine`
   通过 `build_decision(...)`
8. `SanitizePipeline`
9. `RestorePipeline`

补充两点：

- `PPOCREngineAdapter` 会尝试自动加载 PaddleOCR；如果当前环境没有 `paddleocr`，构造阶段不会报错，而是回退到 `MissingDependencyOCRBackend`
- 真正处理截图时，缺失 OCR 依赖才会显式报错

## 3. `sanitize` 请求流

### 3.1 边界层

调用入口：

```python
guard.sanitize(payload)
```

边界层顺序如下：

1. `SanitizeRequestModel.from_payload(payload)`
2. `SanitizePayloadModel.model_validate(payload)`
3. `SanitizeRequestModel.to_dto()`
4. `SanitizePipeline.run(request)`

当前 payload 字段为：

- `session_id`
- `turn_id`
- `prompt`
- `image`
- `protection_level`
- `detector_overrides`

其中 `detector_overrides` 只接受：

- `name`
- `location_clue`
- `address`
- `organization`
- `other`

### 3.2 application 层主流程

`SanitizePipeline.run()` 最终调用：

```python
run_sanitize_pipeline(
    request=request.to_dto(),
    ocr_engine=...,
    pii_detector=...,
    persona_repository=...,
    mapping_store=...,
    decision_engine=...,
    rendering_engine=...,
)
```

`run_sanitize_pipeline()` 当前的实际顺序是：

1. 创建 `DecisionContextBuilder`
2. 若 `request.screenshot is not None`，执行 `ocr_engine.extract(request.screenshot)`；否则 `ocr_blocks = []`
3. 调用 detector
4. 创建 `SessionService`
5. `get_or_create_binding(session_id)`
6. `DecisionContextBuilder.build(...)`
7. `decision_engine.plan(decision_context)`
8. `SessionPlaceholderAllocator.assign(plan)`
9. `rendering_engine.render_text(request.prompt_text, plan)`
10. 若有截图，执行 `rendering_engine.render_image(request.screenshot, plan, ocr_blocks=ocr_blocks)`
11. `session_service.append_turn_replacements(...)`
12. 如果 `plan.active_persona_id` 存在，则 `session_service.bind_active_persona(...)`
13. 返回 `SanitizeResponse`

### 3.3 detector 调用方式

`run_sanitize_pipeline()` 不会假定 detector 一定支持全部上下文字段，而是用 `inspect.signature()` 做兼容调用。

固定会传：

- `prompt_text`
- `ocr_blocks`

如果 detector 的签名里包含这些参数，则还会补传：

- `session_id`
- `turn_id`
- `protection_level`
- `detector_overrides`

因此：

- 老 detector 只实现 `detect(prompt_text, ocr_blocks)` 也能工作
- `RuleBasedPIIDetector` 这类上下文感知实现可以拿到完整请求信息

### 3.4 `DecisionContextBuilder` 构造了什么

当前 `DecisionContextBuilder` 会把这些信息统一装进 `DecisionContext`：

- `session_id`
- `turn_id`
- `prompt_text`
- `protection_level`
- `detector_overrides`
- `ocr_blocks`
- `candidates`
- `session_binding`
- `history_records`
  当前 session 的全部历史替换记录
- `persona_profiles`
- `page_features`
- `candidate_features`
- `persona_features`

这一步是 `de_model`、`label_only`、`label_persona_mixed` 共享的决策边界。

### 3.5 占位符分配

`decision_engine.plan()` 返回后，`SessionPlaceholderAllocator` 会继续处理 `DecisionPlan`：

- 只处理 `GENERICIZE`
- 按 `(attr_type, canonical_source_text/source_text)` 复用 session 内已有占位符
- 否则生成新的 `@姓名1`、`@地址2` 这类标签

这一步发生在渲染之前，所以最终写入 mapping store 的已经是稳定占位符。

### 3.6 渲染

`PromptRenderer.render_text()`：

- 先把 `DecisionAction` 转成 `ReplacementRecord`
- 对 prompt 来源记录优先按 `span_start / span_end` 重建文本
- 对缺 span 的旧记录再做保守替换

`PromptRenderer.render_image()`：

- 实际委托给 `ScreenshotRenderer.render()`
- 依赖 `DecisionPlan + ocr_blocks`
- 可处理同 block 局部替换、跨 block 替换、地址语义切分和不同填充策略

### 3.7 写入 mapping 和 session binding

渲染完成后，`SessionService` 会：

1. `save_replacements(session_id, turn_id, records)`
2. 更新 `SessionBinding.last_turn_id`
3. 更新 `SessionBinding.updated_at`
4. 如果本轮选中了 persona，则更新 `active_persona_id`

### 3.8 对外响应

application 层返回的 `SanitizeResponse` 包含：

- `sanitized_prompt_text`
- `sanitized_screenshot`
- `active_persona_id`
- `replacements`
- `metadata`

但顶层 `PrivacyGuard.sanitize()` 经过 `SanitizeResponseModel` 转换后，对外只返回：

- `status`
- `masked_prompt`
- `masked_image`
- `session_id`
- `turn_id`
- `mapping_count`
- `active_persona_id`

## 4. `restore` 请求流

### 4.1 边界层

调用入口：

```python
guard.restore(payload)
```

顺序如下：

1. `RestoreRequestModel.from_payload(payload)`
2. `RestorePayloadModel.model_validate(payload)`
3. `RestoreRequestModel.to_dto()`
4. `RestorePipeline.run(request)`

payload 字段只有：

- `session_id`
- `turn_id`
- `agent_text`

### 4.2 application 层主流程

`RestorePipeline.run()` 最终调用：

```python
run_restore_pipeline(
    request=request.to_dto(),
    mapping_store=...,
    restoration_module=...,
)
```

`run_restore_pipeline()` 当前只做四步：

1. `mapping_store.get_replacements(session_id, turn_id)`
2. `_merge_records(current_turn_records)`
3. `restoration_module.restore(request.cloud_text, combined_records)`
4. 返回 `RestoreResponse`

### 4.3 `_merge_records()` 的语义

当前 `_merge_records()` 只对当前 turn 记录去重：

- key 是 `replacement_text`
- 长 placeholder 优先
- 不会把历史 turn 记录合并进来

这也是当前 restore 只恢复当前轮文本的原因。

### 4.4 `ActionRestorer.restore()` 的语义

`ActionRestorer` 会：

1. 按 `(turn_id, len(replacement_text))` 倒序处理记录
2. 对每个 placeholder 只恢复一次
3. 使用 `canonical_source_text` 优先，否则回退 `source_text`
4. 产出 `restored_text` 和 `restored_slots`

但顶层 `PrivacyGuard.restore()` 最终只把这三个字段暴露给调用方：

- `status`
- `restored_text`
- `session_id`

## 5. 模块对照

| 层次 | 路径 | 当前职责 |
| --- | --- | --- |
| 顶层 API | `privacyguard/app/privacy_guard.py` | `PrivacyGuard` 装配与对外入口 |
| 顶层仓库写入 | `privacyguard/app/privacy_repository.py` | `PrivacyRepository.write()` |
| Schema/DTO | `privacyguard/app/schemas.py`、`privacyguard/api/dto.py` | 请求响应校验与模型转换 |
| Pipeline 包装 | `privacyguard/app/pipelines.py` | app 层与 application 层之间的胶水 |
| 应用编排 | `privacyguard/application/pipelines/` | sanitize / restore 固定步骤 |
| 应用服务 | `privacyguard/application/services/` | session、placeholder、decision context 等 |
| 领域层 | `privacyguard/domain/` | 枚举、接口、模型、约束解析 |
| 基础设施 | `privacyguard/infrastructure/` | detector / decision / ocr / rendering / mapping / restoration / persona |
| 启动配置 | `privacyguard/bootstrap/` | registry、工厂、模式归一化 |

## 6. 简化数据流

```text
sanitize payload
  -> SanitizeRequestModel
  -> SanitizeRequest DTO
  -> OCR (optional)
  -> detector.detect(...)
  -> SessionService.get_or_create_binding(...)
  -> DecisionContextBuilder.build(...)
  -> decision_engine.plan(context)
  -> SessionPlaceholderAllocator.assign(...)
  -> PromptRenderer.render_text(...)
  -> ScreenshotRenderer.render(...) (optional)
  -> mapping_store.save_replacements(...)
  -> SanitizeResponse DTO
  -> SanitizeResponseModel
  -> dict

restore payload
  -> RestoreRequestModel
  -> RestoreRequest DTO
  -> mapping_store.get_replacements(session_id, turn_id)
  -> _merge_records(current_turn_records)
  -> ActionRestorer.restore(...)
  -> RestoreResponse DTO
  -> RestoreResponseModel
  -> dict
```
