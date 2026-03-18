# PrivacyGuard 请求全流程说明

本文档按「调试视角」梳理：**从用户发起一次请求到拿到响应的完整调用链**，包括类初始化顺序、函数跳转逻辑。示例场景以 `examples/minimal_demo.py` 中的 **sanitize → restore** 为例。

---

## 一、入口与顶层 API

### 1.1 用户入口

```
examples/minimal_demo.py :: main()
```

- 用户代码：`from privacyguard import PrivacyGuard`
- 包入口：`privacyguard/__init__.py` 导出 `PrivacyGuard`
- 实际类：`privacyguard/app/privacy_guard.py` 中的 `PrivacyGuard`

### 1.2 创建 PrivacyGuard 实例

```python
guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
```

调用链从 **`PrivacyGuard.__init__`** 开始，见下一节。

---

## 二、PrivacyGuard 初始化全流程（按执行顺序）

以下为 `PrivacyGuard.__init__(detector_mode="rule_based", decision_mode="label_only")` 时的**严格执行顺序**。

### 步骤 1：获取或创建组件注册表

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1.1 | `get_or_create_registry(registry=None)` | `app/factories.py` | 入参为 None，走“创建并注册默认组件”分支 |
| 1.2 | `create_default_registry()` | `bootstrap/registry.py` | 创建空的 `ComponentRegistry()`（各 dict 为空） |
| 1.3 | `register_default_components(work_registry)` | `bootstrap/factories.py` | 因 `work_registry.ocr_providers` 为空，执行注册 |
| 1.4 | 各类 `registry.register_*()` | `bootstrap/registry.py` + `bootstrap/factories.py` | 注册 OCR、detector、decision、mapping、persona、rendering、restoration 等实现类 |
| 1.5 | 返回 | `app/factories.py` | `self.registry` 被赋值为已注册的 `ComponentRegistry` |

**注册表示例（节选）：**

- `detector_modes`: `rule_based` → `RuleBasedPIIDetector`, ...
- `decision_modes`: `label_only` → `LabelOnlyDecisionEngine`, `label_persona_mixed` → `LabelPersonaMixedDecisionEngine`, ...
- `mapping_store_types`: `in_memory` → `InMemoryMappingStore`, ...
- `persona_repository_types`: `json` → `JsonPersonaRepository`, ...
- `ocr_providers`: `ppocr_v5` → `PPOCREngineAdapter`, ...
- `rendering_modes`: `prompt_renderer` → `PromptRenderer`, ...
- `restoration_modes`: `action_restorer` → `ActionRestorer`, ...

### 步骤 2：归一化模式名

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 2.1 | `normalize_detector_mode("rule_based")` | `bootstrap/mode_config.py` | 校验并返回 `"rule_based"` |
| 2.2 | `normalize_decision_mode("label_only")` | `bootstrap/mode_config.py` | 校验并返回 `"label_only"` |

### 步骤 3：构建无注入依赖的组件（按代码顺序）

以下均通过 `bootstrap/factories.py` 的 **`_build_component(mapping, key, category, ...)`** 从 registry 取实现类并实例化。

| 顺序 | 组件 | 调用 | 实现类（本例） | 说明 |
|------|------|------|----------------|------|
| 3.1 | persona_repo | `_build_component(registry.persona_repository_types, "json", ...)` | `JsonPersonaRepository()` | 默认 path 为 `data/personas.sample.json`，内部 `_load_personas()` |
| 3.2 | mapping_table | `_build_component(registry.mapping_store_types, "in_memory", ...)` | `InMemoryMappingStore()` | 空 `_records` / `_bindings` |
| 3.3 | ocr | `_build_component(registry.ocr_providers, "ppocr_v5", ...)` | `PPOCREngineAdapter()` | 内部通过 `from paddleocr import PaddleOCR` 初始化，并调用 `predict(input=...)` |
| 3.4 | renderer | `_build_component(registry.rendering_modes, "prompt_renderer", ...)` | `PromptRenderer()` | 内部可选 `ScreenshotRenderer()` |
| 3.5 | restoration | `_build_component(registry.restoration_modes, "action_restorer", ...)` | `ActionRestorer()` | 无状态 |

### 步骤 4：构建检测器（依赖 registry）

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 4.1 | `build_detector("rule_based", self.registry)` | `app/factories.py` | 再次 `normalize_detector_mode` 后调用 `_build_component(registry.detector_modes, "rule_based", "detector mode")` |
| 4.2 | `RuleBasedPIIDetector.__init__(...)` | `infrastructure/pii/rule_based_detector.py` | 解析词典路径、`_load_dictionary()`、`_build_patterns()`、创建 `CandidateResolverService()` |

### 步骤 5：构建决策引擎（注入 persona_repo、mapping_table）

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 5.1 | `build_decision("label_only", self.registry, self.persona_repo, self.mapping_table)` | `app/factories.py` | `_build_component(..., injected_dependencies={"persona_repository": persona_repo, "mapping_store": mapping_table})` |
| 5.2 | `LabelOnlyDecisionEngine.__init__(confidence_threshold=0.0, persona_repository=...)` | `infrastructure/decision/label_only_engine.py` | 创建 `ConstraintResolver(persona_repository)` |

### 步骤 6：构建两条流水线

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 6.1 | `SanitizePipeline(ocr=..., detector=..., persona_repo=..., mapping_table=..., decision_engine=..., renderer=...)` | `app/privacy_guard.py` → `app/pipelines.py` | 仅保存引用，无额外初始化逻辑 |
| 6.2 | `RestorePipeline(mapping_table=..., restoration=...)` | `app/privacy_guard.py` → `app/pipelines.py` | 仅保存引用 |

**初始化顺序小结（单次构造）：**

1. `ComponentRegistry` 空实例  
2. `register_default_components` 填充各类实现  
3. `normalize_detector_mode` / `normalize_decision_mode`  
4. `JsonPersonaRepository` → `InMemoryMappingStore` → `PPOCREngineAdapter` → `PromptRenderer` → `ActionRestorer`  
5. `RuleBasedPIIDetector`（内部 `CandidateResolverService`）  
6. `LabelOnlyDecisionEngine`（内部 `ConstraintResolver`）  
7. `SanitizePipeline`、`RestorePipeline`  

补充说明：
- `PPOCREngineAdapter` 兼容 `PIL.Image.Image`、`numpy.ndarray`、本地文件路径以及 `http(s)` 图片 URL。
- 官方 PaddleOCR 的 `predict` 返回值会被适配成项目内部的 `OCRTextBlock`，同时保留底层 `predict` 入口，便于后续直接使用 `res.print()`、`res.save_to_json()` 等官方能力。

---

## 三、Sanitize 请求全流程（脱敏）

用户调用：`guard.sanitize({ "session_id": "demo-session", "turn_id": 1, "prompt": "我叫张三，电话是13800138000。", "image": None, ... })`

### 3.1 边界层：Payload → 内部请求模型

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `PrivacyGuard.sanitize(payload)` | `app/privacy_guard.py` | 入口 |
| 2 | `SanitizeRequestModel.from_payload(payload)` | `app/schemas.py` | 使用 Pydantic 边界模型校验 |
| 3 | `SanitizePayloadModel.model_validate(payload)` | `app/schemas.py` | 校验 session_id, turn_id, prompt, image 等 |
| 4 | 构造 `SanitizeRequestModel(session_id=..., turn_id=..., prompt=..., image=...)` | `app/schemas.py` | 内部请求模型 |

### 3.2 执行脱敏流水线

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 5 | `self.sanitize_pipeline.run(request)` | `app/privacy_guard.py` → `app/pipelines.py` | 传入 `SanitizeRequestModel` |
| 6 | `request.to_dto()` | `app/schemas.py` | 转为 `SanitizeRequest`（session_id, turn_id, prompt_text, screenshot） |
| 7 | `run_sanitize_pipeline(..., request=request_dto, ocr_engine=..., pii_detector=..., ...)` | `app/pipelines.py` → `application/pipelines/sanitize_pipeline.py` | 进入 application 层编排 |

### 3.3 Application 层：run_sanitize_pipeline 内部步骤（按代码顺序）

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 8 | `ocr_engine.extract(request.screenshot)` | `application/pipelines/sanitize_pipeline.py` | 本例 `screenshot is None`，得到 `ocr_blocks = []` |
| 9 | `pii_detector.detect(prompt_text=request.prompt_text, ocr_blocks=ocr_blocks)` | 同上 | 见 **3.4 节** |
| 10 | `SessionService(mapping_store=..., persona_repository=...)` | `application/services/session_service.py` | 新建会话服务（仅保存引用） |
| 11 | `session_service.get_or_create_binding(request.session_id)` | 同上 | 见 **3.5 节** |
| 12 | `decision_engine.plan(session_id=..., turn_id=..., candidates=..., session_binding=...)` | `application/pipelines/sanitize_pipeline.py` | 见 **3.6 节** |
| 13 | `rendering_engine.render_text(request.prompt_text, plan)` | 同上 | 见 **3.7 节** |
| 14 | `rendering_engine.render_image(request.screenshot, plan)` | 同上 | 本例 screenshot 为 None，不执行 |
| 15 | `session_service.append_turn_replacements(session_id, turn_id, applied_records)` | 同上 | 写入 mapping_store，更新 binding |
| 16 | 若 `plan.active_persona_id` 存在则 `session_service.bind_active_persona(...)` | 同上 | label_only 本例通常为 None |
| 17 | 构造 `SanitizeResponse(sanitized_prompt_text=..., sanitized_screenshot=..., active_persona_id=..., replacements=..., metadata=...)` | `application/pipelines/sanitize_pipeline.py` | 返回 DTO |

### 3.4 PII 检测：RuleBasedPIIDetector.detect

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| - | `detect(prompt_text="我叫张三，电话是13800138000。", ocr_blocks=[])` | `infrastructure/pii/rule_based_detector.py` | 只处理 prompt，OCR 为空 |
| 1 | `_scan_text(prompt_text, PIISourceType.PROMPT, bbox=None)` | 同上 | 对整段 prompt 做字典+正则扫描 |
| 2 | `_collect_dictionary_hits(...)` | 同上 | 若词典有「张三」等，会产出 NAME 候选 |
| 3 | `_collect_regex_hits(...)` | 同上 | 手机号正则命中 `13800138000` → PHONE 候选 |
| 4 | `_upsert_candidate(...)` | 同上 | 构建 `PIICandidate`（entity_id 由 `CandidateResolverService.build_candidate_id` 生成） |
| 5 | `self.resolver.resolve_candidates(candidates)` | 同上 | `CandidateResolverService.resolve_candidates` 去重、合并置信度 |
| 6 | 返回 | 同上 | `list[PIICandidate]` 供决策使用 |

### 3.5 会话绑定：SessionService.get_or_create_binding

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `mapping_store.get_session_binding(session_id)` | `application/services/session_service.py` | `InMemoryMappingStore.get_session_binding` 查 `_bindings` |
| 2 | 若为 None：`SessionBinding(session_id=..., created_at=now, updated_at=now, last_turn_id=None)` | `domain/models/mapping.py` | 新建绑定 |
| 3 | `mapping_store.set_session_binding(created)` | `infrastructure/mapping/in_memory_mapping_store.py` | 写入 `_bindings` |
| 4 | 返回 binding | `application/services/session_service.py` | 供 decision_engine.plan 使用 |

### 3.6 决策计划：LabelOnlyDecisionEngine.plan

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `plan(session_id, turn_id, candidates, session_binding)` | `infrastructure/decision/label_only_engine.py` | 遍历 candidates |
| 2 | 对每个 candidate：若 `confidence < confidence_threshold` 则生成 `ActionType.KEEP`；否则 `ActionType.GENERICIZE`，`replacement_text = _label_for_attr(attr_type)`（如 `<NAME>`, `<PHONE>`） | 同上 | 生成 `DecisionAction` 列表 |
| 3 | `self.constraint_resolver.resolve(actions, candidates, session_binding)` | `domain/policies/constraint_resolver.py` | 校验、降级、补全 reason |
| 4 | 构造 `DecisionPlan(session_id, turn_id, active_persona_id=session_binding.active_persona_id, actions=resolved, summary=..., metadata={"mode": "label_only"})` | `infrastructure/decision/label_only_engine.py` | 返回计划 |

### 3.7 文本渲染与记录：PromptRenderer.render_text

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `render_text(prompt_text, plan)` | `infrastructure/rendering/prompt_renderer.py` | 应用决策到文本 |
| 2 | `_build_records_from_plan(plan)` | 同上 | 将 `DecisionAction`（非 KEEP）转为 `ReplacementRecord` 列表 |
| 3 | 按 `source_text` 长度倒序排序，对每条 record 用 `re.sub(_build_boundary_pattern(record.source_text), record.replacement_text, sanitized)` | 同上 | 得到脱敏后的 prompt 文本 |
| 4 | 返回 `(sanitized, applied_records)` | 同上 | applied_records 用于写 mapping_store 与响应 |

### 3.8 响应回传至调用方

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 18 | `SanitizeResponseModel.from_pipeline_result(request, response)` | `app/pipelines.py` → `app/schemas.py` | 将 DTO 转为边界响应模型 |
| 19 | `SanitizeResponseModel.to_dict()` | `app/privacy_guard.py` → `app/schemas.py` | `asdict(self)` 得到字典 |
| 20 | 返回 `dict` 给用户 | `app/privacy_guard.py` | 包含 status, masked_prompt, masked_image, session_id, turn_id, mapping_count, active_persona_id |

---

## 四、Restore 请求全流程（还原）

用户调用：`guard.restore({ "session_id": "demo-session", "turn_id": 1, "agent_text": sanitize_response["masked_prompt"] })`

### 4.1 边界层：Payload → 内部请求模型

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `PrivacyGuard.restore(payload)` | `app/privacy_guard.py` | 入口 |
| 2 | `RestoreRequestModel.from_payload(payload)` | `app/schemas.py` | `RestorePayloadModel.model_validate(payload)` 后构造 |
| 3 | 得到 `RestoreRequestModel(session_id, turn_id, agent_text)` | `app/schemas.py` | 内部请求模型 |

### 4.2 执行还原流水线

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 4 | `self.restore_pipeline.run(request)` | `app/privacy_guard.py` → `app/pipelines.py` | 传入 `RestoreRequestModel` |
| 5 | `request.to_dto()` | `app/schemas.py` | 转为 `RestoreRequest`（session_id, turn_id, cloud_text） |
| 6 | `run_restore_pipeline(request=request_dto, mapping_store=..., restoration_module=...)` | `app/pipelines.py` → `application/pipelines/restore_pipeline.py` | 进入 application 层 |

### 4.3 Application 层：run_restore_pipeline 内部步骤

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 7 | `mapping_store.get_replacements(session_id, turn_id)` | `application/pipelines/restore_pipeline.py` | 只读取当前轮替换记录（本例即 sanitize 时写入的） |
| 8 | `_merge_records(current_turn_records)` | 同上 | 对当前轮记录按 `replacement_text` 去重 |
| 9 | `restoration_module.restore(request.cloud_text, combined_records)` | 同上 | 见 **4.4 节** |
| 10 | 构造 `RestoreResponse(restored_text=..., restored_slots=..., metadata=...)` | 同上 | 返回 DTO |

### 4.4 还原执行：ActionRestorer.restore

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 1 | `restore(cloud_text, records)` | `infrastructure/restoration/action_restorer.py` | 按 (turn_id, len(replacement_text)) 倒序排序 |
| 2 | 对每条 record：若 `replacement_text` 在 `restored_text` 中，则替换一次对应占位符，并追加 `RestoredSlot` | 同上 | 将当前轮脱敏占位符还原为原文 |
| 3 | 返回 `(restored_text, restored_slots)` | 同上 | 供 RestoreResponse 使用 |

### 4.5 响应回传至调用方

| 顺序 | 调用 | 位置 | 说明 |
|------|------|------|------|
| 12 | `RestoreResponseModel.from_pipeline_result(request, response)` | `app/pipelines.py` → `app/schemas.py` | DTO → 边界响应模型 |
| 13 | `RestoreResponseModel.to_dict()` | `app/privacy_guard.py` → `app/schemas.py` | `asdict(self)` |
| 14 | 返回 `dict` 给用户 | `app/privacy_guard.py` | 包含 status, restored_text, session_id |

---

## 五、模块与层次对照（便于跳转）

| 层次 | 目录/模块 | 职责 |
|------|-----------|------|
| 入口 | `privacyguard`、`app/privacy_guard.py` | 对外 API：`PrivacyGuard.sanitize` / `restore` |
| 边界/适配 | `app/schemas.py`、`api/dto.py` | Payload ↔ 内部 Request/Response、DTO |
| 编排 | `app/pipelines.py`（SanitizePipeline / RestorePipeline） | 调用 application 层并做模型转换 |
| 应用流程 | `application/pipelines/sanitize_pipeline.py`、`restore_pipeline.py` | 固定步骤编排（OCR→检测→会话→决策→渲染→落库 等） |
| 应用服务 | `application/services/session_service.py`、`resolver_service.py`、`replacement_service.py` | 会话、候选解析、替换记录拼装 |
| 领域 | `domain/models/*`、`domain/policies/constraint_resolver.py`、`domain/interfaces/*` | 实体、决策计划、约束解析、接口定义 |
| 基础设施 | `infrastructure/pii/*`、`decision/*`、`mapping/*`、`rendering/*`、`restoration/*`、`persona/*`、`ocr/*` | 检测器、决策引擎、存储、渲染、还原、Persona 等实现 |
| 启动/配置 | `bootstrap/registry.py`、`bootstrap/factories.py`、`bootstrap/mode_config.py`、`app/factories.py` | 注册表、默认组件注册、模式归一化、组件构建 |

---

## 六、Sanitize 与 Restore 数据流简图

```
Sanitize:
  payload (dict)
    → SanitizeRequestModel.from_payload
    → SanitizePipeline.run(SanitizeRequestModel)
    → request.to_dto() → SanitizeRequest
    → run_sanitize_pipeline(SanitizeRequest, ocr, detector, ...)
        → ocr.extract(screenshot)           → []
        → detector.detect(prompt, [])       → [PIICandidate, ...]
        → SessionService.get_or_create_binding(session_id)
        → decision_engine.plan(..., candidates, session_binding) → DecisionPlan
        → rendering_engine.render_text(prompt, plan) → (masked_prompt, applied_records)
        → session_service.append_turn_replacements(...)
        → SanitizeResponse(...)
    → SanitizeResponseModel.from_pipeline_result(...)
    → .to_dict() → dict 返回

Restore:
  payload (dict)
    → RestoreRequestModel.from_payload
    → RestorePipeline.run(RestoreRequestModel)
    → request.to_dto() → RestoreRequest
    → run_restore_pipeline(RestoreRequest, mapping_store, restoration)
        → mapping_store.get_replacements(session_id, turn_id)
        → mapping_store.get_replacements(session_id)
        → _merge_records(...)
        → restoration_module.restore(cloud_text, records) → (restored_text, restored_slots)
        → RestoreResponse(...)
    → RestoreResponseModel.from_pipeline_result(...)
    → .to_dict() → dict 返回
```

以上即从「一次请求进入」到「返回字典」的完整顺序与跳转关系，可按本文档在 IDE 中沿调用链逐步调试。
