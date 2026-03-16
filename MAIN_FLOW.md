# PrivacyGuard 主运行流程

## 1. 对外入口

- **统一 API 门面**: `PrivacyGuard` 类（`privacyguard/app/privacy_guard.py`），通过 `privacyguard/__init__.py` 导出为包级 `PrivacyGuard`。
- **两个对外 API**:
  - **API_1 脱敏**: `sanitize(payload: dict) -> dict`
  - **API_2 还原**: `restore(payload: dict) -> dict`
- **底层编排**: `src/privacyguard/api/facade.py` 中的 `PrivacyGuardFacade` 提供 `sanitize(RestoreRequest)/restore(RestoreRequest)` 的 DTO 版本；app 层通过 schemas 将 dict 转为 RequestModel 再转 DTO 调用 pipeline。

## 2. 主流程概览

### 2.1 初始化（PrivacyGuard 构造）

```
PrivacyGuard(detector_mode, decision_mode, 可选组件覆盖)
    ↓
get_or_create_registry() → 注册默认组件（OCR、PII 检测、决策、渲染、还原、mapping、persona 等）
    ↓
构建: persona_repo, mapping_table, ocr, renderer, restoration, detector, decision_engine
    ↓
实例化 SanitizePipeline、RestorePipeline
```

### 2.2 API_1：脱敏（sanitize）

```
sanitize(payload)
    ↓
SanitizeRequestModel.from_payload(payload)  # session_id, turn_id, prompt, image
    ↓
SanitizePipeline.run(request)
    ↓
run_sanitize_pipeline (application/pipelines/sanitize_pipeline.py):
    │
    ├─ ocr_engine.extract(screenshot) → ocr_blocks（若提供截图）
    ├─ pii_detector.detect(prompt_text, ocr_blocks) → candidates
    ├─ SessionService.get_or_create_binding(session_id)
    ├─ decision_engine.plan(session_id, turn_id, candidates, session_binding) → plan
    ├─ rendering_engine.render_text(prompt_text, plan) → sanitized_prompt_text, applied_records
    ├─ rendering_engine.render_image(screenshot, plan) → sanitized_screenshot（若提供截图）
    ├─ session_service.append_turn_replacements(session_id, turn_id, applied_records)
    └─ 返回 SanitizeResponse(sanitized_prompt_text, sanitized_screenshot, active_persona_id, replacements, metadata)
    ↓
SanitizeResponseModel.from_pipeline_result(...).to_dict()
    ↓
返回: status, masked_prompt, masked_image, session_id, turn_id, mapping_count, active_persona_id
```

### 2.3 API_2：还原（restore）

```
restore(payload)
    ↓
RestoreRequestModel.from_payload(payload)  # session_id, turn_id, agent_text
    ↓
RestorePipeline.run(request)
    ↓
run_restore_pipeline (application/pipelines/restore_pipeline.py):
    │
    ├─ mapping_store.get_replacements(session_id, turn_id) → current_turn_records
    ├─ mapping_store.get_replacements(session_id) → session_records
    ├─ _merge_records(current_turn_records, session_records) → combined_records
    ├─ restoration_module.restore(cloud_text, combined_records) → restored_text, restored_slots
    └─ 返回 RestoreResponse(restored_text, restored_slots, metadata)
    ↓
RestoreResponseModel.from_pipeline_result(...).to_dict()
    ↓
返回: status, restored_text, session_id
```

## 3. 核心模块与数据流

| 层级 | 模块/文件 | 职责 |
|------|-----------|------|
| 对外 API | `app/privacy_guard.py` | 接收 dict 请求，转 RequestModel，调用 pipeline，返回 dict |
| 边界模型 | `app/schemas.py` | SanitizePayloadModel / RestorePayloadModel；RequestModel/ResponseModel 与 DTO 互转 |
| API DTO | `api/dto.py` | SanitizeRequest/Response、RestoreRequest/Response（session_id, turn_id, prompt_text/screenshot, cloud_text, restored_text 等） |
| 编排 | `application/pipelines/sanitize_pipeline.py` | run_sanitize_pipeline：OCR → 检测 → Session 绑定 → 决策 → 文本/图渲染 → 写 mapping |
| 编排 | `application/pipelines/restore_pipeline.py` | run_restore_pipeline：按 session/turn 取 replacements → 合并 → restoration_module.restore |
| 领域接口 | `domain/interfaces/*` | OCREngine, PIIDetector, PersonaRepository, MappingStore, DecisionEngine, RenderingEngine, RestorationModule |
| 基础设施 | `infrastructure/*` | PPOCR、规则/NER 检测器、LabelOnly/LabelPersonaMixed/DE 决策、PromptRenderer、ActionRestorer、InMemory/Json MappingStore 等 |
| 装配 | `bootstrap/factories.py`、`app/factories.py` | 注册默认组件、从 registry 按 mode 构建 detector/decision 等 |

## 4. 请求/响应格式摘要

- **sanitize 入参**: `session_id`, `turn_id`（默认 0）, `prompt`, `image`（可选，可为 None）。
- **sanitize 出参**: `masked_prompt`, `masked_image`（可为 None）, `session_id`, `turn_id`, `mapping_count`, `active_persona_id`, `status`。
- **restore 入参**: `session_id`, `turn_id`, `agent_text`（云端返回的文本）。
- **restore 出参**: `restored_text`, `session_id`, `status`。

## 5. 会话与轮次

- 同一 **session_id** 下多轮对话共享 mapping 与 persona 绑定；**turn_id** 标识当前轮，脱敏时写入当轮 replacements，还原时按 turn 优先、session 回溯合并记录后再还原。

---

## 6. 两个 API 接口精确定位

### API_1：脱敏接口

- **位置**: `privacyguard/app/privacy_guard.py` 中 `PrivacyGuard.sanitize(self, payload: dict[str, Any]) -> dict[str, Any]`（第 82–85 行）。
- **等价门面**: `src/privacyguard/api/facade.py` 中 `PrivacyGuardFacade.sanitize(self, request: SanitizeRequest) -> SanitizeResponse`（第 55–67 行），入参为 DTO。
- **入参**: `payload = {"session_id": str, "turn_id": int (≥0), "prompt": str, "image": Any | None}`。
- **出参**: `{"status": "ok", "masked_prompt": str, "masked_image": Any | None, "session_id": str, "turn_id": int, "mapping_count": int, "active_persona_id": str | None}`。

### API_2：还原接口

- **位置**: `privacyguard/app/privacy_guard.py` 中 `PrivacyGuard.restore(self, payload: dict[str, Any]) -> dict[str, Any]`（第 87–90 行）。
- **等价门面**: `src/privacyguard/api/facade.py` 中 `PrivacyGuardFacade.restore(self, request: RestoreRequest) -> RestoreResponse`（第 69–75 行），入参为 DTO。
- **入参**: `payload = {"session_id": str, "turn_id": int (≥0), "agent_text": str}`（云端/模型返回的文本）。
- **出参**: `{"status": "ok", "restored_text": str, "session_id": str}`。
