# 未使用符号检查报告

基于全仓库搜索，以下函数、类、变量在**业务/主流程中未被使用**（仅定义或仅被导出、测试使用的不计为「使用」）。

---

## 一、未使用的函数

| 符号 | 位置 | 说明 |
|------|------|------|
| `load_config` | `privacyguard/bootstrap/factories.py:126` | 仅被 `bootstrap/__init__.py` 导出及 `tests/unit/test_imports_and_bootstrap.py` 使用，主流程未从 YAML 装配配置。 |
| `load_ppocr_backend` | `privacyguard/infrastructure/ocr/ppocr_adapter.py:80` | 仅定义，无任何调用。`PPOCREngineAdapter` 在无 backend 时直接用 `MockOCRBackend()`。 |
| `normalize_image_path` | `privacyguard/infrastructure/ocr/ppocr_adapter.py:86` | 仅定义，无任何调用。 |

---

## 二、未使用的类

| 符号 | 位置 | 说明 |
|------|------|------|
| `PersonaSlotValue` | `privacyguard/domain/models/persona.py:8` | 仅在本模块与 `domain/models/__init__.py` 中导出。实际 persona 槽位使用 `PersonaProfile.slots: dict[PIIAttributeType, str]`，未使用该模型。 |
| `TurnMappingSnapshot` | `privacyguard/domain/models/mapping.py:40` | 仅在本模块与 `domain/models/__init__.py` 中导出，无其他引用。 |
| `ReplacementService` | `privacyguard/application/services/replacement_service.py:9` | 仅被 `application/services/__init__.py` 导出，无任何模块实例化或调用。 |

---

## 三、未使用的变量 / 类型

| 符号 | 位置 | 说明 |
|------|------|------|
| `T` (TypeVar) | `privacyguard/bootstrap/registry.py:14` | 定义后未在 `registry.py` 内使用。 |

---

## 四、仅测试使用的符号（主流程未用）

| 符号 | 位置 | 说明 |
|------|------|------|
| `load_config` | 见上 | 主应用未通过 YAML 装配，仅测试 `test_default_config_can_be_loaded` 使用。 |

---

## 五、可能已过时的测试

以下测试仍在 payload 中传入 `detector_mode` / `decision_mode`，但 sanitize 已不再支持请求级模式切换，行为与测试名/意图可能不一致：

| 测试 | 文件 | 说明 |
|------|------|------|
| `test_mode_switching_can_use_request_modes_dynamically` | `tests/integration/test_mode_switching.py:16` | 断言「可按请求动态切换模式」，当前实现已固定为实例模式，请求中的 mode 会被忽略。 |
| `test_privacy_guard_sanitize_supports_runtime_mode_switch` | `tests/integration/test_privacy_guard_api.py:29` | 同上，传入了 `detector_mode`/`decision_mode`，实际不会生效。 |

建议：若不再支持请求级模式，可删除或重写上述测试（例如改为断言「传入多余字段仍返回 ok」或只测实例级模式）。

---

## 六、已确认被使用的易混符号

- **ScreenshotRenderer**：被 `PromptRenderer` 内部使用。
- **ComponentNotRegisteredError**：被 `bootstrap/factories._build_component` 抛出。
- **load_ppocr_backend** 仅在 `ppocr_adapter` 内定义，未被调用；**MockOCRBackend**、**OCRBackendProtocol** 在模块内使用。
- **DETECTOR_MODE_ALIASES / DECISION_MODE_ALIASES**：被 `normalize_detector_mode` / `normalize_decision_mode` 使用。
- **Placeholder*** 类：通过 `register_default_components` 注册，按模式名「placeholder」时使用。

---

*生成方式：全仓库对上述符号做定义处与引用处 grep，排除仅 __init__ 导出、仅测试引用后汇总。*
