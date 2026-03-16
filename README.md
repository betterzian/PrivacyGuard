# PrivacyGuard

## 1. 项目简介

PrivacyGuard 是一个面向「上传前脱敏（API_1）+ 云端返回后还原（API_2）」的隐私保护框架。  
当前版本重点是提供可运行、可扩展、可替换的工程骨架与最小闭环能力。

## 2. 核心能力

- 统一门面：`PrivacyGuardFacade.sanitize()` 与 `PrivacyGuardFacade.restore()`
- 配置装配：通过 `bootstrap/factories.py` + `registry.py` 按模式切换实现
- 检测链路：支持 `rule_based` 与 `rule_ner_based`（GLiNER 不可用时自动降级）
- 决策链路：支持 `label_only`、`label_persona_mixed`、`de_model`（规则占位版）
- 渲染闭环：可将决策应用到 prompt 与截图，并写入映射
- 还原闭环：可基于 turn/session 映射恢复云端返回文本

## 3. 当前支持模式

### PII Detector
- `rule_based`
- `rule_ner_based`

### Decision Engine
- `label_only`
- `label_persona_mixed`
- `de_model`（`de_model_engine` 同义别名）

### Mapping Store
- `in_memory`
- `json`

### Persona Repository
- `json`

## 4. 目录结构

```text
PrivacyGuard/
├─ configs/
│  ├─ default.yaml
│  ├─ detector.rule_based.yaml
│  ├─ detector.rule_ner_based.yaml
│  └─ decision.label_only.yaml
├─ data/
│  ├─ personas.sample.json
│  └─ pii_dictionary.sample.json
├─ examples/
│  └─ minimal_demo.py
├─ src/privacyguard/
│  ├─ api/
│  ├─ application/
│  │  ├─ pipelines/
│  │  └─ services/
│  ├─ bootstrap/
│  ├─ domain/
│  │  ├─ interfaces/
│  │  ├─ models/
│  │  └─ policies/
│  ├─ infrastructure/
│  │  ├─ decision/
│  │  ├─ mapping/
│  │  ├─ ocr/
│  │  ├─ persona/
│  │  ├─ pii/
│  │  ├─ rendering/
│  │  └─ restoration/
│  └─ utils/
└─ tests/
   ├─ integration/
   └─ unit/
```

## 5. 安装方式

```bash
python -m pip install -e .[dev]
```

## 6. 最小运行示例

可直接运行：

```bash
python examples/minimal_demo.py
```

## 7. sanitize -> restore 调用示例

```python
from privacyguard.api import SanitizeRequest, RestoreRequest
from privacyguard.api.facade import PrivacyGuardFacade

facade = PrivacyGuardFacade.from_config_file("configs/default.yaml")

sanitize_resp = facade.sanitize(
    SanitizeRequest(
        session_id="demo",
        turn_id=1,
        prompt_text="我叫张三，电话是13800138000",
        screenshot=None,
        detector_mode="rule_ner_based",
        decision_mode="label_persona_mixed",
    )
)

restore_resp = facade.restore(
    RestoreRequest(
        session_id="demo",
        turn_id=1,
        cloud_text=sanitize_resp.sanitized_prompt_text,
    )
)
```

## 8. 当前限制

- `de_model` 当前为规则评分占位版，不是训练模型推理。
- OCR 默认走适配器回退后端；未接入真实模型时不会输出真实 OCR 结果。
- `rule_ner_based` 在 GLiNER 依赖缺失时会自动退化到 `rule_based`。
- 截图重绘是最小可行实现（白底覆盖+文本重绘），不追求最终视觉效果。
- 支持请求级动态切换：可在 `SanitizeRequest` 里通过 `detector_mode/decision_mode` 覆盖默认配置。
- 动态切换仅作用于当前 `sanitize` 调用，`restore` 仍基于会话映射恢复。

## 9. 后续扩展方向

- 接入真实 OCR 模型与更稳定的字体测量/排版能力
- 增强 NER 标签映射与多语言规则体系
- 强化 `de_model` 特征工程并替换为真实端侧模型
- 完善还原歧义消解策略与可观测性日志
