# PrivacyGuard

## 1. 项目简介

PrivacyGuard 是一个面向「上传前脱敏（API_1）+ 云端返回后还原（API_2）」的隐私保护框架。  
当前版本重点是提供可运行、可扩展、可替换的工程骨架与最小闭环能力。

## 2. 核心能力

- 统一入口：`PrivacyGuard.sanitize()` 与 `PrivacyGuard.restore()`
- 配置装配：通过 `bootstrap/factories.py` + `registry.py` 按模式切换实现
- 检测链路：支持 `rule_based`
- 决策链路：支持 `label_only`、`label_persona_mixed`、`de_model`（规则占位版）
- 渲染闭环：可将决策应用到 prompt 与截图，并写入映射
- 还原闭环：可基于 turn/session 映射恢复云端返回文本

## 3. 当前支持模式

### PII Detector
- `rule_based`

### Decision Engine
- `label_only`
- `label_persona_mixed`
- `de_model`

### Mapping Store
- `in_memory`
- `json`

### Persona Repository
- `json`

## 4. 目录结构

```text
PrivacyGuard/
├─ data/
│  ├─ personas.sample.json
│  └─ pii_dictionary.sample.json
├─ docs/
│  └─ REQUEST_FLOW.md          # 请求全流程说明（初始化与 sanitize/restore 调用链）
├─ examples/
│  └─ minimal_demo.py
├─ privacyguard/
│  ├─ api/
│  ├─ app/                    # 顶层入口、流水线封装、请求/响应模型
│  ├─ application/
│  │  ├─ pipelines/
│  │  └─ services/
│  ├─ bootstrap/              # 注册表、默认组件注册、模式归一化
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
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    detector_mode="rule_based",
    decision_mode="de_model",
)

sanitize_resp = guard.sanitize(
    {
        "session_id": "demo",
        "turn_id": 1,
        "prompt": "我叫张三，电话是13800138000",
        "image": None,
    }
)

restore_resp = guard.restore(
    {
        "session_id": "demo",
        "turn_id": 1,
        "agent_text": sanitize_resp["masked_prompt"],
    }
)
```

## 8. 当前限制

- `de_model` 当前为规则评分占位版，不是训练模型推理。
- OCR 默认走适配器回退后端；未接入真实模型时不会输出真实 OCR 结果。
- 截图重绘是最小可行实现（白底覆盖+文本重绘），不追求最终视觉效果。
- 检测/决策模式在构造 `PrivacyGuard` 时指定，单次请求不可覆盖。

## 9. 后续扩展方向

- 接入真实 OCR 模型与更稳定的字体测量/排版能力
- 增强 NER 标签映射与多语言规则体系
- 强化 `de_model` 特征工程并替换为真实端侧模型
- 完善还原歧义消解策略与可观测性日志

## 10. 代码注释约定

- `privacyguard/app` 下的核心类与函数均已补充中文 docstring。
- 顶层入口 `PrivacyGuard`、两条流水线（`SanitizePipeline` / `RestorePipeline`）以及请求/响应模型均提供中文职责说明。
- 新增或修改函数时，建议同步补充中文 docstring，优先描述职责、输入输出与关键行为。
