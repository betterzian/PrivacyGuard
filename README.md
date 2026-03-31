# PrivacyGuard

PrivacyGuard 是一个面向 GUI Agent / 手机智能助手场景的端侧隐私保护框架。它在图片和文本上传到云端前执行 `sanitize`，在云端返回文本后执行 `restore`，尽量减少真实 PII 直接暴露给云端的机会，同时保留任务可执行性。

当前仓库已经具备一条可运行的 `sanitize -> restore` 闭环，也已经把 detector / decision / OCR / rendering / mapping / restoration 的边界拆开，方便继续替换实现或接入训练产物。

它现在更适合做研究、原型验证和策略迭代，不是已经完成移动端部署、bundle 导出和线上指标闭环的成品 SDK。

## 当前能力

| 能力 | 当前状态 |
| --- | --- |
| 顶层 API | 已提供 `PrivacyGuard.sanitize()` / `restore()` / `write_privacy_repository()` |
| 文本脱敏与恢复 | 已可运行，支持 session 级占位符复用 |
| 截图脱敏 | 已支持 OCR + 局部重绘 + 多种填充策略 |
| PII 检测 | 默认公开模式为 `rule_based` |
| 决策模式 | `label_only`、`label_persona_mixed`、`de_model` |
| `de_model` runtime | `torch` 可加载 checkpoint，`bundle` 预留但未实现 |
| 训练链路 | 已有 supervised 数据导出、最小 finetune、torch runtime 回接 |

## 它适合做什么

- 在本地先把 prompt 和截图里的姓名、手机号、地址等信息替换成占位符或 persona 槽位，再把脱敏结果发给云端 Agent
- 验证不同策略模式在隐私保护和任务可执行性之间的取舍
- 作为后续 detector、decision engine、mobile runtime、训练导出的工程底座

## 它还不是

- 不是一个已经打包好的移动端 SDK
- 不是一个已完成线上观测、AB 实验、性能基线的生产系统
- 不是一个完整的多模态隐私识别平台；当前公开 detector 仍以规则与词典为主

## 安装

要求：

- Python `>=3.12,<3.13`（与 `pyproject.toml` 中 `requires-python` 一致）

基础安装：

```bash
python -m pip install -e .
```

默认 `decision_mode` 现在是 `label_only`。若要使用 `de_model`，请安装 `'.[train]'` 并显式传入 `decision_config={"runtime_type": "torch", "checkpoint_path": ...}`；否则会在装配 `DEModelEngine` 时失败。

开发依赖：

```bash
python -m pip install -e '.[dev]'
```

截图 OCR 依赖：

```bash
python -m pip install -e '.[ocr]'
```

训练依赖：

```bash
python -m pip install -e '.[train]'
```

一次装齐常用依赖：

```bash
python -m pip install -e '.[dev,ocr,train]'
```

## 快速开始

下面这段最小示例不依赖 OCR，因为 `screenshot=None` 时不会触发截图识别：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(decision_mode="label_only")

sanitize_resp = guard.sanitize(
    {
        "session_id": "demo-session",
        "turn_id": 1,
        "prompt_text": "我叫张三，电话是13800138000。",
        "screenshot": None,
        "protection_level": "balanced",
    }
)

restore_resp = guard.restore(
    {
        "session_id": "demo-session",
        "turn_id": 1,
        "agent_text": sanitize_resp["masked_prompt"],
    }
)

print(sanitize_resp["masked_prompt"])
print(restore_resp["restored_text"])
```

当前仓库里这段示例的输出是：

```text
我叫<姓名1>，电话是<手机号1>。
我叫张三，电话是13800138000。
```

## 处理截图

当 `screenshot` 不为 `None` 时，默认 OCR 提供者是 `PPOCREngineAdapter`。它支持：

- 本地文件路径
- `pathlib.Path`
- `PIL.Image.Image`
- `numpy.ndarray`
- `http(s)` 图片 URL

示例：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    decision_mode="label_persona_mixed",
    screenshot_fill_mode="mix",
    detector_config={
        "privacy_repository_path": "data/privacy_repository.sample.json",
    },
)

response = guard.sanitize(
    {
        "session_id": "image-demo",
        "turn_id": 1,
        "prompt_text": "帮我总结截图内容",
        "screenshot": "test.PNG",
    }
)

masked_image = response["masked_image"]
if masked_image is not None:
    masked_image.save("_sanitized.png")
```

截图填充模式当前支持：

- `ring`
- `gradient`
- `cv`
- `mix`

如果没有安装 `paddleocr`，只有在真正处理截图时才会报错，并提示安装 `python -m pip install -e '.[ocr]'`。

## 写入本地隐私词库

`rule_based` 检测器支持把本地隐私词库写入 JSON，再立即刷新当前 detector：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    detector_mode="rule_based",
    detector_config={"privacy_repository_path": "data/privacy_repository.json"},
)

result = guard.write_privacy_repository(
    {
        "true_personas": [
            {
                "persona_id": "demo_user",
                "display_name": "演示用户",
                "slots": {
                    "name": [
                        {
                            "full": {"value": "张三", "aliases": ["阿三"]},
                            "family": {"value": "张", "aliases": []},
                            "given": {"value": "三", "aliases": []}
                        }
                    ],
                    "phone": [{"value": "13800138000", "aliases": []}],
                    "email": [{"value": "zhangsan@example.com", "aliases": []}],
                    "address": [
                        {
                            "street": {
                                "value": "上海市浦东新区世纪大道100号",
                                "aliases": [],
                            }
                        }
                    ],
                },
            }
        ]
    }
)

print(result["repository_path"])
```

注意：

- `write_privacy_repository()` 只适用于 `rule_based` 检测器
- payload 顶层只接受 `stats` 和 `true_personas`
- 旧格式里的 `version` 字段当前不被 schema 接受
- 如果没有显式配置 `privacy_repository_path`，默认会写入 `data/privacy_repository.json`

## 选择决策模式

### `label_only`

最保守、最容易预测的基线模式：

- 低于阈值的候选保留
- 其余候选统一 `GENERICIZE`
- 不走 `de_model` runtime 推理链

适合：

- 冒烟测试
- 基线对比
- 不希望 persona 介入的简单场景

### `label_persona_mixed`

基于规则阈值做第一层筛选，但会优先尝试 persona 槽位：

- 低于阈值的候选保留
- persona 有对应槽位时优先 `PERSONA_SLOT`
- 其余候选回到 `GENERICIZE`

适合：

- 想让脱敏结果更像“稳定假身份”
- 已经准备好 fake persona 数据

### `de_model`

这是当前默认决策模式。它会消费 `DecisionContext`、页面质量、persona 状态、session 历史等上下文，再输出动作计划。

注意：

- `de_model` 是策略决策层，不是 detector
- 当前只支持 `torch` runtime
- `torch` runtime 必须传入 `checkpoint_path`
- `bundle` runtime 当前会直接抛出 `NotImplementedError`

示例：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    decision_mode="de_model",
    decision_config={
        "runtime_type": "torch",
        "checkpoint_path": "artifacts/sft/tiny_policy_supervised.pt",
    },
)
```

## 默认配置

在不显式注入组件时，`PrivacyGuard` 当前默认装配如下：

| 配置项 | 默认值 |
| --- | --- |
| `detector_mode` | `rule_based` |
| `decision_mode` | `label_only` |
| `de_model.runtime_type` | `torch` |
| `screenshot_fill_mode` | `mix` |
| `mapping_table` | `InMemoryMappingStore` |
| `ocr provider` | `ppocr_v5` |
| `renderer` | `PromptRenderer` |
| `restoration` | `ActionRestorer` |
| `persona_repo` | `JsonPersonaRepository`，本地缺省时回退到 `data/personas.sample.json` |

## API 概览

### `PrivacyGuard.sanitize(payload)`

输入字段：

- `session_id: str`
- `turn_id: int = 0`
- `prompt_text: str`
- `screenshot: Any | None = None`
- `protection_level: "weak" | "balanced" | "strong" = "balanced"`
- `detector_overrides: dict | None`

`detector_overrides` 当前在载荷中可写：`name`、`address`、`organization`、`other`。**`rule_based` 检测器合并**上述四类阈值（见 `DETECTOR_SCORING.md` 第 10 节）。

返回字段：

- `status`
- `masked_prompt`
- `masked_image`
- `session_id`
- `turn_id`
- `mapping_count`
- `active_persona_id`

### `PrivacyGuard.restore(payload)`

输入字段：

- `session_id: str`
- `turn_id: int = 0`
- `agent_text: str`

返回字段：

- `status`
- `restored_text`
- `session_id`

注意：facade 层字段名是 `agent_text`，进入内部 DTO 后才映射为 `cloud_text`。

### `PrivacyGuard.write_privacy_repository(payload)`

输入为隐私词库 patch：

- `stats`：可选
- `true_personas`：可选

返回字段：

- `status`
- `repository_path`

## 高级装配

`PrivacyGuard` 除了 `detector_mode`、`decision_mode`、`screenshot_fill_mode` 这些模式参数，也支持直接注入底层组件：

- `detector`
- `decision_engine`
- `ocr`
- `renderer`
- `restoration`
- `persona_repo`
- `mapping_table`
- `registry`

这意味着：

- detector 和 decision 有公开 mode 开关
- mapping store、persona repository、renderer 等更适合用依赖注入替换

例如改成持久化 mapping store：

```python
from privacyguard import PrivacyGuard
from privacyguard.infrastructure.mapping.json_mapping_store import JsonMappingStore
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository

guard = PrivacyGuard(
    decision_mode="de_model",
    decision_config={
        "runtime_type": "torch",
        "checkpoint_path": "artifacts/sft/tiny_policy_supervised.pt",
    },
    mapping_table=JsonMappingStore(path="data/mapping_store.json"),
    persona_repo=JsonPersonaRepository(path="data/personas.sample.json"),
)
```

## sanitize / restore 执行链路

当前 `sanitize` 的固定骨架是：

```text
payload
-> request model / DTO
-> OCR（仅 screenshot 存在时）
-> detector
-> session context prepare
-> DecisionContextBuilder
-> decision_engine.plan(...)
-> ConstraintResolver + replacement generation
-> render_text / render_image
-> mapping store
-> response DTO
```

当前 `restore` 的固定骨架是：

```text
payload
-> request model / DTO
-> current turn replacement records
-> text restore
-> response DTO
```

其中有两个当前语义很重要：

- `restore` 只读取当前 `session_id + turn_id` 的替换记录，不回溯整个会话
- `GENERICIZE` 和 `PERSONA_SLOT` 都通过 replacement records 恢复；`KEEP` 不参与恢复

## 默认数据文件

- `data/privacy_repository.json`
  默认本地隐私词库输出位置
- `data/privacy_repository.sample.json`
  `rule_based` 词库示例，包含 `true_personas`
- `data/personas.sample.json`
  fake persona 示例；当 `data/persona_repository.json` 不存在时，`JsonPersonaRepository` 会默认回退到这个样例文件
- `data/scanner_lexicons/china_geo_lexicon.json`
  内置地理词典，供 scanner 地址 clue 规则使用

## 训练 `de_model`

训练相关代码放在 [`training/`](training/) 目录，不参与应用运行时的 `sanitize / restore` 主流程。

当前已经可用的训练闭环包括：

- supervised JSONL 数据导出
- 最小 supervised finetune
- torch checkpoint 回接到 `de_model`

最小使用方式：

```python
from pathlib import Path

from training.pipelines.build_dataset import build_supervised_jsonl_dataset
from training.pipelines.run_supervised_finetune import (
    SupervisedFinetuneConfig,
    run_supervised_finetune,
)

dataset_path = build_supervised_jsonl_dataset(
    samples=zip(contexts, plans),
    output_path=Path("artifacts/train.jsonl"),
)

result = run_supervised_finetune(
    SupervisedFinetuneConfig(
        train_jsonl=dataset_path,
        output_dir=Path("artifacts/sft"),
        epochs=1,
        batch_size=8,
        learning_rate=1e-3,
        device="cpu",
    )
)
```

如果只想看训练侧细节，直接读 [`training/README.md`](training/README.md)。

## 仓库结构

```text
PrivacyGuard/
├─ privacyguard/
│  ├─ api/                  # DTO 与错误定义
│  ├─ app/                  # 顶层 facade、payload schema、pipeline 包装
│  ├─ application/          # sanitize / restore 编排与上下文服务
│  ├─ bootstrap/            # 模式默认值、注册表、工厂
│  ├─ domain/               # 枚举、接口、领域模型、约束策略
│  ├─ infrastructure/       # detector / decision / ocr / rendering / mapping / persona 等实现
│  └─ utils/
├─ training/                # de_model 训练与导出相关代码
├─ tests/
├─ docs/
├─ data/
└─ examples/                # 可按需添加演示脚本；仓库内联示例见上文
```

## 推荐阅读

代码入口：

- [`privacyguard/app/privacy_guard.py`](privacyguard/app/privacy_guard.py)
- [`privacyguard/application/pipelines/sanitize_pipeline.py`](privacyguard/application/pipelines/sanitize_pipeline.py)
- [`privacyguard/application/pipelines/restore_pipeline.py`](privacyguard/application/pipelines/restore_pipeline.py)

文档：

- [`docs/DETECTOR_IMPLEMENTATION.md`](docs/DETECTOR_IMPLEMENTATION.md)
- [`docs/DETECTOR_SCORING.md`](docs/DETECTOR_SCORING.md)
- [`docs/DE_MODEL_IMPLEMENTATION.md`](docs/DE_MODEL_IMPLEMENTATION.md)
- [`docs/DE_MODEL_TRAINING_LAYOUT.md`](docs/DE_MODEL_TRAINING_LAYOUT.md)
- [`training/README.md`](training/README.md)

## 当前限制

- 当前公开 detector mode 只有 `rule_based`；`gliner_adapter.py` 仍是实验性适配器，未接入默认注册
- `restore` 目前只恢复文本，不做结构化动作 DSL 恢复
- `restore` 只看当前 turn 的 replacement records
- `de_model` 的 `bundle` runtime 尚未实现
- 训练目录已经能导出与 finetune，但对抗训练和真实移动端 bundle 导出仍未完成
