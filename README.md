# PrivacyGuard

PrivacyGuard 是一个面向 GUI Agent / 手机智能助手场景的端侧隐私保护框架。它在图片和文本上传到云端前执行 `sanitize`，在云端返回文本后执行 `restore`，尽量减少真实 PII 直接暴露给云端的机会，同时保留任务可执行性。

当前仓库已经具备可运行的 `sanitize -> restore` 闭环、可替换的模块边界、较完整的单元测试，以及 `de_model` 的最小训练与 checkpoint 回接链路；但它仍然是研究型工程底座，不是已经完成移动端部署与指标闭环的成品 SDK。

## 项目现状

| 模块 | 当前实现 | 备注 |
| --- | --- | --- |
| 顶层 API | `PrivacyGuard` / `PrivacyRepository` | 已实现 |
| OCR | `PPOCREngineAdapter` | 支持本地路径、`PIL.Image`、`numpy.ndarray`、`http(s)` URL；缺少 `paddleocr` 时会在真正跑截图 OCR 时显式报错 |
| PII 检测 | `rule_based` | 当前唯一注册到主链路的 detector |
| 决策 | `de_model` / `label_only` / `label_persona_mixed` | 默认模式是 `de_model`，默认 runtime 是 heuristic |
| 文本渲染 | `PromptRenderer` | prompt 优先按 span 替换，缺失 span 时回退保守正则替换 |
| 截图渲染 | `ScreenshotRenderer` | 支持 OCR block 局部重建、跨 block 处理、polygon/rotation 感知和 `ring / gradient / cv / mix` 填充策略 |
| 映射与恢复 | `InMemoryMappingStore` / `JsonMappingStore` + `ActionRestorer` | `restore` 只使用当前 turn 的映射记录 |
| 本地隐私仓库 | `JsonPersonaRepository` | 默认读 `data/privacy_repository.json`，缺省时回退 `data/personas.sample.json` |
| 训练 | `training/` | 已有 supervised JSONL 导出、最小行为克隆训练、torch runtime 回接；对抗训练和真实 bundle 导出仍未完成 |

## 核心流程

### `sanitize`

1. 校验 `session_id / turn_id / prompt / image / protection_level / detector_overrides`
2. 若有截图，则先做 OCR
3. `rule_based` 检测 prompt 与 OCR 中的 PII 候选
4. `DecisionContextBuilder` 构造统一 `DecisionContext`
5. 决策引擎输出 `DecisionPlan`
6. `SessionPlaceholderAllocator` 为 `GENERICIZE` 动作分配会话级稳定占位符
7. 渲染 prompt 与截图，并写入当前 turn 的替换记录

### `restore`

1. 校验 `session_id / turn_id / agent_text`
2. 只读取当前 turn 的替换记录
3. 用 `replacement_text -> source_text` 映射恢复云端返回文本

需要特别注意：

- `restore` 当前不回溯整个会话历史
- `restore` 不处理结构化动作 DSL，只处理云端返回文本
- 占位符是 session 级稳定的，但恢复时只认当前 `turn_id`

## 默认行为与可选模式

### 默认值

| 配置 | 默认值 |
| --- | --- |
| `detector_mode` | `rule_based` |
| `decision_mode` | `de_model` |
| `de_model.runtime_type` | `heuristic` |
| `screenshot_fill_mode` | `mix` |
| `mapping_store` | `in_memory` |
| `persona_repository` | `json` |
| `ocr provider` | `ppocr_v5` |

### 当前支持的模式

#### Detector

- `rule_based`

#### Decision

- `de_model`
- `label_only`
- `label_persona_mixed`

#### Mapping Store

- `in_memory`
- `json`

#### Persona Repository

- `json`

#### Screenshot Fill Strategy

- `ring`
- `gradient`
- `cv`
- `mix`

## 安装

要求：

- Python `>=3.11`

基础安装：

```bash
python3 -m pip install -e .
```

开发依赖：

```bash
python3 -m pip install -e '.[dev]'
```

截图 OCR 依赖：

```bash
python3 -m pip install -e '.[ocr]'
```

训练依赖：

```bash
python3 -m pip install -e '.[train]'
```

一次装齐常用依赖：

```bash
python3 -m pip install -e '.[dev,ocr,train]'
```

## 快速开始

### 最小 `sanitize -> restore`

下面这个例子不依赖 OCR，因为 `image=None` 时不会触发截图识别：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    detector_mode="rule_based",
    decision_mode="de_model",
    decision_config={"runtime_type": "heuristic"},
)

sanitize_resp = guard.sanitize(
    {
        "session_id": "demo-session",
        "turn_id": 1,
        "prompt": "我叫张三，电话是13800138000。",
        "image": None,
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

如果你想要一个更保守、可预测的基线，也可以显式指定：

```python
guard = PrivacyGuard(decision_mode="label_only")
```

### 使用截图 OCR

当 `image` 不为 `None` 时，`PPOCREngineAdapter.extract()` 支持：

- 本地文件路径
- `PIL.Image.Image`
- `numpy.ndarray`
- `http(s)` 图片 URL

示例：

```python
guard = PrivacyGuard(
    screenshot_fill_mode="mix",
    detector_config={"dictionary_path": "data/pii_dictionary.sample.json"},
)

response = guard.sanitize(
    {
        "session_id": "image-demo",
        "turn_id": 1,
        "prompt": "帮我总结截图内容",
        "image": "test.PNG",
    }
)
```

如果未安装 `paddleocr`，只有在真正处理截图时才会报错，并提示执行 `python -m pip install -e '.[ocr]'`。

### 写入本地隐私仓库

```python
from privacyguard import PrivacyGuard, PrivacyRepository

repository = PrivacyRepository()
repository.write(
    {
        "personas": [
            {
                "persona_id": "owner",
                "display_name": "主身份",
                "profile": {
                    "name": "张三",
                    "phone": "13800138000",
                },
                "slots": {
                    "email": "zhangsan@example.com",
                },
                "metadata": {
                    "source": "manual_import",
                },
                "stats": {
                    "exposure_count": 0,
                },
            }
        ]
    }
)

guard = PrivacyGuard(decision_mode="label_persona_mixed")
print(guard.persona_repo.get_persona("owner"))
```

`PrivacyRepository.write()` 支持按 `persona_id` 合并写入：

- `profile`
- `slots`
- `metadata`
- `stats`

## 顶层 API

### `PrivacyGuard.sanitize(payload)`

输入字段：

- `session_id: str`
- `turn_id: int = 0`
- `prompt: str`
- `image: Any | None = None`
- `protection_level: "weak" | "balanced" | "strong" = "balanced"`
- `detector_overrides`
  当前请求层只允许覆盖 `name / location_clue / address / organization / other`

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

### `PrivacyRepository.write(payload)`

输入字段：

- `personas: list[...]`

返回字段：

- `status`
- `repository_path`
- `written_count`
- `persona_ids`

## 数据与配置文件

- `data/privacy_repository.json`
  本地 persona 仓库默认落盘位置
- `data/personas.sample.json`
  当本地仓库不存在时的只读回退样例
- `data/pii_dictionary.sample.json`
  `RuleBasedPIIDetector` 示例词典
- `data/china_geo_lexicon.json`
  内置地理词汇表，供地址和 location clue 规则使用

补充说明：

- 词典不会自动启用，需要显式传入 `detector_config={"dictionary_path": ...}`
- `JsonPersonaRepository` 读取时兼容 `{"personas": [...]}` 和直接的列表格式
- 实际持久化到 `data/privacy_repository.json` 时会写成列表格式

## 仓库结构

```text
PrivacyGuard/
├─ privacyguard/
│  ├─ app/                # 顶层 API、payload schema、pipeline 包装
│  ├─ application/        # sanitize / restore 编排与上下文服务
│  ├─ bootstrap/          # 注册表、工厂、模式归一化
│  ├─ domain/             # 枚举、接口、领域模型、约束解析
│  ├─ infrastructure/     # detector / decision / ocr / rendering / mapping / persona 等实现
│  └─ utils/
├─ training/              # de_model 训练与导出相关代码
├─ tests/
├─ docs/
├─ data/
└─ examples/
```

## 当前限制

- `rule_based` 是当前唯一注册到主链路的 detector，`GLiNERAdapter` 仍只是预留扩展位
- `de_model` 默认仍是 heuristic runtime；torch runtime 需要显式提供 checkpoint
- `runtime_type="bundle"` 目前只保留接口，实际会抛出 `NotImplementedError`
- `run_adversarial_finetune()` 尚未实现
- `export_runtime_bundle()` 目前只写 metadata，不负责真实 ONNX/TFLite 导出
- `restore` 只看当前 turn，不做跨 turn 自动恢复
- 顶层对外仍是 Python API，没有 CLI、服务化接口和移动端接线层

## 文档索引

- [What_is_PrivcacyGuard.md](What_is_PrivcacyGuard.md)
- [docs/REQUEST_FLOW.md](docs/REQUEST_FLOW.md)
- [docs/DE_MODEL_IMPLEMENTATION.md](docs/DE_MODEL_IMPLEMENTATION.md)
- [docs/DE_MODEL_TRAINING_LAYOUT.md](docs/DE_MODEL_TRAINING_LAYOUT.md)
- [training/README.md](training/README.md)

## 仓库内示例

```bash
python3 examples/minimal_demo.py
python3 examples/privacy_repository_demo.py
python3 examples/paddleocr_import_demo.py
```
