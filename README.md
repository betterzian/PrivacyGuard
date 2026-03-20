# PrivacyGuard

PrivacyGuard 是一个面向 GUI Agent / 手机智能助手场景的端侧隐私保护框架。它在图片和文本上传到云端前执行 `sanitize`，在云端返回文本后执行 `restore`，尽量减少真实 PII 直接暴露给云端的机会，同时保留任务可执行性。

当前仓库已经具备：

- 可运行的 `sanitize -> restore` 闭环
- 可替换的 detector / decision / rendering / mapping / restoration 边界
- `de_model` 的最小训练、checkpoint 回接和 torch runtime 路径

但它仍然是研究型工程底座，不是已经完成移动端部署、端侧 bundle 导出和线上指标闭环的成品 SDK。

## 项目现状

| 模块 | 当前实现 | 备注 |
| --- | --- | --- |
| 顶层 API | `PrivacyGuard` / `PersonaRepository` | 已实现 |
| OCR | `PPOCREngineAdapter` | 支持本地路径、`PIL.Image`、`numpy.ndarray`、`http(s)` URL；缺少 `paddleocr` 时会在真正跑截图 OCR 时显式报错 |
| PII 检测 | `rule_based` | 当前唯一公开 detector mode |
| 决策 | `de_model` / `label_only` / `label_persona_mixed` | 默认模式是 `de_model`，默认 runtime 是 heuristic |
| 文本渲染 | `PromptRenderer` | prompt 优先按 span 替换，缺失 span 时回退保守正则替换 |
| 截图渲染 | `ScreenshotRenderer` | 支持 OCR block 局部重建、跨 block 处理、polygon/rotation 感知和 `ring / gradient / cv / mix` 填充策略 |
| 映射与恢复 | `InMemoryMappingStore` / `JsonMappingStore` + `ActionRestorer` | `restore` 只使用当前 turn 的映射记录 |
| Persona 仓库 | `JsonPersonaRepository` | 默认读 `data/persona_repository.json`，缺省时回退 `data/personas.sample.json` |
| 训练 | `training/` | 已有 supervised JSONL 导出、层级标签、最小 supervised finetune、torch runtime 回接；对抗训练和真实 bundle 导出仍未完成 |

## 当前架构边界

### `PrivacyGuard` 是 facade，不承载内部策略细节

对外入口是 [`PrivacyGuard`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/app/privacy_guard.py)。

它负责：

- 接收外部 payload
- 转换为 request model / DTO
- 调用 sanitize / restore pipeline
- 返回外部响应字典

它不直接承担：

- detector 规则
- OCR 实现
- `de_model` runtime
- restore 规则

这也是为什么内部即使已经有：

- `DecisionModelContext`
- `protect_decision`
- `rewrite_mode`
- `page_policy_state`

这些字段也不会直接暴露到 facade 的稳定对外返回里。

### `de_model` 是策略决策层，不是 detector

当前代码里，`de_model` 的职责是：

- 消费已有候选
- 读取上下文、页面质量、persona 状态、session 历史
- 输出动作计划

它不是：

- detector
- OCR 清洗主逻辑
- 复杂 linking 系统

当前统一执行动作术语为：

- `KEEP`
- `GENERICIZE`
- `PERSONA_SLOT`

内部 runtime 可以使用两级视角：

- `protect_decision`: `KEEP / REWRITE`
- `rewrite_mode`: `GENERICIZE / PERSONA_SLOT / NONE`

但最终执行边界仍然是上面三类动作。

## sanitize / restore 主链

### `sanitize`

当前 application 主链位于 [`privacyguard/application/pipelines/sanitize_pipeline.py`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/application/pipelines/sanitize_pipeline.py)。

固定骨架是：

```text
payload
-> request model / DTO
-> OCR / detector
-> session context prepare
-> DecisionContextBuilder
-> decision_engine.plan(...)
-> SessionPlaceholderAllocator
-> render
-> mapping store
-> response DTO
```

如果按当前代码展开，真实顺序是：

1. 校验 `session_id / turn_id / prompt_text / screenshot / protection_level / detector_overrides`
2. 若有截图，则先做 OCR；否则 `ocr_blocks=[]`
3. `rule_based` 检测 prompt_text 与 OCR 中的 PII 候选
4. 读取或创建当前 session 的 `SessionBinding`
5. `DecisionContextBuilder` 组装 `DecisionModelContext`
6. 调用具体 `decision_engine.plan(...)`
7. `SessionPlaceholderAllocator` 为 `GENERICIZE` 分配 session 级稳定占位符
8. `PromptRenderer` 渲染 prompt；若有截图则再渲染 screenshot
9. 写入当前 turn 的 `ReplacementRecord`
10. 如有 active persona，则更新 session binding

#### 当前的 context 组织

`DecisionContextBuilder` 当前正式收敛为 `DecisionModelContext`，其核心组织是：

- `raw_refs`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

旧字段 `page_features / candidate_features / persona_features` 仍保留为兼容层，但新的正式组织已经是上面四块。

### `restore`

当前 application 主链位于 [`privacyguard/application/pipelines/restore_pipeline.py`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/application/pipelines/restore_pipeline.py)。

固定骨架是：

```text
payload
-> request model / DTO
-> current turn replacement records
-> text restore
-> response DTO
```

当前 restore 明确保持收敛：

- 只读取当前 `session_id + turn_id` 的替换记录
- 不回溯整个会话历史
- 不处理结构化动作 DSL
- 不对 `de_model` 决策做逆向推理

动作兼容原则是：

- `KEEP` 不参与 restore
- `GENERICIZE` 可恢复
- `PERSONA_SLOT` 可恢复

## 决策模式与分流

当前公开 decision mode 有 3 个。

### `label_only`

实现文件：[`privacyguard/infrastructure/decision/label_only_engine.py`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/label_only_engine.py)

行为：

- 低于阈值的候选 -> `KEEP`
- 其余候选 -> `GENERICIZE`
- 最后进入 `ConstraintResolver`

特点：

- 仍然走统一 sanitize 主链
- 仍然会构建 `DecisionModelContext`
- 但不走 `de_model` 的 features / runtime 推理链

### `label_persona_mixed`

实现文件：[`privacyguard/infrastructure/decision/label_persona_mixed_engine.py`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/label_persona_mixed_engine.py)

行为：

- 低于阈值的候选 -> `KEEP`
- persona 优先属性 -> `PERSONA_SLOT`
- 其余属性 -> `GENERICIZE`
- 最后进入 `ConstraintResolver`

### `de_model`

实现文件：[`privacyguard/infrastructure/decision/de_model_engine.py`](/Users/vis/Documents/GitHub/PrivacyGuard/privacyguard/infrastructure/decision/de_model_engine.py)

行为：

- 读取 `DecisionModelContext`
- `DecisionFeatureExtractor.pack(context)`
- 调用 runtime
- 构造 `DecisionAction`
- 进入 `ConstraintResolver`

当前 `de_model` runtime 支持：

- `heuristic`
- `torch`

其中：

- `heuristic` 是默认 runtime
- `torch` 需要显式提供 `checkpoint_path`
- `bundle` / `onnx` 当前尚未实现成功执行路径

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

如果你想要一个更保守、可预测的基线，可以显式指定：

```python
guard = PrivacyGuard(decision_mode="label_only")
```

如果你想优先复用 persona 槽位：

```python
guard = PrivacyGuard(decision_mode="label_persona_mixed")
```

### 使用截图 OCR

当 `screenshot` 不为 `None` 时，`PPOCREngineAdapter.extract()` 支持：

- 本地文件路径
- `PIL.Image.Image`
- `numpy.ndarray`
- `http(s)` 图片 URL

示例：

```python
guard = PrivacyGuard(
    screenshot_fill_mode="mix",
    detector_config={"privacy_repository_path": "data/privacy_repository.sample.json"},
)

response = guard.sanitize(
    {
        "session_id": "image-demo",
        "turn_id": 1,
        "prompt_text": "帮我总结截图内容",
        "screenshot": "test.PNG",
    }
)
```

如果未安装 `paddleocr`，只有在真正处理截图时才会报错，并提示执行 `python -m pip install -e '.[ocr]'`。

### 使用 `de_model` torch runtime

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    decision_mode="de_model",
    decision_config={
        "runtime_type": "torch",
        "checkpoint_path": "artifacts/tiny_policy_supervised.pt",
    },
)
```

当前 `torch` runtime 依赖已有 checkpoint；如果只想跑默认可用路径，继续用 `runtime_type="heuristic"` 即可。

### 写入 persona 仓库

```python
from privacyguard import PrivacyGuard, PersonaRepository

repository = PersonaRepository()
repository.write(
    {
        "personas": [
            {
                "persona_id": "owner",
                "display_name": "主身份",
                "slots": {
                    "name": "张三",
                    "phone": "13800138000",
                    "email": "zhangsan@example.com",
                    "address": "上海市浦东新区世纪大道100号",
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

`PersonaRepository.write()` 支持按 `persona_id` 合并写入：

- `slots`
- `metadata`
- `stats`

## 顶层 API

### `PrivacyGuard.sanitize(payload)`

输入字段：

- `session_id: str`
- `turn_id: int = 0`
- `prompt_text: str`
- `screenshot: Any | None = None`
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

注意：

- 这些是 facade 的稳定对外字段
- 内部 `protect_decision / rewrite_mode / page_policy_state / candidate_policy_views` 不会直接出现在这里

### `PrivacyGuard.restore(payload)`

输入字段：

- `session_id: str`
- `turn_id: int = 0`
- `agent_text: str`

返回字段：

- `status`
- `restored_text`
- `session_id`

### `PersonaRepository.write(payload)`

输入字段：

- `personas: list[...]`

返回字段：

- `status`
- `repository_path`
- `written_count`
- `persona_ids`

## 训练与 `de_model`

当前 `training/` 已对齐新的层级标签组织。当前 supervised 数据导出至少包含：

- `candidate_policy_view`
- `page_policy_state`
- `persona_policy_states`
- `target_protect_label`
- `target_rewrite_mode`
- `target_persona_id`
- `final_action`

当前 supervised loss 已拆为：

- `L_protect`
- `L_rewrite_mode`
- `L_persona`
- 可选 `L_cost`

其中 `L_cost` 当前至少支持：

- 高 `protection_level` 下误判 `KEEP` 更高惩罚
- 低 `page_quality_state` 下误判 `KEEP` 更高惩罚

## 数据与配置文件

- `data/persona_repository.json`
  本地 persona 仓库默认落盘位置
- `data/personas.sample.json`
  当本地仓库不存在时的只读回退样例
- `data/privacy_repository.sample.json`
  `RuleBasedPIIDetector` 示例词库
- `data/china_geo_lexicon.json`
  内置地理词汇表，供地址和 location clue 规则使用

补充说明：

- 词库不会自动启用，需要显式传入 `detector_config={"privacy_repository_path": ...}`
- `JsonPersonaRepository` 读取时兼容 `{"personas": [...]}` 和直接的列表格式
- 实际持久化到 `data/persona_repository.json` 时会写成列表格式

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
