# PrivacyGuard

PrivacyGuard 是一个面向 GUI Agent / 手机智能助手场景的端侧隐私保护框架，核心思路是：

1. 在图文请求上传云端前先做 `sanitize`；
2. 云端只看到脱敏后的 prompt 与截图；
3. 云端返回文本后在本地执行 `restore`。

当前仓库已经不是纯概念原型，而是具备可运行的 `sanitize -> restore` 闭环、可替换模块边界、单测覆盖和 `de_model` 训练/导出骨架的工程化版本；但它仍然不是一个已经完成端侧部署、指标闭环和模型化决策的成品系统。

## 1. 项目定位

PrivacyGuard 要解决的问题不是“把所有隐私都糊掉”，而是面向 GUI Agent 的真实调用链，在尽量不破坏任务可执行性的前提下，减少云端看到原始 PII 的机会。

典型调用场景如下：

1. 端侧采集当前页面截图；
2. 用户输入 prompt；
3. 图文一起发给云端多模态模型；
4. 云端返回文本指令或动作建议；
5. 端侧执行层继续消费结果。

PrivacyGuard 放在第 2 步和第 4 步之间，承担：

- 上传前脱敏：prompt + screenshot
- 返回后还原：当前以文本结果为主
- 会话级 persona / mapping 管理

## 2. 当前代码状态

| 模块 | 当前状态 | 说明 |
| --- | --- | --- |
| 顶层 API | 已实现 | 统一入口为 `PrivacyGuard.sanitize()` / `PrivacyGuard.restore()` |
| OCR | 已实现 | `PPOCREngineAdapter` 对接 PP-OCRv5，支持本地路径、PIL、numpy、URL 输入 |
| PII 检测 | 已实现基线 | 主链路为 `rule_based`；`GLiNERAdapter` 仅是预留扩展位，未接入默认流程 |
| 决策引擎 | 已实现三种模式 | `label_only`、`label_persona_mixed` 可直接使用；`de_model` 已有上下文、特征、heuristic runtime、可加载 checkpoint 的 torch runtime、TinyPolicyNet 与最小 supervised 训练闭环 |
| 文本渲染 | 已实现 | prompt 优先按字符级 span 替换，兼容旧式保守替换 |
| 截图渲染 | 已实现最小闭环 | 支持 OCR block 局部重绘、polygon/rotation 感知，以及 `ring / gradient / cv / mix` 填充策略 |
| 映射与恢复 | 已实现 | 当前 `restore` 只基于当前 turn 的 `ReplacementRecord` 恢复云端返回文本 |
| 训练与导出 | 已实现最小训练闭环 | `training/` 目录已经支持 supervised JSONL 导出、TinyPolicyNet 行为克隆训练和 checkpoint 回接；adversarial finetune 与 runtime bundle 导出仍未完成 |
| 测试 | 覆盖较完整 | 已覆盖 detector、pipeline、renderer、fill strategy、`de_model` 上下文和 TinyPolicyNet 原型等关键环节 |

一句话概括当前成熟度：这是一个“骨架扎实、主链路真实可跑、核心算法仍在迭代”的仓库。

## 3. 威胁模型与非目标

PrivacyGuard 当前默认云端是 `honest-but-curious`：

- 云端会正常处理上传图文；
- 云端可能记录、关联和分析会话中的隐私线索；
- 云端不知道本地 persona 仓库和映射表的真实内容。

当前项目主要防御：

- 原始 PII 直接上传云端
- 多轮会话下的身份推断风险

当前项目不直接承诺解决：

- prompt injection
- 恶意 GUI 诱导
- 系统级权限隔离
- 非文本视觉隐私的完整防护
- 云端结构化动作规划安全

## 4. 核心工作流

### `sanitize`

1. 接收 `session_id / turn_id / prompt / image`
2. 若有截图，则先做 OCR
3. 用本地 detector 识别 prompt 与 OCR 中的 PII 候选
4. 决策引擎对每个候选输出 `KEEP / GENERICIZE / PERSONA_SLOT`
5. 渲染 prompt 与截图
6. 把本轮替换记录写入 mapping store

### `restore`

1. 接收 `session_id / turn_id / agent_text`
2. 读取当前 turn 的替换记录
3. 把云端返回文本中的占位值恢复为真实值

当前 `restore` 处理的是“云端返回文本”，不是完整结构化动作 DSL；也不会自动回溯整段会话历史。

## 5. 当前支持的模式

### Detector

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

### Screenshot Fill Strategy

- `ring`
- `gradient`
- `cv`
- `mix`

## 6. 安装

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

如果需要真实 OCR：

```bash
python3 -m pip install -e '.[dev,ocr]'
```

如果需要训练侧原型依赖：

```bash
python3 -m pip install -e '.[train]'
```

## 7. 快速开始

最小示例：

```python
from privacyguard import PrivacyGuard

guard = PrivacyGuard(
    detector_mode="rule_based",
    decision_mode="label_persona_mixed",
    screenshot_fill_mode="mix",
    detector_config={"dictionary_path": "data/pii_dictionary.sample.json"},
)

sanitize_resp = guard.sanitize(
    {
        "session_id": "demo-session",
        "turn_id": 1,
        "prompt": "我叫张三，电话是13800138000，地址是北京市海淀区中关村。",
        "image": None,
        "protection_level": "balanced",
        "detector_overrides": {
            "organization": 0.55,
        },
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

运行仓库内示例：

```bash
python3 examples/minimal_demo.py
```

如果想单独验证 PP-OCRv5 的官方 `import` 用法：

```bash
python3 examples/paddleocr_import_demo.py
```

## 8. 示例数据与配置说明

- `data/personas.sample.json`
  用于 `JsonPersonaRepository` 的示例 persona 数据。
- `data/pii_dictionary.sample.json`
  用于 `RuleBasedPIIDetector` 的示例本地词典。

需要注意：

- 示例词典不会自动加载；如果需要启用，必须显式传入 `detector_config={"dictionary_path": ...}`。
- persona JSON 当前兼容旧格式和实体列表格式。
- 如果未安装 `paddleocr`，截图 OCR 不会静默降级，而会明确报错提示安装依赖。

## 9. 仓库结构

```text
PrivacyGuard/
├─ privacyguard/
│  ├─ app/                # 顶层 API、payload schema、pipeline 包装
│  ├─ application/        # sanitize / restore 编排与服务
│  ├─ bootstrap/          # 注册表、工厂、模式归一化
│  ├─ domain/             # 枚举、接口、领域模型、约束策略
│  ├─ infrastructure/     # detector / decision / ocr / rendering / mapping 等实现
│  └─ utils/
├─ training/              # de_model 训练、导出与 runtime bundle 骨架
├─ tests/                 # unit + integration tests
├─ docs/                  # 请求流与补充说明
├─ data/                  # 示例 persona / dictionary
└─ examples/              # 最小运行示例
```

## 10. 当前限制

- `rule_based` 仍是当前检测主线，没有真正接入 NER 模型补召回。
- 已支持相邻 OCR block 的页面级聚合检测与 remap，但在更复杂版面、远距离关联和更强页面语义联合判断上仍有提升空间。
- `de_model` 现在既支持默认 heuristic runtime，也支持显式加载 checkpoint 的 torch runtime；但默认策略仍未切换到训练模型，bundle/ONNX/TFLite runtime 也还没落地。
- `restore` 当前只处理云端返回文本，只看当前 turn 映射，不处理结构化动作 DSL，也不做跨 turn 自动回溯。
- 截图重绘目标是“可用闭环”，不是最终视觉保真；复杂背景下仍可能出现可见痕迹。
- 当前主要是 Python API 仓库，还没有 CLI、服务化接口和移动端集成层。
- README、设计文档与实现会持续收敛，阅读时应优先以 `privacyguard/` 下实际代码为准。

## 11. 依据 `What_is_PrivcacyGuard.md` 的优先改进方向

最值得继续推进的方向，不是继续堆更多概念，而是把已经存在的工程骨架补成真正可评估的系统：

1. `de_model` 从启发式 runtime 升级为真实模型位点  
   已有上下文、特征、TinyPolicyNet、训练与导出骨架，下一步应把 `DEModelEngine` 接到可加载权重的 runtime，并保留失败回退机制。

2. detector 从高召回规则基线升级为“规则 + 模型”双路体系  
   当前规则能力已经不弱，也已支持相邻 OCR block 聚合；但弱上下文短词、复杂页面和更强语义联合判断仍会成为瓶颈。

3. restore 从“文本替换”升级为“结构化动作恢复”  
   如果未来云端返回的是 action DSL、参数列表或坐标化指令，当前恢复能力是不够的。

4. 引入真实评估指标  
   包括检测精度、任务成功率、persona 一致性、身份推断难度、端侧时延和内存占用，而不只是“能不能跑通”。

5. 补齐移动端部署路径  
   当前 `training/` 已经考虑了 runtime bundle 与导出 metadata，但还缺少实际的 ONNX/TFLite 推理接线、定长输入约束验证和真机 benchmark。

## 12. 文档索引

- [What_is_PrivcacyGuard.md](What_is_PrivcacyGuard.md)：项目定位、威胁模型与 `de_model` 设计目标
- [docs/REQUEST_FLOW.md](docs/REQUEST_FLOW.md)：当前代码调用链与请求流说明
- [docs/DE_MODEL_IMPLEMENTATION.md](docs/DE_MODEL_IMPLEMENTATION.md)：当前 `de_model` 的实现细节、模型结构、输入输出和训练/推理链路
- [training/README.md](training/README.md)：训练与导出目录说明

## 13. 当前适合用它做什么

PrivacyGuard 当前最适合：

- 作为 GUI Agent 隐私保护链路的研究型工程底座
- 验证 `sanitize -> cloud -> restore` 的完整闭环
- 试验不同 detector / decision / rendering 策略
- 为后续端侧小模型决策和 Android 集成准备边界与数据结构

如果目标是直接拿来做生产级移动端 SDK，当前仓库还差真实模型权重、指标验证、真机部署和工程集成层。
