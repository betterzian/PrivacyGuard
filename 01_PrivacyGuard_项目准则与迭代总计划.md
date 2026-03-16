# PrivacyGuard 项目准则与迭代总计划

## 1. 目标与范围

本计划基于现有 PrivacyGuard 框架文档整理，核心目标不是重写系统，而是**以最小改动补齐缺失实现**，把项目搭成一个：

- **高内聚**：每个模块只处理自身职责；
- **低耦合**：模块之间只通过接口与数据契约通信；
- **可替换**：同一模块可切换不同实现方案；
- **可恢复**：所有替换动作必须可追踪、可回滚、可还原；
- **可测试**：每轮都有明确的最小验收标准。

本轮规划直接继承你文档中的 7 个核心模块与 2 个 API 闭环，不改变项目定位，不引入额外的系统级概念。

---

## 2. 从现有框架抽取出的硬性约束

以下约束直接来自现有项目定义，编码时不得违背：

1. 系统以 **API_1（上传前脱敏）** 与 **API_2（云端返回后还原）** 为外部入口；
2. 现有模块边界必须保留：
   - OCR
   - PII Detector
   - Persona Repository
   - Local Mapping Table
   - Decision Engine
   - Rendering Engine
   - Restoration Module
3. `Decision Engine` 与 `Restoration Module` 可访问 `Persona Repository`；
4. `Decision Engine` 可访问 `Local Mapping Table`；
5. 同一模块可能有多种实现方案，外部只能通过**统一接口 + 模式标签**选择实现；
6. 决策动作空间必须受控，至少支持：
   - `KEEP`
   - `GENERICIZE`
   - `PERSONA_SLOT`
7. 替换必须可恢复，禁止生成无法映射回真实值的自由文本；
8. 当前阶段优先保护**文本型 PII**，不把头像、二维码、复杂视觉目标识别列为首轮刚需。

---

## 3. 采用的最小改动实现策略

### 3.1 不做的事情

为保证框架尽快落地，本轮不做以下高风险改造：

- 不拆成微服务；
- 不引入异步任务队列；
- 不先上数据库重型持久化；
- 不把 `DEmodel` 直接实现成训练好的端侧模型；
- 不强依赖页面语义理解、App 类型识别、图标语义解析；
- 不在第一版中追求最优隐私效果，而是先保证闭环跑通。

### 3.2 先做的事情

优先完成以下保守但可落地的能力：

1. **领域模型统一化**：把 OCR 结果、PII 实体、策略动作、映射关系全部结构化；
2. **接口先行**：先定义抽象接口，再写具体实现；
3. **模式可切换**：同模块支持 `rule_based / rule_ner_based / label_only / label_persona_mixed` 等；
4. **会话状态可维护**：同一 `session_id` 下保持 persona 与映射稳定；
5. **闭环优先**：保证 `API_1 -> 云端 -> API_2` 能全程跑通；
6. **回归测试可执行**：每轮都有单元测试与最小集成测试。

---

## 4. 推荐项目目录（Python 版本）

```text
privacyguard/
├─ pyproject.toml
├─ README.md
├─ configs/
│  ├─ default.yaml
│  ├─ detector.rule_based.yaml
│  ├─ detector.rule_ner_based.yaml
│  └─ decision.label_only.yaml
├─ data/
│  ├─ personas.sample.json
│  └─ pii_dictionary.sample.json
├─ src/
│  └─ privacyguard/
│     ├─ api/
│     │  ├─ dto.py
│     │  ├─ facade.py
│     │  └─ errors.py
│     ├─ application/
│     │  ├─ pipelines/
│     │  │  ├─ sanitize_pipeline.py
│     │  │  └─ restore_pipeline.py
│     │  └─ services/
│     │     ├─ session_service.py
│     │     ├─ replacement_service.py
│     │     └─ resolver_service.py
│     ├─ domain/
│     │  ├─ enums.py
│     │  ├─ models/
│     │  │  ├─ ocr.py
│     │  │  ├─ pii.py
│     │  │  ├─ persona.py
│     │  │  ├─ mapping.py
│     │  │  ├─ decision.py
│     │  │  ├─ render.py
│     │  │  └─ action.py
│     │  ├─ interfaces/
│     │  │  ├─ ocr_engine.py
│     │  │  ├─ pii_detector.py
│     │  │  ├─ persona_repository.py
│     │  │  ├─ mapping_store.py
│     │  │  ├─ decision_engine.py
│     │  │  ├─ rendering_engine.py
│     │  │  └─ restoration_module.py
│     │  └─ policies/
│     │     └─ constraint_resolver.py
│     ├─ infrastructure/
│     │  ├─ ocr/
│     │  │  └─ ppocr_adapter.py
│     │  ├─ pii/
│     │  │  ├─ rule_based_detector.py
│     │  │  ├─ rule_ner_based_detector.py
│     │  │  └─ gliner_adapter.py
│     │  ├─ persona/
│     │  │  └─ json_persona_repository.py
│     │  ├─ mapping/
│     │  │  ├─ in_memory_mapping_store.py
│     │  │  └─ json_mapping_store.py
│     │  ├─ decision/
│     │  │  ├─ label_only_engine.py
│     │  │  ├─ label_persona_mixed_engine.py
│     │  │  └─ de_model_engine.py
│     │  ├─ rendering/
│     │  │  ├─ prompt_renderer.py
│     │  │  └─ screenshot_renderer.py
│     │  └─ restoration/
│     │     └─ action_restorer.py
│     ├─ bootstrap/
│     │  ├─ factories.py
│     │  └─ registry.py
│     └─ utils/
│        ├─ image.py
│        ├─ text.py
│        └─ ids.py
└─ tests/
   ├─ unit/
   ├─ integration/
   └─ fixtures/
```

### 为什么采用这套结构

- `domain` 只放**抽象与数据模型**，不依赖具体实现；
- `infrastructure` 只放**具体适配器与实现**；
- `application` 负责串联业务流程；
- `api` 只暴露给外部系统可调用入口；
- `bootstrap` 负责按照配置装配具体实现；
- 避免模块之间横向直接 import 具体类，改为面向接口依赖。

---

## 5. 核心数据契约

## 5.1 API_1 入参

```python
SanitizeRequest(
    session_id: str,
    turn_id: int,
    prompt_text: str,
    screenshot: ImageLike,
    detector_mode: str = "rule_based",
    decision_mode: str = "label_only",
)
```

## 5.2 API_1 出参

```python
SanitizeResponse(
    sanitized_prompt_text: str,
    sanitized_screenshot: ImageLike,
    active_persona_id: str | None,
    replacements: list[ReplacementRecord],
    metadata: dict,
)
```

## 5.3 API_2 入参

```python
RestoreRequest(
    session_id: str,
    turn_id: int,
    cloud_text: str,
)
```

## 5.4 API_2 出参

```python
RestoreResponse(
    restored_text: str,
    restored_slots: list[RestoredSlot],
    metadata: dict,
)
```

## 5.5 关键领域对象

### OCRTextBlock
- `text`
- `bbox`
- `score`
- `line_id`
- `source = "screenshot"`

### PIICandidate
- `entity_id`
- `text`
- `normalized_text`
- `attr_type`
- `source` (`prompt` / `ocr`)
- `bbox`
- `confidence`
- `detector_mode`

### DecisionAction
- `candidate_id`
- `action_type` (`KEEP` / `GENERICIZE` / `PERSONA_SLOT`)
- `attr_type`
- `replacement_text`
- `persona_id`
- `reason`

### ReplacementRecord
- `session_id`
- `turn_id`
- `candidate_id`
- `source_text`
- `replacement_text`
- `attr_type`
- `action_type`
- `bbox`
- `persona_id`

---

## 6. 模块设计准则

## 6.1 OCR 模块
职责只限于：
- 接收截图；
- 输出结构化文本块列表。

禁止：
- 在 OCR 模块内做 PII 判定；
- 在 OCR 模块内写映射表；
- 在 OCR 模块内做策略决策。

## 6.2 PII Detector
职责只限于：
- 基于 prompt 与 OCR 文本识别候选隐私实体；
- 输出统一的 `PIICandidate`。

禁止：
- 直接决定替换成什么；
- 直接访问渲染或还原逻辑。

## 6.3 Persona Repository
职责只限于：
- 维护 persona profile；
- 提供按 persona_id / attr_type 的槽位查询；
- 提供暴露统计摘要读写接口。

禁止：
- 自行替换文本；
- 持有会话级临时状态。

## 6.4 Local Mapping Table
职责只限于：
- 保存本会话、本轮替换映射；
- 支撑恢复链路；
- 查询已有绑定关系。

禁止：
- 自行做决策；
- 修改 persona 仓库原始数据。

## 6.5 Decision Engine
职责只限于：
- 接收候选实体 + 会话状态 + 仓库摘要；
- 产出动作决策；
- 更新必要的 persona 绑定建议。

禁止：
- 直接操作图像；
- 直接写 prompt 字符串；
- 直接调用云端 Agent。

## 6.6 Rendering Engine
职责只限于：
- 按决策执行 prompt 文本替换；
- 按 bbox 执行图像局部覆盖与重绘；
- 产出新图文与替换记录。

禁止：
- 自己重新识别 PII；
- 自己改 persona 选择。

## 6.7 Restoration Module
职责只限于：
- 按映射表恢复云端返回文字；
- 输出恢复后的动作文本。

禁止：
- 自己新增替换关系；
- 在恢复阶段擅自切换 persona。

---

## 7. 配置与实现选择机制

统一通过配置选择模块实现，而不是写死依赖。

示例：

```yaml
ocr:
  provider: ppocr_v5

pii_detector:
  mode: rule_ner_based

decision_engine:
  mode: label_persona_mixed

mapping_store:
  type: in_memory

persona_repository:
  type: json
  path: data/personas.sample.json
```

要求：

1. `bootstrap/factories.py` 负责读取配置并创建实现；
2. `bootstrap/registry.py` 维护 `"mode" -> implementation` 映射；
3. 外层业务流程永远依赖接口，不依赖具体实现类。

---

## 8. 迭代总轮次（建议 6 轮）

本项目建议拆为 6 轮。理由：

- 少于 5 轮：Cursor 容易跨模块一次性生成过多代码，耦合过高；
- 多于 7 轮：拆分过细，反而增加上下文切换成本；
- 6 轮足够把“骨架 -> 模块 -> 闭环 -> 测试”完整覆盖。

### 第 1 轮：项目骨架与接口契约
目标：
- 创建目录结构；
- 定义领域模型、枚举、接口；
- 定义 API_1 / API_2 DTO；
- 建立工厂与注册机制；
- 不追求完整实现，只保证可导入、可实例化。

### 第 2 轮：OCR 与 PII 检测链路
目标：
- 实现 OCR 适配器接口；
- 实现 `rule_based` 与 `rule_ner_based` 检测器；
- 完成 prompt + OCR 联合产出 `PIICandidate`；
- 写基础测试。

### 第 3 轮：Persona 仓库与会话映射
目标：
- 完成 JSON Persona Repository；
- 完成 In-Memory / JSON Mapping Store；
- 支持 session 级 persona 绑定；
- 支持按轮写入替换记录与查询恢复线索。

### 第 4 轮：决策引擎与约束解析
目标：
- 实现 `label_only`；
- 实现 `label_persona_mixed`；
- 实现 `de_model_engine` 的规则驱动占位版本；
- 加入约束解析器，确保动作合法、可恢复。

### 第 5 轮：渲染引擎与还原闭环
目标：
- 完成 prompt 文本替换；
- 完成截图局部重绘；
- 完成 cloud_text 恢复；
- 打通替换与还原的最小闭环。

### 第 6 轮：API 整合、测试与交付
目标：
- 用 `sanitize_pipeline` 与 `restore_pipeline` 串起来；
- 完成端到端示例；
- 补足单元测试与集成测试；
- 完成 README、配置样例、假数据样例。

---

## 9. 每轮统一交付标准

无论哪一轮，Cursor 都必须满足以下输出要求：

1. 所有新增公共函数都有类型注解；
2. 关键类必须有 docstring；
3. 不允许出现循环 import；
4. 不允许把业务逻辑写进测试文件；
5. 不允许在接口层依赖具体实现；
6. 每轮至少补 1 组单元测试；
7. 若实现未完成，必须提供 `NotImplementedError` 的明确占位，而不是伪造完成。

---

## 10. Cursor 协作规则

为了提高 Cursor 多轮生成质量，建议每轮都遵守以下规则：

1. **只做当前轮内容**，不跨轮重构全项目；
2. **先列出将新增/修改的文件**，再动手生成；
3. **优先补内部实现，不改对外 DTO**；
4. 若必须修改接口，必须同步更新：
   - DTO
   - 抽象接口
   - 工厂装配
   - 测试
   - README 样例
5. 对于不确定的外部依赖（例如 PP-OCR、GLiNER 真正加载逻辑），先写适配器占位与清晰注释，不要阻塞整体框架。

---

## 11. 最终验收口径

当 6 轮全部完成时，项目至少应达到以下状态：

- 能通过统一 `facade` 调用 `API_1`；
- 能输出脱敏后的 prompt 与截图；
- 能记录替换映射；
- 能通过统一 `facade` 调用 `API_2`；
- 能把云端返回文本中的标签 / persona 替代值恢复为真实值；
- 能切换至少 2 种 detector 模式；
- 能切换至少 2 种 decision mode；
- 有基础样例数据与测试；
- 没有明显的高耦合反模式（如模块横向直接读写彼此内部状态）。

---

## 12. 建议你在 Cursor 中的实际使用方式

建议你每轮给 Cursor 的输入顺序如下：

1. 先贴本文件，让它理解全局约束；
2. 再贴对应轮次文件；
3. 再补一句：
   > 严格只实现本轮要求，不提前实现后续轮次，不要破坏既有接口。
4. 让 Cursor 先输出“计划修改文件列表”，确认后再生成代码。

这样更能控制 Cursor 不要一次性过度发挥。
