# 第 2 轮：OCR 与 PII 检测链路

## 可直接粘贴到 Cursor 的简短提示词

请在已完成项目骨架的基础上，只实现 **OCR 适配层** 与 **PII Detector 检测链路**，重点是把截图 OCR 结果和 prompt 文本统一转成 `PIICandidate`。  
严格不要实现 Decision、Rendering、Restoration 的完整逻辑，只补本轮需要的检测能力和测试。

---

## 本轮目标

把“输入 screenshot + prompt_text”转成“结构化 OCR 文本块 + 统一隐私候选实体列表”。

完成后至少支持：

- OCR 接口可工作（哪怕真实模型用适配器占位）；
- `rule_based` 模式可识别本地字典和规则命中的 PII；
- `rule_ner_based` 模式可在 `rule_based` 基础上挂接轻量 NER；
- prompt 与 OCR 均能产生 `PIICandidate`；
- 输出格式统一、可用于后续决策引擎。

---

## 必须遵守的约束

1. OCR 模块只负责识别文本块，不做隐私判断；
2. Detector 只负责识别候选，不做替换决策；
3. `llm_based` 只保留接口，不做默认实现；
4. 规则优先，NER 作为增强而非替代；
5. 所有候选都必须写明来源：
   - `prompt`
   - `ocr`
6. OCR / NER 外部依赖加载失败时，要有明确降级行为。

---

## 建议创建/修改的文件

- `src/privacyguard/infrastructure/ocr/ppocr_adapter.py`
- `src/privacyguard/infrastructure/pii/rule_based_detector.py`
- `src/privacyguard/infrastructure/pii/rule_ner_based_detector.py`
- `src/privacyguard/infrastructure/pii/gliner_adapter.py`
- `src/privacyguard/application/services/resolver_service.py`  （若需要做文本归一化与冲突去重）
- `src/privacyguard/utils/text.py`
- `src/privacyguard/utils/image.py`
- `data/pii_dictionary.sample.json`
- `configs/detector.rule_based.yaml`
- `configs/detector.rule_ner_based.yaml`

- `tests/unit/test_rule_based_detector.py`
- `tests/unit/test_rule_ner_based_detector.py`
- `tests/unit/test_ppocr_adapter_contract.py`

---

## OCR 适配层要求

### PP-OCR 适配器只暴露统一接口

实现思路：

- `PPOCREngineAdapter` 对外只实现 `extract(image) -> list[OCRTextBlock]`
- 内部真实模型加载可以先采用两层设计：
  1. `real backend`（未来接入真实 PPOCR）
  2. `mock/fallback backend`（当前无模型时返回占位结果或抛清晰异常）

### OCR 输出统一格式

每个文本块至少包含：

- `text`
- `bbox`
- `score`
- `line_id`
- `source = "screenshot"`

### 图像输入兼容性

允许以下输入之一：

- `PIL.Image.Image`
- `numpy.ndarray`
- 文件路径（如果你认为有必要，可作为辅助支持）

但对外接口要尽量统一，避免多处判断。

---

## rule_based 检测器要求

至少支持下列来源：

1. **本地隐私数据库精确匹配**
   - 从 `data/pii_dictionary.sample.json` 读取
   - 支持姓名、手机号、地址、邮箱、身份证号等

2. **正则规则**
   - 手机号
   - 邮箱
   - 验证码（可使用较保守规则）
   - 地址关键词片段（保守匹配，避免过拟合）

3. **prompt 文本检测**
4. **OCR 文本块检测**

### 规则实现要求

- 先做文本归一化（全半角、空格、大小写等）
- 同一文本命中多条规则时要做去重
- 同一位置若同时被数据库和正则命中，可提升置信度
- 输出 `PIICandidate.confidence` 时采用简单可解释策略即可

---

## rule_ner_based 检测器要求

该模式在 `rule_based` 基础上增强。

建议流程：

1. 先跑 `rule_based`
2. 对未命中的文本片段或全部文本再交给 GLiNER 轻量模型
3. 将 GLiNER 输出映射到统一的 `PIIAttributeType`
4. 去重合并

### GLiNER 适配要求

- 单独封装 `GLiNERAdapter`
- 若依赖不存在，允许：
  - 记录 warning
  - 自动退化为纯 `rule_based`
- 不要把 HuggingFace 模型加载逻辑散落在业务代码中

---

## 数据字典建议格式

`data/pii_dictionary.sample.json` 可示例为：

```json
{
  "name": ["张三", "李四"],
  "phone": ["13800138000"],
  "email": ["demo@example.com"],
  "address": ["北京市海淀区XX路"]
}
```

实现时请支持从该结构读入并构造匹配集合。

---

## 冲突与去重规则

请至少实现以下处理：

1. 同一文本完全相同且 attr_type 一致 -> 合并
2. 同一文本被不同来源命中 -> 保留高置信度，并把来源附加到 metadata
3. OCR 文本块与 prompt 文本可重复存在，但来源必须保留
4. 尽量不要让一个候选同时输出多个互斥 attr_type

---

## 测试要求

至少覆盖：

### rule_based
- 能识别字典中的姓名
- 能识别手机号和邮箱
- prompt 与 OCR 两种来源都能出候选
- 重复命中能去重

### rule_ner_based
- 当 GLiNER 不可用时能优雅降级
- 当 GLiNER 返回结果时可合并到最终候选列表

### OCR adapter
- 返回值符合 `OCRTextBlock` 契约
- 非法输入有清晰异常

---

## 禁止事项

- 不要在 detector 中写入 mapping store；
- 不要在 detector 中决定用哪个 persona；
- 不要把 bbox 绘制逻辑写进 OCR 或 detector；
- 不要为了测试方便把所有东西写成全局函数；
- 不要把“云端 LLM 抽取”作为默认路径。

---

## 完成后的自检输出

请在生成代码后简要说明：

1. 当前已经支持哪些 attr_type；
2. OCR 适配器是“真实实现、半占位、还是纯占位”；
3. GLiNER 失败时的降级策略是什么；
4. 当前还缺哪些检测增强点留待后续。
