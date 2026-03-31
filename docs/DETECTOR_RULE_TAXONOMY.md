# Detector Rule Taxonomy

## 1. 结论先行

当前 PrivacyGuard 的中英文识别规则，真实形态不是“两套完全独立规则”，也不是“一套完全不分语言的规则”，而是：

- 一套共享主干规则
- 一部分中文特化规则
- 一部分英文特化规则
- 一层 OCR 场景专用规则

更准确地说，当前 `locale_profile` 是 **软分流**，不是 **硬隔离**：

- `zh_cn` / `en_us` / `mixed` 会影响一部分 regex、姓名启发式、机构后缀、地址解析和 OCR 语义规则
- 但字段标签、词典、很多 validator、本地 session 复用、OCR label-value 规则，其实仍是共享或双语共用的

因此最符合奥卡姆剃刀原则的整理方式不是“继续拆更多独立语言规则”，而是：

- 保留一套共享主干
- 把语言差异收敛在少数 locale-aware 子模块里
- 只在高收益、低歧义的地方加语言专属规则

---

## 2. 分类标尺


| 层级         | 定义                         | 典型特征                                        | 处理原则            |
| ---------- | -------------------------- | ------------------------------------------- | --------------- |
| `S+ 极强`    | 明确、稳定、强约束、误检极低             | 词典精确命中、强结构字段、强格式 regex                      | 必须保留，优先级最高      |
| `S 高准确强`   | 适用面广，准确率高，但仍需 validator 护栏 | 字段标签、强结构地址、强机构后缀                            | 保留为主，不轻易扩展      |
| `A 普通强`    | 适用面较广，靠上下文或词表增强            | 自报姓名、地理词典、英文姓名词典                            | 可以保留，但要严格限边界    |
| `B 普通`     | 场景有效，但容易受噪声影响              | 地址碎片、姓名片段、OCR standalone                    | 只做补召回，不应主导识别    |
| `C 定向`     | 只对特定场景有效                   | OCR 邻接、页面 remap、preview/time 抑制             | 只在目标场景启用        |
| `D 弱 / 兜底` | 为保守召回而存在，歧义高               | generic number、generic masked text、过宽 alnum | 不新增同类规则，必要时还应收紧 |


---

## 3. 规则总图

### 3.1 共享主干

这些规则不是中文专属，也不是英文专属，而是当前 detector 的共同骨架。


| 层级   | 规则族                           | 当前实现                                                                     | 说明                                                                           |
| ---- | ----------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `S+` | `session dictionary`          | 历史 `ReplacementRecord` 聚合，优先级最高                                          | 同 session 已见过的真实值直接复用，是最强证据之一                                                |
| `S+` | `local dictionary`            | `privacy_repository -> compiled dictionary index`                        | 本地真实档案词典命中稳定，支持 alias、结构化 name、结构化 address                                   |
| `S`  | 字段标签规则                        | `_FieldLabelSpec` + `_build_context_rules()`                             | `name / address / phone / email / organization / id ...` 共用一套标签系统，关键词本身是中英混排 |
| `S`  | OCR label-value 规则            | `_collect_ocr_label_adjacency_candidates()`                              | 与字段标签同源，但增加 OCR 几何关系，是 OCR 表单场景的强规则                                          |
| `S`  | 共用格式 regex                    | `email / card / bank_account / passport / time` 等                        | 语言无关或弱语言相关，应继续共用，不必拆两套                                                       |
| `S`  | validator 主干                  | `_is_*_candidate()`、`_address_confidence()`、`_organization_confidence()` | 不是规则来源，但是真实护栏，决定哪些命中能进下游                                                     |
| `A`  | 地址总管线                         | `seed -> grow -> trim -> classify -> emit`                               | 地址框架本身应保持共享，只让 component parser 按 locale 分化                                  |
| `A`  | protected spans + shadow text | `_protected_spans_from_candidates()` + `_build_shadow_text()`            | 不是识别规则，但它决定多层规则如何不互相打架                                                       |
| `C`  | OCR 页级扫描与 remap               | `_scan_ocr_page()`                                                       | 先整页扫描，再 remap 回 block，是 OCR 召回的关键基础设施                                        |
| `C`  | OCR 姓名/地址后处理                  | `_refine_ocr_name_candidate()`、`_derive_address_block_candidates()`      | 只对截图场景有意义，不能视为通用文本规则                                                         |
| `D`  | generic number                | `_collect_generic_number_hits()`                                         | 只做兜底，不应继续扩张更多“弱数字规则”                                                         |
| `D`  | generic masked text           | `_collect_masked_text_hits()`                                            | 只适合保守补漏，不应成为主要识别手段                                                           |


### 3.2 locale 的真实边界

当前代码里的 locale 不是严格隔离：

- `zh_cn` 仍能识别带英文字段标签的 `Name:`、`Address:`
- `en_us` 仍能识别中文字段标签 `姓名:`、`电话:`、`地址:`
- 这说明“字段标签层”实际是共享的双语标签体系
- 真正更强依赖 locale 的，是 free-text 层、部分 regex 层、地址 parser 和 OCR 语义层

因此：

- 不建议把字段标签规则再拆成“纯中文 context 规则”和“纯英文 context 规则”两大套
- 应继续保留“共享标签系统 + locale 特化 validator / parser”的架构

---

## 4. 中文规则分级

这里只列中文特征明显、或对中文场景最重要的规则。共享主干不在此重复展开。

### 4.1 `S+ 极强`


| 规则族                 | 当前实现                                                     | 说明                   |
| ------------------- | -------------------------------------------------------- | -------------------- |
| 中国身份证 regex         | `regex_cn_id_18`、`regex_cn_id_15`、`regex_cn_id_*_spaced` | 结构强、误检低，是中文最强的格式规则之一 |
| 中国手机号 regex         | `regex_phone_mobile`、`regex_phone_mobile_sep`            | 中文移动号码形状稳定，覆盖面和准确率都高 |
| 中文本地 / session 词典命中 | 结构化 `name`、结构化 `address`、别名展开                            | 词典本身是共享机制，但中文在这里收益极高 |


### 4.2 `S 高准确强`


| 规则族                   | 当前实现                                                  | 说明               |
| --------------------- | ----------------------------------------------------- | ---------------- |
| 中文字段标签规则              | `姓名 / 地址 / 手机 / 电话 / 证件 / 银行卡 / 单位 ...`               | 表单、资料页、清单页中极稳    |
| 中文 OCR label-value 规则 | `ocr_label_`*                                         | 截图表单、证件、订单页中很强   |
| 中文地址组件识别              | `province / city / district / road / building / room` | 地址后缀、门牌号、行政层级信号强 |
| 中文地址总候选               | `context_address_field` + 地址管线分类                      | 对“明确写成地址”的文本很稳   |
| 中文机构强后缀               | `公司 / 集团 / 银行 / 医院 / 大学 / 法院 / 研究院 ...`               | 适用面广，误检可控        |


### 4.3 `A 普通强`


| 规则族       | 当前实现                                   | 说明                          |
| --------- | -------------------------------------- | --------------------------- |
| 中文自报姓名    | `我叫 / 名叫 / 叫做 / 我的名字是`                 | 社交、聊天、填表描述里常见               |
| 中文敬称姓名    | `张三先生 / 李四老师 / 王五医生`                   | 准确率较高，但依赖称谓名单               |
| 中文地名词典    | `data/scanner_lexicons/china_geo_lexicon.json` + Aho matcher | 对 location clue 很有效         |
| 中文地理后缀片段  | `省 / 市 / 区 / 路 / 街 / 小区 / 大厦 ...`      | 能补地址 / 地点碎片召回               |
| 中文地址 seed | `address_seed_*`                       | 是地址管线入口，不应再并行造一套新中文地址 regex |


### 4.4 `B 普通`


| 规则族      | 当前实现                                           | 说明                         |
| -------- | ---------------------------------------------- | -------------------------- |
| 中文通用姓名片段 | `heuristic_name_fragment`                      | 依赖姓氏表、长度、边界、上下文，易受语义噪声影响   |
| 中文地址碎片   | `address_component_*`                          | 对多粒度地址有用，但本质是补充候选，不应单独抬高权重 |
| 中文地名碎片   | `heuristic_geo_lexicon`、`heuristic_geo_suffix` | 对地点敏感，但歧义高于完整地址            |


### 4.5 `C 定向`


| 规则族                 | 当前实现                                     | 说明                |
| ------------------- | ---------------------------------------- | ----------------- |
| 中文 OCR 纵向 / 横向标签值推断 | OCR 几何打分 + label adjacency               | 只对 OCR 表单 / 清单强   |
| 中文 OCR 姓名场景修正       | preview / time metadata / UI label 抑制    | 主要解决聊天列表、卡片页误识别   |
| 中文 masked address   | `_looks_like_masked_address_candidate()` | 有价值，但只适合特定脱敏文本    |
| 复姓支持                | `_COMMON_COMPOUND_SURNAMES`              | 必要但窄场景，不属于普适召回扩张点 |


### 4.6 `D 弱 / 兜底`


| 规则族                 | 当前实现                         | 说明                        |
| ------------------- | ---------------------------- | ------------------------- |
| generic number      | `regex_generic_number`       | 只适合保守兜底                   |
| generic masked text | `heuristic_masked_text`      | 只适合高度保守的“这段像被打码了”         |
| 弱地理碎片自由匹配           | 部分 `heuristic_geo_suffix` 命中 | 一旦继续扩张，很容易把普通地名 / 活动名拉成隐私 |


### 4.7 中文侧建议保留的最小强规则集

- `session dictionary`
- `local dictionary`
- 中文字段标签
- 中国手机号 regex
- 中国身份证 regex
- 中文地址总管线
- 中文机构强后缀
- 中文 OCR label-value

这套已经覆盖绝大多数高价值中文结构化场景，不应再额外堆更多弱启发式。

---

## 5. 英文规则分级

这里只列英文特征明显、或对英文场景最重要的规则。共享主干不在此重复展开。

### 5.1 `S+ 极强`


| 规则族                 | 当前实现                                                   | 说明                  |
| ------------------- | ------------------------------------------------------ | ------------------- |
| US 电话 regex         | `regex_phone_us`、`regex_phone_us_masked`               | 英文场景最核心的格式规则之一      |
| 英文本地 / session 词典命中 | 结构化 `name`、结构化 `address`                               | 英文地址与英文姓名在词典态时非常稳   |
| 英文结构化地址展开           | `street / building / city / province / postal_code` 展开 | 对地址实体的稳定复用和替换闭环价值很高 |


### 5.2 `S 高准确强`


| 规则族                   | 当前实现                                                                    | 说明                      |
| --------------------- | ----------------------------------------------------------------------- | ----------------------- |
| 英文字段标签规则              | `name / first name / last name / address / phone / email / company ...` | 表单、profile、resume 页面中很强 |
| 英文 OCR label-value 规则 | `ocr_label_*`                                                           | OCR 表单和资料卡中准确率高         |
| 英文地址强结构规则             | `street suffix + number + state/zip + unit`                             | 当前按 `en_us` 设计，适用面广     |
| 英文机构强后缀               | `Inc / LLC / Ltd / Bank / Hospital / University ...`                    | 误检可控，收益高                |


### 5.3 `A 普通强`


| 规则族      | 当前实现                                            | 说明               |
| -------- | ----------------------------------------------- | ---------------- |
| 英文自报姓名   | `my name is / i am / i'm / this is`             | 对对话、资料说明场景有效     |
| 英文敬称姓名   | `Mr. / Ms. / Dr. / Prof.`                       | 精度较高，但适用面有限于称谓文本 |
| 英文姓名词典支持 | given name / surname lexicon 分层加权               | 是英文独立姓名判定的重要增强   |
| 英文地理词表支持 | US state name / state code / tiered geo lexicon | 对英文地址与地点判定是有效支撑  |


### 5.4 `B 普通`


| 规则族                | 当前实现                                               | 说明                                            |
| ------------------ | -------------------------------------------------- | --------------------------------------------- |
| 英文 standalone name | `heuristic_name_fragment_en`                       | 必须结合 name lexicon、PII context、geo 排斥条件，单独看并不稳 |
| 英文地址组件             | `PO Box / Apt / Suite / Unit / Floor / Room`       | 对地址拆解和下游替换很有用，但本质上是地址子结构                      |
| 英文弱机构后缀            | `tech / studio / media / systems / consulting ...` | 有召回价值，但歧义明显高于强后缀                              |


### 5.5 `C 定向`


| 规则族                               | 当前实现                                        | 说明                   |
| --------------------------------- | ------------------------------------------- | -------------------- |
| 英文 OCR standalone name            | OCR block 级独立姓名                             | 只适合 OCR 页面局部块值很干净的情况 |
| 英文 OCR preview / time metadata 抑制 | `right_time_metadata`、`next_line_preview` 等 | 专门压制聊天 UI、消息列表误识别    |
| 英文 OCR 邻接值链                       | right / down neighbor scoring               | 对表单、订单、卡片页有效，非通用文本规则 |


### 5.6 `D 弱 / 兜底`


| 规则族                 | 当前实现                           | 说明                      |
| ------------------- | ------------------------------ | ----------------------- |
| generic number      | `regex_generic_number`         | 与中文一样，只能做兜底             |
| broad alnum 证件类规则   | 如 `regex_driver_license_alnum` | 过宽，容易与普通字母数字串或上下文串联发生交叉 |
| generic masked text | `heuristic_masked_text`        | 适合作保守补漏，不适合扩张           |


### 5.7 英文侧建议保留的最小强规则集

- `session dictionary`
- `local dictionary`
- 英文字段标签
- US 电话 regex
- 英文地址强结构规则
- 英文机构强后缀
- 英文 OCR label-value
- 英文结构化地址展开与地址管线

这套已经能覆盖 profile、resume、billing、shipping、order、hotel、OCR 表单等大多数高价值英文结构化场景。

---

## 6. 分别识别 vs 一起识别

### 6.1 适合分别识别的部分

这些规则应该继续保留 locale-aware 分支，而不是强行合并：

- 中文手机号 vs US 电话
- 中文身份证 vs 英文证件类弱格式
- 中文姓名判定 vs 英文姓名判定
- 中文地址 parser vs 英文地址 parser
- 中文机构后缀 vs 英文机构后缀
- OCR 英文 preview / time metadata 语义抑制

原因很简单：

- 语言形态差异大
- 误检模式不同
- 不同 locale 的强信号完全不同

### 6.2 适合一起识别的部分

这些规则更适合继续共用主干：

- `session dictionary`
- `local dictionary`
- 双语字段标签体系
- OCR label-value 邻接框架
- email / card / bank_account / passport / time 等强格式 regex
- protected spans / shadow text / candidate resolver
- 地址总管线框架
- validator 外层框架

原因是：

- 这些规则的差异主要在词表、parser、阈值，不在“流程骨架”
- 拆两套只会重复维护
- 不符合奥卡姆剃刀原则

### 6.3 当前最合理的架构表述

最推荐的表述不是：

- “中文 detector 一套，英文 detector 一套”

而是：

- “共享 detector 主干 + locale 特化规则簇”

---

## 7. 冗余分析

### 7.1 看起来重复，但实际上不冗余

#### `session dictionary` vs `local dictionary` vs `rules`

这三者是优先级分层，不是重复：

- `session` 解决同会话复用
- `local` 解决真实档案命中
- `rules` 解决未知值检测

这是必要分层，不能因为都“能识别出同一实体”就误判为冗余。

#### 字段标签规则 vs OCR label-value 规则

语义相同，但输入形态不同：

- 文本场景靠字符串边界
- OCR 场景还需要几何邻接、上下结构、block 组合

这不是重复实现，而是同一规则语义在不同输入模态上的必要投影。

#### 页级 OCR 扫描 vs block 级地址候选派生

这两个也不是重复：

- 页级扫描负责召回跨 block 实体
- block 级派生负责后续截图替换对齐

前者面向检测，后者面向渲染。

#### 地址字段标签 vs 地址管线

文档上容易看起来像重复，但当前代码里：

- `ADDRESS` 已经不走普通 context rule 主路径
- 地址字段标签更多是地址 seed / strong clue
- 真正的地址候选输出由专门地址管线统一完成

这其实已经是“去冗余后的收敛形态”。

### 7.2 真正需要警惕的重叠

#### 高精度数字规则 vs generic number

这是有意保留的层级重叠：

- 先让 `phone / id / card / bank_account / passport / driver_license` 抢占
- 剩余再给 `generic number`

不需要再新增更多“中间层弱数字规则”。

#### 姓名规则族内部重叠

当前姓名相关规则有：

- 词典姓名
- 字段标签姓名
- 自报姓名
- 敬称姓名
- 通用姓名片段
- OCR standalone name

这已经足够完整。继续新增更多 free-text 姓名启发式，大概率只会带来误检，不会带来成比例收益。

#### 地址规则族内部重叠

当前地址已经同时有：

- 字段标签 seed
- 地址组件 parser
- 地址分类器
- 地址碎片候选
- geo fragment

这套层级也已够用。继续再补“另一套英文地址 regex 家族”或“另一套中文地址碎片 regex 家族”，大概率属于重复建设。

### 7.3 当前最像“应收紧”的弱规则

#### `regex_driver_license_alnum`

这条规则过宽：

- 它允许较宽泛的字母数字串
- 容易与普通文本、电话串、上下文拼接后残片发生交叉
- 它更像“弱证件候选”，不是“强驾驶证规则”

建议将其视为 `D 弱` 而不是 `S/A`：

- 不要围绕它继续扩规则
- 后续若做收敛，优先考虑收紧它而不是新增别的证件弱规则

---

## 8. 奥卡姆剃刀式收敛建议

### 8.1 应明确保留的强规则骨架

- `session dictionary`
- `local dictionary`
- 双语字段标签
- 强格式 regex
- locale-aware 地址管线
- locale-aware 姓名判定
- 机构强后缀
- OCR label-value 框架

### 8.2 不建议新增的规则方向

- 新的弱数字规则
- 新的弱机构后缀
- 新的自由文本姓名触发词
- 与现有地址管线并行的第二套地址 regex 家族
- 与现有 OCR 邻接框架并行的第二套 OCR 表单 heuristic

### 8.3 如果后续必须继续增强，优先顺序应该是

1. 扩 locale profile，而不是往 `mixed` 里堆更多全局规则
2. 扩词典质量，而不是扩弱启发式
3. 扩 validator 与负例抑制，而不是扩匹配器数量
4. 扩 OCR 场景规则时，优先复用现有 label / geometry 框架

---

## 9. 最终建议

如果目标是“高准确度、强规则优先”，当前最合理的组织方式是：

- 一份共享主干规则清单
- 一份中文特化规则清单
- 一份英文特化规则清单
- 一份弱规则 / 定向规则观察名单

而不是：

- 为中英文各写一整套从头到尾完全对称的规则体系

一句话概括：

> 当前最应该保留的是“共享主干 + 少量高价值 locale 特化”，最应该避免的是“为了覆盖更多边角场景而继续堆叠弱规则”。

