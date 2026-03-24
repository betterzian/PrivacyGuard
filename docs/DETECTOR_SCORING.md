# PrivacyGuard Detector 打分规则

## 1. 文档范围

本文档只描述当前仓库中 `rule_based` detector 的 `PIICandidate.confidence` 计算方式。

本文档不讨论：

- `de_model` 或 `label_*` decision 的动作分数
- OCR 引擎本身输出的 `OCRTextBlock.score`
- restore 侧逻辑

需要先明确：

- detector 的 `confidence` 是**规则强度分**
- detector 的 `confidence` **不是概率校准值**
- 当前实现**没有统一公式**
- 当前实现是**按规则来源分别给分**

核心代码位于：

- `privacyguard/infrastructure/pii/rule_based_detector.py`

---

## 2. 两类“分”

当前链路里容易混淆的分有两类：

### 2.1 候选分：`PIICandidate.confidence`

这是 detector 给候选实体打的分。

它用于：

- detector 内部候选保留与合并
- 后续 policy context 的 `det_conf_bucket`
- session alias 复用等下游逻辑

### 2.2 OCR 分：`OCRTextBlock.score`

这是 OCR 模块给文本块的质量分，不是 detector 算出来的。

它用于：

- OCR 局部质量判断
- `ocr_local_conf_bucket`
- decision 特征中的页面 / block 质量信号

因此：

- `confidence` 高，不代表 OCR 一定清晰
- OCR score 高，也不代表 detector 命中一定强

---

## 3. detector 的收集顺序

当前 detector 不是把所有规则同时跑完后再统一排序，而是按“强规则优先”的顺序逐层推进。

当前顺序是：

1. `session dictionary`
2. `local dictionary`
3. `context`
4. `regex`
5. `organization`
6. `name`
7. `address`
8. `geo`
9. `generic number`
10. `masked text`

关键点：

- 前面阶段命中的高置信 span 会进入 `protected_spans`
- 后面较弱阶段通常会避开这些 span
- 因此最终保留下来的分，常常是“最先命中的强规则分”

这也是很多文本不会在多个规则之间来回竞争的原因。

---

## 4. 打分原则

虽然当前代码里没有单独的评分设计文档，但从实现可以明确看出分数遵循以下规律：

- 明确、结构强、歧义小的规则，分更高
- 同一类型中，完整格式比分隔符 / OCR 噪声 / 脱敏版本更高
- 需要上下文推断的启发式分更低
- 很弱或不成立时，直接返回 `0.0`，表示拒绝命中
- 存在多规则交叉支撑时，会在高分基础上做小幅加分
- 存在类型冲突时，不是简单降一点，而是降级成更保守的 `OTHER`

可以把当前分值理解为：

- `0.95+`：极强命中
- `0.90` 左右：强命中
- `0.80-0.89`：结构明确但带噪声或有轻微歧义
- `0.70-0.79`：较弱但仍可接受
- `0.60` 左右：兜底弱信号
- `0.0`：当前规则判定不成立

这只是工程语义分层，不是统计意义上的 calibrated probability。

---

## 5. 固定分来源

## 5.1 词典命中

词典命中是当前最强的一类证据。

| 来源 | `matched_by` | 分数 |
| --- | --- | ---: |
| 本地词典，带 `entity_id` 的词条 | `dictionary_local` | `0.99` |
| 本地词典，普通词条 | `dictionary_local` | `0.98` |
| session 历史词条 | `dictionary_session` | `0.97` |
| 同 span 命中多个 binding key 的歧义词条 | `*_ambiguous` | 取命中项中的 `max(confidence)` |

说明：

- 词典分数高，是因为它对应已知实体或历史真值
- 歧义词条虽然保留高分，但会丢失确定实体 binding，只保留“这是敏感项”的信息

## 5.2 字段上下文规则

字段上下文规则本质上是：

```text
字段关键词 + 值
```

例如：

- `姓名: 张三`
- `地址：江宁区...`
- `身份证号 320...`

这类证据强于 free-text 启发式，因此基础分较高。

| 类型 | `matched_by` | 基础分 |
| --- | --- | ---: |
| `NAME` | `context_name_field` | `0.90` |
| `ADDRESS` | `context_address_field` | `0.90` |
| `PHONE` | `context_phone_field` | `0.88` |
| `CARD_NUMBER` | `context_card_field` | `0.90` |
| `BANK_ACCOUNT` | `context_bank_account_field` | `0.90` |
| `PASSPORT_NUMBER` | `context_passport_field` | `0.90` |
| `DRIVER_LICENSE` | `context_driver_license_field` | `0.90` |
| `EMAIL` | `context_email_field` | `0.90` |
| `ID_NUMBER` | `context_id_field` | `0.90` |
| `OTHER` | `context_other_field` | `0.76` |
| `ORGANIZATION` | `context_organization_field` | `0.86` |

额外修正：

- 如果字段值本身没过 validator，但被识别为 `masked address`，则：
  - `matched_by` 变成 `*_masked`
  - `confidence = max(0.62, base_confidence - 0.14)`

因此：

- `context_address_field` 默认是 `0.90`
- `context_address_field_masked` 可能是 `0.76`

## 5.3 自报姓名与敬称姓名

这是 detector 中两条单独的姓名规则。

| 规则 | `matched_by` | 分数 |
| --- | --- | ---: |
| 中文自我介绍，如“我叫/名叫/叫做/我的名字是” | `context_name_self_intro` | `0.78` |
| 英文自我介绍，如 `my name is` | `context_name_self_intro_en` | `0.76` |
| 敬称姓名，如“张老师/李总” | `regex_name_honorific` | `0.72` |

说明：

- 这些规则强于纯碎片启发式
- 但弱于明确字段上下文
- 敬称姓名之所以只有 `0.72`，是因为敬称片段在中文里歧义明显更大

## 5.4 结构型 regex 规则

这类规则使用固定先验分，不依赖复杂上下文。

### 电话

| 规则 | `matched_by` | 分数 |
| --- | --- | ---: |
| 标准手机号 | `regex_phone_mobile` | `0.86` |
| 带分隔符手机号 | `regex_phone_mobile_sep` | `0.84` |
| 座机 | `regex_phone_landline` | `0.78` |
| 脱敏手机号 | `regex_phone_masked` | `0.82` |
| 前缀保留、后段全掩码手机号 | `regex_phone_masked_prefix_only` | `0.80` |

### 卡号 / 银行账号 / 护照 / 驾驶证

| 类型 | 规则 | 分数 |
| --- | --- | ---: |
| `CARD_NUMBER` | `regex_card_number` | `0.83` |
| `CARD_NUMBER` | `regex_card_number_masked` | `0.81` |
| `BANK_ACCOUNT` | `regex_bank_account_number` | `0.78` |
| `BANK_ACCOUNT` | `regex_bank_account_masked` | `0.76` |
| `PASSPORT_NUMBER` | `regex_passport_number` | `0.80` |
| `PASSPORT_NUMBER` | `regex_passport_number_masked` | `0.76` |
| `DRIVER_LICENSE` | `regex_driver_license_12` | `0.74` |
| `DRIVER_LICENSE` | `regex_driver_license_15` | `0.76` |
| `DRIVER_LICENSE` | `regex_driver_license_alnum` | `0.76` |
| `DRIVER_LICENSE` | `regex_driver_license_masked` | `0.74` |

### 邮箱

| 规则 | `matched_by` | 分数 |
| --- | --- | ---: |
| 标准邮箱 | `regex_email` | `0.85` |
| 带空格邮箱 | `regex_email_spaced` | `0.82` |
| OCR 噪声邮箱 | `regex_email_ocr_noise` | `0.81` |
| 脱敏邮箱 | `regex_email_masked` | `0.79` |

### 身份证

| 规则 | `matched_by` | 分数 |
| --- | --- | ---: |
| 18 位身份证 | `regex_cn_id_18` | `0.92` |
| 18 位带分隔符 | `regex_cn_id_18_spaced` | `0.90` |
| 15 位身份证 | `regex_cn_id_15` | `0.82` |
| 15 位带分隔符 | `regex_cn_id_15_spaced` | `0.80` |
| 脱敏身份证 | `regex_cn_id_masked` | `0.86` |
| 仅前缀保留的脱敏身份证 | `regex_cn_id_masked_prefix_only` | `0.84` |

### 时间

| 规则 | `matched_by` | 分数 |
| --- | --- | ---: |
| `HH:MM` / `HH:MM:SS` | `regex_time_clock` | `0.96` |

观察：

- 同一类型里，分值通常按“完整格式 > 分隔符 / 噪声 > 脱敏 / 弱版本”递减
- 身份证和时间这类结构极强的模式分最高

## 5.5 通用数字兜底

当一段文本没有被识别成更具体的高精度数字类型，但看起来仍是值得保护的数字串时，会走通用数字兜底。

规则：

- 至少 4 位数字
- 允许夹少量符号

分值：

- 数字位数 `>= 7`：`0.98`
- 数字位数 `4-6`：`0.94`

这类分很高，因为它的目标不是“准确识别具体证件类型”，而是“高召回地保守保护数字型敏感信息”。

## 5.6 重复掩码文本兜底

对 `***`、`###`、`●●●` 这类被整段遮住的文本，当前还有一层较弱兜底。

| 类型 | 条件 | 分数 |
| --- | --- | ---: |
| `OTHER` | 视觉掩码字符连续重复 | `0.62` |
| `OTHER` | 字母掩码字符连续重复 | `0.56` |

这类规则只在弱兜底阶段才会触发。

## 5.7 OCR 派生地址碎片

当 detector 先识别出跨多个 OCR block 的地址后，会派生出单 block 地址碎片。

它的分数不是重新计算，而是从父候选衰减而来：

```text
max(0.4, parent_confidence - 0.08)
```

这类分数的意图是：

- 保留块级地址信息
- 但不让派生片段比分段原始命中更强

---

## 6. 动态分来源

## 6.1 姓名碎片：`heuristic_name_fragment`

姓名碎片不是固定分，而是由 `_generic_name_confidence(...)` 动态计算。

它主要看：

- 左右是否是中文边界
- 左侧是否有姓名上下文支持词
- 右侧是否跟地理 / 活动词
- 是否为独立成词
- 是否处于 OCR 场景
- 当前 `ProtectionLevel`

典型返回值如下：

| 场景 | 分数 |
| --- | ---: |
| 左侧有强姓名上下文，右侧边界干净 | `0.94` |
| 右侧是地理 / 活动词 | `0.92` |
| `WEAK` 保护级别下的上述两类强命中 | `0.96` |
| `STRONG` 下整段几乎就是一个独立姓名 | `0.90` |
| `STRONG` + OCR 小窗口近似独立姓名 | `0.86` |
| 其余不成立 | `0.0` |

这里 `0.0` 的含义是：

- 这条启发式认为它不是一个可接受的姓名命中
- 不是“低分保留”

## 6.2 地名 / 地址碎片：`heuristic_geo_lexicon` / `heuristic_geo_suffix`

地名碎片的分数由 `_geo_fragment_confidence(...)` 动态计算。

它主要看：

- 是否来自内置地名词典
- 命中的左右边界是否“开”
- 右侧是否跟地理 / 活动词
- 右侧是否紧跟数字
- 当前识别类型是 `ADDRESS` 还是 `LOCATION_CLUE`
- 当前 `ProtectionLevel`

典型返回值如下：

| 场景 | builtin token | generic suffix |
| --- | ---: | ---: |
| 整段就是命中值 | `0.96` | `0.90` |
| 左右边界都开 | `0.96` | `0.90` |
| 右侧是地理 / 活动词 | `0.94` | `0.88` |
| 右侧是数字 | `0.92` | `0.86` |
| 地址型片段，单边界较开 | `0.90` | `0.82` |
| 地址型片段，边界更挤，`STRONG` | `0.76` | `0.72` |
| 地址型片段，边界更挤，`BALANCED` | `0.72` | `0.66` |
| 弱 `LOCATION_CLUE`，仅一侧开 | `0.86` | `0.78` |
| 更弱但 `STRONG` 允许保守收下 | `0.72` | `0.72` |
| 其余不成立 | `0.0` | `0.0` |

说明：

- 这套分数专门用于地名碎片，不走地址加法模型
- bare geo alias 如果未来加入，最可能落在这套动态分里

## 6.3 地址：`_address_confidence(...)`

地址不是固定分，而是累加信号后封顶。

当前加分项如下：

| 信号 | 加分 |
| --- | ---: |
| 包含地区词 `_REGION_TOKENS` | `+0.34` |
| 包含内置地址词典 token | `+0.24` |
| 命中地址后缀，每个 `+0.18`，最多 `+0.36` | `+0.18 ~ +0.36` |
| 命中门牌 / 数字段模式 | `+0.28` |
| 命中独立地址片段模式 | `+0.24` |
| 命中短地址 token 模式 | `+0.10` |
| 文本中出现地址字段关键词 | `+0.18` |
| 字符集和长度像地址 | `+0.08` |
| 纯楼栋 / 单元 / 室号模式 | `+0.20` |

最终：

- `score = min(0.96, sum(signals))`

所以地址分数为什么变化很大，很好理解：

- `江宁区` 这种短行政区片段，可能只吃到少量信号
- `江苏省南京市江宁区天元东路88号` 会叠加多个信号，很快接近封顶

## 6.4 机构：`_organization_confidence(...)`

机构名也是加法模型。

当前加分项如下：

| 信号 | 加分 |
| --- | ---: |
| 强机构后缀 | `+0.62` |
| 弱机构后缀 | `+0.48` |
| 含字母 | `+0.08` |
| 含“大学/学院/医院/银行/公司/集团/法院/研究院”等 | `+0.12` |
| 长度 `>= 6` | `+0.08` |

最终：

- `score = min(0.92, sum(signals))`

说明：

- 弱后缀是否允许，不只看文本本身，还要看是否存在显式就业 / 就读上下文
- 这就是为什么有些“公司/学校”词尾命中会成立，有些不会

---

## 7. 二次修正逻辑

## 7.1 高精度数字类型冲突时的降级

对于 `CARD_NUMBER / BANK_ACCOUNT / PASSPORT_NUMBER / DRIVER_LICENSE / ID_NUMBER` 这类高精度数字类型：

- 先做 regex 命中
- 再做二次校验与类型偏好判断

如果无法确定唯一类型，则：

- 降级为 `PIIAttributeType.OTHER`
- `matched_by = "regex_number_ambiguous"`
- `confidence = max(0.8, 原始 confidence)`

这个逻辑表示：

- “它确定是敏感数字”
- “但具体是银行卡还是证件号不确定”

因此它不会直接丢弃，而是以保守方式保留下来。

## 7.2 重复命中的合并

当前同一个 candidate key 多次命中时，不会做平均，而是按以下方式处理：

1. 默认保留更高分
2. 如果已有项分更高，则保留已有项
3. 若 metadata 可合并，则合并 `matched_by`

## 7.3 多规则交叉支撑加分

当多个来源共同支撑同一个候选时，会做小幅 bonus：

| 条件 | 加分 |
| --- | ---: |
| 同一候选同时命中 `context_*` 和 `regex_*` | `+0.08` |
| 同一候选同时命中 `heuristic_address_fragment` 和 `regex_address_span` | `+0.06` |

最终值上限仍是 `1.0`。

这类加分的目的不是重新排序整个体系，而是表达：

- 多证据共振时，可信度高于单证据

---

## 8. 阈值过滤

打完分并不代表候选一定进入后续链路，还要过 protection level 阈值。

### 8.1 `STRONG`

| 类型 | 最低分 |
| --- | ---: |
| `NAME` | `0.72` |
| `LOCATION_CLUE` | `0.48` |
| `ADDRESS` | `0.35` |
| `ORGANIZATION` | `0.48` |
| `TIME` / `NUMERIC` / `TEXTUAL` / `OTHER` | `0.76` |
| 高精度数字类 / `PHONE` / `EMAIL` | `0.74` |

### 8.2 `BALANCED`

| 类型 | 最低分 |
| --- | ---: |
| `NAME` | `0.72` |
| `LOCATION_CLUE` | `0.52` |
| `ADDRESS` | `0.45` |
| `ORGANIZATION` | `0.48` |
| `TIME` / `NUMERIC` / `TEXTUAL` / `OTHER` | `0.76` |
| 高精度数字类 / `PHONE` / `EMAIL` | `0.74` |

### 8.3 `WEAK`

| 类型 | 最低分 |
| --- | ---: |
| `NAME` | `0.90` |
| `LOCATION_CLUE` | `0.90` |
| `ADDRESS` | `0.60` |
| `ORGANIZATION` | `0.74` |
| `TIME` / `NUMERIC` / `TEXTUAL` / `OTHER` | `0.90` |
| 高精度数字类 / `PHONE` / `EMAIL` | `0.74` |

说明：

- `WEAK` 这里的意思不是“更宽松”，而是“更少保留候选”
- 也就是 detector 需要更强证据才会收下

---

## 9. 为什么同一类规则会返回不同的分

可以归结为 6 个原因：

1. 规则来源不同
2. 文本结构完整度不同
3. 上下文支撑强度不同
4. 当前保护等级不同
5. 是否发生类型冲突降级
6. 是否发生多规则交叉加分

例如：

- `身份证号: 320...` 会优先走字段上下文或强 regex，高分保留
- `320123********1234` 可能是 masked ID，分略低
- `A12345678` 如果在某些上下文里既像驾驶证又像其他编码，可能被降成 `OTHER`
- `张三` 在“联系人张三”里可能是 `0.94`
- 但在普通长句中若缺少边界和上下文，可能直接 `0.0`

因此：

- 返回值不一样是设计目标
- 它反映的是规则证据等级，而不是实现不一致

---

## 10. 当前可调与不可调部分

当前外部 override 能调的主要是**按属性的最低保留阈值**，不是每条规则的基础分。

`RuleBasedPIIDetector._normalize_confidence_overrides` 只会把阈值写进 `min_confidence_by_attr`，且 **仅接受** 内部集合 `_TUNABLE_RULE_ATTR_TYPES`：

- `NAME`
- `ADDRESS`
- `ORGANIZATION`
- `OTHER`

公开 sanitize 载荷里 `detector_overrides` 的 Pydantic 模型（`DetectorOverridesModel`）还包含 `location_clue` 字段，但 **当前不会进入上述可调集合**，因此对 `rule_based` detector 的阈值**不生效**（除非后续扩展 `_TUNABLE_RULE_ATTR_TYPES` 与合并逻辑）。

也就是说：

- 你可以改“这几类候选最低多少分才保留”（通过 API 映射为上述四种属性类型）
- 不能直接从外部把 `regex_phone_mobile` 的基础分从 `0.86` 改成 `0.91`

如果要改变单条规则分值，当前需要直接改 detector 代码。

---

## 11. 工程解读

从当前实现看，detector 的打分体系本质上是：

```text
规则先验分
+ 上下文 / 结构加权
+ 少量多证据 bonus
- 类型冲突降级
-> protection level 阈值过滤
```

它的目标不是概率估计，而是：

1. 用高分表达强命中
2. 用较低分表达保守启发式
3. 让后续链路知道哪些候选更可靠
4. 在歧义场景下尽量“保守识别”，而不是误判具体类型

如果后续需要继续改 detector，最值得优先保持的一致性是：

- 同级证据的相对排序不要乱
- 高精度 regex 不要轻易低于启发式
- 强上下文命中应稳定高于弱 free-text 碎片
- 歧义数字类仍应优先保守降级，而不是强行猜类型
