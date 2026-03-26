# PrivacyGuard Detector 打分与流程

## 1. 文档范围

本文档描述当前仓库中 `rule_based` detector 的真实探测流程与 `PIICandidate.confidence`
打分规则。

本文档讨论：

- detector 在 `sanitize` 主链中的位置
- `RuleBasedPIIDetector.detect(...)` 的共享外层流程
- `zh_cn`、`en_us`、`mixed` 三种 `locale_profile` 在 detector 内部的差异
- `session dictionary -> privacy_repository -> rules` 的层级顺序
- 固定分、动态分、冲突降级、bonus、阈值过滤
- OCR 页级扫描、OCR 姓名 refinement、OCR 地址碎片派生

本文档不讨论：

- `label_only`、`label_persona_mixed`、`de_model` 的 decision 分数
- OCR 引擎本身的 `OCRTextBlock.score` 含义
- render / restore 侧实现

需要先明确：

- detector 的 `confidence` 是工程规则分
- detector 的 `confidence` 不是概率校准值
- 当前实现没有统一单公式
- 当前实现是“分层扫描 + 分阶段打分 + 阈值过滤”

---

## 2. detector 在主链中的位置

当前 `sanitize` 主链里的 detector 边界是：

```text
OCR / prompt parse
-> detector
-> DecisionContextBuilder
-> decision_engine.plan(...)
-> ConstraintResolver + ReplacementGenerationService
-> render
-> mapping store
```

也就是说：

1. pipeline 先准备 `prompt_text` 与 `ocr_blocks`
2. detector 输出 `PIICandidate`
3. decision 再对这些候选规划动作

因此 detector 当前只负责：

- 找候选
- 给候选打规则分
- 合并 metadata

它不负责：

- 产出 `KEEP / GENERICIZE / PERSONA_SLOT`
- 生成 placeholder
- 执行替换

---

## 3. 共享外层流程

无论 `locale_profile` 是什么，`detect(...)` 的共享外层流程都是：

```text
build session dictionary from mapping_store
-> build rule profile from protection_level
-> scan prompt text
-> scan OCR page document
-> deduplicate with CandidateResolverService
```

展开后可以写成：

1. 从 `mapping_store` 中把历史 `ReplacementRecord` 聚成 session dictionary
2. 从 `privacy_repository` 词典索引里取 local dictionary
3. 按 `protection_level` 选择 `_RuleStrengthProfile`
4. 用 `_scan_text(...)` 扫描 prompt
5. 用 `_scan_ocr_page(...)` 扫描 OCR 页面拼接文本
6. 统一进入 `CandidateResolverService.resolve_candidates(...)`

当前 detector 不是 prompt 和 OCR 分两套规则引擎。

它们的关系是：

- prompt：直接 `_scan_text(...)`
- OCR：先整页拼接，再 `_scan_text(...)`，最后 remap 回 block

---

## 4. 分层扫描顺序

当前 `_scan_text(...)` 的顺序固定为：

1. `session dictionary`
2. `local dictionary`
3. `context`
4. `regex`
5. `organization`
6. `name`
7. `address`
8. `geo fragment`
9. `generic number`
10. `masked text`

关键行为：

- 每一层后都会刷新 `protected_spans`
- 后续较弱层通常避开前面较强层已经命中的 span
- organization / name / address / geo / masked text 之前，会构造 `shadow text`
- `shadow text` 会把已识别 span 替换成 `<NAME>`、`<ADDR>`、`<PHONE>` 这类 token

这意味着当前 detector 的工程语义不是“所有规则平权竞争”，而是：

- 先让高确定性证据占位
- 再让弱规则补召回

---

## 5. `locale_profile` 如何影响探测流程

先说结论：

- `locale_profile` 当前不是严格语言沙箱
- 很多共享规则在三种 profile 下都会运行
- `zh_cn / en_us / mixed` 的主要差别，是“额外打开哪些中文或英文专用分支”

### 5.1 三种 profile 的共享基线

下面这些规则簇在三种 profile 下都会进入同一条扫描链：

- `session dictionary`
- `local dictionary`
- `context_*_field`
- `regex_email*`
- `regex_card_number*`
- `regex_bank_account*`
- `regex_passport_number*`
- `regex_driver_license*`
- `regex_cn_id*`
- `regex_time_clock`
- `regex_generic_number`
- 中文通用姓名碎片启发式 `heuristic_name_fragment`
- 中文地址 span 基线 `_ADDRESS_SPAN_PATTERNS`
- 中文地名 / 地址碎片基线 `_GENERIC_GEO_FRAGMENT_PATTERNS`
- 中文机构 span 基线 `_ORGANIZATION_SPAN_PATTERNS`
- OCR scene refinement 与 OCR page remap

这也是为什么：

- `en_us` 不是严格的“只探英文”
- 只要文本里真的出现中文地址 / 中文地名 / 中文姓名碎片，`en_us` 仍可能收下这些候选

### 5.2 `zh_cn`

`zh_cn` 在共享基线之外，额外启用：

- 中文电话 regex
- 中文自报姓名 `context_name_self_intro`
- 中文敬称姓名 `regex_name_honorific`

`zh_cn` 不启用的英文专用分支包括：

- `regex_phone_us`
- `regex_phone_us_masked`
- `context_name_self_intro_en`
- `regex_name_honorific_en`
- `_EN_ADDRESS_SPAN_PATTERNS`
- `_EN_ORGANIZATION_SPAN_PATTERNS`
- `_english_address_confidence(...)` 的英文地址加分

### 5.3 `en_us`

`en_us` 在共享基线之外，额外启用：

- `regex_phone_us`
- `regex_phone_us_masked`
- `context_name_self_intro_en`
- `regex_name_honorific_en`
- `_EN_ADDRESS_SPAN_PATTERNS`
- `_EN_ORGANIZATION_SPAN_PATTERNS`
- `_english_address_confidence(...)`
- 英文机构后缀校验 `_has_en_organization_suffix(...)`

需要特别注意：

- `en_us` 当前没有“通用英文 free-text 姓名碎片扫描”
- 英文姓名更多依赖：
  - dictionary
  - `context_name_field`
  - `context_name_self_intro_en`
  - `regex_name_honorific_en`

也就是说：

- `This is Alice Johnson` 可以中
- `Please ask Alice Johnson to review it` 当前并没有一条对应中文那种通用英文姓名碎片规则

### 5.4 `mixed`

`mixed` 不是“先中文一遍，再英文一遍”的双 pass。

它的真实语义是：

- 同一条共享扫描链
- 同时打开中文专用分支和英文专用分支
- 共用同一套 `protected_spans`
- 共用同一套 `shadow text`

因此 `mixed` 的实际效果是：

- session/local dictionary 先命中
- 后面的 context / regex / organization / name / address / geo 仍然只跑一遍
- 但 phone / self-intro / title / organization span / address span 会变成中英规则并集

---

## 6. locale 与规则簇的对应表

| 规则簇 | `zh_cn` | `en_us` | `mixed` | 备注 |
| --- | --- | --- | --- | --- |
| `session dictionary` | 开 | 开 | 开 | locale 不影响顺序 |
| `local dictionary` | 开 | 开 | 开 | 地址展开已支持英文结构化地址 |
| `context_*_field` | 开 | 开 | 开 | 关键词集本身是多语混合的 |
| 中文电话 regex | 开 | 关 | 开 | `regex_phone_mobile*` / `regex_phone_landline` |
| 英文电话 regex | 关 | 开 | 开 | `regex_phone_us*` |
| `regex_email*` | 开 | 开 | 开 | locale 无关 |
| `regex_card/bank/passport/driver/id/time` | 开 | 开 | 开 | locale 无关 |
| 中文自报姓名 | 开 | 关 | 开 | `context_name_self_intro` |
| 英文自报姓名 | 关 | 开 | 开 | `context_name_self_intro_en` |
| 中文敬称姓名 | 开 | 关 | 开 | `regex_name_honorific` |
| 英文敬称姓名 | 关 | 开 | 开 | `regex_name_honorific_en` |
| 中文通用姓名碎片 | 开 | 开 | 开 | 规则始终存在，但 pattern 本身是中文形态 |
| 中文地址 span 基线 | 开 | 开 | 开 | `_ADDRESS_SPAN_PATTERNS` |
| 英文地址 span 扩展 | 关 | 开 | 开 | `_EN_ADDRESS_SPAN_PATTERNS` |
| 中文 geo fragment | 开 | 开 | 开 | 中文地名字典与后缀仍始终运行 |
| 英文 geo fragment | 无专门通用层 | 无专门通用层 | 无专门通用层 | 当前没有独立 English geo layer |
| 中文机构 span 基线 | 开 | 开 | 开 | `_ORGANIZATION_SPAN_PATTERNS` |
| 英文机构 span 扩展 | 关 | 开 | 开 | `_EN_ORGANIZATION_SPAN_PATTERNS` |
| 英文地址加分 | 关 | 开 | 开 | `_english_address_confidence(...)` |
| OCR 时间元信息（中英） | 开 | 开 | 开 | `_looks_like_ui_time_metadata(...)` 本身就是双语 |

---

## 7. 固定分来源

## 7.1 词典命中

词典命中是当前最强证据之一。

| 来源 | `matched_by` | 分数 |
| --- | --- | ---: |
| 本地词典，带 `entity_id` 的词条 | `dictionary_local` | `0.99` |
| 本地词典，普通词条 | `dictionary_local` | `0.98` |
| session 历史词条 | `dictionary_session` | `0.97` |
| 同 span 多个 binding key 歧义 | `*_ambiguous` | 取命中项中的 `max(confidence)` |

说明：

- `local dictionary` 来自 `privacy_repository`
- `session dictionary` 来自历史 `ReplacementRecord`
- 地址类词条在匹配前会先展开为自然文本变体，英文结构化地址也在此闭环

## 7.2 字段上下文规则

字段上下文规则本质上是：

```text
字段关键词 + 值
```

例如：

- `姓名: 张三`
- `name: Alice Johnson`
- `address: 123 Main St`

当前基础分如下：

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

如果字段值本身没过 validator，但被视为 `masked address`，则：

- `matched_by` 变成 `*_masked`
- `confidence = max(0.62, base_confidence - 0.14)`

因此：

- `context_address_field = 0.90`
- `context_address_field_masked = 0.76`

## 7.3 自报姓名与敬称姓名

| 规则 | `matched_by` | 分数 | 启用 profile |
| --- | --- | ---: | --- |
| 中文自报姓名，如“我叫 / 名叫 / 叫做 / 我的名字是” | `context_name_self_intro` | `0.78` | `zh_cn`、`mixed` |
| 英文自报姓名，如 `my name is / i am / i'm / this is` | `context_name_self_intro_en` | `0.76` | `en_us`、`mixed` |
| 中文敬称姓名，如“张老师 / 李总” | `regex_name_honorific` | `0.72` | `zh_cn`、`mixed` |
| 英文敬称姓名，如 `Mr. Smith / Dr. Alice Johnson` | `regex_name_honorific_en` | `0.78` | `en_us`、`mixed` |

这四条规则都受 `rule_profile` 开关控制：

- `STRONG`：开
- `BALANCED`：开
- `WEAK`：关

## 7.4 结构型 regex

### 电话

| 规则 | `matched_by` | 分数 | 启用 profile |
| --- | --- | ---: | --- |
| 标准中国手机号 | `regex_phone_mobile` | `0.86` | `zh_cn`、`mixed` |
| 带分隔符中国手机号 | `regex_phone_mobile_sep` | `0.84` | `zh_cn`、`mixed` |
| 中国座机 | `regex_phone_landline` | `0.78` | `zh_cn`、`mixed` |
| 脱敏中国手机号 | `regex_phone_masked` | `0.82` | `zh_cn`、`mixed` |
| 前缀保留、后段全掩码手机号 | `regex_phone_masked_prefix_only` | `0.80` | `zh_cn`、`mixed` |
| US / E.164 风格电话 | `regex_phone_us` | `0.84` | `en_us`、`mixed` |
| 脱敏 US 电话 | `regex_phone_us_masked` | `0.80` | `en_us`、`mixed` |

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

---

## 8. 动态分来源

## 8.1 中文姓名碎片：`heuristic_name_fragment`

`heuristic_name_fragment` 不是固定分，而是 `_generic_name_confidence(...)` 动态计算。

它主要看：

- 左右是否是干净边界
- 左侧是否有姓名上下文支持词
- 右侧是否跟地理 / 活动词
- 是否独立成词
- 是否为 OCR 场景
- 当前 `ProtectionLevel`

典型返回值：

| 场景 | 分数 |
| --- | ---: |
| 左侧有强姓名上下文，右边界干净 | `0.94` |
| 右侧是地理 / 活动词 | `0.92` |
| `WEAK` 下上述强命中 | `0.96` |
| `STRONG` 下整段几乎就是独立姓名 | `0.90` |
| `STRONG` + OCR 小窗口近似独立姓名 | `0.86` |
| 不成立 | `0.0` |

注意：

- 这条通用碎片规则当前是中文形态
- 英文没有对应的通用 free-text 姓名碎片规则

## 8.2 机构：`regex_organization_suffix`

机构名由 `_organization_confidence(...)` 加法计算。

当前信号与加分：

| 信号 | 加分 |
| --- | ---: |
| 强机构后缀 | `+0.62` |
| 弱机构后缀 | `+0.48` |
| 含字母 | `+0.08` |
| 含“大学/学院/医院/银行/公司/集团/法院/研究院”或 `university/college/hospital/bank/company/corporation/institute` | `+0.12` |
| 长度 `>= 6` | `+0.08` |

最终：

```text
score = min(0.92, sum(signals))
```

当前实现里，弱后缀并不是默认放开。

`allow_weak_org_suffix` 在三档 profile 里当前都为 `False`，所以弱后缀想成立，需要：

- 显式组织字段上下文
- 或 `_organization_has_explicit_context(...)` 判定为就业 / 就读语境

这条显式上下文当前同时支持中文和英文，例如：

- `就职于`
- `毕业于`
- `work at`
- `study at`
- `employed by`
- `currently at`

## 8.3 地址：`heuristic_address_fragment` / `regex_address_span`

地址分不是固定值，而是 `_address_confidence(...)` 的结果。

### 中文地址信号

| 信号 | 加分 |
| --- | ---: |
| 包含地区词 `_REGION_TOKENS` | `+0.34` |
| 包含内置地址词典 token | `+0.24` |
| 命中中文地址后缀，每个 `+0.18`，最多 `+0.36` | `+0.18 ~ +0.36` |
| 命中门牌 / 数字段模式 | `+0.28` |
| 命中独立地址片段模式 | `+0.24` |
| 命中短地址 token 模式 | `+0.10` |
| 文本中出现地址字段关键词 | `+0.18` |
| 字符集和长度像地址 | `+0.08` |
| 纯楼栋 / 单元 / 室号模式 | `+0.20` |

### 英文地址信号

只有 `en_us` / `mixed` 才会进入 `_english_address_confidence(...)`。

| 信号 | 加分 |
| --- | ---: |
| `PO Box` | `+0.62` |
| 门牌号 | `+0.24` |
| 英文街道后缀，如 `St/Rd/Ave/Blvd/Dr/Ln/...` | `+0.32` |
| 单元 / 楼层，如 `Apt/Suite/Unit/Floor/...` | `+0.12` |
| 州缩写 | `+0.12` |
| 邮编 | `+0.14` |
| 包含 `address/street/road/avenue/...` 这类字样 | `+0.08` |

### 最终地址分

当前地址最终分数是：

```text
score = min(0.96, max(chinese_address_score, english_address_score_if_enabled))
```

因此：

- `zh_cn`：只看中文地址加法模型
- `en_us`：中文地址基线仍在，同时再取一次英文地址加法模型的 `max`
- `mixed`：与 `en_us` 相同，但还同时打开中文 phone / 中文 self-intro / 中文 honorific 等显式中文分支

### 哪些规则会用这个分

| 规则 | `matched_by` | 分数来源 |
| --- | --- | --- |
| 整段文本本身像地址 | `heuristic_address_fragment` | `_address_confidence(...)` |
| 命中地址 span pattern | `regex_address_span` | `_address_confidence(...)` |
| 字段上下文地址 | `context_address_field` | 固定 `0.90` |

## 8.4 地名 / 地址碎片：`heuristic_geo_lexicon` / `heuristic_geo_suffix`

地名碎片由 `_geo_fragment_confidence(...)` 动态计算。

这套规则当前是中文中心的：

- 内置地名字典是中文
- generic geo suffix 也是中文后缀

它主要看：

- 是否来自 builtin geo lexicon
- 左右边界是否“开”
- 右侧是否跟地理 / 活动词
- 右侧是否紧跟数字
- 当前推断类型是 `ADDRESS` 还是 `LOCATION_CLUE`
- 当前 `ProtectionLevel`

典型返回值：

| 场景 | builtin token | generic suffix |
| --- | ---: | ---: |
| 整段就是命中值 | `0.96` | `0.90` |
| 左右边界都开 | `0.96` | `0.90` |
| 右侧是地理 / 活动词 | `0.94` | `0.88` |
| 右侧是数字 | `0.92` | `0.86` |
| 地址型片段，单边界较开 | `0.90` | `0.82` |
| 地址型片段，边界更挤，`STRONG` | `0.76` | `0.72` |
| 地址型片段，边界更挤，`BALANCED` | `0.72` | `0.66` |
| 较弱 `LOCATION_CLUE`，单边界较开 | `0.86` | `0.78` |
| 更弱但 `STRONG` 保守收下 | `0.72` | `0.72` |
| 不成立 | `0.0` | `0.0` |

## 8.5 通用数字兜底：`regex_generic_number`

当更高精度数字类型没有成功收下，但文本仍像“值得保护的数字串”时，会走通用数字兜底。

规则：

- 至少 4 位数字
- 允许夹少量符号

分值：

- 数字位数 `>= 7`：`0.98`
- 数字位数 `4-6`：`0.94`

它分高的原因不是“类型很准”，而是：

- 目标是高召回地保守保护数字型敏感信息

## 8.6 重复掩码兜底：`heuristic_masked_text`

对 `***`、`###`、`●●●` 这类被整段遮住的文本，当前还有一层弱兜底。

| 条件 | 分数 |
| --- | ---: |
| 视觉掩码字符连续重复 | `0.62` |
| 字母掩码字符连续重复 | `0.56` |

这层只有在 `rule_profile.enable_standalone_masked_text=True` 时才会跑。

当前 profile 配置中：

- `STRONG`：关闭
- `BALANCED`：关闭
- `WEAK`：关闭

所以这条规则虽然代码存在，但在当前默认三档 profile 下实际上不会产出候选。

## 8.7 OCR 姓名 refinement：`ocr_scene_name_block`

OCR 路径中，姓名候选在 remap 回 block 后，还会走 `_refine_ocr_name_candidate(...)`。

它的处理方式是：

1. 必须是 `NAME + OCR`
2. `WEAK` 下直接不做 refinement
3. 候选必须只覆盖一个 OCR block
4. 候选文本需要和 block 文本在 compact 后精确对齐
5. 再通过 `_ocr_name_scene_confidence(...)` 结合 UI 场景信号重新评估

### OCR scene 原始加减分

| 信号 | 加减分 |
| --- | ---: |
| block OCR 分 `>= 0.96` | `+0.24` |
| block OCR 分 `>= 0.88` | `+0.14` |
| block OCR 分 `< 0.70` | `-0.24` |
| 同行右侧存在时间元信息 | `+0.40` |
| 下一行像 preview 文本 | `+0.28` |
| 当前 block 本身像时间元信息 | `-0.60` |
| 当前 block 像 UI 标签 | `-0.60` |

### OCR scene 转成最终候选分

`BALANCED`：

- 若累计 `score < 0.48`，直接拒绝
- 否则 `scene_confidence = min(0.86, 0.68 + score * 0.18)`

`STRONG`：

- 若累计 `score < 0.18`，直接拒绝
- 否则 `scene_confidence = min(0.90, 0.70 + score * 0.18)`

最终写回候选时：

```text
candidate.confidence = max(old_confidence, scene_confidence)
```

也就是说：

- OCR refinement 只会抬高已有候选分，或直接过滤掉候选
- 不会把一个已经命中的 OCR 姓名强行降到更低但继续保留

## 8.8 OCR 派生地址碎片：`ocr_page_fragment`

当 detector 先识别出跨多个 OCR block 的地址后，会再为每个 block 派生块级地址候选。

这类派生块的分数不是重新按地址公式计算，而是：

```text
max(0.4, parent_confidence - 0.08)
```

目的很明确：

- 保留块级替换所需的信息
- 但不让派生碎片比分页级父候选更强

---

## 9. 二次修正与冲突收敛

## 9.1 高精度数字类型冲突：`regex_number_ambiguous`

`CARD_NUMBER / BANK_ACCOUNT / PASSPORT_NUMBER / DRIVER_LICENSE / ID_NUMBER`
这些高精度数字类型，在 regex 阶段不是直接裸收。

当前逻辑是：

1. 先命中具体 regex
2. 再做 validator 与类型形状判断
3. 若同一 span 上冲突类型无法唯一确定，则重建为：
   - `attr_type = OTHER`
   - `matched_by = regex_number_ambiguous`
   - `confidence = max(0.8, 原始 confidence)`

这表示：

- “它确定是敏感数字”
- “但不强猜是银行卡还是证件号”

## 9.2 重复命中的合并

同一个 candidate key 多次命中时：

1. 默认保留更高分
2. metadata 做并集合并
3. 若 `context_*` 和 `regex_*` 同时支撑，会做小幅 bonus
4. 若地址同时命中 `heuristic_address_fragment` 与 `regex_address_span`，也会做小幅 bonus

## 9.3 多规则交叉 bonus

| 条件 | 加分 |
| --- | ---: |
| 同一候选同时命中 `context_*` 和 `regex_*` | `+0.08` |
| 同一候选同时命中 `heuristic_address_fragment` 和 `regex_address_span` | `+0.06` |

最终上限仍是 `1.0`。

---

## 10. `strong / balanced / weak` 三档 profile

三档 profile 不只是阈值不同，而是一整组 detector 行为开关。

### 10.1 profile 开关表

| 开关 | `STRONG` | `BALANCED` | `WEAK` |
| --- | --- | --- | --- |
| `enable_self_name_patterns` | 开 | 开 | 关 |
| `enable_honorific_name_pattern` | 开 | 开 | 关 |
| `enable_full_text_address` | 开 | 开 | 关 |
| `address_min_confidence` | `0.35` | `0.45` | `0.60` |
| `allow_weak_org_suffix` | 关 | 关 | 关 |
| `enable_context_masked_text` | 开 | 开 | 关 |
| `enable_standalone_masked_text` | 关 | 关 | 关 |
| `masked_text_min_run` | `3` | `4` | `99` |
| `allow_alpha_mask_text` | 开 | 关 | 关 |

### 10.2 最低保留阈值

| 类型 | `STRONG` | `BALANCED` | `WEAK` |
| --- | ---: | ---: | ---: |
| `NAME` | `0.72` | `0.72` | `0.90` |
| `LOCATION_CLUE` | `0.48` | `0.52` | `0.90` |
| `ADDRESS` | `0.35` | `0.45` | `0.60` |
| `ORGANIZATION` | `0.48` | `0.48` | `0.74` |
| `TIME` | `0.76` | `0.76` | `0.90` |
| `NUMERIC` | `0.76` | `0.76` | `0.90` |
| `TEXTUAL` | `0.76` | `0.76` | `0.90` |
| `OTHER` | `0.76` | `0.76` | `0.90` |
| `PHONE` | `0.74` | `0.74` | `0.74` |
| `CARD_NUMBER` | `0.74` | `0.74` | `0.74` |
| `BANK_ACCOUNT` | `0.74` | `0.74` | `0.74` |
| `PASSPORT_NUMBER` | `0.74` | `0.74` | `0.74` |
| `DRIVER_LICENSE` | `0.74` | `0.74` | `0.74` |
| `EMAIL` | `0.74` | `0.74` | `0.74` |
| `ID_NUMBER` | `0.74` | `0.74` | `0.74` |

解释：

- `WEAK` 这里不是“更宽松”
- 它的语义是“更少保护、更高证据门槛”

---

## 11. OCR 不是单 block 独立打分

当前 OCR 路径是：

```text
OCR blocks
-> build page document
-> scan whole page text
-> remap page span back to block / merged block
-> OCR name refinement
-> OCR address fragment derivation
```

这意味着：

- 地址、姓名、preview、时间元信息可以跨 block 交互
- detector 分值并不只由单个 block 文本决定
- screenshot 替换闭环依赖 page-level span 和 block-level fragment 两套候选

---

## 12. 当前可调与不可调部分

当前外部 override 调的是“按属性的最低保留阈值”，不是单条规则基础分。

当前可调属性集合是：

- `NAME`
- `LOCATION_CLUE`
- `ADDRESS`
- `ORGANIZATION`
- `OTHER`

也就是说：

- 你可以改这些类型“最低多少分才保留”
- 不能直接把 `regex_phone_us` 从 `0.84` 改成 `0.90`
- 不能直接把 `context_name_self_intro_en` 从 `0.76` 改成 `0.82`

如果要改单条规则的基础分，当前需要直接改 detector 代码。

---

## 13. 如何阅读当前 detector 分数

可以把当前分数大致理解为：

- `0.95+`：极强命中
- `0.90` 左右：强命中
- `0.80-0.89`：结构明确但带轻噪声或轻歧义
- `0.70-0.79`：较弱但可接受
- `0.60` 左右：兜底弱信号
- `0.0`：当前规则不成立

但它本质上仍是：

- 工程规则分
- 不是 calibrated probability

---

## 14. 一句话总结

当前 `rule_based` detector 的打分与流程，本质上是：

```text
session dictionary
-> privacy_repository dictionary
-> layered rules (context / regex / organization / name / address / geo / fallback)
-> dynamic scoring / conflict downgrade / bonus
-> profile threshold filtering
-> OCR remap / candidate dedup
```

其中：

- `zh_cn` = 共享基线 + 中文 phone / self-intro / honorific 分支
- `en_us` = 共享基线 + 英文 phone / self-intro / honorific / address / organization 分支
- `mixed` = 同一条分层链里同时打开中英显式分支，而不是双 pass
