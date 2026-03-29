# Detector Clue Priority Analysis

## 当前排序规则

当前 scanner 产出的 `clue` 会按下面的顺序排序后交给 parser：

```text
start 升序 -> priority 降序 -> end 升序
```

这意味着：

- 同一起点时，`priority` 更高的 clue 会先被 parser 看到
- parser 当前是“先开主栈，再视情况开挑战栈”，所以 `priority` 会显著影响谁先成为主栈

相关代码：

- `scanner`: [D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\scanner.py](D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\scanner.py)
- `labels`: [D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\labels.py](D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\labels.py)
- `parser`: [D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\parser.py](D:\GitHub\PrivacyGuard\privacyguard\infrastructure\pii\detector\parser.py)

## 当前 Priority 表

| 类别 | 代表 clue | priority |
|---|---|---:|
| OCR/硬断点 | `break_ocr` | 500 |
| 标点/换行断点 | `break_punct`, `break_newline` | 480 |
| session 字典 hard | `hard_*` from session dictionary | 300 |
| email label | `邮箱地址`, `email address`, `email` | 300-297 |
| local 字典 hard | `hard_*` from local dictionary | 290 |
| phone label | `手机号码`, `手机号`, `phone number`, `phone` | 290-286 |
| id/passport/driver label | `身份证号`, `passport`, `driver license` | 280-276 |
| organization label | `公司名称`, `organization`, `company name` | 260-256 |
| address label | `家庭住址`, `联系地址`, `地址`, `address` | 250-245 |
| company suffix | `有限公司`, `LLC`, `大学`, `银行` | 240 |
| name start | `我是`, `我叫`, `I am`, `my name is` | 230 |
| name label | `姓名`, `name`, `surname`, `given name`, `名` | 230-219 |
| family name | 单字/复姓命中 | 220 |
| address geo value | `address_value_province/city/district/state/city` | 205 |
| address key | `address_key_province/city/district/...` | 204 |
| postal value | 英文 `postal_code` 数值 | 203 |
| regex email | `hard_email` | 120 |
| regex phone cn | `hard_phone` | 118 |
| regex phone us | `hard_phone` | 117 |
| regex id cn | `hard_id` | 115 |
| regex bank | `hard_bank` | 110 |
| regex passport | `hard_passport` | 108 |
| regex driver license | `hard_driver_license` | 107 |

## 当前高风险优先级关系

### 1. `family_name(220) > address_value(205)`

这是当前中文裸地址误判的主要来源。

表现：

- 只要地址前缀里含有常见姓氏字
- `family_name` clue 会先于 `address_value_*`
- parser 更容易先开 `NameStack`

典型样例：

```text
江苏张家港万达广场阳光小区102栋2301
```

当前实际会先出现：

- `family_name = 江`
- `address_value_province = 江苏`

因为 `220 > 205`，所以姓名线索更早进入主栈竞争。

### 2. `family_name(220) > address_key(204)`

这会导致只靠 `区/路/小区/栋/室` 维持的地址更容易被截断。

表现：

- 地址前半段被姓名线索抢走
- 地址只能从后半段 key clue 重新起栈
- 最终地址常常变成残缺片段

典型症状：

- `场阳光小区102栋`
- `世纪大道100号` 前面的片段缺失

### 3. `company_suffix(240) > address_*`

当前带组织后缀的文本明显偏组织。

表现：

- 只要文本里出现 `有限公司 / LLC / 大学 / 银行`
- `OrganizationStack` 更容易先动或在冲突时获胜

典型样例：

```text
浦东新区阳光科技有限公司
```

当前更倾向输出：

- `ORGANIZATION`

而不是：

- `ADDRESS`

### 4. `address_label(250+) > family_name(220)`

这组是有利的，不是问题。

表现：

- 有 `家庭住址:`、`联系地址:`、`地址:` 时
- 地址 label 会明显先于姓氏 clue

结果：

- 带显式 label 的地址稳定很多
- 同样文本，一旦加了 label，地址误判率通常会下降

### 5. `name_start(230) > family_name(220)`

这组也是合理的。

表现：

- `我是张三`
- `My name is Brian Foster`

这类句子里，自报前缀 clue 会先于单独姓氏 clue。

结果：

- `NameStack` 更容易走正确路径

## 对当前流式目标的影响

当前 parser 的运行方式是：

- scanner 先产生 clue
- parser 按 clue 顺序从左到右处理
- 先起主栈
- 必要时才起挑战栈

因此，`priority` 的真实作用不是“直接决定最终赢家”，而是：

1. 决定谁先开主栈
2. 决定后续哪些 clue 还有机会被主栈继续消费
3. 决定谁只能以 challenger 身份进入冲突裁决

所以如果当前目标是：

- 裸中文地址也要稳定
- 单字姓氏不要轻易抢地址
- 地址一旦起栈，应连续处理后续地址 clue

那么当前 `family_name(220) > address_value(205)` 和 `family_name(220) > address_key(204)` 就是不合理的。

## 建议调整方案

### 最小调整版本

只改三项：

| clue | 当前 | 建议 |
|---|---:|---:|
| `family_name` | 220 | 185 |
| `address_value_*` | 205 | 225 |
| `address_key_*` | 204 | 224 |

效果：

- 中文地址 geo 值会先于姓氏 clue
- 地址关键词也会先于姓氏 clue
- `family_name` 仍可作为姓名弱线索，但不再轻易抢地址主栈

### 更完整的建议版本

| 类别 | 建议 priority | 原因 |
|---|---:|---|
| break | 保持 500/480 | 边界规则，不动 |
| structured label | 保持 276-300 | 当前合理 |
| dictionary hard | 保持 290/300 | 当前合理 |
| organization label | 保持 256-260 | 当前合理 |
| address label | 保持 245-250 | 当前合理 |
| company suffix | 240 或略降到 235 | 可后续视组织误判情况调整 |
| name start | 230 | 当前合理 |
| address geo value | 225-228 | 应高于 `family_name` |
| address key | 223-226 | 应高于 `family_name` |
| family name | 180-190 | 应明显下调 |
| postal value | 203 或提高到 220 左右 | 视英文地址需求决定 |
| regex hard | 保持 107-120 | 已由 hard 链处理 |

## 对样例的影响

样例：

```text
江苏张家港万达广场阳光小区102栋2301
```

当前：

- `family_name(江)` 会先于 `address_value_province(江苏)`
- parser 更容易先起 `NameStack`

建议调整后：

- `address_value_province(江苏)` 会先于 `family_name(江)`
- parser 更容易先起 `AddressStack`
- 后续 `小区/栋` 更有机会被同一地址栈继续消费

## 结论

当前 priority 体系的整体偏向是：

- 对带 label 的结构化字段很友好
- 对带强后缀的组织很友好
- 对没有 label 的中文地址不够友好

最关键的优先级问题不是组织，也不是 label，而是：

```text
family_name(220) 压过了 address_value(205) 和 address_key(204)
```

如果后续要优先修中文裸地址，这三项 priority 调整应作为第一优先级。
