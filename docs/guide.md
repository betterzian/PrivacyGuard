# 组织后缀 / 地址关键词 Strength 重构与 Org Stack 增强

## Context

当前组织名后缀和地址关键词的 hard/soft/weak 分级存在三个核心问题：
1. **中英文混用同一词典、共享 strength**，但英文有冠词/限定词可结构性排除泛指用法（"the company"），中文没有
2. **缩写（st/rd/inc）比全称（street/road）的地址指示性更强**，但当前定级相同
3. **Org stack 没有 commit threshold**——任何 suffix+body 都直接通过，无法利用 strength 控制误报
4. 缺少已知公司名（VALUE）作为组织起栈入口

本计划通过 6 个改动解决以上问题。

---

## 改动概览

| # | 改动 | 类型 | 关键文件 |
|---|---|---|---|
| 1 | 词典拆分：中英文组织后缀独立定级 | 数据+加载 | lexicon_loader.py, scanner.py, candidate_utils.py |
| 2 | Break 扩展：英文 determiner 作为 BREAK | scanner+models | models.py, scanner.py |
| 3 | Label 扩充 | 数据 | labels.json |
| 4 | VALUE 机制：已知公司名起栈 | scanner+stack+数据 | scanner.py, organization_base.py, candidate_utils.py |
| 5 | 地址关键词 strength 调整 | 数据 | en/zh_address_keywords.json |
| 6 | Org stack commit threshold | stack | organization_base.py |

---

## 改动1：词典拆分

### 新建文件

**`data/scanner_lexicons/zh_company_suffixes.json`**
```json
{
  "hard": ["股份有限公司", "有限责任公司", "有限公司"],
  "soft": ["事务所", "研究院", "实验室", "工作室", "集团"],
  "weak": ["公司", "学院", "银行", "酒店", "医院", "大学", "中心"]
}
```

**`data/scanner_lexicons/en_company_suffixes.json`**
```json
{
  "hard": ["incorporated", "corporation", "llc", "plc", "gmbh", "pte", "inc", "corp", "ltd"],
  "soft": ["company", "limited", "co", "hotel", "hospital", "clinic", "bank"],
  "weak": ["university", "college", "lab", "labs"]
}
```

### 删除文件

`data/scanner_lexicons/company_suffixes.json`

### 代码修改

**`lexicon_loader.py`**：
- 删除 `load_company_suffixes()`
- 新增 `load_zh_company_suffixes()` 和 `load_en_company_suffixes()`
- 均复用 `_parse_tiered_entries()`

**`scanner.py`**：
- `_company_suffix_matcher()` 改为合并两个词典的 entry（去重，保留各自 strength）
- `_scan_company_suffix_clues()` 无需改动（已从 payload 读取 strength）

**`candidate_utils.py`**：
- `_ORG_SUFFIX_RE` 改为从加载的词典动态构建（`@lru_cache` 惰性编译）
- `has_organization_suffix()` 和 `organization_suffix_start()` 改用动态正则

---

## 改动2：Break 扩展——英文 determiner

### 原理

英文中 `the/a/an/this/that/my/your...` + keyword = 泛指，真实地名/组织名不接受 determiner。这在功能上等同于标点——是结构性边界，应归入 BREAK 而非 NEGATIVE（因为 NEGATIVE 需要与 key span 重叠，而 determiner 与 keyword 之间有空格）。

### 代码修改

**`models.py`**：BreakType 新增 `DETERMINER = "determiner"`

**`scanner.py`**：
- 新增 `_scan_determiner_break_clues()` 函数
- 正则匹配：`\b(the|a|an|this|that|these|those|my|your|his|her|its|our|their|some|any|every|each|no)\b`（case-insensitive）
- 需要 ASCII word boundary 检查，避免在 CJK 上下文中误触
- 生成 `Clue(role=BREAK, break_type=BreakType.DETERMINER, source_kind="break_determiner")`
- 集成到扫描循环

### 在 stack 中的效果

- **地址 stack**：`address_base.py:305` 已有 `if is_break_clue(clue): break` → 链冲洗 → keyword 作为新链起点 → 左扩被 break 阻挡 → 左值空 → 组件不成立
- **组织 stack**：`_left_expand_text_boundary` 已有 `previous_negative_end_char` 查询前置 BREAK/NEGATIVE 的结束位置 → 左扩展到 "the" 的 end 就停止

---

## 改动3：Label 扩充

### 修改文件：`data/scanner_lexicons/labels.json`

**新增英文地址 label**（`ascii_boundary: true`）：
```
work address, office address, billing address,
delivery address, residential address, residence address,
current address, correspondence address, registered address,
business address, home street, home road, home city,
home state, home zip, work street, office street,
billing street, billing city, delivery street
```

**新增中文地址 label**（`ascii_boundary: false`）：
```
户籍地址, 户籍所在地, 现住址, 现居地址,
工作地址, 办公地址, 注册地址, 经营地址,
寄件地址, 送货地址, 常住地址
```

**新增英文组织 label**：
```
firm name, business name, workplace,
corporate name, entity name, legal name
```

**新增中文组织 label**：
```
就职单位, 任职单位, 投保单位, 甲方, 乙方
```

沿用现有 label 机制：满足边界条件 → LABEL seed；不满足 → 降级 inspire。无需代码改动。

---

## 改动4：VALUE 机制

### 新建文件

**`data/scanner_lexicons/zh_company_values.json`**
```json
{
  "hard": ["腾讯", "阿里巴巴", "字节跳动", "京东", "华为", "比亚迪", "大疆", "蔚来",
           "中兴通讯", "万科", "碧桂园", "茅台", "海尔", "格力", "中粮", "万达", "恒大", "浦发", "中信"],
  "soft": ["苹果", "小米", "百度", "美团", "网易", "联想", "平安", "招商", "美的", "理想", "小鹏", "长城"]
}
```

**`data/scanner_lexicons/en_company_values.json`**
```json
{
  "hard": ["Google", "Microsoft", "Amazon", "Tesla", "Netflix", "Oracle", "Intel",
           "Cisco", "Adobe", "Nvidia", "Samsung", "Toyota", "Boeing", "Pfizer",
           "Walmart", "Starbucks", "Disney", "Nike", "Goldman Sachs", "JPMorgan",
           "Citigroup", "BlackRock", "Mastercard", "Visa", "IBM", "HP", "Qualcomm",
           "Huawei", "Alibaba", "Tencent", "ByteDance"],
  "soft": ["Apple", "Meta", "Shell", "Sprint", "Chase", "Target", "Square", "Uber"]
}
```

### 代码修改

**`lexicon_loader.py`**：新增 `load_zh_company_values()` 和 `load_en_company_values()`

**`scanner.py`**：
- 新增 `_company_value_matcher()`（合并中英文 value 词典的 AhoMatcher）
- 新增 `_scan_company_value_clues()` → 生成 `Clue(family=ORGANIZATION, role=VALUE, strength=entry.strength, source_kind="company_value")`
- 集成到扫描循环

**`organization_base.py`**：
- `run()` 方法新增 VALUE seed 分支（介于 SUFFIX 和 return None 之间）
- 新增 `_build_value_seed_run(locale)` 方法：
  1. 向右搜索 suffix（中文 ≤6 unit，英文 ≤2 word-token 窗口内）
  2. 找到 suffix → 吸收 value ~ suffix，effective_strength = value_strength（因为 max(v, min(s+1, v)) = v）
  3. 未找到 → 仅吸收 value
- 新增 `_find_suffix_after_value(value_end, locale)` → 在窗口内找下一个 SUFFIX clue

**`candidate_utils.py`**：
- `_is_plausible_organization()` 新增 `value_driven: bool = False` 参数
- `value_driven=True` 时跳过 suffix 检查（VALUE-only 候选无 suffix）
- `build_organization_candidate_from_value()` 新增 `value_driven` 参数并传递

**确认**：`registry.py:36` 的 `_ORGANIZATION_ROLES` 已包含 `ClueRole.VALUE` → 无需改动

---

## 改动5：地址关键词 strength 调整

### `en_address_keywords.json`

**缩写提级**（几乎不泛指使用，地址指示性强）：
- `st` soft→**hard**，`rd` soft→**hard**，`ave` soft→**hard**，`ln` soft→**hard**
- `apt` soft→**hard**，`rm` soft→**hard**，`fl` soft→**hard**
- `twr` soft→**hard**，`blk` soft→**hard**

**全称降级**（高频泛指，有 break 兜底）：
- `highway` hard→**soft**，`hwy` hard→**soft**
- `freeway` hard→**soft**，`fwy` hard→**soft**
- `alley` hard→**soft**，`aly` hard→**soft**
- `building` hard→**soft**（`bldg` 保持 hard）

**不动**：`ct` 保持 soft（Connecticut 冲突），`dr` 保持 soft（Doctor 歧义），`drive` 保持 soft

### `zh_address_keywords.json`

- `大道` hard→**soft**，`大街` hard→**soft**
- `公路` hard→**soft**，`国道` hard→**soft**

---

## 改动6：Org stack commit threshold

### 当前问题

Org stack 的 `run()` 方法中，只要 suffix+body 存在就返回 StackRun——没有根据 strength 和 protection_level 做门槛判断。把"公司"降到 weak 但不加阈值 → "去公司"仍然检出。

### 实现

**`organization_base.py`**：

1. 新增 `_OrgEvidence` 数据类：

```python
@dataclass(frozen=True, slots=True)
class _OrgEvidence:
    has_suffix: bool = False
    suffix_strength: ClaimStrength = ClaimStrength.WEAK
    has_value: bool = False
    value_strength: ClaimStrength = ClaimStrength.WEAK
    has_label: bool = False
    has_inspire: bool = False
```

2. 新增 `_meets_org_commit_threshold(evidence, locale, protection_level) -> bool`：

**中文阈值**（无结构性 break 兜底，更严格）：

| 场景 | STRONG | BALANCED | WEAK |
|---|---|---|---|
| HARD suffix | ✓ | ✓ | ✓ |
| VALUE + suffix (≥2证据) | ✓ | ✓ | ✓ |
| LABEL seed + body | ✓ | ✓ | ✓ |
| SOFT suffix only + body | ✓ | 需 inspire | ✗ |
| WEAK suffix only + body | ✗ | ✗ | ✗ |
| HARD value only | ✓ | ✓ | ✗ |
| SOFT value only | ✓ | ✗ | ✗ |

**英文阈值**（有 determiner break 兜底，更宽松）：

| 场景 | STRONG | BALANCED | WEAK |
|---|---|---|---|
| HARD suffix | ✓ | ✓ | ✓ |
| VALUE + suffix | ✓ | ✓ | ✓ |
| LABEL seed + body | ✓ | ✓ | ✓ |
| SOFT suffix only + body | ✓ | **✓** | ✗ |
| WEAK suffix only + body | 需 inspire | ✗ | ✗ |
| HARD value only | ✓ | ✓ | ✗ |
| SOFT value only | ✓ | ✗ | ✗ |

3. 在 `run()` 的 SUFFIX / VALUE 路径中构建 `_OrgEvidence`，返回 StackRun 前调用阈值检查

4. **`base.py`**：`StackContextLike` protocol 新增 `inspire_index` 属性（`StackContext` 已有该字段）

---

## 实现顺序

```
Phase 1: 改动1（词典拆分）   — 基础设施，其他改动依赖
Phase 2: 改动5（地址 strength） — 纯词典，独立
Phase 3: 改动2（Break 扩展）   — scanner + models
Phase 4: 改动3（Label 扩充）   — 纯词典
Phase 5: 改动4（VALUE 机制）   — scanner + stack + 词典
Phase 6: 改动6（Org threshold） — stack，依赖改动1/4
```

---

## 关键场景验证矩阵

| 输入 | 期望 | 机制 |
|---|---|---|
| `"123 Main Street"` | ✓ 检出 road | street=soft, 左扩 "123 Main" 合法 |
| `"cross the street"` | ✗ 不检出 | "the" → BREAK, 左扩被阻, 左值空 |
| `"Main St"` | ✓ 检出 road | st=hard, 左扩 "Main" |
| `"the company reported"` | ✗ 不检出 org | "the" → BREAK, 左扩被阻 |
| `"Apple Inc."` | ✓ 检出 org | VALUE(soft) + SUFFIX(hard) → ✓ |
| `"苹果股份有限公司"` | ✓ 检出 org | HARD suffix → 全级别通过 |
| `"苹果公司"` | ✓ 检出 org | VALUE(soft) + SUFFIX(weak) → 2证据, 通过 |
| `"去公司"` | ✗ 不检出 | WEAK suffix only, body="去" → 阈值不通过 |
| `"去银行取钱"` | ✗ 不检出 | WEAK suffix only → 阈值不通过 |
| `"中国建设银行"` | ？ 需旁证 | WEAK suffix, 需要 LABEL/inspire/VALUE 辅助 |
| `"公司名称：金杜律师"` | ✓ 检出 org | LABEL seed → 全级别通过 |
| `"腾讯"` | ✓ 检出 org | HARD value only → STRONG/BALANCED 通过 |
| `"Google"` | ✓ 检出 org | HARD value only → STRONG/BALANCED 通过 |

---

## 测试策略

每个 Phase 完成后运行：
```bash
C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/ -v
```

重点验证：
- 词典拆分后 suffix 匹配行为一致（Phase 1）
- 地址缩写升级后阈值行为变化（Phase 2+5）
- Break 正确阻止 "the street" 类泛指（Phase 3）
- VALUE seed 正确起栈并吸收 suffix（Phase 5）
- Org threshold 的 6×3×2=36 种组合（Phase 6）