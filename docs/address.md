\# 地址 Stack 重构计划



\## Context



当前地址检测的 `AddressComponentType` 有 17 个层级，层级过细导致：

1. COMPOUND 关键词（科技园、花园、住宅等）作为路名/描述修饰时立即提交，导致后继图断链
2. "社区"归为 VILLAGE（admin 层级），在号后面无法接续
3. "楼"同时出现在 building 和 floor 关键词中，产生歧义
4. 逆序 trailing admin 无逗号检查，误把新地址开头当尾部追加



目标：将 17 个类型缩减为 9 个；实现 POI 延迟提交（先满足 gap 条件，再丢弃 clue 语义）；逆序必须有逗号。



\---



\## 一、类型精简：17 → 9



\### 新旧映射



| 新类型 | 合并来源 | 关键词(zh) |

|--------|---------|-----------|

| PROVINCE | PROVINCE + STATE | 省, 自治区, 特别行政区 |

| CITY | CITY | 市, 自治州, 地区, 盟 |

| DISTRICT | DISTRICT | 区, 县, 旗, 新区, 开发区, 高新区, 经济区, 保税区 |

| SUBDISTRICT | STREET_ADMIN + TOWN + VILLAGE | 街道办, 街道, 镇, 乡, 屯, 社区, 居委会, 村委会, 村 |

| ROAD | ROAD + STREET | 大道, 胡同, 公路, 国道, 大街, 中路, 南路, 北路, 东路, 西路, 路, 街, 道, 巷, 弄, 里, 坊, 桥 |

| NUMBER | STREET_NUMBER | 号, 门牌, 门牌号 |

| POI | COMPOUND(重命名) | 小区, 公寓, 大厦, 大楼, 园区, 花园, 家园, 苑, 庭, 府, 湾, 宿舍, 新村, 别墅, 广场, 中心, 城, 商场, 写字楼, 工业园, 科技园, 产业园, 住宅, 楼盘, 新城, 雅苑, 嘉园, 豪庭, 名邸, 华庭, 御园 |

| BUILDING | BUILDING | 号楼, 栋, 幢, 座 |

| DETAIL | UNIT + FLOOR + ROOM | 单元, 层, 楼, 室, 房, 户 |



删除：STATE, STREET, STREET_ADMIN, TOWN, VILLAGE, UNIT, FLOOR, ROOM, COMPOUND, STREET_NUMBER, ADMIN, DIRECTION, POSTAL_CODE



注意：

\- "楼" 从 BUILDING 移至 DETAIL（floor 义）；"号楼" 保留在 BUILDING

\- "大楼" 新增到 POI

\- "社区" 从 VILLAGE 移至 SUBDISTRICT



\### 新后继图



\```

PROVINCE    → {CITY, DISTRICT, SUBDISTRICT, ROAD, POI}

CITY        → {DISTRICT, SUBDISTRICT, ROAD, POI}

DISTRICT    → {SUBDISTRICT, ROAD, POI}

SUBDISTRICT → {SUBDISTRICT, ROAD, POI, NUMBER}

ROAD        → {NUMBER, POI, BUILDING, DETAIL}

NUMBER      → {POI, BUILDING, DETAIL}

POI         → {NUMBER, BUILDING, DETAIL}

BUILDING    → {DETAIL}

DETAIL      → {DETAIL}

\```



\---



\## 二、POI 延迟提交



\### 核心规则



1. 遇到 POI KEY clue → **不立即提交**，存为 `deferred_poi`，但**更新 gap 锚点**（先满足 6-unit 条件）
2. 继续扫描下一个 KEY clue：

   \- **紧邻 + 可组合**（下一个 KEY 类型为 ROAD / BUILDING / DETAIL / SUBDISTRICT / POI）：

​     \- 若下一个也是 POI → 替换 `deferred_poi`，丢弃旧的

​     \- 否则 → 丢弃 `deferred_poi` 的 clue 语义，用下一个 KEY 的类型处理（见下方"组合构建"）

   \- **不可组合**（下一个 KEY 类型为 CITY / DISTRICT / NUMBER 等）→ `deferred_poi` 是独立 POI → 正常提交为 component

   \- **无后续 KEY** → 正常提交为 component

3. pending_value 中的 POI VALUE clue 同理：flush 时若后面紧跟可组合 KEY，丢弃而非提交



\### 组合构建逻辑



当 `deferred_poi` 被后续 KEY 吞噬时：



\```python

\# 从 deferred_poi 的 start 位置左扩找 value（而非从 next_key.start）

floor = _left_address_floor(clues, next_key_index)

expand_start = _left_expand_zh_chars(raw_text, deferred_poi.start, floor, max_chars=2)

value_text = raw_text[expand_start : next_key.start]  # 包含 deferred_poi 文字

value = _normalize_address_value(next_key_comp_type, value_text)



if not value:

​    \# value 无效（如"住宅"不含数字 → DETAIL 正规化后为空）

​    \# → 两个 clue 都相当于没有，文字保留在地址跨度内

​    pass

else:

​    \# 构建 component，类型为 next_key 的类型

​    component = {comp_type: next_key_type, value: value, key: next_key.text, ...}

\```



\### 关键约束



\- "紧邻"判定：`deferred_poi.end == next_key.start`（中文无间隔）或仅有空白间隔

\- 丢弃 = 丢弃 clue 的语义标记，文字本身保留在地址跨度内

\- 丢弃的 clue 仍更新 `last_consumed_address_clue`（gap 锚点）和 `consumed_ids`（防止其他 stack 重复处理）



\### 典型场景验证



| 输入 | deferred_poi | 下一个 KEY | 动作 | 结果 |

|------|-------------|-----------|------|------|

| 科技园路10号 | 科技园(POI) | 路(ROAD) | 组合 → ROAD(科技园, 路) | ✓ |

| 花园街5号 | 花园(POI) | 街(ROAD) | 组合 → ROAD(花园, 街) | ✓ |

| 住宅楼GG栋 | 住宅(POI) | 楼(DETAIL) | 组合 → value="住宅"→正规化为空→丢弃; 栋(BUILDING)正常处理 | ✓ |

| 深圳湾社区E栋 | 湾(POI) | 社区(SUBDISTRICT) | 组合 → SUBDISTRICT(深圳湾, 社区) | ✓ |

| 科苑花园C栋 | 花园(POI) | 栋(BUILDING) → 不紧邻(中间有"C") | POI独立提交 → POI(科苑, 花园); BUILDING(C, 栋) | ✓ |

| 产业园小区A栋 | 产业园(POI) | 小区(POI) | 替换 → 新deferred=小区; 小区后接栋(BUILDING)不紧邻 → POI(产业园小区, 小区)... | 需确认 |



\---



\## 三、逆序必须有逗号



\### 修改位置



`address.py` 第 290-300 行，进入 `in_trailing_admin = True` 前增加逗号检查：



\```python

\# 检查上一个 component 的 end 到当前 clue 的 start 之间是否有逗号

gap_text = raw_text[last_end : clue.start]

has_comma = ',' in gap_text or '，' in gap_text

if not has_comma:

​    break  # 无逗号 → 不视为逆序，直接截断

in_trailing_admin = True

\```



\### 逆序尾部类型



保持不变：`_TRAILING_ADMIN_TYPES = {PROVINCE, CITY, DISTRICT}`



\---



\## 四、需修改的文件清单



\### 第 1 步：枚举 & 关键词（基础层）



| 文件 | 改动 |

|------|------|

| `privacyguard/infrastructure/pii/detector/models.py` | 重写 `AddressComponentType` 枚举：保留 PROVINCE/CITY/DISTRICT，新增 SUBDISTRICT/ROAD/NUMBER/POI/BUILDING/DETAIL，删除其余 |

| `data/scanner_lexicons/zh_address_keywords.json` | 按新类型合并关键词组；新增"大楼"到 POI；"楼"移至 DETAIL；"社区"移至 SUBDISTRICT |

| `data/scanner_lexicons/en_address_keywords.json` | street→road, compound→poi, unit/floor/room→detail, admin→删除(或保留为 SUBDISTRICT), direction→删除 |



\### 第 2 步：下游依赖适配



| 文件 | 改动 |

|------|------|

| `privacyguard/infrastructure/repository/schemas.py` | `AddressLevel` 枚举、`_ADDRESS_LEVEL_FIELDS`、`AddressLevelExposureStats` 字段全部改为新 9 类型 |

| `privacyguard/utils/normalized_pii.py` | `_ADDRESS_COMPONENT_KEYS`、`_ADDRESS_MATCH_KEYS`、`_ADDRESS_DETAIL_KEYS`、`_LOCAL_ADMIN_KEYS`、`_ADDRESS_COMPONENT_ALIASES` 全部改为新类型名 |

| `privacyguard/utils/pii_value.py` | `_en_address_unit_prefixes()` 改为检查 "detail" 类型；`_en_address_street_suffixes()` 改为检查 "road" |

| `privacyguard/infrastructure/pii/address/types.py` | `AddressComponent.component_type` 字段文档更新（字符串值变了） |

| `privacyguard/infrastructure/pii/detector/lexicon_loader.py` | `_parse_component_type()` 无需改（它直接用 enum value 解析），但关联的 `_en_prefix_keywords()` 过滤逻辑需改为检查 DETAIL |



\### 第 3 步：地址 stack 核心重写



| 文件 | 改动 |

|------|------|

| `privacyguard/infrastructure/pii/detector/stacks/address.py` | **主要改动文件**，具体如下： |



address.py 改动明细：

1. **类型集合**：`_ADMIN_TYPES`、`_STREET_LEVEL`、`_DETAIL_LEVEL`、`_DETAIL_COMPONENTS`、`_SINGLE_EVIDENCE_ADMIN`、`_TRAILING_ADMIN_TYPES`、`_ANYWHERE_TYPES` → 全部改为新类型
2. **后继图**：`_VALID_SUCCESSORS` → 缩减为 9 节点新图
3. **"号"重映射**（第 283-288 行）：`STREET_NUMBER` → `NUMBER`，`FLOOR/BUILDING/UNIT` → `BUILDING/DETAIL` 后重映射为 DETAIL
4. **POI 延迟提交**：在主循环中新增 `deferred_poi: Clue | None` 状态，处理逻辑见第二节
5. **逆序逗号检查**：在 trailing admin 入口增加逗号检查
6. **digit_tail**：`_DETAIL_HIERARCHY` 和 `_DIGIT_TAIL_MAX_LEN` 简化 → 只需 BUILDING 和 DETAIL 两个层级；`_greedy_assign_types` 简化
7. **`_en_prefix_keywords()`**：改为过滤 DETAIL 类型
8. **默认 key 函数**：`_default_zh_address_keys()` / `_default_en_address_keys()` 自动适配（从 JSON 派生）



\### 第 4 步：脚本 & 测试



| 文件 | 改动 |

|------|------|

| `scripts/debug_address_stack_trace.py` | 更新引用的枚举值 |

| `tests/test_address_stack.py` | 更新 component_type 引用，新增 POI 延迟提交和逆序逗号测试用例 |

| `tests/test_scanner_containment_coverage.py` | 更新 component_type 引用 |

| `tests/test_negative_collision_risk.py` | 间接引用 JSON，自动适配 |



\---



\## 五、验证方案



\```bash

\# 1. 全量测试

C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/ -x -v



\# 2. 重点测试地址 stack

C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/test_address_stack.py -x -v



\# 3. 用 debug 脚本验证关键地址

C:\Users\vis\.conda\envs\paddle\python.exe scripts/debug_address_stack_trace.py

\```



测试用例应覆盖：

\- "科技园路10号" → POI 延迟 + ROAD 吞噬

\- "住宅楼GG栋1102" → POI 延迟 + DETAIL 吞噬（value 为空丢弃）+ BUILDING 正常

\- "深圳湾社区E栋602" → POI 延迟 + SUBDISTRICT 吞噬

\- "科苑花园C栋1503" → POI 独立提交（与 BUILDING 不紧邻）

\- "金钟路968号,上海市" → 逆序有逗号 → 允许

\- "金钟路968号上海市" → 逆序无逗号 → 截断