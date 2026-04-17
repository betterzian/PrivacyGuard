# 地址多层级 admin、MULTI_ADMIN component 与 has_admin 比较闸门实现计划

---

## 0. 设计目标与不变式

### 0.1 三类典型场景

| 场景 | 例子 | 目标行为 |
|------|------|---------|
| value 多层 | 北京（province/city）、朝阳（city/district）、New York（city/state）| 全部层级保留为 `level` 元组；≥2 层时落 `MULTI_ADMIN` |
| key 多层 | "市" ∈ {PROVINCE, CITY, DISTRICT_CITY} | 显式注册 KEY levels；与 value levels 取交集；交集单元素直接落；多元素进 `MULTI_ADMIN` |
| key+value 组合 | "北京市" / "张家港市" | value↔key 走 intersection；intersection ≥2 则落 `MULTI_ADMIN`；左侧无 value 时 "市"→`DISTRICT_CITY` |

### 0.2 落地形态语义

#### `_DraftComponent.level`

- **所有** `_DraftComponent` 都有 `level: tuple[AddressComponentType, ...]`，**始终非空**。
- 普通 component：`level=(SINGLE,)`，例：`ROAD(value=中山, key=路, level=(ROAD,))`。
- MULTI_ADMIN：`level=(P, C)` 等多元素元组，按 `_ADMIN_RANK` 降序排列。
- `component_type` 作为 `level` 的 derived 视图：
  - `len(level) == 1` → `component_type = level[0]`
  - `len(level) >= 2` → `component_type = MULTI_ADMIN`
- 不变式：`level` 的 mutate 必须经过 `_set_component_level` 统一入口，自动同步 `component_type`。

#### `_SuspectEntry.level`

- `level: tuple[AddressComponentType, ...]`（始终非空）。
- 同 value 多层 suspect 用**单条 entry**表达。
- 例：`北京中山路` → `ROAD.suspected = [_SuspectEntry(level=(P, C), value="北京", key="", origin="key")]`。
- 序列化：`_serialize_suspected_entries` 直接读 `entry.level` 元组输出 `{"levels":["province","city"],"value":"北京","key":"","origin":"key"}`。

#### canonical / same-entity 比较语义

**核心规则**：两个地址比较时，对每个 admin 层级 `L`，查找"level 元组中包含 `L` 的 component"（而非按 `component_type` 精确匹配）。MULTI_ADMIN(P,C) 既能在 L=P 被查到也能在 L=C 被查到。

**多层消歧的"或链"语义**：MULTI_ADMIN 的 value 在哪一层属实是**歧义的**。两个地址判定为同实体的充分必要条件是：**存在一种对双方所有 MULTI_ADMIN 的层级解释**，使得在所有"双方共同拥有的层级"上值都一致。等价于：枚举每个 MULTI_ADMIN 的层级解释（2^k 种组合，k = 双方 MULTI_ADMIN 总数），对每种组合做标准单层比较，**任一成立即匹配**。

| A | B | 推理 | 结论 |
|---|---|------|------|
| MULTI(北京,P,C) | PROVINCE=江苏, CITY=南京 | interp A=P: 北京≠江苏; interp A=C: 北京≠南京；两种解释全不符 | 明确不同 |
| MULTI(北京,P,C) | PROVINCE=江苏 (仅一层) | A=C: B 无 C 可比 → 无冲突 | 不可判定 → 交由 has_admin 闸门裁决 |
| MULTI(北京,P,C) | PROVINCE=北京 | A=P 匹配 | 同 |
| MULTI(北京,P,C) | PROVINCE=江苏, CITY=北京 | A=C 匹配；P 层重释为不比较 | 同 |
| MULTI(北京,P,C) | PROVINCE=北京, CITY=南京 | A=P 匹配 | 同 |
| MULTI(北京,P,C) | 仅 DISTRICT=朝阳 | 无 P/C 共同层 | 交由 has_admin 闸门裁决 |

**suspect OR 链（核心语义）**：每个 component 的 `suspected` 列表把可能值扩展到额外层级。当前层 L 的判定步骤：

1. **同层级 peer 子串检验**：`surface = entry.value + entry.key`，若 `surface` 落在**对侧同 component_type 组件**（peer）的 value 内 → 认作一致。
   - 语义：suspect 的文本出现在 peer 同层名字里，说明这段文本是同层名字的一部分（例如：左 ROAD.suspect "北京" 出现在右 ROAD.value "北京中山" 里，则 "北京" 属路名拼接而非行政），不视为行政不一致；同时**不**将 suspect-owner 侧标记为 has_admin。
2. **对侧 suspect 同 level**：对侧 peer.suspected 里有任一 entry 的 `level` 覆盖 L 且 value 相等 → 一致。
3. **对侧 level 覆盖组件**：对侧存在 level 元组覆盖 L 的 component 且 value 相等 → 一致。
4. 其余 → 不一致。

**DISTRICT_CITY 与 DISTRICT 无 level 交集**（一个是 `(DISTRICT_CITY,)`，另一个是 `(DISTRICT,)`），按上述规则**不参与互通**——符合"不同行政性质不做模糊匹配"语义。

### 0.3 重复同值行政对的就地降解

**场景**："北京市北京市朝阳区"——第一个 MULTI_ADMIN(北京,(P,C)) 已占住 P+C，第二个"北京市"进入时必须触发降解。

**机制**：admin VALUE **即将作为 admin commit** 时（`_flush_chain_as_standalone` / `_flush_admin_key_chain` 路径），若 incoming_value 与现存 MULTI_ADMIN 同值且 level 有交集：

| pair 间 | MULTI_ADMIN 保留 | 新来者得到 |
|--------|------------------|-----------|
| 无逗号 | 最高层（PROVINCE） | 次高层（CITY） |
| 有逗号 | 最低层（CITY） | 最高层（PROVINCE） |

**关键限制**：collision 仅在 **admin commit 路径**触发。VALUE 被非行政 KEY 吸收进 suspect 的场景（如"北京中山路"）**不**触发 collision——suspect 是元数据旁注，不挤占 MULTI_ADMIN 的 occupancy。

**"北京市北京市上海市"**：第二个"北京市"触发降解后 P+C 均具体占用，上海市的 `_segment_admit` 自然失败 → `split_at` → 上海市成为新地址，无需额外处理。

### 0.4 PROVINCE→DISTRICT 后继关系

`_VALID_SUCCESSORS[PROVINCE]` 加入 `DISTRICT` 与 `DISTRICT_CITY`，使"北京朝阳"类跳层场景成立，不再依赖中间 CITY 占位。

### 0.5 suspect 与 MULTI_ADMIN 的语义切分

| 概念 | 性质 | 触发来源 | 数据载体 |
|------|------|---------|---------|
| **MULTI_ADMIN** | 本体论：实体真实承担多层（北京 *是* 省 *也是* 市） | scanner 词典 dual-emit / KEY×VALUE intersection | `_DraftComponent(level=(P,C), component_type=MULTI_ADMIN)` |
| **suspect** | 认识论：值是否属于此层不确定（被非行政 KEY 吸收 / 上下文歧义） | `_freeze_value_suspect_for_mismatched_admin_key` / `_freeze_key_suspect_from_previous_key` | `_DraftComponent.suspected: list[_SuspectEntry]` |

两者**正交**：MULTI_ADMIN 是**真状态**（影响 occupancy / successor），suspect 是**只读元数据**（不参与提交决策，仅用于 metadata 与 canonical 比对）。

"北京中山路"完整流程：
```
北京 VALUE → pending_suspects（不进 deferred_chain）
中山路 KEY=路 → 触发 _freeze_key_suspect_from_previous_key
              → 写入 _SuspectEntry(level=(P, C), value="北京", key="", origin="key")
ROAD commit → ROAD(value="北京中山", key="路", level=(ROAD,), suspected=[entry])
_fixup_suspected_info → 用 entry.value+entry.key="北京"+"" 从 value 切去前缀
最终         → ROAD(value="中山", key="路", level=(ROAD,), suspected=[entry])
```

### 0.6 has_admin 标记：比较阶段的行政区闸门

#### 动机

"北京中山路"可能是一条真实路名（纯路名），也可能是北京市的"中山路"（行政 + 路）。两种解释都合法，系统无法从单侧语义上消歧。为同时满足：

- 允许 `北京中山路` ≡ `中山路`（对方无行政信息，放行）
- 禁止 `朝阳中山路` ≡ `江苏省中山路`（双方都有行政信息但无共同层可匹配，拒绝）

在 `NormalizedPII` 上引入一个 `has_admin: bool` 闸门。

#### 语义

`has_admin` 表示"该地址承载可验证的行政区信息"。**admin 层仅指** `{PROVINCE, CITY, DISTRICT, DISTRICT_CITY}`；`SUBDISTRICT` **不**参与 has_admin 计算。

#### 计算

初始 `False`。满足任一条件即改 `True`：

**Case 1（静态 / 单侧可预计算）**：存在已提交 component 其 `level` 与 admin 集合有交集（单层 PROVINCE / CITY / DISTRICT / DISTRICT_CITY，或 MULTI_ADMIN）。

**Case 2（动态 / 双边比较时确定）**：某 component（层级 key1，通常为 ROAD / POI / BUILDING / DETAIL）的 suspect entry `e`（entry.level ⊂ admin 集合）在执行 suspect OR 链**第 1 步**时失败——即 `e.value + e.key` 不是对侧同 component_type peer value 的子串：

- peer 存在但子串判定失败 → 该 suspect 的 value 不是 peer 同层名字的一部分 → 它真实承担 admin 语义 → 当前侧 has_admin=True。
- peer 不存在（对侧同 component_type 组件缺失）→ 无法证伪 suspect 的行政属性 → 保守计为 admin → 当前侧 has_admin=True。

Case 2 仅对 entry.level 完全落在 admin 集合内的 suspect 有效（当前所有 `_freeze_*` 路径产生的 entry 均满足此约束）。

#### 使用（`_same_address` 中作为闸门）

设 `admin_result ∈ {match, mismatch, inconclusive}` 为 `_compare_admin_levels_with_interpretations` 的返回：

- `admin_result == mismatch` → 不同实体（无条件失败）。
- `admin_result == match` → admin 通过，继续其它层比较。
- `admin_result == inconclusive`：
  - 若 `left.has_admin and right.has_admin` → 不同实体（双方都有行政信息却无共同可比层）。
  - 若**任一**侧 `has_admin == False` → admin 不计失败也不计命中，继续其它层比较。

`has_admin` 双边最终值 = Case 1 结果 ∪ Case 2 结果（两者任一为 True 即 True）。Case 2 在遍历 suspect OR 链时顺带累计，不单独二次遍历。

### 0.7 输入解释规则

| 输入 | 目标组件链 |
|------|----------|
| 北京 | MULTI_ADMIN(value=北京, level=(P,C)) |
| 北京市 | MULTI_ADMIN(value=北京, key=市, level=(P,C)) |
| 苏州市 | CITY(value=苏州, key=市, level=(CITY,)) |
| 苏州市张家港市 | CITY(苏州,市) + DISTRICT_CITY(张家港,市) |
| 张家港市 | DISTRICT_CITY(张家港, 市) |
| 北京市朝阳区 | MULTI_ADMIN(北京,市,(P,C)) + DISTRICT(朝阳,区) |
| 北京朝阳 | MULTI_ADMIN(北京,(P,C)) + DISTRICT(朝阳,(D,)) |
| 北京市北京市朝阳区 | PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) |
| 北京北京朝阳 | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳) |
| 朝阳区,北京市,北京市 | DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) |
| 朝阳,北京,北京 | DISTRICT(朝阳) + CITY(北京) + PROVINCE(北京) |
| 朝阳区,北京市北京市 | DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) |
| 北京市北京市上海市 | PROVINCE(北京,市) + CITY(北京,市) ∥ 上海市→新地址 |
| 北京北京 | PROVINCE(北京) + CITY(北京) |
| 北京中山路 | ROAD(中山, key=路, level=(ROAD,), suspected=[{level=(P,C), value=北京, key=""}]) |
| 南京中山路, 南京市 | ROAD(中山, 路, suspected=[]) + CITY(南京) |
| Brooklyn, New York, NY | DISTRICT(Brooklyn) + CITY(New York) + PROVINCE(NY) |

---

## 1. 关键决策汇总

| Q | 决议 |
|---|------|
| `_DraftComponent.level` 字段 | 所有 component 都有；`tuple[AddressComponentType, ...]`；始终非空 |
| `component_type` 字段 | 保留，作为 `level` 的 derived 视图 |
| `_SuspectEntry.level` 字段 | `tuple[AddressComponentType, ...]`；单条 entry 即可表达多层 |
| "市" KEY 无邻接 value 时降级 | `DISTRICT_CITY` |
| KEY 是否多层 | KEY 多层；value↔key 走交集 |
| DISTRICT_CITY 表达 | `AddressComponentType.DISTRICT_CITY`，`_ADMIN_RANK`=2，与 DISTRICT 同级互斥 |
| MULTI_ADMIN 表达 | `AddressComponentType.MULTI_ADMIN`，作为 `len(level)>=2` 时的 derived 类型 |
| MULTI_ADMIN occupancy | 锁住 `level` 中每层的 occupancy slot；不另设 MULTI_ADMIN slot |
| MULTI_ADMIN successor | 前 MULTI_ADMIN：levels 后继**交集**（严格）；后 MULTI_ADMIN：levels 中**任一层**合法即可（宽松） |
| levels 域 | 仅 PROVINCE / CITY / DISTRICT / DISTRICT_CITY / SUBDISTRICT 参与 MULTI_ADMIN |
| has_admin admin 层域 | `{PROVINCE, CITY, DISTRICT, DISTRICT_CITY}`；SUBDISTRICT 不参与 |
| 重复同值对的方向 | 无逗号→正序（高层先）；有逗号→逆序（低层先） |
| collision 触发点 | **仅** admin commit 路径（`_flush_chain_as_standalone` / `_flush_admin_key_chain`）；**不**在 `_freeze_*` 触发 |
| 中英文 | 共用同一 admin span 抽象；enstack 自定 `_ADMIN_RANK` / `_VALID_SUCCESSORS` |
| suspect 函数 | 全部保留；suspect 与 MULTI_ADMIN 正交 |
| suspect OR 链第 1 步 | 检验 `entry.value+entry.key` 是否为**同 component_type peer value** 子串；失败时同时作为 has_admin case 2 信号 |
| canonical 比较 | 按 level 查找 + 多解释枚举；双方 has_admin=True 时 admin 必须 "match"（inconclusive 视为失败） |

KEY 显式 levels 表（硬编码在 `address_policy_common.py`）：

```python
_MULTI_LEVEL_KEY_LEVELS: dict[str, tuple[AddressComponentType, ...]] = {
    "市": (AddressComponentType.PROVINCE,
           AddressComponentType.CITY,
           AddressComponentType.DISTRICT_CITY),
}

def key_levels(clue: Clue) -> tuple[AddressComponentType, ...]:
    explicit = _MULTI_LEVEL_KEY_LEVELS.get(clue.text)
    if explicit:
        return explicit
    if clue.component_type is None:
        return ()
    return (clue.component_type,)
```

has_admin 层集合常量（`normalized_pii.py`）：

```python
_HAS_ADMIN_LEVEL_KEYS = frozenset({"province", "city", "district", "district_city"})
```

---

## 2. 阶段 0 — 类型与共享基建

### 2.1 新增枚举 [`models.py`]

```python
AddressComponentType.DISTRICT_CITY = "district_city"
AddressComponentType.MULTI_ADMIN   = "multi_admin"
```

### 2.2 `_DraftComponent.level` 字段 [`address_state.py`]

```python
@dataclass(slots=True)
class _DraftComponent:
    component_type: AddressComponentType   # derived from level
    level: tuple[AddressComponentType, ...] = ()
    start: int = 0
    end: int = 0
    value: str | list[str] = ""
    key: str | list[str] = ""
    is_detail: bool = False
    raw_chain: list[Clue] = field(default_factory=list)
    suspected: list["_SuspectEntry"] = field(default_factory=list)
    clue_ids: set[str] = field(default_factory=set)
    clue_indices: set[int] = field(default_factory=set)
    suspect_demoted: bool = False

    def __post_init__(self) -> None:
        if not self.level:
            assert self.component_type is not None and self.component_type != AddressComponentType.MULTI_ADMIN
            self.level = (self.component_type,)
        else:
            self.level = _ordered_component_level(self.level)
        self._sync_component_type()

    def _sync_component_type(self) -> None:
        if len(self.level) == 1:
            self.component_type = self.level[0]
        else:
            assert len(self.level) >= 2
            self.component_type = AddressComponentType.MULTI_ADMIN
```

`_clone_draft_component` 同步复制 `level`。

辅助函数：

```python
def _ordered_component_level(level: tuple[AddressComponentType, ...]) -> tuple[AddressComponentType, ...]:
    if len(level) <= 1:
        return tuple(level)
    return tuple(sorted(level, key=lambda l: -_ADMIN_RANK.get(l, 0)))

def _set_component_level(comp: _DraftComponent, new_level: tuple[AddressComponentType, ...]) -> None:
    comp.level = _ordered_component_level(new_level)
    comp._sync_component_type()
```

### 2.3 `_SuspectEntry.level` 字段 [`address_state.py`]

```python
@dataclass(slots=True)
class _SuspectEntry:
    level: tuple[AddressComponentType, ...]
    value: str
    key: str
    origin: str
    start: int
    end: int

    def __post_init__(self) -> None:
        assert len(self.level) >= 1
        self.level = _ordered_component_level(self.level)
```

### 2.4 类型表更新 [`address_state.py`]

- `SINGLE_OCCUPY` += `{DISTRICT_CITY}`（**不**加 MULTI_ADMIN：MULTI_ADMIN 通过 `level` 中各层占位）
- `_ADMIN_TYPES` += `{DISTRICT_CITY}`
- `_COMMA_TAIL_ADMIN_TYPES` += `{DISTRICT_CITY}`
- `_SUSPECT_KEY_TYPES` += `{DISTRICT_CITY}`
- `_ADMIN_RANK`：`DISTRICT_CITY = 2`（与 DISTRICT 同）；MULTI_ADMIN 不入表
- 新辅助：

  ```python
  def _is_admin_component(comp: _DraftComponent) -> bool:
      return any(l in _ADMIN_TYPES for l in comp.level)

  def _admin_rank_max(comp: _DraftComponent) -> int:
      return max((_ADMIN_RANK.get(l, 0) for l in comp.level), default=0)

  def _admin_levels_of(comp: _DraftComponent) -> tuple[AddressComponentType, ...]:
      return tuple(l for l in comp.level if l in _ADMIN_TYPES)
  ```

- `_VALID_SUCCESSORS`：
  - `PROVINCE` 后继 += `{DISTRICT, DISTRICT_CITY}`
  - `CITY` 后继 += `{DISTRICT_CITY}`
  - `DISTRICT_CITY` 后继 = `DISTRICT` 等价集合
  - MULTI_ADMIN 不入静态表，由 `_segment_admit` 按 `level` 动态解析

### 2.5 `_commit` occupancy 写入 [`address_state.py`]

```python
for level in component.level:
    if level in SINGLE_OCCUPY:
        state.occupancy[level] = index
```

MULTI_ADMIN 的 `level=(P,C)` → `state.occupancy[P] = state.occupancy[C] = index`（两者指向同一 idx）。**不**另设 `state.occupancy[MULTI_ADMIN]`。

碰撞反查：`state.components[state.occupancy[P]].component_type == MULTI_ADMIN` 判定该层是否被多层 component 占据。

### 2.6 `_segment_admit` MULTI_ADMIN 后继逻辑 [`address_state.py`]

```python
def _effective_successors(prev: _DraftComponent | None) -> frozenset[AddressComponentType]:
    if prev is None:
        return _ALL_TYPES
    if prev.component_type == AddressComponentType.MULTI_ADMIN:
        sets = [_VALID_SUCCESSORS.get(l, _ALL_TYPES) for l in prev.level]
        return frozenset.intersection(*[frozenset(s) for s in sets])
    return _VALID_SUCCESSORS.get(prev.component_type, _ALL_TYPES)

def _component_can_follow(prev: _DraftComponent | None,
                          next_level: tuple[AddressComponentType, ...]) -> bool:
    valid = _effective_successors(prev)
    return any(l in valid for l in next_level)
```

`_segment_occupancy_conflict` 按 `level` 元组遍历：

```python
def _segment_occupancy_conflict(state, level_tuple):
    return any(_occupies_level(state, l) for l in level_tuple)
```

DISTRICT_CITY 与 DISTRICT 互斥（`_occupies_level` 双向检查 SINGLE_OCCUPY）。

### 2.7 公共 admin span 工具上提 [`address_policy_common.py`]

将以下工具从 `address_policy_zh.py` 上提到 `address_policy_common.py`，不保留 re-export：

`_AdminValueSpan`, `collect_admin_value_span`, `_is_admin_value_clue`, `_same_admin_value_span`, `_build_admin_value_span`, `_ordered_admin_levels`, `match_admin_levels`, `_collect_chain_edge_admin_value_span`

EN 与 ZH 共用同一抽象，但 `_ADMIN_RANK` / `_VALID_SUCCESSORS` 由各 stack 注入（见 6.3）。

---

## 3. 阶段 1 — value 多层级与 MULTI_ADMIN 落地

### 3.1 scanner 直辖市 dual-emit [`scanner.py`]

删除：
```python
direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}  # 单转 CITY
```

直辖市通过词典自然以 PROVINCE + CITY 双层级注册。scanner 同 span 多层级机制（`seen: set[(component_type, text)]`）已支持。

### 3.2 词典层级补齐 [`data/scanner_lexicons/zh_geo_lexicon.json`]

- `provinces.soft` 补入 `{北京, 上海, 天津, 重庆}`（`cities.soft` 已有）
- `district_cities.soft`：新建，初始填 `{张家港}` 等典型县级市
- 不补普通县级市到 `cities`

### 3.3 `resolve_admin_value_span` [`address_policy_common.py`]

返回结构 `_AdminResolveResult(level)`：

- `level: tuple[AddressComponentType, ...]`：occupancy + segment 过滤后剩余的全部可用层级，按 `_ADMIN_RANK` 降序

调用方按 `len(level)` 决定落普通还是 MULTI_ADMIN。

### 3.4 `_flush_chain_as_standalone` admin group 分支 [`address_state.py`]

```python
if len(level) >= 2:
    component = _DraftComponent(
        component_type=AddressComponentType.MULTI_ADMIN,
        level=level, ..., suspected=[],
    )
elif len(level) == 1:
    component = _DraftComponent(
        component_type=level[0], level=level, ..., suspected=[...],
    )
else:
    forced = _resolve_multi_admin_collision(state, raw_text, clue.start, value, origin_levels)
    if forced is None:
        state.split_at = clue.start; return
    # 走强制 level 落库
```

`_remove_pending_suspect_group_by_span` 承担"清理 pending 中已被本次 commit 消化的同 span suspect"职责；剩余层信息由 `level` 字段承载。

### 3.5 KEY-driven `_flush_admin_key_chain` 单段多层处理 [`address_state.py`]

```python
def _flush_admin_key_chain(state, used_entries, key_clue, ...):
    span = _build_admin_value_span(used_entries)
    candidate_levels = ordered_intersect(span.level, key_levels(key_clue))
    available = _filter_available(state, candidate_levels)
    if not available:
        forced = _resolve_multi_admin_collision(
            state, raw_text, span.start, span.text, candidate_levels,
        )
        if forced is None:
            state.split_at = span.start; return
        available = forced
    if len(available) >= 2:
        component_type, level = AddressComponentType.MULTI_ADMIN, available
    else:
        component_type, level = available[0], available
    component = _DraftComponent(
        component_type=component_type, level=level,
        value=normalize(span.text), key=key_clue.text, ...,
    )
    commit(component)
```

### 3.6 KEY-driven 链中同段重复对处理 [`address_state.py`]

`_flush_admin_key_chain` 在**同一次 flush**中遇到相同 value 的相邻段（链内"北京市北京市"）：

```python
if (
    cursor + 1 < len(segments)
    and len(available_levels) == 2
    and segments[cursor + 1][4] == segment_value
    and tuple(segments[cursor + 1][3]) == tuple(candidate_levels)
    and (len(segments) > 2 or _has_admin_anchor_before_chain(state))
):
    has_comma = any(char in ",，" for char in raw_text[...])
    high_level, low_level = available_levels[0], available_levels[1]
    resolved.append(((low_level if has_comma else high_level,), ()))
    resolved.append(((high_level if has_comma else low_level,), ()))
    cursor += 2
    continue
```

直接产出**单层** component（每个 `level=(single,)`），不走 MULTI_ADMIN。

---

## 4. 阶段 2 — KEY 多层级与 intersection 路由

### 4.1 KEY levels 注册 [`address_policy_common.py`]

```python
_MULTI_LEVEL_KEY_LEVELS: dict[str, tuple[AddressComponentType, ...]] = {
    "市": (AddressComponentType.PROVINCE,
           AddressComponentType.CITY,
           AddressComponentType.DISTRICT_CITY),
}

def key_levels(clue: Clue) -> tuple[AddressComponentType, ...]:
    explicit = _MULTI_LEVEL_KEY_LEVELS.get(clue.text)
    if explicit:
        return explicit
    if clue.component_type is None:
        return ()
    return (clue.component_type,)
```

### 4.2 `_routed_key_clue` [`address_policy_zh.py`]

```python
def _routed_key_clue(context, clue_index, clue):
    adjacent_span = _adjacent_value_span(context, clue_index, clue)

    if adjacent_span is not None:
        intersection = ordered_intersect(adjacent_span.level, key_levels(clue))
        if not intersection:
            return None
        if len(intersection) == 1:
            return replace(clue, component_type=intersection[0])
        return replace(clue, component_type=AddressComponentType.MULTI_ADMIN)

    if clue.text == "市":
        return replace(clue, component_type=AddressComponentType.DISTRICT_CITY)
    if clue.text == "省":
        return None
    return clue
```

**不**给 `Clue` 加 `levels` 字段。intersection 信息在 `_flush_admin_key_chain` 中由 `key_levels(clue) ∩ span.level` 重新计算，避免污染 scanner 输出。

### 4.3 `_handle_key_clue` 处理 MULTI_ADMIN routed key [`address_zh.py`]

`effective_clue.component_type == MULTI_ADMIN` 时，照常入 deferred_chain，flush 路径在 3.5 处理多层 commit。

---

## 5. 阶段 3 — 重复同值行政对就地降解

### 5.1 `_resolve_multi_admin_collision` [`address_state.py`]

```python
def _resolve_multi_admin_collision(
    state: _ParseState,
    raw_text: str,
    incoming_start: int,
    incoming_value: str,
    incoming_levels: tuple[AddressComponentType, ...],
) -> tuple[AddressComponentType, ...] | None:
    """
    仅在 admin commit 路径调用。若 incoming_value 与某已提交的 MULTI_ADMIN 同值
    且 level 有交集，根据 pair 间逗号方向把 MULTI_ADMIN 降解，返回 incoming 应取
    的 level 子集。无碰撞或无法降解返回 None。
    """
    target_idx = None
    for lvl in incoming_levels:
        idx = state.occupancy.get(lvl)
        if idx is None: continue
        comp = state.components[idx]
        if (comp.component_type == AddressComponentType.MULTI_ADMIN
                and not isinstance(comp.value, list)
                and comp.value == incoming_value):
            target_idx = idx; break
    if target_idx is None:
        return None

    existing = state.components[target_idx]
    overlap = [l for l in existing.level if l in incoming_levels]
    if not overlap:
        return None

    has_comma = any(c in ",，" for c in raw_text[existing.end:incoming_start])
    if has_comma:
        existing_keep = min(overlap, key=lambda l: _ADMIN_RANK[l])
        incoming_take = max(overlap, key=lambda l: _ADMIN_RANK[l])
    else:
        existing_keep = max(overlap, key=lambda l: _ADMIN_RANK[l])
        incoming_take = min(overlap, key=lambda l: _ADMIN_RANK[l])

    state.occupancy.pop(incoming_take, None)
    new_level = tuple(l for l in existing.level if l != incoming_take)
    _set_component_level(existing, new_level)

    # 同步 component_counts
    if AddressComponentType.MULTI_ADMIN in state.component_counts:
        state.component_counts[AddressComponentType.MULTI_ADMIN] -= 1
        if state.component_counts[AddressComponentType.MULTI_ADMIN] == 0:
            del state.component_counts[AddressComponentType.MULTI_ADMIN]
    if existing.component_type != AddressComponentType.MULTI_ADMIN:
        _increment_component_count(state, existing.component_type)

    if state.last_component_type == AddressComponentType.MULTI_ADMIN:
        state.last_component_type = existing.component_type

    if state.segment_state.group_last_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_last_type = existing.component_type
    if state.segment_state.group_first_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_first_type = existing.component_type
    state.segment_state.direction = None

    return (incoming_take,)
```

### 5.2 触发点

#### 5.2.1 admin VALUE 进入 `_segment_admit` 前 [`address_zh.py`]

```python
if admin_span is not None and not state.deferred_chain:
    if _occupancy_fully_blocked(state, admin_span.level):
        forced = _resolve_multi_admin_collision(
            state, raw_text, clue.start, clue.text, admin_span.level,
        )
        if forced is not None:
            admit_level = forced
        else:
            ...
```

#### 5.2.2 `_flush_chain_as_standalone` 同值重复段

在 cursor 处理 admin VALUE 组时，若 resolve 返回空但存在同值 MULTI_ADMIN，触发 collision（见 3.4 流程）。

#### 5.2.3 `_flush_admin_key_chain` 同上

见 3.5 伪码。

#### 5.2.4 `_freeze_*` 路径**不触发**

suspect 是元数据旁注，不占 occupancy。suspect 的 `level` 元组保持原 value 的候选层级原样写入，不做降解。

### 5.3 流程验证

#### "北京市北京市朝阳区"（无逗号）

```
"北京市"[1] → _flush_admin_key_chain → candidate=(P,C), available=(P,C)
            → MULTI_ADMIN(北京,市,(P,C)), occupancy: {P:0, C:0}

"北京"[2] VALUE → admin_span.level=(P,C), occupancy 全被 MULTI_ADMIN 占
                → _resolve_multi_admin_collision:
                   existing=MULTI_ADMIN at 0, overlap=[P,C], no comma
                   → existing 保 P (→ PROVINCE(北京,市)), incoming 取 C
                   → 返回 (C,)
                → admit_level=(C,) → 加入 chain

"市" KEY → CITY(北京,市) → occupancy: {P:0, C:1}
"朝阳区" → DISTRICT(朝阳,区)
```

#### "朝阳区,北京市,北京市"（pair 间有逗号）

```
"朝阳区" → DISTRICT(朝阳,区), comma_tail, group_first=DISTRICT
"北京市"[1] → MULTI_ADMIN(北京,市,(P,C))
"北京"[2] VALUE → _resolve_multi_admin_collision:
                   has_comma=True → existing 保 C → CITY(北京,市)
                   → 返回 (P,)
"市" KEY → PROVINCE(北京,市)
```

#### "北京市北京市上海市"

```
"北京市"[1] → MULTI_ADMIN(北京,(P,C)), occupancy: {P:0, C:0}
"北京市"[2] → 降解 → PROVINCE + CITY, occupancy: {P:0, C:1}
"上海" VALUE → admin_span.level=(P,C), 全 occupied
             → _resolve_multi_admin_collision: 无同值 MULTI_ADMIN → None
             → _segment_admit 失败 → split_at
```

#### "北京北京"（无 KEY、无 anchor）

```
"北京"[1] VALUE → scanner dual-emit (P,C) → admin_span.level=(P,C)
              → _flush_chain_as_standalone 落 MULTI_ADMIN(北京,(P,C))
              → occupancy: {P:0, C:0}

"北京"[2] VALUE → admin_span.level=(P,C), occupancy 全被 MULTI_ADMIN 占
              → _resolve_multi_admin_collision:
                   existing=MULTI_ADMIN at 0, overlap=[P,C], no comma
                   → existing 保 P → PROVINCE(北京), incoming 取 (C,)
              → 以 level=(C,) 走 _flush_chain_as_standalone 产出 CITY(北京)

结果：PROVINCE(北京) + CITY(北京)
```

**关键要求**：取消任何"连续重复同值 dual-level admin"场景下"第二个静默丢弃 / split 当新地址"的旁路（即 `_should_eager_split_duplicate_dual_admins` 或等价分支一律返回 False / 不入网）。第二个"北京"必须以 VALUE 身份触发 collision，走 5.1 降解路径。后续再接 `朝阳` 时 successor 检查按 CITY→DISTRICT 合法（直辖市链已不依赖 MULTI_ADMIN 占位）。

---

## 6. 阶段 4 — 英文 multi-admin

### 6.1 EN scanner 去重粒度对齐 [`scanner.py`]

```python
seen: set[str]  →  seen: set[tuple[AddressComponentType, str]]
```

使英文同名 dual-level entry 都注册。

### 6.2 `EnAddressStack` 接 deferred chain + admin span [`address_en.py`]

- `_handle_value_clue` 引入 `collect_admin_value_span`
- `_flush_chain` 子类化，传入 EN-friendly resolver
- 复用 `_resolve_multi_admin_collision`（参数化 `_ADMIN_RANK` / `_VALID_SUCCESSORS`）

### 6.3 EN ranking 与后继关系 [`address_policy_en.py`]

EN stack 维护 `_EN_ADMIN_RANK` 与 `_EN_VALID_SUCCESSORS`：

- rank：`STATE > CITY > DISTRICT > SUBDISTRICT`
- successor：`STATE → CITY → DISTRICT → SUBDISTRICT → ROAD → POI`

`_resolve_multi_admin_collision` 与 `_effective_successors` 接受 `admin_rank: dict` 与 `valid_successors: dict` 参数。

### 6.4 EN KEY 多层暂不引入

`is_prefix_en_key` 等接口保持单层。

### 6.5 数据：Brooklyn 等 NYC borough

`en_geo_lexicon.json`：`Brooklyn / Manhattan / Queens / Bronx / Staten Island` → `district`；`New York` → dual-level `city + state`。

---

## 7. 阶段 5 — 下游适配与比较器

### 7.1 `_address_metadata` 序列化 [`address_state.py`]

新增 trace 字段 `address_component_level`（与 `address_component_type` 平行）：

- 单层 component：`"road"` / `"province"` 等字符串
- MULTI_ADMIN：`"province|city"`（按 `_ADMIN_RANK` 降序 `|` 分隔）
- DISTRICT_CITY：`"district_city"`

### 7.2 `parser.py` 透传

新增 `address_component_level` 到透传白名单。

### 7.3 `normalized_pii.py` 常量与数据结构适配

- `_ADDRESS_COMPONENT_KEYS` += `("multi_admin", "district_city")`
- `_ORDERED_COMPONENT_KEYS`：`multi_admin` 插在 `province` 之前；`district_city` 插在 `district` 之后
- `_ADDRESS_MATCH_KEYS` += `("multi_admin", "district_city")`
- `_ADDRESS_COMPONENT_COMPARE_KEYS` += `("multi_admin", "district_city")`
- `_ADMIN_LEVEL_KEYS = ("province", "city", "district", "district_city", "subdistrict")`——canonical 比较时按此顺序逐层检验
- `_HAS_ADMIN_LEVEL_KEYS = frozenset({"province", "city", "district", "district_city"})`——has_admin 计算专用（SUBDISTRICT 不参与）
- `_ADMIN_LEVEL_RANK: dict[str, int]` 供多解释枚举时的排序

### 7.4 `NormalizedAddressComponent.level` 与 `NormalizedPII.has_admin` [`types.py`]

```python
@dataclass(frozen=True)
class NormalizedAddressComponent:
    component_type: str
    value: str | tuple[str, ...]
    key: str | tuple[str, ...] = ""
    suspected: tuple[NormalizedAddressSuspectEntry, ...] = ()
    level: tuple[str, ...] = ()   # 与 detector 端 _DraftComponent.level 一致

@dataclass(frozen=True)
class NormalizedPII:
    ...
    has_admin_static: bool = False   # Case 1 预计算；Case 2 在 _same_address 运行时合入
```

- 单层 component：`level=(component_type,)` 或为空（构造时由 `component_type` 反填充）
- MULTI_ADMIN：`level=("province","city")` 等
- `_ordered_components_from_metadata` 解析时读 `address_component_level` trace 挂到 component 上；若 trace 缺失则按 `component_type` 反填
- `has_admin_static` 在 `NormalizedPII` 构建时计算：遍历 `ordered_components`，任一 component 的 `level` 与 `_HAS_ADMIN_LEVEL_KEYS` 有交集即 True

`NormalizedAddressSuspectEntry` 已有 `levels: tuple[str, ...]`，保持不变。

### 7.5 canonical / same-entity 比较器

#### 7.5.1 按 level 查找

```python
def _component_covering_level(
    normalized: NormalizedPII,
    level: str,
    skip: frozenset[NormalizedAddressComponent] = frozenset(),
) -> NormalizedAddressComponent | None:
    """返回 level 元组中包含 level 且未被 skip 的第一个 component。"""
    for c in normalized.ordered_components:
        if c in skip:
            continue
        if level in c.level or (not c.level and c.component_type == level):
            return c
    return None
```

保留 `_ordered_component_by_type` 作 non-admin 快捷入口；admin 场景全部改走 `_component_covering_level`。

#### 7.5.2 `_same_address` 重写：has_admin 闸门 + 多解释枚举

```python
def _same_address(left: NormalizedPII, right: NormalizedPII) -> bool:
    if not left.identity.get("address_part") or not right.identity.get("address_part"):
        return False

    substantive_hits = 0

    for key in ("country", "province", "house_number", "postal_code"):
        if not _identity_field_match_if_both_present(left, right, key):
            return False
        if left.identity.get(key) and right.identity.get(key):
            substantive_hits += 1

    # has_admin 动态累计器：Case 1 的 static 结果作为起点
    left_has_admin = left.has_admin_static
    right_has_admin = right.has_admin_static

    # 非 admin 层级：road / poi / building / detail（suspect Case 2 在这里触发）
    for key in ("road", "poi", "building", "detail"):
        ok, left_admin_hit, right_admin_hit = _compare_peer_with_suspect_case2(
            left, right, key,
        )
        if not ok:
            return False
        left_has_admin = left_has_admin or left_admin_hit
        right_has_admin = right_has_admin or right_admin_hit
        if _ordered_component_by_type(left, key) and _ordered_component_by_type(right, key):
            substantive_hits += 1

    # admin 层级：多解释枚举
    admin_result = _compare_admin_levels_with_interpretations(left, right)
    if admin_result == "mismatch":
        return False
    if admin_result == "match":
        substantive_hits += 1
    else:  # "inconclusive"
        if left_has_admin and right_has_admin:
            return False   # 双方都有行政信息却无共同可比层 → 不同实体
        # 任一侧无行政信息 → 放行，不计命中

    if not _numbers_match(left.numbers, right.numbers,
                          left_keyed=left.keyed_numbers, right_keyed=right.keyed_numbers):
        return False
    if _numbers_substantive_pair(left, right):
        substantive_hits += 1

    if not _compare_poi_list(left, right):
        return False

    denom = min(len(left.ordered_components), len(right.ordered_components))
    if denom <= 0:
        return False
    return (substantive_hits / denom) > 0.3
```

#### 7.5.3 `_compare_peer_with_suspect_case2` — 非 admin 层比较并累计 Case 2

封装「比较同 component_type peer value + 走 suspect OR 链 + 顺带输出 has_admin Case 2 信号」三合一：

```python
def _compare_peer_with_suspect_case2(
    left: NormalizedPII,
    right: NormalizedPII,
    component_type: str,
) -> tuple[bool, bool, bool]:
    """
    返回 (match_ok, left_admin_from_suspect, right_admin_from_suspect)。

    - match_ok：本层整体比较是否通过（同 _compare_component_with_suspected 语义）。
    - left_admin_from_suspect：左侧是否有 suspect 在第 1 步 peer-subset 判定失败
      → 该 suspect 真实承担 admin 语义（entry.level ⊂ admin 集合时成立）。
    - right_admin_from_suspect：同上对右侧。
    """
    left_component = _ordered_component_by_type(left, component_type)
    right_component = _ordered_component_by_type(right, component_type)

    if left_component is None and right_component is None:
        return True, False, False

    # 值层比较：沿用 _admin_text_subset_either；任一为 None 时跳过值比较
    if left_component is not None and right_component is not None:
        if not _admin_text_subset_either(
            _component_value_text(left_component),
            _component_value_text(right_component),
        ):
            return False, False, False

    left_admin_hit = _suspect_chain_and_case2(left_component, right_component, right)
    right_admin_hit = _suspect_chain_and_case2(right_component, left_component, left)

    return True, left_admin_hit, right_admin_hit


def _suspect_chain_and_case2(
    component: NormalizedAddressComponent | None,
    other_component: NormalizedAddressComponent | None,
    other_normalized: NormalizedPII,
) -> bool:
    """遍历 component.suspected；逐条跑 3 步 OR 链，第 1 步失败且 entry.level
    全在 admin 集合内时累计 Case 2 命中（即使最终 OR 链通过）。
    返回 admin_hit（any-entry 聚合）。"""
    if component is None or not component.suspected:
        return False
    admin_hit = False
    for entry in component.suspected:
        result, step1_failed = _suspect_group_matches_with_flag(
            entry, other_component, other_normalized,
        )
        if result is False:
            # OR 链失败本身已在上层失败路径处理；但这里只关心 Case 2
            admin_hit = admin_hit or (
                step1_failed and _entry_level_all_admin(entry)
            )
            continue
        admin_hit = admin_hit or (
            step1_failed and _entry_level_all_admin(entry)
        )
    return admin_hit


def _entry_level_all_admin(entry: NormalizedAddressSuspectEntry) -> bool:
    return bool(entry.levels) and all(
        l in _HAS_ADMIN_LEVEL_KEYS for l in entry.levels
    )
```

注：上面把"OR 链是否通过"与"Case 2 是否命中"解耦——即便 OR 链最终通过（比如第 2/3 步命中），只要第 1 步未命中就记 Case 2。这符合 0.6 节"suspect value 不是 peer 同层名字的一部分"的判定语义。

#### 7.5.4 suspect 3 步 OR 链（暴露第 1 步失败信号）

```python
def _suspect_group_matches_with_flag(
    entry: NormalizedAddressSuspectEntry,
    other_component: NormalizedAddressComponent | None,
    other_normalized: NormalizedPII,
) -> tuple[bool | None, bool]:
    """
    返回 (match_result, step1_failed)。
    match_result: True / False / None（同现有语义）。
    step1_failed: 第 1 步（entry 文本是否为 peer 同 component_type value 的子串）是否"未命中"。
                  peer 不存在时也视为未命中（保守计 Case 2）。
    """
    surface = f"{entry.value}{entry.key}".strip()
    other_value = _component_value_text(other_component)

    if surface and other_value and surface in other_value:
        return True, False   # 第 1 步命中 → 不触发 Case 2

    step1_failed = True

    # 第 2 步：对侧 peer.suspected 同 level
    for level in entry.levels:
        peer_suspected = _suspect_entry_by_level(other_component, level)
        if peer_suspected is not None:
            return (peer_suspected.value.strip() == entry.value.strip()), step1_failed

    # 第 3 步：对侧按 level 查找任一覆盖该 level 的 component
    for level in entry.levels:
        other_level_component = _component_covering_level(other_normalized, level)
        if other_level_component is None:
            continue
        other_level_value = _component_value_text(other_level_component)
        if not other_level_value:
            continue
        return (other_level_value == entry.value.strip()), step1_failed

    return True, step1_failed   # 无从判定 → 不否决
```

`_suspect_entry_by_level` 现有实现已按 `level in entry.levels` 检查，保留。

#### 7.5.5 `_compare_admin_levels_with_interpretations` 返回三态

```python
def _compare_admin_levels_with_interpretations(
    left: NormalizedPII, right: NormalizedPII,
) -> str:
    """
    返回 "match" / "mismatch" / "inconclusive"。
    """
    left_multis = [c for c in left.ordered_components
                   if c.component_type == "multi_admin" or len(c.level) >= 2]
    right_multis = [c for c in right.ordered_components
                    if c.component_type == "multi_admin" or len(c.level) >= 2]

    def iter_interpretations(multis):
        if not multis:
            yield {}; return
        from itertools import product
        level_sets = [tuple(m.level) for m in multis]
        for combo in product(*level_sets):
            yield dict(zip(multis, combo))

    any_inconclusive_only = True

    for left_interp in iter_interpretations(left_multis):
        for right_interp in iter_interpretations(right_multis):
            result = _admin_match_under_interpretation(
                left, right, left_interp, right_interp,
            )
            if result == "match":
                return "match"
            elif result == "mismatch":
                any_inconclusive_only = False

    return "inconclusive" if any_inconclusive_only else "mismatch"


def _admin_match_under_interpretation(
    left: NormalizedPII,
    right: NormalizedPII,
    left_interp: dict,
    right_interp: dict,
) -> str:
    """某种解释下逐层比较。返回 match/inconclusive/mismatch。"""
    matched_any = False

    for L in _ADMIN_LEVEL_KEYS:
        left_value = _admin_value_at_level(left, L, left_interp)
        right_value = _admin_value_at_level(right, L, right_interp)

        if left_value is None or right_value is None:
            if not _suspect_chain_consistent_at_level(
                left, right, L, left_interp, right_interp,
            ):
                return "mismatch"
            continue

        if _admin_value_match(left_value, right_value):
            matched_any = True
            continue

        if _suspect_chain_can_reconcile(
            left, right, L, left_interp, right_interp,
        ):
            continue
        return "mismatch"

    return "match" if matched_any else "inconclusive"


def _admin_value_at_level(
    normalized: NormalizedPII, level: str, interpretation: dict,
) -> str | None:
    for c in normalized.ordered_components:
        if c in interpretation:
            if interpretation[c] == level:
                return _component_value_text(c)
            continue
        if level in c.level or (not c.level and c.component_type == level):
            return _component_value_text(c)
    return None


def _admin_value_match(a: str, b: str) -> bool:
    return _admin_text_subset_either(a, b)
```

#### 7.5.6 与 non-admin 层的混合流程

- 非 admin 层级（road / poi / building / detail / subdistrict）走 `_compare_peer_with_suspect_case2`；**subdistrict** 使用同路径但**不参与** has_admin 累计（SUBDISTRICT 不在 `_HAS_ADMIN_LEVEL_KEYS`）。
- admin 层级（province / city / district / district_city）由 `_compare_admin_levels_with_interpretations` 统一处理。
- has_admin 最终值由 static（Case 1）与非 admin 层遍历中累计的 Case 2 信号合并；闸门仅在 admin 结果为 inconclusive 时生效。

---

## 8. 阶段 6 — 清理

**删除**（不留 re-export）：

- `_key_should_degrade_from_non_pure_value`
- scanner 中 `direct_city_names` special case
- `address_policy_zh.py` 中已上提到 common 的工具函数本地定义
- `_group_suspected_entries`（"同 group_key 多 entry" 模式被 `_SuspectEntry.level: tuple` 取代；验证无其他调用方后删除）

**保留**：

- `_freeze_value_suspect_for_mismatched_admin_key`
- `_freeze_key_suspect_from_previous_key`（写 `entry.key=""`、`entry.level=(候选层 tuple)`）
- `_remove_last_value_suspect`
- `_remove_pending_suspect_group_by_span`
- `_prune_prior_component_suspects`
- `_fixup_suspected_info`
- `_flush_chain_as_standalone` 中的 `removed_suspects` 调用

**改造**：

- `_serialize_suspected_entries`：直接读 `entry.level` 元组序列化为 `{"levels":[...]}`
- `_remove_pending_suspect_by_level(state, level)`：遍历 entries，若 `level in entry.level`，从 tuple 移除该层；移除后 tuple 空 → 整条删除；否则保留 entry 仅缩短 level
- `_suspect_sort_key`：基于 `entry.level[0]` 的 rank
- `_ordered_component_by_type`：保留作 non-admin 快捷入口；admin 场景改走 `_component_covering_level`
- `_compare_component_with_suspected`：由 `_compare_peer_with_suspect_case2` 取代（保留对外名称作为薄 wrapper，或直接替换所有 call site）

---

## 9. 前置调研结果（代码定位 / 风险判定）

以下条目为动工前完成的代码级调研结论，直接作为实现依据。行号基于当前 `detector` 分支快照；实现时以仓库最新行号为准。

### 9.1 `component_type ==` / `_ordered_component_by_type` 全仓盘点

- **normalized_pii.py**：
  - `_ordered_component_by_type(left/right, key)` 在 city / district / road / subdistrict / poi / building / detail 比较中使用——**保留**（非 admin 快捷入口）。位置：`privacyguard/utils/normalized_pii.py:390-391, 407-408, 453-454`。
  - `_ordered_component_by_type` 内部 `component.component_type == component_type` 精确匹配（`normalized_pii.py:473`）——**保留**。
  - `comp_type in {"building", "detail", "number"}`（`normalized_pii.py:843`）——**保留**。
- **address_state.py**：
  - `comp_type in SINGLE_OCCUPY and comp_type in state.occupancy`（`address_state.py:652`）——**改**：按 `comp.level` 元组遍历（见 §9.4）。
  - 若干 `== AddressComponentType.POI` 等非 admin 精确比对（`address_state.py:681, 722`）——**保留**。
- **admin 场景改造点**：需要在 7.5 改为 `_component_covering_level` 的 call site 共约 3–5 处（主要是引入 `_compare_admin_levels_with_interpretations` 后的新逻辑块，而非替换既有比较——既有 normalized_pii.py 中对 province / city / district 的比较并非按 `component_type==` 直接做，而是通过 identity 字段和 suspect 链路）。
- **结论**：改点明确，无阻塞。

### 9.2 `_VALID_SUCCESSORS[PROVINCE] += {DISTRICT, DISTRICT_CITY}` 副作用

- 定义：`address_state.py:85-92`，当前 `PROVINCE: {CITY, SUBDISTRICT, ROAD, POI}`。
- 主要使用者：`_has_reasonable_successor_key`（`address_policy_zh.py:1022-1078`，行 1069 `_key_has_left_value` + 行 1072 `_chain_can_accept`）；`_segment_admit`（`address_state.py:645-675`）。
- 风险评估（中）：
  - **"北京朝阳路"**：若"朝阳"被 scanner 漏识为 DISTRICT，链可能前瞻到 ROAD 后用 PROVINCE→ROAD 收尾，PROVINCE→DISTRICT 开放并不直接放大此场景；但若识别为 DISTRICT，**正是本计划要启用**的跳层路径。
  - **"周至县 XX 路"**：若县市级词典未覆盖"周至"，其作为裸 VALUE 被 chain 接收时可能被误当 DISTRICT_CITY → PROVINCE→DISTRICT_CITY 合法接入，产生假阳组件；**不是回归，属于"词典覆盖不足"下的既有模式**。
- **结论**：中等风险，可推进；缓解措施见 §11，需监控 tests/ 中"非直辖市 + 县市 + 路"形态旧测试。

### 9.3 `_segment_admit` 在 `direction=None` 下的准入

- 关键分支：`address_state.py:659-665`（`direction is None` 时走 `ok_fwd or ok_rev`）。
- "北京市北京市朝阳区" 降解后走位：
  1. `MULTI_ADMIN(北京,市)` commit → `direction=None, group_first=MULTI_ADMIN, group_last=MULTI_ADMIN`。
  2. 第二个"北京市"触发 collision（§5.1）→ 降解成 `PROVINCE + CITY`；`direction=None` 保持、`group_first/last` 按 `_resolve_multi_admin_collision` 末尾逻辑重写为 `PROVINCE/CITY`。
  3. `CITY` commit 时 `ok_fwd = CITY in _VALID_SUCCESSORS[MULTI_ADMIN level 交集]`（✓，因为 MULTI(P,C) 的后继交集含 CITY）。
  4. 其后 `朝阳区` 进 DISTRICT：`direction=None` 或已由 CITY commit 改为 `"forward"`；`DISTRICT ∈ _VALID_SUCCESSORS[CITY]`（✓）。
- "朝阳区,北京市,北京市" 反向场景：`direction="reverse"` 由 DISTRICT 起；collision 后 MULTI_ADMIN 保低层 → `CITY(北京,市)`；第二个"北京"走 `PROVINCE` 取 `(P,)`；`PROVINCE ∈ _VALID_SUCCESSORS[CITY]` 反向合法（`ok_rev = CITY in _VALID_SUCCESSORS[PROVINCE]` = ✓）。
- **结论**：无阻塞。

### 9.4 `_rebuild_component_derived_state` occupancy 重建

- 位置：`address_state.py:1084-1137`；关键行 `state.occupancy[component_type] = index`（**`address_state.py:1120`**）。
- 当前按 `comp.component_type` 单值写 occupancy，与 MULTI_ADMIN "每层占位"设计不兼容。
- **必改**：替换为
  ```python
  for lvl in component.level:
      if lvl in SINGLE_OCCUPY:
          state.occupancy[lvl] = index
  ```
- 同时 `SINGLE_OCCUPY` 常量（`address_state.py:47-57`）补入 `DISTRICT_CITY`；见 §2.4、§2.5。
- **结论**：critical path，必须随 §2 阶段 0 一起改。

### 9.5 `_freeze_key_suspect_from_previous_key` 与 `_fixup_suspected_info` trim

- `_freeze_key_suspect_from_previous_key`：`address_policy_zh.py:441-504`；当前 entry 写入 `level=available_levels[0].value`（单层 str）、`key=key_clue.text`（例 "市"）（**`address_policy_zh.py:495-502`**）。
- `_fixup_suspected_info` 与 `_recompute_text`：`address_state.py:951-978`；trim token 由 `_suspect_surface_text(entry)` 产出，其值为 `entry.value + entry.key`（**`address_state.py:977`**）。
- 语义验证：
  - 当前写 `key="市"` → surface="北京市" → 在 ROAD.value="北京中山" 中 trim **不命中**（已是潜在 bug，但被 `_trim_once` 的"不命中保持原值"行为遮蔽）。
  - 计划改为 `key=""` → surface="北京" → 在 "北京中山" 中 trim "北京" → 剩 "中山"，符合预期。
- 额外依赖：`address_policy_zh.py:415, 428, 483` 中 `entry.level == ...` 的字符串比对需随 §9.6 一起改。
- **结论**：trim 逻辑兼容 `entry.key=""` 改写；必须与 `_SuspectEntry.level` 元组化同步完成。

### 9.6 `_SuspectEntry.level` str → tuple 迁移

- 当前定义：`_SuspectEntry.level: str`（`address_state.py:175`）。
- 序列化端（`NormalizedAddressSuspectEntry.levels: tuple[str,...]`）已存在（`normalized_pii.py:493`，`level in entry.levels`）。
- 需迁移的 call site：
  | 文件:行 | 当前 | 目标 |
  |---------|------|------|
  | `address_policy_zh.py:352` | `entry.level == level.value` | `level.value in entry.level` |
  | `address_policy_zh.py:415` | `entry.level == level.value` | 同上 |
  | `address_policy_zh.py:483` | `entry.level == available_levels[0].value` | `available_levels[0].value in entry.level` |
  | `address_policy_zh.py:495-502` | `level=available_levels[0].value, key=key_clue.text` | `level=tuple(a.value for a in available_levels), key=""` |
  | `address_state.py:331` | `existing.level == entry.level` | 保留（tuple == tuple 语义等价） |
  | `address_state.py:960` | dedupe key 用 `f"{entry.level}\|..."` | `"|".join(entry.level)` |
- 迁移后立即全仓 grep 校验 `entry.level`、`\.level == ['"]`、`\.level in \(`。
- **结论**：共 5–6 处集中改点，无阻塞。

### 9.7 normalized_pii.py 7.5 改造受影响面

- `_ordered_component_by_type` 所有调用点（`normalized_pii.py:390-391, 407-408, 453-454`）位于非 admin 层比较，**保留**。
- `_compare_component_with_suspected` 当前调用点（`normalized_pii.py:393, 396, 410, 413`）将**全部**替换为 `_compare_peer_with_suspect_case2`（新签名返回 `(ok, left_admin_hit, right_admin_hit)`），以便在非 admin 层遍历中顺带累计 has_admin Case 2 信号。
- `_same_address` 主体（`normalized_pii.py:382-424`）按 §7.5.2 重写；插入：
  1. has_admin 动态累计（初值 = `has_admin_static`）。
  2. 非 admin 层循环中 case 2 聚合。
  3. admin 三态比较（`_compare_admin_levels_with_interpretations`）+ inconclusive 闸门。
  4. `denom` 与 `substantive_hits` 保持现有语义（admin match 计 1）。
- 新增 helper：`_component_covering_level`、`_compare_peer_with_suspect_case2`、`_suspect_chain_and_case2`、`_suspect_group_matches_with_flag`、`_compare_admin_levels_with_interpretations`、`_admin_match_under_interpretation`、`_admin_value_at_level`、`_admin_value_match`、`_entry_level_all_admin`。
- **结论**：大幅但局部改造，无破坏既有非 admin 行为；旧测试红灯以 admin 分支新语义与 denom 解释为主。

### 9.8 `_ADDRESS_COMPONENT_COMPARE_KEYS` 扩展与 denom

- 当前 denom：`min(len(left.ordered_components), len(right.ordered_components))`（`normalized_pii.py:421-424`）。
- MULTI_ADMIN / DISTRICT_CITY 加入 `_ADDRESS_COMPONENT_KEYS` / `_ADDRESS_COMPONENT_COMPARE_KEYS` 后：
  - `ordered_components` 中 MULTI_ADMIN 仍计**一个** entry（不拆层），denom 不会虚增。
  - `substantive_hits` 在 admin "match" 时 +1（不按覆盖 level 数加权），确保分子/分母同粒度。
  - 不均衡场景：一侧 `MULTI_ADMIN + POI`（长度 2），另一侧 `PROVINCE + CITY + POI`（长度 3），denom=2；admin 多解释成功 +1，POI +1 → 2/2=1.0 > 0.3（✓）。
  - 反向不均衡（2 vs 5）：0.3 阈值可能偏严，计划阶段 10 需补测例锁定阈值合理性。
- **结论**：无需改 denom 计数；补测即可。

### 9.9 "北京北京"（无 KEY、无 anchor）当前轨迹与改造路径

- 全仓未发现 `_should_eager_split_duplicate_dual_admins` 具体实现——计划中作为占位风险名称，需在动工时改造或删除等价旁路（"连续同值 dual admin 立刻 split"）。
- 词典 / scanner 依赖：`data/scanner_lexicons/zh_geo_lexicon.json` 的 `provinces.soft` 当前未包含 `{北京, 上海, 天津, 重庆}`，需按 §3.2 补齐；同时删除 `scanner.py` 中 `direct_city_names` special case（§3.1）。
- 当前"北京"单独出现时 scanner 仅 emit CITY；改造后 scanner 同 span dual-emit `(PROVINCE, CITY)`，`collect_admin_value_span` 返回 `levels=(PROVINCE, CITY)`。
- 预期轨迹（改造后）：
  1. 第一个"北京" → `_flush_chain_as_standalone` → `MULTI_ADMIN(北京,(P,C))`；`occupancy={P:0, C:0}`。
  2. 第二个"北京" → admin_span.level=(P,C)，全 occupied → `_resolve_multi_admin_collision`：无逗号 → existing 保 P，incoming 取 `(C,)` → 产出 `CITY(北京)`。
  3. 最终：`PROVINCE(北京) + CITY(北京)`。
- 需要调整的判断点：
  - `_has_reasonable_successor_key`（`address_policy_zh.py:1022-1078`）中 `_preview_first_component_levels_from_chain` 等前瞻函数——**禁止**在"下一个 VALUE 与当前 admin VALUE 同值"时提前 split；把该决定交给 collision。
  - `_flush_chain_as_standalone`（§3.4）对 `len(level)==0` 的 fallback 必须走 collision 路径（已在 §3.4 伪码中规定）。
  - `_chain_can_accept`（`address_state.py:184` 附近）——确认同 value dual-level clue 不会被早期 dedup 静默丢弃。
- **结论**：推进无阻塞；依赖 §3.1 / §3.2 词典与 scanner 改造；`_should_eager_split_duplicate_dual_admins`（或其等价旁路）动工时一并清掉。

### 9.10 总体可推进性与优先级

| 条目 | 状态 | 备注 |
|------|------|------|
| 9.1 | 明确可改 | 改点 3–5 处 |
| 9.2 | 中等风险 | 监控旧测试 |
| 9.3 | 无阻塞 | 逻辑闭合 |
| 9.4 | **必改**（critical） | `address_state.py:1120` |
| 9.5 | 兼容 | 与 9.6 链式改动 |
| 9.6 | 全量迁移 | 5–6 处 |
| 9.7 | 大幅改造 | 局部且封闭 |
| 9.8 | 补测验证 | 不改 denom |
| 9.9 | 依赖 §3.1/§3.2 | 同步清理旁路 |

**推进顺序**：
1. §2 阶段 0（含 §9.4、§9.6 的 occupancy / `_SuspectEntry` 元组化）。
2. §3.1 / §3.2 + §9.9 旁路清理。
3. §3.4–§3.6 / §4 / §5。
4. §7 下游适配（detector 端）与 §7.5 比较器。
5. §10 测试闭环。

---

## 10. 阶段 7 — 测试

### 10.1 新增解析 case（`tests/.../test_address_multi_admin.py`）

| 输入 | 预期组件链 |
|------|----------|
| `朝阳` | MULTI_ADMIN(level=(C,D), value=朝阳) |
| `北京` | MULTI_ADMIN(level=(P,C), value=北京) |
| `北京市` | MULTI_ADMIN(level=(P,C), value=北京, key=市) |
| `北京市朝阳区` | MULTI_ADMIN(北京,市,(P,C)) + DISTRICT(朝阳,区) |
| `北京朝阳` | MULTI_ADMIN(北京,(P,C)) + DISTRICT(朝阳,(D,)) |
| `苏州市` | CITY(苏州, key=市) |
| `苏州市张家港市` | CITY(苏州,市) + DISTRICT_CITY(张家港,市) |
| `张家港市` | DISTRICT_CITY(张家港, key=市) |
| `北京市北京市朝阳区` | PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) |
| `北京北京` | PROVINCE(北京) + CITY(北京) |
| `北京北京朝阳` | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳) |
| `朝阳区,北京市,北京市` | DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) |
| `朝阳,北京,北京` | DISTRICT(朝阳) + CITY(北京) + PROVINCE(北京) |
| `朝阳区,北京市北京市` | DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) |
| `北京市北京市上海市` | PROVINCE(北京,市) + CITY(北京,市) ∥ 上海市→新地址 |
| `北京中山路` | ROAD(中山, key=路, level=(ROAD,), suspected=[{level=(P,C), value=北京, key=""}]) |
| `南京中山路, 南京市` | ROAD(中山, 路, suspected=[]) + CITY(南京) |
| `朝阳区` | DISTRICT(朝阳, key=区) |
| `朝阳市` | CITY(朝阳, key=市) |
| `New York` | MULTI_ADMIN(level=(STATE,CITY), value=New York) |
| `Brooklyn, New York, NY` | DISTRICT(Brooklyn) + CITY(New York) + PROVINCE(NY) |

### 10.2 canonical 比较测试（`tests/.../test_normalized_pii_multi_admin.py`）

MULTI_ADMIN / admin 多解释核心用例：

| 左 | 右 | 预期 | 说明 |
|----|----|------|------|
| MULTI(北京,P,C) + POI | PROVINCE=江苏, CITY=南京, POI 同 | 不同 | admin mismatch |
| MULTI(北京,P,C) + POI | PROVINCE=江苏, POI 同 | 不同 | 双方 has_admin=True, admin inconclusive |
| MULTI(北京,P,C) + POI | PROVINCE=北京, POI 同 | 同 | admin match |
| MULTI(北京,P,C) + POI | PROVINCE=江苏, CITY=北京, POI 同 | 同 | admin match（C 层）|
| MULTI(北京,P,C) | MULTI(北京,P,C) | 同 | |
| MULTI(北京,P,C) | MULTI(上海,P,C) | 不同 | |
| MULTI(北京,P,C) + POI | DISTRICT=朝阳, POI 同 | 不同 | 双方 has_admin=True, 无共同层 |

has_admin 闸门核心用例（suspect 场景）：

| 左 | 右 | 预期 | has_admin 推理 |
|----|----|------|--------------|
| ROAD(中山, suspect=[{(P,C),北京}]) | ROAD(中山) | 同 | L:Case2=True（北京 ⊄ 中山），R:False → 任一 False 放行 |
| ROAD(中山, suspect=[{(P,C),北京}]) | ROAD(中山, suspect=[{(P,C),北京}]) | 同 | 双方 True, admin match at P/C |
| ROAD(中山, suspect=[{(P,C),北京}]) | ROAD(中山, suspect=[{(C,D),朝阳}]) | 不同 | 双方 True, admin 在 C 层 mismatch |
| ROAD(中山, suspect=[{(C,D),朝阳}]) | PROVINCE=江苏 + ROAD(中山) | 不同 | 双方 True（L Case2, R Case1）, 无共同层 inconclusive |
| ROAD(中山, suspect=[{(P,C),北京}]) | MULTI(北京,P,C) + ROAD(中山) | 同 | 双方 True, admin match |
| ROAD(中山, suspect=[{(P,C),北京}]) | PROVINCE=上海 + ROAD(中山) | 不同 | 双方 True, admin mismatch at P |
| ROAD(北京中山, suspect=[]) | ROAD(中山, suspect=[{(P,C),北京}]) | 同 | 左 ROAD value 含 "北京" → 右 suspect 第 1 步命中；右 Case2=False；任一 False 放行 |
| ROAD(中山) | ROAD(中山) | 同 | 双方 has_admin=False, 无 admin 比较 |

### 10.3 旧测试策略

跑 `tests/` 全量后，任何旧测试失败：

1. 暂停实现
2. 在 PR 中列出失败 case 与失败原因
3. 询问用户：(a) 断言需更新 (b) 行为升级但断言未跟上 (c) 真实回归
4. 不主动改任何旧测试，不自行决定"等价升级"

---

## 11. 风险与未验证假设

1. **多解释枚举的计算量**：k = 双方 MULTI_ADMIN 总数，枚举 2^k。实际 k 极少超过 2。若异常数据让 k >> 2，需要对枚举数做上限保护（如 k > 4 时回退为"简单单层比较"）。
2. **`segment_state.direction = None` 副作用**：重置方向可能影响后续组件的逗号尾判断。已知对称 case 已验证；五个以上连续 admin 的复杂序列未系统验证。
3. **PROVINCE→DISTRICT 后继开放**：可能让以前被拒绝的序列通过，产生 false-positive。需监控旧测试。
4. **连续同值 dual-level admin 必须走 collision，不得旁路 split**："北京北京"（无 KEY、无 anchor）的目标落点为 `PROVINCE(北京) + CITY(北京)`，依赖 §3 scanner dual-emit + §5.1 collision 降解。任何"第二个同值 MULTI_ADMIN 提前 split 成新地址"或"静默丢弃"的历史旁路（如计划占位名 `_should_eager_split_duplicate_dual_admins`）一律清除。需用"北京北京"/"北京北京朝阳"两个 case 测试锁定行为。
5. **`_DraftComponent.level` clone / serialize 路径**：`_rebuild_component_derived_state` 中 occupancy 重建对 MULTI_ADMIN 的处理（按 `level` 元组遍历），以及就地降解后的重建正确性，需验证。
6. **`_SuspectEntry.level` 由 str 改 tuple 的迁移**：漏改一处即为 latent bug。`_SuspectEntry` 升级后立刻 grep 全仓 `entry.level` 与 `\.level == ['"]`。
7. **`_freeze_key_suspect_from_previous_key` 改写 `entry.key=""`**：影响下游 `_fixup_suspected_info` 的 trim token 与序列化结构。
8. **`substantive_hits / denom > 0.3`**：MULTI_ADMIN 在 `ordered_components` 里仅算 1 个 entry，但在多解释下等效 2 层——当前设计 admin "match" 时加 1（不按覆盖的 level 数加权）。
9. **has_admin Case 2 的保守取值**：对侧同 component_type peer 不存在时默认 `step1_failed=True`（即视 suspect 为 admin）。当两侧都缺失同类 peer 时，Case 2 信号不会产生；这与"有同类 peer 却无法证伪"场景的语义存在细微差异，需以测试锁定行为。
10. **EN 词典数据缺失**：Brooklyn / NYC boroughs / 主要美国 city-state dual entries 需补充（独立 PR）。
11. **suspect 第 2 步 `_suspect_entry_by_level`**：在多层 entry 语境下，同一个 entry 可能被不同 level 查到并返回。对 OR 链"至少一次匹配即放行"的影响需实测。

---

## 12. PR 拆分建议

| PR | 阶段 | 范围 |
|----|------|------|
| #1 | 阶段 0 | 类型基建：MULTI_ADMIN / DISTRICT_CITY 枚举、`_DraftComponent.level` / `_SuspectEntry.level` 字段、`_commit` occupancy、`_segment_admit` 后继逻辑、公共抽象上提 |
| #2 | 阶段 1 | value 多层落 MULTI_ADMIN：scanner dual-emit、词典补、`_flush_chain_as_standalone` / `_flush_admin_key_chain` 多层 commit |
| #3 | 阶段 2 + 阶段 3 | KEY intersection + `_routed_key_clue` + `_resolve_multi_admin_collision`（仅 admin commit 路径）+ DISTRICT_CITY 路由 |
| #4 | 阶段 4 | EN scanner 去重 + EnAddressStack 接 admin span（不含 EN 词典数据） |
| #5 | 阶段 5（detector 侧） | `_address_metadata.address_component_level` trace、parser 透传、`NormalizedAddressComponent.level` / `NormalizedPII.has_admin_static` |
| #6 | 阶段 5（比较器侧） | `_component_covering_level` / `_compare_admin_levels_with_interpretations`（三态返回）/ `_compare_peer_with_suspect_case2` / has_admin 闸门 |
| #7 | 阶段 6 | 清理 |
| #8 | 数据 | EN 词典补 Brooklyn / NYC boroughs / city-state dual entries |

每个 PR 包含对应新增测试；旧测试红灯停下问用户。
