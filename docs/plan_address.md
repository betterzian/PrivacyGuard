# 地址多层级 admin 与 MULTI_ADMIN component 实现计划

---

## 0. 设计目标与不变式

### 0.1 三类典型场景

| 场景 | 例子 | 当前行为 | 目标行为 |
|------|------|---------|---------|
| value 多层 | 北京（province/city）、朝阳（city/district）、New York（city/state）| 仅按 `_ADMIN_RANK` 取最高一层；其余信息丢失 | 全部层级保留为 `level` 元组，落地时若 ≥2 层则成 `MULTI_ADMIN` |
| key 多层 | "市" ∈ {PROVINCE, CITY, DISTRICT_CITY} | "市" 默认 CITY，靠启发式硬降级到 DISTRICT | 显式注册 KEY levels；与 value levels 取交集；交集单元素直接落；多元素进 `MULTI_ADMIN` |
| key+value 组合 | "北京市" / "张家港市" | 词典+硬规则 | value↔key 走 intersection；intersection ≥2 则落 `MULTI_ADMIN`；左侧无 value 时 "市"→`DISTRICT_CITY` |

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
- 同 value 多层 suspect 用**单条 entry**表达，不再用"同 group_key 多 entry"模拟。
- 例：`北京中山路` → `ROAD.suspected = [_SuspectEntry(level=(P, C), value="北京", key="", origin="key")]`。
- 序列化：`_serialize_suspected_entries` 直接读 `entry.level` 元组输出 `{"levels":["province","city"],"value":"北京","key":"","origin":"key"}`。

#### canonical / same-entity 比较语义

**核心规则**：两个地址比较时，对每个 admin 层级 `L`，查找"level 元组中包含 `L` 的 component"（而非按 `component_type` 精确匹配）。MULTI_ADMIN(P,C) 既能在 L=P 被查到也能在 L=C 被查到。

**多层消歧的"或链"语义**：MULTI_ADMIN 的 value 在哪一层属实是**歧义的**。两个地址判定为同实体的充分必要条件是：**存在一种对双方所有 MULTI_ADMIN 的层级解释**，使得在所有"双方共同拥有的层级"上值都一致。

等价于：枚举每个 MULTI_ADMIN 的层级解释（2^k 种组合，k = 双方 MULTI_ADMIN 总数），对每种组合做标准单层比较，**任一成立即匹配**。

**用户场景验证**：

| A | B | 推理 | 结论 |
|---|---|------|------|
| MULTI(北京,P,C) | PROVINCE=江苏, CITY=南京 | interp A=P: 北京≠江苏; interp A=C: 北京≠南京；两种解释全不符 | 明确不同 ✓ |
| MULTI(北京,P,C) | PROVINCE=江苏 (仅一层) | interp A=C: B 无 C 可比 → 无冲突；A=P 冲突，但 A 可以选 C | 不可判定 → 不返回 False，继续下一角色 ✓ |
| MULTI(北京,P,C) | PROVINCE=北京 | interp A=P: 匹配 | 同 ✓ |
| MULTI(北京,P,C) | PROVINCE=江苏, CITY=北京 | interp A=C: A.北京=B.C.北京 → 匹配；P 层被"重释"为不比较 | 同 ✓ |
| MULTI(北京,P,C) | PROVINCE=北京, CITY=南京 | interp A=P: 北京=北京 → 匹配 | 同 ✓ |
| MULTI(北京,P,C) | 仅 DISTRICT=朝阳 | 无 P/C 共同层 → 跳过该角色 | 继续下一角色 ✓ |

**suspect OR 链**：每个 component 的 `suspected` 列表把可能值扩展到额外层级。查找"A 在 L 的候选值集合"时：

```
A_values_at_L = { c.value 
                  | c ∈ A.components, L ∈ c.level, c 未被当前 interpretation 固定到其他层 }
              ∪ { s.value
                  | c ∈ A.components, s ∈ c.suspected, L ∈ s.level }
```

当前层 L 判定步骤（沿用现有 `_suspect_group_matches` 三步 OR 链，仅把第 3 步的按 `component_type` 查找改为按 `level` 查找）：
1. 表面文本子串：`surface = entry.value + entry.key`，若落在对侧 L 组件的 value 内 → 认作一致；
2. 对侧 suspect 里有任一 entry 的 `level` 覆盖 L 且 value 相等 → 一致；
3. 对侧存在"level 覆盖 L"的 component 且 value 相等 → 一致；
4. 其余 → 不一致。

**DISTRICT_CITY 与 DISTRICT 无 level 交集**（一个是 `(DISTRICT_CITY,)`，另一个是 `(DISTRICT,)`），按上述规则**不参与互通**——符合"不同行政性质不做模糊匹配"语义。

### 0.3 重复同值行政对的就地降解

**场景**："北京市北京市朝阳区"——第一个 MULTI_ADMIN(北京,(P,C)) 已占住 P+C，第二个"北京市"进入时必须触发降解。

**机制**：admin VALUE **即将作为 admin commit** 时（`_flush_chain_as_standalone` / `_flush_admin_key_chain` 路径），若 incoming_value 与现存 MULTI_ADMIN 同值且 level 有交集：

| 情况 | MULTI_ADMIN 保留 | 新来者得到 |
|------|------------------|-----------|
| pair 之间**无逗号** | 最高层（PROVINCE） | 次高层（CITY） |
| pair 之间**有逗号** | 最低层（CITY） | 最高层（PROVINCE） |

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
最终     → ROAD(value="中山", key="路", level=(ROAD,), suspected=[entry])
```

### 0.6 输入解释规则

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
| 重复同值对的方向 | 无逗号→正序（高层先）；有逗号→逆序（低层先） |
| collision 触发点 | **仅** admin commit 路径（`_flush_chain_as_standalone` / `_flush_admin_key_chain`）；**不**在 `_freeze_*` 触发 |
| 中英文 | 共用同一 admin span 抽象；enstack 自定 `_ADMIN_RANK` / `_VALID_SUCCESSORS` |
| suspect 函数 | **全部保留**；suspect 与 MULTI_ADMIN 正交 |
| canonical 比较 | 按 level 查找 + 多解释枚举；suspect 3 步 OR 链保留但第 3 步改为 level-aware |

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

### 3.3 `resolve_admin_value_span` 改造 [`address_policy_common.py`]

返回结构改为 `_AdminResolveResult(level)`：

- `level: tuple[AddressComponentType, ...]`：occupancy + segment 过滤后剩余的全部可用层级，按 `_ADMIN_RANK` 降序

调用方按 `len(level)` 决定落普通还是 MULTI_ADMIN。

### 3.4 `_flush_chain_as_standalone` admin group 分支 [`address_state.py`]

调用新 resolve 拿 `level`：

```python
if len(level) >= 2:
    component = _DraftComponent(
        component_type=AddressComponentType.MULTI_ADMIN,
        level=level,
        ...,
        suspected=[],
    )
elif len(level) == 1:
    component = _DraftComponent(
        component_type=level[0],
        level=level,
        ...,
        suspected=[...],
    )
else:
    # collision 检查（见 5.1）
    forced = _resolve_multi_admin_collision(state, raw_text, clue.start, value, origin_levels)
    if forced is None:
        state.split_at = clue.start; return
    # 走强制 level 落库
    ...
```

`_remove_pending_suspect_group_by_span` 仍调用，承担"清理 pending 中已被本次 commit 消化的同 span suspect"职责；**不再**用 `remaining_levels` 把剩余层塞回 `component.suspected`——剩余层信息由 `level` 字段承载。

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
        component_type=component_type,
        level=level,
        value=normalize(span.text),
        key=key_clue.text,
        ...,
    )
    commit(component)
```

### 3.6 KEY-driven 链中同段重复对处理 [`address_state.py`]

`_flush_admin_key_chain` 在**同一次 flush**中遇到相同 value 的相邻段（如链内"北京市北京市"），按 5.1 统一规则处理：

```python
if (
    cursor + 1 < len(segments)
    and len(available_levels) == 2
    and segments[cursor + 1][4] == segment_value       # 同 value
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

此处直接产出**单层** component（每个 `level=(single,)`），不走 MULTI_ADMIN，因为重复对场景已明确两层各自归宿。

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

### 4.2 `_routed_key_clue` 重写 [`address_policy_zh.py`]

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

`effective_clue.component_type == MULTI_ADMIN` 时，照常入 deferred_chain，flush 路径在 3.5 已处理多层 commit。

### 4.4 删除 `_key_should_degrade_from_non_pure_value` [`address_policy_zh.py`]

被 4.2 的 intersection 逻辑取代，整段及其调用点一并删除。

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
# _handle_value_clue 内，admin_span 算出后
if admin_span is not None and not state.deferred_chain:
    if _occupancy_fully_blocked(state, admin_span.level):
        forced = _resolve_multi_admin_collision(
            state, raw_text, clue.start, clue.text, admin_span.level,
        )
        if forced is not None:
            admit_level = forced
        else:
            ...  # 原逻辑
```

#### 5.2.2 `_flush_chain_as_standalone` 同值重复段

在 cursor 处理 admin VALUE 组时，若 resolve 返回空但存在同值 MULTI_ADMIN，触发 collision（见 3.4 流程）。

#### 5.2.3 `_flush_admin_key_chain` 同上

见 3.5 伪码。

#### 5.2.4 `_freeze_*` 路径**不触发**

`_freeze_value_suspect_for_mismatched_admin_key` 与 `_freeze_key_suspect_from_previous_key` 构造 suspect 时**不**调用 `_resolve_multi_admin_collision`。原因：suspect 是元数据旁注，不占 occupancy。suspect 的 `level` 元组保持原 value 的候选层级原样写入，不做降解。

### 5.3 流程验证

#### "北京市北京市朝阳区"（无逗号）

```
"北京市"[1] → _flush_admin_key_chain → candidate=(P,C), available=(P,C)
            → MULTI_ADMIN(北京,市,(P,C)), occupancy: {P:0, C:0}

"北京"[2] VALUE → admin_span.level=(P,C), occupancy 全被 MULTI_ADMIN 占
                → _resolve_multi_admin_collision:
                   existing=MULTI_ADMIN at 0, overlap=[P,C], no comma
                   → existing 保 P (→ PROVINCE(北京,市)), incoming 取 C
                   → occupancy: {P:0}; direction=None
                   → 返回 (C,)
                → admit_level=(C,) → 加入 chain

"市" KEY → CITY(北京,市) → occupancy: {P:0, C:1} ✓

"朝阳区" → DISTRICT(朝阳,区) ✓ （CITY→DISTRICT 合法）
```

#### "朝阳区,北京市,北京市"（pair 间有逗号）

```
"朝阳区" → DISTRICT(朝阳,区), comma_tail, group_first=DISTRICT
"北京市"[1] → MULTI_ADMIN(北京,市,(P,C))，max rank=4 > 2 ✓
            → occupancy: {DISTRICT:0, P:1, C:1}

"北京"[2] VALUE → _resolve_multi_admin_collision:
                   has_comma=True → existing 保 C → CITY(北京,市)
                   → occupancy: {DISTRICT:0, C:1}
                   → 返回 (P,)

"市" KEY → PROVINCE(北京,市) ✓
结果：DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) ✓
```

#### "朝阳区,北京市北京市"（pair 间无逗号）

```
"朝阳区" → DISTRICT
"北京市"[1] → MULTI_ADMIN(北京,(P,C))
"北京"[2] VALUE → _resolve_multi_admin_collision:
                   has_comma=False → existing 保 P → PROVINCE(北京,市)
                   → 返回 (C,)
"市" KEY → CITY(北京,市) ✓
结果：DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) ✓
```

#### "北京市北京市上海市"（第三城市断开）

```
"北京市"[1] → MULTI_ADMIN(北京,(P,C)), occupancy: {P:0, C:0}
"北京市"[2] → 降解 → PROVINCE + CITY, occupancy: {P:0, C:1}
"上海" VALUE → admin_span.level=(P,C), 全 occupied
             → _resolve_multi_admin_collision: 无同值 MULTI_ADMIN → 返回 None
             → _segment_admit 失败 → split_at ✓
```

#### "北京中山路"

```
"北京" VALUE → pending_suspects（不进 deferred）
"中山路" → _freeze_key_suspect_from_previous_key（不触发 collision）
        → 写 _SuspectEntry(level=(P,C), value="北京", key="", origin="key")
"路" KEY → ROAD(value="北京中山", key="路", level=(ROAD,), suspected=[entry])
_fixup_suspected_info → trim "北京"+"" = "北京" → ROAD.value="中山"
结果：ROAD(中山, 路, level=(ROAD,), suspected=[{level=(P,C), value=北京, key=""}]) ✓
```

#### "南京中山路, 南京市"

```
第一段 → ROAD(中山, 路, suspected=[{level=(C,), value=南京, key=""}])
        （南京仅 CITY 层，suspect.level=(C,)）

", 南京市" → "南京" VALUE, admin_span.level=(C,)
          → _prune_prior_component_suspects 按 (value="南京", level 交集)
             从已提交 ROAD.suspected 移除 → 清空
          → admit (C,) → CITY(南京)
结果：ROAD(中山, 路, suspected=[]) + CITY(南京) ✓
```

---

## 6. 阶段 4 — 英文 multi-admin

### 6.1 EN scanner 去重粒度对齐 [`scanner.py`]

```python
seen: set[str]  →  seen: set[tuple[AddressComponentType, str]]
```

使英文同名 dual-level entry 都注册。

### 6.2 `EnAddressStack` 接 deferred chain + admin span [`address_en.py`]

- `_handle_value_clue` 引入 `collect_admin_value_span`（`address_policy_common.py`）
- `_flush_chain` 子类化，传入 EN-friendly resolver
- 复用 `_resolve_multi_admin_collision`（参数化 `_ADMIN_RANK` / `_VALID_SUCCESSORS`）

### 6.3 EN ranking 与后继关系 [`address_policy_en.py`]

EN stack 维护自己的 `_EN_ADMIN_RANK` 与 `_EN_VALID_SUCCESSORS`，按美国地址书写习惯：

- rank：`STATE > CITY > DISTRICT > SUBDISTRICT`（STATE = PROVINCE 在内部枚举映射）
- successor：`STATE → CITY → DISTRICT → SUBDISTRICT → ROAD → POI`

`_resolve_multi_admin_collision` 与 `_effective_successors` 接受 `admin_rank: dict` 与 `valid_successors: dict` 参数。

### 6.4 EN KEY 多层暂不引入

`is_prefix_en_key` 等接口保持单层；若未来"St"等 KEY 出现多层，再补 `_MULTI_LEVEL_KEY_LEVELS_EN`。

### 6.5 数据：Brooklyn 等 NYC borough

`en_geo_lexicon.json`：`Brooklyn / Manhattan / Queens / Bronx / Staten Island` → `district`；`New York` → dual-level `city + state`。

---

## 7. 阶段 5 — 下游适配

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
- 新增常量：`_ADMIN_LEVEL_KEYS = ("province", "city", "district", "district_city", "subdistrict")`——canonical 比较时按此顺序逐层检验
- `_ADMIN_LEVEL_RANK: dict[str, int]` 供多解释枚举时的排序

### 7.4 `NormalizedAddressComponent.level` 字段 [`types.py`]

```python
@dataclass(frozen=True)
class NormalizedAddressComponent:
    component_type: str
    value: str | tuple[str, ...]
    key: str | tuple[str, ...] = ""
    suspected: tuple[NormalizedAddressSuspectEntry, ...] = ()
    level: tuple[str, ...] = ()   # 新增：与 detector 端 _DraftComponent.level 一致
```

- 单层 component：`level=(component_type,)` 或为空（构造时由 `component_type` 反填充）
- MULTI_ADMIN：`level=("province","city")` 等
- `_ordered_components_from_metadata` 解析时读 `address_component_level` trace 挂到 component 上；若 trace 缺失则按 `component_type` 反填

`NormalizedAddressSuspectEntry` 已有 `levels: tuple[str, ...]`，保持不变，在解析时填充（现有代码已支持）。

### 7.5 canonical / same-entity 比较器扩展

#### 7.5.1 查找函数由"按 component_type 精确"改为"按 level 覆盖"

**旧**：
```python
def _ordered_component_by_type(normalized, component_type):
    for c in normalized.ordered_components:
        if c.component_type == component_type:
            return c
    return None
```

**新**：
```python
def _component_covering_level(
    normalized: NormalizedPII,
    level: str,
    skip: frozenset[NormalizedAddressComponent] = frozenset(),
) -> NormalizedAddressComponent | None:
    """返回 level 元组中包含 level 且未被 skip 的第一个 component。
    用于遍历时"已固定到别的层"的 MULTI_ADMIN 跳过。"""
    for c in normalized.ordered_components:
        if c in skip:
            continue
        if level in c.level or (not c.level and c.component_type == level):
            return c
    return None
```

保留 `_ordered_component_by_type` 作为 non-admin 场景（ROAD / POI / BUILDING 等）的快捷入口；admin 场景全部改走 `_component_covering_level`。

#### 7.5.2 `_same_address` 重写：多解释枚举

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

    # --- 行政层级：多解释枚举 ---
    admin_result = _compare_admin_levels_with_interpretations(left, right)
    if admin_result is False:
        return False
    if admin_result is True:
        # 至少一个层级实质匹配
        substantive_hits += 1
    # 若为 "inconclusive"，substantive_hits 不增但也不失败

    # road / poi / building / detail（非 admin，沿用原流程）
    for key in ("road", "poi", "building", "detail"):
        left_component = _ordered_component_by_type(left, key)
        right_component = _ordered_component_by_type(right, key)
        if left_component is None or right_component is None:
            if not _compare_component_with_suspected(left, right, key):
                return False
            continue
        if not _compare_component_with_suspected(left, right, key):
            return False
        substantive_hits += 1

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

#### 7.5.3 `_compare_admin_levels_with_interpretations` 算法

```python
def _compare_admin_levels_with_interpretations(
    left: NormalizedPII, right: NormalizedPII,
) -> bool | None:
    """
    返回值：
      True  —— 至少一种解释下所有共同层级值一致，且至少一个层级实质命中
      False —— 任何解释都存在确定性冲突
      None  —— 没有共同可比层级（inconclusive），不计失败也不计命中
    """
    left_multis = [c for c in left.ordered_components
                   if c.component_type == "multi_admin" or len(c.level) >= 2]
    right_multis = [c for c in right.ordered_components
                    if c.component_type == "multi_admin" or len(c.level) >= 2]

    def iter_interpretations(multis):
        if not multis:
            yield {}
            return
        from itertools import product
        level_sets = [tuple(m.level) for m in multis]
        for combo in product(*level_sets):
            yield dict(zip(multis, combo))

    any_matched = False
    any_inconclusive_only = True

    for left_interp in iter_interpretations(left_multis):
        for right_interp in iter_interpretations(right_multis):
            result = _admin_match_under_interpretation(
                left, right, left_interp, right_interp,
            )
            if result == "match":
                return True  # 至少一种解释全匹配
            elif result == "inconclusive":
                any_inconclusive_only = any_inconclusive_only  # 保持
                continue
            else:  # "mismatch"
                any_inconclusive_only = False

    if any_inconclusive_only:
        return None
    return False


def _admin_match_under_interpretation(
    left: NormalizedPII,
    right: NormalizedPII,
    left_interp: dict,     # multi component → committed level
    right_interp: dict,
) -> str:
    """
    在给定的 multi 解释下，按 _ADMIN_LEVEL_KEYS 顺序逐层比较。
    返回：
      "match"        —— 所有共同层级值一致，且至少一个层级实质命中
      "inconclusive" —— 没有任何层级有 LHS 和 RHS 同时存在，无失败
      "mismatch"     —— 某层级 LHS 和 RHS 都存在且值不一致
    """
    matched_any = False

    for L in _ADMIN_LEVEL_KEYS:  # ("province","city","district","district_city","subdistrict")
        left_value = _admin_value_at_level(left, L, left_interp)
        right_value = _admin_value_at_level(right, L, right_interp)

        if left_value is None or right_value is None:
            # 本层单侧缺失：跑 suspect OR 链（下文）
            if not _suspect_chain_consistent_at_level(left, right, L, left_interp, right_interp):
                return "mismatch"
            continue

        if _admin_value_match(left_value, right_value):
            matched_any = True
            continue

        # 值不一致：再跑一遍 suspect OR 链
        if _suspect_chain_can_reconcile(left, right, L, left_interp, right_interp):
            continue
        return "mismatch"

    return "match" if matched_any else "inconclusive"


def _admin_value_at_level(
    normalized: NormalizedPII,
    level: str,
    interpretation: dict,
) -> str | None:
    """取"本侧在 level 层的值"。
    - multi component 只有在 interpretation[c] == level 时才算它在 level 层
    - 单层 component 只要 level in c.level 就算
    """
    for c in normalized.ordered_components:
        if c in interpretation:
            if interpretation[c] == level:
                return _component_value_text(c)
            continue  # multi 被解释到别的层，不算它在这层
        if level in c.level or (not c.level and c.component_type == level):
            return _component_value_text(c)
    return None


def _admin_value_match(a: str, b: str) -> bool:
    """行政层级 value 相容：子串互容（短在长内）。"""
    return _admin_text_subset_either(a, b)
```

#### 7.5.4 suspect 3 步 OR 链改造

沿用现有 `_suspect_group_matches`（normalized_pii.py:498-524）的三步语义，**仅把第 3 步**的"按 component_type 查找"改为"按 level 查找"：

```python
def _suspect_group_matches(
    entry: NormalizedAddressSuspectEntry,
    other_component: NormalizedAddressComponent,
    other_normalized: NormalizedPII,
) -> bool | None:
    # 1: 表面文本子串
    surface = f"{entry.value}{entry.key}".strip()
    other_value = _component_value_text(other_component)
    if surface and other_value and surface in other_value:
        return True

    # 2: 对侧 suspect 同 level
    for level in entry.levels:
        peer_suspected = _suspect_entry_by_level(other_component, level)
        if peer_suspected is not None:
            return peer_suspected.value.strip() == entry.value.strip()

    # 3: 对侧按 level 查找（改造点）
    for level in entry.levels:
        other_level_component = _component_covering_level(other_normalized, level)
        if other_level_component is None:
            continue
        other_level_value = _component_value_text(other_level_component)
        if not other_level_value:
            continue
        return other_level_value == entry.value.strip()

    return True
```

`_suspect_entry_by_level` 现有实现已按 `level in entry.levels` 检查（normalized_pii.py:486-495），不需要修改。

#### 7.5.5 与"非 admin 层级"的混合流程

- 非 admin 层级（road / poi / building / detail / subdistrict）按原 `_compare_component_with_suspected` 走——这些层级不参与 multi_admin 解释。
- admin 层级（province / city / district / district_city）全部由 `_compare_admin_levels_with_interpretations` 统一处理。
- subdistrict 不归入 multi_admin 解释范围（目前没有"subdistrict 同值歧义"场景），仍按单层比较。

---

## 8. 阶段 6 — 清理

**明确删除**（不留 re-export）：

- `_key_should_degrade_from_non_pure_value`
- scanner 中 `direct_city_names` special case
- `address_policy_zh.py` 中已上提到 common 的工具函数本地定义
- `_group_suspected_entries`（原"同 group_key 多 entry"模式被 `_SuspectEntry.level: tuple` 取代；验证无其他调用方后删除）

**明确保留**（不删除）：

- `_freeze_value_suspect_for_mismatched_admin_key`：处理行政值被非行政 KEY 吸收
- `_freeze_key_suspect_from_previous_key`：同上配套（仅修改 entry.key 行为：写空字符串）
- `_remove_last_value_suspect`
- `_remove_pending_suspect_group_by_span`：用于"南京中山路, 南京市"清理 ROAD.suspected
- `_prune_prior_component_suspects`
- `_fixup_suspected_info`
- `_flush_chain_as_standalone` 中的 `removed_suspects` 调用（仅承担"清理 pending"职责）

**明确改造**（保留函数名 + 调整签名 / 行为）：

- `_freeze_key_suspect_from_previous_key`：写 `entry.key=""`（原值无 key），写 `entry.level=(候选层 tuple)`
- `_serialize_suspected_entries`：直接读 `entry.level` 元组序列化为 `{"levels":[...]}`
- `_remove_pending_suspect_by_level(state, level)`：新语义——遍历 entries，若 `level in entry.level`，从 tuple 移除该层；移除后 tuple 空 → 整条删除；否则保留 entry 仅缩短 level
- `_suspect_sort_key`：基于 `entry.level[0]` 的 rank
- `_ordered_component_by_type`（normalized_pii.py）：保留作 non-admin 快捷入口；admin 场景全部改走 `_component_covering_level`

---

## 9. 必须前置的调研（动手前完成）

1. 全仓搜索 `component.component_type ==` / `comp_type in` / `_ordered_component_by_type`，列出阶段 7.5 实际需改动的比较点清单。
2. 确认 `_VALID_SUCCESSORS[PROVINCE] += DISTRICT` 是否会让"北京朝阳"类组合在 `_has_reasonable_successor_key` 链路被过早接受，影响其它 case。
3. 确认 `_segment_admit` 在 `direction=None`（就地降解后重置）时，PROVINCE/CITY 能通过 `group_first=DISTRICT` 的 `ok_rev` 检查。
4. 确认 `_rebuild_component_derived_state` 中 occupancy 重建按 `comp.level` 元组遍历，而非仅 `comp.component_type`。
5. 确认 `_freeze_key_suspect_from_previous_key` 改写 `entry.key=""` 后，`_fixup_suspected_info` 的 trim 逻辑（基于 `entry.value + entry.key` 表面文本匹配）仍能正确切掉 ROAD.value 前缀。
6. 确认 `_SuspectEntry.level` 由 str 改为 tuple 后，所有 `entry.level == "..."` 字符串比对处的 call site 都改为 `lvl in entry.level` 或 `entry.level == (lvl,)`。
7. 在 normalized_pii.py 跑一次 `grep -n "component_type ==" /_ordered_component_by_type(` 列出 7.5 改造所有 call site；检验 `_compare_component_with_suspected` 对非 admin 的行为不变。
8. 确认 `_ADDRESS_COMPONENT_COMPARE_KEYS` 扩展后 `_same_address` 的 `denom` 计算不会被 MULTI_ADMIN 虚占（MULTI_ADMIN 在 ordered_components 里算一个 entry，而不是两个）。

---

## 10. 阶段 7 — 测试

### 10.1 新增 case（`tests/.../test_address_multi_admin.py`）

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

| 左 | 右 | 预期 |
|----|----|------|
| MULTI_ADMIN(北京,P,C) + POI | PROVINCE=江苏, CITY=南京, POI 同 | 不同 |
| MULTI_ADMIN(北京,P,C) + POI | PROVINCE=江苏, POI 同 | 同（inconclusive admin + POI 命中）|
| MULTI_ADMIN(北京,P,C) + POI | PROVINCE=北京, POI 同 | 同 |
| MULTI_ADMIN(北京,P,C) + POI | PROVINCE=江苏, CITY=北京, POI 同 | 同 |
| MULTI_ADMIN(北京,P,C) | MULTI_ADMIN(北京,P,C) | 同 |
| MULTI_ADMIN(北京,P,C) | MULTI_ADMIN(上海,P,C) | 不同 |
| MULTI_ADMIN(北京,P,C) | DISTRICT=朝阳 | inconclusive → 看其它层 |
| ROAD(中山,路,suspect=[{level=(P,C),value=北京}]) | PROVINCE=北京 + ROAD(中山,路) | 同（suspect 第 3 步 level-aware 命中）|
| ROAD(中山,路,suspect=[{level=(P,C),value=北京}]) | PROVINCE=上海 + ROAD(中山,路) | 不同（suspect 第 3 步 value 不等）|

### 10.3 旧测试策略

跑 `tests/` 全量后，**任何**旧测试失败：

1. 暂停实现
2. 在 PR 中列出失败 case 与失败原因
3. 询问用户：(a) 断言需更新 (b) 行为升级到 MULTI_ADMIN 但断言未跟上 (c) 真实回归
4. 不主动改任何旧测试，不自行决定"等价升级"

---

## 11. 风险与未验证假设

1. **多解释枚举的计算量**：k = 双方 MULTI_ADMIN 总数，枚举 2^k。实际地址 k 极少超过 2，上限 16 种组合，无性能风险；但若异常数据让 k >> 2，需要对枚举数做上限保护（如 k > 4 时回退为"简单单层比较"）。
2. **`segment_state.direction = None` 副作用**：重置方向可能影响后续组件的逗号尾判断。已知对称 case 已验证；五个以上连续 admin 的复杂序列未系统验证。
3. **PROVINCE→DISTRICT 后继开放**：可能让以前被拒绝的序列通过，产生 false-positive。需监控旧测试。
4. **`_should_eager_split_duplicate_dual_admins` 返回 False**："北京北京"（无 KEY，无 anchor）保留为单个 MULTI_ADMIN，第二个静默丢弃。此行为是否符合预期需测试确认。
5. **`_DraftComponent.level` 的所有 clone / serialize 路径**：`_rebuild_component_derived_state` 中 occupancy 重建对 MULTI_ADMIN 的处理（必须按 `level` 元组遍历），以及就地降解后的重建正确性，需验证。
6. **`_SuspectEntry.level` 由 str 改 tuple 的迁移**：漏改一处即为 latent bug。建议在 PR #1 完成 `_SuspectEntry` 升级后立刻 grep 全仓 `entry.level` 与 `\.level == ['"]` 排查。
7. **`_freeze_key_suspect_from_previous_key` 改写 `entry.key=""`**：影响下游 `_fixup_suspected_info` 的 trim token 与序列化结构。需对比新旧测试输出。
8. **canonical 多解释枚举与实质性命中比例 `> 0.3`**：MULTI_ADMIN 在 `ordered_components` 里仅算 1 个 entry，但在多解释下等效 2 层——需决定 `substantive_hits` 是否在 admin "match" 时加 1 还是加覆盖的 level 数（当前设计加 1）。
9. **EN 词典数据缺失**：Brooklyn / NYC boroughs / 主要美国 city-state dual entries 需补充。当前 plan 只描述代码路径，词典数据视为独立 PR。
10. **suspect 第 2 步 `_suspect_entry_by_level` 的语义**：现有实现是"只要 entry.levels 包含该 level 就返回该 entry"——在 MULTI_ADMIN suspect（多层 entry）语境下，同一个 entry 可能被不同 level 查到并返回。这一"多次命中同一 entry"是否影响 OR 链的"至少一次匹配即放行"，需实测验证。

---

## 12. PR 拆分建议

| PR | 阶段 | 范围 |
|----|------|------|
| #1 | 阶段 0 | 类型基建：MULTI_ADMIN / DISTRICT_CITY 枚举、`_DraftComponent.level` / `_SuspectEntry.level` 字段升级、`_commit` occupancy 改造、`_segment_admit` 后继逻辑、公共抽象上提 |
| #2 | 阶段 1 | value 多层落 MULTI_ADMIN：scanner dual-emit、词典补 + `_flush_chain_as_standalone` / `_flush_admin_key_chain` 多层 commit |
| #3 | 阶段 2 + 阶段 3 | KEY intersection + `_routed_key_clue` 重写 + `_resolve_multi_admin_collision`（仅 admin commit 路径）+ DISTRICT_CITY 路由 |
| #4 | 阶段 4 | EN scanner 去重 + EnAddressStack 接 admin span（不含 EN 词典数据） |
| #5 | 阶段 5（detector 侧） | `_address_metadata.address_component_level` trace 序列化、parser 透传、normalized_pii.py 数据结构扩展 |
| #6 | 阶段 5（比较器侧） | `_component_covering_level` / `_compare_admin_levels_with_interpretations` / suspect 3 步 OR 链第 3 步 level-aware 改造 |
| #7 | 阶段 6 | 清理 |
| #8 | 数据 | EN 词典补 Brooklyn / NYC boroughs / city-state dual entries |

每个 PR 包含对应新增测试；旧测试红灯停下问用户。
