# 地址多层级 admin 与 MULTI_ADMIN component 实现计划

---

## 0. 设计目标与不变式

### 0.1 三类典型场景

| 场景 | 例子 | 当前行为 | 目标行为 |
|------|------|---------|---------|
| value 多层 | 朝阳（city/district）、北京（province/city）、New York（city/state）| 仅按 `_ADMIN_RANK` 取最高一层；其余信息丢弃 | 全部层级保留为 `levels` 元组，落地时若 ≥2 层则成 `MULTI_ADMIN` |
| key 多层 | "市" ∈ {PROVINCE, CITY, DISTRICT_CITY} | "市" 默认 CITY，靠启发式硬降级到 DISTRICT | 显式注册 KEY levels；与 value levels 取交集；交集单元素直接落；多元素进 `MULTI_ADMIN` |
| key+value 组合 | "北京市" / "张家港市" | 词典+硬规则 | value↔key 走 intersection；intersection ≥2 则落 `MULTI_ADMIN`；左侧无 value 时 "市"→`DISTRICT_CITY` |

### 0.2 落地形态语义

- 普通 `_DraftComponent`：`component_type` 单值，`levels=()`，表达"已确定单一层级"。
- `MULTI_ADMIN _DraftComponent`：`component_type=MULTI_ADMIN`，`levels=tuple(...)` 包含 ≥2 个 admin 层级，按 `_ADMIN_RANK` 降序，表达"该实体同时承担多个行政角色"。
- canonical / restore 比较：MULTI_ADMIN 的 levels 与对方 `({type} ∪ levels)` 取交集，**任一层重合**即视作同一 admin 实体。
- 占位（occupancy）：MULTI_ADMIN 提交时同时锁住 `MULTI_ADMIN` 自身 + `levels` 中的每一层。

### 0.3 重复同值行政对的就地降解

**场景**："北京市北京市朝阳区"中，第一个"北京市"已提交为 `MULTI_ADMIN`，第二个
"北京市"进入时因 PROVINCE+CITY 均已占用发生冲突。

**机制**：在 `_segment_admit` 检查前，将已提交的 `MULTI_ADMIN` **就地降解**为某一
具体层级，释放另一层供新来者使用。降解方向基于两者之间是否有逗号：

| 情况 | MULTI_ADMIN 降解为 | 新来者得到 |
|------|-------------------|-----------|
| pair 之间**无逗号** | 最高层（PROVINCE）→ 正序 | 次高层（CITY） |
| pair 之间**有逗号** | 最低层（CITY）→ 逆序 | 最高层（PROVINCE） |

**"北京市北京市上海市"**：降解后 PROVINCE+CITY 均已占用，上海市的 `_segment_admit`
自然失败 → `split_at` → 上海市成为新地址，无需额外处理。

### 0.4 PROVINCE→DISTRICT 后继关系

`_VALID_SUCCESSORS[PROVINCE]` 加入 `DISTRICT` 与 `DISTRICT_CITY`，使"北京朝阳"类
跳层场景成立，不再依赖中间 CITY 占位。

### 0.5 suspect 机制与 MULTI_ADMIN 正交，不删除

suspect 负责"行政值被非行政 KEY 吸收"（如"北京中山路"中"北京"被路名 KEY 吸收），
MULTI_ADMIN 负责"确认实体同时承担多层级"，两者独立。

"北京中山路"处理流程（保持现有 suspect 逻辑不变）：

```
"北京" → pending_suspects [{PROVINCE,北京}, {CITY,北京}]
"中山路" KEY=路 → ROAD{value=北京中山, suspected=[{PROVINCE,北京},{CITY,北京}]}
_fixup_suspected_info → ROAD.value 变 "中山"
下游：ROAD(中山, 路) + admin_suspects(北京 PROVINCE|CITY)
```

### 0.6 输入解释规则

| 输入 | 目标组件链 |
|------|----------|
| 北京市北京市朝阳区 | PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) |
| 朝阳区,北京市,北京市 | DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) |
| 北京北京朝阳 | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳) |
| 朝阳,北京,北京 | DISTRICT(朝阳) + CITY(北京) + PROVINCE(北京) |
| 朝阳区,北京市北京市 | DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) |
| 北京市北京市上海市 | PROVINCE(北京,市) + CITY(北京,市) ∥ 上海市→新地址 |

---

## 1. 关键决策汇总

| Q | 决议 |
|---|------|
| Q1 "市" KEY 无邻接 value 时降级 | `DISTRICT_CITY` |
| Q2 multi-admin 的 key 字段 | 真实文本（standalone="" , key-driven=key clue 原文） |
| Q3 KEY 是否多层 | KEY 多层；value↔key 走交集 |
| Q4 DISTRICT_CITY 表达 | `AddressComponentType.DISTRICT_CITY`，`_ADMIN_RANK`=2，与 DISTRICT 同级 |
| Q5 multi-admin 表达 | `AddressComponentType.MULTI_ADMIN`；与普通 component 概念分离 |
| Q6 中英文 | 中文先跑通，英文后接公共抽象 |
| Q7 levels 域 | 仅 PROVINCE / CITY / DISTRICT 三层参与 MULTI_ADMIN |
| Q8 重复同值对的方向 | 无逗号→正序（高层先）；有逗号→逆序（低层先）；不从外部逗号尾方向推断 |
| Q9 suspect 函数 | **保留**；suspect 与 MULTI_ADMIN 正交，不删除任何 suspect 函数 |

KEY 显式 levels 表（hardcode 在 `address_policy_common.py`）：

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

### 2.2 类型表更新 [`address_state.py`]

- `SINGLE_OCCUPY` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_ADMIN_TYPES` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_COMMA_TAIL_ADMIN_TYPES` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_SUSPECT_KEY_TYPES` += `{DISTRICT_CITY}`
- `_ADMIN_RANK`：`DISTRICT_CITY = 2`（与 DISTRICT 同）；MULTI_ADMIN 不入表
- 辅助 `_admin_rank_of(comp_type, levels) -> int`：MULTI_ADMIN 取 levels 中最大 rank
- `_VALID_SUCCESSORS`：
  - `PROVINCE` 后继 += `{DISTRICT, DISTRICT_CITY}`
  - `CITY` 后继 += `{DISTRICT_CITY}`
  - `DISTRICT` 后继 += `{DISTRICT_CITY}`（罕见但允许）
  - `DISTRICT_CITY` 后继 = `DISTRICT` 后继的同等集合
  - `MULTI_ADMIN` 不写入静态表，由 `_segment_admit` 按 levels 动态解析

### 2.3 `_DraftComponent.levels` 字段 [`address_state.py`]

```python
@dataclass(slots=True)
class _DraftComponent:
    ...
    levels: tuple[AddressComponentType, ...] = ()
    ...
    def __post_init__(self) -> None:
        self.levels = _ordered_component_levels(self.levels)
        is_multi = self.component_type == AddressComponentType.MULTI_ADMIN
        if is_multi != (len(self.levels) >= 2):
            raise AssertionError("MULTI_ADMIN 与 levels 长度不一致")
```

`_clone_draft_component` 同步复制 `levels`。

### 2.4 `_commit` 双重 occupancy [`address_state.py`]

```python
# 在 _commit 的 occupancy 写入段
if comp_type in SINGLE_OCCUPY:
    state.occupancy[comp_type] = index
for level in _component_levels(comp_type, committed.levels):
    state.occupancy[level] = index
```

其中 `_component_levels(MULTI_ADMIN, (PROVINCE, CITY))` 返回 `(PROVINCE, CITY)`，
从而 MULTI_ADMIN 提交时同时占 MULTI_ADMIN + PROVINCE + CITY 三个槽。

### 2.5 `_segment_admit` MULTI_ADMIN 后继 [`address_state.py`]

```python
def _effective_successors(comp_type, levels=()):
    component_levels = _component_levels(comp_type, levels)
    if len(component_levels) <= 1:
        return valid_successors.get(component_levels[0] if component_levels else comp_type, _ALL_TYPES)
    # MULTI_ADMIN：取 levels 中各层后继的**交集**（最严格）
    successor_sets = [valid_successors.get(level, _ALL_TYPES) for level in component_levels]
    return frozenset.intersection(*[frozenset(s) for s in successor_sets])

def _component_can_follow(prev_type, prev_levels, next_type, next_levels):
    next_component_levels = _component_levels(next_type, next_levels)
    if next_component_levels:
        valid = _effective_successors(prev_type, prev_levels)
        # 进入 MULTI_ADMIN：levels 中**任一**层在后继集中即合法（最宽松）
        return any(level in valid for level in next_component_levels)
    return next_type in _effective_successors(prev_type, prev_levels)
```

`_segment_occupancy_conflict` 对 MULTI_ADMIN：

```python
if comp_type == AddressComponentType.MULTI_ADMIN:
    if AddressComponentType.MULTI_ADMIN in state.occupancy:
        return True
    return any(_occupies_level(state, level) for level in component_levels)
return any(_occupies_level(state, level) for level in component_levels)
```

DISTRICT_CITY 与 DISTRICT 互斥（`_occupies_level` 中双向检查）。

### 2.6 公共 admin span 工具上提 [`address_policy_common.py`]

将以下工具从 `address_policy_zh.py` 上提到 `address_policy_common.py`，
`address_policy_zh.py` 删除原定义，不留 re-export：

`_AdminValueSpan`, `collect_admin_value_span`, `_is_admin_value_clue`,
`_same_admin_value_span`, `_build_admin_value_span`, `_ordered_admin_levels`,
`match_admin_levels`, `_collect_chain_edge_admin_value_span`

---

## 3. 阶段 1 — value 多层级与 MULTI_ADMIN 落地

### 3.1 scanner 直辖市 dual-emit [`scanner.py`]

删除：
```python
direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}  # 单转 CITY
```

直辖市通过词典自然以 PROVINCE + CITY 双层级注册。scanner 同 span 多层级机制（`seen:
set[(component_type, text)]`）已支持，无需额外修改。

### 3.2 词典层级补齐 [`data/scanner_lexicons/zh_geo_lexicon.json`]

`provinces.soft` 补入 `{北京, 上海, 天津, 重庆}`（`cities.soft` 中已有）。
香港、澳门保持现状。不补县级市。

### 3.3 `resolve_admin_value_span` 改造 [`address_policy_zh.py`]

返回结构改为 `_AdminResolveResult(primary, levels)`：

- `levels`：occupancy + segment 过滤后剩余的全部可用层级，按 `_ADMIN_RANK` 降序
- `primary = levels[0]`

调用方按 `len(levels)` 决定落普通还是 `MULTI_ADMIN`。

### 3.4 `_flush_chain_as_standalone` admin group 分支 [`address_state.py`]

调用新 resolve 拿 `(primary, levels)`：

- `len(levels) >= 2` → 组件 `suspected` 传入多层 `levels`，`_commit` 时
  `_promote_multi_admin_from_suspects` 自动提升为 `MULTI_ADMIN`
- `len(levels) == 1` → 落普通单层 component

**无 KEY 的重复同值对**（"北京北京朝阳"）已由现有
`_resolve_admin_chain_assignment` + backtrack 处理（无逗号→降序分配
PROVINCE→CITY→DISTRICT），此路径不需要额外改动。

### 3.5 KEY-driven `_flush_admin_key_chain` 单段多层处理 [`address_state.py`]

单段两层时（candidate_levels 有 2 项），构造 component 时传入 `levels=candidate_levels`
进 `suspected`，`_commit` 时 `_promote_multi_admin_from_suspects` 自动提升：

```python
component = _DraftComponent(
    component_type=candidate_levels[0],
    ...
    levels=(),
    suspected=_admin_suspects_for_component(
        value, key_text, candidate_levels,  # 传入多层 → 后续 promote
        origin="key", ...
    ),
)
# _commit → _promote_multi_admin_from_suspects → MULTI_ADMIN
```

**`_promote_multi_admin_from_suspects` 的实现**：

```python
def _promote_multi_admin_from_suspects(component: _DraftComponent) -> None:
    """若 suspected 中存在 entry.value == component.value 且层级 ≥2，提升为 MULTI_ADMIN。"""
    if component.component_type == AddressComponentType.MULTI_ADMIN:
        return
    if isinstance(component.value, list):
        return
    grouped_levels: dict[tuple[str, str], list[AddressComponentType]] = {}
    remaining: list[_SuspectEntry] = []
    for entry in component.suspected:
        level = _pending_suspect_level(entry)
        if level is None or level not in _ADMIN_RANK:
            remaining.append(entry)
            continue
        if entry.value != component.value:  # 只处理 value 与组件相同的 suspect
            remaining.append(entry)
            continue
        grouped_levels.setdefault((entry.value, entry.key), []).append(level)
    promoted_levels: tuple[AddressComponentType, ...] = ()
    promoted_key = component.key if isinstance(component.key, str) else ""
    for (entry_value, entry_key), levels in grouped_levels.items():
        unique_levels = _ordered_component_levels(levels)
        if len(unique_levels) >= 2 and entry_value == component.value:
            promoted_levels = unique_levels
            if entry_key:
                promoted_key = entry_key
            break
    if not promoted_levels:
        return
    component.component_type = AddressComponentType.MULTI_ADMIN
    component.levels = promoted_levels
    component.key = promoted_key
    component.suspected = remaining  # 清空已消费的 suspect
```

### 3.6 KEY-driven 链中同段重复对处理 [`address_state.py`]

当 `_flush_admin_key_chain` 在**同一次 flush 调用**中遇到两个相同 value 的相邻段时
（如同 deferred_chain 内的"北京市北京市"），已有逻辑处理：

```python
if (
    cursor + 1 < len(segments)
    and len(available_levels) == 2
    and segments[cursor + 1][4] == segment_value       # 同 value
    and tuple(segments[cursor + 1][3]) == tuple(candidate_levels)  # 同候选层
    and (len(segments) > 2 or _has_admin_anchor_before_chain(state))
):
    has_comma = any(char in ",，" for char in raw_text[...])
    high_level, low_level = available_levels[0], available_levels[1]
    resolved.append((low_level if has_comma else high_level, ()))  # 有逗号→低层先
    resolved.append((high_level if has_comma else low_level, ()))
    cursor += 2
    continue
```

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

替换现有 if/elif 启发式：

```python
def _routed_key_clue(context, clue_index, clue):
    adjacent_span = _adjacent_value_span(context, clue_index, clue)

    if adjacent_span is not None:
        intersection = ordered_intersect(adjacent_span.levels, key_levels(clue))
        if not intersection:
            return None  # 进 ignored_address_key
        if len(intersection) == 1:
            return replace(clue, component_type=intersection[0], levels=())
        # ≥2：落 MULTI_ADMIN routed key，挂 levels
        return replace(clue, component_type=AddressComponentType.MULTI_ADMIN, levels=intersection)
    else:
        # 左邻不是 value
        if clue.text == "市":
            return replace(clue, component_type=AddressComponentType.DISTRICT_CITY, levels=())
        if clue.text == "省":
            return None
        return replace(clue, levels=())
```

注：`Clue` 需加可选 `levels: tuple[AddressComponentType, ...] = ()`，仅 routed key 临时使用，
scanner 输出仍 `levels=()`。

### 4.3 `_handle_key_clue` 处理 MULTI_ADMIN routed key [`address_zh.py`]

`effective_clue.component_type == MULTI_ADMIN` 时，在 `_flush_chain` 路径中把
routed key 上的 `levels` 透传到 component（在 3.5 的 `_flush_admin_key_chain` 中已做）。

### 4.4 删除 `_key_should_degrade_from_non_pure_value` [`address_policy_zh.py`]

被 4.2 步骤的 intersection 逻辑取代，整段及其调用点一并删除。

---

## 5. 阶段 3 — 重复同值行政对就地降解

> 处理 KEY 驱动场景下"北京市北京市朝阳区"类的重复同值行政对。
> 无 KEY 的 standalone 场景（"北京北京朝阳"）已由 3.4 的 `_resolve_admin_chain_assignment`
> 处理，本阶段不涉及。

### 5.1 新增 `_try_resolve_multi_admin_collision` [`address_state.py`]

```python
def _try_resolve_multi_admin_collision(
    state: _ParseState,
    raw_text: str,
    incoming_start: int,
    incoming_value: str,
    incoming_candidate_levels: tuple[AddressComponentType, ...],
) -> bool:
    """
    当新到来的 admin VALUE 与已提交的 MULTI_ADMIN 同值且 levels 有交集时，
    就地将 MULTI_ADMIN 降解为某一具体层级，释放另一层的 occupancy。

    降解规则：
    - MULTI_ADMIN 末尾到 incoming_start 之间有逗号 → 逆序：降解为最低层（CITY），释放高层（PROVINCE）
    - 无逗号 → 正序：降解为最高层（PROVINCE），释放低层（CITY）

    返回 True 表示已处理冲突，调用方可继续正常提交流程。
    """
    if AddressComponentType.MULTI_ADMIN not in state.occupancy:
        return False
    idx = state.occupancy[AddressComponentType.MULTI_ADMIN]
    existing = state.components[idx]
    if existing.component_type != AddressComponentType.MULTI_ADMIN:
        return False
    if isinstance(existing.value, list) or existing.value != incoming_value:
        return False
    if not any(lvl in incoming_candidate_levels for lvl in existing.levels):
        return False

    # existing.levels 已按 _ADMIN_RANK 降序排列
    has_comma = any(c in ",，" for c in raw_text[existing.end:incoming_start])
    resolved_level = existing.levels[-1] if has_comma else existing.levels[0]

    # 释放所有 MULTI_ADMIN 相关 occupancy
    state.occupancy.pop(AddressComponentType.MULTI_ADMIN, None)
    for lvl in existing.levels:
        state.occupancy.pop(lvl, None)

    # 以 resolved_level 重新占位
    state.occupancy[resolved_level] = idx

    # 降解组件
    existing.component_type = resolved_level
    existing.levels = ()

    # 同步 component_counts
    state.component_counts.pop(AddressComponentType.MULTI_ADMIN, None)
    _increment_component_count(state, resolved_level)

    # 同步 last_component_type
    if state.last_component_type == AddressComponentType.MULTI_ADMIN:
        state.last_component_type = resolved_level

    # 同步 segment_state，重置 direction
    # 重置原因：正序对（PROVINCE→CITY）在逆序逗号尾上下文中仍应被接受，
    # 让第二个组件以 group_first 为基准重新确定方向，而非被旧 direction 阻止。
    if state.segment_state.group_last_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_last_type = resolved_level
        state.segment_state.group_last_levels = ()
    if state.segment_state.group_first_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_first_type = resolved_level
        state.segment_state.group_first_levels = ()
    state.segment_state.direction = None

    return True
```

### 5.2 在 `_handle_value_clue` 中插入调用 [`address_zh.py`]

在 `if state.components or state.deferred_chain:` 块内，计算完 `admitted_level` /
`admitted_levels` 后、`_segment_admit` 检查**之前**插入：

```python
# 就地降解：chain 已 flush（KEY 驱动提交后），若存在同值 MULTI_ADMIN 则先降解
if admin_span is not None and not state.deferred_chain:
    if _try_resolve_multi_admin_collision(
        state,
        raw_text,
        clue.start,
        clue.text,
        admin_span.levels,
    ):
        # 降解后 occupancy 已变化，重新解析可用层级
        resolved_group = _resolve_standalone_admin_value_group(
            state,
            tuple(
                (i, clues[i])
                for i in range(admin_span.first_index, admin_span.last_index + 1)
            ),
        )
        if resolved_group is not None:
            admitted_level = resolved_group[0]
            admitted_levels = resolved_group[1] if len(resolved_group[1]) >= 2 else ()
```

### 5.3 流程验证（三个关键场景）

**"北京市北京市朝阳区"（无逗号）**：

```
北京 VALUE(P+C) + 市 KEY → _flush_admin_key_chain → candidate_levels=(P,C)
  → suspected=[{P,北京,市},{C,北京,市}] → _commit → _promote → MULTI_ADMIN(北京,市)
  → occupancy: {MA:0, P:0, C:0}

北京 VALUE 第2次 → _handle_value_clue
  → deferred_chain=[], components=[MULTI_ADMIN]
  → _try_resolve_multi_admin_collision: has_comma=False → resolved=PROVINCE
  → occupancy: {P:0}，direction=None
  → _resolve_standalone_admin_value_group → available=(CITY,) → admitted=CITY
  → 市 KEY flush → CITY(北京,市) ✓

朝阳区 → DISTRICT(朝阳,区) ✓
结果：PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) ✓
```

**"朝阳区,北京市,北京市"（pair 间有逗号）**：

```
朝阳区 → DISTRICT，comma_tail，direction=None，group_first=DISTRICT
北京市[1] → MULTI_ADMIN，ok_rev(DISTRICT follows MULTI_ADMIN)=True → direction=reverse

北京 VALUE 第2次 → _try_resolve_multi_admin_collision: has_comma=True → resolved=CITY
  → occupancy: {DISTRICT:0, CITY:1}，direction=None
  → available=(PROVINCE,) → admitted=PROVINCE
  → _segment_admit: direction=None, group_first=DISTRICT
      ok_rev=(DISTRICT follows PROVINCE)=True ✓ → direction=reverse ✓

市 KEY → PROVINCE(北京,市) ✓
结果：DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) ✓
```

**"北京市北京市上海市"（第三城市断开）**：

```
北京市[1] → MULTI_ADMIN，occupancy: {MA:0, P:0, C:0}
北京市[2] → _try_resolve → PROVINCE(北京)，occupancy: {P:0}
市 KEY → CITY(北京)，occupancy: {P:0, C:1}

上海 VALUE → _try_resolve: MULTI_ADMIN not in occupancy → False
  → _segment_admit(P): 占用 → False
  → _segment_admit(C): 占用 → False
  → split_at ✓  上海市成为新地址
```

---

## 6. 阶段 4 — 英文 multi-admin

### 6.1 EN scanner 去重粒度对齐 [`scanner.py`]

```python
seen: set[str]  →  seen: set[tuple[AddressComponentType, str]]
```

让英文同名 dual-level entry 都注册（数据驱动；本阶段不补名单）。

### 6.2 `EnAddressStack` 接 deferred chain + admin span [`address_en.py`]

- `_handle_value_clue` 引入 `collect_admin_value_span`
- `_flush_chain` 子类化，传入 EN-friendly resolver

### 6.3 EN resolver 策略 [`address_policy_en.py`]

- 默认 `primary = CITY`（不按 `_ADMIN_RANK` 高优先）
- `levels` 保 intersection 全集 → 多层时落 `MULTI_ADMIN`
- 词典数据暂缓（用户确认 EN 名单后再补）

### 6.4 EN KEY 多层暂不引入

`is_prefix_en_key` 等接口保持单层。

---

## 7. 阶段 5 — 下游适配

### 7.1 `_address_metadata` 序列化 [`address_state.py`]

新增 trace 字段 `address_component_levels`（与 `address_component_type` 平行）：

- 单层级 component：`""` （占位保对齐）
- `MULTI_ADMIN`：`"province|city"`（按 `_ADMIN_RANK` 降序，`|` 分隔）

### 7.2 `parser.py` 透传

新增 `address_component_levels` 到透传白名单。

### 7.3 `normalized_pii.py` 适配

- `_ADDRESS_COMPONENT_KEYS` += `("multi_admin", "district_city")`
- `_ORDERED_COMPONENT_KEYS`：`multi_admin` 插在 `province` 之前；`district_city` 插在 `district` 之后
- `_ADDRESS_COMPONENT_ALIASES`：无新增
- `_ADDRESS_MATCH_KEYS` += `("multi_admin", "district_city")`
- `_ADDRESS_COMPONENT_COMPARE_KEYS` += `("multi_admin", "district_city")`

### 7.4 `NormalizedAddressComponent.levels` 字段

在 `privacyguard/infrastructure/pii/address/types.py` 加 `levels: tuple[str, ...] = ()`。

`_ordered_components_from_metadata` 解析时同时读 `address_component_levels` trace，
挂到 component 上。

### 7.5 canonical / same-entity 比较器扩展

- `MULTI_ADMIN` 与任意 admin component 比较：levels 与对方 `({type} ∪ levels)` 取交集
  ≥1 即视同层
- `DISTRICT_CITY` 与 `DISTRICT` 不互通（不同行政性质，不做模糊匹配）—— 待确认

---

## 8. 阶段 6 — 清理

**明确删除**（不留 re-export）：

- `_key_should_degrade_from_non_pure_value`：被阶段 2 的 intersection 取代
- `direct_city_names` special case：直辖市改为词典 dual-emit
- `_flush_chain_as_standalone` 中被 MULTI_ADMIN 取代的 `removed_suspects` / `remaining_levels` 残留路径
- `address_policy_zh.py` 中已上提到 common 的工具函数本地定义

**明确保留**（不删除）：

- `_freeze_value_suspect_for_mismatched_admin_key`：处理行政值被非行政 KEY 吸收
- `_remove_last_value_suspect`：同上配套函数
- `_freeze_key_suspect_from_previous_key`：阶段 2 完成后评估，无调用再删

---

## 9. 必须前置的调研（动手前完成）

1. 全仓搜索 `component.component_type ==` / `comp_type in` / `_ordered_component_by_type`，
   列出阶段 7.5 实际需改动的比较点清单。

2. 确认 `Clue` dataclass 是否便于加 `levels` 临时字段，或是否应在 `effective_clue`
   替代物上挂载（避免污染 scanner 输出）。

3. 确认 `_VALID_SUCCESSORS[PROVINCE] += DISTRICT` 是否会让"北京朝阳"类组合在
   `_has_reasonable_successor_key` 链路被过早接受，影响其它 case。

4. 确认 `_segment_admit` 在 `direction=None`（就地降解后重置）时，PROVINCE/CITY 能
   通过 `group_first=DISTRICT` 的 `ok_rev` 检查，确保"朝阳区，北京市北京市"产出预期结果。

5. 确认 `_rebuild_component_derived_state` 中 occupancy 重建对 MULTI_ADMIN 已降解组件
   的处理是否正确。

---

## 10. 阶段 7 — 测试

### 10.1 新增 case（`tests/.../test_address_multi_admin.py`）

| 输入 | 预期组件链 |
|------|----------|
| `朝阳` | MULTI_ADMIN(levels=[city,district], value=朝阳) |
| `北京` | MULTI_ADMIN(levels=[province,city], value=北京) |
| `北京市` | MULTI_ADMIN(levels=[province,city], value=北京, key=市) |
| `北京市朝阳区` | MULTI_ADMIN(北京,市) + DISTRICT(朝阳,区) |
| `北京朝阳` | MULTI_ADMIN(北京) + DISTRICT(朝阳) |
| `苏州市` | CITY(苏州, key=市) |
| `苏州市张家港市` | CITY(苏州,市) + DISTRICT_CITY(张家港,市) |
| `张家港市`（单出现）| DISTRICT_CITY(张家港, key=市) |
| `北京市北京市朝阳区` | PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) |
| `北京北京朝阳` | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳) |
| `朝阳区,北京市,北京市` | DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) |
| `朝阳,北京,北京` | DISTRICT(朝阳) + CITY(北京) + PROVINCE(北京) |
| `朝阳区,北京市北京市` | DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) |
| `北京市北京市上海市` | PROVINCE(北京,市) + CITY(北京,市) ∥ 上海市→新地址 |
| `北京中山路` | ROAD(中山, key=路, suspected=[北京PROVINCE\|CITY]) |
| `朝阳区` | DISTRICT(朝阳, key=区) |
| `朝阳市` | CITY(朝阳, key=市) |
| `New York` | MULTI_ADMIN(levels=[city,province], value=New York)（待 EN 词典）|
| `Brooklyn, New York, NY` | CITY(Brooklyn) + MULTI_ADMIN(New York) + PROVINCE(NY)（待 EN 词典）|

### 10.2 旧测试策略

跑 `tests/` 全量后，**任何**旧测试失败：

1. 暂停实现
2. 在 PR 中列出失败 case 与失败原因
3. 询问用户：(a) 断言需更新 (b) 行为升级到 MULTI_ADMIN 但断言未跟上 (c) 真实回归
4. 不主动改任何旧测试，不自行决定"等价升级"

---

## 11. 风险与未验证假设

1. **`_try_resolve_multi_admin_collision` 触发条件**：要求 `not state.deferred_chain`，
   需验证是否有 KEY 驱动场景中 deferred_chain 非空但 MULTI_ADMIN 已提交的边界情况。

2. **`segment_state.direction = None` 副作用**：重置方向可能影响后续组件的逗号尾判断。
   已知对称 case 已验证，五个以上连续 admin 的复杂序列未系统验证。

3. **PROVINCE→DISTRICT 后继开放**：可能让以前被拒绝的序列通过，产生 false-positive。
   需监控旧测试。

4. **`_should_eager_split_duplicate_dual_admins` 返回 False 时**："北京北京"（无 KEY，无
   anchor）保留为单个 MULTI_ADMIN，第二个静默丢弃。此行为是否符合预期需测试确认。

5. **`_DraftComponent.levels` 的所有 clone / serialize 路径**：`_rebuild_component_derived_state`
   中 occupancy 重建对 MULTI_ADMIN 的处理，以及就地降解后的重建正确性，需验证。

6. **canonical / same-entity 比较器**：MULTI_ADMIN 的 OR 匹配语义需在阶段 7.5 调研后
   确认不破坏 restore 行为。

7. **KEY `Clue.levels` 临时字段**：是否破坏 `_dedupe_clues` 的 key 计算需 verify。

---

## 12. PR 拆分建议

| PR | 阶段 | 范围 |
|----|------|------|
| #1 | 阶段 0 + 阶段 1 | 类型基建 + value 多层落 MULTI_ADMIN + 直辖市 + 公共抽提 |
| #2 | 阶段 2 + 阶段 3 | KEY intersection + `_try_resolve_multi_admin_collision` + DISTRICT_CITY |
| #3 | 阶段 4 | EN scanner 去重 + EnAddressStack 接 admin span（不含数据）|
| #4 | 阶段 5 + 阶段 6 | 下游适配 + 清理 |

每个 PR 包含对应新增测试；旧测试红灯停下问用户。
