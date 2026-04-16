# 地址多层级 admin 与 MULTI_ADMIN component 实现计划

---

## 0. 设计目标与不变式

### 0.1 三类典型场景

| 场景 | 例子 | 当前行为 | 目标行为 |
|------|------|---------|---------|
| value 多层 | 北京（province/city）、朝阳（city/district）、New York（city/state）| 仅按 `_ADMIN_RANK` 取最高一层；其余信息丢弃或挂 suspect | 全部层级保留为 `level` 元组，落地时若 ≥2 层则成 `MULTI_ADMIN` |
| key 多层 | "市" ∈ {PROVINCE, CITY, DISTRICT_CITY} | "市" 默认 CITY，靠启发式硬降级到 DISTRICT | 显式注册 KEY levels；与 value levels 取交集；交集单元素直接落；多元素进 `MULTI_ADMIN` |
| key+value 组合 | "北京市" / "张家港市" | 词典+硬规则 | value↔key 走 intersection；intersection ≥2 则落 `MULTI_ADMIN`；左侧无 value 时 "市"→`DISTRICT_CITY` |

### 0.2 落地形态语义

#### `_DraftComponent.level`

- **所有** `_DraftComponent` 都有 `level: tuple[AddressComponentType, ...]`，**始终非空**。
- 普通 component：`level=(SINGLE,)`，例如 `ROAD(value=中山, key=路, level=(ROAD,))`。
- MULTI_ADMIN：`level=(P, C)` 等多元素元组，按 `_ADMIN_RANK` 降序排列。
- `component_type` 字段**保留**，但作为 `level` 的 derived 视图：
  - `len(level) == 1` → `component_type = level[0]`
  - `len(level) >= 2` → `component_type = MULTI_ADMIN`
- 不变式：构造 / mutate `level` 后必须同步刷新 `component_type`，由 `_DraftComponent.__post_init__` 与专用 setter 强制。

#### `_SuspectEntry.level`

- `_SuspectEntry.level: tuple[AddressComponentType, ...]`（旧版是 `level: str`，本次升级为元组），始终非空。
- 同 value 多层 suspect 用**单条 entry** 表达，不再用"同 group_key 多 entry"模拟。
- 例：`北京中山路` → `ROAD.suspected = [_SuspectEntry(level=(P, C), value="北京", key="", origin="key")]`。
- 序列化形式（`_serialize_suspected_entries` 输出）：
  ```json
  [{"levels":["province","city"],"value":"北京","key":"","origin":"key"}]
  ```

#### canonical / restore 比较

- 比较两个 component 视为"同 admin 实体"的判定：`level` 元组**取交集**，若交集非空且 value 等价 → 同实体；交集非空但 value 不等 → 明确不同实体；交集为空 → 不可比较（不参与同实体判定）。
- MULTI_ADMIN 与单层 component 比较时自动落入此规则。

### 0.3 重复同值行政对的就地降解

**场景**："北京市北京市朝阳区"中，第一个"北京市"已提交为 `MULTI_ADMIN(P,C)`，第二个"北京市"进入时因 PROVINCE+CITY 均已被 MULTI_ADMIN 占用发生冲突。

**机制**：在 `_segment_admit` 检查前，将已提交的 `MULTI_ADMIN` **就地降解**为某一具体层级（缩短 `level` 元组），释放另一层供新来者使用。降解方向基于两者之间是否有逗号：

| 情况 | MULTI_ADMIN 保留 | 新来者得到 |
|------|------------------|-----------|
| pair 之间**无逗号** | 最高层（PROVINCE） | 次高层（CITY） |
| pair 之间**有逗号** | 最低层（CITY） | 最高层（PROVINCE） |

**"北京市北京市上海市"**：第二个"北京市"触发降解后 PROVINCE+CITY 均已具体占用，上海市的 `_segment_admit` 自然失败 → `split_at` → 上海市成为新地址，无需额外处理。

### 0.4 PROVINCE→DISTRICT 后继关系

`_VALID_SUCCESSORS[PROVINCE]` 加入 `DISTRICT` 与 `DISTRICT_CITY`，使"北京朝阳"类跳层场景成立，不再依赖中间 CITY 占位。

### 0.5 suspect 与 MULTI_ADMIN 的语义切分

| 概念 | 性质 | 触发来源 | 数据载体 |
|------|------|---------|---------|
| **MULTI_ADMIN** | 本体论：实体真实承担多层（北京 *是* 省 *也是* 市） | scanner 词典 dual-emit / KEY×VALUE intersection | `_DraftComponent(level=(P,C), component_type=MULTI_ADMIN)` |
| **suspect** | 认识论：值是否属于此层不确定（被非行政 KEY 吸收 / 上下文歧义） | `_freeze_value_suspect_for_mismatched_admin_key` / `_freeze_key_suspect_from_previous_key` | `_DraftComponent.suspected: list[_SuspectEntry]` |

两者**正交**：MULTI_ADMIN 是**真状态**（影响 occupancy / successor），suspect 是**只读元数据**（不参与提交决策，仅用于 metadata 与 canonical 还原比对）。

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
| 北京北京中山路 | PROVINCE(北京) + ROAD(中山, 路, suspected=[{level=(C,), value=北京, key=""}]) |
| Brooklyn, New York, NY | DISTRICT(Brooklyn) + CITY(New York) + PROVINCE(NY) |

---

## 1. 关键决策汇总

| Q | 决议 |
|---|------|
| `_DraftComponent.level` 字段 | 所有 component 都有；`tuple[AddressComponentType, ...]`；始终非空 |
| `component_type` 字段 | 保留，作为 `level` 的 derived 视图 |
| `_SuspectEntry.level` 字段 | 升级为 `tuple[AddressComponentType, ...]`；单条 entry 即可表达多层 |
| "市" KEY 无邻接 value 时降级 | `DISTRICT_CITY` |
| multi-admin 的 key 字段 | 真实文本（standalone="" , key-driven=key clue 原文） |
| KEY 是否多层 | KEY 多层；value↔key 走交集 |
| DISTRICT_CITY 表达 | `AddressComponentType.DISTRICT_CITY`，`_ADMIN_RANK`=2，与 DISTRICT 同级互斥 |
| MULTI_ADMIN 表达 | `AddressComponentType.MULTI_ADMIN`，作为 `len(level)>=2` 时的 derived 类型 |
| MULTI_ADMIN occupancy | 锁住 `level` 中每层的 occupancy slot；不另设 MULTI_ADMIN slot |
| MULTI_ADMIN successor | 前 MULTI_ADMIN：levels 后继**交集**（严格）；后 MULTI_ADMIN：levels 中**任一层**为合法后继即可（宽松） |
| levels 域 | 仅 PROVINCE / CITY / DISTRICT / DISTRICT_CITY / SUBDISTRICT 参与 MULTI_ADMIN |
| 重复同值对的方向 | 无逗号→正序（高层先）；有逗号→逆序（低层先） |
| collision 触发点 | `_freeze_*` 写 suspect 前 + `_commit` 写 component 前 |
| 中英文 | 中文先跑通，英文用相同抽象但允许 enstack 自定 ranking |
| suspect 函数 | **全部保留**；suspect 与 MULTI_ADMIN 正交 |

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
            # 兼容旧构造：level 缺省时由 component_type 反向填充
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
    """admin 类按 _ADMIN_RANK 降序；非 admin 类（单元素）保持原状。"""
    if len(level) <= 1:
        return tuple(level)
    return tuple(sorted(level, key=lambda l: -_ADMIN_RANK.get(l, 0)))

def _set_component_level(comp: _DraftComponent, new_level: tuple[AddressComponentType, ...]) -> None:
    """统一入口：mutate level 必须经此函数，自动同步 component_type。"""
    comp.level = _ordered_component_level(new_level)
    comp._sync_component_type()
```

### 2.3 `_SuspectEntry.level` 字段 [`address_state.py`]

```python
@dataclass(slots=True)
class _SuspectEntry:
    level: tuple[AddressComponentType, ...]   # 升级：原 str → tuple
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
- `_ADMIN_TYPES` += `{DISTRICT_CITY}`（**不**加 MULTI_ADMIN：MULTI_ADMIN 不直接参与"是否为 admin"判定，由 `level` 内容决定）
- `_COMMA_TAIL_ADMIN_TYPES` += `{DISTRICT_CITY}`
- `_SUSPECT_KEY_TYPES` += `{DISTRICT_CITY}`
- `_ADMIN_RANK`：`DISTRICT_CITY = 2`（与 DISTRICT 同）；MULTI_ADMIN 不入表
- 新辅助函数：

  ```python
  def _is_admin_component(comp: _DraftComponent) -> bool:
      """component 是否包含 admin 层级（含 MULTI_ADMIN 情况）。"""
      return any(l in _ADMIN_TYPES for l in comp.level)

  def _admin_rank_max(comp: _DraftComponent) -> int:
      """component 的最高 admin rank（用于逗号尾首组件 rank 校验）。"""
      return max((_ADMIN_RANK.get(l, 0) for l in comp.level), default=0)

  def _admin_levels_of(comp: _DraftComponent) -> tuple[AddressComponentType, ...]:
      """component 中属于 admin 的层级子集。"""
      return tuple(l for l in comp.level if l in _ADMIN_TYPES)
  ```

- `_VALID_SUCCESSORS`：
  - `PROVINCE` 后继 += `{DISTRICT, DISTRICT_CITY}`
  - `CITY` 后继 += `{DISTRICT_CITY}`
  - `DISTRICT_CITY` 后继 = `DISTRICT` 后继的同等集合
  - MULTI_ADMIN 不写入静态表，由 `_segment_admit` 按 `level` 动态解析

### 2.5 `_commit` occupancy 写入 [`address_state.py`]

```python
# _commit 的 occupancy 写入段
for level in component.level:
    if level in SINGLE_OCCUPY:
        state.occupancy[level] = index
```

MULTI_ADMIN 提交时，`level=(P, C)` → 同时占住 `state.occupancy[P]` 和 `state.occupancy[C]`，两者指向同一 `index`。**不**另设 `state.occupancy[MULTI_ADMIN]` slot。

碰撞反查：通过 `state.components[state.occupancy[P]].component_type == MULTI_ADMIN` 判定该层是否被多层 component 占据。

### 2.6 `_segment_admit` MULTI_ADMIN 后继逻辑 [`address_state.py`]

```python
def _effective_successors(prev: _DraftComponent | None) -> frozenset[AddressComponentType]:
    if prev is None:
        return _ALL_TYPES
    if prev.component_type == AddressComponentType.MULTI_ADMIN:
        # 严格：所有 levels 后继的交集
        sets = [_VALID_SUCCESSORS.get(l, _ALL_TYPES) for l in prev.level]
        return frozenset.intersection(*[frozenset(s) for s in sets])
    return _VALID_SUCCESSORS.get(prev.component_type, _ALL_TYPES)

def _component_can_follow(prev: _DraftComponent | None,
                          next_level: tuple[AddressComponentType, ...]) -> bool:
    valid = _effective_successors(prev)
    # 宽松：next 是 MULTI_ADMIN 时，level 中任一层在 valid 内即合法
    return any(l in valid for l in next_level)
```

`_segment_occupancy_conflict` 调整为按 `level` 元组遍历：

```python
def _segment_occupancy_conflict(state, level_tuple):
    return any(_occupies_level(state, l) for l in level_tuple)
```

DISTRICT_CITY 与 DISTRICT 互斥（`_occupies_level` 双向检查 SINGLE_OCCUPY）。

### 2.7 公共 admin span 工具上提 [`address_policy_common.py`]

将以下工具从 `address_policy_zh.py` 上提到 `address_policy_common.py`，`address_policy_zh.py` 删除原定义，不留 re-export：

`_AdminValueSpan`, `collect_admin_value_span`, `_is_admin_value_clue`, `_same_admin_value_span`, `_build_admin_value_span`, `_ordered_admin_levels`, `match_admin_levels`, `_collect_chain_edge_admin_value_span`

EN 与 ZH 共用同一抽象，但 `_ADMIN_RANK` 与 `_VALID_SUCCESSORS` 由各 stack 注入（见 6.3）。

---

## 3. 阶段 1 — value 多层级与 MULTI_ADMIN 落地

### 3.1 scanner 直辖市 dual-emit [`scanner.py`]

删除：
```python
direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}  # 单转 CITY
```

直辖市通过词典自然以 PROVINCE + CITY 双层级注册。scanner 同 span 多层级机制（`seen: set[(component_type, text)]`）已支持，无需额外修改。

### 3.2 词典层级补齐 [`data/scanner_lexicons/zh_geo_lexicon.json`]

- `provinces.soft` 补入 `{北京, 上海, 天津, 重庆}`（`cities.soft` 中已有）。
- 香港、澳门保持现状。
- `district_cities.soft`：新建条目，初始填 `{张家港}` 等典型县级市，后续按需扩展。
- 不补普通县级市到 `cities`。

### 3.3 `resolve_admin_value_span` 改造 [`address_policy_common.py`]

返回结构改为 `_AdminResolveResult(level)`：

- `level: tuple[AddressComponentType, ...]`：occupancy + segment 过滤后剩余的全部可用层级，按 `_ADMIN_RANK` 降序

调用方按 `len(level)` 决定落普通还是 `MULTI_ADMIN`。

### 3.4 `_flush_chain_as_standalone` admin group 分支 [`address_state.py`]

调用新 resolve 拿 `level: tuple[...]`：

```python
if len(level) >= 2:
    component = _DraftComponent(
        component_type=AddressComponentType.MULTI_ADMIN,  # 由 __post_init__ 同步
        level=level,
        ...,
        suspected=[],   # 多层信息走 level 字段，不再塞 suspected
    )
elif len(level) == 1:
    component = _DraftComponent(
        component_type=level[0],
        level=level,
        ...,
        suspected=[...],  # 仅承载真正的 suspect（被非行政 KEY 吸收等）
    )
else:
    state.split_at = ...; return
```

`_remove_pending_suspect_group_by_span` 仍调用，承担"清理 pending 中已被本次 commit 消化的同 span suspect"职责，但**不再**用 `remaining_levels` 把剩余层塞回 component.suspected——剩余层信息现在由 `level` 字段直接承载。

### 3.5 KEY-driven `_flush_admin_key_chain` 单段多层处理 [`address_state.py`]

KEY-driven 路径同样统一走"算可用 level → 决定单层 / MULTI_ADMIN"流程：

```python
def _flush_admin_key_chain(state, used_entries, key_clue, ...):
    span = _build_admin_value_span(used_entries)
    candidate_levels = ordered_intersect(span.level, key_levels(key_clue))
    available = _filter_available(state, candidate_levels)
    if not available:
        state.split_at = ...; return
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

当 `_flush_admin_key_chain` 在**同一次 flush 调用**中遇到两个相同 value 的相邻段时（如同 deferred_chain 内的"北京市北京市"），按本计划阶段 3 / 5 的统一规则：

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
    # 有逗号→低层先（逆序）；无逗号→高层先（正序）
    resolved.append(((low_level if has_comma else high_level,), ()))
    resolved.append(((high_level if has_comma else low_level,), ()))
    cursor += 2
    continue
```

注意：此处直接产出**单层** component（每个 component 的 `level=(single,)`），不走 MULTI_ADMIN，因为重复对场景已明确两层各自归宿。

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
        intersection = ordered_intersect(adjacent_span.level, key_levels(clue))
        if not intersection:
            return None  # 进 ignored_address_key
        if len(intersection) == 1:
            return replace(clue, component_type=intersection[0])
        # ≥2：标记为 MULTI_ADMIN，commit 时由 _flush_admin_key_chain 重新计算 level
        return replace(clue, component_type=AddressComponentType.MULTI_ADMIN)
    else:
        # 左邻不是 value
        if clue.text == "市":
            return replace(clue, component_type=AddressComponentType.DISTRICT_CITY)
        if clue.text == "省":
            return None
        return clue
```

注：**不**给 `Clue` 加 `levels` 字段。intersection 信息在 `_flush_admin_key_chain` 中由 `key_levels(clue) ∩ span.level` 重新计算，避免污染 scanner 输出。

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
    若 incoming_value 与某已提交的 MULTI_ADMIN 同值且 level 有交集，
    根据 pair 间逗号方向把 MULTI_ADMIN 降解，返回 incoming 应取的 level 子集。
    返回 None 表示不存在碰撞，调用方按原逻辑处理。
    """
    target_idx = None
    for lvl in incoming_levels:
        idx = state.occupancy.get(lvl)
        if idx is None:
            continue
        comp = state.components[idx]
        if (comp.component_type == AddressComponentType.MULTI_ADMIN
                and not isinstance(comp.value, list)
                and comp.value == incoming_value):
            target_idx = idx
            break
    if target_idx is None:
        return None

    existing = state.components[target_idx]
    overlap = [l for l in existing.level if l in incoming_levels]
    if not overlap:
        return None

    has_comma = any(c in ",," for c in raw_text[existing.end:incoming_start])
    if has_comma:
        # pair 间有逗号 → 逆序：existing 保最低层，incoming 取最高层
        existing_keep = min(overlap, key=lambda l: _ADMIN_RANK[l])
        incoming_take = max(overlap, key=lambda l: _ADMIN_RANK[l])
    else:
        # 无逗号 → 正序：existing 保最高层，incoming 取最低层
        existing_keep = max(overlap, key=lambda l: _ADMIN_RANK[l])
        incoming_take = min(overlap, key=lambda l: _ADMIN_RANK[l])

    # 释放 incoming 要拿的那一层 occupancy
    state.occupancy.pop(incoming_take, None)

    # existing.level 收缩
    new_level = tuple(l for l in existing.level if l != incoming_take)
    _set_component_level(existing, new_level)  # 自动同步 component_type

    # 同步 component_counts
    if AddressComponentType.MULTI_ADMIN in state.component_counts:
        state.component_counts[AddressComponentType.MULTI_ADMIN] -= 1
        if state.component_counts[AddressComponentType.MULTI_ADMIN] == 0:
            del state.component_counts[AddressComponentType.MULTI_ADMIN]
    if existing.component_type != AddressComponentType.MULTI_ADMIN:
        _increment_component_count(state, existing.component_type)

    # 同步 last_component_type
    if state.last_component_type == AddressComponentType.MULTI_ADMIN:
        state.last_component_type = existing.component_type

    # 同步 segment_state，重置 direction
    # 重置原因：让 incoming 以 group_first 为基准重新决策方向，而非被旧 direction 阻止。
    if state.segment_state.group_last_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_last_type = existing.component_type
    if state.segment_state.group_first_type == AddressComponentType.MULTI_ADMIN:
        state.segment_state.group_first_type = existing.component_type
    state.segment_state.direction = None

    return (incoming_take,)
```

### 5.2 触发点

#### 5.2.1 在 `_handle_value_clue` / `_commit` 路径插入 [`address_zh.py`, `address_state.py`]

在 admin VALUE 进入 `_segment_admit` 检查**之前**：

```python
# _handle_value_clue 内，admin_span 算出后
if admin_span is not None and not state.deferred_chain:
    forced_levels = _resolve_multi_admin_collision(
        state, raw_text, clue.start, clue.text, admin_span.level,
    )
    if forced_levels is not None:
        # 降解后 occupancy 已变化，按强制 level 走单层 commit
        admit_level = forced_levels
```

#### 5.2.2 在 `_freeze_*` 写 suspect 路径插入 [`address_state.py`]

当 `_freeze_key_suspect_from_previous_key` / `_freeze_value_suspect_for_mismatched_admin_key` 准备构造 `_SuspectEntry` 时，先做 collision 检查：

```python
def _freeze_key_suspect_from_previous_key(state, raw_text, stream, key_clue):
    span_text, span_start, span_end = _extract_absorbed_value_span(...)
    candidate_levels = _candidate_levels_for_value(span_text)  # 由词典查
    if len(candidate_levels) >= 2:
        forced = _resolve_multi_admin_collision(
            state, raw_text, span_start, span_text, candidate_levels,
        )
        if forced is not None:
            candidate_levels = forced  # suspect 的 level 收缩
    entry = _SuspectEntry(
        level=candidate_levels,
        value=span_text,
        key="",          # ← 原值的 key（被吸收前为空），不是吸收 KEY
        origin="key",
        start=span_start,
        end=span_end,
    )
    state.pending_suspects.append(entry)
```

**关键变化**：`_freeze_key_suspect_from_previous_key` 写入的 `entry.key = ""`（原值的 key），而非吸收 KEY 文本。`_fixup_suspected_info` 的 trim token 由 `entry.value + entry.key = "北京" + "" = "北京"` 计算，正确从 ROAD value 切去前缀。

### 5.3 流程验证

#### "北京市北京市朝阳区"（无逗号）

```
"北京市"[1] → _flush_admin_key_chain → candidate=(P,C), available=(P,C)
            → MULTI_ADMIN(value=北京, key=市, level=(P,C))
            → occupancy: {P:0, C:0}

"北京"[2] VALUE → admin_span.level=(P,C)
                → _resolve_multi_admin_collision:
                   existing=MULTI_ADMIN at idx 0, overlap=[P,C], no comma
                   → existing 保 P，incoming 取 C
                   → existing.level=(P,) → component_type=PROVINCE
                   → occupancy: {P:0}
                   → direction=None
                   → 返回 (C,)
                → admit_level=(C,)，正常 _segment_admit ✓
"市" KEY → CITY(北京, 市) → occupancy: {P:0, C:1} ✓

"朝阳区" → DISTRICT(朝阳, 区) ✓ （CITY→DISTRICT 合法）
结果：PROVINCE(北京,市) + CITY(北京,市) + DISTRICT(朝阳,区) ✓
```

#### "朝阳区,北京市,北京市"（pair 间有逗号）

```
"朝阳区" → DISTRICT(朝阳,区), comma_tail, group_first=DISTRICT, direction=None
"北京市"[1] → MULTI_ADMIN(北京,市,(P,C))
            → 逗号尾首组件 rank check：max(P,C)=4 > 2 ✓
            → direction 待锁
            → occupancy: {DISTRICT:0, P:1, C:1}

"北京"[2] VALUE → _resolve_multi_admin_collision:
                   has_comma=True → existing 保 C，incoming 取 P
                   → existing.level=(C,) → CITY(北京,市)
                   → occupancy: {DISTRICT:0, C:1}
                   → direction=None
                   → 返回 (P,)
                → admit_level=(P,)，_segment_admit:
                   group_first=DISTRICT, incoming=PROVINCE
                   PROVINCE in DISTRICT successors? No
                   DISTRICT in PROVINCE successors? Yes (新加)
                   → direction=reverse ✓

"市" KEY → PROVINCE(北京,市) ✓
结果：DISTRICT(朝阳,区) + CITY(北京,市) + PROVINCE(北京,市) ✓
```

#### "朝阳区,北京市北京市"（pair 间无逗号）

```
"朝阳区" → DISTRICT, group_first=DISTRICT
"北京市"[1] → MULTI_ADMIN(北京,(P,C))，rank check ok，direction 待锁

"北京"[2] VALUE → _resolve_multi_admin_collision:
                   has_comma=False (existing.end → incoming.start 间无逗号)
                   → existing 保 P，incoming 取 C
                   → PROVINCE(北京,市)
                   → occupancy: {DISTRICT:0, P:1}
                   → direction=None
                   → 返回 (C,)
                → admit_level=(C,)，_segment_admit:
                   group_first=DISTRICT, incoming=CITY
                   DISTRICT in CITY successors? Yes
                   → direction=reverse ✓

"市" KEY → CITY(北京,市) ✓
结果：DISTRICT(朝阳,区) + PROVINCE(北京,市) + CITY(北京,市) ✓
```

#### "北京市北京市上海市"（第三城市断开）

```
"北京市"[1] → MULTI_ADMIN(北京,(P,C))，occupancy: {P:0, C:0}
"北京市"[2] → _resolve_multi_admin_collision → 降解为 P + C，occupancy: {P:0, C:1}
"上海" VALUE → admin_span.level=(P,C)
             → _resolve_multi_admin_collision:
                no MULTI_ADMIN with value="上海" in occupancy → 返回 None
             → _segment_admit(P): 占用 → False
             → _segment_admit(C): 占用 → False
             → split_at ✓ 上海市成为新地址
```

#### "北京中山路"

```
"北京" VALUE → pending_suspects（不进 deferred）
"中山路" → 触发 _freeze_key_suspect_from_previous_key
        → 抽取 "北京"，候选 level=(P,C)
        → _resolve_multi_admin_collision: 无 MULTI_ADMIN 同值 → 返回 None
        → 写 _SuspectEntry(level=(P,C), value="北京", key="", origin="key")
"路" KEY → ROAD commit, suspected=[entry]
        → ROAD(value="北京中山", key="路", level=(ROAD,))
_fixup_suspected_info → trim token = "北京"+"" = "北京"
                     → ROAD.value = "中山"
结果：ROAD(中山, 路, level=(ROAD,), suspected=[{level=(P,C), value=北京, key=""}]) ✓
```

#### "南京中山路, 南京市"

```
第一段处理同上 → ROAD(中山, 路, suspected=[{level=(C,), value=南京, key="", origin=key}])
                  （南京只有 CITY 一层，suspect.level=(C,)）

", 南京市" → "南京" VALUE 进入，admin_span.level=(C,) 单层
          → _prune_prior_component_suspects(state, value="南京", level=(C,))
             遍历已提交 components 的 suspected，按 (value, level 交集) 移除匹配条目
             → ROAD.suspected 清空
          → admit (C,) → CITY(南京)
结果：ROAD(中山, 路, suspected=[]) + CITY(南京) ✓
```

#### "北京北京中山路"

```
"北京"[1] VALUE → MULTI_ADMIN(北京,(P,C)), occupancy: {P:0, C:0}
"北京"[2] VALUE → 接下来是非行政 KEY "路"，进入 suspect 路径
                → _freeze_key_suspect_from_previous_key: 候选 level=(P,C)
                → _resolve_multi_admin_collision:
                   existing=MULTI_ADMIN at idx 0, overlap=[P,C], no comma
                   → existing 保 P，incoming 取 C
                   → existing.level=(P,) → PROVINCE(北京)
                   → occupancy: {P:0}
                   → 返回 (C,)
                → 写 _SuspectEntry(level=(C,), value=北京, key="")
"路" → ROAD(value="北京中山", 路, suspected=[entry])
fixup → trim "北京" → ROAD.value="中山"
结果：PROVINCE(北京) + ROAD(中山, 路, suspected=[{level=(C,), value=北京, key=""}]) ✓
```

---

## 6. 阶段 4 — 英文 multi-admin

### 6.1 EN scanner 去重粒度对齐 [`scanner.py`]

```python
seen: set[str]  →  seen: set[tuple[AddressComponentType, str]]
```

让英文同名 dual-level entry 都注册（数据驱动）。

### 6.2 `EnAddressStack` 接 deferred chain + admin span [`address_en.py`]

- `_handle_value_clue` 引入 `collect_admin_value_span`（从 `address_policy_common.py`）。
- `_flush_chain` 子类化，传入 EN-friendly resolver。
- 复用 `_resolve_multi_admin_collision`（与 ZH 共享，参数化 `_ADMIN_RANK` / `_VALID_SUCCESSORS`）。

### 6.3 EN ranking 与后继关系 [`address_policy_en.py`]

EN stack 维护自己的 `_EN_ADMIN_RANK` 与 `_EN_VALID_SUCCESSORS`，按美国地址书写习惯：

- rank：`STATE > CITY > DISTRICT > SUBDISTRICT`（STATE = PROVINCE 在内部枚举映射）
- successor：`STATE → CITY → DISTRICT → SUBDISTRICT → ROAD → POI`

`_resolve_multi_admin_collision` 与 `_effective_successors` 接受 `admin_rank: dict` 与 `valid_successors: dict` 参数；ZH / EN 各自调用时传入对应表。

### 6.4 EN KEY 多层暂不引入

`is_prefix_en_key` 等接口保持单层；如未来 "St" 等 KEY 出现多层，再补 `_MULTI_LEVEL_KEY_LEVELS_EN`。

### 6.5 数据：Brooklyn 等 NYC borough

`en_geo_lexicon.json` 中将 `Brooklyn / Manhattan / Queens / Bronx / Staten Island` 注册为 `district`（borough = NYC 行政区）。`New York` 注册为 `city + state` dual-level。

---

## 7. 阶段 5 — 下游适配

### 7.1 `_address_metadata` 序列化 [`address_state.py`]

新增 trace 字段 `address_component_level`（与 `address_component_type` 平行）：

- 单层 component：`"road"` / `"province"` 等单值字符串
- MULTI_ADMIN：`"province|city"`（按 `_ADMIN_RANK` 降序，`|` 分隔）
- DISTRICT_CITY：`"district_city"`

### 7.2 `parser.py` 透传

新增 `address_component_level` 到透传白名单。

### 7.3 `normalized_pii.py` 适配

- `_ADDRESS_COMPONENT_KEYS` += `("multi_admin", "district_city")`
- `_ORDERED_COMPONENT_KEYS`：`multi_admin` 插在 `province` 之前；`district_city` 插在 `district` 之后
- `_ADDRESS_MATCH_KEYS` += `("multi_admin", "district_city")`
- `_ADDRESS_COMPONENT_COMPARE_KEYS` += `("multi_admin", "district_city")`

### 7.4 `NormalizedAddressComponent.level` 字段

在 `privacyguard/infrastructure/pii/address/types.py` 加 `level: tuple[str, ...] = ()`。

`_ordered_components_from_metadata` 解析时同时读 `address_component_level` trace，挂到 component 上。

### 7.5 canonical / same-entity 比较器扩展

- 任意两个 component 比较时：
  - `level` **元组取交集**：交集为空 → 不可比较该角色（不参与"同实体"判定，也不构成"差异")
  - 交集非空且 value 等价 → 同实体
  - 交集非空但 value 不等价 → 明确不同实体
- 例："北京市中山路" 的 `MULTI_ADMIN(北京, level=(P,C))` 与 "江苏省南京市中山路" 比较：
  - 与 `PROVINCE(江苏, level=(P,))`：交集 `{P}` 非空，value 不等 → 明确不同
  - 与 `CITY(南京, level=(C,))`：交集 `{C}` 非空，value 不等 → 明确不同
  - 最终：明确不同实体 ✓
- DISTRICT_CITY 与 DISTRICT 的 `level` 元组无交集（一个是 `(DISTRICT_CITY,)`，另一个是 `(DISTRICT,)`），按上述规则**不互通**——符合"不同行政性质，不做模糊匹配"语义。

---

## 8. 阶段 6 — 清理

**明确删除**（不留 re-export）：

- `_key_should_degrade_from_non_pure_value`：被阶段 2 的 intersection 取代
- `direct_city_names` special case：直辖市改为词典 dual-emit
- `address_policy_zh.py` 中已上提到 common 的工具函数本地定义
- `_group_suspected_entries`：原"同 group_key 多 entry"模式被 `_SuspectEntry.level: tuple` 取代（如果除序列化外无其他调用方）

**明确保留**（不删除）：

- `_freeze_value_suspect_for_mismatched_admin_key`：处理行政值被非行政 KEY 吸收
- `_freeze_key_suspect_from_previous_key`：同上配套（仅修改 entry.key 行为：写空字符串）
- `_remove_last_value_suspect`：同上配套
- `_remove_pending_suspect_group_by_span`：用于"南京中山路, 南京市"清理 ROAD.suspected
- `_prune_prior_component_suspects`：用于跨 component 的 suspect 移除
- `_fixup_suspected_info`：trim ROAD.value 中被 suspect 标注的前缀
- `_flush_chain_as_standalone` 中的 `removed_suspects` 调用（仅承担"清理 pending"职责，不再承担"多层载体"）

**明确改造**（保留函数名 + 调整签名 / 行为）：

- `_freeze_key_suspect_from_previous_key`：写 `entry.key=""`（原值无 key），写 `entry.level=(候选层 tuple)`（多层一次写完）
- `_serialize_suspected_entries`：直接读 `entry.level` tuple 序列化为 `{"levels":[...]}`，无需先 group
- `_remove_pending_suspect_by_level(state, level)`：新语义——遍历 entries，若 `level in entry.level`，则从 tuple 中移除该层；移除后 tuple 空 → 整条删除；否则保留 entry 仅缩短 level
- `_suspect_sort_key`：基于 `entry.level[0]` 的 rank（已是降序首位）
- `_suspect_group_key`：可保留作 metadata 聚合；若仅服务序列化，可在 8.1 删除时一并清理

---

## 9. 必须前置的调研（动手前完成）

1. 全仓搜索 `component.component_type ==` / `comp_type in` / `_ordered_component_by_type`，列出阶段 7.5 实际需改动的比较点清单。

2. 确认 `_VALID_SUCCESSORS[PROVINCE] += DISTRICT` 是否会让"北京朝阳"类组合在 `_has_reasonable_successor_key` 链路被过早接受，影响其它 case。

3. 确认 `_segment_admit` 在 `direction=None`（就地降解后重置）时，PROVINCE/CITY 能通过 `group_first=DISTRICT` 的 `ok_rev` 检查，确保"朝阳区，北京市北京市"产出预期结果。

4. 确认 `_rebuild_component_derived_state` 中 occupancy 重建对 MULTI_ADMIN 已降解组件的处理是否正确（重建必须按 `comp.level` 元组遍历，而非仅 `comp.component_type`）。

5. 确认 `_freeze_key_suspect_from_previous_key` 改写 `entry.key=""` 后，`_fixup_suspected_info` 的 trim 逻辑（基于 `entry.value + entry.key` 表面文本匹配）仍能正确切掉 ROAD.value 前缀。需新增 case：`北京市中山路` 的 `entry.key=""` vs 旧版 `entry.key="路"` 的 trim 行为对比。

6. 确认 `_SuspectEntry.level` 由 str 改为 tuple 后，所有 `entry.level == "..."` 字符串比对处的 call site 都改为 `lvl in entry.level` 或 `entry.level == (lvl,)`。

7. 确认 `_resolve_multi_admin_collision` 在 `_freeze_*` 触发时，已提交的 MULTI_ADMIN 已经在 `state.components` 中（即 freeze 不发生在 deferred_chain 仍非空的中间态）。

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
| `北京中山路` | ROAD(中山, key=路, level=(ROAD,), suspected=[{level=(P,C), value=北京, key="", origin=key}]) |
| `南京中山路, 南京市` | ROAD(中山, 路, suspected=[]) + CITY(南京) |
| `北京北京中山路` | PROVINCE(北京) + ROAD(中山, 路, suspected=[{level=(C,), value=北京, key=""}]) |
| `朝阳区` | DISTRICT(朝阳, key=区) |
| `朝阳市` | CITY(朝阳, key=市) |
| `New York` | MULTI_ADMIN(level=(STATE,CITY), value=New York) |
| `Brooklyn, New York, NY` | DISTRICT(Brooklyn) + CITY(New York) + PROVINCE(NY) |

### 10.2 旧测试策略

跑 `tests/` 全量后，**任何**旧测试失败：

1. 暂停实现
2. 在 PR 中列出失败 case 与失败原因
3. 询问用户：(a) 断言需更新 (b) 行为升级到 MULTI_ADMIN 但断言未跟上 (c) 真实回归
4. 不主动改任何旧测试，不自行决定"等价升级"

---

## 11. 风险与未验证假设

1. **`_resolve_multi_admin_collision` 在 `_freeze_*` 触发的边界**：要求 freeze 时 MULTI_ADMIN 已在 `state.components`。需验证是否存在 deferred_chain 非空时调用 freeze 的中间态（理论上 freeze 仅在 admin VALUE 被非行政 KEY 吸收时触发，此时之前的 admin 链应已 commit）。

2. **`segment_state.direction = None` 副作用**：重置方向可能影响后续组件的逗号尾判断。已知对称 case 已验证；五个以上连续 admin 的复杂序列未系统验证。

3. **PROVINCE→DISTRICT 后继开放**：可能让以前被拒绝的序列通过，产生 false-positive。需监控旧测试。

4. **`_should_eager_split_duplicate_dual_admins` 返回 False 时**："北京北京"（无 KEY，无 anchor）保留为单个 MULTI_ADMIN，第二个静默丢弃。此行为是否符合预期需测试确认。

5. **`_DraftComponent.level` 的所有 clone / serialize 路径**：`_rebuild_component_derived_state` 中 occupancy 重建对 MULTI_ADMIN 的处理（必须按 `level` 元组遍历），以及就地降解后的重建正确性，需验证。

6. **`_SuspectEntry.level` 由 str 改 tuple 的迁移**：现有所有 `entry.level == "province"` 字符串比较点都需改写。漏改一处即为 latent bug。建议在 PR #1 完成 `_SuspectEntry` 升级后立刻 grep 全仓 `entry.level` 与 `\.level == ['"]` 排查。

7. **`_freeze_key_suspect_from_previous_key` 改写 `entry.key=""`**：影响下游 `_fixup_suspected_info` 的 trim token 计算与序列化结构。需对比新旧测试输出。

8. **canonical / same-entity 比较器**：MULTI_ADMIN 的 level overlap 语义需在阶段 7.5 调研后确认不破坏 restore 行为。

9. **EN 词典数据缺失**：Brooklyn / NYC boroughs / 主要美国 city-state dual entries 需补充。当前 plan 只描述代码路径，词典数据视为独立 PR。

---

## 12. PR 拆分建议

| PR | 阶段 | 范围 |
|----|------|------|
| #1 | 阶段 0 | 类型基建：MULTI_ADMIN / DISTRICT_CITY 枚举、`_DraftComponent.level` / `_SuspectEntry.level` 字段升级、`_commit` occupancy 改造、`_segment_admit` 后继逻辑、公共抽象上提 |
| #2 | 阶段 1 | value 多层落 MULTI_ADMIN：scanner dual-emit、词典补 + `_flush_chain_as_standalone` / `_flush_admin_key_chain` 多层 commit |
| #3 | 阶段 2 + 阶段 3 | KEY intersection + `_routed_key_clue` 重写 + `_resolve_multi_admin_collision` + DISTRICT_CITY 路由 |
| #4 | 阶段 4 | EN scanner 去重 + EnAddressStack 接 admin span（不含 EN 词典数据） |
| #5 | 阶段 5 + 阶段 6 | 下游适配（metadata / normalized_pii / canonical 比较）+ 清理 |
| #6 | 数据 | EN 词典补 Brooklyn / NYC boroughs / city-state dual entries |

每个 PR 包含对应新增测试；旧测试红灯停下问用户。
