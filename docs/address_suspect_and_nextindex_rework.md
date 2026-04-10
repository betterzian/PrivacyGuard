# AddressStack：suspect 延迟落地 + next_index 精确化 方案

> 针对 `privacyguard/infrastructure/pii/detector/stacks/address.py` 的两项调整：
> 1. suspect 从「run 末尾无脑 fixup」改为「事件驱动 + run 末尾统一落地」；
> 2. `run` 返回的 `next_index` 改为严格等于「最后被消费 clue 的下标 + 1」。
>
> 本文档只描述设计与实施计划，不改代码。实施时按 §6 顺序落地。

---

## 1. 现状诊断

### 1.1 suspect 的旧语义

- 主循环在 `_handle_address_clue` 的 **VALUE 分支**会把 admin VALUE clue 压进 `deferred_chain`；`_flush_chain` 有 KEY 分支把 `deferred_chain[:last_key_idx]` 原封不动挂到新 `_DraftComponent.raw_chain`；`_flush_chain_as_standalone` 把每个单 clue 写成 `raw_chain=[clue]`。
- 主循环结束后，`_run_with_clues` / `_run_with_sub_clues` 都**无条件**调 `_fixup_suspected_info`：
  - 对每个 component，按顺序扫 `_leading_admin_value_clues(raw_chain)`；
  - 若某层级已经在 `state.occupancy` 且占用者不是自己 → `broken=True`，后续 clue 全部降级；
  - 否则写入 `component.suspected`，并通过 `_recompute_text` 把 suspect 文本从 `value` 中剥离。
- 结果：只要链上出现过 admin VALUE，就会被**无条件落地**为 suspect，哪怕它实际上只是"普通文字"。

### 1.2 后置前瞻分支的副作用

`_handle_address_clue` VALUE 分支里 `_has_reasonable_successor_key` 命中后会把当前 admin VALUE **当作普通文字**重新入链，再让下游 KEY 吃掉（即「扑南京人西路」式链穿透）：

```python
_flush_chain(...)
state.deferred_chain.append(clue)      # ← 以"普通文字"身份进链
state.chain_left_anchor = clue.start
```

问题：这个 clue 明明已经被语义上"降级"为普通文字，`_fixup_suspected_info` 仍然会把它识别成 admin VALUE 并尝试写 suspect。

### 1.3 standalone admin 的自引用

`_flush_chain_as_standalone` 把单个 admin VALUE 写成 `raw_chain=[clue]`，`fixup` 又会把自己写进自己的 suspected（虽然 `_recompute_text` 会把空 value 回退到原值，结果看起来没崩，但语义上是错的，且在只看 metadata 时会看到自引用的 suspect）。

### 1.4 next_index 偏大

`_run_with_clues` 的循环里这些情况都会 `index += 1`：

| 位置 | 场景 |
|------|------|
| 770 | `clue.attr_type is None` |
| 775 | 吸收 digit clue（非 ADDRESS、可吸收） |
| 779 | 跨越 NAME / ORGANIZATION |
| 786 | ADDRESS LABEL clue |
| 790 | `clue.start < address_start`（起栈前跳过） |
| 769 | negative_clue 记录 negative_spans 后继续 |
| 804 | 正常 `_handle_address_clue` 之后 |

循环出口的 `index` 被直接塞给 `StackRun.next_index`。dispatcher（`parser.py:107`）随后调用 `_next_unconsumed_index(clues, current_run.next_index, consumed_ids)` 决定下一次起栈，于是**所有"扫过但没进 component.clue_ids"的 clue** 全部失去了再次作为 seed 的机会。

例：例 1 里 `run` 扫到北京后 break，但北京的 index **等于** break 时的 index，所以 dispatcher 的下一次起栈会从北京开始——这是对的。但是例如 "上海钟山路 非法噪声 123 小区" 这种情况下，run 在 123 被吸收、噪声被跳过后再 break，`next_index` 会跳到 break 处，而"123/噪声/小区"都被锁死。

---

## 2. 新的 suspect 语义

### 2.1 核心概念

> **suspect = 某个 component 在构造过程中，其链的"真正起点"位置上压入的 admin VALUE clue**。
>
> 后置前瞻分支压进来的 admin VALUE **不算 suspect**（它已经被判为普通文字）；standalone 产出的 admin VALUE **不算 suspect**（它本身就是一个独立 component，不需要自指）。

### 2.2 数据结构

- `_ParseState` 新增：
  ```python
  suspect_chain: list[Clue] = field(default_factory=list)
  ```
  只在"真正起点式"入链时同步写入；在"后置前瞻"分支入链时**不**写入。
- `_DraftComponent.raw_chain` 的语义从「链上 key 之前所有 admin VALUE」收窄为「链真正起点上的 admin VALUE 候选」。
- `_DraftComponent` 新增（可选，实现便利用）：
  ```python
  suspect_demoted: bool = False
  ```
  当 raw_chain 被事件清理触发截断时置 True，便于调试/断言。

### 2.3 入链规则

在 `_handle_address_clue` VALUE 分支里：

| 场景 | deferred_chain | suspect_chain |
|------|---------------|---------------|
| 起点入链（`state.components` 与 `state.deferred_chain` 都空 或 段首） | append | admin VALUE 同步 append |
| 链继续生长（链非空、顺序合法，正常顺序 admin VALUE 连续入链） | append | admin VALUE 同步 append |
| 后置前瞻分支（`_has_reasonable_successor_key == True`） | `_flush_chain` + append | **不** append |
| `_flush_chain_as_standalone` 出来的单 clue | —— | —— |

要点：
- "后置前瞻"分支会先 `_flush_chain(...)` 把前一条链结算；此时 `suspect_chain` 也需要**同步清空**。
- 之后只压 `deferred_chain`，`suspect_chain` 保持空。
- 非 admin VALUE clue（POI value 等）永远不进 `suspect_chain`。

### 2.4 flush 规则

#### 2.4.1 `_flush_chain` 有 KEY 分支

- 取 `raw_chain_clues = list(state.suspect_chain)`。
- **紧邻 KEY 同类型过滤**：如果 `raw_chain_clues` 末尾的 clue 的 `component_type` 与 `key_clue.component_type` 相同，把末尾那个 clue **pop 掉**。
  - 语义："KEY 紧邻的那个同层级 VALUE 是 KEY 的本体 value，不是 suspect"。
  - 只 pop 一个（不递归向前过滤）——这样可以在多 VALUE 同类型场景下仍然区分"前面的 suspect"和"被 KEY 消费的 value"。
  - 例 1："上海钟山路"，链=[上海(city), 路(road)]，suspect_chain=[上海]；KEY=路(road)。末尾 `上海.component_type=city ≠ road` → **不 pop** → raw_chain=[上海]。
  - 例 3："上海市"，链=[上海(city), 市(city)]，suspect_chain=[上海]；KEY=市(city)。末尾 `上海.component_type=city == city` → **pop** → raw_chain=[]。
  - 反例："北京天津市"，suspect_chain=[北京, 天津]；KEY=市(city)。末尾 `天津.component_type=city == city` → pop 天津 → raw_chain=[北京] → CITY{value:"北京天津"→剥离"北京"→"天津", suspect:{city:北京}}。
- 新建 `_DraftComponent` 时 `raw_chain = raw_chain_clues`（过滤后的结果）。
- 结尾清空 `deferred_chain` 与 `suspect_chain`。

> 这样做的后果：链中被链穿透的中间 KEY 不会出现在 raw_chain 里——本来 `_leading_admin_value_clues` 遇到 KEY 就 break，效果一样。

#### 2.4.2 `_flush_chain_as_standalone`

- 每个 standalone component 的 `raw_chain = []`（不再写 `[clue]`）。
- 结尾清空 `deferred_chain` 与 `suspect_chain`。

#### 2.4.3 其他 STOP / break 路径

所有最终会触发 run 结算的路径都要确保 `suspect_chain` 与 `deferred_chain` 同步清空（最保险的做法：`_flush_chain` 负责清空，所有 STOP 前都必须先调 `_flush_chain`，现有代码已经这么做）。

### 2.5 事件驱动的 suspect 夺占清理

每次 `_commit(state, component)` 之后，如果新 commit 的 component 的 `component_type` 是 SINGLE_OCCUPY（即 province / city / district / subdistrict / road / number），对**所有之前已 commit** 的 components 执行：

```
for prior in state.components[:-1]:
    for i, clue in enumerate(prior.raw_chain):
        if clue.component_type == new_component.component_type:
            # 位置 i 及之后全部清除（保留 §5.6 的 broken 传染）
            if i < len(prior.raw_chain):
                prior.raw_chain = prior.raw_chain[:i]
                prior.suspect_demoted = True
            break
```

语义：新组件夺占了该 admin 层级 → 前面 component 里从第一个同层级 clue 开始的**所有后续 suspect** 都被视为普通文字，截断丢弃。

> 为什么是"截断而不是只删一个"：按 `docs/address.md §5.6` 的 broken 传染规则——一旦链上某层级被外部夺走，其后的低层级 suspect 也失去"可信赖的链条"，一并降级。

### 2.6 run 末尾的 `_fixup_suspected_info` 简化

新职责只剩"把 raw_chain 里剩下的 admin VALUE 写成 suspected + 剥离 value"：

```python
def _fixup_suspected_info(state, raw_text):
    for component in state.components:
        if not component.raw_chain:
            continue
        suspected: dict[str, str] = {}
        for clue in component.raw_chain:
            level = clue.component_type
            if level is None or clue.role != ClueRole.VALUE:
                continue
            if level not in _ADMIN_TYPES:
                continue
            level_key = level.value
            if level_key not in suspected:
                suspected[level_key] = clue.text
        if not suspected:
            continue
        component.suspected = suspected
        component.value = _recompute_text(component, suspected, raw_text)
```

对比旧版的差异：
- **不再**查 `state.occupancy`（夺占判断已由 §2.5 事件驱动完成）；
- **不再**维护 `broken` 标志（截断已在事件驱动时完成）；
- standalone / POI 的 raw_chain 已经是空 → 天然跳过，不会自引用；
- 后置前瞻入链的 clue 没进 `suspect_chain` → 天然不参与落地。

---

## 3. 例子回放

### 3.1 例 1：`上海钟山路南京西小区北京`

clue 序列（`i` 为 index，仅示意）：

| i | 文本 | role / type |
|---|------|-------------|
| 0 | 上海 | VALUE city |
| 1 | 路   | KEY road |
| 2 | 南京 | VALUE city |
| 3 | 小区 | KEY poi |
| 4 | 北京 | VALUE city |

#### 步骤 1：commit ROAD

- i=0 上海：空链起点 → `deferred_chain=[上海]`, `suspect_chain=[上海]`
- i=1 路：KEY, road；`_segment_admit` 通过；`_chain_can_accept(上海→路)` 通过（gap ≤ 1 unit）→ 进链
- `deferred_chain=[上海,路]`, `suspect_chain=[上海]`
- 触发 `_flush_chain` 有 KEY 分支：
  - `last_key_idx=1`
  - `expand_start = chain_left_anchor = 上海.start`
  - `value_text = raw_text[上海.start:路.start] = "上海钟山"`
  - 产出 `ROAD{value:"上海钟山", key:"路", raw_chain:[上海], clue_ids:{上海.id, 路.id}}`
  - `_commit` 后：`occupancy={road}`；`state.components=[ROAD]`；调 `_maybe_demote_prior_suspects(ROAD)` → 之前没别的 component → no-op
  - 清空 `deferred_chain`, `suspect_chain`
  - `state.last_committed_clue_index = max(0,1) = 1`

#### 步骤 2：commit POI

- i=2 南京（VALUE city）：`state.components` 非空；`_segment_admit` 返回 False（road→city 反向，无逗号）；`_has_reasonable_successor_key(..., CITY, ...)` 往右找，命中 i=3 小区（POI，POI ∈ REACHABLE[CITY]）→ 走**后置前瞻分支**：
  - `_flush_chain`（空链，no-op）
  - `deferred_chain=[南京]`，**`suspect_chain` 保持空** ← 关键
  - `chain_left_anchor=南京.start`
- i=3 小区：KEY, poi；`_segment_admit`（road→poi 合法）通过；`_chain_can_accept` 通过 → 进链
- `deferred_chain=[南京,小区]`, `suspect_chain=[]`
- 触发 `_flush_chain` 有 KEY 分支：
  - `last_key_idx=1`
  - `expand_start=南京.start`
  - `value_text = raw_text[南京.start:小区.start] = "南京西"`
  - 产出 `POI{value:["南京西"], key:"小区", raw_chain:[], clue_ids:{南京.id, 小区.id}}`
  - `_commit` 后：`state.components=[ROAD, POI]`；调 `_maybe_demote_prior_suspects(POI)` → POI 不在 SINGLE_OCCUPY → no-op
  - `last_committed_clue_index = max(1,2,3) = 3`

#### 步骤 3：北京触发 STOP

- i=4 北京（VALUE city）：`state.components` 非空；`_segment_admit` False（poi→city 反向，且 city 当下**不在** occupancy）
- `_has_reasonable_successor_key(..., CITY, ...)` 往右找，没有 → 走"无合理后继 KEY"分支：
  - `_flush_chain`（空链，no-op）
  - `state.split_at = 北京.start`
  - `return _SENTINEL_STOP`
- 主循环 break；此时 `index=4`（未 ++）

#### 步骤 4：run 结束落地

- `_fixup_suspected_info`：
  - ROAD.raw_chain=[上海] → `suspected={city:"上海"}`，从 "上海钟山" 剥离第一个 "上海" → value="钟山"
  - POI.raw_chain=[] → 跳过
- 最终 components：
  - `ROAD{value:"钟山", key:"路", suspected:{city:"上海"}}`
  - `POI{value:["南京西"], key:"小区", suspected:{}}`
- `next_index = state.last_committed_clue_index + 1 = 3 + 1 = 4`（即北京的 index）✓

### 3.2 例 2：`浦东钟山路浦东西小区，浦东，上海`

clue 序列：

| i | 文本 | role / type |
|---|------|-------------|
| 0 | 浦东 | VALUE district |
| 1 | 路   | KEY road |
| 2 | 浦东 | VALUE district |
| 3 | 小区 | KEY poi |
| 4 | 浦东 | VALUE district |
| 5 | 上海 | VALUE city |

（i=3 与 i=4 之间有 `,`；i=4 与 i=5 之间有 `,`）

#### 步骤 1：commit ROAD

- i=0 浦东：起点 → `deferred_chain=[浦东0]`, `suspect_chain=[浦东0]`
- i=1 路：进链 → flush → `ROAD{value:"浦东钟山", raw_chain:[浦东0], ...}`
- `occupancy={road}`；清空两个 chain；`last_committed_clue_index=1`

#### 步骤 2：commit POI（浦东西）

- i=2 浦东（district VALUE）：后置前瞻（i=3 小区是 POI ∈ REACHABLE[district]）→ 后置前瞻分支：
  - `deferred_chain=[浦东2]`, `suspect_chain=[]`
- i=3 小区：进链 → flush → `POI{value:["浦东西"], raw_chain:[], ...}`
- `last_committed_clue_index=3`

#### 步骤 3：commit DISTRICT（第三个浦东，逗号逆序合法）

- i=4 浦东（district VALUE）：`state.components` 非空
- `_segment_admit`：
  - `gap_text = raw_text[poi.end:浦东4.start]` 含逗号 → `segment_state.reset()`
  - `district ∉ state.occupancy`（occupancy 是 {road, poi}）→ return True
- `_segment_admit` 已 admit，不走后置前瞻分支，进**正常 VALUE 入链**：
  - `deferred_chain=[浦东4]`, `suspect_chain=[浦东4]`
  - 注意：这是段首起点，算 suspect 候选 ✓（尽管最终会 standalone）

#### 步骤 4：commit CITY（上海）

- i=5 上海（city VALUE）：
- `_segment_admit`：
  - `gap_text` 含逗号 → `segment_state.reset()`
  - `city ∉ state.occupancy`（{road, poi}；district 还没提交）→ True
- 正常 VALUE 入链 → `deferred_chain=[浦东4, 上海]`, `suspect_chain=[浦东4, 上海]`

#### 步骤 5：到末尾，flush standalone

- `_flush_chain`：链里没有 KEY → 走 `_flush_chain_as_standalone`
- 对 `deferred_chain=[浦东4, 上海]` 逐个产出：
  - 浦东4：commit 为 `DISTRICT{value:"浦东", raw_chain:[]}`
    - `_maybe_demote_prior_suspects(DISTRICT)` → new_type=district ∈ SINGLE_OCCUPY
    - 遍历前面 components：
      - ROAD.raw_chain=[浦东0] → 发现 clue.component_type=district 命中 → 截断：`ROAD.raw_chain=[]`, `ROAD.suspect_demoted=True`
      - POI.raw_chain=[] → no-op
    - ROAD 的 suspect 被**事件驱动清除** ✓
  - 上海：commit 为 `CITY{value:"上海", raw_chain:[]}`
    - `_maybe_demote_prior_suspects(CITY)` → city 层级无匹配 → no-op
- `last_committed_clue_index = 5`

#### 步骤 6：run 末尾落地

- `_fixup_suspected_info`：
  - ROAD.raw_chain=[] → 跳过
  - POI.raw_chain=[] → 跳过
  - DISTRICT.raw_chain=[] → 跳过
  - CITY.raw_chain=[] → 跳过
- 最终 components：
  - `ROAD{value:"浦东钟山", key:"路", suspected:{}}`
  - `POI{value:["浦东西"], key:"小区", suspected:{}}`
  - `DISTRICT{value:"浦东", suspected:{}}`
  - `CITY{value:"上海", suspected:{}}`
- `next_index = 5 + 1 = 6`

与用户预期完全一致 ✓

### 3.3 例 3：`上海市浦东西康路`

clue 序列：

| i | 文本 | role / type |
|---|------|-------------|
| 0 | 上海 | VALUE city |
| 1 | 市   | KEY city |
| 2 | 浦东 | VALUE district |
| 3 | 路   | KEY road |

#### 步骤 1：commit CITY（上海市）

- i=0 上海（city VALUE）：空链起点
  - `deferred_chain=[(0,上海)]`, `suspect_chain=[(0,上海)]`
  - `chain_left_anchor=上海.start`
- i=1 市（city KEY）：
  - `state.components` 空，`_segment_admit` 通过
  - `_chain_can_accept(上海→市)`：gap ≤ 1 unit，且`ClueRole.VALUE`→`ClueRole.KEY` 满足条件 → True
  - 进链 → `deferred_chain=[(0,上海),(1,市)]`, `suspect_chain=[(0,上海)]`
- 触发 `_flush_chain` 有 KEY 分支：
  - `last_key_idx=1`, `key_clue=市`, `comp_type=city`
  - `raw_chain_clues = list(suspect_chain) = [上海]`
  - **紧邻 KEY 同类型过滤**：`raw_chain_clues[-1].component_type = city == key_clue.component_type = city` → **pop 末尾** → `raw_chain_clues = []`
  - `expand_start = chain_left_anchor = 上海.start`
  - `value_text = raw_text[上海.start:市.start] = "上海"`
  - 产出 `CITY{value:"上海", key:"市", raw_chain:[], clue_ids:{上海.id, 市.id}}`
  - `_commit` → `state.components=[CITY]`；`occupancy={city}`；`_maybe_demote_prior_suspects(CITY)` → 无前面 component → no-op
  - 清空 chain / suspect_chain
  - `last_committed_clue_index = 1`

#### 步骤 2：commit ROAD（浦东西康路）

- i=2 浦东（district VALUE）：
  - `state.components=[CITY]` 非空
  - `_segment_admit`：`segment_state.last_type=city`，`district ∈ REACHABLE[city]`，`district ∉ occupancy={city}` → True
  - `_segment_admit` 已 admit → 正常入链分支（不走后置前瞻）
  - `deferred_chain=[(2,浦东)]`, `suspect_chain=[(2,浦东)]`
  - `chain_left_anchor=浦东.start`
- i=3 路（road KEY）：
  - `_segment_admit`：`segment_state.last_type` 此时还是 city（未 reset），`road ∈ REACHABLE[city]`，`road ∉ occupancy` → True
    - 说明：`_segment_admit` 更新 `last_type` 是 `_commit` 做的，这里 VALUE 只是入 chain，last_type 仍为上一次 commit 时的 city。`_chain_can_accept` 负责 gap 判断。
  - 进链 → `deferred_chain=[(2,浦东),(3,路)]`, `suspect_chain=[(2,浦东)]`
- 触发 `_flush_chain` 有 KEY 分支：
  - `last_key_idx=1`, `key_clue=路`, `comp_type=road`
  - `raw_chain_clues = [浦东]`
  - **紧邻 KEY 同类型过滤**：`浦东.component_type=district ≠ road` → **不 pop** → `raw_chain_clues=[浦东]`
  - `expand_start=浦东.start`
  - `value_text = raw_text[浦东.start:路.start] = "浦东西康"`
  - 产出 `ROAD{value:"浦东西康", key:"路", raw_chain:[浦东], clue_ids:{浦东.id, 路.id}}`
  - `_commit` → `state.components=[CITY, ROAD]`；`occupancy={city, road}`；`_maybe_demote_prior_suspects(ROAD)` → CITY.raw_chain=[] → no-op
  - `last_committed_clue_index = 3`

#### 步骤 3：末尾，自然结束，落地

- 主循环 `index=4=len(clues)` → 正常退出
- `_flush_chain` 再次调用（空链，no-op）
- `_fixup_suspected_info`：
  - CITY.raw_chain=[] → 跳过
  - ROAD.raw_chain=[浦东] → `suspected={district:"浦东"}`，从 "浦东西康" 剥离第一个 "浦东" → value="西康"
- 最终 components：
  - `CITY{value:"上海", key:"市", suspected:{}}`
  - `ROAD{value:"西康", key:"路", suspected:{district:"浦东"}}`
- `next_index = 3 + 1 = 4`

与用户预期完全一致 ✓

> 关键验证：如果没有"紧邻 KEY 同类型过滤"规则，步骤 1 会把 CITY 的 raw_chain 落地为 `suspected={city:上海}`，然后剥离 "上海" → value="" → 回退到原值 "上海"，结果看起来"对"（value 对），但 metadata 会错误地挂上 `suspected:{city:上海}`——这正是例 3 要求修复的点。

---

## 4. next_index 精确化

### 4.1 追踪字段

```python
@dataclass(slots=True)
class _ParseState:
    ...
    last_committed_clue_index: int = -1
```

### 4.2 更新时机

- `_commit(state, component, *, clue_indices)` 新增关键字参数 `clue_indices: Iterable[int]`：
  - `state.last_committed_clue_index = max(state.last_committed_clue_index, *clue_indices)`
- 调用方要传入：
  - `_flush_chain` 有 KEY 分支：`clue_indices = [i for i in range(...)]`——由 `_flush_chain` 现在已经能拿到 `clues` 与 `clue_index`，把对应 clue 的 index 传进去（需要把 `deferred_chain` 里每个 clue 的原始 index 记下来，或者在 `_handle_address_clue` 的 VALUE/KEY 分支存 `(clue_index, clue)` 而不是只存 clue）。
  - `_flush_chain_as_standalone`：传入当前 standalone clue 的 index。
  - `_commit_poi` 的合并路径：原有 POI 被扩展时 `last_committed_clue_index` 也要推进到新 POI 的 clue index。
  - `_handle_address_clue` KEY 分支里直接构建的 `_build_key_component`：传 `clue_index`。

**实现建议**：最小改动是让 `deferred_chain` / `suspect_chain` 里存 `tuple[int, Clue]` 而不是裸 `Clue`，其它地方只要解包。这样 `_flush_chain` 里能直接拿到所有入链 clue 的 index。

### 4.3 digit_tail 补 clue_ids / index

`_analyze_digit_tail` 通过 `_find_clue_for_digit_run(clues, ..., clue_scan_index)` 能拿到对应的 `digit_run` clue 的 index。把结果扩展成：

```python
@dataclass
class DigitTailResult:
    ...
    consumed_clue_indices: list[int]  # 新增
```

- `followed_by_address_key=True` 路径：在 `_run_with_clues` 把 `tail.consumed_clue_indices` 并入 `state.last_committed_clue_index`（以及 `state.committed_clue_ids`——通过 `clues[i].clue_id`）。
- `followed_by_address_key=False` 路径：
  - conservative run 不消费 digit（last_committed_clue_index 不变）
  - extended run 消费 digit（在构造 `state_ext` 时把 index 推进到 digit clue index）
  - 这一路已经有两种 `next_index`，`PendingChallenge` 里的 `extended_next_index` 用 extended 的。

### 4.4 吸收 digit clue

`_run_with_clues` 里"可吸收 digit clue"路径：

```python
if _is_absorbable_digit_clue(clue):
    state.absorbed_digit_unit_end = max(...)
    state.last_committed_clue_index = max(state.last_committed_clue_index, index)  # 新增
    index += 1
    continue
```

理由：吸收的 digit 实际影响了当前候选的 unit range（gap anchor），算消费，避免下一轮重复扫描。

### 4.5 跨越 NAME / ORGANIZATION clue

```python
if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
    if _has_nearby_address_clue(...):
        state.absorbed_digit_unit_end = max(...)
        # 不更新 last_committed_clue_index，因为这些 clue 并未被当前 run 消费
        index += 1
        continue
```

判断：跨越的 NAME/ORG clue 不算 address run 的消费。下一轮 parser 可能由它们起新 run（事实上它们自己的 stack 会处理），所以 `next_index` 要回退到它们之前。**但注意** dispatcher 用的是 `_next_unconsumed_index`，它只根据 `consumed_ids` 跳过，而 address run 并没有把这些 clue 写入 `consumed_ids`——所以即使 `next_index` 跨过了它们，dispatcher 也能凭 `consumed_ids is empty` 再回头扫到它们？

实际上不行。看 `parser.py:107`：
```python
index = self._next_unconsumed_index(context.clues, current_run.next_index, consumed_ids) or len(context.clues)
```
它从 `current_run.next_index` **向右**找——永远不会回头。所以如果 `next_index` 跳过了 NAME/ORG clue，这些 clue 就永久失去作为 seed 的机会。

→ 结论：跨越的 NAME/ORG clue **必须**不推进 `last_committed_clue_index`，并且用户需求 2 的实现会自动修复这一现存 bug。

### 4.6 LABEL / attr_type is None / clue.start < address_start 路径

这些路径是"扫过但完全未消费"：

```python
if clue.attr_type is None:
    index += 1
    continue
if clue.role == ClueRole.LABEL:
    index += 1
    continue
if clue.start < address_start:
    index += 1
    continue
```

都**不**更新 `last_committed_clue_index`。

> 特例：起栈时的 label_seed（`handled_labels` 含 `self.clue.clue_id`）已经经由 `handled_label_clue_ids` 路径被 dispatcher 标记，不依赖 `next_index`——这条保留。

### 4.7 `_pop_components_overlapping_negative` 同步剔除

当 `negative_spans` 非空并从 `state.components` 里弹出某些 component 时，也要：

1. 从 `state.committed_clue_ids` 中移除被弹 component 的 `clue_ids`；
2. 重算 `state.last_committed_clue_index`：`max(committed_indices)`（如果全弹空则回到 -1）。

为此把 `_pop_components_overlapping_negative` 的返回类型改成 `tuple[list[_DraftComponent], set[str]]`——第二项是被删掉的 clue_id 集合，调用方按此同步剔除。

### 4.8 最终 next_index

`_build_address_run_from_state` 忽略参数 `next_index`，改为：

```python
next_index_final = state.last_committed_clue_index + 1 if state.last_committed_clue_index >= 0 else self.clue_index + 1
```

- `>= 0`：已经 commit 过东西，按 committed 后一个；
- `< 0`（没 commit 过但上层仍然进入了 `_build_address_run_from_state`）：不会发生，因为上层在 `not state.components` 时已经 return None。保留 fallback 只是为了防崩。

`_run_with_sub_clues` 走 HARD 路径，原本传的是 `self.clue_index + 1`——这条**不改**（HARD clue 的下一次起栈语义本来就是"HARD 之后"）。

---

## 5. 现有代码改动点清单

### 5.1 `_ParseState`（约 162 行附近）

```python
@dataclass(slots=True)
class _ParseState:
    ...
    suspect_chain: list[tuple[int, Clue]] = field(default_factory=list)  # (index, clue)
    deferred_chain: list[tuple[int, Clue]] = field(default_factory=list)  # 同上，把裸 Clue 换成 (index, Clue)
    last_committed_clue_index: int = -1
```

（或者保留 `list[Clue]`，另外引入 `deferred_chain_indices: list[int]` 平行维护。两种都行，按代码整洁度选。）

### 5.2 `_handle_address_clue` VALUE 分支

- 原本的 `state.deferred_chain.append(clue)` 全部替换成 `_append_value(state, index, clue, *, is_suspect: bool)`：
  - 正常入链：`is_suspect = (clue.role == ClueRole.VALUE and clue.component_type in _ADMIN_TYPES)`
  - 后置前瞻分支：`is_suspect = False`
- KEY 分支里的 `state.deferred_chain.append(clue)`（950 行附近）也同理——KEY 进链不算 suspect 候选（KEY 本身不是 admin VALUE）。

### 5.3 `_flush_chain`

- `raw_chain_clues = list(state.suspect_chain)` 取代现有的 `list(state.deferred_chain[:last_key_idx])`
- 产出 `_DraftComponent` 时传 `raw_chain=raw_chain_clues`（注意此时 raw_chain 的元素要么统一为 `Clue`，要么统一为 `(index, clue)` 的 tuple——接口需要一致）
- 最后 `state.suspect_chain.clear()` + `state.deferred_chain.clear()`
- `_commit` 调用时传 `clue_indices=[i for i, _ in deferred_chain[:last_key_idx+1]]`

### 5.4 `_flush_chain_as_standalone`

- 每个 component 的 `raw_chain=[]`
- 结尾清空 `suspect_chain` 与 `deferred_chain`
- `_commit` 调用时传 `clue_indices=[i]`（当前 standalone clue 的 index）

### 5.5 `_commit`

```python
def _commit(state, component, *, clue_indices: list[int]) -> None:
    ...
    # 原有逻辑
    state.committed_clue_ids |= component.clue_ids
    state.last_committed_clue_index = max(
        state.last_committed_clue_index, *clue_indices
    )
    _maybe_demote_prior_suspects(state, component)
```

### 5.6 新增 `_maybe_demote_prior_suspects`

```python
def _maybe_demote_prior_suspects(state: _ParseState, new_component: _DraftComponent) -> None:
    new_type = new_component.component_type
    if new_type not in SINGLE_OCCUPY:
        return
    for prior in state.components[:-1]:
        if not prior.raw_chain:
            continue
        cut_at: int | None = None
        for i, clue in enumerate(prior.raw_chain):
            if clue.component_type == new_type:
                cut_at = i
                break
        if cut_at is not None:
            prior.raw_chain = prior.raw_chain[:cut_at]
            prior.suspect_demoted = True
```

### 5.7 `_fixup_suspected_info` 简化（见 §2.6）

### 5.8 `_run_with_clues` 循环内各分支

- 吸收 digit clue：`state.last_committed_clue_index = max(..., index)`
- NAME/ORG 跨越：**不**更新
- LABEL / attr_type None / start<address_start：**不**更新
- negative_clue 记录 span：**不**更新
- `_handle_address_clue` 返回非 STOP 后、`index += 1` 前：**不**主动更新（由 `_commit` 统一负责）

### 5.9 `_pop_components_overlapping_negative`

- 返回 `(kept, removed_clue_ids)`；调用方：
  ```python
  state.components, removed_ids = _pop_components_overlapping_negative(...)
  state.committed_clue_ids -= removed_ids
  # 重算 last_committed_clue_index
  if state.committed_clue_ids:
      state.last_committed_clue_index = max(
          idx for idx, c in enumerate(clues) if c.clue_id in state.committed_clue_ids
      )
  else:
      state.last_committed_clue_index = -1
  ```

### 5.10 `_build_address_run_from_state`

- 把 `next_index: int` 参数保留签名但内部用 `state.last_committed_clue_index + 1`（fallback 到传入值）。

### 5.11 `_analyze_digit_tail` / `DigitTailResult`

- 新增 `consumed_clue_indices: list[int]`；来自 `_find_clue_for_digit_run` 的命中 index。
- 调用方按 `followed_by_address_key` 决定是否把它们并入 `last_committed_clue_index`。
- `digit_tail` 产生的新 component 写入 `clue_ids = {clues[i].clue_id for i in consumed_clue_indices}`。

---

## 6. 实施步骤（建议落地顺序）

| 步骤 | 内容 | 影响面 | 可独立验证 |
|------|------|--------|-----------|
| S1 | `_ParseState` 增 `suspect_chain` / `last_committed_clue_index`；`_DraftComponent` 增 `suspect_demoted` | 类型 | ✗（无行为变化） |
| S2 | `deferred_chain` 改为 `list[tuple[int, Clue]]`（或平行索引）；`_handle_address_clue` 全部入链点适配 | 主循环 | 跑一遍现有测试，不应该有差异（等价重构） |
| S3 | 正常入链点同步写 `suspect_chain`；后置前瞻点**不**写 | 主循环 | 跑一遍测试：应该只影响 `_fixup_suspected_info` 的输入 |
| S4 | `_flush_chain` / `_flush_chain_as_standalone` 改为从 `suspect_chain` 取 raw_chain | 结算 | 跑测试：此时现有 fixup 仍然运行，结果会变少（少了后置前瞻的 suspect） |
| S5 | 新增 `_maybe_demote_prior_suspects`，在 `_commit` 尾部调用 | 结算 | 跑测试：例 2 类案例行为改变 |
| S6 | `_fixup_suspected_info` 简化 | 结算 | 跑测试 |
| S7 | `_commit` 追踪 `last_committed_clue_index`；`_build_address_run_from_state` 用新 next_index | dispatcher | 跑测试：某些"被锁死的 clue"现在会被 dispatcher 再起 seed |
| S8 | digit_tail 补 consumed_clue_indices + clue_ids | digit_tail | 跑 digit_tail 相关测试 |
| S9 | `_pop_components_overlapping_negative` 同步剔除 | negative 路径 | 跑 negative 相关测试 |

每一步独立提交 + 独立跑测试，方便定位回归。

---

## 7. 已知风险 / 待验证 / 非本次范围

1. **测试预期大调整**：`tests/test_address_stack.py` 里对 "南京中山路"、"南京浦东中山路" 之类的断言大概率会变——旧版把 `南京` 默认写到 `suspected.city`，新版在没有后续冲突时 value 保留完整，suspected 为空。需要用户明确这些 case 的新预期。
2. **canonical 比较回归**：`normalized_pii.py::_compare_component_with_suspected` 依赖 suspected 字段做子集比对。新版 suspected 变少后，某些原本靠 suspected 对齐的跨省份比对会 FAIL。**这次方案不改 canonical 侧**；若需要同步修改，请在新一轮里追加。
3. **`suspect_chain` 在 segment 重置点的行为**：逗号分段后，前一段的 suspect_chain 已经被 `_flush_chain` 清空，所以逗号后的 admin VALUE 会重新作为段首起点进入 `suspect_chain`（见例 2 步骤 3）。这符合用户例子，但如果用户期望的是"段首 admin 也不算 suspect（因为有逗号分段保护）"，则需要再加条件判断。**默认按例 2 的行为实现**。
4. **链穿透多 KEY 场景（`科技园社区小区`）**：新 raw_chain 只存 `suspect_chain` 里的 admin VALUE，`科技园` 是 POI VALUE → 不进 suspect_chain → POI 的 raw_chain 空。不影响 `_leading_admin_value_clues` 的结果（本来也没 admin）。
5. **HARD sub-tokenize 路径**：`_run_with_sub_clues` 使用 `sub_clues`，其 clue_id 以 `sub_` 前缀生成，不在外层 `self.context.clues` 序列里——对应的 `last_committed_clue_index` 没法直接用于 dispatcher。这条路径的 `next_index` 目前是 `self.clue_index + 1`，**保持不变**。
6. **`_is_absorbable_digit_clue` 吸收后再碰到 digit_tail**：如果同一个 digit clue 先在主循环被吸收（§4.4），再在 digit_tail 被再次扩展成 component，会不会双重推进 `last_committed_clue_index`？不会，因为 `max` 是幂等的；但要确保 digit_tail 不会跨到已经消费过的 digit。留待实施时校对。
7. **`_recompute_text` 保留原有行为**：只按 suspected 的 values 从 value 中剥离首次出现的子串——新版 suspected 更少 → 剥离更少 → value 更长。这是预期的。

---

## 8. 对照用户需求的验收清单

- [x] 单个组件被 flush 时不对 suspect 里面的元素落地（§2.4、§2.6，raw_chain 进 component 只是"挂着"，落地在 run 末尾且仅对未被事件清理的 clue 生效）
- [x] 后面出现同类型元素时对之前组件里的 suspect 进行清除（§2.5 `_maybe_demote_prior_suspects`，例 2 验证）
- [x] 后置前瞻入链的 admin VALUE 不算 suspect（§2.3，例 1 验证）
- [x] 紧邻 KEY 且与 KEY 同类型的 admin VALUE 不算 suspect（§2.4.1 紧邻过滤，例 3 验证）
- [x] run 最后提交的 index 是消费的最后一个 clue 后一个 clue 的 index（§4.1-§4.8，例 1/例 2/例 3 验证）

