# 地址 Stack 设计与实施规划

> 本文是 `privacyguard/infrastructure/pii/detector/stacks/address.py` 的算法规范与落地分阶段计划。
> CLAUDE.md 视当前为开发版，**不做**兼容层。

---

## 1. 设计目标

1. **机制统一**：HARD/SOFT、POI/非 POI、正向/逆向走同一套 clue 状态机。
2. **链式吸收泛化**：把"延迟提交"机制覆盖所有 KEY 类型（不仅是 POI）。
3. **逗号分段 + 占位数组**：用 occupancy 显式管理"单占位类型"，逗号分段 + 段内严格正向。
4. **疑似信息**：给残留的 admin VALUE 一个降级路径（chain-break + occupancy fixup）。
5. **POI 列表化**：POI 一个地址内允许多个，提交时丢 key 留 value 数组。
6. **canonical 早退 + 子集 fallback**：层级早退 + suspected 三段 fallback + POI 子集匹配。

---

## 2. 核心概念

### 2.1 单占位类型（single-occupy）

`AddressComponentType` 中以下类型在**同一个地址实例**内最多出现一次：

```
PROVINCE, CITY, DISTRICT, SUBDISTRICT, ROAD, NUMBER
```

POI 不在此列（一个地址内允许多个 POI 元素）。BUILDING / DETAIL 同样不限制。

> 同占位再次出现 → 触发**地址边界切分**（详见 §5.5）。

### 2.2 occupancy 数组

```python
occupancy: dict[AddressComponentType, ComponentRef]
```

- key 为单占位类型；value 为已写入的 component 引用。
- 由 main loop 实时维护；fixup pass 中作为只读快照使用。
- **suspected 信息不占用 occupancy 槽位**。suspected 仅记录被链式吸收后降级的行政层级信息，不影响 occupancy 的判定。同一链内出现两个相同 admin 层级（如"上海北京中山路"两个 city）时，先到者写入 suspected，后到者降级为普通文本（留在 value 中）。

### 2.3 unit 与 1-unit gap

- "unit" 沿用 `stream.units` 的切分：CJK 单字、`digit_run`、`alpha_run`、空白等各为一个 unit。
- "1-unit gap" 指两个 clue 之间最多隔一个有效 unit（空白不计）；`gap == 1 unit` 仍判为同一组。
- 链式吸收（§5.3）以此为粘合阈值。

### 2.4 deferred_chain

通用链式缓冲，覆盖所有可被下游 KEY 吞噬的 VALUE / KEY clue：

```python
deferred_chain: list[Clue]   # 按出现顺序保存待吸收的 VALUE/KEY clue
chain_left_anchor: int       # 链最左 char 位置（fixup 取 value 文本用）
```

### 2.5 suspected 信息

draft component 上挂载：

```python
component.raw_chain: list[Clue]      # 起栈到 KEY 之间所有的 admin VALUE clue（含被吞噬的）
component.suspected: dict[str, str]  # fixup 后产物：level -> value
```

`raw_chain` 在主循环中挂上去；`suspected` 在 fixup pass 中根据最终 occupancy 计算。

### 2.6 comma-segment

- 整个 stack run 按 `,` / `，` 切成若干段。
- **段内严格正向**（按后继图 forward）。
- **段间允许"层级回跳"**，但每个新组件仍受 occupancy 单占位约束。

---

## 3. 主流程伪代码

```text
function run():
    if clue.strength == HARD:
        sub_clues = sub_tokenize(clue.span)        # §4
        return run_with_clues(sub_clues, mode='hard_local')

    return run_with_clues(self.context.clues, mode='normal')


function run_with_clues(clues, mode):
    state = ParseState(
        components=[],            # draft component
        occupancy={},
        deferred_chain=[],
        chain_left_anchor=None,
        segment_state=ForwardSegmentState(),
        last_consumed=None,
        last_value=None,
        evidence_count=0,
    )

    seed = pick_seed(clues, mode)
    if seed is None:
        return None

    cursor = seed.index
    while cursor < len(clues):
        clue = clues[cursor]

        if is_break_or_negative(clue) or attr_type_breaks(clue):
            break

        if clue.attr_type == ADDRESS:
            handle_address_clue(state, clue, cursor)
        elif is_absorbable_digit(clue):
            absorb_digit(state, clue)
        else:
            break

        cursor += 1

    if state.deferred_chain:
        flush_chain_as_standalone(state)            # §5.3

    if not state.components:
        return None

    fixup_suspected_info(state)                     # §5.6
    components = run_digit_tail(state, clues, cursor)
    return build_stack_run(state, components, cursor)
```

### 3.1 handle_address_clue 主分支

```text
function handle_address_clue(state, clue, index):
    comp_type = clue.component_type
    if comp_type is None:
        return

    # NUMBER 上下文重映射
    comp_type = remap_number_in_context(comp_type, state.last_component_type)

    # ---- 段内/段间转移 ----
    if not segment_admit(state, clue, comp_type):
        # occupancy 冲突或段内反向 → 视作新地址边界
        state.split_at = clue.start
        return STOP

    # ---- 链式吸收（KEY 触发）----
    if clue.role == KEY:
        if can_consume_chain(state, clue):
            component = build_chain_component(state, clue, comp_type)
            commit(state, component, raw_chain=state.deferred_chain[:])
            state.deferred_chain.clear()
            return
        else:
            flush_chain_as_standalone(state)
            component = build_key_component(state, clue, comp_type)
            commit(state, component, raw_chain=[])
            return

    # ---- VALUE clue ----
    if clue.role == VALUE:
        # value 加入链：之后看是否被 KEY 吸收
        state.deferred_chain.append(clue)
        if state.chain_left_anchor is None:
            state.chain_left_anchor = clue.start
        state.last_value = clue
        return
```

### 3.2 起栈方向

- **不会**从 KEY 起栈跑到左侧扫 VALUE；当左侧已有 VALUE clue，**起栈一定落在最左的 VALUE 上**。
- 这意味着 "南京浦东中山路" 的 stack run 起点是 `南京`，不是 `路`。
- VALUE 起栈后向右扫描，链式收集，遇到 KEY 时结算或遇到 break / 6-unit gap 时 standalone。

---

## 4. HARD clue 子分词

```text
function sub_tokenize(span):
    text = stream.text[span.start:span.end]
    sub_clues = scan_lexicon_in_window(text, span.start, [zh_address_keywords, en_address_keywords])
    if not sub_clues:
        # 退化：把整段当作单一 component
        return [synthetic_value_clue(span, default_type=POI)]
    return sub_clues
```

- 词典扫描局部覆盖 span 区间，产出和正常解析一样的 KEY / VALUE clue。
- 子 clue 走与 SOFT 同一条 `run_with_clues` 路径（mode='hard_local'）。
- mode='hard_local' 下：
  - 6-unit gap 检查仍生效（防 OCR 噪声）。
  - **不允许**越出 HARD span 范围：cursor 命中 span 外 clue 即停。
  - HARD span 至少需要产出一个 component；若 sub_tokenize 后什么都没产出，回退用 span 文本当一个 fallback POI（保留 HARD recall）。

---

## 5. 关键规则细化

### 5.1 起栈与左扩展

`build_key_component` / `build_chain_component` 中，从 key.start 向左扩展取 value 文本：

| 语言 | 规则 |
|------|------|
| 中文 | 最多向左扩 **2 个 unit**；若链上有更左的 VALUE clue，则扩到链的最左 anchor。 |
| 英文 | 向左扩到最近的一个 `digit_run` unit（如有），否则扩到上一个英文 token 边界。 |

### 5.2 链式吸收

链上的 clue 满足以下条件即可"粘合"：

- 相邻或 gap ≤ 1 unit（**含**正好 1 unit 的情况）
- 中间没有 break / negative / 非 ADDRESS clue（可吸收 digit clue 除外）
- 没有"已经被 commit 的 KEY component"截断

`can_consume_chain(state, key_clue)` 返回 True 当：

```
state.deferred_chain 非空
AND deferred_chain[-1] 与 key_clue 的 gap ≤ 1 unit
AND key_clue.component_type ∈ POI_COMBINABLE_TYPES ∪ {POI 自身}
```

`build_chain_component`：

```text
expand_start = state.chain_left_anchor
value_text = stream.text[expand_start : key_clue.start]
value = normalize_address_value(comp_type, value_text)
component = {
    type: comp_type,
    start: expand_start,
    end: key_clue.end,
    value: value,
    key: key_clue.text,
    raw_chain: state.deferred_chain[:],   # 给 fixup pass 用
}
```

#### 链上多 KEY 穿透

`扑南京人西路` → 西路 是 ROAD KEY，链 = `[南京 (city VALUE)]`，左 anchor = `扑`（非 clue，但被 left-expand 吸收）。

`科技园社区小区` → 链 = `[科技园 (POI VALUE), 社区 (SUBDISTRICT KEY)]` → 当遇到 `小区 (POI KEY)` 且 gap ≤ 1 unit 时：
- 穿透中间 KEY `社区`：丢弃其 component_type 但**保留它的文字**在 value 中。
- 中间 KEY 不写 occupancy（它已被吞噬，不算独立组件）。
- 最终 component = POI{value=`科技园社区`, key=`小区`}。

### 5.3 VALUE 起栈的 standalone 化

VALUE clue 进入 `deferred_chain` 后，**有以下任一条件**则结算为 standalone：

1. 后续遇到 break / negative / 非 ADDRESS clue → flush 整条链为 standalone（按各自原层级）。
2. 6-unit gap 内未出现新的 ADDRESS clue → 同上。
3. 遇到 KEY 但 `can_consume_chain` 失败 → 同上。
4. 链上 VALUE 之间 gap > 1 unit → 在断点处把链一切两段，前段 standalone，后段继续。

> "上海浦东balabala"（balabala 内无 clue）的处理：
> - 上海 (city VALUE) 入链。
> - 浦东 (district VALUE) 入链，gap ≤ 1 unit。
> - 6 unit 后无 clue → flush。
> - flush 时按链顺序逐个 commit standalone：上海 → CITY，浦东 → DISTRICT。
> - occupancy 同步写入 {CITY, DISTRICT}。

#### flush_chain_as_standalone 算法

```text
function flush_chain_as_standalone(state):
    for clue in state.deferred_chain:
        comp_type = clue.component_type
        # 单占位冲突 → 切分新地址
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            state.split_at = clue.start
            break
        component = build_standalone_component(clue, comp_type)
        commit(state, component, raw_chain=[clue])
    state.deferred_chain.clear()
    state.chain_left_anchor = None
```

> 注意：standalone 化的 admin VALUE 也会带 `raw_chain=[self]`，方便 fixup pass 统一处理（实际不会被降级，因为它本身就是 occupancy 的来源）。

### 5.4 comma-segment + occupancy

```text
class ForwardSegmentState:
    last_type: AddressComponentType | None
    in_segment: bool

function segment_admit(state, clue, comp_type):
    gap_text = raw_text[state.last_end : clue.start]
    has_comma = ',' in gap_text or '，' in gap_text

    if has_comma:
        state.segment_state.reset()  # 新段：last_type 清空
        # 单占位冲突 → 仍然不允许（同一地址内）
        if comp_type in SINGLE_OCCUPY and comp_type in state.occupancy:
            return False  # 触发地址切分
        return True

    # 无逗号 → 段内严格正向
    if state.segment_state.last_type is None:
        return True
    if comp_type in REACHABLE[state.segment_state.last_type]:
        return True
    return False
```

#### segment 与 occupancy 的边界

- 段内严格 forward；段间任意 forward；都受 occupancy 单占位约束。
- 单占位冲突 → 视为新地址，把 cursor 停在冲突 clue 上，外层 dispatcher 再次起栈。
- `segment_state.last_type` 在 commit 时同步更新为 component 的类型。

#### 场景对照表

| 输入 | seg1 | seg2 | seg3 | 结果 |
|------|------|------|------|------|
| 南京中路，上海浦东 | road | city→district | - | ✓ |
| 南京中路，浦东，上海 | road | district | city | ✓ |
| 南京中路，上海浦东，中国 | road | city→district | province | ✓ |
| 南京中路，浦东上海中国 | road | (district→city 反向) | - | ✗ 段内反向 |
| 南京中路，浦东上海，天元西路 | road | (district→city 反向 / road 已占) | - | ✗ |

### 5.5 地址边界切分

当出现以下情况时切分：

1. 单占位类型再次写入。
2. break / negative clue 命中。
3. 6-unit gap 触发（仅截断当前 run，不一定开新地址）。

切分行为：

- 当前 run 在冲突点之前结算。
- `next_index` 指向冲突 clue 的位置，外层 `dispatch` 用它作为下一个 run 的 seed。
- 不在 stack 内部强行 spawn 第二个 run。

### 5.6 fixup_suspected_info

> fixup 是独立函数，主循环只挂 `raw_chain`，不计算 suspected。

```text
function fixup_suspected_info(state):
    occupancy_levels = {comp.type for comp in state.components if comp.type in SINGLE_OCCUPY}

    for component in state.components:
        admin_clues = leading_admin_value_clues(component.raw_chain)
        if not admin_clues:
            continue

        suspected = {}
        broken = False
        demoted_chars = []

        for clue in admin_clues:
            level = clue.component_type
            if broken:
                demoted_chars.append(clue.text)
                continue
            if level in occupancy_levels and state.occupancy[level] is not component:
                broken = True
                demoted_chars.append(clue.text)
                continue
            # survive
            suspected[level.value] = clue.text

        component.suspected = suspected
        if demoted_chars or suspected:
            component.value = recompute_text(component, suspected)
        # recompute_text 规则：
        #   - suspected 中的 clue 文本从 component.value 中删除
        #   - 被降级的 clue 文本保留在 component.value 中（不动）
```

#### 关键规则

- `leading_admin_value_clues` 只取 component **自身的** raw_chain 上 KEY 之前的 admin VALUE clue。
- "降级"指 clue 自身的层级槽位已被 occupancy 占用，且占位者不是当前 component。
- 一旦某个 clue 被降级 → 后续链上 clue 全部降级（不再写 suspected）。
- **同层级去重**：同一链内出现两个相同 admin 层级时，先到者写入 suspected，后到者降级为普通文本（不写 suspected、不触发 broken）。
- `recompute_text` 把 surviving suspected 的文字从 component.value 中删除（按 char 区间），让 value 只包含残留 + 真正的核心文字。

#### 用例对照

| 输入 | occupancy | suspected | text |
|------|-----------|-----------|------|
| 南京浦东中山路 | {road} | city=南京, district=浦东 | 中山 |
| 南京浦东中山路 | {road, district} | city=南京 | 浦东中山 |
| 南京浦东中山路 | {road, city} | {} | 南京浦东中山 |
| 南京浦东中山路 | {road, city, district} | {} | 南京浦东中山 |
| 南京科技园路 | {road} | city=南京 | 科技园 |
| 浦东科技园路 | {road} | district=浦东 | 科技园 |
| 浦东科技园路 | {road, city} | district=浦东 | 科技园 |
| 浦东科技园路 | {road, district} | {} | 浦东科技园 |

### 5.7 POI 列表化

#### 数据模型

`AddressComponent` 上 POI 字段语义：

```python
poi: list[str]   # 可空 list
```

#### 解析流程

POI clue 仍然走 §3.1 的链式吸收，但 commit 时合并到一个 list：

```text
function commit_poi(state, component):
    if state.components 中已有 POI 且 component 是 POI：
        # POI 不受单占位约束 → 直接 append
        existing_poi.values.append(component.value)
        existing_poi.keys.append(component.key)   # 仅 debug 用
    else:
        state.components.append(component)
```

提交到 normalized_pii 时：

```python
poi_value = [c.value for c in poi_components]
metadata["address_poi_keys"] = [c.key for c in poi_components]   # debug only
```

#### 拆链规则

POI 链段的拆点仍按 §5.2 的 1-unit 阈值，但 §5.5 的"单占位冲突"对 POI 不触发切分。

#### 用例

`携程阳光社区小区里的住宅楼`：

- 链 1：携程阳光 → 社区(SUBDISTRICT) → 小区(POI)，gap ≤ 1 unit
  - 注意：社区是 SUBDISTRICT key，但被 §5.2 链穿透；最终 component_type 来自最右 KEY = POI(小区)
  - value = `携程阳光社区`
- "里的" → 非 clue 文字，距 小区.end gap > 1 unit → 链断
- 链 2：里的住宅 → 楼(POI)
  - value = `里的住宅`
- 提交：POI list = `["携程阳光社区", "里的住宅"]`

> 这里 SUBDISTRICT 被穿透，是否要给 occupancy 写入 SUBDISTRICT？
> 决议：**不写**。穿透的中间 KEY 既不算独立组件，也不占位。

---

## 6. canonical 比较

### 6.1 比较顺序

```
province → city → district → road → numbers → subdistrict → poi
```

任一双方都有的层级失败 → 立即返回 false。

### 6.2 单 component 类型（province/city/district/road/subdistrict）

```text
function compare_single(left, right, level):
    if level not in left.identity and level not in right.identity:
        return CONTINUE
    if level not in left.identity or level not in right.identity:
        return CONTINUE   # 单边缺失不否决
    return compare_component_with_suspected(left[level], right[level])
```

### 6.3 含 suspected 的组件比较

```text
function compare_component_with_suspected(A, B):
    # 1. 当前层级的 identity 文本必须互为子集
    if not subset_either(A.text, B.text):
        return FAIL

    a_susp = A.suspected or {}
    b_susp = B.suspected or {}
    if not a_susp and not b_susp:
        return PASS

    # 2. 对 A 每条 suspected（level -> a_val），按顺序尝试：
    for level, a_val in a_susp.items():
        if level in b_susp:
            if a_val == b_susp[level]:
                return PASS
            return FAIL   # 双方 suspected 同级 key 均存在但值不一致 → 冲突
        if a_val in B.text:
            return PASS
        if level in B.components and subset_either(a_val, B.components[level]):
            return PASS

    # 3. 对 B 每条 suspected 同理（反向）
    for level, b_val in b_susp.items():
        if level in a_susp:
            if b_val == a_susp[level]:
                return PASS
            return FAIL
        if b_val in A.text:
            return PASS
        if level in A.components and subset_either(b_val, A.components[level]):
            return PASS

    return FAIL
```

> 决议：OR 链按序尝试；任一步满足即 PASS；双方 suspected 同级 key 值不一致则 FAIL；全部尝试结束仍未 PASS 则 **FAIL**（不再默认通过）。

### 6.4 numbers

keyed-numbers 优先 → 失败 fallback 到 reversed-subsequence 匹配。
BUILDING/DETAIL 走 numbers 序列；"NUMBER" 单占位类型也接入 keyed numbers。

### 6.5 POI 列表比较

```text
function compare_poi_list(A, B):
    if not A and not B:
        return CONTINUE
    if not A or not B:
        return CONTINUE
    for a, a_key in zip(A.values, A.last_keys):   # last_keys 与 value 同序，来自 trace
        a' = strip_suffix_if_endswith(a, a_key)    # 仅去掉「最后一个 key」，不剥穿透在中间的 key
        for b, b_key in zip(B.values, B.last_keys):
            b' = strip_suffix_if_endswith(b, b_key)
            if subset_either(a', b') and min(len(a'), len(b')) >= MIN_POI_LEN:
                return PASS
    return FAIL
```

- **strip_suffix_if_endswith**：仅当 `a` 以 `a_key` 结尾时去掉该后缀；不得用「广场 / 小区 / Plaza」等通用类别词表批量剥词（否则会把链上已穿透的中间 key 误剥掉）。
- `MIN_POI_LEN`：中文 ≥ 2 字符，英文 ≥ 4 字符（防止"中心"这种短词误匹配）。（实现侧可暂统一阈值，以代码为准。）

---

## 7. 数据结构与下游变更

### 7.1 `AddressComponent`（infrastructure/pii/address/types.py）

```python
@dataclass
class AddressComponent:
    component_type: AddressComponentType
    start: int
    end: int
    value: str | list[str]              # POI 时为 list
    key: str | list[str]                # POI 时为 list（debug）
    is_detail: bool
    raw_chain: list[Clue] = field(default_factory=list)   # 主循环填充
    suspected: dict[str, str] = field(default_factory=dict)  # fixup 填充
```

### 7.2 `normalized_pii.py`

- `_normalize_address`：识别 POI 是 list，分别 normalize 每个元素。
- `_address_components`：POI 字段输出 list。
- **suspected**：metadata 使用 `address_component_suspected`（与 detector 组件顺序一一对应，每项为 `level:value` 用 `;` 拼接，无则空串）；归一结果为 `NormalizedPII.component_suspected: tuple[dict[str, str], ...]`，并合并得到 `suspected` 供兼容与 `same_entity`。
- 旧数据仅有 `address_suspected_trace`（扁平）时仍解析为 `suspected`，`component_suspected` 为空。
- `_same_address`：按 §6 重写。
- `_KEYED_NUMBER_TYPES`：保持含 `"number"`。
- 新增 `_compare_component_with_suspected` helper。

### 7.3 `schemas.py`

- `AddressLevel.POI` 的存储类型从 `Optional[str]` 改 `list[str]`。
- `AddressLevelExposureStats` 的 POI 计数语义改：以"地址内 POI 元素总数"统计。
- DB schema 不变（POI 仍存 JSON），但反序列化器需要兼容旧数据 → 决议**不做**兼容，需要 migration 脚本统一改写。

### 7.4 `pii_value.py` / `lexicon_loader.py`

- `_en_address_unit_prefixes()`：DETAIL 类型不变。
- `_en_address_street_suffixes()`：ROAD 类型不变。
- 无破坏性改动。

---

## 8. 实施计划（分 PR）

| PR | 主题 | 涉及文件 | 风险 |
|----|------|----------|------|
| **PR1** | occupancy 数组 + comma-segment | `address.py` 主循环；`segment_admit` 抽出 | 中：替换 `_TRAILING_ADMIN_TYPES` 全部逻辑 |
| **PR2** | deferred_chain 泛化（含 §5.1 / §5.2） | `address.py` 链式吸收逻辑 | 中：影响所有 POI 组合用例 |
| **PR3** | VALUE 起栈 standalone 化（§5.3） | `address.py::flush_chain_as_standalone` | 低-中：少数 standalone admin 用例改变 |
| **PR4** | HARD sub-tokenize | `address.py::run`；新增 `sub_tokenize` | 低：HARD clue 用例少，需要新增 |
| **PR5** | suspected fixup pass（§5.6） | `address.py::fixup_suspected_info`；`AddressComponent.suspected` 字段 | 高：所有跨层链断的用例需要新增/校对 |
| **PR6** | POI 列表化（§5.7） | `AddressComponent`、`schemas`、`normalized_pii`、`render_address_text` | 高：schema 改动 + DB migration |
| **PR7** | canonical 重写（§6） | `normalized_pii::_same_address` | 中-高：依赖 PR5/PR6；需要新建 canonical 测试集 |
| **PR8** | 清理与脚本更新 | `scripts/debug_address_stack_trace.py`、删除遗留 `_TRAILING_ADMIN_TYPES`、`_ADMIN_DEMOTABLE_AFTER`、`deferred_poi` | 低 |

> 每个 PR 必须独立通过 `tests/test_address_stack.py` 与 `tests/test_normalized_pii_address_en.py`。

---

## 9. 测试用例清单

### 9.1 comma-segment 与占位（PR1）

- `南京中路，上海浦东` → road + city + district
- `南京中路，浦东，上海` → 同上（三段）
- `南京中路，上海浦东，中国` → road + city + district + province
- `南京中路，浦东上海中国` → 段内反向 → 截断
- `南京中路，浦东上海，天元西路` → road 占位冲突 → 截断
- `北京市朝阳区中山路` → 正向单段
- `北京朝阳中山路` → 链式吸收 + suspected fixup（PR5）

### 9.2 deferred_chain（PR2）

- `扑南京人西路` → ROAD{value:扑南京人, key:西路}
- `科技园社区小区` → POI{value:科技园社区, key:小区}
- `科技园社区` → SUBDISTRICT{value:科技园, key:社区}（§5.2 不被穿透时）
- `产业园小区A栋` → POI{value:产业园, key:小区} + BUILDING{A栋}（小区与栋不相邻）
- `住宅楼GG栋1102` → 楼 value 为空 → 丢弃；BUILDING(GG栋) + DETAIL(1102)
- `科技园路10号` → POI 链 + ROAD 吞噬
- `深圳湾社区E栋602` → POI 链 + SUBDISTRICT 吞噬 + DETAIL

### 9.3 VALUE standalone（PR3）

- `上海浦东` → CITY(上海) + DISTRICT(浦东)
- `上海浦东balabala` → 同上（balabala 无 clue）
- `上海，北京` → 触发地址边界切分（两个 city 占位冲突）

### 9.4 HARD sub-tokenize（PR4）

- HARD clue 覆盖 `朝阳区中山路100号` → sub_tokenize 出 DISTRICT + ROAD + NUMBER

### 9.5 suspected fixup（PR5）

- §5.6 用例对照表 8 行全部覆盖
- `北京天津朝阳中山路` 系列（链长 ≥ 3）

### 9.6 POI 列表（PR6）

- `携程阳光社区小区里的住宅楼` → POI=["携程阳光社区", "里的住宅"]
- `万科城广场A栋` → POI=["万科城", "广场"] + BUILDING

### 9.7 canonical（PR7）

- `北京朝阳中山路1号` vs `朝阳区中山路1号` → suspected city=北京 与对方 district 子集 → PASS
- `万科广场` vs `万科城广场` → 纯子串非包含 → POI 比较 **FAIL**（不得用后缀表凑子集）
- `中山路1号` vs `中山路2号` → numbers 不匹配 → FAIL（早退）

### 9.8 通用回归

- `金钟路968号,上海市` → 逆序有逗号 → 允许
- `金钟路968号上海市` → 逆序无逗号 → 截断

---

## 10. 已确认设计决策

> 落地前已与用户对齐的开放点：

1. **suspected 不占用 occupancy 槽位**。"上海北京中山路" 两个 city 候选中，先到者"上海"写入 suspected，后到者"北京"降级为普通文本（留在 value 中），不触发地址边界切分。
2. **suspected 的 chain break 方向**：从左到右，遇到第一个被降级的 clue → 后续全部降级。与"高层级在前"的中文地址书写习惯一致。
3. **HARD clue 子分词失败的 fallback**：把整段当作 fallback POI，保留 HARD recall。
4. **POI list 元素之间的顺序**：按出现顺序保留。canonical 比较时双向子集匹配，顺序不影响结果。
5. **段内 forward 允许跳级**：例 `北京朝阳` 直接 province→district 跳过 city。
6. **链穿透中间 KEY 时**：穿透的中间 KEY **不写** occupancy。
7. **6-unit gap 不随 segment 重置**：逗号本身已经把链断开了，新段从下一个 clue 开始，gap 锚点自动跟上。
