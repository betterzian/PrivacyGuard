# 地址多层级 admin 与 MULTI\_ADMIN component 实现计划

## 0. 设计目标与不变式

针对中文/英文地址中"同一文本片段同时承载多个行政层级身份"的场景，建立统一的解析、保留、落地与对外表达机制。

### 0.1 三类典型场景

| 场景           | 例子                                                       | 当前行为                                                                     | 目标行为                                                                                      |
| ------------ | -------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| value 多层     | 朝阳（city/district）、北京（province/city）、New York（city/state） | 仅按 `_ADMIN_RANK` 取最高一层；其余信息丢弃                                            | 全部层级保留为 `levels` 元组，落地时若 ≥2 层则成 `MULTI_ADMIN`                                             |
| key 多层       | "市" ∈ {PROVINCE, CITY, DISTRICT\_CITY}                   | "市" 默认 CITY，靠 `_key_should_degrade_from_non_pure_value` 启发式硬降级到 DISTRICT | 显式注册 KEY levels；与 value levels 取交集；交集为空判非法；为单元素直接落；多元素进 suspect 链                         |
| key+value 组合 | "北京市" / "张家港市"                                           | 第一类靠词典+硬规则；第二类纯启发式                                                       | value↔key 走 intersection；intersection 为 ≥2 则落 MULTI\_ADMIN；左侧无 value 时 "市"→DISTRICT\_CITY |

### 0.2 落地形态语义

- 普通 `_DraftComponent`：`component_type` 单值，`levels=()`，表达"已确定单一层级"。
- `MULTI_ADMIN _DraftComponent`：`component_type=MULTI_ADMIN`，`levels=tuple(...)` 包含 ≥2 个 admin 层级，按 `_ADMIN_RANK` 降序，表达"承认该实体同时承担多个行政角色"。
- canonical / restore 比较：MULTI\_ADMIN 的 levels 与对方 `({type} ∪ levels)` 取交集，**任一层重合**即视作同一 admin 实体。
- 占位（occupancy）：MULTI\_ADMIN 提交时同时锁住 `MULTI_ADMIN` 自身 + `levels` 中的每一层。

### 0.3 suspect → 实体分裂的降序原则（新增点 1）

当 suspect 链最终落成两个独立实体时，按链中出现顺序：

- 第 1 个实体 → 取候选 levels 中 `_ADMIN_RANK` 最高的那一层；
- 第 2 个实体 → 取候选 levels 中次高的层；
- 依此类推。

例：`北京 北京 朝阳` →

- 第 1 个"北京" levels 候选 = {PROVINCE, CITY}，落 PROVINCE；
- 第 2 个"北京" levels 候选 = {CITY}（PROVINCE 已占），落 CITY；
- "朝阳" levels 候选 = {DISTRICT}（CITY 已占），落 DISTRICT。

### 0.4 PROVINCE→DISTRICT 后继关系（新增点 1）

`_VALID_SUCCESSORS[PROVINCE]` 加入 `DISTRICT`，使 `朝阳区 北京市 北京市` 类倒序场景可被接受：

- 倒序解析：朝阳区(DISTRICT) → 北京市(CITY) → 北京市(PROVINCE) 在逗号尾 reverse 方向被 `_segment_admit` 接受；
- 正序场景中 `北京 朝阳`（北京 = PROVINCE，朝阳 = DISTRICT）也直接成立，不再依赖中间 CITY 占位。

### 0.5 输入解释规则修正（新增点 2 推翻原 plan 6.1）

| 输入          | 原 plan 期望                 | 新期望                                       |
| ----------- | ------------------------- | ----------------------------------------- |
| 北京市北京市朝阳区   | MULTI\_ADMIN(北京市) + split | PROVINCE(北京市) + CITY(北京市) + DISTRICT(朝阳区) |
| 朝阳区,北京市,北京市 | —                         | DISTRICT(朝阳区) + CITY(北京市) + PROVINCE(北京市) |
| 北京北京朝阳      | —                         | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳)    |
| 朝阳,北京北京     | —                         | DISTRICT(朝阳) + PROVINCE(北京) + CITY(北京)    |

落地机制：

1. 第 1 个 "北京市" 进 deferred chain，作为 MULTI\_ADMIN suspect（levels={PROVINCE, CITY}）；
2. 第 2 个 "北京市" 进入时，发现链上存在同 value 的 MULTI\_ADMIN suspect → 触发 **suspect-split**：
   - 第 1 个 suspect 锁定为候选 levels 的最高位（PROVINCE），落普通 PROVINCE component；
   - 当前进入者作为新 suspect，候选 levels 删去已锁层级（剩 {CITY}），落 CITY component；
3. 后续 "朝阳区"，正常 KEY 路由，DISTRICT 槽空，落 DISTRICT。

倒序场景 `朝阳区 北京市 北京市` 由步骤 2 的"按 deferred chain 内出现顺序"自然产出 CITY → PROVINCE。

***

## 1. 关键决策汇总

| Q                        | 决议                                                                 |
| ------------------------ | ------------------------------------------------------------------ |
| Q1 "市" KEY 无邻接 value 时降级 | DISTRICT\_CITY                                                     |
| Q2 multi-admin 的 key 字段  | 真实文本（standalone="", key-driven=key clue 原文）                        |
| Q3 KEY 是否多层              | KEY 多层；value↔key 走交集                                               |
| Q4 DISTRICT\_CITY 表达     | 新枚举值 `AddressComponentType.DISTRICT_CITY`，与 DISTRICT 同 ADMIN\_RANK |
| Q5 multi-admin 表达        | 新枚举值 `AddressComponentType.MULTI_ADMIN`；普通 component 与之概念分离        |
| Q6 中英文                   | 一并出方案；中文先跑通，英文后接公共抽象                                               |
| Q7 levels 域              | 仅 PROVINCE / CITY / DISTRICT 三层                                    |

KEY 显式 levels 表（hardcode 在 policy\_common 中，词典只管 strength）：

```
"市": (PROVINCE, CITY, DISTRICT_CITY)
"省": (PROVINCE,)
"区": (DISTRICT,)
其他 KEY: 词典声明的 (component_type,)
```

***

## 2. 阶段 0 — 类型与共享基建

### 2.1 新增枚举 [models.py:65](privacyguard/infrastructure/pii/detector/models.py:65)

- `AddressComponentType.DISTRICT_CITY = "district_city"`
- `AddressComponentType.MULTI_ADMIN = "multi_admin"`

### 2.2 类型表更新 [address\_state.py:47-128](privacyguard/infrastructure/pii/detector/stacks/address_state.py:47)

- `_ADMIN_TYPES` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_COMMA_TAIL_ADMIN_TYPES` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_SUSPECT_KEY_TYPES` += `{DISTRICT_CITY}`
- `_ADMIN_RANK`：`DISTRICT_CITY = 2`（与 DISTRICT 同 rank，用于排序）；MULTI\_ADMIN 不入表
- 辅助 `_admin_rank_of(comp_type, levels) -> int`：MULTI\_ADMIN 取 levels 中最大 rank
- `SINGLE_OCCUPY` += `{DISTRICT_CITY, MULTI_ADMIN}`
- `_VALID_SUCCESSORS`：
  - `PROVINCE` 后继 += `{DISTRICT, DISTRICT_CITY}`（新增点 1.4）
  - `CITY` 后继 += `{DISTRICT_CITY}`
  - `DISTRICT` 后继 += `{DISTRICT_CITY}`（罕见但允许；如不希望可去）
  - `DISTRICT_CITY` 后继 = `DISTRICT` 后继的同等集合
  - `MULTI_ADMIN` 不写入静态表，由 `_segment_admit` 按 levels 动态解析（取 levels 中最严格那层的后继并集）

### 2.3 `_DraftComponent.levels` 字段 [address\_state.py:155](privacyguard/infrastructure/pii/detector/stacks/address_state.py:155)

- 新增 `levels: tuple[AddressComponentType, ...] = ()`
- 构造后置 assert：`(component_type == MULTI_ADMIN) ⇔ (len(levels) >= 2)`
- `_clone_draft_component` 同步复制

### 2.4 `_commit` 双重 occupancy [address\_state.py:718](privacyguard/infrastructure/pii/detector/stacks/address_state.py:718)

- `comp_type == MULTI_ADMIN` 时除 `state.occupancy[MULTI_ADMIN]` 外，对 `levels` 中每层都写入 `state.occupancy[level] = index`
- `_segment_admit` 检查 SINGLE\_OCCUPY 时：
  - 普通 `comp_type` 已被某 MULTI\_ADMIN.levels 占用 → 拒接
  - 进入的 MULTI\_ADMIN 任一层已被占 → 拒接
  - DISTRICT\_CITY 与 DISTRICT 互斥（任一占用另一即拒）

### 2.5 `_segment_admit` MULTI\_ADMIN 后继 [address\_state.py:645](privacyguard/infrastructure/pii/detector/stacks/address_state.py:645)

- 上一组件类型为 MULTI\_ADMIN 时，后继合法集 = `⋂ {valid_successors[level] for level in last.levels}`
  - "最严格"取交集而非并集，避免某层非法被另一层覆盖
- 进入组件为 MULTI\_ADMIN 时，按 levels 中**任一**层与上一组件后继合法即视为合法（最宽松，因多层身份留 fallback）

### 2.6 公共 admin span 工具上提

- `_AdminValueSpan / collect_admin_value_span / _is_admin_value_clue / _same_admin_value_span / _build_admin_value_span / _ordered_admin_levels / match_admin_levels / _collect_chain_edge_admin_value_span` 从 [address\_policy\_zh.py](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py) 上提到 [address\_policy\_common.py](privacyguard/infrastructure/pii/detector/stacks/address_policy_common.py)
- `address_policy_zh.py` 删除原定义，**不留 re-export**（clean code）

***

## 3. 阶段 1 — value 多层级与 MULTI\_ADMIN 落地

### 3.1 scanner 直辖市 dual-emit [scanner.py:2103-2111](privacyguard/infrastructure/pii/detector/scanner.py:2103)

- 删除 `direct_city_names = {"北京","上海","天津","重庆","香港","澳门"}` 单转 CITY 的 special case
- 直辖市自然以 PROVINCE + CITY 双层级注册（按词典原层级）
- scanner 同 span 多层级机制 [scanner.py:2117](privacyguard/infrastructure/pii/detector/scanner.py:2117) `seen: set[(component_type, text)]` 已支持，无需改

### 3.2 词典层级补齐 [data/scanner\_lexicons/zh\_geo\_lexicon.json](data/scanner_lexicons/zh_geo_lexicon.json)

- 直辖市同时出现在 `provinces` 与 `cities` 池子（已有 `cities.soft.北京`；需在 `provinces.soft` 也存在 `北京/上海/天津/重庆`，香港/澳门保持现状）
- 不补县级市（按用户决定）

### 3.3 `resolve_admin_value_span` 改造 [address\_policy\_zh.py:258](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:258)

- 返回结构改为 `_AdminResolveResult(primary, levels)`：
  - `levels`：occupancy + segment 过滤后剩余的全部可用层级，按 ADMIN\_RANK 降序
  - `primary = levels[0]`（保持现有"按 rank 高优先"）
- 调用方按 `len(levels)` 决定落普通还是 MULTI\_ADMIN

### 3.4 `_flush_chain_as_standalone` admin group 分支 [address\_state.py:843-924](privacyguard/infrastructure/pii/detector/stacks/address_state.py:843)

- 调用新 resolve 拿 `(primary, levels)`
- `len(levels) >= 2` → 落 `_DraftComponent(component_type=MULTI_ADMIN, levels=levels, key="", value=...)`
- `len(levels) == 1` → 落普通单层 component
- 移除现有 `removed_suspects` + `remaining_levels` 路径（被 MULTI\_ADMIN 取代）

### 3.5 KEY-driven `_flush_chain` 主分支 [address\_state.py:791-822](privacyguard/infrastructure/pii/detector/stacks/address_state.py:791)

- 当 routed key 的 `component_type == MULTI_ADMIN`：
  - 复制 routed key 上挂载的 `levels` 到 `_DraftComponent.levels`
  - `is_detail = False`
- 其余路径不变

### 3.6 删除已废 suspect 路径

- `_freeze_value_suspect_for_mismatched_admin_key` [address\_policy\_zh.py:365](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:365)：被 intersection 取代，删
- `_remove_last_value_suspect` [address\_policy\_zh.py:507](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:507)：失去触发场景，删
- `_freeze_key_suspect_from_previous_key` [address\_policy\_zh.py:441](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:441)：完成 4.x 后评估能否删

***

## 4. 阶段 2 — KEY 多层级与 intersection 路由

### 4.1 KEY levels 注册 \[address\_policy\_common.py 新增]

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

### 4.2 `_routed_key_clue` 重写 [address\_policy\_zh.py:812](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:812)

替换现有 if/elif 启发式：

```
key_lvls = key_levels(clue)
adj_value_span = _adjacent_value_span(context, clue)  # 已有

if adj_value_span is not None:
    intersection = ordered_intersect(adj_value_span.levels, key_lvls)
    if not intersection:
        return None  # 进 ignored_address_key
    if len(intersection) == 1:
        return clue with component_type = intersection[0], levels=()
    # ≥2: 落 MULTI_ADMIN routed key，挂 levels
    return clue with component_type = MULTI_ADMIN, levels = intersection
else:
    # 左邻不是 value
    if clue.text == "市":
        return clue with component_type = DISTRICT_CITY
    if clue.text == "省":
        return None
    # 其他词典定义层级
    return clue
```

注：`Clue` 现无 `levels` 字段，需在 `Clue` 上补可选 `levels: tuple[AddressComponentType, ...] = ()`，仅 routed key 临时使用，scanner 输出仍 `levels=()`。

### 4.3 `_handle_key_clue` 处理 MULTI\_ADMIN routed key [address\_zh.py:238](privacyguard/infrastructure/pii/detector/stacks/address_zh.py:238)

- 现有 `comp_type` 取自 effective\_clue，自然是 MULTI\_ADMIN
- 进入 `_flush_chain` 路径时把 routed key 上的 levels 透传到 component（在 3.5 已做）

### 4.4 删除 `_key_should_degrade_from_non_pure_value` [address\_policy\_zh.py:721](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:721)

- 已被 4.2 步骤 4 取代，整段删除
- 调用点 [address\_policy\_zh.py:821](privacyguard/infrastructure/pii/detector/stacks/address_policy_zh.py:821) 一并删除

***

## 5. 阶段 3 — suspect-split 与降序分裂（新增点 1+2 核心）

> 这是本次最关键的新机制。处理 `北京 北京 朝阳` / `北京市 北京市 朝阳区` / 其倒序变体。

### 5.1 触发位置

在 `_handle_value_clue` [address\_zh.py:136](privacyguard/infrastructure/pii/detector/stacks/address_zh.py:136) 与 `_handle_key_clue` [address\_zh.py:238](privacyguard/infrastructure/pii/detector/stacks/address_zh.py:238) 入口判定：

- 当前进入 clue 命中的 levels 与 deferred\_chain 末端（或链中存在的）某条 admin clue 的 levels 有非空交集，且当前文本 `clue.text` 与链中那条 admin clue 文本相同 → 触发 **homogeneous-split** 路径，而非通用 split\_at。

### 5.2 homogeneous-split 算法

```
设链中已有 suspect: prev (levels = L_prev, value v)
当前进入: cur (levels = L_cur, value v)  且 v_prev == v_cur

候选并集 U = ordered_unique(L_prev + L_cur), rank desc
分配:
    prev_assigned = U[0]                      # 最高 rank
    cur_assigned  = U[1]                      # 次高 rank
若 |U| < 2 → 不分裂，按现行逻辑走 split_at（异常）

效果:
    1. flush prev as 普通 component(component_type = prev_assigned, levels=())
       占住 prev_assigned + (如适用) 在 _segment_admit 顺利通过
    2. 把 cur 作为新 suspect 入链，候选 levels = U \ {prev_assigned}
       若 |候选| == 1 立即 commit；若 ≥ 2 仍是 MULTI_ADMIN 候选
```

倒序场景：因第 1 个进来的 cur 与第 2 个 prev 的 levels 相同（皆 {PROVINCE, CITY}），按"先来者占最高 rank"分配会得到 prev=PROVINCE, cur=CITY；这与"朝阳区 北京市 北京市"期望（CITY 在前 PROVINCE 在后）相反。

**修正**：分配方向必须考虑链方向（forward/reverse）。借用现有 `_CommaSegmentState.direction` 的"逗号尾方向"语义，新增\*\*"admin 行政方向"\*\*：

- 默认方向 = `forward`：第 1 个实体取最高 rank（PROVINCE → CITY → DISTRICT）；
- 当 prev 已是某确定 admin 层、cur 与 prev 同 value、且 cur 候选包含**比 prev 更高的层** → 切换为 `reverse`：cur 取更高层。
- 实操：分配时检查 prev 已 commit 的 component\_type；若 cur 候选最高 > prev rank → cur=候选最高, prev 已落不动；若 cur 候选最高 ≤ prev rank → cur 取候选中 < prev rank 的最高一项。

进一步完整算法：

```
def split_homogeneous_admin(prev_committed, cur_levels, prev_levels):
    """
    prev_committed: 已 commit 的 component（可能是 MULTI_ADMIN）
    cur_levels:    新进 clue 候选 levels (filtered by occupancy)
    prev_levels:   prev 原候选 levels
    """
    # case A: prev 还在 deferred_chain 是 MULTI_ADMIN suspect 未落
    if prev not committed yet:
        # 按降序分配
        union = ordered_desc(prev_levels ∪ cur_levels)
        return prev=union[0], cur=union[1..]
    # case B: prev 已落（某 admin 层）
    prev_rank = ADMIN_RANK[prev_committed.component_type]
    higher = [l for l in cur_levels if ADMIN_RANK[l] > prev_rank and l not in occupancy]
    lower  = [l for l in cur_levels if ADMIN_RANK[l] < prev_rank and l not in occupancy]
    if higher:
        return cur = max(higher, by rank)   # reverse 方向：cur 升
    if lower:
        return cur = max(lower, by rank)    # forward 方向：cur 降
    return None  # 异常，走 split_at
```

### 5.3 落地步骤

新增 `_split_homogeneous_admin_suspect(state, clue, levels)` 函数 in \[address\_state.py]，由 `_handle_value_clue` / `_handle_key_clue` 在 prehandle 阶段调用。

### 5.4 标记顺序保留

`state.deferred_chain` 与 `state.components` 都以列表保序；MULTI\_ADMIN 与普通 component 按 commit 顺序排列；`_address_metadata` 的 trace 保持组件提交顺序（已是该行为）。

***

## 6. 阶段 4 — 英文 multi-admin

### 6.1 EN scanner 去重粒度对齐 [scanner.py:2208](privacyguard/infrastructure/pii/detector/scanner.py:2208)

- `seen: set[str]` → `seen: set[tuple[AddressComponentType, str]]`
- 让英文同名 dual-level entry 都注册（数据驱动；本 PR 不补名单）

### 6.2 EnAddressStack 接 deferred chain + admin span [address\_en.py:83](privacyguard/infrastructure/pii/detector/stacks/address_en.py:83)

- `_handle_value_clue` 引入 `collect_admin_value_span`
- `_flush_chain` 子类化，传入 EN-friendly resolver

### 6.3 EN resolver 策略 \[address\_policy\_en.py 新增]

- 默认 `primary = CITY`（不照搬 `_ADMIN_RANK` 高优先）
- `levels` 仍保 intersection 全集 → 多层时落 MULTI\_ADMIN
- 词典数据准备暂缓（用户确认 EN 名单后再补）

### 6.4 EN KEY 多层暂不引入

- `is_prefix_en_key` 等接口保持单层

***

## 7. 阶段 5 — 下游适配

### 7.1 `_address_metadata` 序列化 [address\_state.py:1015-1051](privacyguard/infrastructure/pii/detector/stacks/address_state.py:1015)

- 新增 trace 字段 `address_component_levels`：与 `address_component_type` 平行
  - 单层级 component：`""`（占位保对齐）
  - MULTI\_ADMIN：`"province|city"`（按 ADMIN\_RANK 降序）
- `address_component_type` 写 `"multi_admin"`

### 7.2 `parser.py` 透传 [parser.py:84-93](privacyguard/infrastructure/pii/detector/parser.py:84)

- 新增 `address_component_levels` 到透传白名单

### 7.3 `normalized_pii.py` 适配 [normalized\_pii.py:29-78](privacyguard/utils/normalized_pii.py:29)

- `_ADDRESS_COMPONENT_KEYS` += `("multi_admin", "district_city")`
- `_ORDERED_COMPONENT_KEYS`：在 `province` 之前插入 `multi_admin`；在 `district` 之后插入 `district_city`
- `_ADDRESS_COMPONENT_ALIASES`：无新增（新枚举值就是 canonical 名）
- `_ADDRESS_MATCH_KEYS` += `("multi_admin", "district_city")` —— 用于 same\_entity 比较纳入
- `_ADDRESS_COMPONENT_COMPARE_KEYS` += `("multi_admin", "district_city")`

### 7.4 `NormalizedAddressComponent.levels` 字段

- 在 [privacyguard/infrastructure/pii/address/types.py](privacyguard/infrastructure/pii/address/types.py) 给 `NormalizedAddressComponent` 加 `levels: tuple[str, ...] = ()` 字段
- `_ordered_components_from_metadata` [normalized\_pii.py:732](privacyguard/utils/normalized_pii.py:732) 解析时同时读 `address_component_levels` trace，挂到 component 上

### 7.5 canonical / same-entity 比较器扩展

- 调研后定位实际比较点（grep `component.component_type ==` / `_ordered_component_by_type`）
- MULTI\_ADMIN 与任意 admin component 比较：levels 与对方 `({type} ∪ levels)` 取交集 ≥1 即视同层
- DISTRICT\_CITY 与 DISTRICT 不互通（属不同行政性质，不做模糊匹配）—— 待确认

***

## 8. 阶段 6 — 清理（执行至 7 完成后）

明确删除（不留 re-export）：

- `_freeze_value_suspect_for_mismatched_admin_key`
- `_remove_last_value_suspect`
- `_key_should_degrade_from_non_pure_value`
- `direct_city_names` special case
- `_flush_chain_as_standalone` 中已被 MULTI\_ADMIN 取代的 `removed_suspects` / `remaining_levels` 残留路径
- `_freeze_key_suspect_from_previous_key`：4.x 完成后评估，无调用即删
- `address_policy_zh.py` 中已上提到 common 的工具函数本地定义

***

## 9. 阶段 7 — 测试

### 9.1 仅新增 case 必须通过；旧 case 失败一律先停下问用户

新增专属 case（按场景，新建独立 test 文件 `tests/.../test_address_multi_admin.py`）：

| 输入                       | 预期组件链                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------- |
| `朝阳`                     | MULTI\_ADMIN(levels=\[city, district], value=朝阳)                                   |
| `北京`                     | MULTI\_ADMIN(levels=\[province, city], value=北京)                                   |
| `北京市`                    | MULTI\_ADMIN(levels=\[province, city], value=北京, key=市)                            |
| `北京市朝阳区`                 | MULTI\_ADMIN(levels=\[province, city], 北京) + DISTRICT(朝阳, key=区)                   |
| `北京朝阳`                   | MULTI\_ADMIN(levels=\[province, city], 北京) + DISTRICT(朝阳)（依赖 PROVINCE→DISTRICT 后继） |
| `苏州市`                    | CITY(苏州, key=市)                                                                    |
| `苏州市张家港市`                | CITY(苏州) + DISTRICT\_CITY(张家港, key=市)（启发式降级）                                       |
| `张家港市` 单出现               | DISTRICT\_CITY(张家港, key=市)                                                         |
| `北京市北京市朝阳区`              | PROVINCE(北京, key=市) + CITY(北京, key=市) + DISTRICT(朝阳, key=区)                        |
| `北京北京朝阳`                 | PROVINCE(北京) + CITY(北京) + DISTRICT(朝阳)                                             |
| `朝阳区,北京市,北京市`            | DISTRICT(朝阳, key=区) + CITY(北京, key=市) + PROVINCE(北京, key=市)                        |
| `朝阳,北京,北京`               | DISTRICT(朝阳) + CITY(北京) + PROVINCE(北京)                                             |
| `朝阳区`                    | DISTRICT(朝阳, key=区)                                                                |
| `朝阳市`                    | CITY(朝阳, key=市)                                                                    |
| `New York`               | MULTI\_ADMIN(levels=\[city, province], value=New York)                             |
| `Brooklyn, New York, NY` | CITY(Brooklyn) + MULTI\_ADMIN(...New York) + PROVINCE(NY)（待 EN 词典）                 |

### 9.2 旧测试策略

- 跑 `tests/` 全量后，**任何**旧测试失败：
  - 暂停实现
  - 在 PR 描述里列出失败 case 与失败原因
  - 询问用户该 case 是否：(a) 行为正确仅断言需更新，(b) 行为升级到 MULTI\_ADMIN 但断言未跟上，(c) 真实回归 → 用户决定如何处理
- 不主动改任何旧测试，不自行决定"等价升级"

***

## 10. 必须前置的调研（动手前 1 小时内完成）

1. 全仓搜索 `component.component_type ==` / `comp_type in` / `_ordered_component_by_type`，列出阶段 7.5 实际需改动的比较点清单
2. 确认 `Clue` dataclass 是否便于加 `levels` 临时字段，或者是否应在 `effective_clue` 替代物上挂载（避免污染 scanner 输出）
3. 确认 `_VALID_SUCCESSORS[PROVINCE] += DISTRICT` 是否会让 `北京朝阳` 之类组合在 `_has_reasonable_successor_key` 链路被过早接受，影响其它 case
4. 确认 `_segment_admit` 的"MULTI\_ADMIN 后继取 levels 交集"方案在逗号尾 `direction != None` 分支下是否可行（reverse 方向需要把 levels 当目标层级反查后继）

***

## 11. 风险与未验证假设

1. suspect-split 算法（5.2）的 forward/reverse 方向决断只在 `北京 北京 朝阳` / `朝阳 北京 北京` 两个对称 case 下推演过；对 `北京 朝阳 北京` / `朝阳 北京 朝阳` 等交错形态未验证，可能落入 `异常 → split_at` 分支
2. PROVINCE→DISTRICT 后继开放后，`_VALID_SUCCESSORS` 边界扩散；可能让以前被 `_segment_admit` 拒绝的"北京 朝阳"（无 CITY 中间项）case 在某些上下文（如 OCR 噪声）误命中
3. EN 部分（阶段 4）只实现代码骨架；实际可用需 EN dual-level 词典数据，本计划不交付该数据
4. canonical / same-entity 比较器对 MULTI\_ADMIN 的 OR 匹配语义需用户在阶段 7.5 调研后确认是否影响 restore 行为
5. `_DraftComponent.levels` 字段对所有 clone / serialize 路径都需校验未漏点，特别是 [address\_state.py:1084](privacyguard/infrastructure/pii/detector/stacks/address_state.py:1084) `_rebuild_component_derived_state` 中 occupancy 重建对 MULTI\_ADMIN 的处理
6. KEY `Clue.levels` 临时字段是否破坏 `_dedupe_clues` 的 key 计算（[scanner.py:2322](privacyguard/infrastructure/pii/detector/scanner.py:2322)）需要 verify

***

## 12. PR 拆分建议

| PR | 阶段          | 范围                                                   |
| -- | ----------- | ---------------------------------------------------- |
| #1 | 阶段 0 + 阶段 1 | 类型基建 + value 多层落 MULTI\_ADMIN + 直辖市 + 公共抽提           |
| #2 | 阶段 2 + 阶段 3 | KEY 多层 intersection + suspect-split + DISTRICT\_CITY |
| #3 | 阶段 4        | EN scanner 去重 + EnAddressStack 接 admin span（不含数据）    |
| #4 | 阶段 5 + 阶段 6 | 下游适配 + 清理                                            |

每个 PR 都含对应 case 的新增测试；旧测试若挂红停下问用户。
