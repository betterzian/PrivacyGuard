# PrivacyGuard Rule-Based PII Detector 中文地址 Stack 算法说明

## 摘要

本文基于 `PrivacyGuard` 仓库中 `rule_based` PII 检测器的当前实现，对中文地址识别相关的 `AddressStack` 代码进行结构化梳理，并按论文写法给出其输入表示、状态设计、主流程、关键子算法、冲突裁决机制以及工程特性说明。该实现并不是简单的“正则匹配 + 左右拼接”，而是一个**以 clue 为驱动、以状态机为核心、以组件级提交为目标**的地址解析器。其核心思想是：先将 prompt/OCR 文本规约为统一的 `StreamInput` 与 `Clue` 序列，再由 `AddressStack` 在局部上下文中执行 `seed → deferred chain → segment admit → suspect fixup → digit tail → candidate build` 的多阶段解析，最终输出结构化地址候选。

从代码行为上看，该实现同时考虑了以下困难场景：

1. 中文地址的层级结构并不总是严格正序，存在“逗号逆序补充行政区”的写法；
2. OCR 文本存在跨块、跨行拼接问题，候选边界不能只依赖原始字符位置；
3. 地址中的一部分片段在表面上像行政区或道路，但在具体上下文中可能只是普通文本，需要延迟提交；
4. 某些尾部数字既可能是地址的一部分，也可能是独立数字实体，因此需要与结构化数字栈协同裁决；
5. 地址与姓名、组织名在文本中可能相邻或重叠，因此需要统一 parser 层完成跨栈冲突消解。

因此，PrivacyGuard 的中文地址 stack 更适合被理解为一种**轻量级、可解释的规则状态机解析器**，而非单轮静态匹配器。

---

## 1. 模块定位与调用链

### 1.1 在检测器中的位置

`RuleBasedPIIDetector.detect(...)` 会分别对 `prompt_text` 和 `ocr_blocks` 做预处理、扫描与解析。整体调用链如下：

```text
RuleBasedPIIDetector.detect
    ├── build_prompt_stream / build_ocr_stream
    ├── build_clue_bundle
    ├── StreamParser.parse
    │     └── AddressStack.run（当 family=ADDRESS 且 role 合法时）
    ├── apply_ocr_geometry（仅 OCR 路径）
    └── _to_pii_candidates / resolver.resolve_candidates
```

其中，`RuleBasedPIIDetector` 还会载入本地隐私词典与会话词典，并构建 `StructuredLookupIndex`；但地址 stack 本身并不直接操作这些仓库，而是消费已经扫描好的地址 clue 序列。

### 1.2 在 parser 中的优先级

`StreamParser` 采用“单主栈 + 优先级冲突裁决”的架构。对于 soft clue，优先级为：

- `ADDRESS = 30`
- `NAME = 20`
- `ORGANIZATION = 10`

这意味着当地址候选与姓名、组织候选重叠时，地址栈默认拥有更高优先级；败方可尝试 `shrink` 回缩剩余区域，无法回缩则被丢弃。

### 1.3 合法起栈角色

地址栈允许以下 role 作为起点：

- `LABEL`
- `START`
- `VALUE`
- `KEY`

因此，地址解析既可由显式标签（如“收货地址”）触发，也可由地址值片段或地址关键字直接触发。

---

## 2. 输入表示与基本对象

### 2.1 文本流表示 `StreamInput`

无论来源于 prompt 还是 OCR，文本都会被规约成 `StreamInput`。其核心字段包括：

- `text`：清洗后的串行文本；
- `units`：离散单元序列；
- `char_to_unit`：字符到 unit 的映射；
- `char_refs`：字符到原始来源（prompt/OCR block/bbox）的映射。

在预处理后，文本会被切成如下 unit 类型：

- `cjk_char`
- `ascii_word`
- `alnum_run`
- `digit_run`
- `space`
- `inline_gap`
- `ocr_break`
- `punct`
- `other_char`

对于 OCR，系统还会先进行块间语义拼接：同行相邻块尽可能用 `_OCR_INLINE_GAP_TOKEN` 连接，不同语义段之间插入 `OCR_BREAK`。这一步直接影响后续“gap ≤ 1 unit”与“gap ≤ 6 units”的地址链规则。

### 2.2 地址 clue 表示

地址栈消费的是 `Clue` 序列。地址相关字段包括：

- `family = ADDRESS`
- `role ∈ {LABEL, START, VALUE, KEY}`
- `attr_type = ADDRESS`
- `component_type ∈ {province, city, district, subdistrict, road, number, poi, building, detail}`
- `start/end` 与 `unit_start/unit_end`

从语义上看：

- `VALUE` 表示某段文本可作为某级地址值；
- `KEY` 表示某个地址关键词，如“路”“号”“楼”等；
- `LABEL` 表示触发型标签，如“收货地址”；
- `START` 表示某些可以直接起栈的弱触发点。

### 2.3 地址组件类型

当前实现将地址压缩为 9 类组件：

1. `province`
2. `city`
3. `district`
4. `subdistrict`
5. `road`
6. `number`
7. `poi`
8. `building`
9. `detail`

该设计体现出一个明确倾向：**先抓取对还原地址最关键的层级骨架，再把楼栋、单元、房号等细节归入 building/detail 两个尾部层级**。

---

## 3. 解析问题定义

给定一个文本流 `X` 与地址线索序列 `C = {c_1, c_2, ..., c_n}`，目标是输出一个地址候选 `A`，满足：

1. `A` 对应一段连续文本区间 `[s, e)`；
2. 该区间可被解释为若干有序地址组件的组合；
3. 组件间满足代码定义的层级合法性与局部 gap 约束；
4. 对疑似但不确定的行政层级信息，允许延迟落地为 `suspected` 元数据；
5. 当候选右端存在尾部数字或重叠负向片段时，允许做增量修复或挑战裁决；
6. 当候选与其他 family 候选重叠时，服从 parser 层统一冲突裁决。

从这个角度看，`AddressStack` 解决的并不是“关键词抽取”问题，而是一个**局部结构化片段重建**问题。

---

## 4. 整体算法框架

### 4.1 顶层流程

地址栈的核心入口可概括为：

```text
run
 ├── 若 seed 为 HARD clue：_run_hard → _sub_tokenize → _run_with_sub_clues
 └── 否则：_run_with_clues
        ├── 主循环遍历 clue
        ├── _handle_address_clue
        ├── _flush_chain
        ├── negative tail repair
        ├── _fixup_suspected_info
        ├── digit_tail analysis / pending challenge
        └── _build_address_run_from_state
```

### 4.2 五个核心阶段

按代码语义，可将其拆为五个阶段：

1. **起栈与 seed 确定**：决定地址解析起点；
2. **链式吸收与组件提交**：将 VALUE/KEY clue 吸收到 `deferred_chain`，并在必要时提交为组件；
3. **段内合法性与逗号逆序处理**：控制组件顺序、自环、逆序行政补充；
4. **尾部修复与尾数字扩展**：处理负向片段、digit tail 与结构化挑战；
5. **候选构造与元数据输出**：输出地址文本、组件轨迹、suspected 信息等。

---

## 5. 解析状态设计

### 5.1 `_ParseState`

地址栈使用 `_ParseState` 保存解析过程中的动态状态。关键字段如下：

- `components`：已提交组件序列；
- `occupancy`：单占位组件（如 city、district、road 等）已占用的位置；
- `deferred_chain`：尚未提交、等待最终判定的一串 indexed clue；
- `suspect_chain`：可能降落为 `suspected` 的 admin VALUE clue；
- `chain_left_anchor`：当前链左边界锚点；
- `segment_state`：当前段内方向与逗号尾状态；
- `evidence_count`：证据数量；
- `absored_digit_unit_end`：已吸收数字单元的右界；
- `split_at`：若发现应在此处分裂为下一地址候选，则记录切分位置；
- `pending_community_poi_index`：被临时当成 `poi` 的“社区”组件索引；
- `comma_tail_checkpoint`：逗号尾回滚快照；
- `consumed_clue_indices / committed_clue_ids`：已消费 clue 的索引与 ID；
- `suppress_challenger_clue_ids`：允许被当前地址 run 跨越，但不允许 parser 重新作为 challenger 的 clue。

### 5.2 单占位组件

以下类型在同一地址实例内最多出现一次：

- `province`
- `city`
- `district`
- `subdistrict`
- `road`
- `number`

这通过 `SINGLE_OCCUPY` 与 `occupancy` 控制。若某种组件已经被占用，再次出现通常意味着：

- 当前地址应终止，或
- 需要在逗号尾逆序模式下重新解释，或
- 前一个疑似组件应被降级。

---

## 6. 起栈与 seed 选择

### 6.1 `LABEL` 起栈

若种子 clue 为 `LABEL`，系统并不会直接把标签后的整段文本当成地址，而是：

1. 从标签末尾跳过分隔符；
2. 在后续最多 6 个 unit 内寻找第一个地址 `VALUE` 或 `KEY` clue；
3. 仅在找到合法 clue 时才真正起栈。

因此，“收货地址：你好世界”不会误生成地址候选。

### 6.2 `VALUE/KEY/START` 起栈

若种子本身就是地址值或地址 key，则直接以该 clue 的字符起点作为 `address_start`。这种方式适合无显式标签的地址片段。

### 6.3 `HARD` clue 起栈

如果起点是高置信 `HARD` clue，地址栈先对该 clue 覆盖区间做局部子分词：

- 在该 span 内再次调用中英文地址 key/value matcher；
- 生成更细粒度的 `sub_clues`；
- 对重叠匹配做“长匹配覆盖短匹配”的去重；
- 再把这些 `sub_clues` 输入主循环。

这使得一个大的高置信 span 不会被当作整体硬提交，而是仍可经过组件级重建。

---

## 7. 主循环：链式吸收与提交

### 7.1 基本思想

主循环顺序扫描 clue。并不是每来一个 clue 就立刻提交组件，而是先尝试放入 `deferred_chain`。只有在以下情况出现时，才会冲洗链并提交：

- 当前 clue 无法继续挂链；
- 需要进行后置前瞻；
- 进入逗号尾模式；
- 循环结束；
- 已检测到应切分下一地址。

这种“延迟提交”机制是该实现最核心的设计之一。

### 7.2 链接受规则 `_chain_can_accept`

代码只允许以下三类链式传导：

1. `VALUE → VALUE`：两者间非空白 gap ≤ 1 unit；
2. `VALUE → KEY`：gap ≤ 6 units；
3. `KEY → KEY`：
   - gap = 0，或
   - gap = 1 且中间正文满足穿透规则。

其中，`KEY → VALUE` **不允许**继续挂链。这意味着一旦链尾是 KEY，再来 VALUE 时通常需要先结算前面的组件。

### 7.3 `KEY→KEY` 的特殊穿透规则

当两个 key 之间 gap=1 时，系统允许极有限的正文穿透：

- 中间若是中文 `cjk_char`，可穿透；
- 中间若是英文 `ascii_word`，长度至少为 3 才可穿透；
- 若左右两侧都是英文词，则中间不能是中文；
- 若左右两侧都是中文，则中间可以是中文或长英文。

该规则本质上是在做一种非常保守的“链内容错”，避免一些 OCR 切分造成的假断裂。

---

## 8. VALUE 处理逻辑

### 8.1 正常 VALUE 入链

若当前 clue 为地址 `VALUE`，且满足链规则，则执行：

- 加入 `deferred_chain`；
- 若属于行政层级（province/city/district/subdistrict），则还会进入 `suspect_chain`；
- 更新 `last_value` 与 `last_end`。

### 8.2 当链尾为 KEY

若当前链尾是 KEY，则当前 VALUE 不能直接接在后面。系统会先执行 `_flush_chain` 结算当前组件，再考虑后续行为。

### 8.3 后置前瞻：疑似新地址 vs 普通文字

这是当前实现最细致的一部分。

当已有组件或链存在，而新的 `VALUE` 由于层级冲突无法直接被 `segment_admit` 接受时，系统不会立刻切断，而是分两类处理：

1. **若该 VALUE 是行政层级，且右侧存在“合理后继 KEY”**：
   - 先结算前一条链；
   - 再把当前 VALUE 当作“普通文字”重新压入 `deferred_chain`；
   - 它不进入 `suspect_chain`。

   这意味着它更可能被右边的 KEY 吞并，形成如“南京西路”“浦东西小区”这样的更长片段。

2. **若没有合理后继 KEY**：
   - 直接把 `split_at` 设为当前 VALUE 起点；
   - 当前 run 停止，后续 clue 交给 parser 作为下一候选重新起栈。

这一步显著降低了“行政区词误被切成新地址”的风险。

---

## 9. KEY 处理逻辑

### 9.1 动态重路由 `_route_dynamic_key_type`

某些 key 的组件类型并不是静态固定的，而是与上下文相关。当前代码显式处理了两类：

#### 9.1.1 “社区”

若 clue 文本为“社区”，且原始类型为 `subdistrict`，则重路由为 `poi`。

这说明实现把“社区”默认视为兴趣点型地址片段，而不是稳定行政层。

#### 9.1.2 “楼”

“楼”的处理更复杂：

- 若左值不存在，则维持原类型；
- 若左值是纯字母数字混合：
  - 若右侧还跟着 detail key，则保持 `detail`；
  - 若前一组件已是 `building`，则仍归 `detail`；
  - 否则升级为 `building`；
- 若左值不是普通字母数字串，则转为 `poi`。

这说明代码把“楼”视为一个强上下文依赖 key，而不是固定地映射到 building。

### 9.2 KEY 左侧取值

对于普通 KEY，系统会尝试向左寻找其 value：

- 中文路径：优先吸收左邻 `digit_run / alpha_run / ascii_word`，否则按最多 2 个中文字符左扩；
- 英文路径：向左连续吸收字母数字；
- 但若 key 是英文本前缀关键词（如一些 detail 前缀或 `#`），则改为向右扫描取值。

### 9.3 KEY 直接建组件 vs 延迟入链

若 KEY 左侧存在有效 value，则它不会立即独立成组件，而是：

- 把当前 `chain_left_anchor` 设到扩展后的左边界；
- 将 KEY 入 `deferred_chain`；
- 等整条 `VALUE→...→KEY` 链在 `_flush_chain` 中一次性结算。

如果 KEY 没有左值，则：

- 英文前缀 key 走“右扫取值”逻辑；
- 其他 KEY 直接被降级为普通文本，加入 `ignored_address_key_indices`，以后不再阻挡左扩。

---

## 10. 组件提交 `_flush_chain` 与 `_commit`

### 10.1 `_flush_chain`

当需要冲洗链时：

1. 若链中包含 KEY，则取**最后一个 KEY**作为当前组件类型；
2. 组件左边界取 `chain_left_anchor`；
3. 组件 value 取 `[chain_left_anchor, key.start)` 的原文，再按组件类型归一化；
4. 组件 `raw_chain` 由 `suspect_chain` 中与本次提交 clue 索引相交的部分构成；
5. 生成 `_DraftComponent` 并调用 `_commit`。

若链中没有 KEY，则 `_flush_chain_as_standalone` 会把每个 VALUE 单独作为一个组件提交。

### 10.2 `_commit`

`_commit` 完成以下任务：

1. 调用 `_segment_admit` 校验段内合法性；
2. 若在逗号尾模式下提交了非法低层级组件，则触发回滚；
3. 提交普通组件或执行 `POI` 合并；
4. 更新 `occupancy` 与 `component_counts`；
5. 更新 `segment_state`、`last_component_type`、`last_end`；
6. 累加 `evidence_count`；
7. 写入 `committed_clue_ids` 与 `consumed_clue_indices`；
8. 对更早组件执行 `suspected` 剪枝；
9. 如有需要，登记临时的 `community poi`。

### 10.3 POI 的列表化合并

与其他组件不同，`poi` 允许在同一地址中多次出现，但不会生成多个独立组件，而是被合并到同一个 `POI` 组件中：

- `value` 变为列表；
- `key` 也变为列表；
- `end` 取最大右边界；
- clue IDs 与索引做并集。

这说明系统把多个兴趣点片段视为同一地址候选中的“并列 POI 组”。

---

## 11. 段内合法性与逗号逆序机制

### 11.1 正常顺序下的后继图

代码通过 `_VALID_SUCCESSORS` 显式定义了组件合法后继。例如：

- `province → city / district / subdistrict / road / poi`
- `city → district / subdistrict / road / poi`
- `district → subdistrict / road / poi`
- `road → number / poi / building / detail`
- `building → detail`
- `detail → detail`

这不是严格的行政区树，而是一张**为实际文本拼接服务的可达图**。例如 `city` 可以直接跟 `road`，对应“上海路”这类短地址写法。

### 11.2 逗号尾逆序逻辑

实现允许形如：

- `金钟路968号,上海市`

这样的“先细后粗”写法，但限制极严。核心条件是：

1. gap 中必须真的出现逗号；
2. 逗号后的第一个真实组件必须是 `province/city/district` 之一；
3. 它必须高于逗号左侧已提交组件中的最高行政层；
4. 进入逗号尾后，方向会在第二个组件上锁定为 `forward` 或 `reverse`；
5. 若后续落到区以下层级，则回滚到逗号左侧快照并停止。

这实际上实现了一种**受控逆序补全**，只允许用逗号补充更高层级的行政信息，而不允许借逗号胡乱拼接任意低层地址碎片。

---

## 12. `suspected` 信息的延迟落地

### 12.1 设计意图

在很多情况下，链左端的行政区值不一定应该直接作为组件 value，而更像是当前组件的上级上下文。例如：

- “上海钟山路”中的“上海”更像 `road` 的上级 `city`；
- “浦东西康路”中的“浦东”更像 `road` 的上级 `district`。

系统不在入链时立即做这种解释，而是把对应 VALUE clue 暂存于 `raw_chain`。

### 12.2 `_fixup_suspected_info`

在 run 即将结束时，系统对每个已提交组件执行：

1. 从 `raw_chain` 中抽取前导行政层 VALUE clue；
2. 对每个层级只保留第一次出现；
3. 写入 `component.suspected`；
4. 把这些文本从组件 `value` 中剥离；
5. 若剥离后为空，则回退到原值。

因此，最终 metadata 中会出现如下结构性信息：

- `address_component_suspected`
- `address_component_trace`
- `address_component_key_trace`

这使得候选既保留了表面文本，又保存了更细粒度的层级解释结果。

---

## 13. 负向 clue 修复

### 13.1 负向 clue 的意义

控制类 clue 中存在 `NEGATIVE`，用于标记某些不应被当作地址的片段。例如“路由”中的“路”不应被解释为道路 key。

### 13.2 修复策略

若负向片段只影响最右侧尾部组件，则系统不会直接抛弃整个地址，而是：

1. 找到最右侧与 negative span 重叠的组件；
2. 取该组件对应的有序 clue 前缀；
3. 在一个临时 `_ParseState` 中重放这些 clue；
4. 尝试找到不与 negative span 重叠的最稳定前缀；
5. 若仍无法修复，则逐级删除更右组件。

因此，该实现更接近“**只修坏掉的尾部**”，而不是“一旦有负向冲突就全盘丢弃”。

---

## 14. digit tail：尾部数字扩展

### 14.1 触发条件

若最终最右组件类型属于：

- `road`
- `poi`
- `number`
- `building`
- `detail`

并且其右侧紧邻一个 `digit_run` unit，则触发 `digit tail` 分析。

### 14.2 解析方式

系统会：

1. 读取 `digit_run` 文本，允许其中含空格或连字符；
2. 依据前一组件类型决定允许的 dash 数与后续可分配类型；
3. 将尾数字分割成若干片段；
4. 采用贪心策略把这些片段依次映射到 `building/detail` 等尾部组件；
5. 构造新的 `_DraftComponent` 序列。

例如，道路后面的 `79` 可能被解释为一个 detail/building 级尾部片段，从而把“上海路79”整体纳入地址候选。

### 14.3 挑战裁决 `PendingChallenge`

尾部数字并不总应被地址吸收。若该数字对应的 clue 也可能被 `StructuredStack` 识别为普通数字或字母数字实体，则地址栈不会立即强行扩展，而是：

1. 先构造一个保守候选；
2. 再构造一个扩展候选；
3. 通过 `PendingChallenge` 把争议 clue 交给 parser；
4. parser 调用 `StructuredStack` 判断它更像 `NUMERIC/ALNUM` 还是地址尾部；
5. 决定最终使用保守候选还是扩展候选。

这是一种典型的“**局部不确定 → 交给更合适的栈裁决**”设计。

---

## 15. 候选构造与输出元数据

### 15.1 候选边界

最终候选的字符边界并不直接取最后一个组件的 value，而是：

- `start = min(component.start)`
- `end = max(component.end)`

然后再对整段 `[start, end)` 执行 `clean_value`，以去除边缘空白、OCR gap token 和多余标点，最终生成 `CandidateDraft`。

### 15.2 证据阈值 `_meets_commit_threshold`

地址栈是否输出候选还取决于保护等级：

- `strong`：只要有证据即可；
- `balanced`：至少 2 个证据，或出现 `province/city` 这类强行政层；
- `weak`：至少 2 个证据。

因此，保护等级不仅影响替换决策，也反向影响检测器的保守程度。

### 15.3 地址 metadata

地址候选会输出较丰富的结构化 metadata，包括：

- `matched_by`
- `address_kind`
- `address_match_origin`
- `address_component_type`
- `address_component_trace`
- `address_component_key_trace`
- `address_details_type`
- `address_details_text`
- `address_component_suspected`

这组字段非常适合后续做：

- 归一化；
- placeholder 分配；
- session 级对齐；
- 论文中的可解释性展示。

---

## 16. 冲突裁决与回缩

### 16.1 parser 层的优先级裁决

若地址候选与姓名/组织候选重叠，则 parser 先比较：

1. `hard` vs `soft`；
2. 若都为 soft，则比较 `soft_priority`；
3. 若优先级相同，则用 `StackManager.score` 做最终裁决。

### 16.2 地址栈的 `shrink`

当地址栈作为失败方需要回缩时，会：

1. 按赢家的 unit 区间裁掉重叠部分；
2. 通过 `trim_candidate` 重新构造一个更短的地址候选；
3. 若剩余文本已不再具有地址信号，且也不是 label 驱动，则丢弃。

因此，地址候选不会在被裁掉关键部分后仍然盲目保留。

---

## 17. 与测试行为一致的典型案例

从 `tests/test_address_stack.py` 可以归纳出当前实现明确支持的行为：

1. **标签后 6-unit 内找不到地址 clue 时，不起栈**；
2. **“上海路”这类 city + road key 可合并为地址**；
3. **中间 negative 不一定杀死整条地址，只有污染到最右尾部时才做回退或删除**；
4. **道路后连续数字可被 `digit tail` 吸收**；
5. **同层级 VALUE 连续出现时，前一个可先落成组件，后一个继续作为新链起点**；
6. **POI 可延迟到后面的 road/buiding/detail 组件中被消费**；
7. **有逗号时允许“细地址 + 高层行政区”逆序补充，无逗号则不允许**。

这些测试说明该实现并非只覆盖理想正序地址，而是已显式考虑了 OCR 和自然语言中常见的“短地址、混合地址、逆序补充地址”场景。

---

## 18. 复杂度分析

设当前 run 实际扫描的 clue 数量为 `m`，最终组件数为 `k`。

### 18.1 主循环复杂度

在不考虑修复与挑战的普通情况下：

- 主循环为一次线性扫描，复杂度约为 `O(m)`；
- `_chain_can_accept`、`_segment_admit`、`_commit` 均为常数或很小的局部扫描；
- `_has_reasonable_successor_key` 与逗号尾预演会向右看一段 clue，但受 gap ≤ 6 units 和 break 约束，平均成本较低。

因此，正常路径可近似视为线性。

### 18.2 修复与 replay 成本

`negative tail repair` 可能对最右组件执行多次前缀重放，最坏情况下会带来额外的局部平方级代价；但其作用域只限于最右受污染组件，而不是全局全文本重解析，因此实际代价通常可控。

### 18.3 工程结论

该实现本质上是一种**低阶、局部回溯的状态机解析器**。相较于神经序列标注模型，它的复杂度更可控、解释性更强，适合端侧和规则增强场景。

---

## 19. 实现特征总结

从代码实现出发，PrivacyGuard 的中文地址 stack 具有以下特征：

### 19.1 优点

1. **可解释性强**：组件、suspected、trace、key_trace 都可直接输出；
2. **对 OCR 友好**：通过 `StreamUnit`、`inline_gap`、`ocr_break` 把视觉文本规约成可解析流；
3. **对中文短地址鲁棒**：允许 `city → road`、`district → road` 等非完整行政链；
4. **支持逆序补充**：通过逗号尾机制支持“细地址 + 高层行政区”写法；
5. **支持局部修复**：negative repair 与 digit tail challenge 使其不会因为一个边角错误而整段失效；
6. **与多栈协作良好**：parser 层统一做挑战与冲突消解。

### 19.2 局限

1. **规则复杂度高**：状态字段和分支较多，维护成本不低；
2. **对 clue 质量依赖较强**：若上游 scanner 的 component_type 给错，地址栈只能局部修补，不能完全纠正；
3. **强依赖局部启发式**：如“楼”“社区”的动态路由仍然是经验规则；
4. **长距离全局一致性有限**：当前主要在单个 run 内做结构恢复，不做更强的全局图优化；
5. **HARD 子分词仍依赖 matcher**：若词法资源不足，复杂地址的子组件召回仍可能受限。

---

## 20. 适合论文描述的算法总结

若用论文化的一句话概括当前实现，可以表述为：

> PrivacyGuard 的 rule-based 中文地址检测并非采用单步模式匹配，而是构建了一种基于 clue 序列的地址状态机解析器：系统先将 prompt/OCR 文本归一为 unit 流与地址线索，再由 AddressStack 在局部上下文内执行链式吸收、组件提交、逗号逆序补全、疑似行政层延迟落地、负向尾部修复以及尾数字挑战裁决，最终输出带有组件轨迹和 suspected 行政层信息的结构化地址候选。

进一步写成论文中的“方法贡献”语言，则可归纳为三点：

1. **线索驱动的组件化地址解析**：以 `VALUE/KEY/LABEL` clue 为中间层，而非直接在原文本上做端到端切分；
2. **兼顾中文地址变体的状态机设计**：通过后继图、逗号尾、动态 key 重路由与 digit tail，覆盖更广泛的真实地址书写方式；
3. **面向端侧隐私保护的可解释输出**：候选不仅包含最终地址 span，还输出组件级 trace 与 suspected 元数据，便于后续匿名化、还原与会话一致性维护。

---

## 21. 结论

总体上，PrivacyGuard 当前的 `AddressStack` 已经不是一个简单的“中文地址规则表”，而是一套较为完整的地址片段解析框架。它以统一 clue 序列为输入，以状态机和组件图为核心中间表示，以局部修复和跨栈挑战为补充机制，最终输出可直接供后续匿名化与恢复模块使用的地址候选。对于你的论文写作而言，这一实现非常适合被表述为：

- 一个**面向 GUI/OCR 场景的规则型地址结构恢复算法**；
- 一个**轻量、可解释、可工程部署**的端侧地址检测模块；
- 一个**可与 de-model 或后续决策模块解耦协作**的 PII 前端解析器。

如果后续继续扩展到论文正文，建议把本实现拆成三个子节书写：

1. 文本流与 clue 构造；
2. 地址 stack 状态机；
3. 负向修复与 digit tail 挑战。

这样最符合当前代码的真实结构，也最利于审稿人理解其工程与算法价值。

---

## 附录 A：核心源码路径

- `privacyguard/infrastructure/pii/detector/rule_based.py`
- `privacyguard/infrastructure/pii/detector/parser.py`
- `privacyguard/infrastructure/pii/detector/preprocess.py`
- `privacyguard/infrastructure/pii/detector/models.py`
- `privacyguard/infrastructure/pii/detector/stacks/base.py`
- `privacyguard/infrastructure/pii/detector/stacks/registry.py`
- `privacyguard/infrastructure/pii/detector/stacks/address.py`
- `privacyguard/infrastructure/pii/detector/candidate_utils.py`
- `tests/test_address_stack.py`

## 附录 B：适合直接放进论文的方法伪代码

```text
Algorithm 1: AddressStack Parsing
Input: stream X, clue sequence C, seed clue c_s
Output: address candidate A or None

1: initialize parse state S
2: determine address_start from seed c_s
3: for each clue c_i after seed do
4:     if c_i is BREAK then stop
5:     if c_i is NEGATIVE then record negative span and continue
6:     if c_i is non-address but absorbable digit then absorb and continue
7:     if c_i is NAME/ORG and can be crossed safely then suppress challenger and continue
8:     if c_i is ADDRESS clue then
9:         dynamically reroute key type if necessary
10:        handle comma-tail precheck
11:        if c_i is VALUE then
12:            if current chain cannot accept c_i then flush current chain
13:            if c_i conflicts with current segment order then
14:                if c_i has a reasonable successor key then defer as plain text
15:                else split and stop
16:            else append c_i into deferred chain
17:        else if c_i is KEY then
18:            if current chain can accept c_i then append and continue
19:            else flush chain first
20:            if c_i has valid left value then defer key into chain
21:            else if c_i is prefix-key then build direct component
22:            else ignore this key
23: flush remaining chain
24: repair rightmost components if negative spans overlap
25: fixup suspected admin clues
26: analyze digit tail and optionally create pending challenge
27: if evidence threshold satisfied then build candidate A
28: return A
```
