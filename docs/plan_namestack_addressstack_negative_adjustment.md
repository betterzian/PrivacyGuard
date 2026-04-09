# NameStack & AddressStack Negative 处理调整计划书

> 日期：2026-04-09
> 项目：PrivacyGuard
> 范围：NameStack 强信号豁免 / AddressStack 右弹逻辑修正 / 词表清理与扩张

---

## 一、总览

| 阶段 | 内容 | 文件 | 可并行 |
|------|------|------|--------|
| **A** | 词表清理 + 百家姓扩张 | `negative_name_words.json`, `negative_address_words.json` | ✅ |
| **B** | AddressStack 改为"只检查最右组件" | `address.py` | ✅ |
| **C** | NameStack 强信号 seed 豁免 negative | `name.py` | ✅ |
| **D** | 测试补全 | `test_name_stack.py`, `test_address_stack.py` | 依赖 A/B/C |

A、B、C 三个阶段互相独立，可以并行。D 在三者完成后执行。

---

## 二、问题背景

### 2.1 NameStack — Negative 三重阻断过于激进

NameStack 中 negative 有三重独立阻断机制：

```
┌─────────────────────────────────────────────────────────────────┐
│ (A) _is_name_blocker: NEGATIVE 阻止 name span 向右扩展         │
│ (B) _has_active_stop_overlap: cursor 在 negative 内 → 立即停止 │
│ (C) _meets_commit_threshold: span 内有 negative → 绝对否决      │
│     例外：FULL_NAME / ALIAS 完全跳过 (C)                        │
└─────────────────────────────────────────────────────────────────┘
```

即使有 START（如"我叫"）或 LABEL（如"收件人"）这种强信号，也无法穿透 negative 否决：

| 场景 | 当前结果 | 期望结果 |
|------|---------|---------|
| 我叫张力 | ❌ 丢失（neg「张力」阻断） | ✅ 识别 |
| 收件人：孟子轩 | ❌ 丢失（neg「孟子」阻断，GIVEN「子轩」也因重叠被否决） | ✅ 识别 |
| 我叫王国庆 | ❌ 丢失（neg「王国」阻断） | ✅ 识别 |
| 用户许可欣已激活 | ❌ 两条路径全部堵死 | ✅ 识别 |
| 张力是一种物理量 | ✅ 正确拒绝 | ✅ 维持拒绝 |
| 高兴地说 | ✅ 正确拒绝 | ✅ 维持拒绝 |

**致命边界 Case「收件人：孟子轩」推演**：

```
1. LABEL seed → start=4, expand_seed_right
2. 处理 FAMILY_NAME「孟」→ cursor=5
3. cursor=5: _has_active_stop_overlap(5) → neg「孟子」[4,6): 4<5<6 → YES → return 5
4. candidate='孟', neg overlap → 拒绝
5. GIVEN_NAME「子轩」[5,7) 单独作为 seed:
   → neg「孟子」[4,6) 与 [5,7) 重叠（5<6）→ 也被拒绝
6. 两条识别路径全部堵死
```

### 2.2 AddressStack — 右弹逻辑检查整体 span 导致误杀

当前 `_pop_components_overlapping_negative` 检查所有组件的 **OVERALL span** 是否与 negative 重叠，然后从最右开始弹出：

```
┌──────────────────────────────────────────────────────────────────────┐
│ while components:                                                    │
│   overall_span = [min_start, max_end)   ← 检查整体                  │
│   if overall_span 不与任何 negative 重叠:                            │
│     return components                                                │
│   pop(最右 component)                   ← 弹出最右                   │
└──────────────────────────────────────────────────────────────────────┘
```

中间的 negative 会连带弹出右侧无辜组件：

| 场景 | 当前结果 | 期望结果 |
|------|---------|---------|
| 上海市中心路109号 + neg「市中心」 | ❌ 全部弹出，地址丢失 | ✅ 全保留（109号干净） |
| 北京市朝阳区建国路88号 + neg「建国」 | [北京市, 朝阳区]（丢失路和号） | ✅ 全保留（88号干净） |
| 朝阳路由用户反馈 + neg「路由」 | ❌ 全丢 | ❌ 全丢（正确！） |

**推演「上海市中心路109号」+ neg「市中心」(2,5)**：

```
第1步: span=[0,10) → 与 neg(2,5) 重叠 → 弹出 109号[6,10)
第2步: span=[0,6)  → 与 neg(2,5) 重叠 → 弹出 中心路[3,6)
第3步: span=[0,3)  → 与 neg(2,5) 重叠 → 弹出 上海市[0,3)
结果: 全部弹出 → 地址丢失 ❌
```

正确设计意图：**看号没有命中 negative 则认为是地址**——即只检查最右组件。

---

## 三、阶段 A — 词表清理与百家姓扩张

### A1. `negative_address_words.json` 移除 3 条

| 条目 | 移除原因 |
|------|---------|
| `"工作室"` | 与 `company_suffixes.json` 矛盾，org stack 需要它做后缀匹配 |
| `"实验室"` | 同上 |
| `"市中心"` | 跨层级 negative，会摧毁「上海市中心路109号」这类真实地址 |

### A2. `negative_name_words.json` 移除 3 条

| 条目 | 移除原因 |
|------|---------|
| `"沈阳"` | 真实地名，在 `zh_geo_lexicon.json` 中存在 |
| `"苏州"` | 同上 |
| `"白云"` | 同上，白云区是真实行政区 |

### A3. `negative_name_words.json` 新增约 215 条

在中文段末尾（英文段之前）追加百家姓常用词块。覆盖重点姓氏：

| 姓氏 | 当前 neg 数 | 拟新增数 | 典型新增词 |
|------|-----------|---------|-----------|
| 华 | 0 | 12 | 华丽、华人、华语、华裔、繁华、精华、豪华、年华、才华、中华、华夏、华侨 |
| 封 | 0 | 9 | 封面、封装、封锁、封闭、封号、封存、密封、信封、封印 |
| 单 | 3 | 10 | 单纯、单一、单调、单打、单向、单身、简单、清单、菜单、单项 |
| 平 | 9 | 10 | 平价、平坦、平滑、平行、平庸、平板、平民、平凡、平淡、平息 |
| 明 | 3 | 10 | 明白、明星、明朗、明智、明年、明理、说明、证明、文明、光明 |
| 成 | 4 | 8 | 成绩、成果、成交、成熟、成长、成立、成分、成就 |
| 卫 | 0 | 8 | 卫生、卫星、卫浴、卫士、守卫、防卫、自卫、保卫 |
| 范 | 2 | 8 | 范畴、范例、规范、典范、范文、模范、示范、防范 |
| 金 | 4 | 8 | 金钱、金库、金条、金价、金矿、金色、金子、金银 |
| 高 | 9 | 8 | 高频、高质量、高性能、高分、高清、高压、高手、高原 |
| 水 | 9 | 8 | 水位、水利、水费、水泥、水量、水压、水管、水质 |
| 景 | 0 | 7 | 景色、景点、景观、风景、前景、景象、场景 |
| 安 | 5 | 7 | 安心、安居、安慰、安定、安置、安稳、安保 |
| 姜 | 0 | 6 | 姜黄、姜茶、姜汁、生姜、姜片、老姜 |
| 孔 | 0 | 6 | 孔雀、孔径、孔洞、通孔、打孔、气孔 |
| 温 | 5 | 6 | 温差、温控、温柔、温文、温室、温热 |
| 史 | 0 | 6 | 史料、史诗、史前、史册、史实、史学 |
| 陶 | 0 | 5 | 陶瓷、陶艺、陶器、陶醉、熏陶 |
| 符 | 0 | 5 | 符号、符合、符文、音符、不符 |
| 花 | 2 | 5 | 花纹、花瓣、花卉、花圃、花束 |
| 池 | 1 | 5 | 池化、池子、水池、电池、池水 |
| 常 | 3 | 5 | 常态、常识、常年、常驻、常理 |
| 云 | 6 | 5 | 云盘、云平台、云数据、云部署、云架构 |
| 石 | 7 | 4 | 石化、石碑、石板、石窟 |
| 白 | 3 | 4 | 白班、白费、白搭、白板 |
| 任 | 3 | 4 | 任职、任命、任期、任性 |
| 万 | 3 | 6 | 万能、万岁、万千、万物、万分、万事 |
| 龙 | 6 | 3 | 龙门、龙脉、龙骨 |
| 丁 | 1 | 3 | 丁点、补丁、园丁 |
| 易 | 1 | 3 | 容易、易懂、易碎 |
| 路 | 5 | 7 | 路口、路段、路上、路面、路况、路标、路人 |
| 向 | 3 | 2 | 向量、向导 |
| 马 | 2 | 2 | 马力、马虎 |
| 柴 | 0 | 2 | 柴油、柴火 |
| 尤 | 0 | 2 | 尤其、尤为 |
| 李 | 0 | 2 | 李子、李白酒 |
| 刘 | 0 | 1 | 刘海 |
| 侯 | 2 | 1 | 侯门 |
| 牛 | 6 | 1 | 牛顿 |

**新增后仍无覆盖的 233 个姓氏**（褚、蒋、吕、魏…）极少有常见非人名词汇以它们开头，不需要 negative 保护。

---

## 四、阶段 B — AddressStack 改为"只检查最右组件"

### 修改目标

**文件**: `privacyguard/infrastructure/pii/detector/stacks/address.py`
**函数**: `_pop_components_overlapping_negative`（约 line 553-566）

### 当前实现

```python
def _pop_components_overlapping_negative(
    components: list[dict[str, object]],
    negative_spans: list[tuple[int, int]],
) -> list[dict[str, object]]:
    ordered = list(components)
    while ordered:
        final_start = min(int(c["start"]) for c in ordered)
        final_end = max(int(c["end"]) for c in ordered)
        if not _overlaps_any_span(final_start, final_end, negative_spans):
            return ordered
        ordered.sort(key=lambda c: (int(c["end"]), int(c["start"])))
        ordered.pop()
    return []
```

### 新实现

```python
def _pop_components_overlapping_negative(
    components: list[dict[str, object]],
    negative_spans: list[tuple[int, int]],
) -> list[dict[str, object]]:
    """弹出被 negative 覆盖的最右组件，直到最右组件干净或无组件。"""
    ordered = sorted(components, key=lambda c: (int(c["end"]), int(c["start"])))
    while ordered:
        last = ordered[-1]
        if not _overlaps_any_span(int(last["start"]), int(last["end"]), negative_spans):
            return ordered                          # 最右组件干净 → 全部保留
        ordered.pop()                               # 最右被污染 → 弹出
    return []
```

### 变更要点

- 仅检查**最右组件本身**是否与 negative 重叠，而非整体 span。
- 中间的 negative 不会连锁弹出右侧无辜组件。
- 最右组件被 negative 覆盖时仍然正确弹出（如「朝阳路由用户反馈」）。

### 场景效果对比

| 场景 | 方案 A（当前） | 方案 D（改后） | 正确答案 |
|------|-------------|-------------|---------|
| 人民路123号（无 neg） | ✅ 全保留 | ✅ 全保留 | 全保留 |
| 上海市中心路109号 + neg「市中心」 | ❌ 全丢 | ✅ 全保留 | 全保留 |
| 北京市朝阳区建国路88号 + neg「建国」 | [京,朝] | ✅ 全保留 | 全保留 |
| 朝阳路由用户反馈 + neg「路由」 | ❌ 全丢 | ❌ 全丢 | 正确丢弃 |
| 长安街道办事处 + neg「街道」 | ❌ 全丢 | ❌ 全丢 | 正确丢弃 |
| 中关村大街23号楼1103室（无 neg） | ✅ 全保留 | ✅ 全保留 | 全保留 |

---

## 五、阶段 C — NameStack 强信号 seed 豁免 negative

### 修改目标

**文件**: `privacyguard/infrastructure/pii/detector/stacks/name.py`

需要协调修改三重阻断机制，共涉及 **6 个函数 + 1 个调用点**。

### C1. `_is_name_blocker` 增加 `ignore_negative` 参数

**位置**: 约 line 314-319
**作用**: 解除机制 (A)——让 NEGATIVE 在有强 seed 时不再阻止右扩展边界计算。

```python
# 当前
def _is_name_blocker(self, clue: Clue) -> bool:
    if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR}:
        return True
    if clue.attr_type is None:
        return False
    return clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES

# 改为
def _is_name_blocker(self, clue: Clue, *, ignore_negative: bool = False) -> bool:
    if clue.role == ClueRole.NEGATIVE:
        return not ignore_negative
    if clue.role in {ClueRole.BREAK, ClueRole.CONNECTOR}:
        return True
    if clue.attr_type is None:
        return False
    return clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES
```

### C2. `_has_active_stop_overlap` 增加 `ignore_negative` 参数

**位置**: 约 line 308-312
**作用**: 解除机制 (B)——让 cursor 在 NEGATIVE span 内部时不再立即停止扩展。

```python
# 当前
def _has_active_stop_overlap(self, cursor: int) -> bool:
    for clue in self.context.clues:
        if clue.start < cursor < clue.end and self._is_name_blocker(clue):
            return True
    return False

# 改为
def _has_active_stop_overlap(self, cursor: int, *, ignore_negative: bool = False) -> bool:
    for clue in self.context.clues:
        if clue.start < cursor < clue.end and self._is_name_blocker(clue, ignore_negative=ignore_negative):
            return True
    return False
```

### C3. `_find_next_right_blocker` 增加 `ignore_negative` 参数

**位置**: 约 line 299-306

```python
# 当前
def _find_next_right_blocker(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
    for index in range(search_index, len(self.context.clues)):
        clue = self.context.clues[index]
        if clue.start < cursor:
            continue
        if self._is_name_blocker(clue):
            return (index, clue)
    return None

# 改为
def _find_next_right_blocker(self, cursor: int, search_index: int, *,
                              ignore_negative: bool = False) -> tuple[int, Clue] | None:
    for index in range(search_index, len(self.context.clues)):
        clue = self.context.clues[index]
        if clue.start < cursor:
            continue
        if self._is_name_blocker(clue, ignore_negative=ignore_negative):
            return (index, clue)
    return None
```

### C4. `_expand_seed_right` 增加 `ignore_negative` 参数

**位置**: 约 line 131-176

```python
# 改为（仅展示签名和透传点）
def _expand_seed_right(
    self,
    *,
    start: int,
    end: int,
    search_index: int,
    locale: str,
    ignore_negative: bool = False,          # ← 新参数
) -> int:
    cursor = end
    next_index = search_index
    while True:
        if self._has_active_stop_overlap(cursor, ignore_negative=ignore_negative):  # ← 透传
            return cursor

        next_component = self._find_next_component_clue(cursor, next_index)
        next_blocker = self._find_next_right_blocker(
            cursor, next_index, ignore_negative=ignore_negative)                    # ← 透传
        # ... 其余逻辑不变 ...
```

### C5. `run()` 中为 LABEL/START 传入 `ignore_negative=True`

**位置**: 约 line 41-51

```python
# 当前
if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
    start = _skip_separators(self.context.stream.text, self.clue.end)
    if start >= len(self.context.stream.text):
        return None
    end = self._expand_seed_right(
        start=start,
        end=start,
        search_index=self.clue_index + 1,
        locale=locale,
    )
    return self._build_name_run(start=start, end=end)

# 改为
if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
    start = _skip_separators(self.context.stream.text, self.clue.end)
    if start >= len(self.context.stream.text):
        return None
    end = self._expand_seed_right(
        start=start,
        end=start,
        search_index=self.clue_index + 1,
        locale=locale,
        ignore_negative=True,               # ← 新增
    )
    return self._build_name_run(start=start, end=end)
```

> **FAMILY_NAME、GIVEN_NAME 路径不变**，保持 `ignore_negative=False`（默认值）。

### C6. `_meets_commit_threshold` 绝对否决改为条件否决

**位置**: 约 line 393-410

```python
# 当前
def _meets_commit_threshold(
    self,
    *,
    candidate_text: str,
    clue_count: int,
    negative_count: int,
    name_clues: list[tuple[int, Clue]],
) -> bool:
    if negative_count > 0:
        return False                    # ← 绝对否决
    # ... protection_level 判断 ...

# 改为
def _meets_commit_threshold(
    self,
    *,
    candidate_text: str,
    clue_count: int,
    negative_count: int,
    name_clues: list[tuple[int, Clue]],
    strong_seed: bool = False,          # ← 新参数
) -> bool:
    if negative_count > 0:
        if not strong_seed:
            return False                # 无强 seed → 维持绝对否决
        # 有 LABEL/START 强 seed → negative 被上下文信号覆盖，继续正常阈值检查
    # ... 后续 protection_level 判断不变 ...
```

### C7. `_build_name_run` 调用处传入 `strong_seed`

**位置**: 约 line 101-107

```python
if self.clue.role not in {ClueRole.FULL_NAME, ClueRole.ALIAS} and not self._meets_commit_threshold(
    candidate_text=candidate.text,
    clue_count=clue_count,
    negative_count=negative_count,
    name_clues=name_clues,
    strong_seed=self.clue.role in {ClueRole.LABEL, ClueRole.START},  # ← 新增
):
    return None
```

### 改后效果推演

| 场景 | 机制(A)(B) | 机制(C) | 结果 |
|------|-----------|---------|------|
| 我叫张力 (START) | neg 不阻断 → candidate=「张力」 | strong_seed → 跳过否决 | ✅ 识别 |
| 收件人：孟子轩 (LABEL) | neg 不阻断 → 消费 FAMILY+GIVEN → candidate=「孟子轩」 | strong_seed → 跳过 | ✅ 识别 |
| 我叫王国庆 (START) | neg「王国」不阻断 → candidate=「王国庆」 | strong_seed → 跳过 | ✅ 识别 |
| 用户许可欣 (LABEL) | neg 不阻断 → candidate=「许可欣」 | strong_seed → 跳过 | ✅ 识别 |
| 联系人张力手机号... (LABEL) | neg 不阻断 → candidate=「张力」 | strong_seed → 跳过 | ✅ 识别 |
| 黄金华女士 (FAMILY_NAME) | ignore_negative=False → neg 阻断 | strong_seed=False → 否决 | ❌ 仍丢失 |
| 张力是物理量 (FAMILY_NAME) | 同上 | 同上 | ✅ 正确拒绝 |
| 高兴地说 (FAMILY_NAME) | 同上 | 同上 | ✅ 正确拒绝 |
| FULL_NAME「张力」 | 不经过 expand | 跳过 threshold | ✅ 识别（已有行为不变） |

---

## 六、阶段 D — 测试补全

### D1. NameStack 新增测试用例

| 用例 | 输入 | 期望 |
|------|------|------|
| `test_start_seed_overrides_negative_same_length` | "我叫张力" START + neg「张力」 | 候选「张力」被识别 |
| `test_label_seed_overrides_negative_prefix` | "收件人：孟子轩" LABEL + neg「孟子」+ GIVEN「子轩」 | 候选「孟子轩」被识别 |
| `test_start_seed_overrides_三字名_prefix_neg` | "我叫王国庆" START + neg「王国」 | 候选「王国庆」被识别 |
| `test_label_seed_overrides_negative_许可欣` | "用户许可欣" LABEL + neg「许可」+ GIVEN「可欣」 | 候选「许可欣」被识别 |
| `test_family_name_seed_still_blocked` | "张力是物理量" FAMILY_NAME「张」+ neg「张力」 | None（不变） |
| `test_no_seed_negative_blocks` | "高兴地说" FAMILY_NAME「高」+ neg「高兴」 | None（不变） |

### D2. AddressStack 新增测试用例

| 用例 | 输入 | 期望 |
|------|------|------|
| `test_middle_neg_does_not_pop_rightmost` | 组件 [上海市, 中心路, 109号] + neg(2,5) | 全部保留 |
| `test_rightmost_neg_pops_correctly` | 组件 [朝阳路] + neg(2,4) | 全部弹出（正确） |
| `test_neg_on_middle_component_keeps_all` | 组件 [北京市, 朝阳区, 建国路, 88号] + neg(6,8) | 全部保留 |

### D3. 回归验证

```bash
C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/test_name_stack.py tests/test_address_stack.py -v
```

确保以下已有测试仍然通过：
- NameStack 中 FAMILY_NAME seed 的 negative 否决测试
- AddressStack 中最右组件被 negative 覆盖的弹出测试
- FULL_NAME / ALIAS 绕过 negative 的测试

---

## 七、风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| LABEL/START 强信号过度信任（如「收件人：高兴」被误识别为姓名） | 中 | 低 | `_meets_commit_threshold` 仍有 `clue_count` / `protection_level` 门槛；纯 FAMILY_NAME 无 GIVEN_NAME 支撑时，在 WEAK/BALANCED 下仍被门槛拦截 |
| AddressStack 中间 neg 被忽略导致假阳性地址 | 低 | 低 | 中间组件已被 scanner 识别为合法地址组件；negative 的核心目的是阻止右边界误延伸 |
| `ignore_negative` 参数穿透 4 个函数，增加 API 复杂度 | — | 低 | 所有参数默认 `False`，不影响 FAMILY_NAME / GIVEN_NAME 现有路径；无存量调用需要修改 |
| FAMILY_NAME 路径仍无法识别「黄金华」这类无 seed 的真名 | 中 | 中 | 仅限 negative 恰好是姓名前缀的情况（0.08%），可通过将高频冲突名（黄金华、张力等）加入 `full_name` 词表来补救 |

---

## 八、修改文件总清单

| 文件 | 阶段 | 变更类型 |
|------|------|---------|
| `data/scanner_lexicons/negative_address_words.json` | A | 删除 3 条 |
| `data/scanner_lexicons/negative_name_words.json` | A | 删除 3 条，新增约 215 条 |
| `privacyguard/infrastructure/pii/detector/stacks/address.py` | B | 修改 `_pop_components_overlapping_negative` 函数体 |
| `privacyguard/infrastructure/pii/detector/stacks/name.py` | C | 修改 6 个函数签名/逻辑 + 1 个调用点 |
| `tests/test_name_stack.py` | D | 新增 6 个测试用例 |
| `tests/test_address_stack.py` | D | 新增 3 个测试用例 |
