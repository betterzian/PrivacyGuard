# 跨 OCR Inline Gap 匹配实现计划



## Context



OCR 拼接流程在同一 chunk 内相邻 block 之间插入 `inline_gap`（U+E000）。Scanner Pass 2 已经能剥离 gap 让**单个 clue** 跨 block 被发现，但 **stack 扩展阶段**把 `inline_gap` 当硬墙——无法将多个 clue 跨 gap 合并为完整候选。本次改动让三个 stack（Address / Name / Organization）能穿越 `inline_gap`，同时保持 `ocr_break` 作为不可穿越的硬墙。



---



## 修改文件与具体改动



### 1. `stacks/common.py` — 新增共用 helper



**A. `_gap_is_soft(units, start_ui, end_ui) -> bool`**

- 检查 `[start_ui, end_ui)` 范围内所有 unit 是否仅为 `"space"` 或 `"inline_gap"`。

- 遇到 `ocr_break` / `punct` / 内容 unit → `False`；空范围 → `True`。



**B. `_count_content_units(units, start_ui, end_ui) -> int`**

- 统计范围内 kind 不属于 `{"space", "inline_gap"}` 的 unit 数量。

- 与现有 `_count_non_space_units` 同构，多排除 `inline_gap`。



---



### 2. `stacks/address.py` — 三处改动



**C. 扩展循环 gap 阈值（line 272-275）**



```python

# 现行：

if clue.unit_start - gap_anchor > 6:

    break



# 改为：用 _count_content_units 排除 space 和 inline_gap 后再比阈值

if _count_content_units(self.context.stream.units, gap_anchor, clue.unit_start) > 6:

    break

```



需在 import 区新增 `_count_content_units`。



**D. `_address_gap_too_wide()`（line 615-627）**



```python

# 现行 line 618：

if OCR_BREAK in gap_text or _OCR_INLINE_GAP_TOKEN in gap_text:

    return True



# 改为：

if OCR_BREAK in gap_text:

    return True

# 最多允许穿越 1 个 inline_gap

if gap_text.count(_OCR_INLINE_GAP_TOKEN) > 1:

    return True

# 剥离 inline_gap 后再做长度/词数判断

gap_text = gap_text.replace(_OCR_INLINE_GAP_TOKEN, "")

if not gap_text:

    return False

```



后续的 `punct_count` / 长度检查保持不变，作用于已剥离 gap 的文本。



**E. `_build_value_key_component()` value-key 间隔（line 630-649）**



- 英文分支：`_EN_VALUE_KEY_GAP_RE`（line ~143）改为 `re.compile(r"^[ \uE000]*$")`，允许 gap token 出现。

- 中文分支（line 649 `else: return None, False`）：先剥离 `_OCR_INLINE_GAP_TOKEN` 和空格，剥离后为空则放行。



---



### 3. `stacks/name.py` — 两处改动



**F. `_gap_allows_single_plain_word()`（line 352-374）**



```python

# line 364，现行：

if unit.kind == "space":

# 改为：

if unit.kind in {"space", "inline_gap"}:

```



让 inline_gap 像空格一样透明。



**G. `_previous_plain_ascii_word()`（line 376-392）**



- line 381：`units[ui].kind == "space"` → `units[ui].kind in {"space", "inline_gap"}`

- line 390：`gap_unit.kind != "space"` → `gap_unit.kind not in {"space", "inline_gap"}`



---



### 4. `stacks/organization.py` — 一处改动



**H. `_resolve_label_upper_boundary()`（line 139）**



```python

# 现行：

if unit.kind in {"inline_gap", "ocr_break"}:

    return unit.char_start



# 改为：仅 ocr_break 是硬墙

if unit.kind == "ocr_break":

    return unit.char_start

```



---



## 实施顺序



1. `common.py` — 新增 `_gap_is_soft` + `_count_content_units`

2. `address.py` — 改动 C、D、E + 更新 import

3. `name.py` — 改动 F、G

4. `organization.py` — 改动 H

5. 跑现有测试确认无回归



## 验证



```bash

C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/ -x -q

```



- 现有测试全部通过 = 无回归

- `ocr_break` 仍是硬墙（现有测试应已覆盖）



## 风险



- **Address 扩展循环语义微调**：从"unit 索引差"改为"内容 unit 计数"，原有含空格的 gap 计数方式会变。如测试回归，退路是只排除 `inline_gap` 不排除 `space`：`kind not in {"inline_gap"}`。

- **误扩展**：穿越 gap 后可能合并不相关内容。缓解措施：(a) address 限制最多穿越 1 个 gap，(b) 邻接表、component 排序等结构约束不变，(c) ocr_break 仍为硬墙。

