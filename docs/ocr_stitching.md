# OCR 文本拼接算法说明

本文描述仓库中 **`build_ocr_stream`** 将若干 `OCRTextBlock` 排成阅读流、划分 **chunk**、并生成 **raw/clean 流** 的算法。实现位于 [`privacyguard/infrastructure/pii/detector/preprocess.py`](../privacyguard/infrastructure/pii/detector/preprocess.py)。

---

## 1. 算法思想

1. **块即结点**  
   每个带 bbox、非空文本的块参与构图与合并；输出为若干 **chunk**（语义上可串成一段连续阅读顺序）。**chunk 之间**插入硬断点 **`OCR_BREAK`**；**chunk 内**相邻块之间插入 **`inline_gap`**（私有区字符，与下游扫描器、词典匹配约定一致）。

2. **合并前的静态图**  
   在尚未按阅读流从池中删除块之前，对**全量**块预计算：
   - **链 A**：与 `cur` 在 **y 轴有正重叠** 且 **严格** 在 `cur` 右边界右侧的块；候选间排序：若两候选 **y 无重叠** 则 **y 起小** 优先，若 **y 有重叠** 则 **x 小** 优先，再 `block_id` / `id` 决胜；
   - **链 B（静态）**：在 `cur` **下方**（顶边不低于 `cur` 底边）且 **`|v.x − cur.x| ≤ max(h_cur, h_v)`** 的块，排序。  
   据此构造**有向边**：从块 `u` 指向 **`A(u)` 的第一个元素**（若存在），以及 **`B_static(u)` 中的每一个**元素，得到后继集合与**入度**。入度为 0 表示「未被任何块的 A 首元或静态 B 指向」，即可作为**本段起点候选**。

3. **多段 chunk 主循环**  
   剩余池非空时：在**剩余块中入度为 0** 的子集里取 **阅读序最小** 作为本段起点；若不存在入度 0 的块则抛出 **`OCRSemanticChunkGraphError`**（不回落到全局阅读序最小）。段间**不再**根据上一段链首锚点强行指定下一段起点。

4. **单段内展开**（递归 + 外层轮询）  
   维护本段全局列表 **`chain`**（已按拼接顺序并入的块）。反复执行：
   - **链 A 阶段（仅行内）**：当前块 `cur` 只在预计算 **`A(cur)`** 中取**第一个仍在池内**的候选 `fa`；**仅当** **`_can_merge_same_line_adjacent(cur, fa)`** 为真才合并。**此阶段不用链 B，也不对 A 候选使用跨行规则。**
   - **链 A 无法再延伸后**，对**当前整条 `chain`** 上每个块取**合并前预计算的链 B**，做**并集**、按块 `id` **去重**，且只保留仍在**剩余池**中的块，再按阅读键排序，即 **`_below_list_for_semantic_chain`**；将该列表对象赋给当前**同行 row** 中每一块的 **`mutable_b`**（**共享同一 `list`**）。
   - **链 B 阶段**：按序扫描该列表；以当前**链尾** `cur_tail` 与候选 `e` 判断 **`_can_merge_space_between_ordered`**（允许**同行或跨行**）；若可合并则并入 `chain`、出池，并对 `e` **递归**进入同一套「先 A 后 B」。若本轮 B 中有任一成功，则将 **`cur` 置为本轮最终链尾**、`row = [该链尾]`，回到**外层**下一轮（再次先做链 A）。

5. **静态 B 与运行期 B**  
   初值 **`mutable_b[u]`** 来自静态 **`B_static(u)`** 的拷贝；运行中会被 **``⋃_{u∈chain} B_static(u)``**（去重、限剩余池）重算结果覆盖。**建图用入度**仅依赖**初始**静态 A/B，中途不因 `mutable_b` 刷新而重算。

6. **流生成**  
   **`_build_stream_from_chunks`**：chunk 内块按顺序拼接；相邻块之间 raw/clean 使用 **`inline_gap`**（标点相邻时不插 gap 等规则见 `_join_clean_blocks_ocr_inline` / `_prepare_ocr_block_text`）；chunk 之间写入 **`OCR_BREAK`**。

---

## 2. 步骤与代码对应（简表）

| 阶段 | 行为 |
|------|------|
| 输入 | `_build_ocr_stream`：`materialized` = 有文本且 `bbox != None` |
| 预处理 | `_build_recursive_ocr_chunks`：`pre_a`、`pre_b_static`；`succ`、`indeg`；`mutable_b` 初值 |
| 段起点 | 仅在 `indeg==0` 的剩余块中取阅读序最小，否则 **`OCRSemanticChunkGraphError`** |
| 段展开 | `_space_expand_chain_from_start` → `_expand_semantic_from_block_precomputed` |
| 流 | `_build_stream_from_chunks(chunks)` → `PreparedOCRContext` |

---

## 3. 可合并判定（摘要）

- **`_can_merge_same_line_adjacent`（链 A 专用）**  
  `y` 轴开区间有重叠；高度相对差 \< 10%；水平间隙 `gap_x ≤ 0.5 * max(h)`。

- **`_can_merge_space_between_ordered`（链 B 与链尾）**  
  若行内相邻成立则接受；否则 **`_can_merge_across_lines`**：垂距上界、行高代表值一致度、**两行最小左缘 x 之差** 不超过阈值等（见源码）。

---

## 4. 伪代码

下文与实现同名函数对应，仅省略 Python 细节。

```
BuildOCRStream(blocks):
    materialized ← 过滤（非空文本且 bbox 存在）
    若 materialized 为空 → 返回空 PreparedOCRContext
    chunks ← BuildRecursiveChunks(materialized)
    返回 BuildStreamFromChunks(chunks)

BuildRecursiveChunks(materialized):
    对每块 u:
        A[u] ← { v | v 与 u 的 y 正重叠 且 v.x > u 右界 }，按「候选两两 y 不重叠则比 y 起，否则比 x」排序
        B0[u] ← { v | v.y ≥ u 底 且 |v.x−u.x| ≤ max(h_u,h_v) } 排序
    对每块 u:
        succ[u] ← { A[u] 首元（若存在） } ∪ { v | v ∈ B0[u] }
        indeg[v] += 1（对 succ[u] 中每个 v，可用集合去重边）
    remaining ← 所有块 id
    mutableB[u] ← copy(B0[u])

    chunks ← ∅
    while remaining 非空:
        Z ← { id ∈ remaining | indeg[id] = 0 }
        if Z = ∅ → raise OCRSemanticChunkGraphError
        start ← ReadingMin( Z 映射回块 )

        chain ← SpaceExpandFromStart(start, remaining, indeg, succ, A, mutableB, …)
        chunks.append(chain)

    return chunks

SpaceExpandFromStart(start, …):
    chain ← [start]
    RemoveFromPool(start)  // remaining 删除、对 succ[start] indeg--
    ExpandSemantic(start, chain, …)
    return chain

ExpandSemantic(entry, chain, …):
    cur ← entry
    row ← [entry]
    loop:
        // 链 A：仅行内；只取 A[cur] 中第一个仍在池内的 fa
        loop:
            fa ← FirstInPool(A[cur], remaining)
            if fa = ∅ or not SameLineAdjacent(cur, fa):
                break
            chain.append(fa); RemoveFromPool(fa)
            cur ← fa; row.append(fa)

        newB ← BelowFromSemanticChain(chain, remaining)
        for m in row: mutableB[m] ← newB   // 同一 list 引用

        curTail ← cur
        any ← false
        for e in newB:  // 有序
            if e ∉ remaining: continue
            if not MergeableOrdered(curTail, e): continue
            chain.append(e); RemoveFromPool(e)
            ExpandSemantic(e, chain, …)
            curTail ← chain 最后一个
            any ← true
        if any:
            cur ← curTail; row ← [curTail]
        else:
            break

BelowFromSemanticChain(chain, remaining, B0):
    cand ← ∅
    seen ← ∅
    for u in chain:
        for v in B0[u]:
            if id(v) ∈ remaining and id(v) ∉ seen:
                seen.add(id(v)); cand.append(v)
    return SortByReadingKey(cand)
```

**说明**

- **`RemoveFromPool`**：从 `remaining` 去掉块 id，并对该块的 `succ` 中每个后继 `indeg--`。
- **`ReadingMin`**：与 **`_compare_blocks_reading_order`** 一致的比较器下取最小块。
- **`MergeableOrdered`**：即 **`_can_merge_space_between_ordered`**。

---

## 5. 时间复杂度

记 **n = |materialized|**。

| 部分 | 复杂度 | 说明 |
|------|--------|------|
| 预计算 `A[u]`、`B0[u]` | **O(n² log n)** | 每块 O(n) 扫描；每列表排序最坏 O(n log n) |
| 建图 | **O(n²)** | 每块后继数最坏 O(n) |
| **`BelowFromSemanticChain`** | **O(|chain|·L + k log k)** | 各块静态 B 总长 L 上界 O(n)；k 为去重后在池候选数 |
| 池删除 | 共 **O(n)** 次 | 每块最多被移除一次 |
| 展开阶段 | 与布局相关 | 每轮可能 O(n log n) 重算 B；递归深度与分支依赖输入 |

**整体**  
预处理通常为 **O(n² log n)**。展开阶段宽松上界可记 **O(n² log n)**；更悲观的结构可至 **O(n³)**（若频繁大列表排序与深层递归叠加）。

**空间**  
存储 `A`、`B0`、`succ` 等；最坏后继总量 **O(n²)**，实际由几何稀疏度决定。

---

## 6. 修订记录

- 文档随 `preprocess.py` 中 **`_build_recursive_ocr_chunks` / `_expand_semantic_from_block_precomputed`** 实现维护；若改动合并规则或异常语义，请同步更新本文。
- 已移除段间 **`forced_next`**（及 **`_ocr_break_next_block`**）：段起点一律来自剩余池中 **`indeg==0`** 的阅读序最小块。
