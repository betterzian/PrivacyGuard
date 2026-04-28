"""Prompt 与 OCR 流的预处理。"""

from __future__ import annotations

import bisect
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from functools import cmp_to_key

from privacyguard.domain.enums import PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector.models import (
    OCRScene,
    OCRSceneBlock,
    PreparedOCRContext,
    SourceRef,
    StreamInput,
    StreamUnit,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    OCR_BREAK,
    _OCR_INLINE_GAP_TOKEN,
)

_ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"})
_STREAM_PUNCT_NORMALIZATION = str.maketrans({
    "（": "(",
    "）": ")",
})


class OCRSemanticChunkGraphError(RuntimeError):
    """OCR 合并依赖图在剩余块中无入度为 0 的源点（可能存在环或图构造与池不一致）。"""


@dataclass(frozen=True, slots=True)
class _BlockToken:
    kind: str
    text: str
    raw_indices: tuple[int | None, ...]


def build_prompt_stream(text: str) -> StreamInput:
    clean_text = _normalize_stream_text(text or "")
    units, char_to_unit = _build_stream_units(clean_text)
    char_refs = tuple(
        SourceRef(
            source=PIISourceType.PROMPT,
            block_id=None,
            bbox=None,
            block_char_index=index,
            raw_index=index,
        )
        for index, _char in enumerate(clean_text)
    )
    return StreamInput(
        source=PIISourceType.PROMPT,
        text=clean_text,
        units=units,
        char_to_unit=char_to_unit,
        char_refs=char_refs,
    )


def build_ocr_stream(blocks: list[OCRTextBlock]) -> PreparedOCRContext:
    """构建 OCR 流：预计算链 A/B 一次后供合并图使用；段间 ``OCR_BREAK``。"""
    materialized = [b for b in blocks if (b.text or "").strip() and b.bbox is not None]
    if not materialized:
        empty_stream = StreamInput(
            source=PIISourceType.OCR,
            text="",
            units=(),
            char_to_unit=(),
            char_refs=(),
            metadata={"ocr_block_count": 0},
        )
        return PreparedOCRContext(raw_text="", stream=empty_stream, scene=_build_scene([]))

    pre_a, pre_b = _precompute_all_chains(materialized)
    chunks = _build_recursive_ocr_chunks(materialized, pre_a=pre_a, pre_b_static=pre_b)
    return _build_stream_from_chunks(chunks)


def _bbox_y_interval(b: OCRTextBlock) -> tuple[float, float]:
    """``(y_start, y_end)``，y_end 为下边（开区间比较与其它块是否纵向重叠时用）。"""
    bb = b.bbox
    if bb is None:
        return (0.0, 0.0)
    y0 = float(bb.y)
    y1 = float(bb.y + bb.height)
    return (y0, y1)


def _y_overlaps_interval_open(a: OCRTextBlock, b: OCRTextBlock) -> bool:
    """两框在 y 轴上是否有正长度重叠（开区间意义：``max(y1) < min(y2)``）。"""
    ay0, ay1 = _bbox_y_interval(a)
    by0, by1 = _bbox_y_interval(b)
    return max(ay0, by0) < min(ay1, by1)


def _compare_blocks_reading_order(a: OCRTextBlock, b: OCRTextBlock) -> int:
    """阅读序：y 区间有重叠则以 x 小优先；无重叠则以 y 起小优先；再二级 x、y、block_id 稳定决胜。"""
    if _y_overlaps_interval_open(a, b):
        ax = float(a.bbox.x) if a.bbox is not None else 0.0
        bx = float(b.bbox.x) if b.bbox is not None else 0.0
        if ax < bx:
            return -1
        if ax > bx:
            return 1
    else:
        ay0, _ = _bbox_y_interval(a)
        by0, _ = _bbox_y_interval(b)
        if ay0 < by0:
            return -1
        if ay0 > by0:
            return 1
        ax = float(a.bbox.x) if a.bbox is not None else 0.0
        bx = float(b.bbox.x) if b.bbox is not None else 0.0
        if ax < bx:
            return -1
        if ax > bx:
            return 1

    ay0, _ = _bbox_y_interval(a)
    by0, _ = _bbox_y_interval(b)
    if ay0 < by0:
        return -1
    if ay0 > by0:
        return 1
    aid = a.block_id or ""
    bid = b.block_id or ""
    if aid < bid:
        return -1
    if aid > bid:
        return 1
    if id(a) < id(b):
        return -1
    if id(a) > id(b):
        return 1
    return 0


def _can_merge_space_between_ordered(left: OCRTextBlock, right: OCRTextBlock) -> bool:
    """有序序列中相邻两块是否用语义 inline 间隙连接（同行或跨行）；跨行 x 仅两行行首对齐。"""
    if _can_merge_same_line_adjacent(left, right):
        return True
    return _can_merge_across_lines([left], [right])


def _compare_chain_a_candidates(a: OCRTextBlock, b: OCRTextBlock) -> int:
    """链 A 候选间排序：若两框 ``y`` 无重叠则 ``y`` 起小优先；若有重叠则 ``x`` 小优先；再稳定决胜。"""
    if _y_overlaps_interval_open(a, b):
        ax = float(a.bbox.x) if a.bbox is not None else 0.0
        bx = float(b.bbox.x) if b.bbox is not None else 0.0
        if ax < bx:
            return -1
        if ax > bx:
            return 1
    else:
        ay0, _ = _bbox_y_interval(a)
        by0, _ = _bbox_y_interval(b)
        if ay0 < by0:
            return -1
        if ay0 > by0:
            return 1
        ax = float(a.bbox.x) if a.bbox is not None else 0.0
        bx = float(b.bbox.x) if b.bbox is not None else 0.0
        if ax < bx:
            return -1
        if ax > bx:
            return 1

    ay0, _ = _bbox_y_interval(a)
    by0, _ = _bbox_y_interval(b)
    if ay0 < by0:
        return -1
    if ay0 > by0:
        return 1
    aid = a.block_id or ""
    bid = b.block_id or ""
    if aid < bid:
        return -1
    if aid > bid:
        return 1
    if id(a) < id(b):
        return -1
    if id(a) > id(b):
        return 1
    return 0



def _precompute_all_chains(
    materialized: list[OCRTextBlock],
) -> tuple[dict[int, list[OCRTextBlock]], dict[int, list[OCRTextBlock]]]:
    """一次遍历构建所有块的链 A（同行右侧）和链 B（下方对齐），用 y 排序 + bisect 加速。"""
    by_y = sorted(materialized, key=lambda b: float(b.bbox.y + b.bbox.height / 2) if b.bbox else 0.0)
    y_centers = [float(b.bbox.y + b.bbox.height / 2) if b.bbox else 0.0 for b in by_y]

    pre_a: dict[int, list[OCRTextBlock]] = {id(b): [] for b in materialized}
    pre_b: dict[int, list[OCRTextBlock]] = {id(b): [] for b in materialized}

    for cur in materialized:
        cb = cur.bbox
        if cb is None:
            continue
        cur_id = id(cur)
        cur_h = float(cb.height)
        cur_right = float(cb.x + cb.width)
        cur_y_end = float(cb.y + cb.height)
        cur_x = float(cb.x)
        cur_cy = float(cb.y) + cur_h / 2

        # 链 A：y 区间重叠的块中，在 cur 右边界右侧的。
        lo = bisect.bisect_left(y_centers, cur_cy - cur_h)
        hi = bisect.bisect_right(y_centers, cur_cy + cur_h)
        for j in range(lo, hi):
            b = by_y[j]
            if b is cur:
                continue
            bb = b.bbox
            if bb is None or float(bb.x) <= cur_right:
                continue
            if not _y_overlaps_interval_open(cur, b):
                continue
            pre_a[cur_id].append(b)
        pre_a[cur_id].sort(key=cmp_to_key(_compare_chain_a_candidates))

        # 链 B：在 cur 下方且左缘对齐。
        start_idx = bisect.bisect_left(y_centers, cur_y_end - cur_h * 0.5)
        for j in range(start_idx, len(by_y)):
            b = by_y[j]
            if b is cur:
                continue
            bb = b.bbox
            if bb is None:
                continue
            if float(bb.y) < cur_y_end:
                continue
            bh = float(bb.height)
            h_max = max(cur_h, bh, 1e-6)
            if abs(float(bb.x) - cur_x) > h_max:
                continue
            pre_b[cur_id].append(b)
        pre_b[cur_id].sort(
            key=lambda b: (float(b.bbox.y), float(b.bbox.x), b.block_id or "", id(b)) if b.bbox else (0.0, 0.0, "", id(b)),
        )

    return pre_a, pre_b


def _below_list_for_semantic_chain(
    semantic_blocks: list[OCRTextBlock],
    remaining_ids: set[int],
    pre_b_by_id: dict[int, list[OCRTextBlock]],
) -> list[OCRTextBlock]:
    """对 ``semantic_blocks`` 各块合并前预计算的链 B 取并集、``id`` 去重，仅保留仍在 ``remaining`` 的块，再按阅读键排序。"""
    seen: set[int] = set()
    cand: list[OCRTextBlock] = []
    for b in semantic_blocks:
        for v in pre_b_by_id.get(id(b), ()):
            vid = id(v)
            if vid not in remaining_ids or vid in seen:
                continue
            seen.add(vid)
            cand.append(v)
    cand.sort(
        key=lambda b: (float(b.bbox.y), float(b.bbox.x), b.block_id or "", id(b)) if b.bbox else (0.0, 0.0, "", id(b)),
    )
    return cand


def _assign_shared_chain_b(row_members: list[OCRTextBlock], shared_b: list[OCRTextBlock], mutable_b: dict[int, list[OCRTextBlock]]) -> None:
    """同行合并块指向同一条链 B 列表对象。"""
    for m in row_members:
        mutable_b[id(m)] = shared_b


def _first_in_list_remaining(lst: list[OCRTextBlock], remaining_ids: set[int]) -> OCRTextBlock | None:
    for b in lst:
        if id(b) in remaining_ids:
            return b
    return None


def _remove_block_from_graph(
    b: OCRTextBlock,
    remaining_ids: set[int],
    indeg: dict[int, int],
    succ_by_id: dict[int, list[int]],
) -> None:
    bid = id(b)
    if bid not in remaining_ids:
        return
    remaining_ids.discard(bid)
    for vid in succ_by_id.get(bid, ()):
        indeg[vid] -= 1


def _expand_semantic_from_block_precomputed(
    entry: OCRTextBlock,
    remaining_ids: set[int],
    indeg: dict[int, int],
    succ_by_id: dict[int, list[int]],
    pre_a: dict[int, list[OCRTextBlock]],
    pre_b_static: dict[int, list[OCRTextBlock]],
    mutable_b: dict[int, list[OCRTextBlock]],
    chain: list[OCRTextBlock],
) -> None:
    """链 A 阶段只处理同行：仅 ``cur`` 的链 A 首候选且须 ``_can_merge_same_line_adjacent``；不在这儿走链 B。

    链 A 无法再延伸后，将 ``chain`` 上各块预计算链 B 并集去重（限仍在池内）得到运行期链 B，写入同行 ``row`` 共享引用；再扫链 B。"""
    cur = entry
    row: list[OCRTextBlock] = [entry]
    while True:
        # 链 A：只认「该点链 A 的第一个仍在池内的候选」的**行内**合并；不交错链 B。
        while True:
            cur_id = id(cur)
            fa = _first_in_list_remaining(pre_a[cur_id], remaining_ids)
            if fa is None or not _can_merge_same_line_adjacent(cur, fa):
                break
            chain.append(fa)
            _remove_block_from_graph(fa, remaining_ids, indeg, succ_by_id)
            cur = fa
            row.append(fa)

        new_b = _below_list_for_semantic_chain(chain, remaining_ids, pre_b_static)
        _assign_shared_chain_b(row, new_b, mutable_b)

        shared_b = new_b
        cur_tail = cur
        any_merged = False
        for e in shared_b:
            if id(e) not in remaining_ids:
                continue
            if not _can_merge_space_between_ordered(cur_tail, e):
                continue
            chain.append(e)
            _remove_block_from_graph(e, remaining_ids, indeg, succ_by_id)
            _expand_semantic_from_block_precomputed(
                e, remaining_ids, indeg, succ_by_id, pre_a, pre_b_static, mutable_b, chain
            )
            cur_tail = chain[-1]
            any_merged = True
        if any_merged:
            cur = cur_tail
            row = [cur_tail]
            continue
        break


def _space_expand_chain_from_start(
    start: OCRTextBlock,
    remaining_ids: set[int],
    indeg: dict[int, int],
    succ_by_id: dict[int, list[int]],
    pre_a: dict[int, list[OCRTextBlock]],
    pre_b_static: dict[int, list[OCRTextBlock]],
    mutable_b: dict[int, list[OCRTextBlock]],
) -> list[OCRTextBlock]:
    chain: list[OCRTextBlock] = [start]
    _remove_block_from_graph(start, remaining_ids, indeg, succ_by_id)
    _expand_semantic_from_block_precomputed(
        start, remaining_ids, indeg, succ_by_id, pre_a, pre_b_static, mutable_b, chain
    )
    return chain


def _build_recursive_ocr_chunks(
    materialized: list[OCRTextBlock],
    *,
    pre_a: dict[int, list[OCRTextBlock]],
    pre_b_static: dict[int, list[OCRTextBlock]],
) -> list[list[OCRTextBlock]]:
    """根据已预计算的链 A/B 构建合并图；起点取 ``remaining`` 内入度 0 且阅读序最小的块。"""
    id_to_block = {id(b): b for b in materialized}

    succ_by_id: dict[int, list[int]] = {}
    indeg: dict[int, int] = defaultdict(int)
    for b in materialized:
        bid = id(b)
        targets: set[int] = set()
        if pre_a[bid]:
            targets.add(id(pre_a[bid][0]))
        for v in pre_b_static[bid]:
            targets.add(id(v))
        succ_by_id[bid] = list(targets)
        for vid in targets:
            indeg[vid] += 1

    mutable_b: dict[int, list[OCRTextBlock]] = {
        id(b): list(pre_b_static[id(b)]) for b in materialized
    }
    remaining_ids: set[int] = {id(b) for b in materialized}
    chunks: list[list[OCRTextBlock]] = []

    while remaining_ids:
        zero_sources = [id_to_block[i] for i in remaining_ids if indeg[i] == 0]
        if not zero_sources:
            raise OCRSemanticChunkGraphError(
                "剩余 OCR 块中无入度为 0 的源点，无法确定下一段起点（请检查块依赖图是否含环或与池不一致）。"
            )
        start = min(zero_sources, key=cmp_to_key(_compare_blocks_reading_order))

        chain = _space_expand_chain_from_start(
            start, remaining_ids, indeg, succ_by_id, pre_a, pre_b_static, mutable_b
        )
        chunks.append(chain)

    return chunks



def _max_block_height(line: list[OCRTextBlock]) -> float:
    return float(max((b.bbox.height for b in line if b.bbox is not None), default=0))


def _line_left_x(line: list[OCRTextBlock]) -> float:
    return float(min((b.bbox.x for b in line if b.bbox is not None), default=0.0))


def _vertical_gap_between_lines(upper: list[OCRTextBlock], lower: list[OCRTextBlock]) -> float:
    u_y2 = max(b.bbox.y + b.bbox.height for b in upper if b.bbox is not None)
    l_y1 = min(b.bbox.y for b in lower if b.bbox is not None)
    return float(l_y1 - u_y2)


def _line_has_cjk(line: list[OCRTextBlock]) -> bool:
    for b in line:
        for ch in b.text or "":
            if _is_cjk(ch):
                return True
    return False


def _height_tolerance_ratio(upper: list[OCRTextBlock], lower: list[OCRTextBlock]) -> float:
    u_cjk = _line_has_cjk(upper)
    l_cjk = _line_has_cjk(lower)
    if u_cjk and l_cjk:
        return 0.09
    return 0.20


def _can_merge_same_line_adjacent(left: OCRTextBlock, right: OCRTextBlock) -> bool:
    """水平向：两框 y 区间须重叠，且高度与水平间距满足阈值时才可用空格衔接。"""
    if not _y_overlaps_interval_open(left, right):
        return False
    lb, rb = left.bbox, right.bbox
    if lb is None or rb is None:
        return False
    h1 = float(lb.height)
    h2 = float(rb.height)
    h_tall = max(h1, h2)
    if h_tall <= 0:
        return False
    if abs(h1 - h2) / h_tall >= 0.10:
        return False
    gap_x = float(rb.x) - (float(lb.x) + float(lb.width))
    if gap_x > 0.5 * h_tall:
        return False
    return True


def _can_merge_across_lines(upper: list[OCRTextBlock], lower: list[OCRTextBlock]) -> bool:
    """跨行拼接条件：垂距、行高一致度、两行行首 x 差（段包络仅用于构造链 B，不参与此处）。"""
    if not upper or not lower:
        return False
    if not _cross_line_char_types_compatible(upper, lower):
        return False
    h_up = _max_block_height(upper)
    h_lo = _max_block_height(lower)
    h_max = max(h_up, h_lo)

    # 1. 下行顶边与上行底边的垂距：不超过上行最大高度，且不超过更高行代表高度的一半。
    gap = _vertical_gap_between_lines(upper, lower)
    if gap > h_up:
        return False
    if gap > 0.5 * h_max:
        return False

    # 2. 两行代表高度（各行最大 block 高）的相对误差。
    tol = _height_tolerance_ratio(upper, lower)
    if abs(h_up - h_lo) / h_max > tol:
        return False

    # 3. 两行行首（最小左缘）相距不超过 ``h_max``。
    if abs(_line_left_x(upper) - _line_left_x(lower)) > h_max:
        return False
    return True


def _cross_line_char_types_compatible(upper: list[OCRTextBlock], lower: list[OCRTextBlock]) -> bool:
    """跨行拼接前做轻量文本类型约束，避免数字行与英文 UI 文案串接。"""
    upper_types = _ocr_line_char_types(upper)
    lower_types = _ocr_line_char_types(lower)
    if not upper_types:
        return True
    if "cjk" in upper_types:
        return "cjk" in lower_types
    return upper_types <= lower_types


def _ocr_line_char_types(blocks: list[OCRTextBlock]) -> set[str]:
    types: set[str] = set()
    for block in blocks:
        for char in unicodedata.normalize("NFKC", block.text or ""):
            if "\u4e00" <= char <= "\u9fff":
                types.add("cjk")
            elif ("A" <= char <= "Z") or ("a" <= char <= "z"):
                types.add("latin")
            elif char.isdigit():
                types.add("digit")
    return types


def _build_stream_from_chunks(
    chunks: list[list[OCRTextBlock]],
) -> PreparedOCRContext:
    """链内用语义 ``inline_gap`` 拼接；链与链之间 ``OCR_BREAK``。"""
    raw_chunks: list[str] = []
    clean_chunks: list[str] = []
    clean_char_refs: list[SourceRef | None] = []
    scene_blocks: list[OCRSceneBlock] = []
    raw_cursor = 0
    clean_cursor = 0
    order_index = 0
    previous_clean_text: str | None = None

    for ci, chunk in enumerate(chunks):
        if ci > 0 and raw_chunks:
            raw_chunks.append(OCR_BREAK)
            raw_cursor += len(OCR_BREAK)
            _append_clean_token(
                clean_chunks=clean_chunks,
                clean_char_refs=clean_char_refs,
                token=OCR_BREAK,
            )
            clean_cursor += len(OCR_BREAK)
            previous_clean_text = None

        for bi, block in enumerate(chunk):
            if bi > 0:
                raw_chunks.append(_OCR_INLINE_GAP_TOKEN)
                raw_cursor += len(_OCR_INLINE_GAP_TOKEN)

            block_id = block.block_id or f"ocr-{order_index}"
            clean_text, clean_raw_indices = _prepare_ocr_block_text(block.text or "")

            raw_start = raw_cursor
            raw_text = block.text or ""
            raw_chunks.append(raw_text)
            raw_cursor += len(raw_text)
            raw_end = raw_cursor

            if clean_text:
                if bi > 0:
                    join_text = _join_clean_blocks_ocr_inline(previous_clean_text, clean_text)
                    if join_text:
                        _append_clean_token(
                            clean_chunks=clean_chunks,
                            clean_char_refs=clean_char_refs,
                            token=join_text,
                        )
                        clean_cursor += len(join_text)
                clean_start = clean_cursor
                clean_chunks.append(clean_text)
                for raw_block_index in clean_raw_indices:
                    if raw_block_index is None:
                        clean_char_refs.append(None)
                        continue
                    clean_char_refs.append(
                        SourceRef(
                            source=PIISourceType.OCR,
                            block_id=block_id,
                            bbox=block.bbox,
                            block_char_index=raw_block_index,
                            raw_index=raw_start + raw_block_index,
                        )
                    )
                clean_cursor += len(clean_text)
                clean_end = clean_cursor
                previous_clean_text = clean_text
            else:
                clean_start = clean_cursor
                clean_end = clean_cursor

            scene_blocks.append(
                OCRSceneBlock(
                    block=block.model_copy(deep=True),
                    block_id=block_id,
                    order_index=order_index,
                    raw_start=raw_start,
                    raw_end=raw_end,
                    clean_start=clean_start,
                    clean_end=clean_end,
                    clean_text=clean_text,
                )
            )
            order_index += 1

    stream_text = "".join(clean_chunks)
    units, char_to_unit = _build_stream_units(stream_text)
    stream = StreamInput(
        source=PIISourceType.OCR,
        text=stream_text,
        units=units,
        char_to_unit=char_to_unit,
        char_refs=tuple(clean_char_refs),
        metadata={"ocr_block_count": len(scene_blocks)},
    )
    return PreparedOCRContext(
        raw_text="".join(raw_chunks),
        stream=stream,
        scene=_build_scene(scene_blocks),
    )


def _prepare_ocr_block_text(text: str) -> tuple[str, tuple[int | None, ...]]:
    chars, raw_indices = _normalize_block_chars(text)
    chars, raw_indices = _rewrite_whitespace(chars, raw_indices)
    chars, raw_indices = _strip_edge_noise(chars, raw_indices)
    clean_text = _apply_ambiguity_fixes("".join(chars))
    return (clean_text, tuple(raw_indices))


def _normalize_block_chars(text: str) -> tuple[list[str], list[int | None]]:
    chars: list[str] = []
    raw_indices: list[int | None] = []
    for raw_index, raw_char in enumerate(text):
        raw_char = _normalize_stream_char(raw_char)
        normalized = raw_char if unicodedata.category(raw_char).startswith("P") else unicodedata.normalize("NFKC", raw_char)
        for char in normalized:
            rewritten = _normalize_intermediate_char(char)
            if not rewritten:
                continue
            for piece in rewritten:
                chars.append(piece)
                raw_indices.append(raw_index)
    return (chars, raw_indices)


def _normalize_intermediate_char(char: str) -> str:
    if char in _ZERO_WIDTH_CHARS:
        return ""
    if char.isspace():
        return " "
    if unicodedata.category(char).startswith("C"):
        return ""
    return char


def _normalize_stream_text(text: str) -> str:
    """统一 prompt / OCR 流在 detector 前的最小字符规整。"""
    if not text:
        return ""
    return text.translate(_STREAM_PUNCT_NORMALIZATION)


def _normalize_stream_char(char: str) -> str:
    """按单字符规整全角括号，保持 raw_index 一对一映射。"""
    return char.translate(_STREAM_PUNCT_NORMALIZATION)


def _rewrite_whitespace(chars: list[str], raw_indices: list[int | None]) -> tuple[list[str], list[int | None]]:
    if not chars:
        return (chars, raw_indices)
    tokens = _tokenize_intermediate(chars, raw_indices)
    rewritten_chars: list[str] = []
    rewritten_indices: list[int | None] = []
    for token in tokens:
        if token.kind != "space_run":
            rewritten_chars.extend(token.text)
            rewritten_indices.extend(token.raw_indices)
            continue
        rewritten_chars.append(" ")
        rewritten_indices.append(token.raw_indices[0] if token.raw_indices else None)
    return (rewritten_chars, rewritten_indices)


def _tokenize_intermediate(chars: list[str], raw_indices: list[int | None]) -> list[_BlockToken]:
    tokens: list[_BlockToken] = []
    cursor = 0
    while cursor < len(chars):
        char = chars[cursor]
        if char == " ":
            end = cursor + 1
            while end < len(chars) and chars[end] == " ":
                end += 1
            tokens.append(_BlockToken(kind="space_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_cjk(char):
            end = cursor + 1
            while end < len(chars) and _is_cjk(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="cjk_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_ascii_letter(char):
            end = cursor + 1
            while end < len(chars) and _is_ascii_letter(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="ascii_word", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_ascii_digit(char):
            end = cursor + 1
            while end < len(chars) and _is_ascii_digit(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="digit_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_punctuation(char):
            tokens.append(_BlockToken(kind="punct", text=char, raw_indices=(raw_indices[cursor],)))
            cursor += 1
            continue
        end = cursor + 1
        while (
            end < len(chars)
            and chars[end] != " "
            and not _is_cjk(chars[end])
            and not _is_ascii_letter(chars[end])
            and not _is_ascii_digit(chars[end])
            and not _is_punctuation(chars[end])
        ):
            end += 1
        tokens.append(_BlockToken(kind="other_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
        cursor = end
    return tokens


# 旧版 ``_plan_gap_outputs``（CJK 五元组、标点两侧删格、宽间隙 ``_OCR_INLINE_GAP_TOKEN``）已弃用；
# 空白改为在 ``_rewrite_whitespace`` 中统一「多空格 → 单空格」，块首尾空白在 ``_strip_edge_noise`` 清除。
#
# def _plan_gap_outputs(tokens: list[_BlockToken]) -> dict[int, str]:
#     ...  # 见 git 历史


def _strip_edge_noise(chars: list[str], raw_indices: list[int | None]) -> tuple[list[str], list[int | None]]:
    start = 0
    end = len(chars)
    while start < end and _should_strip_edge_char(chars[start]):
        start += 1
    while end > start and _should_strip_edge_char(chars[end - 1]):
        end -= 1
    return (chars[start:end], raw_indices[start:end])


def _should_strip_edge_char(char: str) -> bool:
    """仅去掉块首尾空格；中间噪声字符仍由 ``_normalize_intermediate_char`` 等处理，不因本函数剥边。"""
    return char == " "


def _apply_ambiguity_fixes(text: str) -> str:
    if not text:
        return text
    chars = list(text)
    protected = _protected_mask(text)
    for index, char in enumerate(chars):
        if protected[index]:
            continue
        replacement = _resolve_ambiguous_char(chars, protected, index, char)
        if replacement is not None:
            chars[index] = replacement
    return "".join(chars)


def _protected_mask(text: str) -> list[bool]:
    protected = [False] * len(text)
    for token in (_OCR_INLINE_GAP_TOKEN, OCR_BREAK):
        start = 0
        while True:
            index = text.find(token, start)
            if index < 0:
                break
            for cursor in range(index, index + len(token)):
                protected[cursor] = True
            start = index + len(token)
    return protected


def _resolve_ambiguous_char(chars: list[str], protected: list[bool], index: int, char: str) -> str | None:
    if char not in {"I", "l", "1", "O", "0", "О"}:
        return None
    prev_char = _adjacent_neighbor(chars, protected, index - 1)
    next_char = _adjacent_neighbor(chars, protected, index + 1)
    if prev_char is None or next_char is None:
        return None
    if _is_ascii_digit(prev_char) and _is_ascii_digit(next_char):
        return "1" if char in {"I", "l", "1"} else "0"
    if _is_ascii_letter(prev_char) and _is_ascii_letter(next_char):
        if prev_char.islower() and next_char.islower():
            return "l" if char in {"I", "l", "1"} else "o"
        return "I" if char in {"I", "l", "1"} else "O"
    return None


def _adjacent_neighbor(chars: list[str], protected: list[bool], index: int) -> str | None:
    if index < 0 or index >= len(chars):
        return None
    if protected[index]:
        return None
    return chars[index]


def _append_clean_token(
    *,
    clean_chunks: list[str],
    clean_char_refs: list[SourceRef | None],
    token: str,
) -> None:
    if not token:
        return
    clean_chunks.append(token)
    clean_char_refs.extend([None] * len(token))


def _join_clean_blocks(left_text: str | None, right_text: str) -> str:
    if not left_text or not right_text:
        return ""
    if _is_punctuation(left_text[-1]) or _is_punctuation(right_text[0]):
        return ""
    return " "


def _join_clean_blocks_ocr_inline(left_text: str | None, right_text: str) -> str:
    """OCR 链内块间可插入时的分隔符：``_OCR_INLINE_GAP_TOKEN``（与流单元 ``inline_gap`` 一致）。"""
    if not left_text or not right_text:
        return ""
    if _is_punctuation(left_text[-1]) or _is_punctuation(right_text[0]):
        return ""
    return _OCR_INLINE_GAP_TOKEN


def _build_stream_units(text: str) -> tuple[tuple[StreamUnit, ...], tuple[int, ...]]:
    if not text:
        return ((), ())
    units: list[StreamUnit] = []
    char_to_unit: list[int] = []
    cursor = 0
    while cursor < len(text):
        if text.startswith(_OCR_INLINE_GAP_TOKEN, cursor):
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="inline_gap",
                text=_OCR_INLINE_GAP_TOKEN,
                start=cursor,
                end=cursor + len(_OCR_INLINE_GAP_TOKEN),
            )
            continue
        if text.startswith(OCR_BREAK, cursor):
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="ocr_break",
                text=OCR_BREAK,
                start=cursor,
                end=cursor + len(OCR_BREAK),
            )
            continue
        char = text[cursor]
        if char == " ":
            cursor = _append_unit(units, char_to_unit, kind="space", text=" ", start=cursor, end=cursor + 1)
            continue
        if _is_cjk(char):
            cursor = _append_unit(units, char_to_unit, kind="cjk_char", text=char, start=cursor, end=cursor + 1)
            continue
        if _is_ascii_letter(char):
            end = cursor + 1
            seen_digit = False
            while end < len(text) and (_is_ascii_letter(text[end]) or _is_ascii_digit(text[end])):
                seen_digit = seen_digit or _is_ascii_digit(text[end])
                end += 1
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="alnum_run" if seen_digit else "ascii_word",
                text=text[cursor:end],
                start=cursor,
                end=end,
            )
            continue
        if _is_ascii_digit(char):
            end = cursor + 1
            seen_letter = False
            while end < len(text) and (_is_ascii_letter(text[end]) or _is_ascii_digit(text[end])):
                seen_letter = seen_letter or _is_ascii_letter(text[end])
                end += 1
            if seen_letter:
                cursor = _append_unit(
                    units,
                    char_to_unit,
                    kind="alnum_run",
                    text=text[cursor:end],
                    start=cursor,
                    end=end,
                )
                continue
            # 连续数字合并为一个 digit_run unit；允许数字之间夹杂单个空格或连字符 "-"。
            # 注意：这里不做清洗，unit.text 保留空格与连字符（例如 "+86 139-1234-1234"）。
            while end < len(text):
                if (
                    text[end] in {" ", "-"}
                    and end + 1 < len(text)
                    and _is_ascii_digit(text[end + 1])
                ):
                    end += 2
                    continue
                if _is_ascii_digit(text[end]):
                    end += 1
                    continue
                break
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="digit_run",
                text=text[cursor:end],
                start=cursor,
                end=end,
            )
            continue
        if _is_punctuation(char):
            cursor = _append_unit(units, char_to_unit, kind="punct", text=char, start=cursor, end=cursor + 1)
            continue
        cursor = _append_unit(units, char_to_unit, kind="other_char", text=char, start=cursor, end=cursor + 1)
    return (tuple(units), tuple(char_to_unit))


def _append_unit(
    units: list[StreamUnit],
    char_to_unit: list[int],
    *,
    kind: str,
    text: str,
    start: int,
    end: int,
) -> int:
    unit_index = len(units)
    units.append(StreamUnit(kind=kind, text=text, char_start=start, char_end=end))
    char_to_unit.extend([unit_index] * (end - start))
    return end


def _is_cjk(char: str) -> bool:
    codepoint = ord(char)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x3040 <= codepoint <= 0x30FF
        or 0xAC00 <= codepoint <= 0xD7AF
    )


def _is_ascii_letter(char: str) -> bool:
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _is_punctuation(char: str) -> bool:
    return unicodedata.category(char).startswith("P")


def _build_scene(scene_blocks: list[OCRSceneBlock]) -> OCRScene:
    id_to_block = {item.block_id: item for item in scene_blocks}
    return OCRScene(
        blocks=tuple(scene_blocks),
        id_to_block=id_to_block,
    )
