from __future__ import annotations

"""OCR 块 → 阅读序文字流。

将同一页内的文本块按行聚类、行内按 x 排序，拼接为带换行与可选分隔符的连续字符串，
并维护字符到块索引的映射，供流式检测后将字符跨度还原为 bbox 与 block_id。
"""

from dataclasses import dataclass

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCRPageDocument,
    _OCRSceneIndex,
    _OCR_SEMANTIC_BREAK_TOKEN,
)


@dataclass(frozen=True, slots=True)
class OCRSpanMapping:
    """整流文本上的一段跨度对应到 OCR 几何与块信息（单块时可得块内 span）。"""

    bbox: BoundingBox | None
    block_id: str | None
    span_start: int | None
    span_end: int | None
    block_indices: tuple[int, ...]
    block_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OCRStreamDocument:
    """拼接后的全文、块列表、每字符所属块索引、行结构及底层 page 文档引用。"""

    text: str
    blocks: tuple[OCRTextBlock, ...]
    char_block_indices: tuple[int | None, ...]
    lines: tuple[tuple[int, ...], ...]
    page_document: _OCRPageDocument
    scene_index: _OCRSceneIndex


def build_ocr_scene_index(blocks: list[OCRTextBlock] | tuple[OCRTextBlock, ...]) -> _OCRSceneIndex | None:
    """按几何位置排序块并聚类为行，行内按 x 排序，生成块索引到 (行号, 列号) 的映射。"""
    normalized = tuple(block for block in blocks if str(block.text or "").strip())
    if not normalized:
        return None

    indexed = sorted(range(len(normalized)), key=lambda index: _sort_key(normalized[index]))
    grouped_lines: list[list[int]] = []
    for block_index in indexed:
        block = normalized[block_index]
        if not grouped_lines:
            grouped_lines.append([block_index])
            continue
        current_line = grouped_lines[-1]
        reference = normalized[current_line[-1]]
        if _belongs_to_same_line(reference, block):
            current_line.append(block_index)
            continue
        grouped_lines.append([block_index])

    ordered_lines: list[tuple[int, ...]] = []
    positions: dict[int, tuple[int, int]] = {}
    for line_index, line in enumerate(grouped_lines):
        ordered = tuple(sorted(line, key=lambda index: (normalized[index].bbox.x, normalized[index].bbox.y)))
        ordered_lines.append(ordered)
        for item_index, block_index in enumerate(ordered):
            positions[block_index] = (line_index, item_index)

    return _OCRSceneIndex(
        blocks=normalized,
        lines=tuple(ordered_lines),
        position_by_block_index=positions,
    )


def build_ocr_stream_document(
    blocks: list[OCRTextBlock] | tuple[OCRTextBlock, ...] | _OCRSceneIndex,
) -> OCRStreamDocument | None:
    """行与行之间插入换行，同行块之间插入分隔符（列间隙大时用语义断点），并构建 char_refs。"""
    if isinstance(blocks, _OCRSceneIndex):
        scene_index = blocks
    else:
        scene_index = build_ocr_scene_index(blocks)
    if scene_index is None or not scene_index.blocks:
        return None

    merged_chars: list[str] = []
    char_refs: list[tuple[int, int] | None] = []
    char_block_indices: list[int | None] = []
    for line_index, line in enumerate(scene_index.lines):
        if line_index > 0:
            merged_chars.append("\n")
            char_refs.append(None)
            char_block_indices.append(None)
        for item_index, block_index in enumerate(line):
            block = scene_index.blocks[block_index]
            if item_index > 0:
                previous = scene_index.blocks[line[item_index - 1]]
                separator = _separator_between(previous, block)
                if separator:
                    merged_chars.append(separator)
                    char_refs.extend([None] * len(separator))
                    char_block_indices.extend([None] * len(separator))
            for char_index, char in enumerate(block.text):
                merged_chars.append(char)
                char_refs.append((block_index, char_index))
                char_block_indices.append(block_index)

    page_document = _OCRPageDocument(
        line_index=0,
        blocks=scene_index.blocks,
        text="".join(merged_chars),
        char_refs=tuple(char_refs),
    )
    return OCRStreamDocument(
        text=page_document.text,
        blocks=scene_index.blocks,
        char_block_indices=tuple(char_block_indices),
        lines=scene_index.lines,
        page_document=page_document,
        scene_index=scene_index,
    )


def remap_ocr_span(
    document: OCRStreamDocument,
    span_start: int | None,
    span_end: int | None,
) -> OCRSpanMapping:
    """将 [span_start, span_end) 映射到覆盖到的块：单块返回块内字符偏移；多块仅合并 bbox。"""
    if span_start is None or span_end is None or span_end <= span_start:
        return OCRSpanMapping(None, None, None, None, (), ())

    covered_refs = [
        ref
        for ref in document.page_document.char_refs[max(0, span_start) : min(len(document.page_document.char_refs), span_end)]
        if ref is not None
    ]
    if not covered_refs:
        return OCRSpanMapping(None, None, None, None, (), ())

    block_positions: dict[int, list[int]] = {}
    for block_index, char_index in covered_refs:
        block_positions.setdefault(block_index, []).append(char_index)

    block_indices = tuple(sorted(block_positions))
    block_ids = tuple(
        block.block_id
        for index, block in enumerate(document.blocks)
        if index in block_positions and block.block_id is not None
    )
    bbox = _combine_bboxes(
        tuple(
            block.bbox
            for index, block in enumerate(document.blocks)
            if index in block_positions and block.bbox is not None
        )
    )
    if len(block_indices) == 1:
        only_block = block_indices[0]
        local_positions = block_positions[only_block]
        block = document.blocks[only_block]
        return OCRSpanMapping(
            bbox=bbox,
            block_id=block.block_id,
            span_start=min(local_positions),
            span_end=max(local_positions) + 1,
            block_indices=block_indices,
            block_ids=block_ids,
        )
    return OCRSpanMapping(
        bbox=bbox,
        block_id=None,
        span_start=None,
        span_end=None,
        block_indices=block_indices,
        block_ids=block_ids,
    )


def _sort_key(block: OCRTextBlock) -> tuple[float, float, float]:
    """全局排序：先按行中心 y，再 x，再宽度（稳定阅读序）。"""
    bbox = block.bbox
    return (bbox.y + bbox.height / 2, bbox.x, bbox.width)


def _belongs_to_same_line(left: OCRTextBlock, right: OCRTextBlock) -> bool:
    """根据两行中心 y 差与平均行高判断两块是否属于同一文本行。"""
    if left.bbox is None or right.bbox is None:
        return False
    left_center = left.bbox.y + left.bbox.height / 2
    right_center = right.bbox.y + right.bbox.height / 2
    average_height = (left.bbox.height + right.bbox.height) / 2
    tolerance = _clamp(average_height * 0.6, min_px=8.0, max_px=28.0)
    return abs(left_center - right_center) <= tolerance


def _separator_between(left: OCRTextBlock, right: OCRTextBlock) -> str:
    """列级间隙插入语义断点 token；词级间隙在英文相接时插入空格；否则无分隔。"""
    gap_kind = _horizontal_gap_kind(left, right)
    if gap_kind == "column":
        return _OCR_SEMANTIC_BREAK_TOKEN
    left_text = str(left.text or "")
    right_text = str(right.text or "")
    if gap_kind == "word" and left_text and right_text and _is_ascii_tail(left_text[-1]) and _is_ascii_head(right_text[0]):
        return " "
    return ""


def _horizontal_gap_kind(left: OCRTextBlock, right: OCRTextBlock) -> str:
    """根据水平间距与行高比例区分 token / word / column 三级间隙。"""
    if left.bbox is None or right.bbox is None:
        return "token"
    horizontal_gap = max(0.0, float(right.bbox.x - (left.bbox.x + left.bbox.width)))
    min_height = float(min(left.bbox.height, right.bbox.height))
    avg_height = (left.bbox.height + right.bbox.height) / 2
    token_gap = _clamp(min_height * 0.4, min_px=6.0, max_px=12.0)
    word_gap = max(token_gap, _clamp(avg_height * 0.55, min_px=8.0, max_px=18.0))
    if horizontal_gap <= token_gap:
        return "token"
    if horizontal_gap <= word_gap:
        return "word"
    return "column"


def _is_ascii_tail(char: str) -> bool:
    """左侧块末字是否为 ASCII 字母数字或闭合符号（用于决定是否插空格）。"""
    return char.isascii() and (char.isalnum() or char in ")]}'\"")


def _is_ascii_head(char: str) -> bool:
    """右侧块首字是否为 ASCII 字母数字或开符号。"""
    return char.isascii() and (char.isalnum() or char in "([{'\"")


def _combine_bboxes(boxes: tuple[BoundingBox, ...]) -> BoundingBox | None:
    """多块外包矩形，坐标取整且保证宽高至少为 1。"""
    if not boxes:
        return None
    min_x = min(box.x for box in boxes)
    min_y = min(box.y for box in boxes)
    max_x = max(box.x + box.width for box in boxes)
    max_y = max(box.y + box.height for box in boxes)
    return BoundingBox(
        x=max(0, int(min_x)),
        y=max(0, int(min_y)),
        width=max(1, int(max_x - min_x)),
        height=max(1, int(max_y - min_y)),
    )


def _clamp(value: float, *, min_px: float, max_px: float) -> float:
    """将像素类阈值限制在 [min_px, max_px]。"""
    return min(max_px, max(min_px, value))
