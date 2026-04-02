"""UI 截图 OCR 块的结构理解层。

职责：从原始 OCR blocks 出发，经过裁剪、分行、行内切分、区域分割、
布局检测、按类型拼接，输出语义分组结果供 build_ocr_stream 消费。

零模型依赖，纯坐标计算。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from statistics import median

from privacyguard.domain.models.ocr import OCRTextBlock


# ====================================================================
# 数据结构
# ====================================================================

class LayoutType(str, Enum):
    FLOW = "flow"
    TABLE = "table"


@dataclass(slots=True)
class LayoutRegion:
    """一个布局区域：连续若干行，共享同一种布局类型。"""

    layout: LayoutType
    # 行号区间 [line_start, line_end)，索引基于 segmented_lines。
    line_start: int
    line_end: int


@dataclass(slots=True)
class SemanticGroup:
    """语义分组：拼接后构成一个逻辑字段的 block 序列。"""

    blocks: list[OCRTextBlock] = field(default_factory=list)


# ====================================================================
# 常量
# ====================================================================

# 裁剪：去掉顶部 / 底部各占截图高度的百分比。
_CROP_TOP_RATIO = 0.06
_CROP_BOTTOM_RATIO = 0.08

# 分行：Y 方向重叠比例阈值。
_Y_OVERLAP_RATIO = 0.45

# 行内切分：间距超过平均字符宽度的倍数即断开。
_INLINE_GAP_MULTIPLIER = 3.0

# 区域分割：垂直大间距倍率（相对 median_h）。
_REGION_GAP_RATIO = 2.0

# 区域分割：列对齐容差（相对 median_h 的倍率）。
_COLUMN_ALIGN_RATIO = 0.8

# 流式合并：缩进判定容差（相对 median_h 的倍率）。
_INDENT_RATIO = 0.6

# 流式合并：垂直大间距倍率。
_FLOW_GAP_RATIO = 1.8


# ====================================================================
# ① 裁剪
# ====================================================================

def crop_blocks(
    blocks: list[OCRTextBlock],
    image_height: int | None = None,
) -> list[OCRTextBlock]:
    """按 Y 百分比裁剪顶部状态栏和底部导航栏区域的 blocks。

    如果未提供 image_height，则从 blocks 自身的 bbox 推断截图高度。
    """
    if not blocks:
        return []

    if image_height is None or image_height <= 0:
        image_height = max(
            (b.bbox.y + b.bbox.height for b in blocks if b.bbox is not None),
            default=0,
        )
    if image_height <= 0:
        return list(blocks)

    y_min = image_height * _CROP_TOP_RATIO
    y_max = image_height * (1.0 - _CROP_BOTTOM_RATIO)

    return [
        b for b in blocks
        if b.bbox is not None
        and b.bbox.y >= y_min
        and (b.bbox.y + b.bbox.height) <= y_max
    ]


# ====================================================================
# ② 分行（Y-overlap）
# ====================================================================

def group_into_lines(blocks: list[OCRTextBlock]) -> list[list[OCRTextBlock]]:
    """将 blocks 按 Y 方向重叠聚合为视觉行，行内按 X 排序。"""
    materialized = [
        b for b in blocks
        if (b.text or "").strip() and b.bbox is not None
    ]
    if not materialized:
        return []

    materialized.sort(key=lambda b: b.bbox.y)

    lines: list[list[OCRTextBlock]] = [[materialized[0]]]

    for b in materialized[1:]:
        last_line = lines[-1]
        line_y1 = min(bl.bbox.y for bl in last_line)
        line_y2 = max(bl.bbox.y + bl.bbox.height for bl in last_line)
        line_h = line_y2 - line_y1

        overlap_top = max(b.bbox.y, line_y1)
        overlap_bot = min(b.bbox.y + b.bbox.height, line_y2)
        overlap = max(0, overlap_bot - overlap_top)

        min_h = min(b.bbox.height, line_h)
        ratio = overlap / min_h if min_h > 0 else 0.0

        if ratio > _Y_OVERLAP_RATIO:
            last_line.append(b)
        else:
            # 结束当前行，按 X 排序。
            last_line.sort(key=lambda bl: bl.bbox.x)
            lines.append([b])

    # 最后一行排序。
    lines[-1].sort(key=lambda bl: bl.bbox.x)
    return lines


# ====================================================================
# ③ 行内切分
# ====================================================================

def split_line_segments(
    line: list[OCRTextBlock],
) -> list[list[OCRTextBlock]]:
    """行内按大间距切分为语义段。"""
    if len(line) <= 1:
        return [list(line)]

    total_w = sum(b.bbox.width for b in line if b.bbox is not None)
    total_chars = max(sum(len(b.text or "") for b in line), 1)
    avg_char_w = total_w / total_chars
    threshold = avg_char_w * _INLINE_GAP_MULTIPLIER

    segments: list[list[OCRTextBlock]] = [[line[0]]]
    for i in range(1, len(line)):
        prev_b = line[i - 1]
        curr_b = line[i]
        gap = curr_b.bbox.x - (prev_b.bbox.x + prev_b.bbox.width)
        if gap > threshold:
            segments.append([curr_b])
        else:
            segments[-1].append(curr_b)

    return segments


# ====================================================================
# ④ 区域分割
# ====================================================================

@dataclass(frozen=True, slots=True)
class _SegmentedLine:
    """一行经过行内切分后的结果。"""

    segments: list[list[OCRTextBlock]]
    y1: float
    y2: float

    @property
    def seg_count(self) -> int:
        return len(self.segments)

    def seg_x1(self, idx: int) -> float:
        """第 idx 个 segment 的首个 block 的 x1。"""
        return self.segments[idx][0].bbox.x


def _build_segmented_lines(
    lines: list[list[OCRTextBlock]],
) -> list[_SegmentedLine]:
    result: list[_SegmentedLine] = []
    for line in lines:
        segs = split_line_segments(line)
        y1 = min(b.bbox.y for b in line if b.bbox is not None)
        y2 = max(b.bbox.y + b.bbox.height for b in line if b.bbox is not None)
        result.append(_SegmentedLine(segments=segs, y1=y1, y2=y2))
    return result


def split_into_regions(
    seg_lines: list[_SegmentedLine],
) -> list[tuple[int, int]]:
    """将连续行序列切成区域，返回 [(start, end), ...] 区间列表。

    三个切割信号：
    1. 垂直大间距。
    2. 列数跳变。
    3. 列对齐断裂（列数相同但 x 位置不对齐）。
    """
    if not seg_lines:
        return []

    boundaries: list[int] = [0]

    for i in range(1, len(seg_lines)):
        prev = seg_lines[i - 1]
        curr = seg_lines[i]

        # 用相邻两行中较小的行高作为局部参考，更保守。
        local_h = min(prev.y2 - prev.y1, curr.y2 - curr.y1) or 20.0

        # 信号 1：垂直大间距。
        v_gap = curr.y1 - prev.y2
        if v_gap > local_h * _REGION_GAP_RATIO:
            boundaries.append(i)
            continue

        # 信号 2：列数跳变。
        # N↔1 的转换不切割（可能是卡片式 header+body 交替），
        # 留给 detect_layout 判定。仅在 N↔M（N,M >= 2 且不等）时切。
        if curr.seg_count != prev.seg_count:
            if curr.seg_count >= 2 and prev.seg_count >= 2:
                boundaries.append(i)
                continue

        # 信号 3：列对齐断裂（两行列数相同且 >= 2 时才检查）。
        if curr.seg_count >= 2 and curr.seg_count == prev.seg_count:
            aligned = all(
                abs(curr.seg_x1(c) - prev.seg_x1(c)) <= local_h * _COLUMN_ALIGN_RATIO
                for c in range(curr.seg_count)
            )
            if not aligned:
                boundaries.append(i)
                continue

    # 转成 (start, end) 对。
    regions: list[tuple[int, int]] = []
    for idx in range(len(boundaries)):
        start = boundaries[idx]
        end = boundaries[idx + 1] if idx + 1 < len(boundaries) else len(seg_lines)
        regions.append((start, end))
    return regions


# ====================================================================
# ⑤ 布局检测
# ====================================================================

def detect_layout(
    seg_lines: list[_SegmentedLine],
    start: int,
    end: int,
) -> LayoutType:
    """判定 [start, end) 范围内的行是表格还是流式。

    TABLE 条件：多段行（>= 2 段）占多数，且多段行之间列位置纵向对齐。
    允许少量单段行混入（如聊天列表的 body 行）。
    不满足则 FLOW。
    """
    region = seg_lines[start:end]
    if len(region) < 2:
        return LayoutType.FLOW

    multi_lines = [sl for sl in region if sl.seg_count >= 2]
    if len(multi_lines) < 2:
        return LayoutType.FLOW

    from collections import Counter
    counts = Counter(sl.seg_count for sl in multi_lines)
    dominant_cols = counts.most_common(1)[0][0]

    heights = [sl.y2 - sl.y1 for sl in region]
    median_h = median(heights) if heights else 20.0
    col_tolerance = median_h * _COLUMN_ALIGN_RATIO

    matching = [sl for sl in multi_lines if sl.seg_count == dominant_cols]
    for col in range(dominant_cols):
        xs = [sl.seg_x1(col) for sl in matching]
        if max(xs) - min(xs) > col_tolerance:
            return LayoutType.FLOW

    return LayoutType.TABLE


# ====================================================================
# ⑥ 流式拼接
# ====================================================================

_LABEL_RE = re.compile(r"[:：]\s*$")


def _is_label_text(text: str) -> bool:
    """以冒号结尾 → 大概率是 label。"""
    return bool(_LABEL_RE.search(text.strip()))


def _seg_text(blocks: list[OCRTextBlock]) -> str:
    return "".join(b.text or "" for b in blocks)


def _seg_x1(blocks: list[OCRTextBlock]) -> float:
    return blocks[0].bbox.x if blocks and blocks[0].bbox else 0.0


def merge_flow(
    seg_lines: list[_SegmentedLine],
    start: int,
    end: int,
) -> list[SemanticGroup]:
    """流式布局合并：缩进从属 + 左对齐续行 + anchor 回退 + 冒号 label。"""
    # 将区域内所有 segment 扁平化。
    flat: list[tuple[list[OCRTextBlock], int, int, float, float, float]] = []
    for line_idx in range(start, end):
        sl = seg_lines[line_idx]
        for seg_idx, seg in enumerate(sl.segments):
            x1 = _seg_x1(seg)
            flat.append((seg, line_idx, seg_idx, x1, sl.y1, sl.y2))

    if not flat:
        return []

    groups: list[SemanticGroup] = [SemanticGroup(blocks=list(flat[0][0]))]
    anchor_x1 = flat[0][3]

    for i in range(1, len(flat)):
        seg, line_idx, seg_idx, x1, y1, y2 = flat[i]
        prev_seg, prev_line_idx, prev_seg_idx, prev_x1, _, prev_y2 = flat[i - 1]

        # 用当前段自身的行高计算阈值。
        curr_h = (y2 - y1) or 20.0
        prev_h = (prev_y2 - flat[i - 1][4]) or 20.0
        local_h = min(curr_h, prev_h)
        indent_tol = local_h * _INDENT_RATIO

        # 同一行的不同 segment → 不同字段。
        if line_idx == prev_line_idx and seg_idx != prev_seg_idx:
            groups.append(SemanticGroup(blocks=list(seg)))
            anchor_x1 = x1
            continue

        # 垂直间距太大 → 新字段。
        v_gap = y1 - prev_y2
        if v_gap > local_h * _FLOW_GAP_RATIO:
            groups.append(SemanticGroup(blocks=list(seg)))
            anchor_x1 = x1
            continue

        # 冒号 label 且回到 anchor 同级 → 新字段。
        text = _seg_text(seg)
        if _is_label_text(text) and x1 <= anchor_x1 + indent_tol:
            groups.append(SemanticGroup(blocks=list(seg)))
            anchor_x1 = x1
            continue

        # A：和上一行左对齐 → 续行。
        if abs(x1 - prev_x1) < indent_tol:
            groups[-1].blocks.extend(seg)
            continue

        # B：比 anchor 更靠右 → 缩进从属。
        if x1 > anchor_x1 + indent_tol:
            groups[-1].blocks.extend(seg)
            continue

        # C：回到 anchor 同级 → 新字段。
        groups.append(SemanticGroup(blocks=list(seg)))
        anchor_x1 = x1

    return groups


# ====================================================================
# ⑦ 表格拼接
# ====================================================================

def merge_table(
    seg_lines: list[_SegmentedLine],
    start: int,
    end: int,
) -> list[SemanticGroup]:
    """表格布局：每行横向合并为一个语义组。

    例如 "姓名 张三" 为一组、"电话 138xxxx" 为一组，
    使 label 和 value 保持在同一组内，便于下游 parser 配对。
    """
    groups: list[SemanticGroup] = []
    for line_idx in range(start, end):
        sl = seg_lines[line_idx]
        row_blocks: list[OCRTextBlock] = []
        for seg in sl.segments:
            row_blocks.extend(seg)
        if row_blocks:
            groups.append(SemanticGroup(blocks=row_blocks))
    return groups



# ====================================================================
# 主入口
# ====================================================================

def analyze_ui_layout(
    blocks: list[OCRTextBlock],
    image_height: int | None = None,
) -> list[SemanticGroup]:
    """完整流水线：OCR blocks → 语义分组。

    返回 list[SemanticGroup]，每个 group 内的 blocks 按阅读顺序排列，
    保持原始 OCRTextBlock 引用不变，供下游 build_ocr_stream 消费。
    """
    # ① 裁剪。
    cropped = crop_blocks(blocks, image_height=image_height)
    if not cropped:
        return []

    # ② 分行。
    lines = group_into_lines(cropped)
    if not lines:
        return []

    # ③ 行内切分 + 构建 SegmentedLine。
    seg_lines = _build_segmented_lines(lines)

    # ④ 区域分割。
    regions = split_into_regions(seg_lines)

    # ⑤⑥⑦⑧ 逐区域检测布局并拼接。
    all_groups: list[SemanticGroup] = []
    for region_start, region_end in regions:
        layout = detect_layout(seg_lines, region_start, region_end)
        if layout == LayoutType.TABLE:
            all_groups.extend(merge_table(seg_lines, region_start, region_end))
        else:
            all_groups.extend(merge_flow(seg_lines, region_start, region_end))

    return all_groups
