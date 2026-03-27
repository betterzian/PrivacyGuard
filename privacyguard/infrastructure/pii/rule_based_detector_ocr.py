"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_labels import (
    _FieldLabelSpec,
    _match_inline_field_labels,
    _match_pure_field_labels,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import *


def _build_ocr_page_document(
    self,
    ocr_blocks: list[OCRTextBlock] | tuple[OCRTextBlock, ...] | _OCRSceneIndex,
) -> _OCRPageDocument | None:
    """把整页 OCR block 聚合成单个扫描文档，减少重复扫描成本。"""
    if isinstance(ocr_blocks, _OCRSceneIndex):
        scene_index = ocr_blocks
    else:
        if not ocr_blocks:
            return None
        scene_index = self._build_ocr_scene_index(tuple(ocr_blocks))
    if not scene_index.blocks:
        return None
    merged_chars: list[str] = []
    char_refs: list[tuple[int, int] | None] = []
    visited: set[int] = set()
    chains = self._collect_ocr_block_chains(scene_index)
    line_count = 0
    for chain in chains:
        if not chain:
            continue
        if line_count > 0:
            self._append_ocr_page_separator(merged_chars, char_refs, _OCR_SEMANTIC_BREAK_TOKEN)
        for block_index, separator in chain:
            if separator:
                self._append_ocr_page_separator(merged_chars, char_refs, separator)
            block = scene_index.blocks[block_index]
            visited.add(block_index)
            for char_index, char in enumerate(block.text):
                merged_chars.append(char)
                char_refs.append((block_index, char_index))
        line_count += 1
    for block_index, block in enumerate(scene_index.blocks):
        if block_index in visited or not block.text.strip():
            continue
        if line_count > 0:
            self._append_ocr_page_separator(merged_chars, char_refs, "\n")
        for char_index, char in enumerate(block.text):
            merged_chars.append(char)
            char_refs.append((block_index, char_index))
        line_count += 1
    if not visited and not any(block.text.strip() for block in scene_index.blocks):
        return None
    return _OCRPageDocument(
        line_index=0,
        blocks=scene_index.blocks,
        text="".join(merged_chars),
        char_refs=tuple(char_refs),
    )

def _build_ocr_scene_index(self, blocks: tuple[OCRTextBlock, ...] | list[OCRTextBlock]) -> _OCRSceneIndex:
    block_tuple = tuple(blocks)
    lines = self._group_blocks_by_page_line(list(block_tuple))
    block_index_by_identity = {id(block): index for index, block in enumerate(block_tuple)}
    indexed_lines: list[tuple[int, ...]] = []
    position_by_block_index: dict[int, tuple[int, int]] = {}
    assigned: set[int] = set()
    for line in lines:
        indexed_line: list[int] = []
        for block in line:
            block_index = block_index_by_identity.get(id(block))
            if block_index is None:
                continue
            position_by_block_index[block_index] = (len(indexed_lines), len(indexed_line))
            indexed_line.append(block_index)
            assigned.add(block_index)
        if indexed_line:
            indexed_lines.append(tuple(indexed_line))
    for block_index in range(len(block_tuple)):
        if block_index in assigned:
            continue
        position_by_block_index[block_index] = (len(indexed_lines), 0)
        indexed_lines.append((block_index,))
    return _OCRSceneIndex(
        blocks=block_tuple,
        lines=tuple(indexed_lines),
        position_by_block_index=position_by_block_index,
    )

def _group_blocks_by_page_line(self, ocr_blocks: list[OCRTextBlock]) -> list[list[OCRTextBlock]]:
    """按 bbox 的垂直重叠关系将 OCR block 近似聚成页面文本行。"""
    sortable = [block for block in ocr_blocks if block.bbox is not None and block.text.strip()]
    sortable.sort(key=lambda item: (self._bbox_center_y(item.bbox), item.bbox.x))
    lines: list[list[OCRTextBlock]] = []
    for block in sortable:
        assigned = False
        for line in lines:
            if self._belongs_to_same_page_line(line, block):
                line.append(block)
                line.sort(key=lambda item: item.bbox.x if item.bbox is not None else 0)
                assigned = True
                break
        if not assigned:
            lines.append([block])
    return lines

def _collect_ocr_block_chains(self, scene_index: _OCRSceneIndex) -> list[list[tuple[int, str]]]:
    """按 block 级别选择右邻或下邻后继，构建 OCR 阅读链。"""
    if not scene_index.lines:
        return []
    page_order = [block_index for line in scene_index.lines for block_index in line]
    position_by_key = {block_index: index for index, block_index in enumerate(page_order)}
    proposals = self._collect_ocr_successor_proposals(scene_index)
    accepted: dict[int, tuple[int, str]] = {}
    used_sources: set[int] = set()
    used_targets: set[int] = set()
    for source_key, target_key, separator, score in sorted(
        proposals,
        key=lambda item: (-item[3], position_by_key[item[0]], position_by_key[item[1]]),
    ):
        if source_key in used_sources or target_key in used_targets:
            continue
        accepted[source_key] = (target_key, separator)
        used_sources.add(source_key)
        used_targets.add(target_key)

    start_keys = [key for key in page_order if key not in used_targets]
    visited: set[int] = set()
    chains: list[list[tuple[int, str]]] = []
    for start_key in start_keys:
        if start_key in visited:
            continue
        chain: list[tuple[int, str]] = []
        current_key = start_key
        separator = ""
        while current_key not in visited:
            visited.add(current_key)
            chain.append((current_key, separator))
            next_item = accepted.get(current_key)
            if next_item is None:
                break
            current_key, separator = next_item
        if chain:
            chains.append(chain)
    for key in page_order:
        if key in visited:
            continue
        chains.append([(key, "")])
        visited.add(key)
    return chains

def _collect_ocr_successor_proposals(
    self,
    scene_index: _OCRSceneIndex,
) -> list[tuple[int, int, str, float]]:
    """为每个 block 提议右邻/下邻后继，再交给贪心匹配挑选。"""
    proposals: list[tuple[int, int, str, float]] = []
    for line_index, line in enumerate(scene_index.lines):
        for item_index, source_block_index in enumerate(line):
            right_candidate = self._horizontal_successor_proposal(scene_index, line_index, item_index)
            if right_candidate is not None:
                proposals.append((source_block_index, right_candidate[0], right_candidate[1], right_candidate[2]))
            down_candidate = self._downward_successor_proposal(scene_index, line_index, item_index)
            if down_candidate is not None:
                proposals.append((source_block_index, down_candidate[0], down_candidate[1], down_candidate[2]))
    return proposals

def _horizontal_successor_proposal(
    self,
    scene_index: _OCRSceneIndex,
    line_index: int,
    item_index: int,
) -> tuple[int, str, float] | None:
    """提议同一行内的右侧后继。"""
    line = scene_index.lines[line_index]
    if item_index + 1 >= len(line):
        return None
    source_block_index = line[item_index]
    target_block_index = line[item_index + 1]
    score = self._score_horizontal_successor_by_index(scene_index, source_block_index, target_block_index)
    if score is None:
        return None
    return target_block_index, self._block_join_separator_by_index(scene_index, source_block_index, target_block_index), score

def _downward_successor_proposal(
    self,
    scene_index: _OCRSceneIndex,
    line_index: int,
    item_index: int,
) -> tuple[int, str, float] | None:
    """提议更像是纵向续写的下方后继。"""
    source_line = scene_index.lines[line_index]
    source_block_index = source_line[item_index]
    source_prefix = source_line[: item_index + 1]
    best_target: tuple[int, str, float] | None = None
    for next_line_index in range(line_index + 1, len(scene_index.lines)):
        next_line = scene_index.lines[next_line_index]
        line_score = self._score_vertical_line_successor_by_indices(scene_index, source_prefix, next_line)
        if line_score is None:
            continue
        for target_block_index in next_line:
            block_score = self._score_vertical_block_successor_by_index(
                scene_index,
                source_block_index,
                target_block_index,
            )
            if block_score is None:
                continue
            score = line_score * 0.45 + block_score * 0.55
            if best_target is None or score > best_target[2]:
                best_target = (target_block_index, "\n", score)
        if best_target is not None:
            return best_target
    return None

def _belongs_to_same_page_line(self, line: list[OCRTextBlock], block: OCRTextBlock) -> bool:
    """判断一个 OCR block 是否应并入已有页面文本行。"""
    if block.bbox is None or not line:
        return False
    line_tops = [item.bbox.y for item in line if item.bbox is not None]
    line_bottoms = [item.bbox.y + item.bbox.height for item in line if item.bbox is not None]
    line_centers = [self._bbox_center_y(item.bbox) for item in line if item.bbox is not None]
    if not line_tops or not line_bottoms or not line_centers:
        return False
    line_top = min(line_tops)
    line_bottom = max(line_bottoms)
    overlap = min(line_bottom, block.bbox.y + block.bbox.height) - max(line_top, block.bbox.y)
    min_height = min(
        block.bbox.height,
        min((item.bbox.height for item in line if item.bbox is not None), default=block.bbox.height),
    )
    center_delta = abs(sum(line_centers) / len(line_centers) - self._bbox_center_y(block.bbox))
    center_delta_threshold = self._clamped_ocr_tolerance(
        float(block.bbox.height),
        ratio=0.28,
        min_px=4.0,
        max_px=10.0,
    )
    return overlap >= max(1, int(min_height * 0.35)) or center_delta <= center_delta_threshold

def _ocr_horizontal_gap_thresholds(self, *, min_height: float, avg_height: float) -> tuple[float, float]:
    token_gap = self._clamped_ocr_tolerance(min_height, ratio=0.4, min_px=6.0, max_px=12.0)
    word_gap = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    return token_gap, max(token_gap, word_gap)


def _classify_ocr_horizontal_gap(self, *, gap: float, min_height: float, avg_height: float) -> str:
    token_gap, word_gap = self._ocr_horizontal_gap_thresholds(min_height=min_height, avg_height=avg_height)
    if gap <= token_gap:
        return "token"
    if gap <= word_gap:
        return "word"
    return "column"


def _ocr_pair_geometry(
    self,
    scene_index: _OCRSceneIndex,
    source_block_index: int,
    target_block_index: int,
    *,
    direction: str,
) -> _OCRPairGeometry | None:
    cache_key = (source_block_index, target_block_index, direction)
    cached = scene_index.pair_geometry_cache.get(cache_key)
    if cache_key in scene_index.pair_geometry_cache:
        return cached
    if (
        source_block_index < 0
        or target_block_index < 0
        or source_block_index >= len(scene_index.blocks)
        or target_block_index >= len(scene_index.blocks)
    ):
        scene_index.pair_geometry_cache[cache_key] = None
        return None
    source_block = scene_index.blocks[source_block_index]
    target_block = scene_index.blocks[target_block_index]
    if source_block.bbox is None or target_block.bbox is None:
        scene_index.pair_geometry_cache[cache_key] = None
        return None
    source_box = source_block.bbox
    target_box = target_block.bbox
    min_height = float(min(source_box.height, target_box.height))
    max_height = float(max(source_box.height, target_box.height))
    avg_height = (source_box.height + target_box.height) / 2
    horizontal_gap = max(0.0, float(target_box.x - (source_box.x + source_box.width)))
    vertical_gap = max(0.0, float(target_box.y - (source_box.y + source_box.height)))
    center_delta = abs(self._bbox_center_y(source_box) - self._bbox_center_y(target_box))
    left_edge_delta = abs(source_box.x - target_box.x)
    vertical_overlap = max(
        0,
        min(source_box.y + source_box.height, target_box.y + target_box.height) - max(source_box.y, target_box.y),
    )
    vertical_overlap_ratio = vertical_overlap / max(1.0, min_height)
    horizontal_overlap = max(
        0,
        min(source_box.x + source_box.width, target_box.x + target_box.width) - max(source_box.x, target_box.x),
    )
    horizontal_overlap_ratio = horizontal_overlap / max(1.0, float(min(source_box.width, target_box.width)))
    gap_kind = None
    if direction == "right":
        gap_kind = self._classify_ocr_horizontal_gap(
            gap=horizontal_gap,
            min_height=min_height,
            avg_height=avg_height,
        )
    geometry = _OCRPairGeometry(
        source_block_index=source_block_index,
        target_block_index=target_block_index,
        direction=direction,
        min_height_px=min_height,
        avg_height_px=avg_height,
        max_height_px=max_height,
        gap_px=horizontal_gap,
        vertical_gap_px=vertical_gap,
        center_delta_px=center_delta,
        left_edge_delta_px=left_edge_delta,
        vertical_overlap_ratio=vertical_overlap_ratio,
        horizontal_overlap_ratio=horizontal_overlap_ratio,
        height_ratio=max_height / max(1.0, min_height),
        gap_kind=gap_kind,
    )
    scene_index.pair_geometry_cache[cache_key] = geometry
    return geometry


def _block_join_separator_by_index(
    self,
    scene_index: _OCRSceneIndex,
    left_block_index: int,
    right_block_index: int,
) -> str:
    if not self._blocks_semantically_related_by_index(scene_index, left_block_index, right_block_index):
        return _OCR_SEMANTIC_BREAK_TOKEN
    left = scene_index.blocks[left_block_index]
    right = scene_index.blocks[right_block_index]
    left_char = left.text[-1:] if left.text else ""
    right_char = right.text[:1] if right.text else ""
    if not left_char or not right_char:
        return ""
    geometry = self._ocr_pair_geometry(scene_index, left_block_index, right_block_index, direction="right")
    if geometry is None or geometry.gap_kind == "token":
        return ""
    if geometry.gap_kind == "word" and left_char.isascii() and left_char.isalnum() and right_char.isascii() and right_char.isalnum():
        return " "
    return ""


def _blocks_semantically_related_by_index(
    self,
    scene_index: _OCRSceneIndex,
    left_block_index: int,
    right_block_index: int,
) -> bool:
    geometry = self._ocr_pair_geometry(scene_index, left_block_index, right_block_index, direction="right")
    if geometry is None:
        left = scene_index.blocks[left_block_index]
        right = scene_index.blocks[right_block_index]
        return left.bbox is None or right.bbox is None
    if geometry.gap_kind == "column":
        return False
    left_box = scene_index.blocks[left_block_index].bbox
    right_box = scene_index.blocks[right_block_index].bbox
    if left_box is None or right_box is None:
        return True
    top_delta = abs(left_box.y - right_box.y)
    bottom_delta = abs((left_box.y + left_box.height) - (right_box.y + right_box.height))
    center_delta_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.3, min_px=4.0, max_px=10.0)
    left_edge_threshold = self._clamped_ocr_tolerance(geometry.min_height_px, ratio=0.35, min_px=6.0, max_px=12.0)
    vertical_delta_threshold = self._clamped_ocr_tolerance(geometry.max_height_px, ratio=0.2, min_px=4.0, max_px=8.0)
    overlap_center_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.22, min_px=4.0, max_px=8.0)
    left_edge_aligned = geometry.left_edge_delta_px <= left_edge_threshold
    if geometry.vertical_overlap_ratio < 0.38 and geometry.center_delta_px > center_delta_threshold:
        return False
    if left_edge_aligned and (
        geometry.height_ratio >= 1.55
        or top_delta > vertical_delta_threshold
        or bottom_delta > vertical_delta_threshold
    ):
        return False
    if geometry.horizontal_overlap_ratio >= 0.45 and geometry.center_delta_px > overlap_center_threshold:
        return False
    return True


def _score_horizontal_successor_by_index(
    self,
    scene_index: _OCRSceneIndex,
    left_block_index: int,
    right_block_index: int,
) -> float | None:
    geometry = self._ocr_pair_geometry(scene_index, left_block_index, right_block_index, direction="right")
    if geometry is None or not self._blocks_semantically_related_by_index(scene_index, left_block_index, right_block_index):
        return None
    if geometry.gap_kind == "column":
        return None
    _, word_gap = self._ocr_horizontal_gap_thresholds(
        min_height=geometry.min_height_px,
        avg_height=geometry.avg_height_px,
    )
    center_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.3, min_px=4.0, max_px=10.0)
    score = 1.0
    score -= 0.55 * min(1.0, geometry.gap_px / max(1.0, word_gap))
    score -= 0.3 * min(1.0, geometry.center_delta_px / max(1.0, center_threshold))
    score -= 0.15 * min(1.0, max(0.0, geometry.height_ratio - 1.0) / 0.45)
    if geometry.gap_kind == "token":
        score += 0.06
    return max(0.0, score)


def _score_vertical_line_successor_by_indices(
    self,
    scene_index: _OCRSceneIndex,
    previous_line_indices: tuple[int, ...],
    current_line_indices: tuple[int, ...],
) -> float | None:
    if not previous_line_indices or not current_line_indices:
        return None
    previous_line = [scene_index.blocks[index] for index in previous_line_indices]
    current_line = [scene_index.blocks[index] for index in current_line_indices]
    if not self._lines_semantically_related(previous_line, current_line):
        return None
    previous_box = self._combine_bboxes(block.bbox for block in previous_line if block.bbox is not None)
    current_box = self._combine_bboxes(block.bbox for block in current_line if block.bbox is not None)
    if previous_box is None or current_box is None:
        return None
    avg_height = (previous_box.height + current_box.height) / 2
    vertical_gap = max(0.0, float(current_box.y - (previous_box.y + previous_box.height)))
    left_edge_delta = abs(previous_box.x - current_box.x)
    gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=6.0, max_px=16.0)
    left_edge_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    score = 1.0
    score -= 0.45 * min(1.0, vertical_gap / max(1.0, gap_threshold))
    score -= 0.45 * min(1.0, left_edge_delta / max(1.0, left_edge_threshold))
    previous_text = "".join(block.text.strip() for block in previous_line)
    current_text = "".join(block.text.strip() for block in current_line)
    if self._looks_like_short_numeric_metadata(current_text) and len(previous_text) >= 6:
        score -= 0.25
    return max(0.0, score)


def _score_vertical_block_successor_by_index(
    self,
    scene_index: _OCRSceneIndex,
    upper_block_index: int,
    lower_block_index: int,
) -> float | None:
    geometry = self._ocr_pair_geometry(scene_index, upper_block_index, lower_block_index, direction="down")
    if geometry is None:
        return None
    upper = scene_index.blocks[upper_block_index]
    lower = scene_index.blocks[lower_block_index]
    if upper.bbox is None or lower.bbox is None:
        return None
    if self._bbox_center_y(lower.bbox) <= self._bbox_center_y(upper.bbox):
        return None
    if self._looks_like_short_numeric_metadata(lower.text.strip()) and len(upper.text.strip()) >= 6:
        return None
    left_edge_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.35, min_px=6.0, max_px=12.0)
    if geometry.left_edge_delta_px > left_edge_threshold and geometry.horizontal_overlap_ratio < 0.35:
        return None
    vertical_gap_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.4, min_px=4.0, max_px=10.0)
    if geometry.height_ratio > 1.35:
        return None
    score = 1.0
    score -= 0.4 * min(1.0, geometry.left_edge_delta_px / max(1.0, left_edge_threshold))
    score -= 0.35 * min(1.0, geometry.vertical_gap_px / max(1.0, vertical_gap_threshold))
    score -= 0.15 * min(1.0, max(0.0, geometry.height_ratio - 1.0) / 0.35)
    score += 0.1 * min(1.0, geometry.horizontal_overlap_ratio)
    return max(0.0, score)


def _block_join_separator(self, left: OCRTextBlock, right: OCRTextBlock) -> str:
    """决定两个相邻 OCR block 在拼接时是否需要补空格。"""
    if left.bbox is None or right.bbox is None:
        return ""
    if not self._blocks_semantically_related(left, right):
        return _OCR_SEMANTIC_BREAK_TOKEN
    left_char = left.text[-1:] if left.text else ""
    right_char = right.text[:1] if right.text else ""
    if not left_char or not right_char:
        return ""
    min_height = float(min(left.bbox.height, right.bbox.height))
    avg_height = (left.bbox.height + right.bbox.height) / 2
    gap = max(0.0, float(right.bbox.x - (left.bbox.x + left.bbox.width)))
    gap_kind = self._classify_ocr_horizontal_gap(gap=gap, min_height=min_height, avg_height=avg_height)
    if gap_kind == "token":
        return ""
    if gap_kind == "word" and left_char.isascii() and left_char.isalnum() and right_char.isascii() and right_char.isalnum():
        return " "
    return ""

def _append_ocr_page_separator(
    self,
    merged_chars: list[str],
    char_refs: list[tuple[int, int] | None],
    separator: str,
) -> None:
    for char in separator:
        merged_chars.append(char)
        char_refs.append(None)

def _line_join_separator(
    self,
    previous_line: list[OCRTextBlock] | None,
    current_line: list[OCRTextBlock],
) -> str:
    if not previous_line:
        return "\n"
    if self._lines_semantically_related(previous_line, current_line):
        return "\n"
    return _OCR_SEMANTIC_BREAK_TOKEN

def _blocks_semantically_related(self, left: OCRTextBlock, right: OCRTextBlock) -> bool:
    """根据 bbox 几何关系判断两个 OCR block 是否应视为同一语义片段。"""
    if left.bbox is None or right.bbox is None:
        return True
    left_box = left.bbox
    right_box = right.bbox
    min_height = float(min(left_box.height, right_box.height))
    max_height = float(max(left_box.height, right_box.height))
    avg_height = (left_box.height + right_box.height) / 2
    top_delta = abs(left_box.y - right_box.y)
    bottom_delta = abs((left_box.y + left_box.height) - (right_box.y + right_box.height))
    center_delta = abs(self._bbox_center_y(left_box) - self._bbox_center_y(right_box))
    gap = right_box.x - (left_box.x + left_box.width)
    vertical_overlap = max(0, min(left_box.y + left_box.height, right_box.y + right_box.height) - max(left_box.y, right_box.y))
    vertical_overlap_ratio = vertical_overlap / max(1.0, min_height)
    height_ratio = max_height / max(1.0, min_height)
    gap_kind = self._classify_ocr_horizontal_gap(gap=gap, min_height=min_height, avg_height=avg_height)
    center_delta_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.3, min_px=4.0, max_px=10.0)
    left_edge_threshold = self._clamped_ocr_tolerance(min_height, ratio=0.35, min_px=6.0, max_px=12.0)
    vertical_delta_threshold = self._clamped_ocr_tolerance(max_height, ratio=0.2, min_px=4.0, max_px=8.0)
    overlap_center_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.22, min_px=4.0, max_px=8.0)
    left_edge_aligned = abs(left_box.x - right_box.x) <= left_edge_threshold
    horizontal_overlap = max(0, min(left_box.x + left_box.width, right_box.x + right_box.width) - max(left_box.x, right_box.x))
    horizontal_overlap_ratio = horizontal_overlap / max(1.0, float(min(left_box.width, right_box.width)))

    if gap_kind == "column":
        return False
    if vertical_overlap_ratio < 0.38 and center_delta > center_delta_threshold:
        return False
    if left_edge_aligned and (
        height_ratio >= 1.55
        or top_delta > vertical_delta_threshold
        or bottom_delta > vertical_delta_threshold
    ):
        return False
    if horizontal_overlap_ratio >= 0.45 and center_delta > overlap_center_threshold:
        return False
    return True

def _lines_semantically_related(self, previous_line: list[OCRTextBlock], current_line: list[OCRTextBlock]) -> bool:
    """判断相邻页面文本行是否像同一语义片段的连续换行。"""
    previous_boxes = [block.bbox for block in previous_line if block.bbox is not None]
    current_boxes = [block.bbox for block in current_line if block.bbox is not None]
    if not previous_boxes or not current_boxes:
        return True
    previous_box = self._combine_bboxes(previous_boxes)
    current_box = self._combine_bboxes(current_boxes)
    previous_head = next((block for block in previous_line if block.bbox is not None), None)
    current_head = next((block for block in current_line if block.bbox is not None), None)
    if previous_box is None or current_box is None or previous_head is None or current_head is None:
        return True
    previous_heights = [box.height for box in previous_boxes]
    current_heights = [box.height for box in current_boxes]
    avg_height = (sum(previous_heights) / len(previous_heights) + sum(current_heights) / len(current_heights)) / 2
    min_height = float(min(min(previous_heights), min(current_heights)))
    max_height = float(max(max(previous_heights), max(current_heights)))
    height_ratio = max_height / max(1.0, min_height)
    vertical_gap = current_box.y - (previous_box.y + previous_box.height)
    left_edge_delta = abs(previous_head.bbox.x - current_head.bbox.x)
    vertical_gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=6.0, max_px=16.0)
    left_edge_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    horizontal_overlap_gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.45, min_px=6.0, max_px=12.0)
    horizontal_overlap = max(
        0,
        min(previous_box.x + previous_box.width, current_box.x + current_box.width) - max(previous_box.x, current_box.x),
    )
    horizontal_overlap_ratio = horizontal_overlap / max(1.0, float(min(previous_box.width, current_box.width)))
    previous_text = "".join(block.text.strip() for block in previous_line)
    current_text = "".join(block.text.strip() for block in current_line)

    if vertical_gap > vertical_gap_threshold:
        return False
    if height_ratio > 1.55:
        return False
    if (
        left_edge_delta <= left_edge_threshold
        and len(previous_text) <= 6
        and len(current_text) >= 8
        and current_box.width >= previous_box.width * 1.8
    ):
        return False
    if left_edge_delta <= left_edge_threshold:
        return True
    return horizontal_overlap_ratio >= 0.55 and vertical_gap <= horizontal_overlap_gap_threshold

def _score_horizontal_successor(self, left: OCRTextBlock, right: OCRTextBlock) -> float | None:
    """给同一行右邻 block 计算续写分数。"""
    if left.bbox is None or right.bbox is None:
        return None
    if not self._blocks_semantically_related(left, right):
        return None
    avg_height = (left.bbox.height + right.bbox.height) / 2
    min_height = float(min(left.bbox.height, right.bbox.height))
    gap = max(0.0, float(right.bbox.x - (left.bbox.x + left.bbox.width)))
    gap_kind = self._classify_ocr_horizontal_gap(gap=gap, min_height=min_height, avg_height=avg_height)
    if gap_kind == "column":
        return None
    _, gap_threshold = self._ocr_horizontal_gap_thresholds(min_height=min_height, avg_height=avg_height)
    center_delta = abs(self._bbox_center_y(left.bbox) - self._bbox_center_y(right.bbox))
    center_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.3, min_px=4.0, max_px=10.0)
    max_height = float(max(left.bbox.height, right.bbox.height))
    height_ratio = max_height / max(1.0, min_height)
    score = 1.0
    score -= 0.55 * min(1.0, gap / max(1.0, gap_threshold))
    score -= 0.3 * min(1.0, center_delta / max(1.0, center_threshold))
    score -= 0.15 * min(1.0, max(0.0, height_ratio - 1.0) / 0.45)
    if gap_kind == "token":
        score += 0.06
    return max(0.0, score)

def _score_vertical_line_successor(
    self,
    previous_line: list[OCRTextBlock],
    current_line: list[OCRTextBlock],
) -> float | None:
    """给纵向续写的整行关系计算分数。"""
    if not previous_line or not current_line:
        return None
    if not self._lines_semantically_related(previous_line, current_line):
        return None
    previous_box = self._combine_bboxes(block.bbox for block in previous_line if block.bbox is not None)
    current_box = self._combine_bboxes(block.bbox for block in current_line if block.bbox is not None)
    if previous_box is None or current_box is None:
        return None
    avg_height = (previous_box.height + current_box.height) / 2
    vertical_gap = max(0.0, float(current_box.y - (previous_box.y + previous_box.height)))
    left_edge_delta = abs(previous_box.x - current_box.x)
    gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=6.0, max_px=16.0)
    left_edge_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    score = 1.0
    score -= 0.45 * min(1.0, vertical_gap / max(1.0, gap_threshold))
    score -= 0.45 * min(1.0, left_edge_delta / max(1.0, left_edge_threshold))
    previous_text = "".join(block.text.strip() for block in previous_line)
    current_text = "".join(block.text.strip() for block in current_line)
    if self._looks_like_short_numeric_metadata(current_text) and len(previous_text) >= 6:
        score -= 0.25
    return max(0.0, score)

def _score_vertical_block_successor(self, upper: OCRTextBlock, lower: OCRTextBlock) -> float | None:
    """给纵向 block 续写关系计算分数。"""
    if upper.bbox is None or lower.bbox is None:
        return None
    if self._bbox_center_y(lower.bbox) <= self._bbox_center_y(upper.bbox):
        return None
    if self._looks_like_short_numeric_metadata(lower.text.strip()) and len(upper.text.strip()) >= 6:
        return None
    avg_height = (upper.bbox.height + lower.bbox.height) / 2
    left_edge_delta = abs(upper.bbox.x - lower.bbox.x)
    left_edge_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.35, min_px=6.0, max_px=12.0)
    horizontal_overlap = max(
        0,
        min(upper.bbox.x + upper.bbox.width, lower.bbox.x + lower.bbox.width) - max(upper.bbox.x, lower.bbox.x),
    )
    min_width = float(min(upper.bbox.width, lower.bbox.width))
    horizontal_overlap_ratio = horizontal_overlap / max(1.0, min_width)
    if left_edge_delta > left_edge_threshold and horizontal_overlap_ratio < 0.35:
        return None
    vertical_gap = max(0.0, float(lower.bbox.y - (upper.bbox.y + upper.bbox.height)))
    vertical_gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.4, min_px=4.0, max_px=10.0)
    min_height = float(min(upper.bbox.height, lower.bbox.height))
    max_height = float(max(upper.bbox.height, lower.bbox.height))
    height_ratio = max_height / max(1.0, min_height)
    if height_ratio > 1.35:
        return None
    score = 1.0
    score -= 0.4 * min(1.0, left_edge_delta / max(1.0, left_edge_threshold))
    score -= 0.35 * min(1.0, vertical_gap / max(1.0, vertical_gap_threshold))
    score -= 0.15 * min(1.0, max(0.0, height_ratio - 1.0) / 0.35)
    score += 0.1 * min(1.0, horizontal_overlap_ratio)
    return max(0.0, score)

def _looks_like_short_numeric_metadata(self, text: str) -> bool:
    """识别短时间/计数类 UI 元信息，避免误拼成正文续写。"""
    stripped = text.strip()
    if len(stripped) > 6 or not stripped:
        return False
    if re.fullmatch(r"[\d\s:：./\-]{1,6}", stripped) is None:
        return False
    return any(char.isdigit() for char in stripped)

def _ocr_candidate_block_indices(
    self,
    candidate: PIICandidate,
    document: _OCRPageDocument,
) -> tuple[int, ...]:
    block_index_by_id = {
        block.block_id: index
        for index, block in enumerate(document.blocks)
        if block.block_id
    }
    indices: list[int] = []
    for block_id in candidate.metadata.get("ocr_block_ids", []):
        block_index = block_index_by_id.get(block_id)
        if block_index is not None:
            indices.append(block_index)
    if not indices and candidate.block_id:
        block_index = block_index_by_id.get(candidate.block_id)
        if block_index is not None:
            indices.append(block_index)
    if not indices and candidate.bbox is not None:
        for index, block in enumerate(document.blocks):
            if block.bbox == candidate.bbox and candidate.text and candidate.text in block.text:
                indices.append(index)
                break
    if not indices and len(document.blocks) == 1:
        return (0,)
    return tuple(dict.fromkeys(indices))


def _ocr_candidate_signature(self, candidate: PIICandidate) -> tuple[str, str, tuple[str, ...]]:
    block_ids = tuple(
        dict.fromkeys(
            block_id
            for block_id in [*candidate.metadata.get("ocr_block_ids", []), candidate.block_id]
            if block_id
        )
    )
    return candidate.attr_type.value, candidate.normalized_text, block_ids


def _collect_ocr_label_adjacency_candidates(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    rule_profile: _RuleStrengthProfile,
) -> list[PIICandidate]:
    candidates: list[PIICandidate] = []
    seen_signatures: set[tuple[str, str, tuple[str, ...]]] = set()
    for block_index, block in enumerate(document.blocks):
        if block.bbox is None or not block.text.strip():
            continue
        for spec, inline_value, start_offset in _match_inline_field_labels(block.text):
            candidate = self._build_ocr_inline_label_candidate(
                document,
                scene_index,
                label_block_index=block_index,
                spec=spec,
                inline_value=inline_value,
                inline_start_offset=start_offset,
                rule_profile=rule_profile,
            )
            if candidate is None:
                continue
            signature = self._ocr_candidate_signature(candidate)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            candidates.append(candidate)
        for spec in self._ocr_label_specs_for_block(block):
            candidate = self._build_ocr_label_adjacency_candidate(
                document,
                scene_index,
                label_block_index=block_index,
                spec=spec,
                rule_profile=rule_profile,
            )
            if candidate is None:
                continue
            signature = self._ocr_candidate_signature(candidate)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            candidates.append(candidate)
    return candidates


def _collect_ocr_standalone_name_candidates(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    existing_candidates: tuple[PIICandidate, ...],
    rule_profile: _RuleStrengthProfile,
) -> list[PIICandidate]:
    page_ranges: dict[int, tuple[int, int]] = {}
    for page_index, ref in enumerate(document.char_refs):
        if ref is None:
            continue
        block_index, _ = ref
        current = page_ranges.get(block_index)
        if current is None:
            page_ranges[block_index] = (page_index, page_index + 1)
        else:
            page_ranges[block_index] = (current[0], page_index + 1)
    consumed_name_blocks: set[int] = set()
    for candidate in existing_candidates:
        if candidate.attr_type != PIIAttributeType.NAME or candidate.source != PIISourceType.OCR:
            continue
        consumed_name_blocks.update(self._ocr_candidate_block_indices(candidate, document))
    previous_context_text = getattr(self, "_active_standalone_context_text", None)
    previous_context_candidates = getattr(self, "_active_standalone_context_candidates", ())
    self._active_standalone_context_text = document.text
    self._active_standalone_context_candidates = tuple(existing_candidates)
    try:
        candidates: list[PIICandidate] = []
        seen_signatures: set[tuple[str, str, tuple[str, ...]]] = set()
        bound_anchor_keys: set[str] = set()
        for block_index, block in enumerate(document.blocks):
            if (
                block_index in consumed_name_blocks
                or not block.text.strip()
                or self._is_ocr_pure_label_block(block)
                or self._contains_field_keyword(block.text)
                or self._looks_like_ui_time_metadata(block.text)
                or self._looks_like_bracketed_ui_label(block.text)
            ):
                continue
            page_span = page_ranges.get(block_index)
            if page_span is None:
                continue
            scene_mode, scene_bonus = self._ocr_standalone_scene_mode(document, scene_index, block_index)
            local_skip_spans: list[tuple[int, int]] = []
            name_matches: list[tuple[re.Match[str], str]] = [
                (match, "heuristic_name_fragment")
                for match in self.generic_name_pattern.finditer(block.text)
            ]
            if self._supports_en():
                name_matches.extend(
                    (match, "heuristic_name_fragment_en")
                    for match in self.en_standalone_name_pattern.finditer(block.text)
                )
            for match, matched_by in name_matches:
                extracted = self._extract_match(block.text, *match.span("value"))
                if extracted is None:
                    continue
                value, local_start, local_end = extracted
                if self._overlaps_any_span(local_start, local_end, local_skip_spans):
                    continue
                if not self._ocr_match_covers_standalone_block(block.text, local_start, local_end):
                    continue
                canonical_source_text = self._canonical_name_source_text(
                    value,
                    allow_ocr_noise=True,
                )
                validator_value = canonical_source_text or value
                if not self._is_name_candidate(validator_value):
                    continue
                page_start = page_span[0] + local_start
                page_end = page_span[0] + local_end
                confidence = self._generic_name_confidence(
                    document.text,
                    page_start,
                    page_end,
                    value=validator_value,
                    source=PIISourceType.OCR,
                    rule_profile=rule_profile,
                )
                anchor_key = None
                if scene_mode == "multi_name":
                    confidence = max(confidence, min(0.9, 0.74 + scene_bonus))
                else:
                    anchor_key, anchor_bonus = self._ocr_single_name_anchor_binding(
                        document,
                        scene_index,
                        block_index=block_index,
                        existing_candidates=existing_candidates,
                    )
                    if anchor_key is None and confidence <= 0.0:
                        continue
                    if anchor_key is not None and anchor_key in bound_anchor_keys:
                        continue
                    confidence = max(confidence, min(0.92, confidence + anchor_bonus))
                if confidence <= 0.0:
                    continue
                candidate = self._build_ocr_inline_value_candidate(
                    document,
                    block_index=block_index,
                    text=value,
                    attr_type=PIIAttributeType.NAME,
                    confidence=confidence,
                    canonical_source_text=canonical_source_text,
                    span_start=local_start,
                    span_end=local_end,
                    metadata=self._merge_candidate_metadata(
                        {
                            "matched_by": [matched_by],
                            "ocr_block_ids": [block.block_id] if block.block_id else [],
                            "ocr_postpass": ["standalone_name"],
                            "ocr_standalone_scene": [scene_mode],
                        },
                        self._name_component_metadata("full"),
                    ),
                )
                if candidate is None:
                    continue
                if anchor_key is not None:
                    candidate.metadata = self._merge_candidate_metadata(
                        candidate.metadata,
                        {"ocr_anchor_entity_id": [anchor_key]},
                    )
                signature = self._ocr_candidate_signature(candidate)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                candidates.append(candidate)
                if anchor_key is not None:
                    bound_anchor_keys.add(anchor_key)
                local_skip_spans.append((local_start, local_end))
        return candidates
    finally:
        self._active_standalone_context_text = previous_context_text
        self._active_standalone_context_candidates = previous_context_candidates


def _ocr_match_covers_standalone_block(
    self,
    block_text: str,
    span_start: int,
    span_end: int,
) -> bool:
    prefix = block_text[:span_start]
    suffix = block_text[span_end:]
    allowed_noise = r"[\s:：,，.。;；/\\|｜()\[\]{}<>《》【】\"'`·•_\-]*"
    return re.fullmatch(allowed_noise, prefix or "") is not None and re.fullmatch(allowed_noise, suffix or "") is not None


def _ocr_standalone_scene_mode(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    block_index: int,
) -> tuple[str, float]:
    position = scene_index.position_by_block_index.get(block_index)
    block = document.blocks[block_index]
    if position is None or block.bbox is None:
        return "single_name", 0.0
    line_index, _ = position
    peer_count = 0
    for line_offset in (-3, -2, -1, 1, 2, 3):
        peer_line_index = line_index + line_offset
        if not 0 <= peer_line_index < len(scene_index.lines):
            continue
        for peer_index in scene_index.lines[peer_line_index]:
            if peer_index == block_index:
                continue
            peer_block = document.blocks[peer_index]
            if not self._ocr_block_is_standalone_name_shape(peer_block):
                continue
            if peer_block.bbox is None:
                continue
            height_ratio = peer_block.bbox.height / max(1.0, float(block.bbox.height))
            if not 0.7 <= height_ratio <= 1.45:
                continue
            left_delta = abs(peer_block.bbox.x - block.bbox.x)
            left_threshold = self._clamped_ocr_tolerance(float(block.bbox.height), ratio=2.4, min_px=22.0, max_px=120.0)
            if left_delta > left_threshold:
                continue
            peer_count += 1
            if peer_count >= 2:
                return "multi_name", 0.14 + min(0.1, 0.03 * peer_count)
    return "single_name", 0.0


def _ocr_block_is_standalone_name_shape(self, block: OCRTextBlock) -> bool:
    text = self._clean_extracted_value(block.text)
    if not text or self._contains_field_keyword(text) or self._looks_like_ui_time_metadata(text) or self._looks_like_bracketed_ui_label(text):
        return False
    for match in self.generic_name_pattern.finditer(text):
        if self._ocr_match_covers_standalone_block(text, *match.span("value")):
            return True
    if self._supports_en():
        for match in self.en_standalone_name_pattern.finditer(text):
            if self._ocr_match_covers_standalone_block(text, *match.span("value")):
                return True
    return False


def _ocr_single_name_anchor_binding(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    block_index: int,
    existing_candidates: tuple[PIICandidate, ...],
) -> tuple[str | None, float]:
    position = scene_index.position_by_block_index.get(block_index)
    if position is None:
        return None, 0.0
    line_index, item_index = position
    best_anchor: tuple[str, float] | None = None
    strong_types = {
        PIIAttributeType.PHONE,
        PIIAttributeType.EMAIL,
        PIIAttributeType.ID_NUMBER,
        PIIAttributeType.CARD_NUMBER,
        PIIAttributeType.BANK_ACCOUNT,
        PIIAttributeType.PASSPORT_NUMBER,
        PIIAttributeType.DRIVER_LICENSE,
        PIIAttributeType.ADDRESS,
    }
    for candidate in existing_candidates:
        if candidate.attr_type not in strong_types:
            continue
        candidate_blocks = self._ocr_candidate_block_indices(candidate, document)
        if not candidate_blocks:
            continue
        distances: list[float] = []
        for candidate_block_index in candidate_blocks:
            candidate_position = scene_index.position_by_block_index.get(candidate_block_index)
            if candidate_position is None:
                continue
            candidate_line, candidate_item = candidate_position
            line_delta = abs(candidate_line - line_index)
            item_delta = abs(candidate_item - item_index)
            if line_delta > 2 and item_delta > 2:
                continue
            distances.append(line_delta * 1.2 + item_delta * 0.35)
        if not distances:
            continue
        distance = min(distances)
        score = max(0.0, 0.18 - min(0.12, distance * 0.04))
        if score <= 0.0:
            continue
        anchor_key = candidate.entity_id
        if best_anchor is None or score > best_anchor[1]:
            best_anchor = (anchor_key, score)
    if best_anchor is None:
        return None, 0.0
    return best_anchor


def _ocr_label_specs_for_block(self, block: OCRTextBlock) -> tuple[_FieldLabelSpec, ...]:
    return _match_pure_field_labels(block.text)


def _is_ocr_pure_label_block(self, block: OCRTextBlock) -> bool:
    return bool(self._ocr_label_specs_for_block(block))


def _build_ocr_label_adjacency_candidate(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    label_block_index: int,
    spec: _FieldLabelSpec,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    candidate_options: list[PIICandidate] = []
    right_option = self._collect_ocr_right_value_chain(document, scene_index, label_block_index, spec)
    if right_option is not None:
        candidate = self._validate_ocr_label_value_chain(
            document,
            block_indices=right_option[0],
            relation_score=right_option[1],
            spec=spec,
            rule_profile=rule_profile,
        )
        if candidate is not None:
            candidate_options.append(candidate)
    down_option = self._collect_ocr_down_value_chain(document, scene_index, label_block_index, spec)
    if down_option is not None:
        candidate = self._validate_ocr_label_value_chain(
            document,
            block_indices=down_option[0],
            relation_score=down_option[1],
            spec=spec,
            rule_profile=rule_profile,
        )
        if candidate is not None:
            candidate_options.append(candidate)
    if not candidate_options:
        return None
    candidate_options.sort(
        key=lambda item: (
            item.confidence,
            len(item.metadata.get("ocr_block_ids", [])),
            -(item.bbox.y if item.bbox is not None else 0),
        ),
        reverse=True,
    )
    return candidate_options[0]


def _build_ocr_inline_label_candidate(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    label_block_index: int,
    spec: _FieldLabelSpec,
    inline_value: str,
    inline_start_offset: int,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    inline_end_offset = inline_start_offset + len(inline_value)
    candidate_options: list[PIICandidate] = []
    direct_candidate = self._validate_ocr_label_value_text(
        document,
        block_indices=(label_block_index,),
        value_text=inline_value,
        relation_score=1.0,
        spec=spec,
        rule_profile=rule_profile,
        inline_span=(inline_start_offset, inline_end_offset),
    )
    if direct_candidate is not None:
        candidate_options.append(direct_candidate)

    right_option = self._collect_ocr_right_value_chain(document, scene_index, label_block_index, spec)
    if right_option is not None:
        joined_text = self._join_inline_and_ocr_value_text(
            inline_value,
            self._join_ocr_block_text(document, right_option[0]),
        )
        candidate = self._validate_ocr_label_value_text(
            document,
            block_indices=(label_block_index, *right_option[0]),
            value_text=joined_text,
            relation_score=right_option[1],
            spec=spec,
            rule_profile=rule_profile,
        )
        if candidate is not None:
            candidate_options.append(candidate)

    down_option = self._collect_ocr_down_value_chain(document, scene_index, label_block_index, spec)
    if down_option is not None:
        joined_text = self._join_inline_and_ocr_value_text(
            inline_value,
            self._join_ocr_block_text(document, down_option[0]),
        )
        candidate = self._validate_ocr_label_value_text(
            document,
            block_indices=(label_block_index, *down_option[0]),
            value_text=joined_text,
            relation_score=down_option[1],
            spec=spec,
            rule_profile=rule_profile,
        )
        if candidate is not None:
            candidate_options.append(candidate)

    if not candidate_options:
        return None
    candidate_options.sort(
        key=lambda item: (
            item.confidence,
            len(item.metadata.get("ocr_block_ids", [])),
            -(item.bbox.y if item.bbox is not None else 0),
        ),
        reverse=True,
    )
    return candidate_options[0]


def _collect_ocr_right_value_chain(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    label_block_index: int,
    spec: _FieldLabelSpec,
) -> tuple[tuple[int, ...], float] | None:
    position = scene_index.position_by_block_index.get(label_block_index)
    label_block = document.blocks[label_block_index]
    if position is None or label_block.bbox is None:
        return None
    line_index, item_index = position
    line = scene_index.lines[line_index]
    best_anchor: tuple[int, float] | None = None
    for next_block_index in line[item_index + 1 :]:
        block = scene_index.blocks[next_block_index]
        if self._is_ocr_pure_label_block(block):
            break
        score = self._score_ocr_label_right_neighbor(scene_index, label_block_index, next_block_index, spec)
        if score is None:
            continue
        if best_anchor is None or score > best_anchor[1]:
            best_anchor = (next_block_index, score)
    if best_anchor is None:
        return None
    continuation_blocks, continuation_score = self._collect_ocr_same_line_continuation(
        document,
        scene_index,
        anchor_block_index=best_anchor[0],
        spec=spec,
    )
    block_indices = (best_anchor[0], *continuation_blocks)
    relation_score = best_anchor[1] if continuation_score is None else best_anchor[1] * 0.7 + continuation_score * 0.3
    return tuple(dict.fromkeys(block_indices)), relation_score


def _collect_ocr_down_value_chain(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    label_block_index: int,
    spec: _FieldLabelSpec,
) -> tuple[tuple[int, ...], float] | None:
    position = scene_index.position_by_block_index.get(label_block_index)
    label_block = document.blocks[label_block_index]
    if position is None or label_block.bbox is None:
        return None
    line_index, _ = position
    best_anchor: tuple[int, float] | None = None
    for next_line_index in range(line_index + 1, min(len(scene_index.lines), line_index + 5)):
        line = scene_index.lines[next_line_index]
        line_blocks = [scene_index.blocks[index] for index in line]
        if not line_blocks:
            continue
        if self._is_ocr_pure_label_block(line_blocks[0]):
            break
        for candidate_index in line:
            block = scene_index.blocks[candidate_index]
            if self._is_ocr_pure_label_block(block):
                continue
            score = self._score_ocr_label_down_neighbor(scene_index, label_block_index, candidate_index, spec)
            if score is None:
                continue
            if best_anchor is None or score > best_anchor[1]:
                best_anchor = (candidate_index, score)
        if best_anchor is not None:
            break
    if best_anchor is None:
        return None
    continuation_blocks, continuation_score = self._collect_ocr_same_line_continuation(
        document,
        scene_index,
        anchor_block_index=best_anchor[0],
        spec=spec,
    )
    block_indices = (best_anchor[0], *continuation_blocks)
    relation_score = best_anchor[1] if continuation_score is None else best_anchor[1] * 0.68 + continuation_score * 0.32
    return tuple(dict.fromkeys(block_indices)), relation_score


def _collect_ocr_same_line_continuation(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    anchor_block_index: int,
    spec: _FieldLabelSpec,
) -> tuple[tuple[int, ...], float | None]:
    position = scene_index.position_by_block_index.get(anchor_block_index)
    if position is None:
        return (), None
    line_index, item_index = position
    line = scene_index.lines[line_index]
    collected: list[int] = []
    scores: list[float] = []
    previous_block_index = anchor_block_index
    for next_block_index in line[item_index + 1 :]:
        block = scene_index.blocks[next_block_index]
        if self._is_ocr_pure_label_block(block):
            break
        if self._score_ocr_label_value_block(block, spec) is None:
            break
        successor_score = self._score_horizontal_successor_by_index(scene_index, previous_block_index, next_block_index)
        if successor_score is None or successor_score < 0.34:
            break
        collected.append(next_block_index)
        scores.append(successor_score)
        previous_block_index = next_block_index
    if not scores:
        return tuple(collected), None
    return tuple(collected), sum(scores) / len(scores)


def _score_ocr_label_value_block(self, block: OCRTextBlock, spec: _FieldLabelSpec) -> float | None:
    cleaned = self._clean_extracted_value(block.text)
    if not cleaned:
        return None
    if self._is_ocr_pure_label_block(block):
        return None
    if len(cleaned) <= 2 and re.fullmatch(r"[\W_?？!！·•]+", cleaned):
        return None
    if spec.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION}:
        if self._looks_like_ui_time_metadata(cleaned):
            return None
    if spec.attr_type == PIIAttributeType.NAME:
        if self._is_ui_operation_name_token(cleaned):
            return None
        alpha_or_cjk = sum(1 for char in cleaned if char.isalpha() or self._is_cjk_char(char))
        if alpha_or_cjk == 0:
            return None
        return min(1.0, 0.6 + alpha_or_cjk * 0.08)
    if spec.attr_type in {
        PIIAttributeType.PHONE,
        PIIAttributeType.CARD_NUMBER,
        PIIAttributeType.BANK_ACCOUNT,
        PIIAttributeType.ID_NUMBER,
    }:
        digit_count = sum(char.isdigit() for char in cleaned)
        if digit_count < 4:
            return None
        return min(1.0, 0.58 + digit_count * 0.04)
    if spec.attr_type == PIIAttributeType.EMAIL:
        return 1.0 if "@" in cleaned else 0.52
    if spec.attr_type == PIIAttributeType.ADDRESS:
        score = self._address_confidence(cleaned)
        return score if score > 0 else 0.48
    if spec.attr_type == PIIAttributeType.ORGANIZATION:
        score = self._organization_confidence(cleaned, allow_weak_suffix=True)
        return score if score > 0 else 0.5
    return 0.6


def _score_ocr_label_right_neighbor(
    self,
    scene_index: _OCRSceneIndex,
    label_block_index: int,
    value_block_index: int,
    spec: _FieldLabelSpec,
) -> float | None:
    geometry = self._ocr_pair_geometry(scene_index, label_block_index, value_block_index, direction="right")
    if geometry is None:
        return None
    label_block = scene_index.blocks[label_block_index]
    value_block = scene_index.blocks[value_block_index]
    if label_block.bbox is None or value_block.bbox is None:
        return None
    if value_block.bbox.x + value_block.bbox.width <= label_block.bbox.x:
        return None
    value_score = self._score_ocr_label_value_block(value_block, spec)
    if value_score is None:
        return None
    gap_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=6.0, min_px=28.0, max_px=220.0)
    center_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=1.5, min_px=12.0, max_px=52.0)
    if geometry.gap_px > gap_threshold * 1.6 or geometry.center_delta_px > center_threshold * 2.0:
        return None
    score = 1.0
    score -= 0.18 * min(1.0, geometry.gap_px / max(1.0, gap_threshold))
    score -= 0.18 * min(1.0, geometry.center_delta_px / max(1.0, center_threshold))
    score -= 0.12 * min(1.0, max(0.0, geometry.height_ratio - 1.0) / 1.0)
    score += 0.14 * max(0.0, value_score - 0.5)
    if geometry.gap_kind == "token":
        score += 0.04
    score += 0.04 if value_block.score >= 0.94 else 0.0
    return score if score >= 0.34 else None


def _score_ocr_label_down_neighbor(
    self,
    scene_index: _OCRSceneIndex,
    label_block_index: int,
    value_block_index: int,
    spec: _FieldLabelSpec,
) -> float | None:
    geometry = self._ocr_pair_geometry(scene_index, label_block_index, value_block_index, direction="down")
    if geometry is None:
        return None
    label_block = scene_index.blocks[label_block_index]
    value_block = scene_index.blocks[value_block_index]
    if label_block.bbox is None or value_block.bbox is None:
        return None
    if self._bbox_center_y(value_block.bbox) <= self._bbox_center_y(label_block.bbox):
        return None
    value_score = self._score_ocr_label_value_block(value_block, spec)
    if value_score is None:
        return None
    vertical_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=4.0, min_px=18.0, max_px=120.0)
    if geometry.vertical_gap_px > vertical_threshold * 1.8:
        return None
    center_x_delta = abs(
        (label_block.bbox.x + label_block.bbox.width / 2) - (value_block.bbox.x + value_block.bbox.width / 2)
    )
    align_threshold = self._clamped_ocr_tolerance(geometry.avg_height_px, ratio=2.2, min_px=18.0, max_px=84.0)
    if (
        geometry.left_edge_delta_px > align_threshold * 1.8
        and center_x_delta > align_threshold * 1.8
        and geometry.horizontal_overlap_ratio < 0.18
    ):
        return None
    score = 1.0
    score -= 0.2 * min(1.0, geometry.vertical_gap_px / max(1.0, vertical_threshold))
    score -= 0.14 * min(1.0, min(geometry.left_edge_delta_px, center_x_delta) / max(1.0, align_threshold))
    score += 0.1 * min(1.0, geometry.horizontal_overlap_ratio)
    score += 0.14 * max(0.0, value_score - 0.5)
    score += 0.04 if value_block.score >= 0.94 else 0.0
    return score if score >= 0.34 else None


def _validate_ocr_label_value_chain(
    self,
    document: _OCRPageDocument,
    *,
    block_indices: tuple[int, ...],
    relation_score: float,
    spec: _FieldLabelSpec,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    return self._validate_ocr_label_value_text(
        document,
        block_indices=block_indices,
        value_text=self._join_ocr_block_text(document, block_indices),
        relation_score=relation_score,
        spec=spec,
        rule_profile=rule_profile,
    )


def _validate_ocr_label_value_text(
    self,
    document: _OCRPageDocument,
    *,
    block_indices: tuple[int, ...],
    value_text: str,
    relation_score: float,
    spec: _FieldLabelSpec,
    rule_profile: _RuleStrengthProfile,
    inline_span: tuple[int, int] | None = None,
) -> PIICandidate | None:
    cleaned_text = self._clean_phone_candidate(value_text) if spec.attr_type == PIIAttributeType.PHONE else self._clean_extracted_value(value_text)
    if not cleaned_text:
        return None
    allow_ocr_noise = True
    canonical_source_text: str | None = None
    confidence = spec.ocr_confidence
    if spec.attr_type == PIIAttributeType.NAME:
        component = spec.name_component or "full"
        if component == "full":
            canonical_source_text = self._canonical_name_source_text(cleaned_text, allow_ocr_noise=allow_ocr_noise)
        else:
            canonical_source_text = self._canonical_name_component_source_text(
                cleaned_text,
                component=component,
                allow_ocr_noise=allow_ocr_noise,
            )
        if canonical_source_text is None:
            return None
    elif spec.attr_type == PIIAttributeType.PHONE:
        if not self._is_context_phone_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.EMAIL:
        if not self._is_email_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.ADDRESS:
        if not self._looks_like_address_candidate(cleaned_text, min_confidence=rule_profile.address_min_confidence):
            return None
        canonical_source_text = self._clean_address_candidate(cleaned_text)
        confidence = max(confidence, min(0.96, self._address_confidence(cleaned_text) + 0.08))
    elif spec.attr_type == PIIAttributeType.ID_NUMBER:
        if not self._is_id_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.CARD_NUMBER:
        if not self._is_context_card_number_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.BANK_ACCOUNT:
        if not self._is_bank_account_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.PASSPORT_NUMBER:
        if not self._is_passport_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.DRIVER_LICENSE:
        if not self._is_driver_license_candidate(cleaned_text):
            return None
        canonical_source_text = cleaned_text
    elif spec.attr_type == PIIAttributeType.ORGANIZATION:
        if not self._is_context_organization_candidate(cleaned_text):
            return None
        canonical_source_text = self._clean_organization_candidate(cleaned_text)
        confidence = max(
            confidence,
            min(0.94, self._organization_confidence(cleaned_text, allow_weak_suffix=rule_profile.allow_weak_org_suffix) + 0.08),
        )
    confidence = min(0.99, max(confidence, confidence * 0.84 + relation_score * 0.16))
    metadata = self._merge_candidate_metadata(
        {
            "matched_by": [spec.ocr_matched_by],
            "ocr_block_ids": [
                document.blocks[index].block_id
                for index in tuple(dict.fromkeys(block_indices))
                if 0 <= index < len(document.blocks) and document.blocks[index].block_id
            ],
        },
        self._name_component_metadata(spec.name_component) if spec.name_component else None,
    )
    unique_block_indices = tuple(dict.fromkeys(block_indices))
    if inline_span is not None and len(unique_block_indices) == 1:
        return self._build_ocr_inline_value_candidate(
            document,
            block_index=unique_block_indices[0],
            text=cleaned_text,
            attr_type=spec.attr_type,
            confidence=confidence,
            canonical_source_text=canonical_source_text,
            span_start=inline_span[0],
            span_end=inline_span[1],
            metadata=metadata,
        )
    return self._build_ocr_block_candidate(
        document,
        block_indices=unique_block_indices,
        text=cleaned_text,
        attr_type=spec.attr_type,
        confidence=confidence,
        canonical_source_text=canonical_source_text,
        metadata=metadata,
    )


def _build_ocr_inline_value_candidate(
    self,
    document: _OCRPageDocument,
    *,
    block_index: int,
    text: str,
    attr_type: PIIAttributeType,
    confidence: float,
    canonical_source_text: str | None,
    span_start: int,
    span_end: int,
    metadata: dict[str, list[str]] | None = None,
) -> PIICandidate | None:
    if block_index < 0 or block_index >= len(document.blocks):
        return None
    block = document.blocks[block_index]
    if block.block_id is None:
        return None
    normalized = canonicalize_pii_value(attr_type, text)
    entity_id = self.resolver.build_candidate_id(
        self.detector_mode,
        PIISourceType.OCR.value,
        normalized,
        attr_type.value,
        block_id=block.block_id,
        span_start=span_start,
        span_end=span_end,
    )
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        canonical_source_text=canonical_source_text,
        normalized_text=normalized,
        attr_type=attr_type,
        source=PIISourceType.OCR,
        bbox=block.bbox,
        block_id=block.block_id,
        span_start=span_start,
        span_end=span_end,
        confidence=confidence,
        metadata=metadata or {},
    )


def _join_inline_and_ocr_value_text(self, inline_value: str, continuation_text: str) -> str:
    left = self._clean_extracted_value(inline_value)
    right = self._clean_extracted_value(continuation_text)
    if not left:
        return right
    if not right:
        return left
    if left[-1:].isascii() and left[-1:].isalnum() and right[:1].isascii() and right[:1].isalnum():
        return f"{left} {right}"
    return f"{left}{right}"


def _join_ocr_block_text(self, document: _OCRPageDocument, block_indices: tuple[int, ...]) -> str:
    if not block_indices:
        return ""
    parts: list[str] = []
    previous_block: OCRTextBlock | None = None
    for block_index in block_indices:
        block = document.blocks[block_index]
        if previous_block is not None:
            separator = self._block_join_separator(previous_block, block)
            if separator == _OCR_SEMANTIC_BREAK_TOKEN:
                separator = "\n"
            parts.append(separator)
        parts.append(block.text)
        previous_block = block
    return "".join(parts)


def _build_ocr_block_candidate(
    self,
    document: _OCRPageDocument,
    *,
    block_indices: tuple[int, ...],
    text: str,
    attr_type: PIIAttributeType,
    confidence: float,
    canonical_source_text: str | None,
    metadata: dict[str, list[str]] | None = None,
) -> PIICandidate | None:
    if not block_indices:
        return None
    cleaned_text = self._clean_phone_candidate(text) if attr_type == PIIAttributeType.PHONE else self._clean_extracted_value(text)
    if not cleaned_text:
        return None
    normalized = canonicalize_pii_value(attr_type, cleaned_text)
    blocks = [document.blocks[index] for index in block_indices]
    if len(blocks) == 1:
        block = blocks[0]
        if block.block_id is None:
            return None
        entity_id = self.resolver.build_candidate_id(
            self.detector_mode,
            PIISourceType.OCR.value,
            normalized,
            attr_type.value,
            block_id=block.block_id,
            span_start=0,
            span_end=len(block.text),
        )
        return PIICandidate(
            entity_id=entity_id,
            text=cleaned_text,
            canonical_source_text=canonical_source_text,
            normalized_text=normalized,
            attr_type=attr_type,
            source=PIISourceType.OCR,
            bbox=block.bbox,
            block_id=block.block_id,
            span_start=0,
            span_end=len(block.text),
            confidence=confidence,
            metadata=metadata or {},
        )
    combined_bbox = self._combine_bboxes(block.bbox for block in blocks if block.bbox is not None)
    merge_block_id = "ocr-merge-" + "-".join(
        block.block_id or f"{document.line_index}-{block_index}"
        for block_index, block in zip(block_indices, blocks, strict=False)
    )
    entity_id = self.resolver.build_candidate_id(
        self.detector_mode,
        PIISourceType.OCR.value,
        normalized,
        attr_type.value,
        block_id=merge_block_id,
        span_start=None,
        span_end=None,
    )
    return PIICandidate(
        entity_id=entity_id,
        text=cleaned_text,
        canonical_source_text=canonical_source_text,
        normalized_text=normalized,
        attr_type=attr_type,
        source=PIISourceType.OCR,
        bbox=combined_bbox,
        block_id=merge_block_id,
        span_start=None,
        span_end=None,
        confidence=confidence,
        metadata=metadata or {},
    )

def _refine_ocr_name_candidate(
    self,
    candidate: PIICandidate,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    if candidate.attr_type != PIIAttributeType.NAME or candidate.source != PIISourceType.OCR:
        return candidate
    block_indices = self._ocr_candidate_block_indices(candidate, document)
    if len(block_indices) != 1:
        return candidate
    block_index = block_indices[0]
    block = document.blocks[block_index]
    candidate_compact = self._compact_name_value(
        candidate.canonical_source_text or candidate.text,
        allow_ocr_noise=True,
    )
    if not candidate_compact:
        return None
    if self._is_ui_operation_name_token(candidate_compact):
        return None
    block_compact = self._compact_name_value(block.text, allow_ocr_noise=True)
    exact_block_match = bool(block_compact) and block_compact == candidate_compact
    if not exact_block_match:
        if self._looks_like_ui_time_metadata(block.text):
            return None
        if self._looks_like_bracketed_ui_label(block.text):
            return None
        return candidate
    scene_confidence, scene_tags = self._ocr_name_scene_confidence(
        document,
        scene_index,
        block_index=block_index,
        rule_profile=rule_profile,
    )
    if scene_confidence <= 0.0:
        return None
    refined = candidate.model_copy(deep=True)
    refined.confidence = max(refined.confidence, scene_confidence)
    refined.metadata = self._merge_candidate_metadata(
        refined.metadata,
        {
            "matched_by": ["ocr_scene_name_block"],
            "ocr_scene_signals": scene_tags,
        },
    )
    return refined

def _ocr_name_scene_confidence(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    block_index: int,
    rule_profile: _RuleStrengthProfile,
) -> tuple[float, list[str]]:
    block = document.blocks[block_index]
    score = 0.0
    scene_tags: list[str] = ["ocr_scene_exact_block"]
    if block.score >= 0.96:
        score += 0.24
        scene_tags.append("high_ocr_score")
    elif block.score >= 0.88:
        score += 0.14
        scene_tags.append("good_ocr_score")
    elif block.score < 0.7:
        score -= 0.24
        scene_tags.append("low_ocr_score")
    if self._same_line_has_right_time_metadata(document, scene_index, block_index):
        score += 0.4
        scene_tags.append("right_time_metadata")
    if self._next_line_has_preview_text(document, scene_index, block_index):
        score += 0.28
        scene_tags.append("next_line_preview")
    if self._looks_like_ui_time_metadata(block.text):
        score -= 0.6
        scene_tags.append("time_like_block")
    if self._looks_like_bracketed_ui_label(block.text):
        score -= 0.6
        scene_tags.append("ui_label_block")
    if score < 0.18:
        return 0.0, scene_tags
    return min(0.9, 0.7 + score * 0.18), scene_tags

def _same_line_has_right_time_metadata(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    block_index: int,
) -> bool:
    position = scene_index.position_by_block_index.get(block_index)
    if position is None:
        return False
    line_index, item_index = position
    if line_index >= len(scene_index.lines):
        return False
    for next_block_index in scene_index.lines[line_index][item_index + 1 :]:
        if self._looks_like_ui_time_metadata(document.blocks[next_block_index].text):
            return True
    return False

def _next_line_has_preview_text(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    block_index: int,
) -> bool:
    position = scene_index.position_by_block_index.get(block_index)
    block = document.blocks[block_index]
    if position is None or block.bbox is None:
        return False
    line_index, _ = position
    if line_index + 1 >= len(scene_index.lines):
        return False
    left_tolerance = self._clamped_ocr_tolerance(
        float(block.bbox.height),
        ratio=0.65,
        min_px=8.0,
        max_px=24.0,
    )
    for next_block_index in scene_index.lines[line_index + 1]:
        next_block = document.blocks[next_block_index]
        if next_block.bbox is None:
            continue
        if abs(next_block.bbox.x - block.bbox.x) > left_tolerance:
            continue
        if self._looks_like_ocr_preview_text(next_block.text):
            return True
    return False

def _looks_like_ocr_preview_text(self, text: str) -> bool:
    compact = re.sub(r"\s+", "", self._clean_extracted_value(text))
    if len(compact) < 4:
        return False
    if self._looks_like_ui_time_metadata(compact):
        return False
    if self._looks_like_bracketed_ui_label(compact):
        return False
    if re.fullmatch(r"[\d+＋]+", compact):
        return False
    if any(self._is_cjk_char(char) for char in compact):
        return True
    alpha_count = sum(char.isalpha() for char in compact)
    return alpha_count >= 4

def _looks_like_ui_time_metadata(self, text: str) -> bool:
    compact = re.sub(r"\s+", "", self._clean_extracted_value(text))
    if not compact or len(compact) > 16:
        return False
    if self._looks_like_short_numeric_metadata(compact):
        return True
    if re.fullmatch(r"(?:20\d{2}/)?\d{1,2}/\d{1,2}", compact):
        return True
    if re.fullmatch(r"(?:昨天|今天|前天|明天)?(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\d{1,2}[:：]\d{2}", compact):
        return True
    if re.fullmatch(r"(?:昨天|今天|前天|明天|刚刚|星期[一二三四五六日天]|周[一二三四五六日天])", compact):
        return True
    if re.fullmatch(
        r"(?:昨天|今天|前天|明天|星期[一二三四五六日天]|周[一二三四五六日天])(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\d{0,2}(?::\d{2})?",
        compact,
    ):
        return True
    if re.fullmatch(r"(?:yesterday|today|tomorrow|justnow|now|mon|tue|wed|thu|fri|sat|sun|am|pm)", compact, re.IGNORECASE):
        return True
    if re.fullmatch(
        r"(?:yesterday|today|tomorrow|mon|tue|wed|thu|fri|sat|sun)?(?:am|pm)?\d{1,2}(?::\d{2})?",
        compact,
        re.IGNORECASE,
    ):
        return True
    return False

def _looks_like_bracketed_ui_label(self, text: str) -> bool:
    stripped = text.strip()
    if re.match(r"^[\[\(（【<《].{1,8}[\]\)）】>》]", stripped):
        return True
    cleaned = self._clean_extracted_value(stripped)
    compact = re.sub(r"\s+", "", cleaned)
    lowered = re.sub(r"\s+", " ", cleaned).strip().lower()
    if compact in _UI_NEGATIVE_TERMS_ZH or cleaned in _UI_NEGATIVE_PHRASES_ZH:
        return True
    if lowered in _UI_NEGATIVE_PHRASES_EN:
        return True
    return any(lowered.startswith(token) for token in _UI_NEGATIVE_TERMS_EN)

def _remap_ocr_page_candidate(
    self,
    candidate: PIICandidate,
    document: _OCRPageDocument,
) -> PIICandidate | None:
    """将页面扫描候选映射回单 block 或多 block 联合候选。"""
    if candidate.span_start is None or candidate.span_end is None:
        return None
    covered: dict[int, list[int]] = {}
    covered_block_ids: list[str] = []
    for ref in document.char_refs[candidate.span_start:candidate.span_end]:
        if ref is None:
            continue
        block_index, char_index = ref
        covered.setdefault(block_index, []).append(char_index)
        block_id = document.blocks[block_index].block_id
        if block_id and block_id not in covered_block_ids:
            covered_block_ids.append(block_id)
    if not covered:
        return None
    extra_metadata = {"ocr_block_ids": covered_block_ids}
    if len(document.blocks) > 1:
        extra_metadata["matched_by"] = ["ocr_page_span"]
    remapped_metadata = self._merge_candidate_metadata(candidate.metadata, extra_metadata)
    if len(covered) == 1:
        block_index, positions = next(iter(covered.items()))
        block = document.blocks[block_index]
        local_start = min(positions)
        local_end = max(positions) + 1
        local_text = block.text[local_start:local_end]
        normalized = canonicalize_pii_value(candidate.attr_type, local_text)
        entity_id = self.resolver.build_candidate_id(
            self.detector_mode,
            PIISourceType.OCR.value,
            normalized,
            candidate.attr_type.value,
            block_id=block.block_id,
            span_start=local_start,
            span_end=local_end,
        )
        return PIICandidate(
            entity_id=entity_id,
            text=local_text,
            normalized_text=normalized,
            attr_type=candidate.attr_type,
            source=PIISourceType.OCR,
            bbox=block.bbox,
            block_id=block.block_id,
            span_start=local_start,
            span_end=local_end,
            confidence=candidate.confidence,
            metadata=remapped_metadata,
        )
    covered_indices = set(covered)
    combined_bbox = self._combine_bboxes(
        block.bbox
        for index, block in enumerate(document.blocks)
        if index in covered_indices and block.bbox is not None
    )
    merge_block_id = "ocr-merge-" + "-".join(
        item.block_id or f"{document.line_index}-{index}"
        for index, item in enumerate(document.blocks)
        if index in covered
    )
    entity_id = self.resolver.build_candidate_id(
        self.detector_mode,
        PIISourceType.OCR.value,
        candidate.normalized_text,
        candidate.attr_type.value,
        block_id=merge_block_id,
        span_start=None,
        span_end=None,
    )
    return PIICandidate(
        entity_id=entity_id,
        text=candidate.text,
        normalized_text=candidate.normalized_text,
        attr_type=candidate.attr_type,
        source=PIISourceType.OCR,
        bbox=combined_bbox,
        block_id=merge_block_id,
        span_start=None,
        span_end=None,
        confidence=candidate.confidence,
        metadata=remapped_metadata,
    )

def _combine_bboxes(self, boxes) -> BoundingBox | None:
    """将多个 bbox 合并成一个外接矩形。"""
    valid_boxes = [box for box in boxes if box is not None]
    if not valid_boxes:
        return None
    min_x = min(box.x for box in valid_boxes)
    min_y = min(box.y for box in valid_boxes)
    max_x = max(box.x + box.width for box in valid_boxes)
    max_y = max(box.y + box.height for box in valid_boxes)
    return BoundingBox(
        x=max(0, int(min_x)),
        y=max(0, int(min_y)),
        width=max(1, int(max_x - min_x)),
        height=max(1, int(max_y - min_y)),
    )

def _bbox_center_y(self, bbox) -> float:
    return bbox.y + bbox.height / 2

def _clamped_ocr_tolerance(
    self,
    reference: float,
    *,
    ratio: float,
    min_px: float,
    max_px: float,
) -> float:
    """OCR 几何容差：小字号按比例，大字号按像素封顶。"""
    if reference <= 0:
        return min_px
    return min(max_px, max(min_px, reference * ratio))

def _derive_address_block_candidates(
    self,
    candidate: PIICandidate,
    document: _OCRPageDocument,
) -> list[PIICandidate]:
    """对多 block 地址命中补充派生单 block 地址碎片，避免丢失原始块级信息。"""
    if candidate.attr_type != PIIAttributeType.ADDRESS:
        return []
    if candidate.span_start is None or candidate.span_end is None:
        return []
    if len(document.blocks) <= 1:
        return []
    covered_positions: dict[int, list[int]] = {}
    for ref in document.char_refs[candidate.span_start:candidate.span_end]:
        if ref is None:
            continue
        block_index, char_index = ref
        covered_positions.setdefault(block_index, []).append(char_index)
    if len(covered_positions) <= 1:
        return []
    fragments: list[PIICandidate] = []
    for block_index, positions in covered_positions.items():
        block = document.blocks[block_index]
        if not positions:
            continue
        local_start = min(positions)
        local_end = max(positions) + 1
        local_text = block.text[local_start:local_end]
        if not self._looks_like_address_candidate(local_text):
            continue
        normalized = canonicalize_pii_value(PIIAttributeType.ADDRESS, local_text)
        entity_id = self.resolver.build_candidate_id(
            self.detector_mode,
            PIISourceType.OCR.value,
            normalized,
            PIIAttributeType.ADDRESS.value,
            block_id=block.block_id,
            span_start=local_start,
            span_end=local_end,
        )
        fragments.append(
            PIICandidate(
                entity_id=entity_id,
                text=local_text,
                normalized_text=normalized,
                attr_type=PIIAttributeType.ADDRESS,
                source=PIISourceType.OCR,
                bbox=block.bbox,
                block_id=block.block_id,
                span_start=local_start,
                span_end=local_end,
                confidence=max(0.4, candidate.confidence - 0.08),
                metadata=self._merge_candidate_metadata(
                    candidate.metadata,
                    {
                        "matched_by": ["ocr_page_fragment"],
                        "ocr_block_ids": [block.block_id] if block.block_id else [],
                    },
                ),
            )
        )
    return fragments
