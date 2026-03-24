"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _build_ocr_page_document(self, ocr_blocks: list[OCRTextBlock]) -> _OCRPageDocument | None:
    """把整页 OCR block 聚合成单个扫描文档，减少重复扫描成本。"""
    if not ocr_blocks:
        return None
    merged_chars: list[str] = []
    char_refs: list[tuple[int, int] | None] = []
    ordered_blocks: list[OCRTextBlock] = []
    lines = self._group_blocks_by_page_line(ocr_blocks)
    assigned_blocks = {id(block) for line in lines for block in line if block.text.strip()}
    chains = self._collect_ocr_block_chains(lines)
    line_count = 0
    for chain in chains:
        if not chain:
            continue
        if line_count > 0:
            self._append_ocr_page_separator(merged_chars, char_refs, _OCR_SEMANTIC_BREAK_TOKEN)
        for block, separator in chain:
            if separator:
                self._append_ocr_page_separator(merged_chars, char_refs, separator)
            block_index = len(ordered_blocks)
            ordered_blocks.append(block)
            for char_index, char in enumerate(block.text):
                merged_chars.append(char)
                char_refs.append((block_index, char_index))
        line_count += 1
    for block in ocr_blocks:
        if id(block) in assigned_blocks or not block.text.strip():
            continue
        if line_count > 0:
            self._append_ocr_page_separator(merged_chars, char_refs, "\n")
        block_index = len(ordered_blocks)
        ordered_blocks.append(block)
        for char_index, char in enumerate(block.text):
            merged_chars.append(char)
            char_refs.append((block_index, char_index))
        line_count += 1
    if not ordered_blocks:
        return None
    return _OCRPageDocument(
        line_index=0,
        blocks=tuple(ordered_blocks),
        text="".join(merged_chars),
        char_refs=tuple(char_refs),
    )

def _build_ocr_scene_index(self, blocks: tuple[OCRTextBlock, ...]) -> _OCRSceneIndex:
    lines = self._group_blocks_by_page_line(list(blocks))
    block_index_by_identity = {id(block): index for index, block in enumerate(blocks)}
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
    for block_index in range(len(blocks)):
        if block_index in assigned:
            continue
        position_by_block_index[block_index] = (len(indexed_lines), 0)
        indexed_lines.append((block_index,))
    return _OCRSceneIndex(lines=tuple(indexed_lines), position_by_block_index=position_by_block_index)

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

def _collect_ocr_block_chains(self, lines: list[list[OCRTextBlock]]) -> list[list[tuple[OCRTextBlock, str]]]:
    """按 block 级别选择右邻或下邻后继，构建 OCR 阅读链。"""
    indexed_lines = [
        [
            ((line_index, block_index), block)
            for block_index, block in enumerate(line)
            if block.text.strip()
        ]
        for line_index, line in enumerate(lines)
    ]
    indexed_lines = [line for line in indexed_lines if line]
    if not indexed_lines:
        return []
    page_order = [key for line in indexed_lines for key, _ in line]
    block_by_key = {key: block for line in indexed_lines for key, block in line}
    position_by_key = {key: index for index, key in enumerate(page_order)}
    proposals = self._collect_ocr_successor_proposals(indexed_lines)
    accepted: dict[tuple[int, int], tuple[tuple[int, int], str]] = {}
    used_sources: set[tuple[int, int]] = set()
    used_targets: set[tuple[int, int]] = set()
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
    visited: set[tuple[int, int]] = set()
    chains: list[list[tuple[OCRTextBlock, str]]] = []
    for start_key in start_keys:
        if start_key in visited:
            continue
        chain: list[tuple[OCRTextBlock, str]] = []
        current_key = start_key
        separator = ""
        while current_key not in visited:
            visited.add(current_key)
            chain.append((block_by_key[current_key], separator))
            next_item = accepted.get(current_key)
            if next_item is None:
                break
            current_key, separator = next_item
        if chain:
            chains.append(chain)
    for key in page_order:
        if key in visited:
            continue
        chains.append([(block_by_key[key], "")])
        visited.add(key)
    return chains

def _collect_ocr_successor_proposals(
    self,
    indexed_lines: list[list[tuple[tuple[int, int], OCRTextBlock]]],
) -> list[tuple[tuple[int, int], tuple[int, int], str, float]]:
    """为每个 block 提议右邻/下邻后继，再交给贪心匹配挑选。"""
    proposals: list[tuple[tuple[int, int], tuple[int, int], str, float]] = []
    for line_index, line in enumerate(indexed_lines):
        for block_index, (source_key, source_block) in enumerate(line):
            right_candidate = self._horizontal_successor_proposal(line, block_index)
            if right_candidate is not None:
                proposals.append((source_key, right_candidate[0], right_candidate[1], right_candidate[2]))
            down_candidate = self._downward_successor_proposal(indexed_lines, line_index, block_index)
            if down_candidate is not None:
                proposals.append((source_key, down_candidate[0], down_candidate[1], down_candidate[2]))
    return proposals

def _horizontal_successor_proposal(
    self,
    line: list[tuple[tuple[int, int], OCRTextBlock]],
    block_index: int,
) -> tuple[tuple[int, int], str, float] | None:
    """提议同一行内的右侧后继。"""
    if block_index + 1 >= len(line):
        return None
    _, source_block = line[block_index]
    target_key, target_block = line[block_index + 1]
    score = self._score_horizontal_successor(source_block, target_block)
    if score is None:
        return None
    return target_key, self._block_join_separator(source_block, target_block), score

def _downward_successor_proposal(
    self,
    indexed_lines: list[list[tuple[tuple[int, int], OCRTextBlock]]],
    line_index: int,
    block_index: int,
) -> tuple[tuple[int, int], str, float] | None:
    """提议更像是纵向续写的下方后继。"""
    source_key, source_block = indexed_lines[line_index][block_index]
    source_prefix = [block for _, block in indexed_lines[line_index][: block_index + 1]]
    best_target: tuple[tuple[int, int], str, float] | None = None
    for next_line in indexed_lines[line_index + 1 :]:
        next_blocks = [block for _, block in next_line]
        line_score = self._score_vertical_line_successor(source_prefix, next_blocks)
        if line_score is None:
            continue
        for target_key, target_block in next_line:
            block_score = self._score_vertical_block_successor(source_block, target_block)
            if block_score is None:
                continue
            score = line_score * 0.45 + block_score * 0.55
            if best_target is None or score > best_target[2]:
                best_target = (target_key, "\n", score)
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

def _block_join_separator(self, left: OCRTextBlock, right: OCRTextBlock) -> str:
    """决定两个相邻 OCR block 在拼接时是否需要补空格。"""
    if not self._blocks_semantically_related(left, right):
        return _OCR_SEMANTIC_BREAK_TOKEN
    if left.bbox is None or right.bbox is None:
        return ""
    left_char = left.text[-1:] if left.text else ""
    right_char = right.text[:1] if right.text else ""
    if not left_char or not right_char:
        return ""
    gap = right.bbox.x - (left.bbox.x + left.bbox.width)
    threshold = int(
        self._clamped_ocr_tolerance(
            float(min(left.bbox.height, right.bbox.height)),
            ratio=0.4,
            min_px=6.0,
            max_px=12.0,
        )
    )
    if gap <= threshold:
        return ""
    if left_char.isascii() and left_char.isalnum() and right_char.isascii() and right_char.isalnum():
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
    gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    center_delta_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.3, min_px=4.0, max_px=10.0)
    left_edge_threshold = self._clamped_ocr_tolerance(min_height, ratio=0.35, min_px=6.0, max_px=12.0)
    vertical_delta_threshold = self._clamped_ocr_tolerance(max_height, ratio=0.2, min_px=4.0, max_px=8.0)
    overlap_center_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.22, min_px=4.0, max_px=8.0)
    left_edge_aligned = abs(left_box.x - right_box.x) <= left_edge_threshold
    horizontal_overlap = max(0, min(left_box.x + left_box.width, right_box.x + right_box.width) - max(left_box.x, right_box.x))
    horizontal_overlap_ratio = horizontal_overlap / max(1.0, float(min(left_box.width, right_box.width)))

    if gap > gap_threshold:
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
    gap = max(0.0, float(right.bbox.x - (left.bbox.x + left.bbox.width)))
    gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
    center_delta = abs(self._bbox_center_y(left.bbox) - self._bbox_center_y(right.bbox))
    center_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.3, min_px=4.0, max_px=10.0)
    min_height = float(min(left.bbox.height, right.bbox.height))
    max_height = float(max(left.bbox.height, right.bbox.height))
    height_ratio = max_height / max(1.0, min_height)
    score = 1.0
    score -= 0.55 * min(1.0, gap / max(1.0, gap_threshold))
    score -= 0.3 * min(1.0, center_delta / max(1.0, center_threshold))
    score -= 0.15 * min(1.0, max(0.0, height_ratio - 1.0) / 0.45)
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

def _refine_ocr_name_candidate(
    self,
    candidate: PIICandidate,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    if candidate.attr_type != PIIAttributeType.NAME or candidate.source != PIISourceType.OCR:
        return candidate
    if rule_profile.level == ProtectionLevel.WEAK:
        return candidate
    block_indices = self._ocr_candidate_block_indices(candidate, document)
    if len(block_indices) != 1:
        return candidate
    block_index = block_indices[0]
    block = document.blocks[block_index]
    candidate_compact = self._compact_name_value(
        candidate.canonical_source_text or candidate.text,
        allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
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
    if rule_profile.level == ProtectionLevel.BALANCED:
        if score < 0.48:
            return 0.0, scene_tags
        return min(0.86, 0.68 + score * 0.18), scene_tags
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
    return any(self._is_cjk_char(char) for char in compact)

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
    return False

def _looks_like_bracketed_ui_label(self, text: str) -> bool:
    stripped = text.strip()
    if re.match(r"^[\[\(（【<《].{1,8}[\]\)）】>》]", stripped):
        return True
    compact = re.sub(r"\s+", "", self._clean_extracted_value(stripped))
    return any(compact.startswith(token) for token in _UI_OPERATION_NAME_WHITELIST)

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
