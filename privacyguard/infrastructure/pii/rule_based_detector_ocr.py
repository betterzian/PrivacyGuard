"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *


@dataclass(frozen=True, slots=True)
class _OCRLabelSpec:
    attr_type: PIIAttributeType
    matched_by: str
    keywords: tuple[str, ...]
    name_component: str | None = None
    base_confidence: float = 0.96


_OCR_LABEL_DECORATION_PATTERN = re.compile(r"[\s:：=*_?？!！,，.。;；/\\|｜()\[\]{}<>《》【】\"'`·•_\-]+")
_OCR_LABEL_FULL_NAME_KEYWORDS = (
    "name",
    "full name",
    "username",
    "realname",
    "real name",
    "真实姓名",
    "姓名",
    "住客姓名",
    "昵称",
    "称呼",
    "联系人",
    "联系人姓名",
    "收件人",
    "收货人",
    "寄件人",
    "收件姓名",
    "申请人",
    "委托人",
    "监护人",
    "法定代表人",
    "户主",
    "住户",
    "本人",
    "客户",
    "用户",
    "病人姓名",
    "患者姓名",
)
_OCR_LABEL_GIVEN_NAME_KEYWORDS = (
    "first name",
    "given name",
    "名",
)
_OCR_LABEL_SPECS = (
    _OCRLabelSpec(
        attr_type=PIIAttributeType.NAME,
        matched_by="ocr_label_name_family_field",
        keywords=_NAME_FAMILY_FIELD_KEYWORDS,
        name_component="family",
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.NAME,
        matched_by="ocr_label_name_given_field",
        keywords=_OCR_LABEL_GIVEN_NAME_KEYWORDS,
        name_component="given",
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.NAME,
        matched_by="ocr_label_name_middle_field",
        keywords=_NAME_MIDDLE_FIELD_KEYWORDS,
        name_component="middle",
        base_confidence=0.97,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.NAME,
        matched_by="ocr_label_name_field",
        keywords=_OCR_LABEL_FULL_NAME_KEYWORDS,
        name_component="full",
        base_confidence=0.97,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.PHONE,
        matched_by="ocr_label_phone_field",
        keywords=_PHONE_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.EMAIL,
        matched_by="ocr_label_email_field",
        keywords=_EMAIL_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.ADDRESS,
        matched_by="ocr_label_address_field",
        keywords=_ADDRESS_FIELD_KEYWORDS,
        base_confidence=0.86,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.ID_NUMBER,
        matched_by="ocr_label_id_field",
        keywords=_ID_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.CARD_NUMBER,
        matched_by="ocr_label_card_field",
        keywords=_CARD_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.BANK_ACCOUNT,
        matched_by="ocr_label_bank_account_field",
        keywords=_BANK_ACCOUNT_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.PASSPORT_NUMBER,
        matched_by="ocr_label_passport_field",
        keywords=_PASSPORT_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.DRIVER_LICENSE,
        matched_by="ocr_label_driver_license_field",
        keywords=_DRIVER_LICENSE_FIELD_KEYWORDS,
        base_confidence=0.98,
    ),
    _OCRLabelSpec(
        attr_type=PIIAttributeType.ORGANIZATION,
        matched_by="ocr_label_organization_field",
        keywords=_ORGANIZATION_FIELD_KEYWORDS,
        base_confidence=0.88,
    ),
)


def _normalize_ocr_label_token(value: str) -> str:
    return _OCR_LABEL_DECORATION_PATTERN.sub("", str(value or "").strip().lower())


_OCR_LABEL_SPEC_LOOKUP: dict[str, tuple[_OCRLabelSpec, ...]] = {}
for _spec in _OCR_LABEL_SPECS:
    for _keyword in _spec.keywords:
        _normalized_keyword = _normalize_ocr_label_token(_keyword)
        if not _normalized_keyword:
            continue
        _OCR_LABEL_SPEC_LOOKUP.setdefault(_normalized_keyword, tuple())
        if _spec not in _OCR_LABEL_SPEC_LOOKUP[_normalized_keyword]:
            _OCR_LABEL_SPEC_LOOKUP[_normalized_keyword] = _OCR_LABEL_SPEC_LOOKUP[_normalized_keyword] + (_spec,)


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


def _ocr_label_specs_for_block(self, block: OCRTextBlock) -> tuple[_OCRLabelSpec, ...]:
    normalized = _normalize_ocr_label_token(block.text)
    if not normalized:
        return ()
    return _OCR_LABEL_SPEC_LOOKUP.get(normalized, ())


def _is_ocr_pure_label_block(self, block: OCRTextBlock) -> bool:
    return bool(self._ocr_label_specs_for_block(block))


def _build_ocr_label_adjacency_candidate(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    *,
    label_block_index: int,
    spec: _OCRLabelSpec,
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


def _collect_ocr_right_value_chain(
    self,
    document: _OCRPageDocument,
    scene_index: _OCRSceneIndex,
    label_block_index: int,
    spec: _OCRLabelSpec,
) -> tuple[tuple[int, ...], float] | None:
    position = scene_index.position_by_block_index.get(label_block_index)
    label_block = document.blocks[label_block_index]
    if position is None or label_block.bbox is None:
        return None
    line_index, item_index = position
    line = scene_index.lines[line_index]
    best_anchor: tuple[int, float] | None = None
    for next_block_index in line[item_index + 1 :]:
        block = document.blocks[next_block_index]
        if self._is_ocr_pure_label_block(block):
            break
        score = self._score_ocr_label_right_neighbor(label_block, block, spec)
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
    spec: _OCRLabelSpec,
) -> tuple[tuple[int, ...], float] | None:
    position = scene_index.position_by_block_index.get(label_block_index)
    label_block = document.blocks[label_block_index]
    if position is None or label_block.bbox is None:
        return None
    line_index, _ = position
    best_anchor: tuple[int, float] | None = None
    for next_line_index in range(line_index + 1, min(len(scene_index.lines), line_index + 5)):
        line = scene_index.lines[next_line_index]
        line_blocks = [document.blocks[index] for index in line]
        if not line_blocks:
            continue
        if self._is_ocr_pure_label_block(line_blocks[0]):
            break
        for candidate_index in line:
            block = document.blocks[candidate_index]
            if self._is_ocr_pure_label_block(block):
                continue
            score = self._score_ocr_label_down_neighbor(label_block, block, spec)
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
    spec: _OCRLabelSpec,
) -> tuple[tuple[int, ...], float | None]:
    position = scene_index.position_by_block_index.get(anchor_block_index)
    if position is None:
        return (), None
    line_index, item_index = position
    line = scene_index.lines[line_index]
    collected: list[int] = []
    scores: list[float] = []
    previous_block = document.blocks[anchor_block_index]
    for next_block_index in line[item_index + 1 :]:
        block = document.blocks[next_block_index]
        if self._is_ocr_pure_label_block(block):
            break
        if self._score_ocr_label_value_block(block, spec) is None:
            break
        successor_score = self._score_horizontal_successor(previous_block, block)
        if successor_score is None or successor_score < 0.42:
            break
        collected.append(next_block_index)
        scores.append(successor_score)
        previous_block = block
    if not scores:
        return tuple(collected), None
    return tuple(collected), sum(scores) / len(scores)


def _score_ocr_label_value_block(self, block: OCRTextBlock, spec: _OCRLabelSpec) -> float | None:
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
    label_block: OCRTextBlock,
    value_block: OCRTextBlock,
    spec: _OCRLabelSpec,
) -> float | None:
    if label_block.bbox is None or value_block.bbox is None:
        return None
    if value_block.bbox.x + value_block.bbox.width <= label_block.bbox.x:
        return None
    value_score = self._score_ocr_label_value_block(value_block, spec)
    if value_score is None:
        return None
    avg_height = (label_block.bbox.height + value_block.bbox.height) / 2
    gap = max(0.0, float(value_block.bbox.x - (label_block.bbox.x + label_block.bbox.width)))
    center_delta = abs(self._bbox_center_y(label_block.bbox) - self._bbox_center_y(value_block.bbox))
    gap_threshold = self._clamped_ocr_tolerance(avg_height, ratio=2.4, min_px=12.0, max_px=72.0)
    center_threshold = self._clamped_ocr_tolerance(avg_height, ratio=0.85, min_px=8.0, max_px=28.0)
    if gap > gap_threshold * 1.8 or center_delta > center_threshold * 1.45:
        return None
    min_height = float(min(label_block.bbox.height, value_block.bbox.height))
    max_height = float(max(label_block.bbox.height, value_block.bbox.height))
    height_ratio = max_height / max(1.0, min_height)
    score = 1.0
    score -= 0.42 * min(1.0, gap / max(1.0, gap_threshold))
    score -= 0.24 * min(1.0, center_delta / max(1.0, center_threshold))
    score -= 0.12 * min(1.0, max(0.0, height_ratio - 1.0) / 1.0)
    score += 0.14 * max(0.0, value_score - 0.5)
    score += 0.04 if value_block.score >= 0.94 else 0.0
    return score if score >= 0.42 else None


def _score_ocr_label_down_neighbor(
    self,
    label_block: OCRTextBlock,
    value_block: OCRTextBlock,
    spec: _OCRLabelSpec,
) -> float | None:
    if label_block.bbox is None or value_block.bbox is None:
        return None
    if self._bbox_center_y(value_block.bbox) <= self._bbox_center_y(label_block.bbox):
        return None
    value_score = self._score_ocr_label_value_block(value_block, spec)
    if value_score is None:
        return None
    avg_height = (label_block.bbox.height + value_block.bbox.height) / 2
    vertical_gap = max(0.0, float(value_block.bbox.y - (label_block.bbox.y + label_block.bbox.height)))
    vertical_threshold = self._clamped_ocr_tolerance(avg_height, ratio=2.8, min_px=10.0, max_px=84.0)
    if vertical_gap > vertical_threshold * 1.8:
        return None
    left_delta = abs(label_block.bbox.x - value_block.bbox.x)
    center_x_delta = abs(
        (label_block.bbox.x + label_block.bbox.width / 2) - (value_block.bbox.x + value_block.bbox.width / 2)
    )
    align_threshold = self._clamped_ocr_tolerance(avg_height, ratio=1.2, min_px=12.0, max_px=48.0)
    horizontal_overlap = max(
        0,
        min(label_block.bbox.x + label_block.bbox.width, value_block.bbox.x + value_block.bbox.width)
        - max(label_block.bbox.x, value_block.bbox.x),
    )
    min_width = float(min(label_block.bbox.width, value_block.bbox.width))
    overlap_ratio = horizontal_overlap / max(1.0, min_width)
    if left_delta > align_threshold and center_x_delta > align_threshold and overlap_ratio < 0.18:
        return None
    score = 1.0
    score -= 0.34 * min(1.0, vertical_gap / max(1.0, vertical_threshold))
    score -= 0.2 * min(1.0, min(left_delta, center_x_delta) / max(1.0, align_threshold))
    score += 0.1 * min(1.0, overlap_ratio)
    score += 0.14 * max(0.0, value_score - 0.5)
    score += 0.04 if value_block.score >= 0.94 else 0.0
    return score if score >= 0.42 else None


def _validate_ocr_label_value_chain(
    self,
    document: _OCRPageDocument,
    *,
    block_indices: tuple[int, ...],
    relation_score: float,
    spec: _OCRLabelSpec,
    rule_profile: _RuleStrengthProfile,
) -> PIICandidate | None:
    raw_text = self._join_ocr_block_text(document, block_indices)
    cleaned_text = self._clean_phone_candidate(raw_text) if spec.attr_type == PIIAttributeType.PHONE else self._clean_extracted_value(raw_text)
    if not cleaned_text:
        return None
    allow_ocr_noise = rule_profile.level == ProtectionLevel.STRONG
    canonical_source_text: str | None = None
    confidence = spec.base_confidence
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
    return self._build_ocr_block_candidate(
        document,
        block_indices=block_indices,
        text=raw_text,
        attr_type=spec.attr_type,
        confidence=confidence,
        canonical_source_text=canonical_source_text,
        metadata=self._merge_candidate_metadata(
            {
                "matched_by": [spec.matched_by],
                "ocr_block_ids": [
                    document.blocks[index].block_id
                    for index in block_indices
                    if document.blocks[index].block_id
                ],
            },
            self._name_component_metadata(spec.name_component) if spec.name_component else None,
        ),
    )


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
