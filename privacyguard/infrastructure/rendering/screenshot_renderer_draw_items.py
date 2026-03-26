"""ScreenshotRenderer internal helper functions."""

from privacyguard.infrastructure.rendering.screenshot_renderer_shared import *

def _build_draw_items(self, plan: DecisionPlan, ocr_blocks: list[OCRTextBlock]) -> list[_DrawItem]:
    """根据 plan 与 OCR 原始块构建最终绘制单元。"""
    block_map = {block.block_id: block for block in ocr_blocks if block.block_id}
    grouped_actions: dict[str, list[DecisionAction]] = {}
    ordered_block_ids: list[str] = []
    block_legacy_actions: dict[str, DecisionAction] = {}
    legacy_items: list[_DrawItem] = []
    cross_block_items: list[_DrawItem] = []
    reserved_block_ids: set[str] = set()

    for action in plan.actions:
        if action.action_type == ActionType.KEEP:
            continue
        if not action.replacement_text or action.bbox is None:
            continue
        cross_block_ids = self._resolve_cross_block_ids(action, block_map)
        if cross_block_ids:
            if any(block_id in reserved_block_ids for block_id in cross_block_ids):
                continue
            draw_items = self._build_cross_block_draw_items(action, cross_block_ids, block_map)
            if draw_items:
                cross_block_items.extend(draw_items)
                reserved_block_ids.update(cross_block_ids)
                continue
        if action.block_id and action.block_id in block_map:
            if action.span_start is not None and action.span_end is not None:
                if action.block_id not in grouped_actions:
                    grouped_actions[action.block_id] = []
                    ordered_block_ids.append(action.block_id)
                grouped_actions[action.block_id].append(action)
            else:
                block_legacy_actions.setdefault(action.block_id, action)
            continue
        legacy_items.append(_DrawItem(bbox=action.bbox, text=action.replacement_text))

    draw_items: list[_DrawItem] = list(cross_block_items)
    handled_block_ids = set(reserved_block_ids)
    for block_id in ordered_block_ids:
        if block_id in reserved_block_ids:
            continue
        block = block_map.get(block_id)
        if block is None:
            continue
        rebuilt_text = self._rebuild_block_text(block.text, grouped_actions.get(block_id, []))
        draw_items.append(
            _DrawItem(
                bbox=block.bbox,
                text=rebuilt_text,
                block_id=block_id,
                original_text=block.text,
                polygon=block.polygon,
                rotation_degrees=block.rotation_degrees,
            )
        )
        handled_block_ids.add(block_id)
    for block_id, action in block_legacy_actions.items():
        if block_id in handled_block_ids:
            continue
        block = block_map.get(block_id)
        if block is None:
            continue
        draw_items.append(
            _DrawItem(
                bbox=block.bbox,
                text=action.replacement_text or "",
                block_id=block_id,
                original_text=block.text,
                polygon=block.polygon,
                rotation_degrees=block.rotation_degrees,
            )
        )
    draw_items.extend(legacy_items)
    return draw_items

def _resolve_cross_block_ids(
    self,
    action: DecisionAction,
    block_map: dict[str, OCRTextBlock],
) -> list[str]:
    """读取 action metadata 中的跨 block 关联，并确保所有 block 都存在。"""
    block_ids = action.metadata.get("ocr_block_ids", [])
    resolved: list[str] = []
    for block_id in block_ids:
        if block_id in block_map and block_id not in resolved:
            resolved.append(block_id)
    if len(resolved) <= 1:
        return []
    if len(resolved) != len(block_ids):
        return []
    return resolved

def _build_cross_block_draw_items(
    self,
    action: DecisionAction,
    block_ids: list[str],
    block_map: dict[str, OCRTextBlock],
) -> list[_DrawItem]:
    """把跨 block action 展开成多个绘制单元。"""
    blocks = [block_map[block_id] for block_id in block_ids]
    split_texts = self._split_cross_block_replacement(action, blocks)
    if not split_texts:
        return []
    draw_items: list[_DrawItem] = []
    for block, text in zip(blocks, split_texts, strict=False):
        if block.bbox is None:
            continue
        draw_items.append(
            _DrawItem(
                bbox=block.bbox,
                text=text,
                block_id=block.block_id,
                original_text=block.text,
                polygon=block.polygon,
                rotation_degrees=block.rotation_degrees,
            )
        )
    return draw_items

def _split_cross_block_replacement(
    self,
    action: DecisionAction,
    blocks: list[OCRTextBlock],
) -> list[str]:
    """按动作类型将跨 block replacement 切分到各原始 OCR block。"""
    replacement_text = action.replacement_text or ""
    if not blocks:
        return []
    if len(blocks) == 1:
        return [replacement_text]
    if action.action_type == ActionType.GENERICIZE:
        return [replacement_text] + [""] * (len(blocks) - 1)
    if action.action_type == ActionType.PERSONA_SLOT:
        if action.attr_type == PIIAttributeType.ADDRESS:
            address_chunks = self._split_address_replacement_across_blocks(action, blocks)
            if address_chunks is not None:
                return address_chunks
        return self._split_text_proportionally(replacement_text, blocks)
    return [replacement_text] + [""] * (len(blocks) - 1)

def _split_address_replacement_across_blocks(
    self,
    action: DecisionAction,
    blocks: list[OCRTextBlock],
) -> list[str] | None:
    """地址 persona 替换优先按语义组件分配到各 block。"""
    source_units = self._address_units(action.source_text or "".join(block.text for block in blocks))
    replacement_units = self._address_units(action.replacement_text or "")
    if not source_units or not replacement_units:
        return None
    if len(source_units) != len(replacement_units):
        return self._group_units_by_block_capacity(replacement_units, blocks)
    aligned = self._assign_address_units_by_source_overlap(source_units, replacement_units, blocks)
    if aligned is not None:
        return aligned
    return self._group_units_by_block_capacity(replacement_units, blocks)

def _assign_address_units_by_source_overlap(
    self,
    source_units: list[str],
    replacement_units: list[str],
    blocks: list[OCRTextBlock],
) -> list[str] | None:
    """根据源地址组件在各 block 的覆盖关系，把 persona 地址组件映射回去。"""
    combined_block_text = "".join(block.text for block in blocks)
    combined_source_text = "".join(source_units)
    if combined_block_text != combined_source_text:
        return None
    block_ranges = self._segment_ranges([block.text for block in blocks])
    unit_ranges = self._segment_ranges(source_units)
    assigned = [""] * len(blocks)
    for index, unit_range in enumerate(unit_ranges):
        target_block = self._best_overlap_block(unit_range, block_ranges)
        if target_block is None:
            return None
        assigned[target_block] += replacement_units[index]
    if any(not chunk for chunk in assigned):
        return None
    return assigned

def _group_units_by_block_capacity(
    self,
    units: list[str],
    blocks: list[OCRTextBlock],
) -> list[str]:
    """在无法精确对齐源组件时，按 block 容量把语义组件整块分配。"""
    if not units:
        return [""] * len(blocks)
    if len(blocks) == 1:
        return ["".join(units)]
    if len(blocks) > len(units):
        return self._split_text_proportionally("".join(units), blocks)

    capacities = [self._block_capacity(block) for block in blocks]
    total_capacity = sum(capacities) or len(blocks)
    unit_lengths: list[int] = []
    running = 0
    for unit in units:
        running += len(unit)
        unit_lengths.append(running)

    grouped: list[str] = []
    start = 0
    consumed_capacity = 0
    total_text_len = unit_lengths[-1]
    for index, capacity in enumerate(capacities[:-1]):
        consumed_capacity += capacity
        remaining_blocks = len(capacities) - index - 1
        min_cut = start + 1
        max_cut = len(units) - remaining_blocks
        ideal_cumulative = round(total_text_len * consumed_capacity / total_capacity)
        best_cut = min_cut
        best_score: tuple[int, int] | None = None
        for cut in range(min_cut, max_cut + 1):
            cumulative = unit_lengths[cut - 1]
            score = (abs(cumulative - ideal_cumulative), cut)
            if best_score is None or score < best_score:
                best_cut = cut
                best_score = score
        grouped.append("".join(units[start:best_cut]))
        start = best_cut
    grouped.append("".join(units[start:]))
    return grouped

def _split_text_proportionally(
    self,
    text: str,
    blocks: list[OCRTextBlock],
) -> list[str]:
    """按 block 容量对 replacement 文本做保守切分。"""
    if len(blocks) <= 1:
        return [text]
    capacities = [self._block_capacity(block) for block in blocks]
    total_capacity = sum(capacities) or len(blocks)
    text_len = len(text)
    chunks: list[str] = []
    start = 0
    consumed_capacity = 0
    for index, capacity in enumerate(capacities):
        if index == len(capacities) - 1:
            end = text_len
        else:
            consumed_capacity += capacity
            ideal_end = round(text_len * consumed_capacity / total_capacity)
            remaining_blocks = len(capacities) - index - 1
            min_end = start
            if text_len - start > remaining_blocks:
                min_end = start + 1
            max_end = max(start, text_len - remaining_blocks)
            end = min(max(ideal_end, min_end), max_end)
        chunks.append(text[start:end])
        start = end
    return chunks

def _address_units(self, text: str) -> list[str]:
    """把地址文本拆成省/市/区/详情语义组件。"""
    components = parse_address_components(text)
    units = address_display_units(
        components,
        include_country=bool(components.country_text),
        granularity="detail",
    )
    if units:
        return units
    return [text] if text else []

def _segment_ranges(self, segments: list[str]) -> list[tuple[int, int]]:
    """把顺序文本段映射成拼接串中的闭开区间。"""
    ranges: list[tuple[int, int]] = []
    cursor = 0
    for segment in segments:
        end = cursor + len(segment)
        ranges.append((cursor, end))
        cursor = end
    return ranges

def _best_overlap_block(
    self,
    target_range: tuple[int, int],
    block_ranges: list[tuple[int, int]],
) -> int | None:
    """选择与目标区间重叠最大的 block；平票时偏向靠后的 block。"""
    best_index: int | None = None
    best_overlap = 0
    for index, block_range in enumerate(block_ranges):
        overlap = self._range_overlap(target_range, block_range)
        if overlap < best_overlap:
            continue
        if overlap > best_overlap or best_index is None or index > best_index:
            best_index = index
            best_overlap = overlap
    if best_overlap <= 0:
        return None
    return best_index

def _range_overlap(
    self,
    range_1: tuple[int, int],
    range_2: tuple[int, int],
) -> int:
    """计算两个闭开区间的重叠字符数。"""
    return max(0, min(range_1[1], range_2[1]) - max(range_1[0], range_2[0]))

def _block_capacity(self, block: OCRTextBlock) -> int:
    """估计单个 OCR block 可承载的字符容量。"""
    if block.bbox is not None:
        return max(1, block.bbox.width)
    return max(1, len(block.text))

def _rebuild_block_text(self, original_text: str, actions: list[DecisionAction]) -> str:
    """按 span 在 OCR 原文上做局部替换；span 不可靠时尝试回退到原文查找。"""
    selected = self._select_non_overlapping_actions(original_text, actions)
    if not selected:
        return self._fallback_rebuild_block_text(original_text, actions)
    rebuilt = original_text
    for resolved in sorted(selected, key=lambda item: item.start, reverse=True):
        rebuilt = rebuilt[:resolved.start] + (resolved.action.replacement_text or "") + rebuilt[resolved.end:]
    return rebuilt

def _select_non_overlapping_actions(
    self,
    original_text: str,
    actions: list[DecisionAction],
) -> list[_ResolvedAction]:
    """优先保留更长的非重叠替换，避免同框 span 相互踩踏。"""
    ranked = sorted(
        actions,
        key=lambda item: (
            0 if self._is_valid_span_action(original_text, item) else 1,
            -len(item.source_text or ""),
            item.span_start if item.span_start is not None else 10**9,
        ),
    )
    selected: list[_ResolvedAction] = []
    occupied: list[tuple[int, int]] = []
    for action in ranked:
        span = self._resolve_action_span(original_text, action, occupied)
        if span is None:
            continue
        selected.append(_ResolvedAction(action=action, start=span[0], end=span[1]))
        occupied.append(span)
    return selected

def _resolve_action_span(
    self,
    original_text: str,
    action: DecisionAction,
    occupied: list[tuple[int, int]],
) -> tuple[int, int] | None:
    """优先使用显式 span，失败时退回到原文中的 source_text 定位。"""
    for start, end in self._candidate_spans(original_text, action):
        if any(not (end <= used_start or start >= used_end) for used_start, used_end in occupied):
            continue
        return (start, end)
    return None

def _candidate_spans(self, original_text: str, action: DecisionAction) -> list[tuple[int, int]]:
    """枚举 action 在原文中的候选 span。"""
    spans: list[tuple[int, int]] = []
    if self._is_valid_span_action(original_text, action):
        spans.append((action.span_start, action.span_end))
    source_text = action.source_text or ""
    if not source_text:
        return spans
    literal_spans = self._find_literal_spans(original_text, source_text)
    if action.span_start is not None:
        literal_spans.sort(key=lambda item: (abs(item[0] - action.span_start), item[0]))
    for span in literal_spans:
        if span not in spans:
            spans.append(span)
    return spans

def _find_literal_spans(self, original_text: str, source_text: str) -> list[tuple[int, int]]:
    """查找 source_text 在原文中的全部字面位置。"""
    spans: list[tuple[int, int]] = []
    if not source_text:
        return spans
    start = 0
    while True:
        index = original_text.find(source_text, start)
        if index < 0:
            return spans
        spans.append((index, index + len(source_text)))
        start = index + 1

def _fallback_rebuild_block_text(self, original_text: str, actions: list[DecisionAction]) -> str:
    """显式 span 全部失效时，尽量基于 source_text 在原文中回退重建。"""
    rebuilt = original_text
    applied = False
    for action in sorted(actions, key=lambda item: len(item.source_text or ""), reverse=True):
        source_text = action.source_text or ""
        replacement_text = action.replacement_text or ""
        if not source_text or not replacement_text:
            continue
        index = rebuilt.find(source_text)
        if index < 0:
            continue
        rebuilt = rebuilt[:index] + replacement_text + rebuilt[index + len(source_text):]
        applied = True
    if applied:
        return rebuilt
    if actions and actions[0].replacement_text:
        return actions[0].replacement_text
    return original_text

def _is_valid_span_action(self, original_text: str, action: DecisionAction) -> bool:
    """校验 action 的 span 是否能安全应用到 OCR 原文。"""
    if action.span_start is None or action.span_end is None:
        return False
    start = action.span_start
    end = action.span_end
    if start < 0 or end <= start or end > len(original_text):
        return False
    if not action.replacement_text:
        return False
    source_text = action.source_text or ""
    return not source_text or original_text[start:end] == source_text
