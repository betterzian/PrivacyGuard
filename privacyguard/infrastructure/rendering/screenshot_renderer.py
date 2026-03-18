"""截图渲染器实现。填充逻辑由注入的 ScreenshotFillStrategy 提供（与 decision 一致：按模式注册、工厂构建）。"""

from dataclasses import dataclass
import logging
import math
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.interfaces.screenshot_fill_strategy import ScreenshotFillStrategy
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint
from privacyguard.infrastructure.rendering.fill_strategies import MixFillStrategy
from privacyguard.utils.pii_value import parse_address_components

# 常见系统字体路径
_DEFAULT_FONT_PATHS = [
    "C:/Windows/Fonts/msyh.ttc",   # Windows 微软雅黑
    "C:/Windows/Fonts/msyhbd.ttc",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/PingFang.ttc",
    "/System/Library/Fonts/Helvetica.ttc",
]
LOGGER = logging.getLogger(__name__)


def _get_font_path() -> Path | None:
    """获取可用的 TrueType 字体路径。"""
    for p in _DEFAULT_FONT_PATHS:
        path = Path(p)
        if path.exists():
            return path
    return None


@dataclass
class _DrawItem:
    """截图渲染阶段的实际绘制单元。"""

    bbox: BoundingBox
    text: str
    block_id: str | None = None
    original_text: str | None = None
    polygon: list[PolygonPoint] | None = None
    rotation_degrees: float = 0.0


@dataclass
class _ResolvedAction:
    """可安全应用到 OCR 原文的替换动作。"""

    action: DecisionAction
    start: int
    end: int


@dataclass
class _TextLayout:
    """文本布局结果。"""

    mask: Any
    rendered_text: str
    font_size: int
    char_spacing: float = 0.0
    scale_x: float = 1.0
    scale_y: float = 1.0


class ScreenshotRenderer:
    """截图上对 PII 区域填充并绘制替代文本；填充策略由注入的 ScreenshotFillStrategy 提供（与 decision 一致）。"""

    def __init__(
        self,
        fill_strategy: ScreenshotFillStrategy | None = None,
        background_color: str | None = None,
        text_color: str = "black",
    ) -> None:
        self._fill_strategy = fill_strategy or MixFillStrategy()
        self._fallback_bg = background_color or "white"
        self.text_color = text_color

    def render(
        self,
        image: Any,
        plan: DecisionPlan,
        ocr_blocks: list[OCRTextBlock] | None = None,
    ) -> Any:
        """将决策计划应用到截图并返回新图像。"""
        if image is None:
            return None
        pil_image = self._to_pil_image(image)
        if pil_image is None:
            LOGGER.warning("screenshot rendering skipped: Pillow unavailable or image input unsupported.")
            return image
        draw_items = self._build_draw_items(plan, ocr_blocks=ocr_blocks or [])
        pil_image, skip_fill_flags = self._fill_strategy.apply(pil_image, plan, draw_items)
        draw = self._create_draw(pil_image)
        for i, item in enumerate(draw_items):
            self._draw_text_box(
                draw=draw,
                item=item,
                image=pil_image,
                skip_fill=skip_fill_flags[i],
            )
        return pil_image

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
        units: list[str] = []
        if components.province_text:
            units.append(components.province_text)
        if components.city_text and components.city_text != components.province_text:
            units.append(components.city_text)
        if components.district_text:
            units.append(components.district_text)
        if components.detail_text:
            units.append(components.detail_text)
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

    def _to_pil_image(self, image: Any):
        """将输入统一转换为 PIL Image。"""
        try:
            from PIL import Image
        except Exception:
            return None
        if isinstance(image, Image.Image):
            return image.copy()
        if isinstance(image, (str, Path)):
            path = Path(image)
            if path.exists():
                try:
                    return Image.open(path).convert("RGB")
                except Exception:
                    return None
            return None
        try:
            import numpy as np
        except Exception:
            np = None
        if np is not None and isinstance(image, np.ndarray):
            return Image.fromarray(image).convert("RGB")
        return None

    def _create_draw(self, image):
        """创建绘图对象。"""
        from PIL import ImageDraw

        return ImageDraw.Draw(image)

    def _get_bbox_fill_color(self, image: Any, bbox: BoundingBox) -> tuple[int, int, int]:
        """box1=[x,y,w,h]，box2 为四边各外扩 2 像素；取 (box2 - box1) 环带内像素平均色填充。"""
        try:
            from PIL import Image
            w, h = image.size
            x, y, bw, bh = bbox.x, bbox.y, bbox.width, bbox.height
            x1, y1 = x, y
            x2, y2 = x + bw, y + bh
            x1e = max(0, x1 - 2)
            y1e = max(0, y1 - 2)
            x2e = min(w, x2 + 2)
            y2e = min(h, y2 + 2)
            pixels: list[tuple[int, int, int]] = []
            for py in range(y1e, y2e):
                for px in range(x1e, x2e):
                    if px < x1 or px >= x2 or py < y1 or py >= y2:
                        pixels.append(image.getpixel((px, py))[:3])
            if not pixels:
                crop = image.crop((max(0, x1), max(0, y1), min(w, x2), min(h, y2)))
                pixels = list(crop.getdata())
            if not pixels:
                return self._parse_fill(self._fallback_bg)
            r = sum(p[0] for p in pixels) // len(pixels)
            g = sum(p[1] for p in pixels) // len(pixels)
            b = sum(p[2] for p in pixels) // len(pixels)
            return (r, g, b)
        except Exception:
            return self._parse_fill(self._fallback_bg)

    def _parse_fill(self, color: str) -> tuple[int, int, int]:
        """将 'white'/'black' 或 '#rrggbb' 转为 (r,g,b)。"""
        if color in ("white", "#fff", "#ffffff"):
            return (255, 255, 255)
        if color in ("black", "#000", "#000000"):
            return (0, 0, 0)
        if color.startswith("#") and len(color) >= 7:
            return (int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16))
        return (255, 255, 255)

    def _font_size_from_bbox_height(self, bbox: BoundingBox) -> int:
        """以 box 高度为文字高度计算字号（保守值，避免渲染后超出）。"""
        return max(8, int(bbox.height * 0.85))

    def _draw_text_box(
        self,
        draw,
        item: _DrawItem,
        image: Any,
        skip_fill: bool = False,
    ) -> None:
        """按原文估计字号，优先横向适配，再将离屏文字蒙版居中贴回 box。"""
        bbox = item.bbox
        text = item.text
        left = bbox.x
        top = bbox.y
        right = bbox.x + bbox.width
        bottom = bbox.y + bbox.height
        fill_rgb = self._get_bbox_fill_color(image, bbox)
        if not skip_fill:
            draw.rectangle([(left, top), (right, bottom)], fill=fill_rgb, outline=None)
        if not text:
            return
        pad = 2
        center_x, center_y, target_w, target_h, rotation_degrees = self._text_region_geometry(item, pad=pad)
        layout = self._resolve_text_layout(
            draw=draw,
            bbox=bbox,
            text=text,
            original_text=item.original_text or text,
            target_w=target_w,
            target_h=target_h,
        )
        if layout is None:
            return
        mask = layout.mask
        if abs(rotation_degrees) >= 1.0:
            mask = self._rotate_mask(mask, -rotation_degrees)
        mask_w, mask_h = mask.size
        tx = int(round(center_x - mask_w / 2))
        ty = int(round(center_y - mask_h / 2))
        r, g, b = fill_rgb
        luminance = (r * 299 + g * 587 + b * 114) / 1000
        text_fill = (255, 255, 255) if luminance < 140 else (0, 0, 0)
        image.paste(text_fill, (tx, ty), mask)

    def _resolve_text_layout(
        self,
        draw,
        bbox: BoundingBox,
        text: str,
        original_text: str,
        *,
        target_w: int | None = None,
        target_h: int | None = None,
    ) -> _TextLayout | None:
        """先锁定接近原文的基准字号，再按宽度优先适配 replacement 文本。"""
        from PIL import ImageFont

        pad = 2
        target_w = target_w if target_w is not None else max(4, bbox.width - 2 * pad)
        target_h = target_h if target_h is not None else max(4, bbox.height - 2 * pad)
        font_path = _get_font_path()
        base_font_size = self._estimate_base_font_size(
            draw=draw,
            text=original_text or text,
            font_path=font_path,
            target_h=target_h,
        )
        min_font_size = 6
        current_size = max(base_font_size, min_font_size)
        while current_size >= min_font_size:
            font = self._load_font(font_path, current_size, ImageFont)
            original_single_line = self._build_text_mask(draw, original_text or text, font)
            desired_width = min(target_w, original_single_line.size[0])
            for single_line, char_spacing in self._single_line_masks(
                draw=draw,
                text=text,
                font=font,
                desired_width=desired_width,
            ):
                exact_layout = self._layout_from_mask(
                    mask=single_line,
                    rendered_text=text,
                    font_size=current_size,
                    target_w=target_w,
                    target_h=target_h,
                    allow_x_scale=False,
                    allow_y_scale=False,
                    char_spacing=char_spacing,
                )
                if exact_layout is not None:
                    return exact_layout
                compressed_single_line = self._layout_from_mask(
                    mask=single_line,
                    rendered_text=text,
                    font_size=current_size,
                    target_w=target_w,
                    target_h=target_h,
                    allow_x_scale=True,
                    allow_y_scale=False,
                    min_x_scale=0.72,
                    char_spacing=char_spacing,
                )
                if compressed_single_line is not None:
                    return compressed_single_line
            wrapped_text = self._wrap_text_to_width(draw, text, font, target_w)
            if wrapped_text != text:
                wrapped_mask = self._build_text_mask(draw, wrapped_text, font)
                wrapped_layout = self._layout_from_mask(
                    mask=wrapped_mask,
                    rendered_text=wrapped_text,
                    font_size=current_size,
                    target_w=target_w,
                    target_h=target_h,
                    allow_x_scale=False,
                    allow_y_scale=False,
                    char_spacing=0.0,
                )
                if wrapped_layout is not None:
                    return wrapped_layout
                compressed_wrapped_layout = self._layout_from_mask(
                    mask=wrapped_mask,
                    rendered_text=wrapped_text,
                    font_size=current_size,
                    target_w=target_w,
                    target_h=target_h,
                    allow_x_scale=True,
                    allow_y_scale=False,
                    min_x_scale=0.72,
                    char_spacing=0.0,
                )
                if compressed_wrapped_layout is not None:
                    return compressed_wrapped_layout
            current_size = max(min_font_size, current_size - 2)
            if current_size == min_font_size:
                break

        final_font = self._load_font(font_path, min_font_size, ImageFont)
        final_text = self._wrap_text_to_width(draw, text, final_font, target_w) or text
        final_mask = self._build_text_mask(draw, final_text, final_font)
        return self._layout_from_mask(
            mask=final_mask,
            rendered_text=final_text,
            font_size=min_font_size,
            target_w=target_w,
            target_h=target_h,
            allow_x_scale=True,
            allow_y_scale=True,
            min_x_scale=0.0,
            min_y_scale=0.0,
            char_spacing=0.0,
        )

    def _estimate_base_font_size(
        self,
        draw,
        text: str,
        font_path: Path | None,
        target_h: int,
    ) -> int:
        """根据原 OCR 文本的视觉高度反推一个接近原图的基准字号。"""
        from PIL import ImageFont

        sample_text = text or "Hg"
        low = 6
        high = max(12, target_h * 3)
        best = low
        while low <= high:
            mid = (low + high) // 2
            font = self._load_font(font_path, mid, ImageFont)
            bbox_xy = self._measure_multiline_text(draw, sample_text, font)
            text_h = bbox_xy[3] - bbox_xy[1]
            if text_h <= target_h:
                best = mid
                low = mid + 1
            else:
                high = mid - 1
        return max(best, 6)

    def _load_font(self, font_path: Path | None, font_size: int, image_font_module):
        """加载指定字号字体，失败时回退到默认字体。"""
        try:
            if font_path is not None:
                return image_font_module.truetype(str(font_path), size=font_size)
        except Exception:
            pass
        return image_font_module.load_default()

    def _single_line_masks(
        self,
        draw,
        text: str,
        font,
        desired_width: int,
    ) -> list[tuple[Any, float]]:
        """生成单行文本的自然字距与自适应字距候选。"""
        candidates: list[tuple[Any, float]] = []
        natural_mask = self._build_text_mask(draw, text, font)
        candidates.append((natural_mask, 0.0))
        char_spacing = self._estimate_char_spacing(text, natural_mask.size[0], desired_width)
        if abs(char_spacing) < 0.5:
            return candidates
        candidates.append((self._build_text_mask(draw, text, font, char_spacing=char_spacing), char_spacing))
        return sorted(candidates, key=lambda item: abs(item[0].size[0] - desired_width))

    def _estimate_char_spacing(self, text: str, natural_width: int, desired_width: int) -> float:
        """估计单行文本的字符间距，使其更接近原文占宽。"""
        if len(text) <= 1:
            return 0.0
        gap_count = len(text) - 1
        average_char_width = max(1.0, natural_width / len(text))
        target_spacing = (desired_width - natural_width) / gap_count
        min_spacing = -average_char_width * 0.35
        max_spacing = average_char_width * 0.9
        return max(min_spacing, min(max_spacing, target_spacing))

    def _build_text_mask(self, draw, text: str, font, char_spacing: float = 0.0) -> Any:
        """将文本离屏渲染成蒙版，用真实像素 bbox 参与布局与居中。"""
        if "\n" not in text and abs(char_spacing) >= 0.01:
            return self._build_spaced_single_line_mask(draw, text, font, char_spacing)
        return self._build_default_text_mask(draw, text, font)

    def _build_default_text_mask(self, draw, text: str, font) -> Any:
        """默认文本蒙版生成。"""
        from PIL import Image, ImageDraw

        bbox_xy = self._measure_multiline_text(draw, text, font)
        width = max(1, bbox_xy[2] - bbox_xy[0])
        height = max(1, bbox_xy[3] - bbox_xy[1])
        mask = Image.new("L", (width, height), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.multiline_text(
            (-bbox_xy[0], -bbox_xy[1]),
            text,
            fill=255,
            font=font,
            spacing=0,
            align="left",
        )
        return mask

    def _build_spaced_single_line_mask(self, draw, text: str, font, char_spacing: float) -> Any:
        """按字符间距逐字离屏渲染单行文本。"""
        from PIL import Image, ImageDraw

        line_bbox = draw.textbbox((0, 0), text, font=font)
        line_top = line_bbox[1]
        line_bottom = line_bbox[3]
        glyph_boxes: list[tuple[tuple[int, int, int, int], float]] = []
        cursor_x = 0.0
        min_left = 0.0
        max_right = 0.0
        for index, char in enumerate(text):
            bbox_xy = draw.textbbox((0, 0), char, font=font)
            glyph_boxes.append((bbox_xy, cursor_x))
            min_left = min(min_left, cursor_x + bbox_xy[0])
            max_right = max(max_right, cursor_x + bbox_xy[2])
            advance = bbox_xy[2] - bbox_xy[0]
            cursor_x += advance
            if index < len(text) - 1:
                cursor_x += char_spacing
        width = max(1, int(math.ceil(max_right - min_left)))
        height = max(1, int(math.ceil(line_bottom - line_top)))
        mask = Image.new("L", (width, height), 0)
        mask_draw = ImageDraw.Draw(mask)
        for index, char in enumerate(text):
            bbox_xy, glyph_x = glyph_boxes[index]
            mask_draw.text(
                (glyph_x - min_left - bbox_xy[0], -line_top),
                char,
                fill=255,
                font=font,
            )
        return mask

    def _layout_from_mask(
        self,
        mask: Any,
        rendered_text: str,
        font_size: int,
        target_w: int,
        target_h: int,
        *,
        allow_x_scale: bool,
        allow_y_scale: bool,
        min_x_scale: float = 1.0,
        min_y_scale: float = 1.0,
        char_spacing: float = 0.0,
    ) -> _TextLayout | None:
        """把离屏蒙版适配到目标框内。"""
        from PIL import Image

        mask_w, mask_h = mask.size
        if mask_w <= 0 or mask_h <= 0:
            return None
        scale_x = 1.0
        scale_y = 1.0
        if mask_w > target_w:
            if not allow_x_scale:
                return None
            scale_x = target_w / mask_w
            if scale_x < min_x_scale:
                return None
        if mask_h > target_h:
            if not allow_y_scale:
                return None
            scale_y = target_h / mask_h
            if scale_y < min_y_scale:
                return None
        if scale_x == 1.0 and scale_y == 1.0:
            return _TextLayout(
                mask=mask,
                rendered_text=rendered_text,
                font_size=font_size,
                char_spacing=char_spacing,
            )
        resampling = getattr(Image, "Resampling", Image).LANCZOS
        resized = mask.resize(
            (
                max(1, int(round(mask_w * scale_x))),
                max(1, int(round(mask_h * scale_y))),
            ),
            resample=resampling,
        )
        return _TextLayout(
            mask=resized,
            rendered_text=rendered_text,
            font_size=font_size,
            char_spacing=char_spacing,
            scale_x=scale_x,
            scale_y=scale_y,
        )

    def _text_region_geometry(
        self,
        item: _DrawItem,
        *,
        pad: int = 2,
    ) -> tuple[float, float, int, int, float]:
        """返回绘制中心点、文本区域宽高与旋转角度。"""
        bbox = item.bbox
        if item.polygon and len(item.polygon) >= 4:
            points = [(point.x, point.y) for point in item.polygon]
            center_x = sum(point[0] for point in points) / len(points)
            center_y = sum(point[1] for point in points) / len(points)
            top_width = self._distance(points[0], points[1])
            bottom_width = self._distance(points[2], points[3])
            left_height = self._distance(points[0], points[3])
            right_height = self._distance(points[1], points[2])
            target_w = max(4, int(round(max(1.0, (top_width + bottom_width) / 2 - 2 * pad))))
            target_h = max(4, int(round(max(1.0, (left_height + right_height) / 2 - 2 * pad))))
            rotation_degrees = item.rotation_degrees or self._polygon_rotation(item.polygon)
            return center_x, center_y, target_w, target_h, rotation_degrees
        center_x = bbox.x + bbox.width / 2
        center_y = bbox.y + bbox.height / 2
        target_w = max(4, bbox.width - 2 * pad)
        target_h = max(4, bbox.height - 2 * pad)
        return center_x, center_y, target_w, target_h, 0.0

    def _polygon_rotation(self, polygon: list[PolygonPoint]) -> float:
        """根据 polygon 的顶部边估计视觉旋转角度。"""
        if len(polygon) < 2:
            return 0.0
        for index in range(len(polygon)):
            point_1 = polygon[index]
            point_2 = polygon[(index + 1) % len(polygon)]
            dx = point_2.x - point_1.x
            dy = point_2.y - point_1.y
            if abs(dx) < 1e-6 and abs(dy) < 1e-6:
                continue
            return math.degrees(math.atan2(dy, dx))
        return 0.0

    def _rotate_mask(self, mask: Any, angle_degrees: float) -> Any:
        """旋转文本蒙版，使其与 OCR 多边形方向一致。"""
        from PIL import Image

        resampling = getattr(Image, "Resampling", Image).BICUBIC
        return mask.rotate(angle_degrees, resample=resampling, expand=True)

    def _distance(self, point_1: tuple[float, float], point_2: tuple[float, float]) -> float:
        """计算两点间距离。"""
        return math.hypot(point_2[0] - point_1[0], point_2[1] - point_1[1])

    def _wrap_text_to_width(self, draw, text: str, font, target_w: int) -> str:
        """按宽度将文本折成多行，优先保证不横向溢出。"""
        paragraphs = text.splitlines() or [text]
        wrapped_lines: list[str] = []
        for paragraph in paragraphs:
            if not paragraph:
                wrapped_lines.append("")
                continue
            current = ""
            for char in paragraph:
                candidate = current + char
                if current and self._text_width(draw, candidate, font) > target_w:
                    wrapped_lines.append(current)
                    current = char
                    continue
                current = candidate
            if current:
                wrapped_lines.append(current)
        return "\n".join(wrapped_lines)

    def _measure_multiline_text(self, draw, text: str, font) -> tuple[int, int, int, int]:
        """测量多行文本的 bbox。"""
        try:
            return draw.multiline_textbbox((0, 0), text, font=font, spacing=0, align="left")
        except Exception:
            return draw.textbbox((0, 0), text, font=font)

    def _text_width(self, draw, text: str, font) -> int:
        """测量单行文本宽度。"""
        bbox_xy = draw.textbbox((0, 0), text, font=font)
        return bbox_xy[2] - bbox_xy[0]
