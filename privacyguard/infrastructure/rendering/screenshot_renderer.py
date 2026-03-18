"""截图渲染器实现。填充逻辑由注入的 ScreenshotFillStrategy 提供（与 decision 一致：按模式注册、工厂构建）。"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import ActionType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.interfaces.screenshot_fill_strategy import ScreenshotFillStrategy
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.rendering.fill_strategies import RingFillStrategy

# 常见系统字体路径
_DEFAULT_FONT_PATHS = [
    "C:/Windows/Fonts/msyh.ttc",   # Windows 微软雅黑
    "C:/Windows/Fonts/msyhbd.ttc",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/PingFang.ttc",
    "/System/Library/Fonts/Helvetica.ttc",
]


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


class ScreenshotRenderer:
    """截图上对 PII 区域填充并绘制替代文本；填充策略由注入的 ScreenshotFillStrategy 提供（与 decision 一致）。"""

    def __init__(
        self,
        fill_strategy: ScreenshotFillStrategy | None = None,
        background_color: str | None = None,
        text_color: str = "black",
    ) -> None:
        self._fill_strategy = fill_strategy or RingFillStrategy()
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
            return image
        draw_items = self._build_draw_items(plan, ocr_blocks=ocr_blocks or [])
        pil_image, skip_fill_flags = self._fill_strategy.apply(pil_image, plan, draw_items)
        draw = self._create_draw(pil_image)
        for i, item in enumerate(draw_items):
            self._draw_text_box(
                draw=draw,
                bbox=item.bbox,
                text=item.text,
                image=pil_image,
                skip_fill=skip_fill_flags[i],
            )
        return pil_image

    def _build_draw_items(self, plan: DecisionPlan, ocr_blocks: list[OCRTextBlock]) -> list[_DrawItem]:
        """根据 plan 与 OCR 原始块构建最终绘制单元。"""
        block_map = {block.block_id: block for block in ocr_blocks if block.block_id}
        grouped_actions: dict[str, list[DecisionAction]] = {}
        ordered_block_ids: list[str] = []
        legacy_items: list[_DrawItem] = []

        for action in plan.actions:
            if action.action_type == ActionType.KEEP:
                continue
            if not action.replacement_text or action.bbox is None:
                continue
            if (
                action.block_id
                and action.block_id in block_map
                and action.span_start is not None
                and action.span_end is not None
            ):
                if action.block_id not in grouped_actions:
                    grouped_actions[action.block_id] = []
                    ordered_block_ids.append(action.block_id)
                grouped_actions[action.block_id].append(action)
                continue
            legacy_items.append(_DrawItem(bbox=action.bbox, text=action.replacement_text))

        draw_items: list[_DrawItem] = []
        for block_id in ordered_block_ids:
            block = block_map.get(block_id)
            if block is None:
                continue
            rebuilt_text = self._rebuild_block_text(block.text, grouped_actions.get(block_id, []))
            draw_items.append(_DrawItem(bbox=block.bbox, text=rebuilt_text))
        draw_items.extend(legacy_items)
        return draw_items

    def _rebuild_block_text(self, original_text: str, actions: list[DecisionAction]) -> str:
        """按 span 在 OCR 原文上做局部替换，再生成整框重绘文本。"""
        selected = self._select_non_overlapping_actions(original_text, actions)
        if not selected:
            return actions[0].replacement_text or original_text
        rebuilt = original_text
        for action in sorted(selected, key=lambda item: item.span_start or 0, reverse=True):
            start = action.span_start or 0
            end = action.span_end or start
            rebuilt = rebuilt[:start] + (action.replacement_text or "") + rebuilt[end:]
        return rebuilt

    def _select_non_overlapping_actions(
        self,
        original_text: str,
        actions: list[DecisionAction],
    ) -> list[DecisionAction]:
        """优先保留更长的非重叠替换，避免同框 span 相互踩踏。"""
        valid_actions = [action for action in actions if self._is_valid_span_action(original_text, action)]
        ranked = sorted(
            valid_actions,
            key=lambda item: (-(item.span_end - item.span_start), item.span_start),
        )
        selected: list[DecisionAction] = []
        occupied: list[tuple[int, int]] = []
        for action in ranked:
            start = action.span_start or 0
            end = action.span_end or start
            if any(not (end <= used_start or start >= used_end) for used_start, used_end in occupied):
                continue
            selected.append(action)
            occupied.append((start, end))
        return selected

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
        bbox: BoundingBox,
        text: str,
        image: Any,
        skip_fill: bool = False,
    ) -> None:
        """环带平均色填充（无边框）或跳过填充（cv 已 inpaint）；全文绘制，不够时缩小字号直至全部放入 box。"""
        from PIL import ImageDraw, ImageFont

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
        target_w = max(4, bbox.width - 2 * pad)
        target_h = max(4, bbox.height - 2 * pad)
        font_path = _get_font_path()
        font_size = self._font_size_from_bbox_height(bbox)
        min_font_size = 6
        font = None
        try:
            if font_path is not None:
                font = ImageFont.truetype(str(font_path), size=font_size)
            else:
                font = ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        while font_path and font_size >= min_font_size:
            try:
                font = ImageFont.truetype(str(font_path), size=font_size)
                bbox_xy = draw.textbbox((0, 0), text, font=font)
                tw = bbox_xy[2] - bbox_xy[0]
                th = bbox_xy[3] - bbox_xy[1]
                if tw <= target_w and th <= target_h:
                    break
                font_size = max(min_font_size, font_size - 2)
            except Exception:
                break
        if font is None:
            try:
                font = ImageFont.truetype(str(font_path), size=font_size) if font_path else ImageFont.load_default()
            except Exception:
                font = ImageFont.load_default()
        try:
            bbox_xy = draw.textbbox((0, 0), text, font=font)
            tw = bbox_xy[2] - bbox_xy[0]
            th = bbox_xy[3] - bbox_xy[1]
            offset_y = bbox_xy[1]
            tx = left + pad
            ty = top + max(0, (bbox.height - th) // 2) - offset_y
        except Exception:
            tx, ty = left + pad, top + pad
        r, g, b = fill_rgb
        luminance = (r * 299 + g * 587 + b * 114) / 1000
        text_fill = (255, 255, 255) if luminance < 140 else (0, 0, 0)
        draw.text((tx, ty), text, fill=text_fill, font=font)
