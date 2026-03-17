"""截图渲染器实现。填充逻辑由注入的 ScreenshotFillStrategy 提供（与 decision 一致：按模式注册、工厂构建）。"""

from pathlib import Path
from typing import Any

from privacyguard.domain.enums import ActionType
from privacyguard.domain.interfaces.screenshot_fill_strategy import ScreenshotFillStrategy
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox
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

    def render(self, image: Any, plan: DecisionPlan) -> Any:
        """将决策计划应用到截图并返回新图像。"""
        if image is None:
            return None
        pil_image = self._to_pil_image(image)
        if pil_image is None:
            return image
        actions_list = list(self._iter_draw_actions(plan))
        pil_image, skip_fill_flags = self._fill_strategy.apply(pil_image, plan, actions_list)
        draw = self._create_draw(pil_image)
        for i, action in enumerate(actions_list):
            self._draw_text_box(
                draw=draw,
                bbox=action.bbox,
                text=action.replacement_text,
                image=pil_image,
                skip_fill=skip_fill_flags[i],
            )
        return pil_image

    def _iter_draw_actions(self, plan: DecisionPlan):
        """可绘制动作迭代（KEEP 且无 bbox/replacement 的已过滤）。"""
        for action in plan.actions:
            if action.action_type == ActionType.KEEP:
                continue
            if not action.replacement_text or action.bbox is None:
                continue
            yield action

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
