"""截图渲染器实现。"""

from pathlib import Path
from typing import Any

from privacyguard.domain.enums import ActionType
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox


class ScreenshotRenderer:
    """根据决策动作在截图上覆盖并重绘替代文本。"""

    def render(self, image: Any, plan: DecisionPlan) -> Any:
        """将决策计划应用到截图并返回新图像。"""
        if image is None:
            return None
        pil_image = self._to_pil_image(image)
        if pil_image is None:
            return image
        draw = self._create_draw(pil_image)
        for action in plan.actions:
            if action.action_type == ActionType.KEEP:
                continue
            if not action.replacement_text or action.bbox is None:
                continue
            text_to_draw = self._fit_text_to_bbox(action.replacement_text, action.bbox)
            self._draw_text_box(draw=draw, bbox=action.bbox, text=text_to_draw)
        return pil_image

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

    def _fit_text_to_bbox(self, text: str, bbox: BoundingBox) -> str:
        """根据 bbox 宽度对替代文本做保守截断。"""
        estimated_char_width = 8
        max_chars = max(1, bbox.width // estimated_char_width)
        if len(text) <= max_chars:
            return text
        if max_chars == 1:
            return text[0]
        return text[: max_chars - 1] + "…"

    def _draw_text_box(self, draw, bbox: BoundingBox, text: str) -> None:
        """在指定 bbox 区域覆盖并绘制文本。"""
        left = bbox.x
        top = bbox.y
        right = bbox.x + bbox.width
        bottom = bbox.y + bbox.height
        draw.rectangle([(left, top), (right, bottom)], fill="white")
        draw.text((left + 1, top + 1), text, fill="black")
