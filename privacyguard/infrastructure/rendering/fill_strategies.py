"""截图填充策略实现：ring、cv、mix（与 decision 一致，按模式注册、工厂构建）。"""

from typing import Any

from privacyguard.domain.enums import ActionType
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox


def _inpaint_bboxes(
    pil_image: Any,
    plan: DecisionPlan,
    only_actions: list[Any] | None = None,
) -> Any:
    """对指定 action 的 bbox 做 OpenCV inpaint；only_actions 为空则对所有非 KEEP 且含 bbox 的 action 做。"""
    try:
        import numpy as np
        import cv2
    except ImportError:
        return pil_image
    try:
        from PIL import Image
        w, h = pil_image.size
        arr = np.array(pil_image)
        if arr.ndim == 2:
            arr = cv2.cvtColor(arr, cv2.COLOR_GRAY2BGR)
        elif arr.shape[-1] == 3:
            arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
        mask = np.zeros((h, w), dtype=np.uint8)
        actions_to_mask = (
            only_actions
            if only_actions is not None
            else [a for a in plan.actions if a.action_type != ActionType.KEEP and a.bbox is not None]
        )
        for action in actions_to_mask:
            if action.bbox is None:
                continue
            x, y = int(action.bbox.x), int(action.bbox.y)
            bw, bh = int(action.bbox.width), int(action.bbox.height)
            x2, y2 = min(w, x + bw), min(h, y + bh)
            x, y = max(0, x), max(0, y)
            if x2 > x and y2 > y:
                mask[y:y2, x:x2] = 255
        if np.any(mask):
            radius = max(2, min(w, h) // 200)
            result = cv2.inpaint(arr, mask, radius, cv2.INPAINT_TELEA)
            return Image.fromarray(cv2.cvtColor(result, cv2.COLOR_BGR2RGB))
        return pil_image
    except Exception:
        return pil_image


class RingFillStrategy:
    """环带平均色填充：不在此处改图，由 ScreenshotRenderer 对每格画矩形。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        actions_list: list[Any],
    ) -> tuple[Any, list[bool]]:
        filled = image
        skip_fill = [False] * len(actions_list)
        return (filled, skip_fill)


class CVFillStrategy:
    """OpenCV inpaint 填充：对所有 bbox 做一次 inpaint，每格不再画矩形。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        actions_list: list[Any],
    ) -> tuple[Any, list[bool]]:
        filled = _inpaint_bboxes(image, plan, only_actions=None)
        skip_fill = [True] * len(actions_list)
        return (filled, skip_fill)


class MixFillStrategy:
    """主色占比法：复杂背景用 cv，纯色用 ring；仅对复杂 bbox 做 inpaint。"""

    def __init__(self, main_color_ratio_threshold: float = 0.7) -> None:
        self._main_color_ratio_threshold = main_color_ratio_threshold

    def _is_complex_background(self, image: Any, bbox: BoundingBox) -> bool:
        try:
            w, h = image.size
            x1 = max(0, min(bbox.x, w - 1))
            y1 = max(0, min(bbox.y, h - 1))
            x2 = max(x1 + 1, min(bbox.x + bbox.width, w))
            y2 = max(y1 + 1, min(bbox.y + bbox.height, h))
            crop = image.crop((x1, y1, x2, y2))
            pixels = list(crop.getdata())
            if len(pixels) < 4:
                return False
            bin_shift = 4
            hist: dict[tuple[int, int, int], int] = {}
            for p in pixels:
                r, g, b = p[0], p[1], p[2]
                key = (r >> bin_shift, g >> bin_shift, b >> bin_shift)
                hist[key] = hist.get(key, 0) + 1
            total = len(pixels)
            max_count = max(hist.values()) if hist else 0
            ratio = max_count / total
            return ratio < self._main_color_ratio_threshold
        except Exception:
            return True

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        actions_list: list[Any],
    ) -> tuple[Any, list[bool]]:
        skip_fill = [self._is_complex_background(image, a.bbox) for a in actions_list]
        complex_actions = [a for a, skip in zip(actions_list, skip_fill) if skip]
        filled = _inpaint_bboxes(image, plan, only_actions=complex_actions) if complex_actions else image
        return (filled, skip_fill)
