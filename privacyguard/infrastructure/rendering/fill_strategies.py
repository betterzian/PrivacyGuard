"""截图填充策略实现：ring、gradient、cv、mix。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox

Color = tuple[int, int, int]


@dataclass
class _FillContext:
    """单个绘制单元在填充阶段需要的局部几何与采样信息。"""

    item: Any
    crop_box: tuple[int, int, int, int]
    inner_bounds: tuple[int, int, int, int]
    shape_mask: Any
    ring_samples: list[tuple[int, int, Color]]
    side_samples: dict[str, list[Color]]


@dataclass
class _GradientSpec:
    """局部双线性渐变的四角颜色。"""

    top_left: Color
    top_right: Color
    bottom_left: Color
    bottom_right: Color


def _rgb_tuple(pixel: Any) -> Color:
    """把图像像素统一规整成 RGB 三元组。"""
    if isinstance(pixel, int):
        return (pixel, pixel, pixel)
    if isinstance(pixel, tuple):
        if len(pixel) >= 3:
            return (int(pixel[0]), int(pixel[1]), int(pixel[2]))
        if len(pixel) == 1:
            value = int(pixel[0])
            return (value, value, value)
    return (255, 255, 255)


def _shape_polygon(item: Any) -> list[tuple[int, int]] | None:
    """提取绘制单元上的 polygon 顶点。"""
    polygon = getattr(item, "polygon", None)
    if not polygon or len(polygon) < 3:
        return None
    points: list[tuple[int, int]] = []
    for point in polygon:
        x = getattr(point, "x", None)
        y = getattr(point, "y", None)
        if x is None or y is None:
            continue
        points.append((int(round(float(x))), int(round(float(y)))))
    return points or None


def _shape_bounds(item: Any) -> tuple[int, int, int, int]:
    """提取绘制单元的轴对齐范围。"""
    bbox = getattr(item, "bbox", None)
    if bbox is None:
        raise ValueError("fill item requires bbox.")
    left = int(bbox.x)
    top = int(bbox.y)
    right = left + int(bbox.width)
    bottom = top + int(bbox.height)
    return (left, top, right, bottom)


def _context_padding(item: Any) -> int:
    """根据目标大小动态决定外围采样带厚度。"""
    bbox = getattr(item, "bbox", None)
    if bbox is None:
        return 6
    return max(3, min(20, int(round(min(bbox.width, bbox.height) * 0.38))))


def _build_shape_mask(size: tuple[int, int], item: Any, offset: tuple[int, int]) -> Any:
    """构建 item 的局部形状蒙版，polygon 优先，bbox 兜底。"""
    from PIL import Image, ImageDraw, ImageFilter

    width, height = size
    offset_x, offset_y = offset
    mask = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(mask)
    bbox = getattr(item, "bbox", None)
    expansion = 3
    if bbox is not None:
        expansion = max(2, min(6, int(round(min(bbox.width, bbox.height) * 0.1))))
    polygon = _shape_polygon(item)
    if polygon is not None:
        shifted = [(x - offset_x, y - offset_y) for x, y in polygon]
        draw.polygon(shifted, fill=255)
        kernel = expansion * 2 + 1
        return mask.filter(ImageFilter.MaxFilter(kernel)).filter(ImageFilter.GaussianBlur(radius=max(1, expansion // 2)))
    left, top, right, bottom = _shape_bounds(item)
    draw.rectangle(
        [
            (left - offset_x - expansion, top - offset_y - expansion),
            (right - offset_x - 1 + expansion, bottom - offset_y - 1 + expansion),
        ],
        fill=255,
        outline=None,
    )
    return mask


def _build_fill_context(image: Any, item: Any) -> _FillContext:
    """围绕目标区域收集背景 ring 像素与边缘颜色样本。"""
    left, top, right, bottom = _shape_bounds(item)
    image_w, image_h = image.size
    pad = _context_padding(item)
    crop_left = max(0, left - pad)
    crop_top = max(0, top - pad)
    crop_right = min(image_w, right + pad)
    crop_bottom = min(image_h, bottom + pad)
    crop = image.crop((crop_left, crop_top, crop_right, crop_bottom)).convert("RGB")
    crop_w, crop_h = crop.size
    shape_mask = _build_shape_mask((crop_w, crop_h), item, offset=(crop_left, crop_top))

    inner_left = max(0, left - crop_left)
    inner_top = max(0, top - crop_top)
    inner_right = min(crop_w, right - crop_left)
    inner_bottom = min(crop_h, bottom - crop_top)
    ring_samples: list[tuple[int, int, Color]] = []
    side_samples: dict[str, list[Color]] = {"top": [], "bottom": [], "left": [], "right": []}
    crop_pixels = crop.load()
    mask_pixels = shape_mask.load()
    for y in range(crop_h):
        for x in range(crop_w):
            if mask_pixels[x, y] != 0:
                continue
            color = _rgb_tuple(crop_pixels[x, y])
            ring_samples.append((x, y, color))
            if y < inner_top:
                side_samples["top"].append(color)
            if y >= inner_bottom:
                side_samples["bottom"].append(color)
            if x < inner_left:
                side_samples["left"].append(color)
            if x >= inner_right:
                side_samples["right"].append(color)
    return _FillContext(
        item=item,
        crop_box=(crop_left, crop_top, crop_right, crop_bottom),
        inner_bounds=(inner_left, inner_top, inner_right, inner_bottom),
        shape_mask=shape_mask,
        ring_samples=ring_samples,
        side_samples=side_samples,
    )


def _average_color(colors: list[Color]) -> Color:
    """求 RGB 列表的平均色。"""
    if not colors:
        return (255, 255, 255)
    total = len(colors)
    return (
        sum(color[0] for color in colors) // total,
        sum(color[1] for color in colors) // total,
        sum(color[2] for color in colors) // total,
    )


def _median_color(colors: list[Color]) -> Color:
    """求 RGB 列表的逐通道中位色，更抗噪。"""
    if not colors:
        return (255, 255, 255)
    reds = sorted(color[0] for color in colors)
    greens = sorted(color[1] for color in colors)
    blues = sorted(color[2] for color in colors)
    mid = len(colors) // 2
    return (reds[mid], greens[mid], blues[mid])


def _mix_colors(color_a: Color, color_b: Color) -> Color:
    """计算两种颜色的中间色。"""
    return (
        (color_a[0] + color_b[0]) // 2,
        (color_a[1] + color_b[1]) // 2,
        (color_a[2] + color_b[2]) // 2,
    )


def _color_distance(color_a: Color, color_b: Color) -> float:
    """估计两种颜色在视觉上的距离。"""
    return (
        abs(color_a[0] - color_b[0]) +
        abs(color_a[1] - color_b[1]) +
        abs(color_a[2] - color_b[2])
    ) / 3.0


def _dominant_color_ratio(colors: list[Color], bin_shift: int = 4) -> float:
    """计算主色在量化色桶中的占比。"""
    if not colors:
        return 1.0
    histogram: dict[tuple[int, int, int], int] = {}
    for red, green, blue in colors:
        key = (red >> bin_shift, green >> bin_shift, blue >> bin_shift)
        histogram[key] = histogram.get(key, 0) + 1
    return max(histogram.values()) / len(colors)


def _mean_color_error(colors: list[Color], target: Color) -> float:
    """计算一组颜色到目标色的平均偏差。"""
    if not colors:
        return 0.0
    return sum(_color_distance(color, target) for color in colors) / len(colors)


def _build_gradient_spec(context: _FillContext) -> _GradientSpec:
    """使用上下左右的边缘样本估计一个局部双线性渐变。"""
    ring_colors = [sample[2] for sample in context.ring_samples]
    base_color = _median_color(ring_colors)
    top_color = _median_color(context.side_samples["top"]) if context.side_samples["top"] else base_color
    bottom_color = _median_color(context.side_samples["bottom"]) if context.side_samples["bottom"] else base_color
    left_color = _median_color(context.side_samples["left"]) if context.side_samples["left"] else base_color
    right_color = _median_color(context.side_samples["right"]) if context.side_samples["right"] else base_color
    return _GradientSpec(
        top_left=_mix_colors(top_color, left_color),
        top_right=_mix_colors(top_color, right_color),
        bottom_left=_mix_colors(bottom_color, left_color),
        bottom_right=_mix_colors(bottom_color, right_color),
    )


def _gradient_color_at(context: _FillContext, spec: _GradientSpec, x: int, y: int) -> Color:
    """按局部坐标从双线性渐变中采样颜色。"""
    left, top, right, bottom = context.inner_bounds
    width = max(1, right - left)
    height = max(1, bottom - top)
    u = min(1.0, max(0.0, (x - left) / max(1, width - 1)))
    v = min(1.0, max(0.0, (y - top) / max(1, height - 1)))
    top_color = (
        spec.top_left[0] * (1.0 - u) + spec.top_right[0] * u,
        spec.top_left[1] * (1.0 - u) + spec.top_right[1] * u,
        spec.top_left[2] * (1.0 - u) + spec.top_right[2] * u,
    )
    bottom_color = (
        spec.bottom_left[0] * (1.0 - u) + spec.bottom_right[0] * u,
        spec.bottom_left[1] * (1.0 - u) + spec.bottom_right[1] * u,
        spec.bottom_left[2] * (1.0 - u) + spec.bottom_right[2] * u,
    )
    return (
        int(round(top_color[0] * (1.0 - v) + bottom_color[0] * v)),
        int(round(top_color[1] * (1.0 - v) + bottom_color[1] * v)),
        int(round(top_color[2] * (1.0 - v) + bottom_color[2] * v)),
    )


def _gradient_fit_error(context: _FillContext, spec: _GradientSpec) -> float:
    """用 ring 样本评估双线性渐变的拟合误差。"""
    if not context.ring_samples:
        return 0.0
    return sum(
        _color_distance(color, _gradient_color_at(context, spec, x, y))
        for x, y, color in context.ring_samples
    ) / len(context.ring_samples)


def _paste_flat_fill(image: Any, context: _FillContext) -> Any:
    """使用局部主色或中位色填充目标区域。"""
    from PIL import Image

    crop_left, crop_top, crop_right, crop_bottom = context.crop_box
    ring_colors = [sample[2] for sample in context.ring_samples]
    fill_color = _median_color(ring_colors)
    overlay = Image.new("RGB", (crop_right - crop_left, crop_bottom - crop_top), fill_color)
    image.paste(overlay, (crop_left, crop_top), context.shape_mask)
    return image


def _paste_gradient_fill(image: Any, context: _FillContext) -> Any:
    """使用局部双线性渐变填充目标区域。"""
    from PIL import Image

    crop_left, crop_top, crop_right, crop_bottom = context.crop_box
    width = crop_right - crop_left
    height = crop_bottom - crop_top
    spec = _build_gradient_spec(context)
    overlay = Image.new("RGB", (width, height))
    overlay_pixels = overlay.load()
    for y in range(height):
        for x in range(width):
            overlay_pixels[x, y] = _gradient_color_at(context, spec, x, y)
    image.paste(overlay, (crop_left, crop_top), context.shape_mask)
    return image


def _build_inpaint_mask(items: list[Any], size: tuple[int, int]) -> Any:
    """按 draw item 几何生成 OpenCV inpaint 使用的掩码。"""
    import numpy as np
    import cv2

    width, height = size
    mask = np.zeros((height, width), dtype=np.uint8)
    for item in items:
        polygon = _shape_polygon(item)
        if polygon is not None:
            cv2.fillPoly(mask, [np.array(polygon, dtype=np.int32)], 255)
            continue
        bbox = getattr(item, "bbox", None)
        if bbox is None:
            continue
        left = max(0, int(bbox.x))
        top = max(0, int(bbox.y))
        right = min(width, left + int(bbox.width))
        bottom = min(height, top + int(bbox.height))
        if right > left and bottom > top:
            mask[top:bottom, left:right] = 255
    kernel = np.ones((5, 5), dtype=np.uint8)
    mask = cv2.dilate(mask, kernel, iterations=2)
    return mask


def _inpaint_shapes(pil_image: Any, items: list[Any]) -> tuple[Any, bool]:
    """对指定绘制单元形状做 OpenCV inpaint。"""
    if not items:
        return (pil_image, True)
    try:
        import numpy as np
        import cv2
    except ImportError:
        return (pil_image, False)
    try:
        from PIL import Image

        width, height = pil_image.size
        arr = np.array(pil_image)
        if arr.ndim == 2:
            arr = cv2.cvtColor(arr, cv2.COLOR_GRAY2BGR)
        elif arr.shape[-1] == 3:
            arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
        mask = _build_inpaint_mask(items, (width, height))
        if not mask.any():
            return (pil_image, True)
        min_side = min(getattr(item.bbox, "width", 1) for item in items if getattr(item, "bbox", None) is not None)
        radius = max(2, min(8, int(round(max(1, min_side) * 0.12))))
        result = cv2.inpaint(arr, mask, radius, cv2.INPAINT_TELEA)
        return (Image.fromarray(cv2.cvtColor(result, cv2.COLOR_BGR2RGB)), True)
    except Exception:
        return (pil_image, False)


class RingFillStrategy:
    """平坦背景优先的纯色填充，polygon-aware。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        draw_items: list[Any],
    ) -> tuple[Any, list[bool]]:
        filled = image
        for item in draw_items:
            filled = _paste_flat_fill(filled, _build_fill_context(filled, item))
        skip_fill = [True] * len(draw_items)
        return (filled, skip_fill)


class GradientFillStrategy:
    """局部渐变填充；当边缘颜色接近一致时自然退化为纯色。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        draw_items: list[Any],
    ) -> tuple[Any, list[bool]]:
        filled = image
        for item in draw_items:
            filled = _paste_gradient_fill(filled, _build_fill_context(filled, item))
        skip_fill = [True] * len(draw_items)
        return (filled, skip_fill)


class CVFillStrategy:
    """OpenCV inpaint 填充；不可用时回退到渐变填充。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        draw_items: list[Any],
    ) -> tuple[Any, list[bool]]:
        filled, succeeded = _inpaint_shapes(image, draw_items)
        if succeeded:
            return (filled, [True] * len(draw_items))
        return GradientFillStrategy().apply(image, plan, draw_items)


class MixFillStrategy:
    """flat + gradient + inpaint 三段式背景填充。"""

    def __init__(
        self,
        main_color_ratio_threshold: float = 0.7,
        flat_error_threshold: float = 12.0,
        gradient_error_threshold: float = 18.0,
    ) -> None:
        self._main_color_ratio_threshold = main_color_ratio_threshold
        self._flat_error_threshold = flat_error_threshold
        self._gradient_error_threshold = gradient_error_threshold

    def _classify_fill_mode(self, context: _FillContext) -> str:
        ring_colors = [sample[2] for sample in context.ring_samples]
        if len(ring_colors) < 6:
            return "flat"
        flat_color = _median_color(ring_colors)
        dominant_ratio = _dominant_color_ratio(ring_colors)
        flat_error = _mean_color_error(ring_colors, flat_color)
        if dominant_ratio >= self._main_color_ratio_threshold or flat_error <= self._flat_error_threshold:
            return "flat"
        gradient_spec = _build_gradient_spec(context)
        gradient_error = _gradient_fit_error(context, gradient_spec)
        if gradient_error <= self._gradient_error_threshold:
            return "gradient"
        return "inpaint"

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        draw_items: list[Any],
    ) -> tuple[Any, list[bool]]:
        contexts = [_build_fill_context(image, item) for item in draw_items]
        filled = image
        skip_fill = [False] * len(draw_items)
        inpaint_indices: list[int] = []

        for index, context in enumerate(contexts):
            fill_mode = self._classify_fill_mode(context)
            if fill_mode == "flat":
                filled = _paste_flat_fill(filled, context)
                skip_fill[index] = True
                continue
            if fill_mode == "gradient":
                filled = _paste_gradient_fill(filled, context)
                skip_fill[index] = True
                continue
            inpaint_indices.append(index)

        if inpaint_indices:
            inpaint_items = [draw_items[index] for index in inpaint_indices]
            filled, succeeded = _inpaint_shapes(filled, inpaint_items)
            if succeeded:
                for index in inpaint_indices:
                    skip_fill[index] = True
            else:
                for index in inpaint_indices:
                    filled = _paste_gradient_fill(filled, contexts[index])
                    skip_fill[index] = True

        return (filled, skip_fill)
