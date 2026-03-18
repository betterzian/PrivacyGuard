"""安卓风格截图的填充回归测试。"""

from types import SimpleNamespace

from PIL import Image, ImageDraw

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.infrastructure.rendering import fill_strategies
from privacyguard.infrastructure.rendering.fill_strategies import MixFillStrategy


def _demo_plan() -> DecisionPlan:
    return DecisionPlan(
        session_id="android-regression",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-android",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                replacement_text="李四",
                bbox=BoundingBox(x=0, y=0, width=1, height=1),
                reason="android-regression",
            )
        ],
    )


def _draw_fake_text(image: Image.Image, bbox: BoundingBox, color: tuple[int, int, int] = (24, 24, 24)) -> None:
    """在 bbox 内画出几段类似安卓界面文字的粗短横条。"""
    draw = ImageDraw.Draw(image)
    x = bbox.x + 6
    y = bbox.y + max(2, bbox.height // 4)
    bar_height = max(3, bbox.height // 4)
    gaps = max(3, bbox.height // 5)
    for width in (18, 12, 16, 10):
        if x + width >= bbox.x + bbox.width - 4:
            break
        draw.rounded_rectangle(
            [(x, y), (x + width, y + bar_height)],
            radius=1,
            fill=color,
        )
        x += width + gaps


def _fill_vertical_gradient(
    image: Image.Image,
    top_color: tuple[int, int, int],
    bottom_color: tuple[int, int, int],
    region: tuple[int, int, int, int] | None = None,
) -> None:
    """向指定区域写入竖向渐变。"""
    if region is None:
        left = 0
        top = 0
        right, bottom = image.size
    else:
        left, top, right, bottom = region
    height = max(1, bottom - top)
    pixels = image.load()
    for y in range(top, bottom):
        ratio = (y - top) / max(1, height - 1)
        color = tuple(
            int(round(top_color[index] * (1.0 - ratio) + bottom_color[index] * ratio))
            for index in range(3)
        )
        for x in range(left, right):
            pixels[x, y] = color


def _build_item(bbox: BoundingBox) -> SimpleNamespace:
    return SimpleNamespace(bbox=bbox, polygon=None, text="张三")


def _sample(image: Image.Image, x: int, y: int) -> tuple[int, int, int]:
    return tuple(int(value) for value in image.getpixel((x, y))[:3])


def _avg_channel_delta(color_a: tuple[int, int, int], color_b: tuple[int, int, int]) -> float:
    return sum(abs(color_a[index] - color_b[index]) for index in range(3)) / 3.0


def _build_settings_scene() -> tuple[Image.Image, SimpleNamespace]:
    image = Image.new("RGB", (320, 220), (248, 248, 248))
    draw = ImageDraw.Draw(image)
    draw.rectangle([(0, 0), (320, 56)], fill=(245, 245, 245))
    draw.line([(0, 86), (320, 86)], fill=(229, 229, 229), width=2)
    draw.line([(0, 150), (320, 150)], fill=(229, 229, 229), width=2)
    bbox = BoundingBox(x=108, y=104, width=108, height=24)
    _draw_fake_text(image, bbox)
    return image, _build_item(bbox)


def _build_toolbar_scene() -> tuple[Image.Image, SimpleNamespace]:
    image = Image.new("RGB", (320, 132), (255, 255, 255))
    _fill_vertical_gradient(image, (248, 251, 255), (96, 148, 241), region=(0, 0, 320, 88))
    bbox = BoundingBox(x=92, y=30, width=136, height=26)
    _draw_fake_text(image, bbox, color=(18, 34, 78))
    return image, _build_item(bbox)


def _build_chat_bubble_scene() -> tuple[Image.Image, SimpleNamespace]:
    image = Image.new("RGB", (320, 220), (244, 245, 247))
    draw = ImageDraw.Draw(image)
    bubble_region = (54, 72, 266, 152)
    draw.rounded_rectangle(bubble_region, radius=18, fill=(214, 247, 226))
    _fill_vertical_gradient(image, (236, 255, 241), (140, 219, 169), region=bubble_region)
    draw.rounded_rectangle(bubble_region, radius=18, outline=(208, 238, 216), width=1)
    bbox = BoundingBox(x=96, y=97, width=128, height=24)
    _draw_fake_text(image, bbox, color=(32, 77, 48))
    return image, _build_item(bbox)


def _build_photo_scene() -> tuple[Image.Image, SimpleNamespace]:
    image = Image.new("RGB", (240, 180), (0, 0, 0))
    pixels = image.load()
    for y in range(180):
        for x in range(240):
            pixels[x, y] = (
                (x * 17 + y * 13) % 256,
                (x * 29 + y * 7 + ((x * y) % 31) * 3) % 256,
                (x * 11 + y * 19 + ((x // 5 + y // 3) % 9) * 17) % 256,
            )
    bbox = BoundingBox(x=72, y=68, width=96, height=28)
    _draw_fake_text(image, bbox, color=(250, 250, 250))
    return image, _build_item(bbox)


def test_android_settings_scene_prefers_flat_fill() -> None:
    strategy = MixFillStrategy()
    image, item = _build_settings_scene()
    context = fill_strategies._build_fill_context(image, item)

    assert strategy._classify_fill_mode(context) == "flat"

    filled, skip_fill = strategy.apply(image.copy(), _demo_plan(), [item])
    center = _sample(filled, item.bbox.x + item.bbox.width // 2, item.bbox.y + item.bbox.height // 2)
    ring = _sample(filled, item.bbox.x - 3, item.bbox.y + item.bbox.height // 2)

    assert skip_fill == [True]
    assert _avg_channel_delta(center, ring) <= 6.0


def test_android_toolbar_scene_prefers_gradient_fill() -> None:
    strategy = MixFillStrategy()
    image, item = _build_toolbar_scene()
    context = fill_strategies._build_fill_context(image, item)

    assert strategy._classify_fill_mode(context) == "gradient"

    filled, skip_fill = strategy.apply(image.copy(), _demo_plan(), [item])
    center_x = item.bbox.x + item.bbox.width // 2
    top_inside = _sample(filled, center_x, item.bbox.y + 3)
    bottom_inside = _sample(filled, center_x, item.bbox.y + item.bbox.height - 4)
    top_outside = _sample(filled, center_x, item.bbox.y - 2)
    bottom_outside = _sample(filled, center_x, item.bbox.y + item.bbox.height + 1)

    assert skip_fill == [True]
    assert _avg_channel_delta(top_inside, top_outside) <= 10.0
    assert _avg_channel_delta(bottom_inside, bottom_outside) <= 10.0
    assert top_inside[2] > bottom_inside[2]


def test_android_chat_bubble_scene_prefers_gradient_fill() -> None:
    strategy = MixFillStrategy()
    image, item = _build_chat_bubble_scene()
    context = fill_strategies._build_fill_context(image, item)

    assert strategy._classify_fill_mode(context) == "gradient"

    filled, skip_fill = strategy.apply(image.copy(), _demo_plan(), [item])
    center_x = item.bbox.x + item.bbox.width // 2
    top_inside = _sample(filled, center_x, item.bbox.y + 3)
    bottom_inside = _sample(filled, center_x, item.bbox.y + item.bbox.height - 4)

    assert skip_fill == [True]
    assert top_inside[1] > bottom_inside[1]
    assert _avg_channel_delta(top_inside, bottom_inside) >= 6.0


def test_android_photo_scene_prefers_inpaint_branch(monkeypatch) -> None:
    strategy = MixFillStrategy()
    image, item = _build_photo_scene()
    context = fill_strategies._build_fill_context(image, item)
    captured: dict[str, object] = {}

    def fake_inpaint(pil_image, items):
        captured["items"] = items
        return (pil_image, True)

    monkeypatch.setattr(fill_strategies, "_inpaint_shapes", fake_inpaint)

    assert strategy._classify_fill_mode(context) == "inpaint"

    filled, skip_fill = strategy.apply(image.copy(), _demo_plan(), [item])

    assert filled is not None
    assert skip_fill == [True]
    assert captured["items"] == [item]
