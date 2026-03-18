"""截图渲染器在 OCR 同框局部替换场景下的测试。"""

from PIL import Image, ImageDraw

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
import pytest

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


def test_screenshot_renderer_rebuilds_full_block_text_for_partial_ocr_replacement() -> None:
    renderer = ScreenshotRenderer()
    ocr_blocks = [
        OCRTextBlock(
            text="张三出去吃东西了",
            bbox=BoundingBox(x=1, y=1, width=10, height=50),
            block_id="ocr-box-1",
        )
    ]
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-1",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="李四",
                bbox=BoundingBox(x=1, y=1, width=10, height=50),
                block_id="ocr-box-1",
                span_start=0,
                span_end=2,
                reason="test",
            )
        ],
    )

    draw_items = renderer._build_draw_items(plan, ocr_blocks=ocr_blocks)

    assert len(draw_items) == 1
    assert draw_items[0].bbox == BoundingBox(x=1, y=1, width=10, height=50)
    assert draw_items[0].text == "李四出去吃东西了"


def test_screenshot_renderer_falls_back_to_legacy_draw_item_without_span() -> None:
    renderer = ScreenshotRenderer()
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-legacy",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="李四",
                bbox=BoundingBox(x=2, y=2, width=20, height=20),
                reason="legacy",
            )
        ],
    )

    draw_items = renderer._build_draw_items(plan, ocr_blocks=[])

    assert len(draw_items) == 1
    assert draw_items[0].text == "李四"


def test_screenshot_renderer_recovers_from_incorrect_span_using_source_text() -> None:
    renderer = ScreenshotRenderer()
    ocr_blocks = [
        OCRTextBlock(
            text="张三出去吃东西了",
            bbox=BoundingBox(x=1, y=1, width=10, height=50),
            block_id="ocr-box-2",
        )
    ]
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-invalid",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="王五",
                bbox=BoundingBox(x=1, y=1, width=10, height=50),
                block_id="ocr-box-2",
                span_start=4,
                span_end=6,
                reason="invalid-span",
            )
        ],
    )

    draw_items = renderer._build_draw_items(plan, ocr_blocks=ocr_blocks)

    assert len(draw_items) == 1
    assert draw_items[0].bbox == BoundingBox(x=1, y=1, width=10, height=50)
    assert draw_items[0].text == "王五出去吃东西了"


def test_screenshot_renderer_skips_duplicate_legacy_draw_for_grouped_block() -> None:
    renderer = ScreenshotRenderer()
    ocr_blocks = [
        OCRTextBlock(
            text="张三出去吃东西了",
            bbox=BoundingBox(x=1, y=1, width=10, height=50),
            block_id="ocr-box-3",
        )
    ]
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-span",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="李四",
                bbox=BoundingBox(x=1, y=1, width=10, height=50),
                block_id="ocr-box-3",
                span_start=0,
                span_end=2,
                reason="span",
            ),
            DecisionAction(
                candidate_id="cand-legacy",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="@姓名1",
                bbox=BoundingBox(x=1, y=1, width=10, height=50),
                block_id="ocr-box-3",
                reason="legacy-same-block",
            ),
        ],
    )

    draw_items = renderer._build_draw_items(plan, ocr_blocks=ocr_blocks)

    assert len(draw_items) == 1
    assert draw_items[0].block_id == "ocr-box-3"
    assert draw_items[0].text == "李四出去吃东西了"


def test_screenshot_renderer_keeps_full_text_when_layout_needs_adaptation() -> None:
    renderer = ScreenshotRenderer()
    image = Image.new("RGB", (200, 80), "white")
    draw = ImageDraw.Draw(image)

    layout = renderer._resolve_text_layout(
        draw=draw,
        bbox=BoundingBox(x=0, y=0, width=72, height=26),
        text="李四出去吃东西了今天晚上还要去超市",
        original_text="张三出去吃东西了",
    )

    assert layout is not None
    assert layout.rendered_text.replace("\n", "") == "李四出去吃东西了今天晚上还要去超市"
    assert layout.mask.size[0] <= 68
    assert layout.mask.size[1] <= 22
    assert layout.scale_y == 1.0


def test_screenshot_renderer_expands_shorter_text_with_char_spacing() -> None:
    renderer = ScreenshotRenderer()
    image = Image.new("RGB", (240, 80), "white")
    draw = ImageDraw.Draw(image)

    layout = renderer._resolve_text_layout(
        draw=draw,
        bbox=BoundingBox(x=0, y=0, width=96, height=30),
        text="李四",
        original_text="张三出去吃东西了",
    )

    assert layout is not None
    assert layout.rendered_text == "李四"
    assert layout.char_spacing > 0
    assert layout.scale_x == 1.0
    assert layout.scale_y == 1.0


def test_screenshot_renderer_uses_polygon_geometry_for_rotated_blocks() -> None:
    renderer = ScreenshotRenderer()
    draw_item = renderer._build_draw_items(
        DecisionPlan(
            session_id="demo",
            turn_id=1,
            actions=[
                DecisionAction(
                    candidate_id="cand-rotated",
                    action_type=ActionType.GENERICIZE,
                    attr_type=PIIAttributeType.NAME,
                    source_text="张三",
                    replacement_text="李四",
                    bbox=BoundingBox(x=8, y=10, width=42, height=22),
                    block_id="ocr-rotated",
                    span_start=0,
                    span_end=2,
                    reason="rotated",
                )
            ],
        ),
        ocr_blocks=[
            OCRTextBlock(
                text="张三",
                bbox=BoundingBox(x=8, y=10, width=42, height=22),
                block_id="ocr-rotated",
                polygon=[
                    PolygonPoint(x=10.0, y=10.0),
                    PolygonPoint(x=50.0, y=20.0),
                    PolygonPoint(x=48.0, y=32.0),
                    PolygonPoint(x=8.0, y=22.0),
                ],
                rotation_degrees=14.036243467926479,
            )
        ],
    )[0]

    center_x, center_y, target_w, target_h, rotation_degrees = renderer._text_region_geometry(draw_item)

    assert draw_item.text == "李四"
    assert center_x == pytest.approx(29.0)
    assert center_y == pytest.approx(21.0)
    assert target_w == 37
    assert target_h == 8
    assert rotation_degrees == pytest.approx(14.036243467926479)
