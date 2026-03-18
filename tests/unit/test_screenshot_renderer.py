"""截图渲染器在 OCR 同框局部替换场景下的测试。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
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
