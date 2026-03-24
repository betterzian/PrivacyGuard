from __future__ import annotations

from typing import Any

from PIL import Image

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


def test_rule_based_detector_keeps_prompt_and_ocr_paths_wired() -> None:
    detector = RuleBasedPIIDetector()
    candidates = detector.detect(
        prompt_text="请联系 alice@example.com",
        ocr_blocks=[
            OCRTextBlock(
                text="13800138000",
                block_id="ocr-1",
                bbox=BoundingBox(x=0, y=0, width=100, height=20),
            )
        ],
    )

    observed = {
        (candidate.text, candidate.attr_type, candidate.source)
        for candidate in candidates
    }

    assert ("alice@example.com", PIIAttributeType.EMAIL, PIISourceType.PROMPT) in observed
    assert ("13800138000", PIIAttributeType.PHONE, PIISourceType.OCR) in observed


class FillStrategySpy:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def apply(self, image: Any, plan: DecisionPlan, draw_items: list[Any]) -> tuple[Any, list[bool]]:
        self.calls.append(
            {
                "image_size": getattr(image, "size", None),
                "plan_action_count": len(plan.actions),
                "draw_items": list(draw_items),
            }
        )
        return (image, [True] * len(draw_items))


def test_screenshot_renderer_builds_rewritten_draw_items(monkeypatch) -> None:
    fill_strategy = FillStrategySpy()
    renderer = ScreenshotRenderer(fill_strategy=fill_strategy)
    monkeypatch.setattr(renderer, "_draw_text_box", lambda *args, **kwargs: None)

    image = Image.new("RGB", (120, 40), color="white")
    plan = DecisionPlan(
        session_id="s1",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="c1",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.OCR,
                source_text="Alice",
                replacement_text="[NAME]",
                bbox=BoundingBox(x=0, y=0, width=100, height=20),
                block_id="ocr-1",
                span_start=5,
                span_end=10,
            )
        ],
    )
    ocr_blocks = [
        OCRTextBlock(
            text="call Alice",
            block_id="ocr-1",
            bbox=BoundingBox(x=0, y=0, width=100, height=20),
        )
    ]

    rendered = renderer.render(image=image, plan=plan, ocr_blocks=ocr_blocks)

    assert rendered.size == image.size
    assert rendered.mode == image.mode
    assert len(fill_strategy.calls) == 1
    call = fill_strategy.calls[0]
    assert call["image_size"] == (120, 40)
    assert call["plan_action_count"] == 1
    assert len(call["draw_items"]) == 1

    draw_item = call["draw_items"][0]
    assert draw_item.block_id == "ocr-1"
    assert draw_item.original_text == "call Alice"
    assert draw_item.text == "call [NAME]"
