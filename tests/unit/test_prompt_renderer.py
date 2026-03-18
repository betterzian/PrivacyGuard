"""PromptRenderer 的 span 优先渲染测试。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer


def test_prompt_renderer_replaces_duplicate_prompt_tokens_by_span() -> None:
    renderer = PromptRenderer()
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-1",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                source_text="张三",
                replacement_text="李四",
                span_start=0,
                span_end=2,
                reason="first",
            ),
            DecisionAction(
                candidate_id="cand-2",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                source_text="张三",
                replacement_text="王五",
                span_start=3,
                span_end=5,
                reason="second",
            ),
        ],
    )

    sanitized, records = renderer.render_text("张三和张三", plan)

    assert sanitized == "李四和王五"
    assert all(record.source == PIISourceType.PROMPT for record in records)


def test_prompt_renderer_ignores_ocr_actions_when_rendering_prompt_text() -> None:
    renderer = PromptRenderer()
    plan = DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-ocr",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.OCR,
                source_text="张三",
                replacement_text="李四",
                bbox=BoundingBox(x=1, y=1, width=10, height=10),
                block_id="ocr-1",
                span_start=0,
                span_end=2,
                reason="ocr-only",
            ),
        ],
    )

    sanitized, records = renderer.render_text("请把资料发给张三", plan)

    assert sanitized == "请把资料发给张三"
    assert len(records) == 1
    assert records[0].source == PIISourceType.OCR
