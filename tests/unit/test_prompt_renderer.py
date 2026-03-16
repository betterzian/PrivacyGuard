"""Prompt 渲染器测试。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer


def test_prompt_renderer_replaces_by_length_desc_order() -> None:
    """验证按长度倒序替换可避免短串误替换。"""
    renderer = PromptRenderer()
    plan = DecisionPlan(
        session_id="s1",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="c1",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.OTHER,
                source_text="13800138000",
                replacement_text="<PHONE>",
            ),
            DecisionAction(
                candidate_id="c2",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.OTHER,
                source_text="1380",
                replacement_text="<SHORT>",
            ),
        ],
    )

    sanitized, records = renderer.render_text("号码是13800138000", plan)

    assert sanitized == "号码是<PHONE>"
    assert len(records) == 2


def test_prompt_renderer_returns_applied_records() -> None:
    """验证渲染后返回可写入映射的记录。"""
    renderer = PromptRenderer()
    plan = DecisionPlan(
        session_id="s1",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="c1",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
                replacement_text="<NAME>",
                reason="test",
            )
        ],
    )

    sanitized, records = renderer.render_text("我是张三", plan)

    assert sanitized == "我是<NAME>"
    assert len(records) == 1
    assert records[0].source_text == "张三"
    assert records[0].replacement_text == "<NAME>"

