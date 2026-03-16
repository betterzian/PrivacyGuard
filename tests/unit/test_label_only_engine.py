"""LabelOnly 决策引擎测试。"""

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.label_only_engine import LabelOnlyDecisionEngine


def _candidate(entity_id: str, attr_type: PIIAttributeType, text: str, confidence: float = 0.9) -> PIICandidate:
    """创建测试候选实体。"""
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        normalized_text=text.lower(),
        attr_type=attr_type,
        source=PIISourceType.PROMPT,
        bbox=BoundingBox(x=0, y=0, width=10, height=10),
        confidence=confidence,
        detector_mode="rule_based",
    )


def test_label_only_replaces_all_sensitive_with_standard_labels() -> None:
    """验证敏感字段可替换为标准标签。"""
    engine = LabelOnlyDecisionEngine(confidence_threshold=0.0)
    candidates = [
        _candidate("c1", PIIAttributeType.NAME, "张三"),
        _candidate("c2", PIIAttributeType.PHONE, "13800138000"),
        _candidate("c3", PIIAttributeType.EMAIL, "demo@example.com"),
    ]

    plan = engine.plan(session_id="s1", turn_id=1, candidates=candidates, session_binding=None)
    replacements = {action.attr_type: action.replacement_text for action in plan.actions}

    assert replacements[PIIAttributeType.NAME] == "<NAME>"
    assert replacements[PIIAttributeType.PHONE] == "<PHONE>"
    assert replacements[PIIAttributeType.EMAIL] == "<EMAIL>"


def test_label_only_label_format_is_consistent() -> None:
    """验证相同 attr_type 的标签格式保持一致。"""
    engine = LabelOnlyDecisionEngine(confidence_threshold=0.0)
    candidates = [
        _candidate("c1", PIIAttributeType.NAME, "张三"),
        _candidate("c2", PIIAttributeType.NAME, "李四"),
    ]
    plan = engine.plan(session_id="s1", turn_id=2, candidates=candidates, session_binding=SessionBinding(session_id="s1"))
    tags = {action.replacement_text for action in plan.actions}
    assert tags == {"<NAME>"}

