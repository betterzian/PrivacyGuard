"""动作还原模块测试。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.infrastructure.restoration.action_restorer import ActionRestorer


def _record(turn_id: int, source_text: str, replacement_text: str) -> ReplacementRecord:
    """构造测试替换记录。"""
    return ReplacementRecord(
        session_id="s1",
        turn_id=turn_id,
        candidate_id=f"c{turn_id}",
        source_text=source_text,
        replacement_text=replacement_text,
        attr_type=PIIAttributeType.NAME,
        action_type=ActionType.GENERICIZE,
        source=PIISourceType.PROMPT,
    )


def test_action_restorer_restores_with_recent_turn_priority() -> None:
    """验证恢复时更近 turn 记录优先。"""
    restorer = ActionRestorer()
    old_record = _record(turn_id=1, source_text="张三", replacement_text="<NAME>")
    new_record = _record(turn_id=2, source_text="李四", replacement_text="<NAME>")

    restored_text, restored_slots = restorer.restore("你好 <NAME>", [old_record, new_record])

    assert restored_text == "你好 李四"
    assert restored_slots[0].value == "李四"


def test_action_restorer_keeps_text_when_mapping_missing() -> None:
    """验证找不到映射时保持原文本。"""
    restorer = ActionRestorer()
    record = _record(turn_id=1, source_text="张三", replacement_text="<NAME>")

    restored_text, restored_slots = restorer.restore("无占位文本", [record])

    assert restored_text == "无占位文本"
    assert restored_slots == []

