"""In-Memory Mapping Store 测试。"""

import pytest

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore


def _record(session_id: str, turn_id: int, candidate_id: str, action_type: ActionType = ActionType.GENERICIZE) -> ReplacementRecord:
    """创建测试替换记录。"""
    return ReplacementRecord(
        session_id=session_id,
        turn_id=turn_id,
        candidate_id=candidate_id,
        source_text="张三",
        replacement_text="[NAME]",
        attr_type=PIIAttributeType.NAME,
        action_type=action_type,
        persona_id="zhangsan" if action_type == ActionType.PERSONA_SLOT else None,
        source=PIISourceType.PROMPT,
    )


def test_mapping_store_save_and_query_by_session_turn() -> None:
    """验证可保存并按 session/turn 读回记录。"""
    store = InMemoryMappingStore()
    store.save_replacements("s1", 1, [_record("s1", 1, "c1"), _record("s1", 1, "c2")])
    assert len(store.get_replacements("s1", 1)) == 2
    assert len(store.get_replacements("s1")) == 2


def test_mapping_store_save_and_get_session_binding() -> None:
    """验证可保存并读取 session binding。"""
    store = InMemoryMappingStore()
    binding = SessionBinding(session_id="s1", active_persona_id="zhangsan")
    store.set_session_binding(binding)
    loaded = store.get_session_binding("s1")
    assert loaded is not None
    assert loaded.active_persona_id == "zhangsan"


def test_mapping_store_rejects_persona_slot_without_persona_id() -> None:
    """验证 PERSONA_SLOT 缺失 persona_id 时拒绝写入。"""
    store = InMemoryMappingStore()
    bad = _record("s1", 1, "c1", action_type=ActionType.PERSONA_SLOT)
    bad.persona_id = None
    with pytest.raises(ValueError):
        store.save_replacements("s1", 1, [bad])


def test_mapping_store_deduplicates_same_candidate() -> None:
    """验证同 session+turn+candidate 写入时按 candidate 覆盖去重。"""
    store = InMemoryMappingStore()
    first = _record("s1", 1, "c1")
    second = _record("s1", 1, "c1")
    second.replacement_text = "[NAME_2]"
    store.save_replacements("s1", 1, [first, second])
    records = store.get_replacements("s1", 1)
    assert len(records) == 1
    assert records[0].replacement_text == "[NAME_2]"

