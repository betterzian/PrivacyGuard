"""SessionService 测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.application.services.session_service import SessionService


def _write_personas(tmp_path: Path) -> Path:
    """创建测试 persona 文件。"""
    path = tmp_path / "personas.sample.json"
    path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "zhangsan",
                    "profile": {"name": "张三", "phone": "13900001111"},
                    "stats": {"exposure_count": 0, "last_exposed_session_id": None, "last_exposed_turn_id": None},
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def _record() -> ReplacementRecord:
    """创建测试替换记录。"""
    return ReplacementRecord(
        session_id="s1",
        turn_id=1,
        candidate_id="c1",
        source_text="张三",
        replacement_text="[NAME]",
        attr_type=PIIAttributeType.NAME,
        action_type=ActionType.GENERICIZE,
        source=PIISourceType.PROMPT,
    )


def test_session_service_can_create_binding(tmp_path: Path) -> None:
    """验证可创建默认会话绑定。"""
    service = SessionService(
        mapping_store=InMemoryMappingStore(),
        persona_repository=JsonPersonaRepository(path=str(_write_personas(tmp_path))),
    )
    binding = service.get_or_create_binding("s1")
    assert binding.session_id == "s1"
    assert binding.active_persona_id is None


def test_session_service_can_bind_active_persona(tmp_path: Path) -> None:
    """验证可绑定 active persona。"""
    service = SessionService(
        mapping_store=InMemoryMappingStore(),
        persona_repository=JsonPersonaRepository(path=str(_write_personas(tmp_path))),
    )
    binding = service.bind_active_persona("s1", "zhangsan", turn_id=2)
    assert binding.active_persona_id == "zhangsan"
    assert binding.last_turn_id == 2


def test_session_service_can_append_turn_replacements(tmp_path: Path) -> None:
    """验证可追加某轮替换记录。"""
    store = InMemoryMappingStore()
    service = SessionService(
        mapping_store=store,
        persona_repository=JsonPersonaRepository(path=str(_write_personas(tmp_path))),
    )
    service.append_turn_replacements("s1", 1, [_record()])
    records = store.get_replacements("s1", 1)
    assert len(records) == 1
    assert records[0].candidate_id == "c1"

