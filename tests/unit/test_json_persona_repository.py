"""JSON Persona 仓库测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


def _write_personas(tmp_path: Path) -> Path:
    """写入测试用 persona 文件。"""
    path = tmp_path / "personas.sample.json"
    path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "zhangsan",
                    "profile": {
                        "name": "张三",
                        "phone": "13900001111",
                        "address": "上海市浦东新区世纪大道100号",
                        "email": "zhangsan@example.com",
                    },
                    "stats": {
                        "exposure_count": 1,
                        "last_exposed_session_id": "s1",
                        "last_exposed_turn_id": 2,
                    },
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def test_json_persona_repository_can_load_file(tmp_path: Path) -> None:
    """验证可加载样例 persona 文件。"""
    repo = JsonPersonaRepository(path=str(_write_personas(tmp_path)))
    personas = repo.list_personas()
    assert len(personas) == 1
    assert personas[0].persona_id == "zhangsan"


def test_json_persona_repository_can_read_slot_value(tmp_path: Path) -> None:
    """验证可按 persona 与 attr_type 读取槽位。"""
    repo = JsonPersonaRepository(path=str(_write_personas(tmp_path)))
    phone = repo.get_slot_value("zhangsan", PIIAttributeType.PHONE)
    assert phone == "13900001111"


def test_json_persona_repository_handles_missing_key(tmp_path: Path) -> None:
    """验证不存在的 persona 或槽位返回空值。"""
    repo = JsonPersonaRepository(path=str(_write_personas(tmp_path)))
    assert repo.get_persona("nobody") is None
    assert repo.get_slot_value("zhangsan", PIIAttributeType.ID_NUMBER) is None

