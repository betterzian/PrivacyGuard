"""JsonPersonaRepository 字段映射测试。"""

import json

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.persona.json_persona_repository import (
    DEFAULT_PERSONA_REPOSITORY_PATH,
    DEFAULT_PERSONA_SAMPLE_PATH,
    JsonPersonaRepository,
)


def test_json_persona_repository_loads_all_supported_non_other_slots(tmp_path) -> None:
    persona_path = tmp_path / "personas.json"
    persona_path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "persona-all",
                    "slots": {
                        "name": "李四",
                        "phone": "13900001111",
                        "card_number": "4111111111111111",
                        "bank_account": "6222020202020202020",
                        "passport_number": "E12345678",
                        "driver_license": "110101199001011234",
                        "email": "lisi@example.com",
                        "address": "北京市海淀区知春路88号",
                        "id_number": "110101199001011234",
                        "organization": "星海数据科技有限公司",
                    },
                    "stats": {"exposure_count": 0},
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository(path=str(persona_path))
    persona = repo.get_persona("persona-all")

    assert persona is not None
    assert persona.slots == {
        PIIAttributeType.NAME: "李四",
        PIIAttributeType.PHONE: "13900001111",
        PIIAttributeType.CARD_NUMBER: "4111111111111111",
        PIIAttributeType.BANK_ACCOUNT: "6222020202020202020",
        PIIAttributeType.PASSPORT_NUMBER: "E12345678",
        PIIAttributeType.DRIVER_LICENSE: "110101199001011234",
        PIIAttributeType.EMAIL: "lisi@example.com",
        PIIAttributeType.ADDRESS: "北京市海淀区知春路88号",
        PIIAttributeType.ID_NUMBER: "110101199001011234",
        PIIAttributeType.ORGANIZATION: "星海数据科技有限公司",
    }


def test_json_persona_repository_reads_sample_but_flushes_to_local_repo(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / DEFAULT_PERSONA_SAMPLE_PATH
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "sample-persona",
                    "slots": {
                        "name": "样例用户",
                    },
                    "stats": {
                        "exposure_count": 0,
                    },
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository()
    assert repo.get_persona("sample-persona") is not None

    repo.upsert_persona(
        PersonaProfile(
            persona_id="local-persona",
            display_name="本地主身份",
            slots={
                PIIAttributeType.NAME: "张三",
                PIIAttributeType.PHONE: "13800138000",
            },
            stats={"exposure_count": 1},
        )
    )

    local_repo_path = tmp_path / DEFAULT_PERSONA_REPOSITORY_PATH
    assert local_repo_path.exists()
    assert json.loads(sample_path.read_text(encoding="utf-8")) == [
        {
            "persona_id": "sample-persona",
            "slots": {
                "name": "样例用户",
            },
            "stats": {
                "exposure_count": 0,
            },
        }
    ]

    reloaded = JsonPersonaRepository()
    assert reloaded.get_persona("sample-persona") is not None
    assert reloaded.get_slot_value("local-persona", PIIAttributeType.PHONE) == "13800138000"
