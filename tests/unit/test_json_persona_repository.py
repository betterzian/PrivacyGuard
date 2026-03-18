"""JsonPersonaRepository 字段映射测试。"""

import json

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


def test_json_persona_repository_loads_all_supported_non_other_slots(tmp_path) -> None:
    persona_path = tmp_path / "personas.json"
    persona_path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "persona-all",
                    "profile": {
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
