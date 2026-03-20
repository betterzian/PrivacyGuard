"""本地隐私仓库写入入口测试。"""

import json
import os

from privacyguard import PrivacyGuard, PrivacyRepository
from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.persona.json_persona_repository import (
    DEFAULT_PERSONA_REPOSITORY_PATH,
    DEFAULT_PERSONA_SAMPLE_PATH,
    JsonPersonaRepository,
)


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


def test_privacy_repository_write_merges_updates_and_guard_reads_existing_repo(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    repository = PrivacyRepository()

    first_write = repository.write(
        {
            "personas": [
                {
                    "persona_id": "owner",
                    "display_name": "主身份",
                    "slots": {
                        "name": "张三",
                        "phone": "13800138000",
                    },
                    "metadata": {
                        "source": "crm",
                    },
                    "stats": {
                        "exposure_count": 1,
                    },
                }
            ]
        }
    )
    second_write = repository.write(
        {
            "personas": [
                {
                    "persona_id": "owner",
                    "slots": {
                        "email": "zhangsan@example.com",
                    },
                    "metadata": {
                        "department": "sales",
                    },
                    "stats": {
                        "last_exposed_session_id": "session-9",
                        "last_exposed_turn_id": 3,
                    },
                }
            ]
        }
    )

    assert first_write["status"] == "ok"
    assert os.path.normpath(second_write["repository_path"]) == os.path.normpath(DEFAULT_PERSONA_REPOSITORY_PATH)
    stored_payload = json.loads((tmp_path / DEFAULT_PERSONA_REPOSITORY_PATH).read_text(encoding="utf-8"))
    assert stored_payload[0]["persona_id"] == "owner"
    assert stored_payload[0]["slots"] == {
        "name": "张三",
        "phone": "13800138000",
        "email": "zhangsan@example.com",
    }
    assert stored_payload[0]["metadata"] == {
        "source": "crm",
        "department": "sales",
    }

    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
    persona = guard.persona_repo.get_persona("owner")

    assert persona is not None
    assert persona.display_name == "主身份"
    assert persona.slots == {
        PIIAttributeType.NAME: "张三",
        PIIAttributeType.PHONE: "13800138000",
        PIIAttributeType.EMAIL: "zhangsan@example.com",
    }
    assert persona.metadata == {
        "source": "crm",
        "department": "sales",
    }
    assert persona.stats == {
        "exposure_count": 1,
        "last_exposed_session_id": "session-9",
        "last_exposed_turn_id": 3,
    }
