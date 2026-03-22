"""JsonPersonaRepository 字段映射测试。"""

import json

import pytest
from pydantic import ValidationError

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.persona.json_persona_repository import (
    DEFAULT_PERSONA_REPOSITORY_PATH,
    DEFAULT_PERSONA_SAMPLE_PATH,
    InvalidPersonaRepositoryError,
    JsonPersonaRepository,
)


def test_json_persona_repository_loads_all_supported_non_other_slots(tmp_path) -> None:
    persona_path = tmp_path / "personas.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "fake_personas": [
                    {
                        "persona_id": "persona-all",
                        "slots": {
                            "name": {"value": "李四", "aliases": []},
                            "phone": {"value": "13900001111", "aliases": []},
                            "card_number": {"value": "4111111111111111", "aliases": []},
                            "bank_account": {"value": "6222020202020202020", "aliases": []},
                            "passport_number": {"value": "E12345678", "aliases": []},
                            "driver_license": {"value": "110101199001011234", "aliases": []},
                            "email": {"value": "lisi@example.com", "aliases": []},
                            "address": {
                                "street": {"value": "北京市海淀区知春路88号", "aliases": []},
                            },
                            "id_number": {"value": "110101199001011234", "aliases": []},
                            "organization": {"value": "星海数据科技有限公司", "aliases": []},
                        },
                        "stats": {"total": {"exposure_count": 0}},
                    }
                ],
            },
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


def test_json_persona_repository_loads_v2_fake_personas_and_renders_replacement_text(tmp_path) -> None:
    persona_path = tmp_path / "persona_repository.v2.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "fake_personas": [
                    {
                        "persona_id": "fake-1",
                        "display_name": "示例假身份",
                        "slots": {
                            "name": {"value": "李然", "aliases": ["李岚"]},
                            "location_clue": {"value": "天河区", "aliases": ["天河"]},
                            "address": {
                                "country": {"value": "中国", "aliases": []},
                                "province": {"value": "广东省", "aliases": []},
                                "city": {"value": "广州市", "aliases": []},
                                "district": {"value": "天河区", "aliases": []},
                                "street": {"value": "体育西路", "aliases": []},
                                "building": {"value": "2号楼", "aliases": []},
                                "room": {"value": "802室", "aliases": []},
                            },
                        },
                        "stats": {
                            "total": {
                                "exposure_count": 2,
                                "last_exposed_session_id": "session-1",
                                "last_exposed_turn_id": 7,
                            }
                        },
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository(path=str(persona_path))
    persona = repo.get_persona("fake-1")

    assert persona is not None
    assert persona.display_name == "示例假身份"
    assert persona.slots == {
        PIIAttributeType.NAME: "李然",
        PIIAttributeType.LOCATION_CLUE: "天河区",
        PIIAttributeType.ADDRESS: "广东省广州市天河区体育西路2号楼802室",
    }
    assert persona.stats == {
        "exposure_count": 2,
        "last_exposed_session_id": "session-1",
        "last_exposed_turn_id": 7,
    }
    assert repo.get_slot_value("fake-1", PIIAttributeType.NAME) == "李然"
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.NAME, "张三") in {"李然", "李岚"}
    assert (
        repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "四川省成都市武侯区")
        == "广东省广州市天河区"
    )
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "中国") == "中国"
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "中国四川省") == "中国广东省"
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "体育西路") == "体育西路"
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "2号楼802室") == "2号楼802室"


def test_json_persona_repository_reads_structured_v2_address_slots(tmp_path) -> None:
    persona_path = tmp_path / "personas.v2.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "fake_personas": [
                    {
                        "persona_id": "legacy-1",
                        "slots": {
                            "name": {"value": "张三", "aliases": ["张三三"]},
                            "address": {
                                "province": {"value": "上海市", "aliases": ["上海"]},
                                "city": {"value": "上海市", "aliases": ["上海"]},
                                "district": {"value": "浦东新区", "aliases": ["浦东"]},
                                "street": {"value": "世纪大道100号", "aliases": ["世纪大道"]},
                                "building": {"value": "1号楼", "aliases": ["一号楼"]},
                                "room": {"value": "101室", "aliases": ["101"]},
                            },
                        },
                        "stats": {"total": {"exposure_count": 1}},
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository(path=str(persona_path))

    assert repo.get_slot_value("legacy-1", PIIAttributeType.NAME) == "张三"
    assert repo.get_slot_value("legacy-1", PIIAttributeType.ADDRESS) == "上海市浦东新区世纪大道100号1号楼101室"
    assert repo.get_slot_replacement_text("legacy-1", PIIAttributeType.NAME, "李四") in {"张三", "张三三"}


def test_json_persona_repository_rejects_malformed_v2_payload(tmp_path) -> None:
    persona_path = tmp_path / "broken_persona_repository.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "personas": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises((ValidationError, InvalidPersonaRepositoryError)):
        JsonPersonaRepository(path=str(persona_path))


def test_json_persona_repository_rejects_non_object_root(tmp_path) -> None:
    persona_path = tmp_path / "array_root.json"
    persona_path.write_text(json.dumps([], ensure_ascii=False), encoding="utf-8")
    with pytest.raises(InvalidPersonaRepositoryError):
        JsonPersonaRepository(path=str(persona_path))


def test_json_persona_repository_upsert_preserves_existing_rich_v2_persona_fields(tmp_path) -> None:
    persona_path = tmp_path / "persona_repository.v2.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "fake_personas": [
                    {
                        "persona_id": "fake-1",
                        "display_name": "示例假身份",
                        "slots": {
                            "name": {"value": "李然", "aliases": ["李岚"]},
                            "address": {
                                "province": {"value": "广东省", "aliases": ["广东"]},
                                "city": {"value": "广州市", "aliases": ["广州"]},
                                "district": {"value": "天河区", "aliases": ["天河"]},
                                "street": {"value": "体育西路", "aliases": ["体西路"]},
                                "building": {"value": "2号楼", "aliases": ["二号楼"]},
                                "room": {"value": "802室", "aliases": ["802"]},
                            },
                        },
                        "stats": {
                            "total": {"exposure_count": 5},
                            "slots": {"name": {"exposure_count": 2}},
                            "address": {"levels": {"city": {"exposure_count": 3}}},
                        },
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository(path=str(persona_path))

    repo.upsert_persona(repo.get_persona("fake-1"))

    written = json.loads(persona_path.read_text(encoding="utf-8"))
    persona = written["fake_personas"][0]

    assert written["version"] == 2
    assert persona["slots"]["name"] == {"value": "李然", "aliases": ["李岚"]}
    assert persona["slots"]["address"]["city"] == {"value": "广州市", "aliases": ["广州"]}
    assert persona["slots"]["address"]["street"] == {"value": "体育西路", "aliases": ["体西路"]}
    assert persona["slots"]["address"]["building"] == {"value": "2号楼", "aliases": ["二号楼"]}
    assert persona["slots"]["address"]["room"] == {"value": "802室", "aliases": ["802"]}
    assert persona["stats"]["total"]["exposure_count"] == 5
    assert persona["stats"]["slots"]["name"]["exposure_count"] == 2
    assert persona["stats"]["address"]["levels"]["city"]["exposure_count"] == 3


def test_json_persona_repository_country_fragment_without_stored_country_does_not_expand_to_full_address(tmp_path) -> None:
    persona_path = tmp_path / "persona_repository.v2.json"
    persona_path.write_text(
        json.dumps(
            {
                "version": 2,
                "fake_personas": [
                    {
                        "persona_id": "fake-1",
                        "slots": {
                            "address": {
                                "province": {"value": "广东省", "aliases": []},
                                "city": {"value": "广州市", "aliases": []},
                                "district": {"value": "天河区", "aliases": []},
                                "street": {"value": "体育西路", "aliases": []},
                                "building": {"value": "2号楼", "aliases": []},
                                "room": {"value": "802室", "aliases": []},
                            }
                        },
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repo = JsonPersonaRepository(path=str(persona_path))

    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "中国") == "广东省"
    assert repo.get_slot_replacement_text("fake-1", PIIAttributeType.ADDRESS, "中国四川省") == "广东省"


def test_json_persona_repository_reads_sample_but_flushes_to_local_repo(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / DEFAULT_PERSONA_SAMPLE_PATH
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_doc = {
        "version": 2,
        "fake_personas": [
            {
                "persona_id": "sample-persona",
                "slots": {
                    "name": {"value": "样例用户", "aliases": []},
                },
                "stats": {"total": {"exposure_count": 0}},
            }
        ],
    }
    sample_path.write_text(json.dumps(sample_doc, ensure_ascii=False), encoding="utf-8")

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
    assert json.loads(sample_path.read_text(encoding="utf-8")) == sample_doc
    local_payload = json.loads(local_repo_path.read_text(encoding="utf-8"))
    assert local_payload["version"] == 2
    assert [item["persona_id"] for item in local_payload["fake_personas"]] == [
        "sample-persona",
        "local-persona",
    ]
    assert local_payload["fake_personas"][1]["slots"]["phone"]["value"] == "13800138000"

    reloaded = JsonPersonaRepository()
    assert reloaded.get_persona("sample-persona") is not None
    assert reloaded.get_slot_value("local-persona", PIIAttributeType.PHONE) == "13800138000"
