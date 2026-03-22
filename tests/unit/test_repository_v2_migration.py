"""Legacy repository to v2 migration tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from privacyguard.infrastructure.repository.migration_v2 import migrate_legacy_repository
from privacyguard.infrastructure.repository.schemas_v2 import (
    PersonaRepositoryDocumentV2,
    PrivacyRepositoryDocumentV2,
)


@pytest.mark.parametrize(
    "payload",
    [
        [
            {
                "persona_id": "fake-1",
                "display_name": "示例假身份",
                "slots": {
                    "name": "李四",
                    "phone": {"value": "13900001111", "aliases": ["13900001112"]},
                    "address": {
                        "country": "中国",
                        "city": {"value": "北京市", "aliases": ["北京"]},
                        "street": "知春路88号",
                        "detail": "1号楼101室",
                    },
                },
                "stats": {
                    "exposure_count": 5,
                    "last_exposed_session_time": "2026-03-21 10:00:00",
                    "last_exposed_session_id": "session-1",
                    "last_exposed_turn_id": 7,
                    "name_exposure_count": 2,
                    "address_exposure_count": 3,
                },
            }
        ],
        {
            "personas": [
                {
                    "persona_id": "fake-1",
                    "display_name": "示例假身份",
                    "slots": {
                        "name": "李四",
                        "phone": {"value": "13900001111", "aliases": ["13900001112"]},
                        "address": {
                            "country": "中国",
                            "city": {"value": "北京市", "aliases": ["北京"]},
                            "street": "知春路88号",
                            "detail": "1号楼101室",
                        },
                    },
                    "stats": {
                        "exposure_count": 5,
                        "last_exposed_session_time": "2026-03-21 10:00:00",
                        "last_exposed_session_id": "session-1",
                        "last_exposed_turn_id": 7,
                        "name_exposure_count": 2,
                        "address_exposure_count": 3,
                    },
                }
            ]
        },
    ],
)
def test_migrate_legacy_persona_payloads_to_v2_persona_repository_document(payload) -> None:
    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PersonaRepositoryDocumentV2)
    assert migrated.version == 2
    assert len(migrated.fake_personas) == 1

    persona = migrated.fake_personas[0]
    assert persona.persona_id == "fake-1"
    assert persona.display_name == "示例假身份"
    assert persona.slots.name.model_dump() == {"value": "李四", "aliases": []}
    assert persona.slots.phone.model_dump() == {
        "value": "13900001111",
        "aliases": ["13900001112"],
    }
    assert persona.slots.address.country.model_dump() == {"value": "中国", "aliases": []}
    assert persona.slots.address.city.model_dump() == {"value": "北京市", "aliases": ["北京"]}
    assert persona.slots.address.street.model_dump() == {"value": "知春路88号", "aliases": []}
    assert persona.slots.address.building.model_dump() == {"value": "1号楼", "aliases": []}
    assert persona.slots.address.room.model_dump() == {"value": "101室", "aliases": []}
    assert persona.stats.total.exposure_count == 5
    assert persona.stats.total.last_exposed_session_id == "session-1"
    assert persona.stats.total.last_exposed_turn_id == 7
    assert persona.stats.total.last_exposed_at.isoformat() == "2026-03-21T10:00:00"
    assert persona.stats.slots.name.exposure_count == 2
    assert persona.stats.slots.address.total.exposure_count == 3
    assert persona.stats.address.total.exposure_count == 3
    assert migrated.stats.total.exposure_count == 5
    assert migrated.stats.personas.total.exposure_count == 5
    assert migrated.stats.slots.name.exposure_count == 2
    assert migrated.stats.address.total.exposure_count == 3


def test_migrate_privacy_entities_to_v2_privacy_repository_document() -> None:
    payload = {
        "entities": [
            {
                "entity_id": "entity-1",
                "name": ["张三", "老张"],
                "email": "zhangsan@example.com",
                "address": [
                    {
                        "city": {"value": "上海市", "aliases": ["上海"]},
                        "street": "世纪大道100号",
                        "detail": "1号楼101室",
                    }
                ],
                "stats": {
                    "exposure_count": 4,
                    "email_exposure_count": 1,
                    "address_exposure_count": 2,
                },
            },
            {
                "id": "entity-2",
                "phone": ["13900001111", "13900001112"],
                "organization": ["星海数科有限公司"],
            },
        ]
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert migrated.version == 2
    assert [persona.persona_id for persona in migrated.true_personas] == ["entity-1", "entity-2"]
    assert migrated.true_personas[0].slots.name.model_dump() == {
        "value": "张三",
        "aliases": ["老张"],
    }
    assert migrated.true_personas[0].slots.email.model_dump() == {
        "value": "zhangsan@example.com",
        "aliases": [],
    }
    assert migrated.true_personas[0].slots.address.city.model_dump() == {
        "value": "上海市",
        "aliases": ["上海"],
    }
    assert migrated.true_personas[0].slots.address.building.model_dump() == {
        "value": "1号楼",
        "aliases": [],
    }
    assert migrated.true_personas[0].slots.address.room.model_dump() == {
        "value": "101室",
        "aliases": [],
    }
    assert migrated.true_personas[1].slots.phone.model_dump() == {
        "value": "13900001111",
        "aliases": ["13900001112"],
    }
    assert migrated.stats.total.exposure_count == 4
    assert migrated.stats.slots.email.exposure_count == 1
    assert migrated.stats.address.total.exposure_count == 2


def test_migrate_flat_privacy_dict_defaults_to_safe_unlinked() -> None:
    payload = {
        "name": ["张三", "李四"],
        "phone": ["13900001111"],
        "address": [
            {"street": "知春路88号", "detail": "101室"},
            "上海市浦东新区世纪大道100号",
        ],
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert len(migrated.true_personas) == 5
    assert len({persona.persona_id for persona in migrated.true_personas}) == 5

    source_slots = [persona.metadata["legacy_source_slot"] for persona in migrated.true_personas]
    assert source_slots.count("name") == 2
    assert source_slots.count("phone") == 1
    assert source_slots.count("address") == 2

    for persona in migrated.true_personas:
        populated = [name for name, value in persona.slots.model_dump(exclude_none=True).items() if value]
        assert len(populated) == 1

    structured_address = next(
        persona for persona in migrated.true_personas if persona.metadata["legacy_source_slot"] == "address"
    )
    assert structured_address.slots.address.street.model_dump() == {
        "value": "知春路88号",
        "aliases": [],
    }
    assert structured_address.slots.address.building.model_dump() == {
        "value": "101室",
        "aliases": [],
    }
    assert structured_address.slots.address.room is None

    scalar_address = next(
        persona
        for persona in migrated.true_personas
        if persona.metadata["legacy_source_slot"] == "address" and persona.slots.address.street.value.startswith("上海市")
    )
    assert scalar_address.slots.address.street.model_dump() == {
        "value": "上海市浦东新区世纪大道100号",
        "aliases": [],
    }


def test_migrate_flat_privacy_dict_with_explicit_link_by_index() -> None:
    payload = {
        "name": ["张三", "李四"],
        "phone": ["13900001111", "13800002222"],
        "address": ["北京市海淀区知春路88号", "上海市浦东新区世纪大道100号"],
    }

    migrated = migrate_legacy_repository(payload, privacy_mode="link_by_index")

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert len(migrated.true_personas) == 2
    assert migrated.true_personas[0].slots.name.value == "张三"
    assert migrated.true_personas[0].slots.phone.value == "13900001111"
    assert migrated.true_personas[0].slots.address.street.value == "北京市海淀区知春路88号"
    assert migrated.true_personas[1].slots.name.value == "李四"
    assert migrated.true_personas[1].slots.phone.value == "13800002222"
    assert migrated.true_personas[1].slots.address.street.value == "上海市浦东新区世纪大道100号"


def test_zero_count_slot_stats_do_not_inherit_legacy_exposure_timestamps() -> None:
    payload = [
        {
            "persona_id": "fake-1",
            "slots": {
                "name": "李四",
                "phone": "13900001111",
            },
            "stats": {
                "exposure_count": 5,
                "last_exposed_session_time": "2026-03-21 10:00:00",
                "last_exposed_session_id": "session-1",
                "last_exposed_turn_id": 7,
                "name_exposure_count": 0,
                "phone_exposure_count": 2,
            },
        }
    ]

    migrated = migrate_legacy_repository(payload)

    name_stats = migrated.fake_personas[0].stats.slots.name
    phone_stats = migrated.fake_personas[0].stats.slots.phone

    assert name_stats.exposure_count == 0
    assert name_stats.last_exposed_at is None
    assert name_stats.last_exposed_session_id is None
    assert name_stats.last_exposed_turn_id is None
    assert phone_stats.exposure_count == 2
    assert phone_stats.last_exposed_at.isoformat() == "2026-03-21T10:00:00"
    assert migrated.stats.slots.name.last_exposed_at is None
    assert migrated.stats.slots.name.last_exposed_session_id is None
    assert migrated.stats.slots.name.last_exposed_turn_id is None


def test_flat_privacy_migration_ignores_sparse_placeholder_values() -> None:
    payload = {
        "name": ["Alice", None, ""],
        "address": [None, "Main St", "   "],
    }

    safe_unlinked = migrate_legacy_repository(payload)
    linked = migrate_legacy_repository(payload, privacy_mode="link_by_index")

    assert isinstance(safe_unlinked, PrivacyRepositoryDocumentV2)
    assert len(safe_unlinked.true_personas) == 2
    assert [persona.metadata["legacy_source_slot"] for persona in safe_unlinked.true_personas] == [
        "name",
        "address",
    ]
    assert safe_unlinked.true_personas[0].slots.name.value == "Alice"
    assert safe_unlinked.true_personas[1].slots.address.street.value == "Main St"

    assert isinstance(linked, PrivacyRepositoryDocumentV2)
    assert len(linked.true_personas) == 2
    assert linked.true_personas[0].slots.name.value == "Alice"
    assert linked.true_personas[0].slots.address is None
    assert linked.true_personas[1].slots.name is None
    assert linked.true_personas[1].slots.address.street.value == "Main St"


def test_link_by_index_preserves_original_sparse_indexes() -> None:
    payload = {
        "name": ["Alice", None, "Bob"],
        "phone": ["111", "222", "333"],
    }

    migrated = migrate_legacy_repository(payload, privacy_mode="link_by_index")

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert len(migrated.true_personas) == 3
    assert migrated.true_personas[0].slots.name.value == "Alice"
    assert migrated.true_personas[0].slots.phone.value == "111"
    assert migrated.true_personas[1].slots.name is None
    assert migrated.true_personas[1].slots.phone.value == "222"
    assert migrated.true_personas[2].slots.name.value == "Bob"
    assert migrated.true_personas[2].slots.phone.value == "333"


def test_flat_privacy_migration_normalizes_legacy_slot_keys_with_whitespace() -> None:
    payload = {
        "name ": ["Alice"],
        " phone": ["111"],
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert len(migrated.true_personas) == 2
    assert migrated.true_personas[0].slots.name.value == "Alice"
    assert migrated.true_personas[1].slots.phone.value == "111"


def test_flat_privacy_migration_merges_colliding_normalized_slot_keys() -> None:
    payload = {
        "name": ["Alice"],
        " name ": ["Bob"],
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    assert len(migrated.true_personas) == 2
    assert migrated.true_personas[0].slots.name.value == "Alice"
    assert migrated.true_personas[1].slots.name.value == "Bob"


def test_persona_slot_migration_merges_colliding_normalized_slot_keys() -> None:
    payload = {
        "personas": [
            {
                "persona_id": "fake-1",
                "slots": {
                    "name": "Alice",
                    " name ": "Bob",
                },
            }
        ]
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PersonaRepositoryDocumentV2)
    assert migrated.fake_personas[0].slots.name.value == "Alice"
    assert migrated.fake_personas[0].slots.name.aliases == ["Bob"]


def test_persona_address_collision_preserves_structured_fields_alongside_value() -> None:
    payload = {
        "personas": [
            {
                "persona_id": "fake-1",
                "slots": {
                    "address": {"value": "Main St"},
                    " address ": {"city": "上海市", "detail": "1号楼101室"},
                },
            }
        ]
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PersonaRepositoryDocumentV2)
    address = migrated.fake_personas[0].slots.address
    assert address.street.model_dump() == {"value": "Main St", "aliases": []}
    assert address.city.model_dump() == {"value": "上海市", "aliases": []}
    assert address.building.model_dump() == {"value": "1号楼", "aliases": []}
    assert address.room.model_dump() == {"value": "101室", "aliases": []}


def test_entity_address_list_preserves_structured_fields_alongside_value() -> None:
    payload = {
        "entities": [
            {
                "entity_id": "entity-1",
                "address": [
                    {"value": "Main St"},
                    {"city": "上海市", "detail": "1号楼101室"},
                ],
            }
        ]
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PrivacyRepositoryDocumentV2)
    address = migrated.true_personas[0].slots.address
    assert address.street.model_dump() == {"value": "Main St", "aliases": []}
    assert address.city.model_dump() == {"value": "上海市", "aliases": []}
    assert address.building.model_dump() == {"value": "1号楼", "aliases": []}
    assert address.room.model_dump() == {"value": "101室", "aliases": []}


def test_detail_without_street_is_preserved_conservatively_as_street() -> None:
    payload = {
        "personas": [
            {
                "persona_id": "fake-1",
                "slots": {
                    "address": {
                        "city": "上海市",
                        "detail": "1号楼101室",
                    }
                },
            }
        ]
    }

    migrated = migrate_legacy_repository(payload)

    assert isinstance(migrated, PersonaRepositoryDocumentV2)
    address = migrated.fake_personas[0].slots.address
    assert address.city.model_dump() == {"value": "上海市", "aliases": []}
    assert address.street.model_dump() == {"value": "1号楼101室", "aliases": []}
    assert address.building is None
    assert address.room is None


def test_repository_v2_migration_cli_writes_json_and_prints_summary(tmp_path) -> None:
    root = Path(__file__).resolve().parents[2]
    script_path = root / "scripts" / "migrate_repository_v2.py"
    input_path = tmp_path / "legacy.json"
    output_path = tmp_path / "migrated.json"
    input_path.write_text(
        json.dumps({"name": ["张三"], "phone": ["13900001111"]}, ensure_ascii=False),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    written = json.loads(output_path.read_text(encoding="utf-8"))

    assert written["version"] == 2
    assert len(written["true_personas"]) == 2
    assert "ok" in result.stdout
    assert "true_personas=2" in result.stdout
