"""Repository v2 storage schema tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from privacyguard.infrastructure.repository.schemas_v2 import (
    AddressLevelExposureStatsV2,
    AddressSlotRuntimeV2,
    AddressSlotStorageV2,
    AddressStatsV2,
    ExposureInfoV2,
    PersonaDocumentV2,
    PersonaRepositoryDocumentV2,
    PersonaStatsV2,
    PrivacyRepositoryDocumentV2,
    RepositorySlotsV2,
    RepositoryStatsV2,
    SharedSlotStorageV2,
    SlotStatsV2,
    V2_VERSION,
    project_fake_persona_to_runtime,
    project_true_persona_to_runtime,
)


def test_scalar_storage_slots_persist_only_value_and_aliases() -> None:
    slot = SharedSlotStorageV2(value="张三", aliases=[])

    assert slot.model_dump() == {"value": "张三", "aliases": []}
    assert "alias_role" not in slot.model_dump()


def test_address_storage_uses_fixed_semantic_levels_with_slot_objects() -> None:
    address = AddressSlotStorageV2(
        country=SharedSlotStorageV2(value="中国", aliases=["中华人民共和国"]),
        province=SharedSlotStorageV2(value="北京市", aliases=[]),
        city=SharedSlotStorageV2(value="北京", aliases=["北京市"]),
        district=SharedSlotStorageV2(value="海淀区", aliases=[]),
        street=SharedSlotStorageV2(value="知春路", aliases=["知春"]),
        building=SharedSlotStorageV2(value="88号", aliases=[]),
        room=SharedSlotStorageV2(value="1201", aliases=[]),
    )

    assert address.model_dump(exclude_none=True) == {
        "country": {"value": "中国", "aliases": ["中华人民共和国"]},
        "province": {"value": "北京市", "aliases": []},
        "city": {"value": "北京", "aliases": ["北京市"]},
        "district": {"value": "海淀区", "aliases": []},
        "street": {"value": "知春路", "aliases": ["知春"]},
        "building": {"value": "88号", "aliases": []},
        "room": {"value": "1201", "aliases": []},
    }


def test_repository_v2_documents_use_integer_version_and_expected_top_level_fields() -> None:
    privacy_doc = PrivacyRepositoryDocumentV2(
        version=V2_VERSION,
        stats=RepositoryStatsV2(total=ExposureInfoV2(exposure_count=1)),
        true_personas=[
            PersonaDocumentV2(
                persona_id="p1",
                display_name="真实用户",
                slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="a", aliases=[])),
                stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
                metadata={"source": "seed"},
            )
        ],
    )
    persona_doc = PersonaRepositoryDocumentV2(
        version=V2_VERSION,
        stats=RepositoryStatsV2(total=ExposureInfoV2(exposure_count=1)),
        fake_personas=[
            PersonaDocumentV2(
                persona_id="f1",
                slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="b", aliases=["alias-b"])),
                stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
                metadata={"source": "seed"},
            )
        ],
    )

    assert V2_VERSION == 2
    assert privacy_doc.version == 2
    assert persona_doc.version == 2
    assert privacy_doc.model_dump(exclude_none=True).keys() == {"version", "stats", "true_personas"}
    assert persona_doc.model_dump(exclude_none=True).keys() == {"version", "stats", "fake_personas"}
    assert privacy_doc.true_personas[0].model_dump(exclude_none=True).keys() == {
        "persona_id",
        "display_name",
        "slots",
        "stats",
        "metadata",
    }


def test_repository_v2_documents_reject_duplicate_persona_ids() -> None:
    with pytest.raises(ValidationError, match="persona_id"):
        PrivacyRepositoryDocumentV2(
            version=V2_VERSION,
            stats=RepositoryStatsV2(total=ExposureInfoV2(exposure_count=1)),
            true_personas=[
                PersonaDocumentV2(
                    persona_id="dup",
                    display_name="真实一",
                    slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="a", aliases=[])),
                    stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
                    metadata={"source": "seed"},
                ),
                PersonaDocumentV2(
                    persona_id="dup",
                    display_name="真实二",
                    slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="b", aliases=[])),
                    stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
                    metadata={"source": "seed"},
                ),
            ],
        )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: SharedSlotStorageV2(value="x", aliases=["y", "y"]), "unique"),
        (lambda: SharedSlotStorageV2(value="x", aliases=["x"]), "duplicate"),
        (lambda: SharedSlotStorageV2(value="x", aliases=[], alias_role="match"), "extra"),
        (lambda: AddressSlotStorageV2(room=SharedSlotStorageV2(value="1201", aliases=[])), "building"),
        (
            lambda: AddressSlotStorageV2(building=SharedSlotStorageV2(value="88号", aliases=[])),
            "street",
        ),
        (lambda: AddressSlotStorageV2(), "address"),
        (
            lambda: AddressSlotStorageV2(
                city=SharedSlotStorageV2(value="北京", aliases=[]),
                postal_code=SharedSlotStorageV2(value="100000", aliases=[]),
            ),
            "extra",
        ),
    ],
)
def test_repository_v2_storage_validation_rules(factory, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        factory()


def test_repository_v2_documents_require_non_empty_slots() -> None:
    with pytest.raises(ValidationError, match="slots"):
        PersonaDocumentV2(
            persona_id="empty",
            slots=RepositorySlotsV2(),
            stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=0)),
            metadata={},
        )


def test_repository_v2_stats_models_use_structured_exposure_info_everywhere() -> None:
    stats = RepositoryStatsV2(
        total=ExposureInfoV2(
            exposure_count=10,
            last_exposed_at="2026-03-22T10:11:12Z",
            last_exposed_session_id="s-1",
            last_exposed_turn_id=7,
        ),
        personas=PersonaStatsV2(
            total=ExposureInfoV2(exposure_count=4),
            slots=SlotStatsV2(
                name=ExposureInfoV2(exposure_count=2),
                address=AddressStatsV2(
                    total=ExposureInfoV2(exposure_count=1),
                    levels=AddressLevelExposureStatsV2(city=ExposureInfoV2(exposure_count=1)),
                ),
            ),
            address=AddressStatsV2(
                total=ExposureInfoV2(exposure_count=1),
                levels=AddressLevelExposureStatsV2(room=ExposureInfoV2(exposure_count=1)),
            ),
        ),
        slots=SlotStatsV2(phone=ExposureInfoV2(exposure_count=3)),
        address=AddressStatsV2(
            total=ExposureInfoV2(exposure_count=2),
            levels=AddressLevelExposureStatsV2(country=ExposureInfoV2(exposure_count=2)),
        ),
    )

    total_dump = stats.total.model_dump(mode="json", exclude_none=True)

    assert total_dump == {
        "exposure_count": 10,
        "last_exposed_at": "2026-03-22T10:11:12Z",
        "last_exposed_session_id": "s-1",
        "last_exposed_turn_id": 7,
    }
    assert stats.personas.total.exposure_count == 4
    assert stats.personas.slots.name.exposure_count == 2
    assert stats.personas.slots.address.total.exposure_count == 1
    assert stats.personas.address.levels.room.exposure_count == 1
    assert stats.address.levels.country.exposure_count == 2


def test_true_and_fake_persona_runtime_projection_derives_alias_role_from_repository_context() -> None:
    persona = PersonaDocumentV2(
        persona_id="persona-1",
        display_name="示例",
        slots=RepositorySlotsV2(
            name=SharedSlotStorageV2(value="张三", aliases=["张同学", "李同学"]),
            address=AddressSlotStorageV2(
                country=SharedSlotStorageV2(value="中国", aliases=["中华人民共和国"]),
                city=SharedSlotStorageV2(value="北京", aliases=["北京市"]),
                street=SharedSlotStorageV2(value="知春路", aliases=["知春"]),
                building=SharedSlotStorageV2(value="88号", aliases=[]),
            ),
        ),
        stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
        metadata={"source": "seed"},
    )

    true_runtime = project_true_persona_to_runtime(persona)
    fake_runtime = project_fake_persona_to_runtime(persona)

    assert true_runtime.slots.name.match_aliases == ["张同学", "李同学"]
    assert true_runtime.slots.name.render_aliases == []
    assert fake_runtime.slots.name.match_aliases == []
    assert fake_runtime.slots.name.render_aliases == ["张同学", "李同学"]
    assert true_runtime.slots.address.city.match_aliases == ["北京市"]
    assert true_runtime.slots.address.city.render_aliases == []
    assert fake_runtime.slots.address.city.match_aliases == []
    assert fake_runtime.slots.address.city.render_aliases == ["北京市"]


def test_runtime_projection_detaches_stats_from_storage_persona() -> None:
    persona = PersonaDocumentV2(
        persona_id="persona-2",
        slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="张三", aliases=[])),
        stats=PersonaStatsV2(total=ExposureInfoV2(exposure_count=1)),
        metadata={},
    )

    runtime = project_true_persona_to_runtime(persona)
    runtime.stats.total.exposure_count = 99

    assert persona.stats.total.exposure_count == 1
    assert runtime.stats.total.exposure_count == 99


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: AddressSlotRuntimeV2(), "address"),
        (
            lambda: AddressSlotRuntimeV2(
                room=project_true_persona_to_runtime(
                    PersonaDocumentV2(
                        persona_id="p-room",
                        slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="x", aliases=[])),
                        stats=PersonaStatsV2(),
                        metadata={},
                    )
                ).slots.name
            ),
            "building",
        ),
        (
            lambda: AddressSlotRuntimeV2(
                building=project_true_persona_to_runtime(
                    PersonaDocumentV2(
                        persona_id="p-building",
                        slots=RepositorySlotsV2(name=SharedSlotStorageV2(value="x", aliases=[])),
                        stats=PersonaStatsV2(),
                        metadata={},
                    )
                ).slots.name
            ),
            "street",
        ),
    ],
)
def test_runtime_address_validation_rules_match_storage(factory, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        factory()
