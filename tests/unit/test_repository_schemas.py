"""仓库（repository）存储 schema 的单元测试。"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from privacyguard.infrastructure.repository.schemas import (
    AddressLevelExposureStats,
    AddressSlotRuntime,
    AddressSlotStorage,
    AddressStats,
    ExposureInfo,
    PersonaDocument,
    PersonaRepositoryDocument,
    PersonaStats,
    PersonaSlots,
    PrivacyRepositoryDocument,
    RepositoryStats,
    SharedSlotStorage,
    SlotStats,
    project_fake_persona_to_runtime,
    project_true_persona_to_runtime,
)


def test_scalar_storage_slots_persist_only_value_and_aliases() -> None:
    slot = SharedSlotStorage(value="张三", aliases=[])

    assert slot.model_dump() == {"value": "张三", "aliases": []}
    assert "alias_role" not in slot.model_dump()


def test_address_storage_uses_fixed_semantic_levels_with_slot_objects() -> None:
    address = AddressSlotStorage(
        country=SharedSlotStorage(value="中国", aliases=["中华人民共和国"]),
        province=SharedSlotStorage(value="北京市", aliases=[]),
        city=SharedSlotStorage(value="北京", aliases=["北京市"]),
        district=SharedSlotStorage(value="海淀区", aliases=[]),
        street=SharedSlotStorage(value="知春路", aliases=["知春"]),
        building=SharedSlotStorage(value="88号", aliases=[]),
        room=SharedSlotStorage(value="1201", aliases=[]),
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


def test_repository_documents_top_level_fields() -> None:
    privacy_doc = PrivacyRepositoryDocument(
        stats=RepositoryStats(total=ExposureInfo(exposure_count=1)),
        true_personas=[
            PersonaDocument(
                persona_id="p1",
                display_name="真实用户",
                slots=PersonaSlots(name=SharedSlotStorage(value="a", aliases=[])),
                stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
                metadata={"source": "seed"},
            )
        ],
    )
    persona_doc = PersonaRepositoryDocument(
        stats=RepositoryStats(total=ExposureInfo(exposure_count=1)),
        fake_personas=[
            PersonaDocument(
                persona_id="f1",
                slots=PersonaSlots(name=SharedSlotStorage(value="b", aliases=["alias-b"])),
                stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
                metadata={"source": "seed"},
            )
        ],
    )

    assert privacy_doc.model_dump(exclude_none=True).keys() == {"stats", "true_personas"}
    assert persona_doc.model_dump(exclude_none=True).keys() == {"stats", "fake_personas"}
    assert privacy_doc.true_personas[0].model_dump(exclude_none=True).keys() == {
        "persona_id",
        "display_name",
        "slots",
        "stats",
        "metadata",
    }


def test_repository_documents_reject_duplicate_persona_ids() -> None:
    with pytest.raises(ValidationError, match="persona_id"):
        PrivacyRepositoryDocument(
            stats=RepositoryStats(total=ExposureInfo(exposure_count=1)),
            true_personas=[
                PersonaDocument(
                    persona_id="dup",
                    display_name="真实一",
                    slots=PersonaSlots(name=SharedSlotStorage(value="a", aliases=[])),
                    stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
                    metadata={"source": "seed"},
                ),
                PersonaDocument(
                    persona_id="dup",
                    display_name="真实二",
                    slots=PersonaSlots(name=SharedSlotStorage(value="b", aliases=[])),
                    stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
                    metadata={"source": "seed"},
                ),
            ],
        )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: SharedSlotStorage(value="x", aliases=["y", "y"]), "唯一"),
        (lambda: SharedSlotStorage(value="x", aliases=["x"]), "主值"),
        (lambda: SharedSlotStorage(value="x", aliases=[], alias_role="match"), "extra"),
        (lambda: AddressSlotStorage(room=SharedSlotStorage(value="1201", aliases=[])), "楼栋"),
        (
            lambda: AddressSlotStorage(building=SharedSlotStorage(value="88号", aliases=[])),
            "街道",
        ),
        (lambda: AddressSlotStorage(), "地址"),
        (
            lambda: AddressSlotStorage(
                city=SharedSlotStorage(value="北京", aliases=[]),
                postal_code=SharedSlotStorage(value="100000", aliases=[]),
            ),
            "extra",
        ),
    ],
)
def test_repository_storage_validation_rules(factory, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        factory()


def test_repository_documents_require_non_empty_slots() -> None:
    with pytest.raises(ValidationError, match="slots"):
        PersonaDocument(
            persona_id="empty",
            slots=PersonaSlots(),
            stats=PersonaStats(total=ExposureInfo(exposure_count=0)),
            metadata={},
        )


def test_repository_stats_models_use_structured_exposure_info_everywhere() -> None:
    stats = RepositoryStats(
        total=ExposureInfo(
            exposure_count=10,
            last_exposed_at="2026-03-22T10:11:12Z",
            last_exposed_session_id="s-1",
            last_exposed_turn_id=7,
        ),
        personas=PersonaStats(
            total=ExposureInfo(exposure_count=4),
            slots=SlotStats(
                name=ExposureInfo(exposure_count=2),
                address=AddressStats(
                    total=ExposureInfo(exposure_count=1),
                    levels=AddressLevelExposureStats(city=ExposureInfo(exposure_count=1)),
                ),
            ),
            address=AddressStats(
                total=ExposureInfo(exposure_count=1),
                levels=AddressLevelExposureStats(room=ExposureInfo(exposure_count=1)),
            ),
        ),
        slots=SlotStats(phone=ExposureInfo(exposure_count=3)),
        address=AddressStats(
            total=ExposureInfo(exposure_count=2),
            levels=AddressLevelExposureStats(country=ExposureInfo(exposure_count=2)),
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
    persona = PersonaDocument(
        persona_id="persona-1",
        display_name="示例",
        slots=PersonaSlots(
            name=SharedSlotStorage(value="张三", aliases=["张同学", "李同学"]),
            address=AddressSlotStorage(
                country=SharedSlotStorage(value="中国", aliases=["中华人民共和国"]),
                city=SharedSlotStorage(value="北京", aliases=["北京市"]),
                street=SharedSlotStorage(value="知春路", aliases=["知春"]),
                building=SharedSlotStorage(value="88号", aliases=[]),
            ),
        ),
        stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
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
    persona = PersonaDocument(
        persona_id="persona-2",
        slots=PersonaSlots(name=SharedSlotStorage(value="张三", aliases=[])),
        stats=PersonaStats(total=ExposureInfo(exposure_count=1)),
        metadata={},
    )

    runtime = project_true_persona_to_runtime(persona)
    runtime.stats.total.exposure_count = 99

    assert persona.stats.total.exposure_count == 1
    assert runtime.stats.total.exposure_count == 99


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: AddressSlotRuntime(), "地址"),
        (
            lambda: AddressSlotRuntime(
                room=project_true_persona_to_runtime(
                    PersonaDocument(
                        persona_id="p-room",
                        slots=PersonaSlots(name=SharedSlotStorage(value="x", aliases=[])),
                        stats=PersonaStats(),
                        metadata={},
                    )
                ).slots.name
            ),
            "楼栋",
        ),
        (
            lambda: AddressSlotRuntime(
                building=project_true_persona_to_runtime(
                    PersonaDocument(
                        persona_id="p-building",
                        slots=PersonaSlots(name=SharedSlotStorage(value="x", aliases=[])),
                        stats=PersonaStats(),
                        metadata={},
                    )
                ).slots.name
            ),
            "街道",
        ),
    ],
)
def test_runtime_address_validation_rules_match_storage(factory, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        factory()
