"""共享的 privacy / persona 仓库存储 schema。"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class RepositoryBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AliasRole(str, Enum):
    MATCH = "match"
    RENDER = "render"


class AddressLevel(str, Enum):
    COUNTRY = "country"
    PROVINCE = "province"
    CITY = "city"
    DISTRICT = "district"
    STREET = "street"
    BUILDING = "building"
    ROOM = "room"


class ExposureInfo(RepositoryBaseModel):
    exposure_count: int = Field(default=0, ge=0)
    last_exposed_at: datetime | None = None
    last_exposed_session_id: NonEmptyStr | None = None
    last_exposed_turn_id: int | None = Field(default=None, ge=0)


class AddressLevelExposureStats(RepositoryBaseModel):
    country: ExposureInfo = Field(default_factory=ExposureInfo)
    province: ExposureInfo = Field(default_factory=ExposureInfo)
    city: ExposureInfo = Field(default_factory=ExposureInfo)
    district: ExposureInfo = Field(default_factory=ExposureInfo)
    street: ExposureInfo = Field(default_factory=ExposureInfo)
    building: ExposureInfo = Field(default_factory=ExposureInfo)
    room: ExposureInfo = Field(default_factory=ExposureInfo)


class AddressStats(RepositoryBaseModel):
    total: ExposureInfo = Field(default_factory=ExposureInfo)
    levels: AddressLevelExposureStats = Field(default_factory=AddressLevelExposureStats)


class SlotStats(RepositoryBaseModel):
    name: ExposureInfo = Field(default_factory=ExposureInfo)
    location_clue: ExposureInfo = Field(default_factory=ExposureInfo)
    phone: ExposureInfo = Field(default_factory=ExposureInfo)
    card_number: ExposureInfo = Field(default_factory=ExposureInfo)
    bank_account: ExposureInfo = Field(default_factory=ExposureInfo)
    passport_number: ExposureInfo = Field(default_factory=ExposureInfo)
    driver_license: ExposureInfo = Field(default_factory=ExposureInfo)
    email: ExposureInfo = Field(default_factory=ExposureInfo)
    address: AddressStats = Field(default_factory=AddressStats)
    id_number: ExposureInfo = Field(default_factory=ExposureInfo)
    organization: ExposureInfo = Field(default_factory=ExposureInfo)


class PersonaStats(RepositoryBaseModel):
    total: ExposureInfo = Field(default_factory=ExposureInfo)
    slots: SlotStats = Field(default_factory=SlotStats)
    address: AddressStats = Field(default_factory=AddressStats)


class RepositoryStats(RepositoryBaseModel):
    total: ExposureInfo = Field(default_factory=ExposureInfo)
    personas: PersonaStats = Field(default_factory=PersonaStats)
    slots: SlotStats = Field(default_factory=SlotStats)
    address: AddressStats = Field(default_factory=AddressStats)


class SharedSlotStorage(RepositoryBaseModel):
    value: NonEmptyStr
    aliases: list[NonEmptyStr] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_aliases(self) -> "SharedSlotStorage":
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("别名必须唯一")
        if self.value in self.aliases:
            raise ValueError("别名不能与主值重复")
        return self


AtomicSlotStorage = SharedSlotStorage
StorageSlot = SharedSlotStorage


def _validate_address_levels(
    country: SharedSlotStorage | SharedSlotRuntime | None,
    province: SharedSlotStorage | SharedSlotRuntime | None,
    city: SharedSlotStorage | SharedSlotRuntime | None,
    district: SharedSlotStorage | SharedSlotRuntime | None,
    street: SharedSlotStorage | SharedSlotRuntime | None,
    building: SharedSlotStorage | SharedSlotRuntime | None,
    room: SharedSlotStorage | SharedSlotRuntime | None,
) -> None:
    if not any((country, province, city, district, street, building, room)):
        raise ValueError("地址不能为空")
    if room and not building:
        raise ValueError("有房间则必须有楼栋")
    if building and not street:
        raise ValueError("有楼栋则必须有街道")


class AddressSlotStorage(RepositoryBaseModel):
    country: SharedSlotStorage | None = None
    province: SharedSlotStorage | None = None
    city: SharedSlotStorage | None = None
    district: SharedSlotStorage | None = None
    street: SharedSlotStorage | None = None
    building: SharedSlotStorage | None = None
    room: SharedSlotStorage | None = None

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotStorage":
        _validate_address_levels(
            self.country,
            self.province,
            self.city,
            self.district,
            self.street,
            self.building,
            self.room,
        )
        return self


class SharedSlotRuntime(RepositoryBaseModel):
    value: NonEmptyStr
    match_aliases: list[NonEmptyStr] = Field(default_factory=list)
    render_aliases: list[NonEmptyStr] = Field(default_factory=list)


AtomicSlotRuntime = SharedSlotRuntime
RuntimeSlot = SharedSlotRuntime


class AddressSlotRuntime(RepositoryBaseModel):
    country: SharedSlotRuntime | None = None
    province: SharedSlotRuntime | None = None
    city: SharedSlotRuntime | None = None
    district: SharedSlotRuntime | None = None
    street: SharedSlotRuntime | None = None
    building: SharedSlotRuntime | None = None
    room: SharedSlotRuntime | None = None

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotRuntime":
        _validate_address_levels(
            self.country,
            self.province,
            self.city,
            self.district,
            self.street,
            self.building,
            self.room,
        )
        return self


class PersonaSlots(RepositoryBaseModel):
    name: SharedSlotStorage | None = None
    location_clue: SharedSlotStorage | None = None
    phone: SharedSlotStorage | None = None
    card_number: SharedSlotStorage | None = None
    bank_account: SharedSlotStorage | None = None
    passport_number: SharedSlotStorage | None = None
    driver_license: SharedSlotStorage | None = None
    email: SharedSlotStorage | None = None
    address: AddressSlotStorage | None = None
    id_number: SharedSlotStorage | None = None
    organization: SharedSlotStorage | None = None

    @model_validator(mode="after")
    def _validate_non_empty(self) -> "PersonaSlots":
        if not any(
            (
                self.name,
                self.location_clue,
                self.phone,
                self.card_number,
                self.bank_account,
                self.passport_number,
                self.driver_license,
                self.email,
                self.address,
                self.id_number,
                self.organization,
            )
        ):
            raise ValueError("slots 不能为空")
        return self


class PersonaSlotsRuntime(RepositoryBaseModel):
    name: SharedSlotRuntime | None = None
    location_clue: SharedSlotRuntime | None = None
    phone: SharedSlotRuntime | None = None
    card_number: SharedSlotRuntime | None = None
    bank_account: SharedSlotRuntime | None = None
    passport_number: SharedSlotRuntime | None = None
    driver_license: SharedSlotRuntime | None = None
    email: SharedSlotRuntime | None = None
    address: AddressSlotRuntime | None = None
    id_number: SharedSlotRuntime | None = None
    organization: SharedSlotRuntime | None = None


RepositorySlots = PersonaSlots
RepositorySlotsRuntime = PersonaSlotsRuntime


class PersonaDocument(RepositoryBaseModel):
    persona_id: NonEmptyStr
    display_name: NonEmptyStr | None = None
    slots: PersonaSlots
    stats: PersonaStats = Field(default_factory=PersonaStats)
    metadata: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)


class PrivacyRepositoryDocument(RepositoryBaseModel):
    stats: RepositoryStats = Field(default_factory=RepositoryStats)
    true_personas: list[PersonaDocument]

    @model_validator(mode="after")
    def _validate_unique_personas(self) -> "PrivacyRepositoryDocument":
        persona_ids = [persona.persona_id for persona in self.true_personas]
        if len(set(persona_ids)) != len(persona_ids):
            raise ValueError("文档内 persona_id 必须唯一")
        return self


class PersonaRepositoryDocument(RepositoryBaseModel):
    stats: RepositoryStats = Field(default_factory=RepositoryStats)
    fake_personas: list[PersonaDocument]

    @model_validator(mode="after")
    def _validate_unique_personas(self) -> "PersonaRepositoryDocument":
        persona_ids = [persona.persona_id for persona in self.fake_personas]
        if len(set(persona_ids)) != len(persona_ids):
            raise ValueError("文档内 persona_id 必须唯一")
        return self


class PersonaRuntime(RepositoryBaseModel):
    persona_id: NonEmptyStr
    display_name: NonEmptyStr | None = None
    slots: PersonaSlotsRuntime
    stats: PersonaStats = Field(default_factory=PersonaStats)
    metadata: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)


def _project_aliases(slot: SharedSlotStorage, alias_role: AliasRole) -> dict[str, list[str]]:
    aliases = list(slot.aliases)
    if alias_role == AliasRole.MATCH:
        return {"match_aliases": aliases, "render_aliases": []}
    return {"match_aliases": [], "render_aliases": aliases}


def _project_scalar_slot_to_runtime(slot: SharedSlotStorage, alias_role: AliasRole) -> SharedSlotRuntime:
    return SharedSlotRuntime(value=slot.value, **_project_aliases(slot, alias_role))


def project_storage_slot_to_runtime(
    slot: StorageSlot | AddressSlotStorage,
    alias_role: AliasRole,
) -> RuntimeSlot | AddressSlotRuntime:
    if isinstance(slot, AddressSlotStorage):
        return AddressSlotRuntime(
            country=_project_scalar_slot_to_runtime(slot.country, alias_role) if slot.country else None,
            province=_project_scalar_slot_to_runtime(slot.province, alias_role) if slot.province else None,
            city=_project_scalar_slot_to_runtime(slot.city, alias_role) if slot.city else None,
            district=_project_scalar_slot_to_runtime(slot.district, alias_role) if slot.district else None,
            street=_project_scalar_slot_to_runtime(slot.street, alias_role) if slot.street else None,
            building=_project_scalar_slot_to_runtime(slot.building, alias_role) if slot.building else None,
            room=_project_scalar_slot_to_runtime(slot.room, alias_role) if slot.room else None,
        )
    return _project_scalar_slot_to_runtime(slot, alias_role)


def _project_slots_to_runtime(slots: PersonaSlots, alias_role: AliasRole) -> PersonaSlotsRuntime:
    return PersonaSlotsRuntime(
        name=_project_scalar_slot_to_runtime(slots.name, alias_role) if slots.name else None,
        location_clue=_project_scalar_slot_to_runtime(slots.location_clue, alias_role) if slots.location_clue else None,
        phone=_project_scalar_slot_to_runtime(slots.phone, alias_role) if slots.phone else None,
        card_number=_project_scalar_slot_to_runtime(slots.card_number, alias_role) if slots.card_number else None,
        bank_account=_project_scalar_slot_to_runtime(slots.bank_account, alias_role) if slots.bank_account else None,
        passport_number=_project_scalar_slot_to_runtime(slots.passport_number, alias_role) if slots.passport_number else None,
        driver_license=_project_scalar_slot_to_runtime(slots.driver_license, alias_role) if slots.driver_license else None,
        email=_project_scalar_slot_to_runtime(slots.email, alias_role) if slots.email else None,
        address=project_storage_slot_to_runtime(slots.address, alias_role) if slots.address else None,
        id_number=_project_scalar_slot_to_runtime(slots.id_number, alias_role) if slots.id_number else None,
        organization=_project_scalar_slot_to_runtime(slots.organization, alias_role) if slots.organization else None,
    )


def project_storage_persona_to_runtime(persona: PersonaDocument, alias_role: AliasRole) -> PersonaRuntime:
    return PersonaRuntime(
        persona_id=persona.persona_id,
        display_name=persona.display_name,
        slots=_project_slots_to_runtime(persona.slots, alias_role),
        stats=persona.stats.model_copy(deep=True),
        metadata=dict(persona.metadata),
    )


def project_true_persona_to_runtime(persona: PersonaDocument) -> PersonaRuntime:
    return project_storage_persona_to_runtime(persona, AliasRole.MATCH)


def project_fake_persona_to_runtime(persona: PersonaDocument) -> PersonaRuntime:
    return project_storage_persona_to_runtime(persona, AliasRole.RENDER)


__all__ = [
    "AddressLevel",
    "AddressLevelExposureStats",
    "AddressSlotRuntime",
    "AddressSlotStorage",
    "AddressStats",
    "AliasRole",
    "AtomicSlotRuntime",
    "AtomicSlotStorage",
    "ExposureInfo",
    "PersonaDocument",
    "PersonaRepositoryDocument",
    "PersonaRuntime",
    "PersonaSlotsRuntime",
    "PersonaSlots",
    "PersonaStats",
    "PrivacyRepositoryDocument",
    "RepositoryStats",
    "RepositorySlotsRuntime",
    "RepositorySlots",
    "RepositoryBaseModel",
    "RuntimeSlot",
    "SharedSlotRuntime",
    "SharedSlotStorage",
    "SlotStats",
    "StorageSlot",
    "project_fake_persona_to_runtime",
    "project_storage_persona_to_runtime",
    "project_storage_slot_to_runtime",
    "project_true_persona_to_runtime",
]
