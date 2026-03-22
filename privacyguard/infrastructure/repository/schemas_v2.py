"""Shared v2 repository storage schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
V2_VERSION = 2


class V2BaseModel(BaseModel):
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


class ExposureInfoV2(V2BaseModel):
    exposure_count: int = Field(default=0, ge=0)
    last_exposed_at: datetime | None = None
    last_exposed_session_id: NonEmptyStr | None = None
    last_exposed_turn_id: int | None = Field(default=None, ge=0)


class AddressLevelExposureStatsV2(V2BaseModel):
    country: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    province: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    city: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    district: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    street: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    building: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    room: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)


class AddressStatsV2(V2BaseModel):
    total: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    levels: AddressLevelExposureStatsV2 = Field(default_factory=AddressLevelExposureStatsV2)


class SlotStatsV2(V2BaseModel):
    name: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    location_clue: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    phone: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    card_number: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    bank_account: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    passport_number: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    driver_license: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    email: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    address: AddressStatsV2 = Field(default_factory=AddressStatsV2)
    id_number: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    organization: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)


class PersonaStatsV2(V2BaseModel):
    total: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    slots: SlotStatsV2 = Field(default_factory=SlotStatsV2)
    address: AddressStatsV2 = Field(default_factory=AddressStatsV2)


class RepositoryStatsV2(V2BaseModel):
    total: ExposureInfoV2 = Field(default_factory=ExposureInfoV2)
    personas: PersonaStatsV2 = Field(default_factory=PersonaStatsV2)
    slots: SlotStatsV2 = Field(default_factory=SlotStatsV2)
    address: AddressStatsV2 = Field(default_factory=AddressStatsV2)


class SharedSlotStorageV2(V2BaseModel):
    value: NonEmptyStr
    aliases: list[NonEmptyStr] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_aliases(self) -> "SharedSlotStorageV2":
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("aliases must be unique")
        if self.value in self.aliases:
            raise ValueError("aliases cannot duplicate value")
        return self


# Compatibility alias: storage no longer preserves semantics via subclass identity.
AtomicSlotStorageV2 = SharedSlotStorageV2
StorageSlotV2 = SharedSlotStorageV2


def _validate_address_levels(
    country: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    province: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    city: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    district: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    street: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    building: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
    room: SharedSlotStorageV2 | SharedSlotRuntimeV2 | None,
) -> None:
    if not any((country, province, city, district, street, building, room)):
        raise ValueError("address must not be empty")
    if room and not building:
        raise ValueError("room requires building")
    if building and not street:
        raise ValueError("building requires street")


class AddressSlotStorageV2(V2BaseModel):
    country: SharedSlotStorageV2 | None = None
    province: SharedSlotStorageV2 | None = None
    city: SharedSlotStorageV2 | None = None
    district: SharedSlotStorageV2 | None = None
    street: SharedSlotStorageV2 | None = None
    building: SharedSlotStorageV2 | None = None
    room: SharedSlotStorageV2 | None = None

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotStorageV2":
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


class SharedSlotRuntimeV2(V2BaseModel):
    value: NonEmptyStr
    match_aliases: list[NonEmptyStr] = Field(default_factory=list)
    render_aliases: list[NonEmptyStr] = Field(default_factory=list)


AtomicSlotRuntimeV2 = SharedSlotRuntimeV2
RuntimeSlotV2 = SharedSlotRuntimeV2


class AddressSlotRuntimeV2(V2BaseModel):
    country: SharedSlotRuntimeV2 | None = None
    province: SharedSlotRuntimeV2 | None = None
    city: SharedSlotRuntimeV2 | None = None
    district: SharedSlotRuntimeV2 | None = None
    street: SharedSlotRuntimeV2 | None = None
    building: SharedSlotRuntimeV2 | None = None
    room: SharedSlotRuntimeV2 | None = None

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotRuntimeV2":
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


class PersonaSlotsV2(V2BaseModel):
    name: SharedSlotStorageV2 | None = None
    location_clue: SharedSlotStorageV2 | None = None
    phone: SharedSlotStorageV2 | None = None
    card_number: SharedSlotStorageV2 | None = None
    bank_account: SharedSlotStorageV2 | None = None
    passport_number: SharedSlotStorageV2 | None = None
    driver_license: SharedSlotStorageV2 | None = None
    email: SharedSlotStorageV2 | None = None
    address: AddressSlotStorageV2 | None = None
    id_number: SharedSlotStorageV2 | None = None
    organization: SharedSlotStorageV2 | None = None

    @model_validator(mode="after")
    def _validate_non_empty(self) -> "PersonaSlotsV2":
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
            raise ValueError("slots must not be empty")
        return self


class PersonaSlotsRuntimeV2(V2BaseModel):
    name: SharedSlotRuntimeV2 | None = None
    location_clue: SharedSlotRuntimeV2 | None = None
    phone: SharedSlotRuntimeV2 | None = None
    card_number: SharedSlotRuntimeV2 | None = None
    bank_account: SharedSlotRuntimeV2 | None = None
    passport_number: SharedSlotRuntimeV2 | None = None
    driver_license: SharedSlotRuntimeV2 | None = None
    email: SharedSlotRuntimeV2 | None = None
    address: AddressSlotRuntimeV2 | None = None
    id_number: SharedSlotRuntimeV2 | None = None
    organization: SharedSlotRuntimeV2 | None = None


RepositorySlotsV2 = PersonaSlotsV2
RepositorySlotsRuntimeV2 = PersonaSlotsRuntimeV2


class PersonaDocumentV2(V2BaseModel):
    persona_id: NonEmptyStr
    display_name: NonEmptyStr | None = None
    slots: PersonaSlotsV2
    stats: PersonaStatsV2 = Field(default_factory=PersonaStatsV2)
    metadata: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)


class PrivacyRepositoryDocumentV2(V2BaseModel):
    version: Literal[2] = V2_VERSION
    stats: RepositoryStatsV2 = Field(default_factory=RepositoryStatsV2)
    true_personas: list[PersonaDocumentV2]

    @model_validator(mode="after")
    def _validate_unique_personas(self) -> "PrivacyRepositoryDocumentV2":
        persona_ids = [persona.persona_id for persona in self.true_personas]
        if len(set(persona_ids)) != len(persona_ids):
            raise ValueError("persona_id must be unique within document")
        return self


class PersonaRepositoryDocumentV2(V2BaseModel):
    version: Literal[2] = V2_VERSION
    stats: RepositoryStatsV2 = Field(default_factory=RepositoryStatsV2)
    fake_personas: list[PersonaDocumentV2]

    @model_validator(mode="after")
    def _validate_unique_personas(self) -> "PersonaRepositoryDocumentV2":
        persona_ids = [persona.persona_id for persona in self.fake_personas]
        if len(set(persona_ids)) != len(persona_ids):
            raise ValueError("persona_id must be unique within document")
        return self


class PersonaRuntimeV2(V2BaseModel):
    persona_id: NonEmptyStr
    display_name: NonEmptyStr | None = None
    slots: PersonaSlotsRuntimeV2
    stats: PersonaStatsV2 = Field(default_factory=PersonaStatsV2)
    metadata: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)


def _project_aliases(slot: SharedSlotStorageV2, alias_role: AliasRole) -> dict[str, list[str]]:
    aliases = list(slot.aliases)
    if alias_role == AliasRole.MATCH:
        return {"match_aliases": aliases, "render_aliases": []}
    return {"match_aliases": [], "render_aliases": aliases}


def _project_scalar_slot_to_runtime(slot: SharedSlotStorageV2, alias_role: AliasRole) -> SharedSlotRuntimeV2:
    return SharedSlotRuntimeV2(value=slot.value, **_project_aliases(slot, alias_role))


def project_storage_slot_to_runtime(
    slot: StorageSlotV2 | AddressSlotStorageV2,
    alias_role: AliasRole,
) -> RuntimeSlotV2 | AddressSlotRuntimeV2:
    if isinstance(slot, AddressSlotStorageV2):
        return AddressSlotRuntimeV2(
            country=_project_scalar_slot_to_runtime(slot.country, alias_role) if slot.country else None,
            province=_project_scalar_slot_to_runtime(slot.province, alias_role) if slot.province else None,
            city=_project_scalar_slot_to_runtime(slot.city, alias_role) if slot.city else None,
            district=_project_scalar_slot_to_runtime(slot.district, alias_role) if slot.district else None,
            street=_project_scalar_slot_to_runtime(slot.street, alias_role) if slot.street else None,
            building=_project_scalar_slot_to_runtime(slot.building, alias_role) if slot.building else None,
            room=_project_scalar_slot_to_runtime(slot.room, alias_role) if slot.room else None,
        )
    return _project_scalar_slot_to_runtime(slot, alias_role)


def _project_slots_to_runtime(slots: PersonaSlotsV2, alias_role: AliasRole) -> PersonaSlotsRuntimeV2:
    return PersonaSlotsRuntimeV2(
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


def project_storage_persona_to_runtime(persona: PersonaDocumentV2, alias_role: AliasRole) -> PersonaRuntimeV2:
    return PersonaRuntimeV2(
        persona_id=persona.persona_id,
        display_name=persona.display_name,
        slots=_project_slots_to_runtime(persona.slots, alias_role),
        stats=persona.stats.model_copy(deep=True),
        metadata=dict(persona.metadata),
    )


def project_true_persona_to_runtime(persona: PersonaDocumentV2) -> PersonaRuntimeV2:
    return project_storage_persona_to_runtime(persona, AliasRole.MATCH)


def project_fake_persona_to_runtime(persona: PersonaDocumentV2) -> PersonaRuntimeV2:
    return project_storage_persona_to_runtime(persona, AliasRole.RENDER)


__all__ = [
    "AddressLevel",
    "AddressLevelExposureStatsV2",
    "AddressSlotRuntimeV2",
    "AddressSlotStorageV2",
    "AddressStatsV2",
    "AliasRole",
    "AtomicSlotRuntimeV2",
    "AtomicSlotStorageV2",
    "ExposureInfoV2",
    "PersonaDocumentV2",
    "PersonaRepositoryDocumentV2",
    "PersonaRuntimeV2",
    "PersonaSlotsRuntimeV2",
    "PersonaSlotsV2",
    "PersonaStatsV2",
    "PrivacyRepositoryDocumentV2",
    "RepositoryStatsV2",
    "RepositorySlotsRuntimeV2",
    "RepositorySlotsV2",
    "RuntimeSlotV2",
    "SharedSlotRuntimeV2",
    "SharedSlotStorageV2",
    "SlotStatsV2",
    "StorageSlotV2",
    "V2_VERSION",
    "project_fake_persona_to_runtime",
    "project_storage_persona_to_runtime",
    "project_storage_slot_to_runtime",
    "project_true_persona_to_runtime",
]
