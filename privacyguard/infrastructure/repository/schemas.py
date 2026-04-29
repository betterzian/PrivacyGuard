"""共享的 privacy / persona 仓库存储 schema。"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from privacyguard.infrastructure.pii.detector.models import ClaimStrength

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_ADDRESS_LEVEL_FIELDS = (
    "country",
    "province",
    "city",
    "district",
    "subdistrict",
    "road",
    "number",
    "poi",
    "building",
    "detail",
)


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
    SUBDISTRICT = "subdistrict"
    ROAD = "road"
    NUMBER = "number"
    POI = "poi"
    BUILDING = "building"
    DETAIL = "detail"


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
    subdistrict: ExposureInfo = Field(default_factory=ExposureInfo)
    road: ExposureInfo = Field(default_factory=ExposureInfo)
    number: ExposureInfo = Field(default_factory=ExposureInfo)
    poi: ExposureInfo = Field(default_factory=ExposureInfo)
    building: ExposureInfo = Field(default_factory=ExposureInfo)
    detail: ExposureInfo = Field(default_factory=ExposureInfo)


class AddressStats(RepositoryBaseModel):
    total: ExposureInfo = Field(default_factory=ExposureInfo)
    levels: AddressLevelExposureStats = Field(default_factory=AddressLevelExposureStats)


class SlotStats(RepositoryBaseModel):
    name: ExposureInfo = Field(default_factory=ExposureInfo)
    phone: ExposureInfo = Field(default_factory=ExposureInfo)
    bank_number: ExposureInfo = Field(default_factory=ExposureInfo)
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
StorageSlot = list[SharedSlotStorage]


class NameSlotStorage(RepositoryBaseModel):
    full: SharedSlotStorage
    family: SharedSlotStorage | None = None
    given: SharedSlotStorage | None = None
    alias: SharedSlotStorage | None = None
    middle: SharedSlotStorage | None = None

    @model_validator(mode="after")
    def _validate_name(self) -> "NameSlotStorage":
        if not any((self.family, self.given, self.alias, self.middle)):
            raise ValueError("姓名必须至少包含一个拆分字段")
        return self


def _validate_address_levels(
    country: SharedSlotStorage | SharedSlotRuntime | None,
    province: SharedSlotStorage | SharedSlotRuntime | None,
    city: SharedSlotStorage | SharedSlotRuntime | None,
    district: SharedSlotStorage | SharedSlotRuntime | None,
    subdistrict: SharedSlotStorage | SharedSlotRuntime | None,
    road: SharedSlotStorage | SharedSlotRuntime | None,
    number: SharedSlotStorage | SharedSlotRuntime | None,
    poi: SharedSlotStorage | SharedSlotRuntime | None,
    building: SharedSlotStorage | SharedSlotRuntime | None,
    detail: SharedSlotStorage | SharedSlotRuntime | None,
) -> None:
    if not any((country, province, city, district, subdistrict, road, number, poi, building, detail)):
        raise ValueError("地址不能为空")


class AddressComponentSlot(RepositoryBaseModel):
    """扁平化的地址组件条目，供 scanner 作独立匹配源。

    - `level` 记录 component 自身承担的层级末端（MULTI_ADMIN 取最末 rank）。
    - `value` 为该层级的原文值，已由 ingestor 清洗/归一。
    - `strength` 为入库时预置的 ClaimStrength；`None` 表示由消费侧按字数兜底。
    """

    level: AddressLevel
    value: NonEmptyStr
    strength: ClaimStrength | None = None


class AddressSlotStorage(RepositoryBaseModel):
    country: SharedSlotStorage | None = None
    province: SharedSlotStorage | None = None
    city: SharedSlotStorage | None = None
    district: SharedSlotStorage | None = None
    subdistrict: SharedSlotStorage | None = None
    road: SharedSlotStorage | None = None
    number: SharedSlotStorage | None = None
    poi: SharedSlotStorage | None = None
    building: SharedSlotStorage | None = None
    detail: SharedSlotStorage | None = None
    # 扁平组件袋：除 10 级主结构外，额外承载 MULTI_ADMIN 展开与 suspect 子组件，
    # 作为 scanner 独立匹配源（与主结构 match_terms 并列，不替代）。
    components: list[AddressComponentSlot] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotStorage":
        # 允许 10 级主结构全为空但 components 非空的情形：扁平组件袋可独立承担地址语义。
        if not self.components:
            _validate_address_levels(
                self.country,
                self.province,
                self.city,
                self.district,
                self.subdistrict,
                self.road,
                self.number,
                self.poi,
                self.building,
                self.detail,
            )
        return self


class SharedSlotRuntime(RepositoryBaseModel):
    value: NonEmptyStr
    match_aliases: list[NonEmptyStr] = Field(default_factory=list)
    render_aliases: list[NonEmptyStr] = Field(default_factory=list)


AtomicSlotRuntime = SharedSlotRuntime
RuntimeSlot = list[SharedSlotRuntime]


class NameSlotRuntime(RepositoryBaseModel):
    full: SharedSlotRuntime
    family: SharedSlotRuntime | None = None
    given: SharedSlotRuntime | None = None
    alias: SharedSlotRuntime | None = None
    middle: SharedSlotRuntime | None = None

    @model_validator(mode="after")
    def _validate_name(self) -> "NameSlotRuntime":
        if not any((self.family, self.given, self.alias, self.middle)):
            raise ValueError("姓名必须至少包含一个拆分字段")
        return self


def _validate_slot_list(values: list[SharedSlotStorage] | list[SharedSlotRuntime] | None, *, field_name: str) -> None:
    if values is None:
        return
    if not values:
        raise ValueError(f"{field_name} 不能为空列表")


def _validate_address_slot_list(values: list[AddressSlotStorage] | list[AddressSlotRuntime] | None, *, field_name: str) -> None:
    if values is None:
        return
    if not values:
        raise ValueError(f"{field_name} 不能为空列表")


class AddressSlotRuntime(RepositoryBaseModel):
    country: SharedSlotRuntime | None = None
    province: SharedSlotRuntime | None = None
    city: SharedSlotRuntime | None = None
    district: SharedSlotRuntime | None = None
    subdistrict: SharedSlotRuntime | None = None
    road: SharedSlotRuntime | None = None
    number: SharedSlotRuntime | None = None
    poi: SharedSlotRuntime | None = None
    building: SharedSlotRuntime | None = None
    detail: SharedSlotRuntime | None = None
    components: list[AddressComponentSlot] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_address(self) -> "AddressSlotRuntime":
        if not self.components:
            _validate_address_levels(
                self.country,
                self.province,
                self.city,
                self.district,
                self.subdistrict,
                self.road,
                self.number,
                self.poi,
                self.building,
                self.detail,
            )
        return self


class PersonaSlots(RepositoryBaseModel):
    name: list[NameSlotStorage] | None = None
    phone: list[SharedSlotStorage] | None = None
    bank_number: list[SharedSlotStorage] | None = None
    passport_number: list[SharedSlotStorage] | None = None
    driver_license: list[SharedSlotStorage] | None = None
    email: list[SharedSlotStorage] | None = None
    address: list[AddressSlotStorage] | None = None
    id_number: list[SharedSlotStorage] | None = None
    organization: list[SharedSlotStorage] | None = None

    @model_validator(mode="after")
    def _validate_non_empty(self) -> "PersonaSlots":
        _validate_slot_list(self.name, field_name="name")
        _validate_slot_list(self.phone, field_name="phone")
        _validate_slot_list(self.bank_number, field_name="bank_number")
        _validate_slot_list(self.passport_number, field_name="passport_number")
        _validate_slot_list(self.driver_license, field_name="driver_license")
        _validate_slot_list(self.email, field_name="email")
        _validate_address_slot_list(self.address, field_name="address")
        _validate_slot_list(self.id_number, field_name="id_number")
        _validate_slot_list(self.organization, field_name="organization")
        if not any(
            (
                self.name,
                self.phone,
                self.bank_number,
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
    name: list[NameSlotRuntime] | None = None
    phone: list[SharedSlotRuntime] | None = None
    bank_number: list[SharedSlotRuntime] | None = None
    passport_number: list[SharedSlotRuntime] | None = None
    driver_license: list[SharedSlotRuntime] | None = None
    email: list[SharedSlotRuntime] | None = None
    address: list[AddressSlotRuntime] | None = None
    id_number: list[SharedSlotRuntime] | None = None
    organization: list[SharedSlotRuntime] | None = None


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


def _project_name_slot_to_runtime(slot: NameSlotStorage, alias_role: AliasRole) -> NameSlotRuntime:
    return NameSlotRuntime(
        full=_project_scalar_slot_to_runtime(slot.full, alias_role),
        family=_project_scalar_slot_to_runtime(slot.family, alias_role) if slot.family else None,
        given=_project_scalar_slot_to_runtime(slot.given, alias_role) if slot.given else None,
        alias=_project_scalar_slot_to_runtime(slot.alias, alias_role) if slot.alias else None,
        middle=_project_scalar_slot_to_runtime(slot.middle, alias_role) if slot.middle else None,
    )


def project_storage_slot_to_runtime(
    slot: StorageSlot | list[AddressSlotStorage] | list[NameSlotStorage],
    alias_role: AliasRole,
) -> RuntimeSlot | list[AddressSlotRuntime] | list[NameSlotRuntime]:
    if not slot:
        return []
    first = slot[0]
    if isinstance(first, NameSlotStorage):
        return [_project_name_slot_to_runtime(item, alias_role) for item in slot]
    if isinstance(first, AddressSlotStorage):
        return [
            AddressSlotRuntime(
                components=[component.model_copy(deep=True) for component in item.components],
                **{
                    field_name: _project_scalar_slot_to_runtime(level_slot, alias_role)
                    for field_name in _ADDRESS_LEVEL_FIELDS
                    if (level_slot := getattr(item, field_name, None)) is not None
                },
            )
            for item in slot
        ]
    return [_project_scalar_slot_to_runtime(item, alias_role) for item in slot]


def _project_slots_to_runtime(slots: PersonaSlots, alias_role: AliasRole) -> PersonaSlotsRuntime:
    return PersonaSlotsRuntime(
        name=project_storage_slot_to_runtime(slots.name, alias_role) if slots.name else None,
        phone=project_storage_slot_to_runtime(slots.phone, alias_role) if slots.phone else None,
        bank_number=project_storage_slot_to_runtime(slots.bank_number, alias_role) if slots.bank_number else None,
        passport_number=project_storage_slot_to_runtime(slots.passport_number, alias_role) if slots.passport_number else None,
        driver_license=project_storage_slot_to_runtime(slots.driver_license, alias_role) if slots.driver_license else None,
        email=project_storage_slot_to_runtime(slots.email, alias_role) if slots.email else None,
        address=project_storage_slot_to_runtime(slots.address, alias_role) if slots.address else None,
        id_number=project_storage_slot_to_runtime(slots.id_number, alias_role) if slots.id_number else None,
        organization=project_storage_slot_to_runtime(slots.organization, alias_role) if slots.organization else None,
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
    "AddressComponentSlot",
    "AddressLevel",
    "AddressLevelExposureStats",
    "AddressSlotRuntime",
    "AddressSlotStorage",
    "AddressStats",
    "AliasRole",
    "ClaimStrength",
    "AtomicSlotRuntime",
    "AtomicSlotStorage",
    "ExposureInfo",
    "NameSlotRuntime",
    "NameSlotStorage",
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
