from dataclasses import asdict, dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from privacyguard.api.dto import RestoreRequest, RestoreResponse, SanitizeRequest, SanitizeResponse
from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.persona import PersonaProfile

PERSONA_SLOT_KEY_TO_ATTR_TYPE = {
    "name": PIIAttributeType.NAME,
    "phone": PIIAttributeType.PHONE,
    "card_number": PIIAttributeType.CARD_NUMBER,
    "bank_account": PIIAttributeType.BANK_ACCOUNT,
    "passport_number": PIIAttributeType.PASSPORT_NUMBER,
    "driver_license": PIIAttributeType.DRIVER_LICENSE,
    "email": PIIAttributeType.EMAIL,
    "address": PIIAttributeType.ADDRESS,
    "id_number": PIIAttributeType.ID_NUMBER,
    "organization": PIIAttributeType.ORGANIZATION,
}


class DetectorOverridesModel(BaseModel):
    """请求层允许覆盖的 detector rule 阈值。"""

    model_config = ConfigDict(extra="forbid")

    name: float | None = Field(default=None, ge=0.0, le=1.0)
    location_clue: float | None = Field(default=None, ge=0.0, le=1.0)
    address: float | None = Field(default=None, ge=0.0, le=1.0)
    organization: float | None = Field(default=None, ge=0.0, le=1.0)
    other: float | None = Field(default=None, ge=0.0, le=1.0)

    def to_attr_map(self) -> dict[PIIAttributeType, float]:
        mapping = {
            "name": PIIAttributeType.NAME,
            "location_clue": PIIAttributeType.LOCATION_CLUE,
            "address": PIIAttributeType.ADDRESS,
            "organization": PIIAttributeType.ORGANIZATION,
            "other": PIIAttributeType.OTHER,
        }
        result: dict[PIIAttributeType, float] = {}
        for key, value in self.model_dump(exclude_none=True).items():
            attr_type = mapping.get(key)
            if attr_type is not None:
                result[attr_type] = float(value)
        return result


class SanitizePayloadModel(BaseModel):
    """sanitize 边界入参模型（dict 解析用）。"""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    turn_id: int = Field(default=0, ge=0)
    prompt_text: str
    screenshot: Any | None = None
    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    detector_overrides: DetectorOverridesModel | None = None


class RestorePayloadModel(BaseModel):
    """restore 边界入参模型（dict 解析用）。"""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    turn_id: int = Field(default=0, ge=0)
    agent_text: str


class PersonaStatsPayloadModel(BaseModel):
    """Persona 仓库允许写入的 stats 字段。"""

    model_config = ConfigDict(extra="forbid")

    exposure_count: int | None = Field(default=None, ge=0)
    last_exposed_session_id: str | None = None
    last_exposed_turn_id: int | None = Field(default=None, ge=0)


class PersonaWritePayloadModel(BaseModel):
    """单个 persona 写入载荷。"""

    model_config = ConfigDict(extra="forbid")

    persona_id: str
    display_name: str | None = None
    slots: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)
    stats: PersonaStatsPayloadModel | None = None


class PersonaRepositoryWritePayloadModel(BaseModel):
    """Persona 仓库写入入口载荷。"""

    model_config = ConfigDict(extra="forbid")

    personas: list[PersonaWritePayloadModel] = Field(min_length=1)


@dataclass(slots=True)
class SanitizeRequestModel:
    """sanitize 内部请求模型。"""

    session_id: str
    turn_id: int
    prompt_text: str
    screenshot: Any | None = None
    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    detector_overrides: dict[PIIAttributeType, float] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SanitizeRequestModel":
        """从边界 payload 创建内部请求对象。"""
        dto = SanitizePayloadModel.model_validate(payload)
        return cls(
            session_id=dto.session_id,
            turn_id=dto.turn_id,
            prompt_text=dto.prompt_text,
            screenshot=dto.screenshot,
            protection_level=dto.protection_level,
            detector_overrides=dto.detector_overrides.to_attr_map() if dto.detector_overrides else {},
        )

    def to_dto(self) -> SanitizeRequest:
        """转换为 application 流程使用的 DTO。"""
        return SanitizeRequest(
            session_id=self.session_id,
            turn_id=self.turn_id,
            prompt_text=self.prompt_text,
            screenshot=self.screenshot,
            protection_level=self.protection_level,
            detector_overrides=self.detector_overrides,
        )


@dataclass(slots=True)
class SanitizeResponseModel:
    """sanitize 对外响应模型。"""

    status: str
    masked_prompt: str
    masked_image: Any | None
    session_id: str
    turn_id: int
    mapping_count: int
    active_persona_id: str | None

    @classmethod
    def from_pipeline_result(cls, request: SanitizeRequestModel, dto: SanitizeResponse) -> "SanitizeResponseModel":
        """从 pipeline 结果构造边界响应对象。"""
        return cls(
            status="ok",
            masked_prompt=dto.sanitized_prompt_text,
            masked_image=dto.sanitized_screenshot,
            session_id=request.session_id,
            turn_id=request.turn_id,
            mapping_count=len(dto.replacements),
            active_persona_id=dto.active_persona_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """转换为对外返回字典。"""
        return asdict(self)


@dataclass(slots=True)
class RestoreRequestModel:
    """restore 内部请求模型。"""

    session_id: str
    turn_id: int
    agent_text: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RestoreRequestModel":
        """从边界 payload 创建内部请求对象。"""
        dto = RestorePayloadModel.model_validate(payload)
        return cls(session_id=dto.session_id, turn_id=dto.turn_id, agent_text=dto.agent_text)

    def to_dto(self) -> RestoreRequest:
        """转换为 application 流程使用的 DTO。"""
        return RestoreRequest(session_id=self.session_id, turn_id=self.turn_id, cloud_text=self.agent_text)


@dataclass(slots=True)
class PersonaRepositoryWriteItemModel:
    """Persona 仓库单条 upsert 请求。"""

    persona_id: str
    display_name: str | None = None
    slot_updates: dict[PIIAttributeType, str] = field(default_factory=dict)
    metadata_updates: dict[str, str] = field(default_factory=dict)
    stats_updates: dict[str, int | str | None] = field(default_factory=dict)

    def build_profile(self, existing: PersonaProfile | None = None) -> PersonaProfile:
        """合并已有 persona，生成新的 PersonaProfile。"""
        slots = dict(existing.slots) if existing else {}
        slots.update(self.slot_updates)

        metadata = dict(existing.metadata) if existing else {}
        metadata.update(self.metadata_updates)

        stats = {
            "exposure_count": 0,
            "last_exposed_session_id": None,
            "last_exposed_turn_id": None,
        }
        if existing:
            stats.update(existing.stats)
        stats.update(self.stats_updates)

        if self.display_name:
            display_name = self.display_name
        elif PIIAttributeType.NAME in self.slot_updates:
            display_name = self.slot_updates[PIIAttributeType.NAME]
        elif existing and existing.display_name:
            display_name = existing.display_name
        elif PIIAttributeType.NAME in slots:
            display_name = slots[PIIAttributeType.NAME]
        else:
            display_name = self.persona_id

        return PersonaProfile(
            persona_id=self.persona_id,
            display_name=display_name,
            slots=slots,
            metadata=metadata,
            stats=stats,
        )


@dataclass(slots=True)
class PersonaRepositoryWriteRequestModel:
    """Persona 仓库批量写入请求。"""

    personas: list[PersonaRepositoryWriteItemModel]

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "PersonaRepositoryWriteRequestModel":
        """从边界 payload 创建 persona 仓库写入请求。"""
        dto = PersonaRepositoryWritePayloadModel.model_validate(payload)
        return cls(personas=[_to_persona_repository_item(item) for item in dto.personas])


@dataclass(slots=True)
class PersonaRepositoryWriteResponseModel:
    """Persona 仓库写入响应。"""

    status: str
    repository_path: str
    written_count: int
    persona_ids: list[str]

    @classmethod
    def from_request(
        cls,
        request: PersonaRepositoryWriteRequestModel,
        *,
        repository_path: str,
    ) -> "PersonaRepositoryWriteResponseModel":
        """根据写入请求生成响应。"""
        return cls(
            status="ok",
            repository_path=repository_path,
            written_count=len(request.personas),
            persona_ids=[item.persona_id for item in request.personas],
        )

    def to_dict(self) -> dict[str, Any]:
        """转换为对外返回字典。"""
        return asdict(self)


@dataclass(slots=True)
class RestoreResponseModel:
    """restore 对外响应模型。"""

    status: str
    restored_text: str
    session_id: str

    @classmethod
    def from_pipeline_result(cls, request: RestoreRequestModel, dto: RestoreResponse) -> "RestoreResponseModel":
        """从 pipeline 结果构造边界响应对象。"""
        return cls(
            status="ok",
            restored_text=dto.restored_text,
            session_id=request.session_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """转换为对外返回字典。"""
        return asdict(self)


def _to_persona_repository_item(dto: PersonaWritePayloadModel) -> PersonaRepositoryWriteItemModel:
    """将 payload 模型转换为内部 persona 写入请求项。"""
    slot_updates = _normalize_persona_slot_map(dto.slots)
    stats_updates = dto.stats.model_dump(exclude_unset=True) if dto.stats else {}
    return PersonaRepositoryWriteItemModel(
        persona_id=dto.persona_id,
        display_name=dto.display_name,
        slot_updates=slot_updates,
        metadata_updates=dict(dto.metadata),
        stats_updates=stats_updates,
    )


def _normalize_persona_slot_map(raw_mapping: dict[str, str]) -> dict[PIIAttributeType, str]:
    """将 persona slots 的 key 归一化为 attr_type 映射。"""
    normalized: dict[PIIAttributeType, str] = {}
    for key, value in raw_mapping.items():
        attr_type = PERSONA_SLOT_KEY_TO_ATTR_TYPE.get(str(key).strip().lower())
        if attr_type is None:
            continue
        normalized[attr_type] = str(value)
    return normalized
