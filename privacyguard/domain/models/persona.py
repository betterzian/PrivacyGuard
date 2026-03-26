"""Persona 领域模型定义。"""

from pydantic import BaseModel, Field

from privacyguard.domain.enums import PIIAttributeType


class PersonaSlotValue(BaseModel):
    """表示 persona 在某一属性上的槽位值。"""

    attr_type: PIIAttributeType
    value: str


class PersonaProfile(BaseModel):
    """表示可用于替换的 persona 配置。"""

    persona_id: str
    display_name: str
    slots: dict[PIIAttributeType, list[str]] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)
    stats: dict[str, int | str | None] = Field(default_factory=dict)
