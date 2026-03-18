"""API 层 DTO 定义。"""

from typing import Any

from pydantic import BaseModel, Field

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.mapping import ReplacementRecord

ImageLike = Any


class SanitizeRequest(BaseModel):
    """SANITIZE 入参：上传前脱敏请求。"""

    session_id: str
    turn_id: int = Field(ge=0)
    prompt_text: str
    screenshot: ImageLike | None = None
    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    detector_overrides: dict[PIIAttributeType, float] = Field(default_factory=dict)


class SanitizeResponse(BaseModel):
    """SANITIZE 出参：脱敏结果。"""

    sanitized_prompt_text: str
    sanitized_screenshot: ImageLike | None = None
    active_persona_id: str | None = None
    replacements: list[ReplacementRecord] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class RestoreRequest(BaseModel):
    """RESTORE 入参：云端返回后还原请求。"""

    session_id: str
    turn_id: int = Field(ge=0)
    cloud_text: str


class RestoreResponse(BaseModel):
    """RESTORE 出参：还原结果。"""

    restored_text: str
    restored_slots: list[RestoredSlot] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
