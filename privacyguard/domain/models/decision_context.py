"""Decision 上下文领域模型定义。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate


class DecisionContext(BaseModel):
    """提供给所有决策引擎的统一上下文。"""

    session_id: str
    turn_id: int = Field(ge=0)
    prompt_text: str = ""
    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    detector_overrides: dict[PIIAttributeType, float] = Field(default_factory=dict)
    ocr_blocks: list[OCRTextBlock] = Field(default_factory=list)
    candidates: list[PIICandidate] = Field(default_factory=list)
    session_binding: SessionBinding | None = None
    history_records: list[ReplacementRecord] = Field(default_factory=list)
    persona_profiles: list[PersonaProfile] = Field(default_factory=list)
