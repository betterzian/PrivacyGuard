"""Decision 上下文领域模型定义。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate


class PageDecisionFeatures(BaseModel):
    """页面级摘要特征。"""

    prompt_length: int = Field(ge=0, default=0)
    ocr_block_count: int = Field(ge=0, default=0)
    candidate_count: int = Field(ge=0, default=0)
    unique_attr_count: int = Field(ge=0, default=0)
    history_record_count: int = Field(ge=0, default=0)
    active_persona_bound: bool = False
    prompt_has_digits: bool = False
    prompt_has_address_tokens: bool = False
    average_candidate_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    min_candidate_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    high_confidence_candidate_ratio: float = Field(ge=0.0, le=1.0, default=0.0)
    low_confidence_candidate_ratio: float = Field(ge=0.0, le=1.0, default=0.0)
    prompt_candidate_count: int = Field(ge=0, default=0)
    ocr_candidate_count: int = Field(ge=0, default=0)
    average_ocr_block_score: float = Field(ge=0.0, le=1.0, default=0.0)
    min_ocr_block_score: float = Field(ge=0.0, le=1.0, default=0.0)
    low_confidence_ocr_block_ratio: float = Field(ge=0.0, le=1.0, default=0.0)


class CandidateDecisionFeatures(BaseModel):
    """单个隐私候选对应的决策特征。"""

    candidate_id: str
    text: str
    normalized_text: str
    attr_type: PIIAttributeType
    source: PIISourceType
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    bbox: BoundingBox | None = None
    block_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None
    prompt_context: str = ""
    ocr_context: str = ""
    history_attr_exposure_count: int = Field(ge=0, default=0)
    history_exact_match_count: int = Field(ge=0, default=0)
    same_attr_page_count: int = Field(ge=0, default=0)
    same_text_page_count: int = Field(ge=0, default=0)
    relative_area: float = Field(ge=0.0, default=0.0)
    aspect_ratio: float = Field(ge=0.0, default=0.0)
    center_x: float = Field(ge=0.0, le=1.0, default=0.0)
    center_y: float = Field(ge=0.0, le=1.0, default=0.0)
    ocr_block_score: float = Field(ge=0.0, le=1.0, default=0.0)
    ocr_block_rotation_degrees: float = 0.0
    is_low_ocr_confidence: bool = False
    is_prompt_source: bool = False
    is_ocr_source: bool = False


class PersonaDecisionFeatures(BaseModel):
    """单个 persona 的摘要特征。"""

    persona_id: str
    display_name: str
    slot_count: int = Field(ge=0, default=0)
    exposure_count: int = Field(ge=0, default=0)
    last_exposed_session_id: str | None = None
    last_exposed_turn_id: int | None = None
    is_active: bool = False
    supported_attr_types: list[PIIAttributeType] = Field(default_factory=list)
    matched_candidate_attr_count: int = Field(ge=0, default=0)
    slots: dict[PIIAttributeType, str] = Field(default_factory=dict)


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
    page_features: PageDecisionFeatures = Field(default_factory=PageDecisionFeatures)
    candidate_features: list[CandidateDecisionFeatures] = Field(default_factory=list)
    persona_features: list[PersonaDecisionFeatures] = Field(default_factory=list)
