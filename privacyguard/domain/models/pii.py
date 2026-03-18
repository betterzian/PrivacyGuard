"""PII 领域模型定义。"""

from pydantic import BaseModel, Field

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox


class PIICandidate(BaseModel):
    """表示一次检测得到的隐私候选实体。"""

    entity_id: str
    text: str
    normalized_text: str
    attr_type: PIIAttributeType
    source: PIISourceType
    bbox: BoundingBox | None = None
    block_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    metadata: dict[str, list[str]] = Field(default_factory=dict)
