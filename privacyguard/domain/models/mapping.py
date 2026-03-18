"""映射表相关领域模型定义。"""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox


class ReplacementRecord(BaseModel):
    """记录一次可恢复替换动作。"""

    replacement_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str
    turn_id: int = Field(ge=0)
    candidate_id: str
    source_text: str
    replacement_text: str
    attr_type: PIIAttributeType
    action_type: ActionType
    bbox: BoundingBox | None = None
    block_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None
    persona_id: str | None = None
    source: PIISourceType = PIISourceType.PROMPT
    metadata: dict[str, str] = Field(default_factory=dict)


class SessionBinding(BaseModel):
    """记录会话与 persona 的绑定状态。"""

    session_id: str
    active_persona_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_turn_id: int | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class TurnMappingSnapshot(BaseModel):
    """记录某一轮次替换映射快照。"""

    session_id: str
    turn_id: int = Field(ge=0)
    records: list[ReplacementRecord] = Field(default_factory=list)
