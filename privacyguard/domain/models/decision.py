"""决策领域模型定义。"""

from pydantic import BaseModel, Field

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox


def clone_action_metadata(metadata: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """复制 action/candidate metadata，避免共享可变 list。"""
    if not metadata:
        return {}
    return {key: list(values) for key, values in metadata.items()}


class DecisionAction(BaseModel):
    """表示对单个候选实体的决策动作。"""

    candidate_id: str
    action_type: ActionType
    attr_type: PIIAttributeType
    source: PIISourceType = PIISourceType.PROMPT
    replacement_text: str | None = None
    source_text: str | None = None
    persona_id: str | None = None
    bbox: BoundingBox | None = None
    block_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None
    reason: str = ""
    metadata: dict[str, list[str]] = Field(default_factory=dict)


class DecisionPlan(BaseModel):
    """表示整轮输入的动作计划。"""

    session_id: str
    turn_id: int = Field(ge=0)
    active_persona_id: str | None = None
    actions: list[DecisionAction] = Field(default_factory=list)
    summary: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
