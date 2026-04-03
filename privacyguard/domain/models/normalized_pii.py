"""统一 PII 归一结果模型。"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from privacyguard.domain.enums import PIIAttributeType


class NormalizedPII(BaseModel):
    """承载统一 canonical、组件、匹配词与身份信息。"""

    model_config = ConfigDict(extra="forbid")

    attr_type: PIIAttributeType
    raw_text: str
    canonical: str = ""
    components: dict[str, str] = Field(default_factory=dict)
    match_terms: tuple[str, ...] = ()
    identity: dict[str, str] = Field(default_factory=dict)


__all__ = ["NormalizedPII"]
