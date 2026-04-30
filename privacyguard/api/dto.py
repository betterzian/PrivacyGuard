"""API 层 DTO 定义。

本文件定义 PrivacyGuard 对外暴露的稳定请求/响应边界：

- `sanitize` / `restore` 的 DTO 形状属于外部稳定协议
- `protect_decision`、`rewrite_mode`、`page_policy_state` 等内部策略字段
  只能停留在内部 pipeline 层，不能泄漏到这些外部 DTO
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel, normalize_protection_level
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.mapping import ReplacementRecord

ImageLike = Any


class SanitizeRequest(BaseModel):
    """SANITIZE 入参：上传前脱敏请求。

    这是 PrivacyGuard 对外稳定输入边界的一部分；内部 pipeline 调整不应改变
    本 DTO 的字段形状。
    """

    session_id: str
    turn_id: int = Field(ge=0)
    prompt_text: str
    screenshot: ImageLike | None = None
    protection_level: ProtectionLevel = ProtectionLevel.STRONG
    detector_overrides: dict[PIIAttributeType, float] = Field(
        default_factory=dict,
        description="检测阶段的可选覆盖参数；属于外部请求输入，不承载内部决策字段。",
    )

    @field_validator("protection_level", mode="before")
    @classmethod
    def _coerce_protection_level(cls, v: object) -> ProtectionLevel:
        if isinstance(v, ProtectionLevel):
            return normalize_protection_level(v)
        if v is None:
            return normalize_protection_level(None)
        return normalize_protection_level(str(v))


class SanitizeResponse(BaseModel):
    """SANITIZE 出参：脱敏结果。

    这是 PrivacyGuard 对外稳定输出边界的一部分。响应只暴露主链执行结果，
    不直接暴露内部策略状态。
    """

    sanitized_prompt_text: str
    sanitized_screenshot: ImageLike | None = None
    active_persona_id: str | None = None
    replacements: list[ReplacementRecord] = Field(default_factory=list)
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "内部调试与运行信息容器；可包含 mode、统计值或运行时摘要，但不是对外稳定协议中"
            "算法字段的主载体，调用方不应依赖具体 metadata key。"
        ),
    )


class RestoreRequest(BaseModel):
    """RESTORE 入参：云端返回后还原请求。

    这是 PrivacyGuard 对外稳定输入边界的一部分；内部 pipeline 调整不应改变
    restore 的请求 DTO 形状。
    """

    session_id: str
    turn_id: int = Field(ge=0)
    cloud_text: str


class RestoreResponse(BaseModel):
    """RESTORE 出参：还原结果。

    对外仅返回 restore 主链结果与必要的辅助信息，不暴露内部策略层对象或训练标签。
    """

    restored_text: str
    restored_slots: list[RestoredSlot] = Field(default_factory=list)
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "内部调试与运行信息容器；用于携带 restore 侧摘要信息，不是对外稳定协议中"
            "算法语义字段的承诺位置。"
        ),
    )
