from dataclasses import asdict, dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from privacyguard.api.dto import RestoreRequest, RestoreResponse, SanitizeRequest, SanitizeResponse


class SanitizePayloadModel(BaseModel):
    """sanitize 边界入参模型（dict 解析用）。"""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    turn_id: int = Field(default=0, ge=0)
    prompt: str
    image: Any | None = None


class RestorePayloadModel(BaseModel):
    """restore 边界入参模型（dict 解析用）。"""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    turn_id: int = Field(default=0, ge=0)
    agent_text: str


@dataclass(slots=True)
class SanitizeRequestModel:
    """sanitize 内部请求模型。"""

    session_id: str
    turn_id: int
    prompt: str
    image: Any | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SanitizeRequestModel":
        """从边界 payload 创建内部请求对象。"""
        dto = SanitizePayloadModel.model_validate(payload)
        return cls(
            session_id=dto.session_id,
            turn_id=dto.turn_id,
            prompt=dto.prompt,
            image=dto.image,
        )

    def to_dto(self) -> SanitizeRequest:
        """转换为 application 流程使用的 DTO。"""
        return SanitizeRequest(
            session_id=self.session_id,
            turn_id=self.turn_id,
            prompt_text=self.prompt,
            screenshot=self.image,
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
