"""本地隐私仓库写入入口。"""

from typing import Any

from privacyguard.app.schemas import PrivacyRepositoryWriteRequestModel, PrivacyRepositoryWriteResponseModel
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class PrivacyRepository:
    """面向应用层的本地隐私仓库写入入口。"""

    def __init__(
        self,
        repository: JsonPersonaRepository | None = None,
        *,
        path: str | None = None,
    ) -> None:
        """初始化写入入口；未提供 repository 时默认写入本地 persona JSON。"""
        self.repository = repository or JsonPersonaRepository(path=path)

    def write(self, payload: dict[str, Any]) -> dict[str, Any]:
        """写入结构化 persona 数据，并返回写入摘要。"""
        request = PrivacyRepositoryWriteRequestModel.from_payload(payload)
        personas = [
            item.build_profile(existing=self.repository.get_persona(item.persona_id))
            for item in request.personas
        ]
        self.repository.upsert_personas(personas)
        return PrivacyRepositoryWriteResponseModel.from_request(
            request,
            repository_path=str(self.repository.path),
        ).to_dict()
