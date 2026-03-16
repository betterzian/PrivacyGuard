"""Persona 仓库抽象接口。"""

from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile


class PersonaRepository(Protocol):
    """定义 persona 配置读取接口。"""

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        """按 persona_id 获取 persona。"""

    def list_personas(self) -> list[PersonaProfile]:
        """列出全部 persona。"""

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        """读取 persona 的属性槽位值。"""
