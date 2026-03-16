"""基于 JSON 文件的 Persona 仓库实现。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile


class JsonPersonaRepository:
    """从本地 JSON 加载并查询 persona 数据。"""

    def __init__(self, path: str = "data/personas.sample.json") -> None:
        """初始化仓库并预加载 persona 数据。"""
        self.path = Path(path)
        self._personas = self._load_personas()

    def _load_personas(self) -> dict[str, PersonaProfile]:
        """读取 JSON 并转换为强类型 persona 索引。"""
        if not self.path.exists():
            return {}
        raw_items = json.loads(self.path.read_text(encoding="utf-8"))
        personas: dict[str, PersonaProfile] = {}
        for item in raw_items:
            persona_id = str(item.get("persona_id", "")).strip()
            if not persona_id:
                continue
            profile_data = item.get("profile", {})
            slots = self._to_slots(profile_data)
            display_name = str(profile_data.get("name", persona_id))
            stats_data = item.get("stats", {})
            personas[persona_id] = PersonaProfile(
                persona_id=persona_id,
                display_name=display_name,
                slots=slots,
                stats=self._to_stats(stats_data),
            )
        return personas

    def _to_slots(self, profile_data: dict[str, object]) -> dict[PIIAttributeType, str]:
        """将 profile 文本键映射为统一 attr_type 槽位。"""
        mapping = {
            "name": PIIAttributeType.NAME,
            "phone": PIIAttributeType.PHONE,
            "email": PIIAttributeType.EMAIL,
            "address": PIIAttributeType.ADDRESS,
            "id_number": PIIAttributeType.ID_NUMBER,
            "organization": PIIAttributeType.ORGANIZATION,
        }
        slots: dict[PIIAttributeType, str] = {}
        for key, value in profile_data.items():
            attr_type = mapping.get(str(key).strip().lower())
            if attr_type is None:
                continue
            slots[attr_type] = str(value)
        return slots

    def _to_stats(self, stats_data: dict[str, object]) -> dict[str, int | str | None]:
        """将 stats 节点转换为标准字典。"""
        return {
            "exposure_count": int(stats_data.get("exposure_count", 0)),
            "last_exposed_session_id": stats_data.get("last_exposed_session_id"),
            "last_exposed_turn_id": stats_data.get("last_exposed_turn_id"),
        }

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        """按 persona_id 读取 persona。"""
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        """返回所有 persona 列表。"""
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        """按 persona_id 与属性类型读取槽位。"""
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        return persona.slots.get(attr_type)

