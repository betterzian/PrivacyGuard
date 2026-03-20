"""基于 JSON 文件的 Persona 仓库实现。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile

DEFAULT_PERSONA_REPOSITORY_PATH = "data/privacy_repository.json"
DEFAULT_PERSONA_SAMPLE_PATH = "data/personas.sample.json"

PROFILE_KEY_TO_ATTR_TYPE = {
    "name": PIIAttributeType.NAME,
    "phone": PIIAttributeType.PHONE,
    "card_number": PIIAttributeType.CARD_NUMBER,
    "bank_account": PIIAttributeType.BANK_ACCOUNT,
    "passport_number": PIIAttributeType.PASSPORT_NUMBER,
    "driver_license": PIIAttributeType.DRIVER_LICENSE,
    "email": PIIAttributeType.EMAIL,
    "address": PIIAttributeType.ADDRESS,
    "id_number": PIIAttributeType.ID_NUMBER,
    "organization": PIIAttributeType.ORGANIZATION,
}

ATTR_TYPE_TO_PROFILE_KEY = {value: key for key, value in PROFILE_KEY_TO_ATTR_TYPE.items()}


class JsonPersonaRepository:
    """从本地 JSON 加载并查询 persona 数据。"""

    def __init__(self, path: str | None = None) -> None:
        """初始化仓库并预加载 persona 数据。"""
        self.path = Path(path) if path else Path(DEFAULT_PERSONA_REPOSITORY_PATH)
        self._source_path = self._resolve_source_path(explicit_path=path is not None)
        self._personas = self._load_personas(self._source_path)

    def _resolve_source_path(self, *, explicit_path: bool) -> Path:
        """优先读取显式路径或本地仓库，缺省时回退到样例仓库。"""
        if self.path.exists():
            return self.path
        if explicit_path:
            return self.path
        fallback_path = Path(DEFAULT_PERSONA_SAMPLE_PATH)
        if fallback_path.exists():
            return fallback_path
        return self.path

    def _load_personas(self, source_path: Path) -> dict[str, PersonaProfile]:
        """读取 JSON 并转换为强类型 persona 索引。"""
        if not source_path.exists():
            return {}
        raw_payload = json.loads(source_path.read_text(encoding="utf-8"))
        if isinstance(raw_payload, dict):
            raw_items = raw_payload.get("personas", [])
        elif isinstance(raw_payload, list):
            raw_items = raw_payload
        else:
            raw_items = []
        personas: dict[str, PersonaProfile] = {}
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            persona_id = str(item.get("persona_id", "")).strip()
            if not persona_id:
                continue
            raw_slots = item.get("slots", {})
            slots = self._to_slots(raw_slots)
            display_name = str(item.get("display_name") or slots.get(PIIAttributeType.NAME) or persona_id)
            stats_data = item.get("stats", {})
            metadata = self._to_metadata(item.get("metadata", {}))
            personas[persona_id] = PersonaProfile(
                persona_id=persona_id,
                display_name=display_name,
                slots=slots,
                metadata=metadata,
                stats=self._to_stats(stats_data),
            )
        return personas

    def _to_slots(
        self,
        raw_slots: dict[str, object] | object,
    ) -> dict[PIIAttributeType, str]:
        """将 slots 文本键映射为统一 attr_type 槽位。"""
        slots: dict[PIIAttributeType, str] = {}
        if not isinstance(raw_slots, dict):
            return slots
        for key, value in raw_slots.items():
            attr_type = PROFILE_KEY_TO_ATTR_TYPE.get(str(key).strip().lower())
            if attr_type is None or value is None:
                continue
            slots[attr_type] = str(value)
        return slots

    def _to_metadata(self, metadata_data: dict[str, object] | object) -> dict[str, str]:
        """将 metadata 节点转换为字符串字典。"""
        if not isinstance(metadata_data, dict):
            return {}
        return {
            str(key): str(value)
            for key, value in metadata_data.items()
            if key is not None and value is not None
        }

    def _to_stats(self, stats_data: dict[str, object] | object) -> dict[str, int | str | None]:
        """将 stats 节点转换为标准字典。"""
        if not isinstance(stats_data, dict):
            stats_data = {}
        return {
            "exposure_count": int(stats_data.get("exposure_count", 0)),
            "last_exposed_session_id": stats_data.get("last_exposed_session_id"),
            "last_exposed_turn_id": stats_data.get("last_exposed_turn_id"),
        }

    def upsert_persona(self, persona: PersonaProfile) -> None:
        """新增或更新单个 persona，并持久化到本地仓库。"""
        self._personas[persona.persona_id] = persona
        self._flush_to_file()

    def upsert_personas(self, personas: list[PersonaProfile]) -> None:
        """批量新增或更新 persona，并持久化到本地仓库。"""
        if not personas:
            return
        for persona in personas:
            self._personas[persona.persona_id] = persona
        self._flush_to_file()

    def _flush_to_file(self) -> None:
        """使用原子替换方式安全写入 persona JSON。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [self._serialize_persona(persona) for persona in self._personas.values()]
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
        self._source_path = self.path

    def _serialize_persona(self, persona: PersonaProfile) -> dict[str, object]:
        """将 PersonaProfile 转换为稳定的 JSON 结构。"""
        item: dict[str, object] = {
            "persona_id": persona.persona_id,
            "slots": self._serialize_profile(persona),
            "stats": self._to_stats(persona.stats),
        }
        if persona.display_name and persona.display_name != persona.persona_id:
            item["display_name"] = persona.display_name
        if persona.metadata:
            item["metadata"] = dict(persona.metadata)
        return item

    def _serialize_profile(self, persona: PersonaProfile) -> dict[str, str]:
        """将 persona 槽位转换为对外 slots 字段。"""
        slots: dict[str, str] = {}
        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            value = persona.slots.get(attr_type)
            if value is None:
                continue
            slots[key] = value
        return slots

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
