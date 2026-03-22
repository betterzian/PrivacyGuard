"""基于 JSON 文件的 Persona 仓库实现。"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.repository.schemas import (
    AddressLevelExposureStats,
    AddressSlotStorage,
    AddressStats,
    ExposureInfo,
    PersonaDocument,
    PersonaRepositoryDocument,
    PersonaSlots,
    PersonaStats,
    RepositoryStats,
    SharedSlotStorage,
    SlotStats,
)
from privacyguard.utils.pii_value import parse_address_components

DEFAULT_PERSONA_REPOSITORY_PATH = "data/persona_repository.json"
DEFAULT_PERSONA_SAMPLE_PATH = "data/personas.sample.json"


class InvalidPersonaRepositoryError(ValueError):
    """persona 仓库 JSON 不符合 schema（需含 ``fake_personas``）。"""

PROFILE_KEY_TO_ATTR_TYPE = {
    "name": PIIAttributeType.NAME,
    "location_clue": PIIAttributeType.LOCATION_CLUE,
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
_ADDRESS_RENDER_ORDER = ("province", "city", "district", "street", "building", "room")


def _runtime_stats_to_persona_stats(stats_data: dict[str, object] | object) -> PersonaStats:
    """将 runtime 扁平 stats 转为 ``PersonaStats``（仅填充 total 等常用字段）。"""
    if not isinstance(stats_data, dict):
        stats_data = {}
    sd = stats_data
    tid_raw = sd.get("last_exposed_turn_id")
    tid: int | None
    try:
        tid = int(tid_raw) if tid_raw is not None else None
    except (TypeError, ValueError):
        tid = None
    if tid is not None:
        tid = max(tid, 0)
    sid_raw = sd.get("last_exposed_session_id")
    sid = str(sid_raw).strip() if sid_raw is not None and str(sid_raw).strip() else None
    total = ExposureInfo(
        exposure_count=max(int(sd.get("exposure_count", 0) or 0), 0),
        last_exposed_session_id=sid,
        last_exposed_turn_id=tid,
    )
    return PersonaStats(total=total)


def _persona_profile_to_persona_document(persona: PersonaProfile) -> PersonaDocument:
    """将 ``PersonaProfile`` 转为 ``PersonaDocument``（扁平槽位写入 storage slot）。"""
    slot_values: dict[str, object] = {}
    for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
        raw = persona.slots.get(attr_type)
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        if attr_type == PIIAttributeType.ADDRESS:
            slot_values["address"] = AddressSlotStorage(
                street=SharedSlotStorage(value=text, aliases=[]),
            )
        else:
            slot_values[key] = SharedSlotStorage(value=text, aliases=[])
    if not slot_values:
        raise ValueError("PersonaProfile must contain at least one non-empty slot for storage")
    slots = PersonaSlots(**slot_values)
    display_name = persona.display_name
    if not display_name and slots.name:
        display_name = slots.name.value
    if not display_name:
        display_name = persona.persona_id
    meta: dict[str, str] = {}
    for mk, mv in (persona.metadata or {}).items():
        ks = str(mk).strip()
        if not ks:
            continue
        if mv is None:
            continue
        vs = str(mv).strip()
        if vs:
            meta[ks] = vs
    return PersonaDocument(
        persona_id=persona.persona_id,
        display_name=display_name,
        slots=slots,
        stats=_runtime_stats_to_persona_stats(persona.stats),
        metadata=meta,
    )


_ADDRESS_STREET_SIGNAL_RE = re.compile(r"(?:路|街|大道|道|巷|弄|胡同)")
_ADDRESS_CITY_SIGNAL_RE = re.compile(r"(?:自治州|地区|盟|市)")
_ADDRESS_DISTRICT_SIGNAL_RE = re.compile(r"(?:新区|自治县|自治旗|区|县|旗)")
_ADDRESS_BUILDING_SIGNAL_RE = re.compile(r"(?:号楼|栋|幢|座|单元)")
_ADDRESS_ROOM_SIGNAL_RE = re.compile(r"(?:室|房|层)")
_COUNTRY_PREFIXES = ("中国大陆", "中国")


def _merge_exposure_info(left: ExposureInfo, right: ExposureInfo) -> ExposureInfo:
    latest_at = left.last_exposed_at
    latest_session = left.last_exposed_session_id
    latest_turn = left.last_exposed_turn_id
    if right.last_exposed_at and (latest_at is None or right.last_exposed_at >= latest_at):
        latest_at = right.last_exposed_at
        latest_session = right.last_exposed_session_id
        latest_turn = right.last_exposed_turn_id
    return ExposureInfo(
        exposure_count=left.exposure_count + right.exposure_count,
        last_exposed_at=latest_at,
        last_exposed_session_id=latest_session,
        last_exposed_turn_id=latest_turn,
    )


def _merge_address_stats(left: AddressStats, right: AddressStats) -> AddressStats:
    return AddressStats(
        total=_merge_exposure_info(left.total, right.total),
        levels=AddressLevelExposureStats(
            country=_merge_exposure_info(left.levels.country, right.levels.country),
            province=_merge_exposure_info(left.levels.province, right.levels.province),
            city=_merge_exposure_info(left.levels.city, right.levels.city),
            district=_merge_exposure_info(left.levels.district, right.levels.district),
            street=_merge_exposure_info(left.levels.street, right.levels.street),
            building=_merge_exposure_info(left.levels.building, right.levels.building),
            room=_merge_exposure_info(left.levels.room, right.levels.room),
        ),
    )


def _aggregate_repository_stats(personas: list[PersonaDocument]) -> RepositoryStats:
    total = ExposureInfo()
    slot_totals = {
        "name": ExposureInfo(),
        "location_clue": ExposureInfo(),
        "phone": ExposureInfo(),
        "card_number": ExposureInfo(),
        "bank_account": ExposureInfo(),
        "passport_number": ExposureInfo(),
        "driver_license": ExposureInfo(),
        "email": ExposureInfo(),
        "id_number": ExposureInfo(),
        "organization": ExposureInfo(),
    }
    address_total = AddressStats()

    for persona in personas:
        total = _merge_exposure_info(total, persona.stats.total)
        for slot_name in slot_totals:
            slot_totals[slot_name] = _merge_exposure_info(slot_totals[slot_name], getattr(persona.stats.slots, slot_name))
        address_total = _merge_address_stats(address_total, persona.stats.address)

    slots_stats = SlotStats(
        name=slot_totals["name"],
        location_clue=slot_totals["location_clue"],
        phone=slot_totals["phone"],
        card_number=slot_totals["card_number"],
        bank_account=slot_totals["bank_account"],
        passport_number=slot_totals["passport_number"],
        driver_license=slot_totals["driver_license"],
        email=slot_totals["email"],
        address=address_total.model_copy(deep=True),
        id_number=slot_totals["id_number"],
        organization=slot_totals["organization"],
    )
    personas_stats = PersonaStats(
        total=total.model_copy(deep=True),
        slots=slots_stats.model_copy(deep=True),
        address=address_total.model_copy(deep=True),
    )
    return RepositoryStats(
        total=total,
        personas=personas_stats,
        slots=slots_stats,
        address=address_total,
    )


def _detail_fragment_mode(detail_text: str | None) -> str | None:
    if not detail_text:
        return None
    compact = str(detail_text).strip()
    if not compact:
        return None
    has_street = bool(_ADDRESS_STREET_SIGNAL_RE.search(compact))
    has_building = bool(_ADDRESS_BUILDING_SIGNAL_RE.search(compact))
    has_room = bool(_ADDRESS_ROOM_SIGNAL_RE.search(compact))
    if has_street and not has_building and not has_room:
        return "street"
    if not has_street and (has_building or has_room):
        return "building_room"
    return "tail"


def _split_country_prefix(source_text: str | None) -> tuple[bool, str]:
    compact = str(source_text or "").strip()
    for prefix in _COUNTRY_PREFIXES:
        if compact.startswith(prefix):
            return (True, compact[len(prefix):])
    return (False, compact)


class JsonPersonaRepository:
    """从本地 JSON 加载并查询 persona 数据。"""

    def __init__(self, path: str | None = None) -> None:
        """初始化仓库并预加载 persona 数据。"""
        self.path = Path(path) if path else Path(DEFAULT_PERSONA_REPOSITORY_PATH)
        self._source_path = self._resolve_source_path(explicit_path=path is not None)
        self._rng = random.Random()
        self._personas, self._stored_fake_personas = self._load_personas(self._source_path)

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

    def _load_personas(self, source_path: Path) -> tuple[dict[str, PersonaProfile], dict[str, PersonaDocument]]:
        """读取 JSON 并转换为 runtime persona 索引与 storage 索引。"""
        if not source_path.exists():
            return ({}, {})

        raw_payload = json.loads(source_path.read_text(encoding="utf-8"))
        document = self._load_document(raw_payload)

        personas: dict[str, PersonaProfile] = {}
        stored_fake_personas: dict[str, PersonaDocument] = {}
        for stored_persona in document.fake_personas:
            personas[stored_persona.persona_id] = self._build_runtime_persona(stored_persona)
            stored_fake_personas[stored_persona.persona_id] = stored_persona
        return (personas, stored_fake_personas)

    def _load_document(self, raw_payload: Any) -> PersonaRepositoryDocument:
        """加载 persona 仓库文档（``fake_personas``）。"""
        if not isinstance(raw_payload, dict):
            raise InvalidPersonaRepositoryError("persona 仓库顶层必须是 JSON 对象")
        return PersonaRepositoryDocument.model_validate(raw_payload)

    def _build_runtime_persona(self, stored_persona: PersonaDocument) -> PersonaProfile:
        """将 storage persona 投影为现有 runtime PersonaProfile。"""
        slots = self._flatten_runtime_slots(stored_persona)
        display_name = stored_persona.display_name or slots.get(PIIAttributeType.NAME) or stored_persona.persona_id
        return PersonaProfile(
            persona_id=stored_persona.persona_id,
            display_name=display_name,
            slots=slots,
            metadata=dict(stored_persona.metadata),
            stats=self._flatten_runtime_stats(stored_persona.stats),
        )

    def _flatten_runtime_slots(self, stored_persona: PersonaDocument) -> dict[PIIAttributeType, str]:
        """将 structured slots 扁平化为当前 runtime 仍在消费的字符串槽位。"""
        slots: dict[PIIAttributeType, str] = {}

        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            if attr_type == PIIAttributeType.ADDRESS:
                address_text = self._render_address_slot(stored_persona.slots.address, randomize=False)
                if address_text:
                    slots[attr_type] = address_text
                continue

            raw_slot = getattr(stored_persona.slots, key, None)
            if raw_slot is not None:
                slots[attr_type] = raw_slot.value

        return slots

    def _flatten_runtime_stats(self, stats: PersonaStats) -> dict[str, int | str | None]:
        """将 stats.total 投影为当前 runtime 兼容字典。"""
        return {
            "exposure_count": stats.total.exposure_count,
            "last_exposed_session_id": stats.total.last_exposed_session_id,
            "last_exposed_turn_id": stats.total.last_exposed_turn_id,
        }

    def _pick_render_text(self, slot: SharedSlotStorage, *, randomize: bool) -> str:
        if not randomize or not slot.aliases:
            return slot.value
        return self._rng.choice([slot.value, *slot.aliases])

    def _render_address_slot(
        self,
        slot: AddressSlotStorage | None,
        *,
        source_text: str | None = None,
        randomize: bool,
    ) -> str | None:
        if slot is None:
            return None

        if not source_text:
            parts = []
            province = self._pick_render_text(slot.province, randomize=randomize) if slot.province else None
            city = self._pick_render_text(slot.city, randomize=randomize) if slot.city else None
            district = self._pick_render_text(slot.district, randomize=randomize) if slot.district else None
            street = self._pick_render_text(slot.street, randomize=randomize) if slot.street else None
            building = self._pick_render_text(slot.building, randomize=randomize) if slot.building else None
            room = self._pick_render_text(slot.room, randomize=randomize) if slot.room else None

            if province:
                parts.append(province)
            if city and city != province:
                parts.append(city)
            if district:
                parts.append(district)
            for value in (street, building, room):
                if value:
                    parts.append(value)
            rendered = "".join(parts)
            return rendered or None

        source_has_country, source_remainder = _split_country_prefix(source_text)
        source_components = parse_address_components(source_remainder)
        detail_mode = _detail_fragment_mode(source_components.detail_text)

        selected = {
            level_name: self._pick_render_text(level_slot, randomize=randomize)
            for level_name in _ADDRESS_RENDER_ORDER
            if (level_slot := getattr(slot, level_name)) is not None
        }

        parts: list[str] = []
        province = selected.get("province")
        city = selected.get("city")
        district = selected.get("district")

        if source_has_country and slot.country is not None:
            parts.append(self._pick_render_text(slot.country, randomize=randomize))

        include_province = source_components.province_text is not None
        include_city = source_components.city_text is not None and bool(_ADDRESS_CITY_SIGNAL_RE.search(source_text))
        include_district = source_components.district_text is not None and (
            bool(_ADDRESS_DISTRICT_SIGNAL_RE.search(source_text))
            or include_province
            or include_city
        )

        if include_province and province:
            parts.append(province)
        if include_city and city and city != province:
            parts.append(city)
        if include_district and district:
            parts.append(district)

        if detail_mode == "street":
            for level_name in ("street",):
                value = selected.get(level_name)
                if value:
                    parts.append(value)
        elif detail_mode == "building_room":
            for level_name in ("building", "room"):
                value = selected.get(level_name)
                if value:
                    parts.append(value)
        elif detail_mode == "tail":
            for level_name in ("street", "building", "room"):
                value = selected.get(level_name)
                if value:
                    parts.append(value)
        elif not any((source_has_country, include_province, include_city, include_district)):
            for level_name in ("street", "building", "room"):
                value = selected.get(level_name)
                if value:
                    parts.append(value)

        rendered = "".join(parts)
        if rendered:
            return rendered

        if source_has_country:
            if not source_remainder:
                for level_name in ("province", "city", "district"):
                    value = selected.get(level_name)
                    if value:
                        return value
            fallback_country_parts = [
                selected.get("province"),
                selected.get("city") if selected.get("city") != selected.get("province") else None,
                selected.get("district"),
            ]
            fallback_country = "".join(part for part in fallback_country_parts if part)
            if fallback_country:
                return fallback_country

        fallback_parts = [
            selected.get("province"),
            selected.get("city") if selected.get("city") != selected.get("province") else None,
            selected.get("district"),
            selected.get("street"),
            selected.get("building"),
            selected.get("room"),
        ]
        fallback = "".join(part for part in fallback_parts if part)
        return fallback or None

    def _to_storage_document(self) -> PersonaRepositoryDocument:
        """将当前 storage persona 集合聚合并持久化为仓库文档。"""
        personas = list(self._stored_fake_personas.values())
        return PersonaRepositoryDocument(
            stats=_aggregate_repository_stats(personas),
            fake_personas=personas,
        )

    def _runtime_persona_to_storage(self, persona: PersonaProfile) -> PersonaDocument:
        """将 runtime PersonaProfile 提升回单条 storage persona。"""
        return _persona_profile_to_persona_document(persona)

    def _merge_runtime_persona_into_storage(
        self,
        persona: PersonaProfile,
        existing: PersonaDocument | None,
    ) -> PersonaDocument:
        """把 runtime 更新合并回 storage persona，并尽量保留原有 rich 结构。"""
        incoming = self._runtime_persona_to_storage(persona)
        if existing is None:
            return incoming

        merged_slot_values: dict[str, object] = {}
        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            current_slot = getattr(existing.slots, key, None)
            incoming_slot = getattr(incoming.slots, key, None)
            runtime_value = persona.slots.get(attr_type)

            if runtime_value is None:
                merged_slot_values[key] = current_slot
                continue

            if attr_type == PIIAttributeType.ADDRESS:
                current_value = self._render_address_slot(current_slot, randomize=False)
            else:
                current_value = current_slot.value if current_slot is not None else None

            if current_slot is not None and runtime_value == current_value:
                merged_slot_values[key] = current_slot
            else:
                merged_slot_values[key] = incoming_slot

        merged_stats = existing.stats.model_copy(deep=True)
        if "exposure_count" in persona.stats:
            merged_stats.total.exposure_count = int(persona.stats.get("exposure_count", 0) or 0)
        if "last_exposed_session_id" in persona.stats:
            merged_stats.total.last_exposed_session_id = persona.stats.get("last_exposed_session_id")
        if "last_exposed_turn_id" in persona.stats:
            merged_stats.total.last_exposed_turn_id = persona.stats.get("last_exposed_turn_id")

        metadata = dict(existing.metadata)
        metadata.update(persona.metadata)

        return PersonaDocument(
            persona_id=persona.persona_id,
            display_name=persona.display_name or existing.display_name or incoming.display_name,
            slots=incoming.slots.model_copy(update=merged_slot_values, deep=True),
            stats=merged_stats,
            metadata=metadata,
        )

    def _serialize_runtime_persona(self, persona: PersonaProfile) -> dict[str, object]:
        """将 runtime PersonaProfile 序列化为可 JSON 化的调试视图（扁平槽位）。"""
        item: dict[str, object] = {
            "persona_id": persona.persona_id,
            "slots": self._serialize_profile(persona),
            "stats": self._serialize_stats(persona.stats),
        }
        if persona.display_name and persona.display_name != persona.persona_id:
            item["display_name"] = persona.display_name
        if persona.metadata:
            item["metadata"] = dict(persona.metadata)
        return item

    def _serialize_profile(self, persona: PersonaProfile) -> dict[str, str]:
        """将 runtime persona 槽位转换为字符串字典。"""
        slots: dict[str, str] = {}
        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            value = persona.slots.get(attr_type)
            if value is None:
                continue
            slots[key] = value
        return slots

    def _serialize_stats(self, stats_data: dict[str, object] | object) -> dict[str, int | str | None]:
        """将 runtime stats 节点转换为扁平字典。"""
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
        self._stored_fake_personas[persona.persona_id] = self._merge_runtime_persona_into_storage(
            persona,
            self._stored_fake_personas.get(persona.persona_id),
        )
        self._flush_to_file()

    def upsert_personas(self, personas: list[PersonaProfile]) -> None:
        """批量新增或更新 persona，并持久化到本地仓库。"""
        if not personas:
            return
        for persona in personas:
            self._personas[persona.persona_id] = persona
            self._stored_fake_personas[persona.persona_id] = self._merge_runtime_persona_into_storage(
                persona,
                self._stored_fake_personas.get(persona.persona_id),
            )
        self._flush_to_file()

    def _flush_to_file(self) -> None:
        """使用原子替换方式安全写入 persona JSON。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = self._to_storage_document()
        payload = document.model_dump(mode="json", exclude_none=True)
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
        self._source_path = self.path
        self._personas = {
            persona.persona_id: self._build_runtime_persona(persona)
            for persona in document.fake_personas
        }
        self._stored_fake_personas = {
            persona.persona_id: persona
            for persona in document.fake_personas
        }

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        """按 persona_id 读取 persona。"""
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        """返回所有 persona 列表。"""
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        """按 persona_id 与属性类型读取 runtime 兼容槽位。"""
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        return persona.slots.get(attr_type)

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        """按源文本粒度与 render aliases 返回替换文本。"""
        stored_persona = self._stored_fake_personas.get(persona_id)
        if stored_persona is None:
            return self.get_slot_value(persona_id, attr_type)

        if attr_type == PIIAttributeType.ADDRESS:
            rendered = self._render_address_slot(
                stored_persona.slots.address,
                source_text=source_text,
                randomize=True,
            )
            if rendered:
                return rendered
            return self.get_slot_value(persona_id, attr_type)

        slot_key = ATTR_TYPE_TO_PROFILE_KEY.get(attr_type)
        if slot_key is None:
            return self.get_slot_value(persona_id, attr_type)

        slot = getattr(stored_persona.slots, slot_key, None)
        if slot is None:
            return self.get_slot_value(persona_id, attr_type)
        return self._pick_render_text(slot, randomize=True)
