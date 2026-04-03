"""基于 JSON 文件的 Persona 仓库实现。"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.repository.schemas import (
    AddressLevelExposureStats,
    AddressSlotStorage,
    AddressStats,
    ExposureInfo,
    NameSlotStorage,
    PersonaDocument,
    PersonaRepositoryDocument,
    PersonaSlots,
    PersonaStats,
    RepositoryStats,
    SharedSlotStorage,
    SlotStats,
)
from privacyguard.utils.normalized_pii import normalize_pii, render_address_text
from privacyguard.utils.pii_value import NameComponents, parse_name_components, render_name_like_source

DEFAULT_PERSONA_REPOSITORY_PATH = "data/persona_repository.json"
DEFAULT_PERSONA_SAMPLE_PATH = "data/personas.sample.json"


class InvalidPersonaRepositoryError(ValueError):
    """persona 仓库 JSON 不符合 schema（需含 ``fake_personas``）。"""


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
_ADDRESS_LEVEL_KEYS = (
    "province",
    "city",
    "district",
    "street_admin",
    "town",
    "village",
    "road",
    "compound",
    "building",
    "unit",
    "floor",
    "room",
    "postal_code",
)


def _runtime_stats_to_persona_stats(stats_data: dict[str, object] | object) -> PersonaStats:
    """将 runtime 扁平 stats 转为 ``PersonaStats``。"""
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


def _normalize_runtime_slot_values(raw: object, *, field_name: str) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError(f"PersonaProfile.slots[{field_name}] 必须是字符串列表")
    values: list[str] = []
    for item in raw:
        text = str(item).strip()
        if text:
            values.append(text)
    if not values:
        raise ValueError(f"PersonaProfile.slots[{field_name}] 不能为空")
    return values


def _shared_slot(value: str) -> SharedSlotStorage:
    return SharedSlotStorage(value=value, aliases=[])


def _name_text_to_storage_slot(text: str) -> NameSlotStorage:
    components = parse_name_components(text)
    full_text = components.full_text or components.original_text or text.strip()
    if not full_text:
        raise ValueError("姓名不能为空")
    return NameSlotStorage(
        full=_shared_slot(full_text),
        family=_shared_slot(components.family_text) if components.family_text else None,
        given=_shared_slot(components.given_text) if components.given_text else None,
        middle=_shared_slot(components.middle_text) if components.middle_text else None,
    )


def _address_text_to_storage_slot(text: str) -> AddressSlotStorage:
    normalized = normalize_pii(PIIAttributeType.ADDRESS, text)
    components = {
        key: value
        for key, value in normalized.components.items()
        if key in _ADDRESS_LEVEL_KEYS and str(value).strip()
    }
    if not components:
        stripped = str(text or "").strip()
        if not stripped:
            raise ValueError("地址不能为空")
        components = {"road": stripped}
    return AddressSlotStorage(
        **{
            key: _shared_slot(value)
            for key, value in components.items()
        }
    )


def _persona_profile_to_persona_document(persona: PersonaProfile) -> PersonaDocument:
    """将 ``PersonaProfile`` 转为 ``PersonaDocument``。"""
    slot_values: dict[str, object] = {}
    for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
        raw = persona.slots.get(attr_type)
        if raw is None:
            continue
        values = _normalize_runtime_slot_values(raw, field_name=key)
        if attr_type == PIIAttributeType.ADDRESS:
            slot_values["address"] = [_address_text_to_storage_slot(text) for text in values]
        elif attr_type == PIIAttributeType.NAME:
            slot_values["name"] = [_name_text_to_storage_slot(text) for text in values]
        else:
            slot_values[key] = [_shared_slot(text) for text in values]
    if not slot_values:
        raise ValueError("PersonaProfile must contain at least one non-empty slot for storage")
    slots = PersonaSlots(**slot_values)
    display_name = persona.display_name
    if not display_name and slots.name:
        display_name = slots.name[0].full.value
    if not display_name:
        display_name = persona.persona_id
    metadata: dict[str, str] = {}
    for raw_key, raw_value in (persona.metadata or {}).items():
        key = str(raw_key).strip()
        value = str(raw_value).strip() if raw_value is not None else ""
        if key and value:
            metadata[key] = value
    return PersonaDocument(
        persona_id=persona.persona_id,
        display_name=display_name,
        slots=slots,
        stats=_runtime_stats_to_persona_stats(persona.stats),
        metadata=metadata,
    )


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
            province=_merge_exposure_info(left.levels.province, right.levels.province),
            city=_merge_exposure_info(left.levels.city, right.levels.city),
            district=_merge_exposure_info(left.levels.district, right.levels.district),
            street_admin=_merge_exposure_info(left.levels.street_admin, right.levels.street_admin),
            town=_merge_exposure_info(left.levels.town, right.levels.town),
            village=_merge_exposure_info(left.levels.village, right.levels.village),
            road=_merge_exposure_info(left.levels.road, right.levels.road),
            compound=_merge_exposure_info(left.levels.compound, right.levels.compound),
            building=_merge_exposure_info(left.levels.building, right.levels.building),
            unit=_merge_exposure_info(left.levels.unit, right.levels.unit),
            floor=_merge_exposure_info(left.levels.floor, right.levels.floor),
            room=_merge_exposure_info(left.levels.room, right.levels.room),
            postal_code=_merge_exposure_info(left.levels.postal_code, right.levels.postal_code),
        ),
    )


def _aggregate_repository_stats(personas: list[PersonaDocument]) -> RepositoryStats:
    total = ExposureInfo()
    slot_totals = {
        "name": ExposureInfo(),
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


class JsonPersonaRepository:
    """从本地 JSON 加载并查询 persona 数据。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path(DEFAULT_PERSONA_REPOSITORY_PATH)
        self._source_path = self._resolve_source_path(explicit_path=path is not None)
        self._rng = random.Random()
        self._personas, self._stored_fake_personas = self._load_personas(self._source_path)

    def _resolve_source_path(self, *, explicit_path: bool) -> Path:
        if self.path.exists():
            return self.path
        if explicit_path:
            return self.path
        fallback_path = Path(DEFAULT_PERSONA_SAMPLE_PATH)
        if fallback_path.exists():
            return fallback_path
        return self.path

    def _load_personas(self, source_path: Path) -> tuple[dict[str, PersonaProfile], dict[str, PersonaDocument]]:
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
        if not isinstance(raw_payload, dict):
            raise InvalidPersonaRepositoryError("persona 仓库顶层必须是 JSON 对象")
        try:
            return PersonaRepositoryDocument.model_validate(raw_payload)
        except ValidationError as exc:
            raise InvalidPersonaRepositoryError(
                'persona_repository 必须包含 {"fake_personas": [...]}'
            ) from exc

    def _build_runtime_persona(self, stored_persona: PersonaDocument) -> PersonaProfile:
        slots = self._flatten_runtime_slots(stored_persona)
        name_values = slots.get(PIIAttributeType.NAME, [])
        display_name = stored_persona.display_name or (name_values[0] if name_values else "") or stored_persona.persona_id
        return PersonaProfile(
            persona_id=stored_persona.persona_id,
            display_name=display_name,
            slots=slots,
            metadata=dict(stored_persona.metadata),
            stats=self._flatten_runtime_stats(stored_persona.stats),
        )

    def _flatten_runtime_slots(self, stored_persona: PersonaDocument) -> dict[PIIAttributeType, list[str]]:
        slots: dict[PIIAttributeType, list[str]] = {}
        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            if attr_type == PIIAttributeType.NAME:
                values = self._render_name_slot_values(stored_persona.slots.name)
            elif attr_type == PIIAttributeType.ADDRESS:
                values = self._render_address_slot_values(stored_persona.slots.address)
            else:
                raw_slots = getattr(stored_persona.slots, key, None)
                values = [slot.value for slot in raw_slots or []]
            if values:
                slots[attr_type] = values
        return slots

    def _flatten_runtime_stats(self, stats: PersonaStats) -> dict[str, int | str | None]:
        return {
            "exposure_count": stats.total.exposure_count,
            "last_exposed_session_id": stats.total.last_exposed_session_id,
            "last_exposed_turn_id": stats.total.last_exposed_turn_id,
        }

    def _pick_render_text(self, slot: SharedSlotStorage, *, randomize: bool) -> str:
        if not randomize or not slot.aliases:
            return slot.value
        return self._rng.choice([slot.value, *slot.aliases])

    def _slot_index(self, *, source_text: str | None, slot_count: int) -> int:
        if slot_count <= 1:
            return 0
        compact = str(source_text or "").strip()
        if not compact:
            return 0
        digest = hashlib.sha256(compact.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % slot_count

    def _pick_storage_slot(
        self,
        slots: list[SharedSlotStorage] | None,
        *,
        source_text: str | None = None,
    ) -> SharedSlotStorage | None:
        if not slots:
            return None
        return slots[self._slot_index(source_text=source_text, slot_count=len(slots))]

    def _pick_name_storage_slot(
        self,
        slots: list[NameSlotStorage] | None,
        *,
        source_text: str | None = None,
    ) -> NameSlotStorage | None:
        if not slots:
            return None
        return slots[self._slot_index(source_text=source_text, slot_count=len(slots))]

    def _pick_address_storage_slot(
        self,
        slots: list[AddressSlotStorage] | None,
        *,
        source_text: str | None = None,
    ) -> AddressSlotStorage | None:
        if not slots:
            return None
        return slots[self._slot_index(source_text=source_text, slot_count=len(slots))]

    def _render_name_slot_values(self, slots: list[NameSlotStorage] | None) -> list[str]:
        return [slot.full.value for slot in (slots or []) if slot.full.value]

    def _render_address_slot_values(self, slots: list[AddressSlotStorage] | None) -> list[str]:
        rendered_values: list[str] = []
        for slot in slots or []:
            rendered = render_address_text(self._selected_address_components(slot, randomize=False))
            if rendered:
                rendered_values.append(rendered)
        return rendered_values

    def _name_component_hint(self, metadata: dict[str, list[str]] | None) -> str | None:
        if not metadata:
            return None
        values = metadata.get("name_component", [])
        if not values:
            return None
        normalized = [str(value).strip().lower() for value in values if str(value).strip()]
        for preferred in ("full", "family", "given", "alias", "middle"):
            if preferred in normalized:
                return preferred
        return normalized[0] if normalized else None

    def _target_name_components(self, slot: NameSlotStorage, *, randomize: bool) -> NameComponents:
        locale = parse_name_components(slot.full.value).locale
        return NameComponents(
            original_text=slot.full.value,
            locale=locale,
            full_text=self._pick_render_text(slot.full, randomize=randomize),
            family_text=self._pick_render_text(slot.family, randomize=randomize) if slot.family else None,
            given_text=self._pick_render_text(slot.given, randomize=randomize) if slot.given else None,
            middle_text=self._pick_render_text(slot.middle, randomize=randomize) if slot.middle else None,
        )

    def _selected_address_components(self, slot: AddressSlotStorage, *, randomize: bool) -> dict[str, str]:
        return {
            key: self._pick_render_text(level_slot, randomize=randomize)
            for key in _ADDRESS_LEVEL_KEYS
            if (level_slot := getattr(slot, key, None)) is not None
        }

    def _render_name_slot(
        self,
        slots: list[NameSlotStorage] | None,
        *,
        source_text: str | None = None,
        metadata: dict[str, list[str]] | None = None,
        randomize: bool,
    ) -> str | None:
        slot = self._pick_name_storage_slot(slots, source_text=source_text)
        if slot is None:
            return None
        component_hint = self._name_component_hint(metadata)
        if component_hint == "alias" and slot.alias:
            return self._pick_render_text(slot.alias, randomize=randomize)
        target_components = self._target_name_components(slot, randomize=randomize)
        source_components = parse_name_components(source_text or slot.full.value)
        rendered = render_name_like_source(
            target_components,
            source_components,
            component_hint=component_hint if component_hint != "alias" else None,
        )
        return rendered or target_components.full_text

    def _render_address_slot(
        self,
        slots: list[AddressSlotStorage] | None,
        *,
        source_text: str | None = None,
        randomize: bool,
    ) -> str | None:
        slot = self._pick_address_storage_slot(slots, source_text=source_text)
        if slot is None:
            return None
        selected = self._selected_address_components(slot, randomize=randomize)
        if not selected:
            return None
        if not source_text:
            return render_address_text(selected) or None
        source_normalized = normalize_pii(PIIAttributeType.ADDRESS, source_text)
        if source_normalized.components:
            rendered = {
                key: value
                for key, value in selected.items()
                if key in source_normalized.components
            }
            if rendered:
                return render_address_text(rendered) or None
        return render_address_text(selected) or None

    def _to_storage_document(self) -> PersonaRepositoryDocument:
        personas = list(self._stored_fake_personas.values())
        return PersonaRepositoryDocument(
            stats=_aggregate_repository_stats(personas),
            fake_personas=personas,
        )

    def _runtime_persona_to_storage(self, persona: PersonaProfile) -> PersonaDocument:
        return _persona_profile_to_persona_document(persona)

    def _merge_runtime_persona_into_storage(
        self,
        persona: PersonaProfile,
        existing: PersonaDocument | None,
    ) -> PersonaDocument:
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

            if attr_type == PIIAttributeType.NAME:
                current_value = self._render_name_slot_values(current_slot)
            elif attr_type == PIIAttributeType.ADDRESS:
                current_value = self._render_address_slot_values(current_slot)
            else:
                current_value = [slot.value for slot in current_slot] if current_slot else []

            merged_slot_values[key] = current_slot if current_slot is not None and runtime_value == current_value else incoming_slot

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

    def _serialize_profile(self, persona: PersonaProfile) -> dict[str, list[str]]:
        slots: dict[str, list[str]] = {}
        for attr_type, key in ATTR_TYPE_TO_PROFILE_KEY.items():
            value = persona.slots.get(attr_type)
            if value is not None:
                slots[key] = list(value)
        return slots

    def _serialize_stats(self, stats_data: dict[str, object] | object) -> dict[str, int | str | None]:
        if not isinstance(stats_data, dict):
            stats_data = {}
        return {
            "exposure_count": int(stats_data.get("exposure_count", 0)),
            "last_exposed_session_id": stats_data.get("last_exposed_session_id"),
            "last_exposed_turn_id": stats_data.get("last_exposed_turn_id"),
        }

    def upsert_persona(self, persona: PersonaProfile) -> None:
        self._personas[persona.persona_id] = persona
        self._stored_fake_personas[persona.persona_id] = self._merge_runtime_persona_into_storage(
            persona,
            self._stored_fake_personas.get(persona.persona_id),
        )
        self._flush_to_file()

    def upsert_personas(self, personas: list[PersonaProfile]) -> None:
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
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        values = persona.slots.get(attr_type)
        if not values:
            return None
        return values[0]

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
        metadata: dict[str, list[str]] | None = None,
    ) -> str | None:
        stored_persona = self._stored_fake_personas.get(persona_id)
        if stored_persona is None:
            return self.get_slot_value(persona_id, attr_type)

        if attr_type == PIIAttributeType.NAME:
            rendered = self._render_name_slot(
                stored_persona.slots.name,
                source_text=source_text,
                metadata=metadata,
                randomize=True,
            )
            return rendered or self.get_slot_value(persona_id, attr_type)

        if attr_type == PIIAttributeType.ADDRESS:
            rendered = self._render_address_slot(
                stored_persona.slots.address,
                source_text=source_text,
                randomize=True,
            )
            return rendered or self.get_slot_value(persona_id, attr_type)

        slot_key = ATTR_TYPE_TO_PROFILE_KEY.get(attr_type)
        if slot_key is None:
            return self.get_slot_value(persona_id, attr_type)
        slot = self._pick_storage_slot(
            getattr(stored_persona.slots, slot_key, None),
            source_text=source_text,
        )
        if slot is None:
            return self.get_slot_value(persona_id, attr_type)
        return self._pick_render_text(slot, randomize=True)
