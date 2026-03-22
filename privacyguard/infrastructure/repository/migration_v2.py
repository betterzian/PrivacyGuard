"""Helpers for migrating legacy repository payloads into the v2 schema."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from privacyguard.infrastructure.repository.schemas_v2 import (
    AddressLevelExposureStatsV2,
    AddressSlotStorageV2,
    AddressStatsV2,
    ExposureInfoV2,
    PersonaDocumentV2,
    PersonaRepositoryDocumentV2,
    PersonaSlotsV2,
    PersonaStatsV2,
    PrivacyRepositoryDocumentV2,
    RepositoryStatsV2,
    SharedSlotStorageV2,
    SlotStatsV2,
    V2_VERSION,
)

PrivacyMode = Literal["safe_unlinked", "link_by_index"]

SCALAR_SLOT_NAMES = (
    "name",
    "location_clue",
    "phone",
    "card_number",
    "bank_account",
    "passport_number",
    "driver_license",
    "email",
    "id_number",
    "organization",
)
SLOT_NAMES = (*SCALAR_SLOT_NAMES, "address")
ADDRESS_LEVEL_NAMES = ("country", "province", "city", "district", "street", "building", "room")
PERSONA_RESERVED_KEYS = {"persona_id", "display_name", "slots", "stats", "metadata"}
ENTITY_RESERVED_KEYS = {"entity_id", "id", "stats", "metadata"}
DETAIL_SPLIT_RE = re.compile(
    r"^(?P<building>.*?(?:号楼|栋|幢|座|单元|building\s*\w+|bldg\.?\s*\w+))\s*(?P<room>.*?(?:室|房|户|room\s*\w+|rm\.?\s*\w+))$",
    re.IGNORECASE,
)


def migrate_legacy_repository(
    payload: Any,
    *,
    privacy_mode: PrivacyMode = "safe_unlinked",
) -> PrivacyRepositoryDocumentV2 | PersonaRepositoryDocumentV2:
    """Convert a legacy repository payload into a validated v2 document."""
    _validate_privacy_mode(privacy_mode)

    if isinstance(payload, list):
        return _build_persona_repository_document(payload)

    if not isinstance(payload, dict):
        raise ValueError("unsupported legacy repository payload")

    if isinstance(payload.get("personas"), list):
        return _build_persona_repository_document(payload.get("personas", []))

    if isinstance(payload.get("entities"), list):
        return _build_privacy_repository_document(
            [_migrate_entity_record(record, index) for index, record in enumerate(payload.get("entities", []))]
        )

    if _looks_like_flat_privacy_dict(payload):
        personas = _migrate_flat_privacy_payload(payload, privacy_mode=privacy_mode)
        return _build_privacy_repository_document(personas)

    raise ValueError("unsupported legacy repository payload")


def read_legacy_payload(path: str | Path) -> Any:
    """Load a legacy repository JSON payload from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_v2_payload(
    document: PrivacyRepositoryDocumentV2 | PersonaRepositoryDocumentV2,
    path: str | Path,
) -> None:
    """Write a validated v2 repository document as JSON."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(document.model_dump(mode="json", exclude_none=True), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_ok_summary(document: PrivacyRepositoryDocumentV2 | PersonaRepositoryDocumentV2) -> str:
    """Return a compact summary string for CLI output."""
    if isinstance(document, PrivacyRepositoryDocumentV2):
        return f"ok version={V2_VERSION} repository=privacy true_personas={len(document.true_personas)}"
    return f"ok version={V2_VERSION} repository=persona fake_personas={len(document.fake_personas)}"


def _validate_privacy_mode(privacy_mode: str) -> None:
    if privacy_mode not in {"safe_unlinked", "link_by_index"}:
        raise ValueError(f"unsupported privacy_mode: {privacy_mode}")


def _looks_like_flat_privacy_dict(payload: dict[str, Any]) -> bool:
    keys = {str(key).strip() for key in payload.keys()}
    return bool(keys) and keys.issubset(set(SLOT_NAMES))


def _normalize_slot_mapping(raw_mapping: Any) -> dict[str, Any]:
    if not isinstance(raw_mapping, dict):
        return {}
    normalized: dict[str, Any] = {}
    for raw_key, value in raw_mapping.items():
        key = str(raw_key).strip()
        if key in SLOT_NAMES:
            if key not in normalized:
                normalized[key] = value
            else:
                normalized[key] = _merge_slot_value(key, normalized[key], value)
    return normalized


def _normalize_flat_slot_mapping(raw_mapping: Any) -> dict[str, list[Any]]:
    if not isinstance(raw_mapping, dict):
        return {}
    normalized: dict[str, list[Any]] = {}
    for raw_key, value in raw_mapping.items():
        key = str(raw_key).strip()
        if key not in SLOT_NAMES:
            continue
        normalized.setdefault(key, []).extend(_as_list(value))
    return normalized


def _merge_slot_value(slot_name: str, current: Any, incoming: Any) -> Any:
    if slot_name == "address":
        return _merge_address_raw_value(current, incoming)
    return _merge_scalar_raw_value(current, incoming)


def _merge_scalar_raw_value(current: Any, incoming: Any) -> dict[str, Any]:
    current_primary, current_aliases = _extract_primary_and_aliases(current)
    incoming_primary, incoming_aliases = _extract_primary_and_aliases(incoming)

    if current_primary is None and incoming_primary is None:
        return {}
    if current_primary is None:
        return {"value": incoming_primary, "aliases": incoming_aliases}
    if incoming_primary is None:
        return {"value": current_primary, "aliases": current_aliases}

    aliases = list(current_aliases)
    if incoming_primary != current_primary:
        aliases.append(incoming_primary)
    aliases.extend(incoming_aliases)
    return {
        "value": current_primary,
        "aliases": _dedupe([alias for alias in aliases if alias != current_primary]),
    }


def _merge_address_raw_value(current: Any, incoming: Any) -> Any:
    current_mapping = _coerce_address_mapping(current)
    incoming_mapping = _coerce_address_mapping(incoming)

    if not current_mapping:
        return incoming_mapping
    if not incoming_mapping:
        return current_mapping

    merged = dict(current_mapping)
    for key, value in incoming_mapping.items():
        if key not in merged:
            merged[key] = value
        elif key in {*ADDRESS_LEVEL_NAMES, "detail", "value"}:
            merged[key] = _merge_scalar_raw_value(merged[key], value)
        elif key == "aliases":
            merged[key] = _dedupe([*(_as_list(merged[key])), *(_as_list(value))])
    return merged


def _coerce_address_mapping(raw_value: Any) -> dict[str, Any]:
    if raw_value is None:
        return {}

    if isinstance(raw_value, list):
        merged: dict[str, Any] = {}
        for item in raw_value:
            merged = _merge_address_raw_value(merged, item)
        return merged

    if isinstance(raw_value, dict):
        normalized: dict[str, Any] = {}
        for raw_key, value in raw_value.items():
            key = str(raw_key).strip()
            if key in {*ADDRESS_LEVEL_NAMES, "detail", "value", "aliases"}:
                if key not in normalized:
                    normalized[key] = value
                elif key in {*ADDRESS_LEVEL_NAMES, "detail", "value"}:
                    normalized[key] = _merge_scalar_raw_value(normalized[key], value)
                else:
                    normalized[key] = _dedupe([*(_as_list(normalized[key])), *(_as_list(value))])
        return normalized

    return {"street": raw_value}


def _build_persona_repository_document(raw_personas: list[Any]) -> PersonaRepositoryDocumentV2:
    personas = [_migrate_persona_record(record, index) for index, record in enumerate(raw_personas)]
    return PersonaRepositoryDocumentV2(
        version=V2_VERSION,
        stats=_aggregate_repository_stats(personas),
        fake_personas=personas,
    )


def _build_privacy_repository_document(personas: list[PersonaDocumentV2]) -> PrivacyRepositoryDocumentV2:
    return PrivacyRepositoryDocumentV2(
        version=V2_VERSION,
        stats=_aggregate_repository_stats(personas),
        true_personas=personas,
    )


def _migrate_persona_record(raw_record: Any, index: int) -> PersonaDocumentV2:
    record = raw_record if isinstance(raw_record, dict) else {}
    slots = _migrate_slots(record.get("slots"))
    persona_id = _stringify(record.get("persona_id")) or f"persona-{index + 1}"
    display_name = _stringify(record.get("display_name")) or _slot_display_name(slots) or persona_id
    return PersonaDocumentV2(
        persona_id=persona_id,
        display_name=display_name,
        slots=slots,
        stats=_migrate_stats(record.get("stats")),
        metadata=_to_string_dict(record.get("metadata")),
    )


def _migrate_entity_record(raw_record: Any, index: int) -> PersonaDocumentV2:
    record = raw_record if isinstance(raw_record, dict) else {}
    persona_id = _stringify(record.get("entity_id") or record.get("id")) or f"entity-{index + 1}"
    slots_payload = _normalize_slot_mapping(record)
    slots = _migrate_slots(slots_payload)
    display_name = _slot_display_name(slots) or persona_id
    return PersonaDocumentV2(
        persona_id=persona_id,
        display_name=display_name,
        slots=slots,
        stats=_migrate_stats(record.get("stats")),
        metadata=_to_string_dict(record.get("metadata")),
    )


def _migrate_flat_privacy_payload(payload: dict[str, Any], *, privacy_mode: PrivacyMode) -> list[PersonaDocumentV2]:
    payload = _normalize_flat_slot_mapping(payload)
    if privacy_mode == "link_by_index":
        return _migrate_flat_privacy_by_index(payload)
    return _migrate_flat_privacy_unlinked(payload)


def _migrate_flat_privacy_unlinked(payload: dict[str, Any]) -> list[PersonaDocumentV2]:
    personas: list[PersonaDocumentV2] = []
    for slot_name in SLOT_NAMES:
        for index, value in enumerate(_as_list(payload.get(slot_name))):
            slot_values = _migrate_slot_values({slot_name: value})
            if not slot_values:
                continue
            slot_payload = PersonaSlotsV2(**slot_values)
            persona_id = f"legacy-{slot_name}-{index + 1}"
            personas.append(
                PersonaDocumentV2(
                    persona_id=persona_id,
                    display_name=_slot_display_name(slot_payload) or persona_id,
                    slots=slot_payload,
                    stats=PersonaStatsV2(),
                    metadata={"legacy_source_slot": slot_name},
                )
            )
    return personas


def _migrate_flat_privacy_by_index(payload: dict[str, Any]) -> list[PersonaDocumentV2]:
    normalized = {slot_name: _as_list(payload.get(slot_name)) for slot_name in SLOT_NAMES}
    max_count = max((len(values) for values in normalized.values()), default=0)
    personas: list[PersonaDocumentV2] = []
    for index in range(max_count):
        record = {slot_name: values[index] for slot_name, values in normalized.items() if index < len(values)}
        if not record:
            continue
        slot_values = _migrate_slot_values(record)
        if not slot_values:
            continue
        slots = PersonaSlotsV2(**slot_values)
        persona_id = f"legacy-linked-{index + 1}"
        personas.append(
            PersonaDocumentV2(
                persona_id=persona_id,
                display_name=_slot_display_name(slots) or persona_id,
                slots=slots,
                stats=PersonaStatsV2(),
                metadata={},
            )
        )
    return personas


def _migrate_slots(raw_slots: Any) -> PersonaSlotsV2:
    slot_values = _migrate_slot_values(raw_slots)
    return PersonaSlotsV2(**slot_values)


def _migrate_slot_values(raw_slots: Any) -> dict[str, Any]:
    slot_map = _normalize_slot_mapping(raw_slots)
    slot_values: dict[str, Any] = {}
    for slot_name in SCALAR_SLOT_NAMES:
        slot = _migrate_scalar_slot(slot_map.get(slot_name))
        if slot is not None:
            slot_values[slot_name] = slot
    address = _migrate_address_slot(slot_map.get("address"))
    if address is not None:
        slot_values["address"] = address
    return slot_values


def _migrate_scalar_slot(raw_value: Any) -> SharedSlotStorageV2 | None:
    primary, aliases = _extract_primary_and_aliases(raw_value)
    if primary is None:
        return None
    return SharedSlotStorageV2(value=primary, aliases=aliases)


def _migrate_address_slot(raw_value: Any) -> AddressSlotStorageV2 | None:
    if isinstance(raw_value, list):
        merged_raw = _coerce_address_mapping(raw_value)
        if not merged_raw:
            return None
        return _migrate_address_slot(merged_raw)

    if raw_value is None:
        return None

    if isinstance(raw_value, dict):
        if "value" in raw_value and set(raw_value).issubset({"value", "aliases"}):
            primary, aliases = _extract_primary_and_aliases(raw_value)
            if primary is None:
                return None
            return AddressSlotStorageV2(street=SharedSlotStorageV2(value=primary, aliases=aliases))

        if "value" in raw_value:
            raw_value = dict(raw_value)
            street_raw = {"value": raw_value.pop("value"), "aliases": raw_value.pop("aliases", [])}
            if "street" in raw_value:
                raw_value["street"] = _merge_scalar_raw_value(street_raw, raw_value["street"])
            else:
                raw_value["street"] = street_raw

        address_values: dict[str, SharedSlotStorageV2] = {}
        for level_name in ADDRESS_LEVEL_NAMES:
            slot = _migrate_scalar_slot(raw_value.get(level_name))
            if slot is not None:
                address_values[level_name] = slot
        detail_value = raw_value.get("detail")
        if detail_value is not None:
            _apply_detail(address_values, detail_value)
        if not address_values:
            return None
        return AddressSlotStorageV2(**address_values)

    primary = _stringify(raw_value)
    if primary is None:
        return None
    return AddressSlotStorageV2(street=SharedSlotStorageV2(value=primary, aliases=[]))


def _apply_detail(address_values: dict[str, SharedSlotStorageV2], raw_detail: Any) -> None:
    detail_value, aliases = _extract_primary_and_aliases(raw_detail)
    if detail_value is None:
        return

    if "street" not in address_values:
        address_values["street"] = SharedSlotStorageV2(value=detail_value, aliases=aliases)
        return

    building_value, room_value = _split_detail(detail_value)
    if building_value and "building" not in address_values:
        address_values["building"] = SharedSlotStorageV2(value=building_value, aliases=[])
    if room_value:
        if "building" in address_values:
            address_values["room"] = SharedSlotStorageV2(value=room_value, aliases=[])
            return
        # Preserve detail conservatively when the room cannot be validated independently.
        address_values["building"] = SharedSlotStorageV2(value=detail_value, aliases=aliases)
        return

    target_level = "building" if "street" in address_values else "street"
    if target_level not in address_values:
        address_values[target_level] = SharedSlotStorageV2(value=detail_value, aliases=aliases)


def _split_detail(detail_value: str) -> tuple[str | None, str | None]:
    match = DETAIL_SPLIT_RE.match(detail_value.strip())
    if not match:
        return (None, None)
    building = match.group("building").strip()
    room = match.group("room").strip()
    return (building or None, room or None)


def _extract_primary_and_aliases(raw_value: Any) -> tuple[str | None, list[str]]:
    if raw_value is None:
        return (None, [])

    if isinstance(raw_value, dict):
        if "value" in raw_value:
            primary = _stringify(raw_value.get("value"))
            aliases = _clean_aliases(raw_value.get("aliases"), primary)
            return (primary, aliases)
        return (None, [])

    values = [_stringify(item) for item in _as_list(raw_value)]
    values = [value for value in values if value is not None]
    if not values:
        primary = _stringify(raw_value)
        return (primary, [])
    primary = values[0]
    return (primary, _dedupe([value for value in values[1:] if value != primary]))


def _migrate_stats(raw_stats: Any) -> PersonaStatsV2:
    stats = raw_stats if isinstance(raw_stats, dict) else {}
    address_stats = _migrate_address_stats(stats)
    return PersonaStatsV2(
        total=_exposure_info_from_legacy(stats, count_key="exposure_count", allow_zero_count_metadata=True),
        slots=SlotStatsV2(
            name=_exposure_info_from_legacy(stats, count_key="name_exposure_count"),
            location_clue=_exposure_info_from_legacy(stats, count_key="location_clue_exposure_count"),
            phone=_exposure_info_from_legacy(stats, count_key="phone_exposure_count"),
            card_number=_exposure_info_from_legacy(stats, count_key="card_number_exposure_count"),
            bank_account=_exposure_info_from_legacy(stats, count_key="bank_account_exposure_count"),
            passport_number=_exposure_info_from_legacy(stats, count_key="passport_number_exposure_count"),
            driver_license=_exposure_info_from_legacy(stats, count_key="driver_license_exposure_count"),
            email=_exposure_info_from_legacy(stats, count_key="email_exposure_count"),
            address=address_stats,
            id_number=_exposure_info_from_legacy(stats, count_key="id_number_exposure_count"),
            organization=_exposure_info_from_legacy(stats, count_key="organization_exposure_count"),
        ),
        address=address_stats.model_copy(deep=True),
    )


def _migrate_address_stats(stats: dict[str, Any]) -> AddressStatsV2:
    levels = AddressLevelExposureStatsV2(
        country=_exposure_info_from_legacy(stats, count_key="address_country_exposure_count"),
        province=_exposure_info_from_legacy(stats, count_key="address_province_exposure_count"),
        city=_exposure_info_from_legacy(stats, count_key="address_city_exposure_count"),
        district=_exposure_info_from_legacy(stats, count_key="address_district_exposure_count"),
        street=_exposure_info_from_legacy(stats, count_key="address_street_exposure_count"),
        building=_exposure_info_from_legacy(stats, count_key="address_building_exposure_count"),
        room=_exposure_info_from_legacy(stats, count_key="address_room_exposure_count"),
    )
    return AddressStatsV2(
        total=_exposure_info_from_legacy(stats, count_key="address_exposure_count"),
        levels=levels,
    )


def _exposure_info_from_legacy(
    stats: dict[str, Any],
    *,
    count_key: str,
    allow_zero_count_metadata: bool = False,
) -> ExposureInfoV2:
    exposure_count = _coerce_non_negative_int(stats.get(count_key))
    if exposure_count <= 0 and not allow_zero_count_metadata:
        return ExposureInfoV2(exposure_count=exposure_count)
    return ExposureInfoV2(
        exposure_count=exposure_count,
        last_exposed_at=_coerce_datetime(stats.get("last_exposed_at") or stats.get("last_exposed_session_time")),
        last_exposed_session_id=_stringify(stats.get("last_exposed_session_id")),
        last_exposed_turn_id=_coerce_optional_non_negative_int(stats.get("last_exposed_turn_id")),
    )


def _aggregate_repository_stats(personas: list[PersonaDocumentV2]) -> RepositoryStatsV2:
    total = ExposureInfoV2()
    slot_totals = {slot_name: ExposureInfoV2() for slot_name in SCALAR_SLOT_NAMES}
    address_total = AddressStatsV2()

    for persona in personas:
        total = _merge_exposure_info(total, persona.stats.total)
        for slot_name in SCALAR_SLOT_NAMES:
            slot_totals[slot_name] = _merge_exposure_info(slot_totals[slot_name], getattr(persona.stats.slots, slot_name))
        address_total = _merge_address_stats(address_total, persona.stats.address)

    slots_stats = SlotStatsV2(
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

    personas_stats = PersonaStatsV2(
        total=total.model_copy(deep=True),
        slots=slots_stats.model_copy(deep=True),
        address=address_total.model_copy(deep=True),
    )
    return RepositoryStatsV2(
        total=total,
        personas=personas_stats,
        slots=slots_stats,
        address=address_total,
    )


def _merge_exposure_info(left: ExposureInfoV2, right: ExposureInfoV2) -> ExposureInfoV2:
    latest_at = left.last_exposed_at
    latest_session = left.last_exposed_session_id
    latest_turn = left.last_exposed_turn_id
    if right.last_exposed_at and (latest_at is None or right.last_exposed_at >= latest_at):
        latest_at = right.last_exposed_at
        latest_session = right.last_exposed_session_id
        latest_turn = right.last_exposed_turn_id
    return ExposureInfoV2(
        exposure_count=left.exposure_count + right.exposure_count,
        last_exposed_at=latest_at,
        last_exposed_session_id=latest_session,
        last_exposed_turn_id=latest_turn,
    )


def _merge_address_stats(left: AddressStatsV2, right: AddressStatsV2) -> AddressStatsV2:
    return AddressStatsV2(
        total=_merge_exposure_info(left.total, right.total),
        levels=AddressLevelExposureStatsV2(
            country=_merge_exposure_info(left.levels.country, right.levels.country),
            province=_merge_exposure_info(left.levels.province, right.levels.province),
            city=_merge_exposure_info(left.levels.city, right.levels.city),
            district=_merge_exposure_info(left.levels.district, right.levels.district),
            street=_merge_exposure_info(left.levels.street, right.levels.street),
            building=_merge_exposure_info(left.levels.building, right.levels.building),
            room=_merge_exposure_info(left.levels.room, right.levels.room),
        ),
    )


def _slot_display_name(slots: PersonaSlotsV2) -> str | None:
    if slots.name:
        return slots.name.value
    if slots.organization:
        return slots.organization.value
    if slots.email:
        return slots.email.value
    if slots.phone:
        return slots.phone.value
    return None


def _as_list(raw_value: Any) -> list[Any]:
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return raw_value
    return [raw_value]


def _clean_aliases(raw_value: Any, primary: str | None) -> list[str]:
    return _dedupe(
        [
            alias
            for alias in (_stringify(item) for item in _as_list(raw_value))
            if alias is not None and alias != primary
        ]
    )


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _to_string_dict(raw_value: Any) -> dict[str, str]:
    if not isinstance(raw_value, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in raw_value.items()
        if _stringify(key) is not None and _stringify(value) is not None
    }


def _stringify(raw_value: Any) -> str | None:
    if raw_value is None:
        return None
    text = str(raw_value).strip()
    return text or None


def _coerce_non_negative_int(raw_value: Any) -> int:
    try:
        return max(int(raw_value), 0)
    except (TypeError, ValueError):
        return 0


def _coerce_optional_non_negative_int(raw_value: Any) -> int | None:
    if raw_value is None:
        return None
    try:
        return max(int(raw_value), 0)
    except (TypeError, ValueError):
        return None


def _coerce_datetime(raw_value: Any) -> datetime | None:
    if raw_value is None:
        return None
    text = _stringify(raw_value)
    if text is None:
        return None
    normalized = text.replace(" ", "T")
    try:
        return datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
