"""基于 JSON 文件的 privacy 词库读写。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.repository.migration_v2 import migrate_legacy_repository
from privacyguard.infrastructure.repository.schemas_v2 import (
    AddressLevelExposureStatsV2,
    AddressSlotStorageV2,
    AddressStatsV2,
    ExposureInfoV2,
    PersonaDocumentV2,
    PersonaStatsV2,
    PrivacyRepositoryDocumentV2,
    RepositoryStatsV2,
    SlotStatsV2,
    V2_VERSION,
)
from privacyguard.utils.pii_value import canonicalize_pii_value

DEFAULT_PRIVACY_REPOSITORY_PATH = "data/privacy_repository.json"

_SLOT_NAME_TO_ATTR_TYPE = {
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
_LEGACY_GENERATED_PERSONA_ID_RE = re.compile(r"^legacy-[a-z_]+-\d+$")


def _dedupe_str_list(values: list[str]) -> list[str]:
    """保持顺序的去重。"""
    return list(dict.fromkeys(values))


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return [text] if text else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    return []


def _merge_top_level_lists(existing: Any, incoming: Any) -> list[str]:
    return _dedupe_str_list(_as_str_list(existing) + _as_str_list(incoming))


def _deep_merge_entity(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """合并同一 entity_id 下的实体条目。"""
    merged = dict(old)
    for key, value in new.items():
        if key in {"entity_id", "id"}:
            continue
        if key not in merged:
            merged[key] = value
            continue
        prev = merged[key]
        if isinstance(prev, list) and isinstance(value, list):
            if _is_flat_str_list(prev) and _is_flat_str_list(value):
                merged[key] = _dedupe_str_list([str(x).strip() for x in prev + value if str(x).strip()])
            else:
                merged[key] = list(prev) + list(value)
        elif isinstance(prev, dict) and isinstance(value, dict):
            sub = dict(prev)
            sub.update(value)
            merged[key] = sub
        else:
            merged[key] = value
    return merged


def _is_flat_str_list(items: list[Any]) -> bool:
    return all(isinstance(x, (str, int, float)) for x in items)


def _merge_entities(existing: Any, incoming: Any) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for raw in existing if isinstance(existing, list) else []:
        if not isinstance(raw, dict):
            continue
        eid = str(raw.get("entity_id") or raw.get("id") or "").strip()
        if not eid:
            continue
        by_id[eid] = dict(raw)
    for raw in incoming if isinstance(incoming, list) else []:
        if not isinstance(raw, dict):
            continue
        eid = str(raw.get("entity_id") or raw.get("id") or "").strip()
        if not eid:
            continue
        if eid in by_id:
            by_id[eid] = _deep_merge_entity(by_id[eid], raw)
        else:
            by_id[eid] = dict(raw)
    return list(by_id.values())


def merge_privacy_documents(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """兼容旧测试的 legacy 文档合并函数。"""
    out = dict(base)
    for key, value in patch.items():
        if key == "entities":
            out["entities"] = _merge_entities(out.get("entities"), value)
            continue
        if value is None:
            continue
        if key not in out:
            out[key] = _dedupe_str_list(_as_str_list(value))
            continue
        out[key] = _merge_top_level_lists(out[key], value)
    return out


def _render_address_value(slot: AddressSlotStorageV2 | None) -> str:
    if slot is None:
        return ""
    province = slot.province.value if slot.province else None
    city = slot.city.value if slot.city else None
    district = slot.district.value if slot.district else None
    street = slot.street.value if slot.street else None
    building = slot.building.value if slot.building else None
    room = slot.room.value if slot.room else None
    parts = []
    if province:
        parts.append(province)
    if city and city != province:
        parts.append(city)
    if district:
        parts.append(district)
    for value in (street, building, room):
        if value:
            parts.append(value)
    return "".join(parts)


def _single_populated_slot(persona: PersonaDocumentV2) -> tuple[str, Any] | None:
    populated = [
        (slot_name, getattr(persona.slots, slot_name))
        for slot_name in _SLOT_NAME_TO_ATTR_TYPE
        if getattr(persona.slots, slot_name) is not None
    ]
    if len(populated) != 1:
        return None
    return populated[0]


def _stable_legacy_persona_id(persona: PersonaDocumentV2) -> str | None:
    if "legacy_source_slot" not in persona.metadata:
        return None
    if not _LEGACY_GENERATED_PERSONA_ID_RE.fullmatch(persona.persona_id):
        return None
    single_slot = _single_populated_slot(persona)
    if single_slot is None:
        return None

    slot_name, slot_value = single_slot
    attr_type = _SLOT_NAME_TO_ATTR_TYPE[slot_name]
    if attr_type == PIIAttributeType.ADDRESS:
        raw_value = _render_address_value(slot_value)
    else:
        raw_value = slot_value.value
    canonical = canonicalize_pii_value(attr_type, raw_value) or raw_value
    digest = hashlib.md5(canonical.encode("utf-8")).hexdigest()[:12]
    return f"legacy-{slot_name}-{digest}"


def _normalize_privacy_document_ids(document: PrivacyRepositoryDocumentV2) -> PrivacyRepositoryDocumentV2:
    by_id: dict[str, PersonaDocumentV2] = {}
    ordered_ids: list[str] = []
    for persona in document.true_personas:
        stable_id = _stable_legacy_persona_id(persona)
        normalized = persona if stable_id is None else persona.model_copy(update={"persona_id": stable_id}, deep=True)
        if normalized.persona_id in by_id:
            by_id[normalized.persona_id] = _merge_persona_documents(by_id[normalized.persona_id], normalized)
            continue
        by_id[normalized.persona_id] = normalized
        ordered_ids.append(normalized.persona_id)
    personas = [by_id[persona_id] for persona_id in ordered_ids]
    return PrivacyRepositoryDocumentV2(
        version=V2_VERSION,
        stats=_aggregate_repository_stats(personas),
        true_personas=personas,
    )


def _is_storage_slot_dict(value: Any) -> bool:
    return isinstance(value, dict) and "value" in value and set(value).issubset({"value", "aliases"})


def ensure_v2_privacy_document(payload: dict[str, Any] | None) -> PrivacyRepositoryDocumentV2:
    """将 legacy/v2 payload 统一规范化为 v2 privacy document。"""
    if not payload:
        return PrivacyRepositoryDocumentV2(version=V2_VERSION, true_personas=[])
    if payload.get("version") == V2_VERSION or "true_personas" in payload:
        return PrivacyRepositoryDocumentV2.model_validate(payload)

    legacy_payload = dict(payload)
    if isinstance(legacy_payload.get("entities"), list):
        legacy_payload["entities"] = _collapse_legacy_entities_for_v2(legacy_payload.get("entities"))

    migrated = migrate_legacy_repository(legacy_payload, privacy_mode="safe_unlinked")
    if not isinstance(migrated, PrivacyRepositoryDocumentV2):
        raise ValueError("privacy repository payload did not migrate to a privacy v2 document")
    return _normalize_privacy_document_ids(migrated)


def _extract_legacy_primary_and_aliases(raw_value: Any) -> tuple[str | None, list[str]]:
    if raw_value is None:
        return (None, [])
    if isinstance(raw_value, dict):
        primary = str(raw_value.get("value") or "").strip() or None
        aliases = [alias for alias in _as_str_list(raw_value.get("aliases")) if alias and alias != primary]
        return (primary, aliases)
    if isinstance(raw_value, list):
        collected: list[str] = []
        for item in raw_value:
            primary, aliases = _extract_legacy_primary_and_aliases(item)
            if primary:
                collected.append(primary)
            collected.extend(alias for alias in aliases if alias)
        if not collected:
            return (None, [])
        primary = collected[0]
        aliases = [alias for alias in _dedupe_str_list(collected[1:]) if alias != primary]
        return (primary, aliases)
    values = _as_str_list(raw_value)
    if not values:
        return (None, [])
    return (values[0], [alias for alias in _dedupe_str_list(values[1:]) if alias != values[0]])


def _merge_legacy_scalar_values(old: Any, new: Any) -> dict[str, Any]:
    old_primary, old_aliases = _extract_legacy_primary_and_aliases(old)
    new_primary, new_aliases = _extract_legacy_primary_and_aliases(new)

    primary = old_primary or new_primary or ""
    aliases = _dedupe_str_list(
        [
            *old_aliases,
            *([new_primary] if new_primary and new_primary != primary else []),
            *new_aliases,
        ]
    )
    return {
        "value": primary,
        "aliases": [alias for alias in aliases if alias and alias != primary],
    }


def _merge_legacy_address_values(old: Any, new: Any) -> list[Any]:
    old_entries = old if isinstance(old, list) else ([] if old is None else [old])
    new_entries = new if isinstance(new, list) else ([] if new is None else [new])
    return [*old_entries, *new_entries]


def _smart_merge_entity_for_v2(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(old)
    for key, value in new.items():
        if key in {"entity_id", "id"}:
            continue
        if key not in merged:
            merged[key] = value
            continue
        prev = merged[key]
        if key in _SLOT_NAME_TO_ATTR_TYPE and key != "address":
            merged[key] = _merge_legacy_scalar_values(prev, value)
            continue
        if key == "address":
            merged[key] = _merge_legacy_address_values(prev, value)
            continue
        if isinstance(prev, list) and isinstance(value, list):
            if _is_flat_str_list(prev) and _is_flat_str_list(value):
                merged[key] = _dedupe_str_list([str(x).strip() for x in prev + value if str(x).strip()])
            else:
                merged[key] = list(prev) + list(value)
            continue
        if isinstance(prev, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_value(prev, value)
            continue
        merged[key] = value
    return merged


def _collapse_legacy_entities_for_v2(raw_entities: Any) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in raw_entities if isinstance(raw_entities, list) else []:
        if not isinstance(raw, dict):
            continue
        eid = str(raw.get("entity_id") or raw.get("id") or "").strip()
        if not eid:
            continue
        if eid in by_id:
            by_id[eid] = _smart_merge_entity_for_v2(by_id[eid], raw)
            continue
        by_id[eid] = dict(raw)
        order.append(eid)
    return [by_id[eid] for eid in order]


def _deep_merge_value(old: Any, new: Any) -> Any:
    if isinstance(old, dict) and isinstance(new, dict):
        if _is_storage_slot_dict(old) and _is_storage_slot_dict(new):
            old_value = str(old.get("value") or "").strip()
            new_value = str(new.get("value") or "").strip()
            primary = old_value or new_value
            aliases = _dedupe_str_list(
                [
                    *(_as_str_list(old.get("aliases"))),
                    *([new_value] if new_value and new_value != primary else []),
                    *(_as_str_list(new.get("aliases"))),
                ]
            )
            return {
                "value": primary,
                "aliases": [alias for alias in aliases if alias and alias != primary],
            }
        merged = dict(old)
        for key, value in new.items():
            if key in merged:
                merged[key] = _deep_merge_value(merged[key], value)
            else:
                merged[key] = value
        return merged
    if isinstance(old, list) and isinstance(new, list):
        if _is_flat_str_list(old) and _is_flat_str_list(new):
            return _dedupe_str_list([str(item).strip() for item in old + new if str(item).strip()])
        return list(old) + list(new)
    return new


def _merge_persona_documents(old: PersonaDocumentV2, new: PersonaDocumentV2) -> PersonaDocumentV2:
    merged_raw = _deep_merge_value(
        old.model_dump(mode="json", exclude_none=True),
        new.model_dump(mode="json", exclude_none=True),
    )
    merged_raw["persona_id"] = old.persona_id
    return PersonaDocumentV2.model_validate(merged_raw)


def merge_v2_privacy_documents(
    base: PrivacyRepositoryDocumentV2,
    patch: PrivacyRepositoryDocumentV2,
) -> PrivacyRepositoryDocumentV2:
    """按 persona_id 合并两份 v2 privacy document。"""
    by_id: dict[str, PersonaDocumentV2] = {persona.persona_id: persona for persona in base.true_personas}
    ordered_ids = [persona.persona_id for persona in base.true_personas]

    for persona in patch.true_personas:
        if persona.persona_id in by_id:
            by_id[persona.persona_id] = _merge_persona_documents(by_id[persona.persona_id], persona)
            continue
        by_id[persona.persona_id] = persona
        ordered_ids.append(persona.persona_id)

    personas = [by_id[persona_id] for persona_id in ordered_ids]
    return PrivacyRepositoryDocumentV2(
        version=V2_VERSION,
        stats=_aggregate_repository_stats(personas),
        true_personas=personas,
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


def _aggregate_repository_stats(personas: list[PersonaDocumentV2]) -> RepositoryStatsV2:
    total = ExposureInfoV2()
    slot_totals = {
        "name": ExposureInfoV2(),
        "location_clue": ExposureInfoV2(),
        "phone": ExposureInfoV2(),
        "card_number": ExposureInfoV2(),
        "bank_account": ExposureInfoV2(),
        "passport_number": ExposureInfoV2(),
        "driver_license": ExposureInfoV2(),
        "email": ExposureInfoV2(),
        "id_number": ExposureInfoV2(),
        "organization": ExposureInfoV2(),
    }
    address_total = AddressStatsV2()

    for persona in personas:
        total = _merge_exposure_info(total, persona.stats.total)
        for slot_name in slot_totals:
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


class JsonPrivacyRepository:
    """读写 rule_based 检测器使用的本地 privacy JSON 词库。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path(DEFAULT_PRIVACY_REPOSITORY_PATH)

    def load_raw(self) -> dict[str, Any]:
        """读取 JSON；文件不存在时返回空对象。"""
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}

    def merge_and_write(self, patch: dict[str, Any]) -> None:
        """将 patch 统一归一到 v2 后合并并原子写入。"""
        base_document = ensure_v2_privacy_document(self.load_raw())
        patch_document = ensure_v2_privacy_document(patch)
        merged = merge_v2_privacy_documents(base_document, patch_document)
        self._atomic_write(merged.model_dump(mode="json", exclude_none=True))

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
