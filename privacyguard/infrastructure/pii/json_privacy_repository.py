"""基于 JSON 文件的 privacy 词库读写。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from privacyguard.infrastructure.repository.schemas import (
    AddressLevelExposureStats,
    AddressStats,
    ExposureInfo,
    PersonaDocument,
    PersonaStats,
    PrivacyRepositoryDocument,
    RepositoryStats,
    SlotStats,
)

DEFAULT_PRIVACY_REPOSITORY_PATH = "data/privacy_repository.json"


class InvalidPrivacyRepositoryError(ValueError):
    """磁盘或 patch 中的 JSON 不符合 privacy 文档 schema。"""


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
_NAME_SLOT_KEYS = ("full", "family", "given", "alias", "middle")


def parse_privacy_repository_document(payload: dict[str, Any] | None) -> PrivacyRepositoryDocument:
    """校验并返回文档；空 payload 视为空词库。"""
    if not payload:
        return PrivacyRepositoryDocument(true_personas=[])
    try:
        return PrivacyRepositoryDocument.model_validate(payload)
    except ValidationError as exc:
        raise InvalidPrivacyRepositoryError(
            'privacy_repository 必须包含 {"true_personas": [...]}'
        ) from exc


def _is_storage_slot_dict(value: Any) -> bool:
    return isinstance(value, dict) and "value" in value and set(value).issubset({"value", "aliases"})


def _is_address_slot_dict(value: Any) -> bool:
    return isinstance(value, dict) and bool(value) and set(value).issubset(set(_ADDRESS_LEVEL_KEYS))


def _is_name_slot_dict(value: Any) -> bool:
    return isinstance(value, dict) and "full" in value and set(value).issubset(set(_NAME_SLOT_KEYS))


def _dedupe_str_list(values: list[str]) -> list[str]:
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


def _merge_storage_slot_dicts(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_value = str(old.get("value") or "").strip()
    new_value = str(new.get("value") or "").strip()
    primary = old_value or new_value
    aliases = _dedupe_str_list(
        [
            *(_as_str_list(old.get("aliases"))),
            *(_as_str_list(new.get("aliases"))),
        ]
    )
    return {
        "value": primary,
        "aliases": [alias for alias in aliases if alias and alias != primary],
    }


def _storage_slot_identity(item: dict[str, Any]) -> str:
    return str(item.get("value") or "").strip()


def _address_slot_identity(item: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in _ADDRESS_LEVEL_KEYS:
        level = item.get(key)
        if not _is_storage_slot_dict(level):
            continue
        values.append(f"{key}:{str(level.get('value') or '').strip()}")
    return tuple(values)


def _name_slot_identity(item: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in _NAME_SLOT_KEYS:
        level = item.get(key)
        if not _is_storage_slot_dict(level):
            continue
        values.append(f"{key}:{str(level.get('value') or '').strip()}")
    return tuple(values)


def _merge_address_slot_dicts(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(old)
    for key, value in new.items():
        if key in merged and _is_storage_slot_dict(merged[key]) and _is_storage_slot_dict(value):
            merged[key] = _merge_storage_slot_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_name_slot_dicts(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(old)
    for key, value in new.items():
        if key in merged and _is_storage_slot_dict(merged[key]) and _is_storage_slot_dict(value):
            merged[key] = _merge_storage_slot_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_storage_slot_list(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    ordered_keys: list[str] = []
    for item in [*old, *new]:
        if not _is_storage_slot_dict(item):
            continue
        key = _storage_slot_identity(item)
        if not key:
            continue
        if key in merged:
            merged[key] = _merge_storage_slot_dicts(merged[key], item)
            continue
        merged[key] = dict(item)
        ordered_keys.append(key)
    return [merged[key] for key in ordered_keys]


def _merge_address_slot_list(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    ordered_keys: list[tuple[str, ...]] = []
    for item in [*old, *new]:
        if not _is_address_slot_dict(item):
            continue
        key = _address_slot_identity(item)
        if not key:
            continue
        if key in merged:
            merged[key] = _merge_address_slot_dicts(merged[key], item)
            continue
        merged[key] = dict(item)
        ordered_keys.append(key)
    return [merged[key] for key in ordered_keys]


def _merge_name_slot_list(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    ordered_keys: list[tuple[str, ...]] = []
    for item in [*old, *new]:
        if not _is_name_slot_dict(item):
            continue
        key = _name_slot_identity(item)
        if not key:
            continue
        if key in merged:
            merged[key] = _merge_name_slot_dicts(merged[key], item)
            continue
        merged[key] = dict(item)
        ordered_keys.append(key)
    return [merged[key] for key in ordered_keys]


def _deep_merge_value(old: Any, new: Any) -> Any:
    if isinstance(old, dict) and isinstance(new, dict):
        if _is_storage_slot_dict(old) and _is_storage_slot_dict(new):
            return _merge_storage_slot_dicts(old, new)
        merged = dict(old)
        for key, value in new.items():
            if key in merged:
                merged[key] = _deep_merge_value(merged[key], value)
            else:
                merged[key] = value
        return merged
    if isinstance(old, list) and isinstance(new, list):
        if all(_is_storage_slot_dict(item) for item in [*old, *new]):
            return _merge_storage_slot_list(old, new)
        if all(_is_name_slot_dict(item) for item in [*old, *new]):
            return _merge_name_slot_list(old, new)
        if all(_is_address_slot_dict(item) for item in [*old, *new]):
            return _merge_address_slot_list(old, new)
        return list(old) + list(new)
    return new


def _merge_persona_documents(old: PersonaDocument, new: PersonaDocument) -> PersonaDocument:
    merged_raw = _deep_merge_value(
        old.model_dump(mode="json", exclude_none=True),
        new.model_dump(mode="json", exclude_none=True),
    )
    merged_raw["persona_id"] = old.persona_id
    return PersonaDocument.model_validate(merged_raw)


def merge_privacy_repository_documents(
    base: PrivacyRepositoryDocument,
    patch: PrivacyRepositoryDocument,
) -> PrivacyRepositoryDocument:
    """按 persona_id 合并两份 privacy document。"""
    by_id: dict[str, PersonaDocument] = {persona.persona_id: persona for persona in base.true_personas}
    ordered_ids = [persona.persona_id for persona in base.true_personas]

    for persona in patch.true_personas:
        if persona.persona_id in by_id:
            by_id[persona.persona_id] = _merge_persona_documents(by_id[persona.persona_id], persona)
            continue
        by_id[persona.persona_id] = persona
        ordered_ids.append(persona.persona_id)

    personas = [by_id[persona_id] for persona_id in ordered_ids]
    return PrivacyRepositoryDocument(
        stats=_aggregate_repository_stats(personas),
        true_personas=personas,
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
        """将 patch 校验后按 persona 合并并原子写入。"""
        base_document = parse_privacy_repository_document(self.load_raw())
        patch_document = parse_privacy_repository_document(patch)
        merged = merge_privacy_repository_documents(base_document, patch_document)
        self._atomic_write(merged.model_dump(mode="json", exclude_none=True))

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
