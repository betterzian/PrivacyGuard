"""基于 JSON 文件的 privacy 词库读写。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.infrastructure.repository.schemas import (
    AddressLevelExposureStats,
    AddressSlotStorage,
    AddressStats,
    ExposureInfo,
    NameSlotStorage,
    PersonaDocument,
    PersonaStats,
    PrivacyRepositoryDocument,
    RepositoryStats,
    SharedSlotStorage,
    SlotStats,
)
from privacyguard.utils.normalized_pii import (
    _canonicalize_address_component_value,  # type: ignore[attr-defined]
    normalize_pii,
)

DEFAULT_PRIVACY_REPOSITORY_PATH = "data/privacy_repository.json"


class InvalidPrivacyRepositoryError(ValueError):
    """磁盘或 patch 中的 JSON 不符合 privacy 文档 schema。"""


_ADDRESS_LEVEL_KEYS = (
    "province",
    "city",
    "district",
    "subdistrict",
    "road",
    "number",
    "poi",
    "building",
    "detail",
)
_ADDRESS_EXTRA_KEYS = ("components",)
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
    return (
        isinstance(value, dict)
        and bool(value)
        and set(value).issubset(set(_ADDRESS_LEVEL_KEYS) | set(_ADDRESS_EXTRA_KEYS))
    )


def _is_address_component_dict(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and "level" in value
        and "value" in value
        and set(value).issubset({"level", "value", "strength"})
    )


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
    components = item.get("components")
    if isinstance(components, list):
        for component in components:
            if not _is_address_component_dict(component):
                continue
            values.append(
                f"component:{str(component.get('level') or '').strip()}={str(component.get('value') or '').strip()}"
            )
    return tuple(values)


def _merge_address_component_list(
    old: list[dict[str, Any]], new: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """按 (level, value) 去重合并扁平组件袋；strength 冲突时 later-wins，非 None 优先。"""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    ordered_keys: list[tuple[str, str]] = []
    for item in [*old, *new]:
        if not _is_address_component_dict(item):
            continue
        level = str(item.get("level") or "").strip()
        value = str(item.get("value") or "").strip()
        if not level or not value:
            continue
        key = (level, value)
        payload = {"level": level, "value": value}
        strength = item.get("strength")
        if strength is not None:
            payload["strength"] = strength
        if key in merged:
            existing = merged[key]
            if "strength" in payload:
                existing["strength"] = payload["strength"]
            continue
        merged[key] = payload
        ordered_keys.append(key)
    return [merged[key] for key in ordered_keys]


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
        if key == "components":
            old_components = merged.get("components") if isinstance(merged.get("components"), list) else []
            new_components = value if isinstance(value, list) else []
            merged["components"] = _merge_address_component_list(old_components, new_components)
            continue
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
        "bank_number": ExposureInfo(),
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
        bank_number=slot_totals["bank_number"],
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


# 满足 repo 命中阈值时必须出现的"具体化层级"集合（任一即可）。
_REPO_PRECISE_KEYS: frozenset[str] = frozenset(
    {"road", "poi", "building", "unit", "room", "suite", "detail"}
)
# 用于"≥2 行政级"判定的 admin key 集合（与 _HAS_ADMIN_LEVEL_KEYS 对齐，但取广义集合便于阈值计数）。
_REPO_ADMIN_KEYS: frozenset[str] = frozenset(
    {"province", "city", "district", "district_city"}
)


@dataclass(frozen=True, slots=True)
class IndexedRepoEntity:
    """单条 repo entity 的归一索引条目。"""

    persona_id: str
    attr_type: PIIAttributeType
    normalized: NormalizedPII
    # 用于阈值过滤；预计算避免重复扫描 components。
    has_precise_component: bool
    admin_level_count: int
    road_canonical: str

    def meets_min_cardinality(self) -> bool:
        """repo entity 是否达到参与命中判定的最小信息量阈值。

        - 含 road / poi / building / unit / room / suite / detail 任一；
        - 或同时含 ≥2 个行政级（province / city / district / district_city）。
        """
        if self.has_precise_component:
            return True
        return self.admin_level_count >= 2


@dataclass(slots=True)
class RepoEntityIndex:
    """所有 attr_type 的 repo entity 归一索引。"""

    by_attr: dict[PIIAttributeType, list[IndexedRepoEntity]] = field(default_factory=dict)
    # 仅地址 attr_type 使用：road canonical → 含该 road 的 entity 列表。
    address_road_bucket: dict[str, list[IndexedRepoEntity]] = field(default_factory=dict)
    # 地址侧 road 缺失的 entity 列表，供 road-missing fallback 全扫使用。
    address_road_missing: list[IndexedRepoEntity] = field(default_factory=list)

    def candidates_for(self, attr_type: PIIAttributeType) -> list[IndexedRepoEntity]:
        return list(self.by_attr.get(attr_type, ()))


def _slot_components_from_address_storage(slot: AddressSlotStorage) -> dict[str, str]:
    """把 AddressSlotStorage 折叠为 normalize_pii(components=...) 的 flat dict。

    - 9 级主结构优先；扁平 components 列表的同名 level 仅在主结构缺失时填补。
    - 非 ASCII 空白等清洗交给 normalize_pii 内部处理，本函数只做去空白与去空。
    """
    out: dict[str, str] = {}
    for field_name in (
        "province",
        "city",
        "district",
        "subdistrict",
        "road",
        "number",
        "poi",
        "building",
        "detail",
    ):
        slot_value: SharedSlotStorage | None = getattr(slot, field_name, None)
        if slot_value is None:
            continue
        text = str(slot_value.value or "").strip()
        if text:
            out[field_name] = text
    for component in slot.components or ():
        level = component.level.value
        text = str(component.value or "").strip()
        if not text:
            continue
        out.setdefault(level, text)
    return out


def _normalize_address_storage(slot: AddressSlotStorage) -> NormalizedPII | None:
    components = _slot_components_from_address_storage(slot)
    if not components:
        return None
    raw_text = "".join(value for value in components.values() if value)
    return normalize_pii(PIIAttributeType.ADDRESS, raw_text, components=components)


def _normalize_name_storage(slot: NameSlotStorage) -> NormalizedPII | None:
    components: dict[str, str] = {}
    for field_name in ("full", "family", "given", "alias", "middle"):
        slot_value: SharedSlotStorage | None = getattr(slot, field_name, None)
        if slot_value is None:
            continue
        text = str(slot_value.value or "").strip()
        if text:
            components[field_name] = text
    if not components:
        return None
    full = components.get("full") or components.get("family") or components.get("given") or ""
    return normalize_pii(PIIAttributeType.NAME, full, components=components)


def _normalize_scalar_storage(
    attr_type: PIIAttributeType, slot: SharedSlotStorage
) -> NormalizedPII | None:
    text = str(slot.value or "").strip()
    if not text:
        return None
    return normalize_pii(attr_type, text)


def _build_address_index_entry(persona_id: str, slot: AddressSlotStorage) -> IndexedRepoEntity | None:
    normalized = _normalize_address_storage(slot)
    if normalized is None:
        return None
    components = normalized.components
    has_precise = any(str(components.get(k) or "").strip() for k in _REPO_PRECISE_KEYS)
    admin_count = sum(1 for k in _REPO_ADMIN_KEYS if str(components.get(k) or "").strip())
    road_value = str(components.get("road") or "").strip()
    road_canonical = (
        _canonicalize_address_component_value("road", road_value) if road_value else ""
    )
    return IndexedRepoEntity(
        persona_id=persona_id,
        attr_type=PIIAttributeType.ADDRESS,
        normalized=normalized,
        has_precise_component=has_precise,
        admin_level_count=admin_count,
        road_canonical=road_canonical,
    )


def _build_simple_index_entry(
    persona_id: str,
    attr_type: PIIAttributeType,
    normalized: NormalizedPII | None,
) -> IndexedRepoEntity | None:
    if normalized is None:
        return None
    return IndexedRepoEntity(
        persona_id=persona_id,
        attr_type=attr_type,
        normalized=normalized,
        has_precise_component=False,
        admin_level_count=0,
        road_canonical="",
    )


# 非地址、非姓名的 attr_type → PersonaSlots 字段名。
_SCALAR_SLOT_FIELDS: tuple[tuple[PIIAttributeType, str], ...] = (
    (PIIAttributeType.PHONE, "phone"),
    (PIIAttributeType.BANK_NUMBER, "bank_number"),
    (PIIAttributeType.PASSPORT_NUMBER, "passport_number"),
    (PIIAttributeType.DRIVER_LICENSE, "driver_license"),
    (PIIAttributeType.EMAIL, "email"),
    (PIIAttributeType.ID_NUMBER, "id_number"),
    (PIIAttributeType.ORGANIZATION, "organization"),
)


def _build_repo_entity_index(document: PrivacyRepositoryDocument) -> RepoEntityIndex:
    index = RepoEntityIndex()
    for persona in document.true_personas:
        slots = persona.slots
        if slots.address:
            for slot in slots.address:
                entry = _build_address_index_entry(persona.persona_id, slot)
                if entry is None:
                    continue
                index.by_attr.setdefault(PIIAttributeType.ADDRESS, []).append(entry)
                if entry.road_canonical:
                    index.address_road_bucket.setdefault(entry.road_canonical, []).append(entry)
                else:
                    index.address_road_missing.append(entry)
        if slots.name:
            for slot in slots.name:
                entry = _build_simple_index_entry(
                    persona.persona_id,
                    PIIAttributeType.NAME,
                    _normalize_name_storage(slot),
                )
                if entry is not None:
                    index.by_attr.setdefault(PIIAttributeType.NAME, []).append(entry)
        for attr_type, field_name in _SCALAR_SLOT_FIELDS:
            slot_list: list[SharedSlotStorage] | None = getattr(slots, field_name, None)
            if not slot_list:
                continue
            for slot in slot_list:
                entry = _build_simple_index_entry(
                    persona.persona_id,
                    attr_type,
                    _normalize_scalar_storage(attr_type, slot),
                )
                if entry is not None:
                    index.by_attr.setdefault(attr_type, []).append(entry)
    return index


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

    def load_indexed_entities(self) -> RepoEntityIndex:
        """加载并归一全部 persona slots，构造可查询的 repo entity 索引。

        - 每个 slot 走 `normalize_pii`，按 attr_type 入桶；
        - 地址条目额外按 road canonical 进 γ 桶，缺 road 的进 fallback 列表；
        - 仅作"加载即归一"的简单实现；不做缓存——`merge_and_write` 后调用方需重新拉取。
        """
        document = parse_privacy_repository_document(self.load_raw())
        return _build_repo_entity_index(document)

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
