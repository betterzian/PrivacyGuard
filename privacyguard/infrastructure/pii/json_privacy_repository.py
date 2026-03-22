"""基于 JSON 文件的 privacy 词库读写（仅支持 v2 schema）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from privacyguard.infrastructure.repository.schemas_v2 import (
    AddressLevelExposureStatsV2,
    AddressStatsV2,
    ExposureInfoV2,
    PersonaDocumentV2,
    PersonaStatsV2,
    PrivacyRepositoryDocumentV2,
    RepositoryStatsV2,
    SlotStatsV2,
    V2_VERSION,
)

DEFAULT_PRIVACY_REPOSITORY_PATH = "data/privacy_repository.json"


class InvalidPrivacyRepositoryError(ValueError):
    """磁盘或 patch 中的 JSON 不符合 privacy v2 文档 schema。"""


def ensure_v2_privacy_document(payload: dict[str, Any] | None) -> PrivacyRepositoryDocumentV2:
    """校验并返回 v2 文档；空 payload 视为空词库。"""
    if not payload:
        return PrivacyRepositoryDocumentV2(version=V2_VERSION, true_personas=[])
    try:
        return PrivacyRepositoryDocumentV2.model_validate(payload)
    except ValidationError as exc:
        raise InvalidPrivacyRepositoryError(
            'privacy_repository 必须为 v2：{"version": 2, "true_personas": [...]}'
        ) from exc


def _is_storage_slot_dict(value: Any) -> bool:
    return isinstance(value, dict) and "value" in value and set(value).issubset({"value", "aliases"})


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


def _is_flat_str_list(items: list[Any]) -> bool:
    return all(isinstance(x, (str, int, float)) for x in items)


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
    """读写 rule_based 检测器使用的本地 privacy JSON 词库（仅 v2）。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path(DEFAULT_PRIVACY_REPOSITORY_PATH)

    def load_raw(self) -> dict[str, Any]:
        """读取 JSON；文件不存在时返回空对象。"""
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}

    def merge_and_write(self, patch: dict[str, Any]) -> None:
        """将 patch 校验为 v2 后按 persona 合并并原子写入。"""
        base_document = ensure_v2_privacy_document(self.load_raw())
        patch_document = ensure_v2_privacy_document(patch)
        merged = merge_v2_privacy_documents(base_document, patch_document)
        self._atomic_write(merged.model_dump(mode="json", exclude_none=True))

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
