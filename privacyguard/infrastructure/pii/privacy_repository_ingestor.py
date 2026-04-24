"""本地隐私库入库 helper。

职责：
- 把"用户喂的半结构化字段"打包为符合 schema 的 `PersonaDocument`，供 scanner 消费。
- 不重跑 detector；只对原始文本做必要的轻量归一（去空白、组织去后缀、地址组件展开）。
- 未识别的后缀/未知层级静默丢弃，以保持 schema 紧致；入库侧不承担 detector 的模糊判断。

与 scanner 的契约：
- Name 的切分规则（尤其是英文 full → family/given）只在 session 消费侧生效；此处不做自动切分。
- Address 的扁平组件袋（含 suspect）由 ingestor 在此统一展开，后续 scanner 直接消费。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.repository.schemas import (
    AddressComponentSlot,
    AddressLevel,
    AddressSlotStorage,
    NameSlotStorage,
    PersonaDocument,
    PersonaSlots,
    PrivacyRepositoryDocument,
    SharedSlotStorage,
)
from privacyguard.utils.normalized_pii import (
    _organization_canonical,  # type: ignore[attr-defined]
    normalize_pii,
)


_ADDRESS_LEVEL_SET = {level.value for level in AddressLevel}


def _clean(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _dedupe_preserving_order(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in values:
        text = _clean(item)
        if text and text not in seen:
            seen[text] = None
    return list(seen.keys())


def ingest_name(
    full: str,
    *,
    family: str | None = None,
    given: str | None = None,
    alias: str | None = None,
    middle: str | None = None,
) -> NameSlotStorage:
    """打包姓名槽。full 必填；其余字段只在显式传入时生成。"""
    full_text = _clean(full)
    if not full_text:
        raise ValueError("ingest_name 要求 full 非空")

    def _slot(value: str | None) -> SharedSlotStorage | None:
        text = _clean(value)
        return SharedSlotStorage(value=text) if text else None

    return NameSlotStorage(
        full=SharedSlotStorage(value=full_text),
        family=_slot(family),
        given=_slot(given),
        alias=_slot(alias),
        middle=_slot(middle),
    )


def ingest_organization(
    raw: str,
    *,
    aliases: Iterable[str] | None = None,
) -> SharedSlotStorage:
    """打包组织槽。

    - `value` = 对输入执行一次 `_organization_canonical` 去后缀；若无后缀识别，整串原样作 value。
    - `aliases` 去重后剔除等于 value 的项；若 value 与原始文本不同，主动把原始文本加入 aliases，
      使得 scanner 可同时匹配去后缀形式与带后缀完整形式。
    """
    raw_text = _clean(raw)
    if not raw_text:
        raise ValueError("ingest_organization 要求 raw 非空")
    stripped = _organization_canonical(raw_text) or raw_text
    alias_pool: list[str] = [*(aliases or [])]
    if stripped != raw_text:
        alias_pool.append(raw_text)
    alias_list = [item for item in _dedupe_preserving_order(alias_pool) if item and item != stripped]
    return SharedSlotStorage(value=stripped, aliases=alias_list)


def _address_component_values(component_value: object) -> list[str]:
    """地址组件 value 可能是 str 或 tuple[str,...]（MULTI_ADMIN）。统一展开成多个 str。"""
    if isinstance(component_value, tuple):
        return [text for text in (_clean(item) for item in component_value) if text]
    text = _clean(component_value if isinstance(component_value, str) else "")
    return [text] if text else []


def _expand_ordered_components(
    ordered_components,
) -> list[AddressComponentSlot]:
    """把 NormalizedAddressComponent 及其 suspected 展开为扁平组件条目。

    - 每个 component 的 `level` 取末端（MULTI_ADMIN 取最末 rank）；
    - 未落入 `AddressLevel` 枚举的层级丢弃；
    - suspected 条目同规则展开（各自独立 level）。
    """
    slots: list[AddressComponentSlot] = []
    seen: set[tuple[str, str]] = set()

    def _emit(level_text: str, value_text: str) -> None:
        level_text = _clean(level_text)
        value_text = _clean(value_text)
        if not level_text or not value_text:
            return
        if level_text not in _ADDRESS_LEVEL_SET:
            return
        key = (level_text, value_text)
        if key in seen:
            return
        seen.add(key)
        slots.append(AddressComponentSlot(level=AddressLevel(level_text), value=value_text))

    for component in ordered_components or ():
        level_tuple = getattr(component, "level", ()) or ()
        primary_level = level_tuple[-1] if level_tuple else getattr(component, "component_type", "")
        for value_text in _address_component_values(getattr(component, "value", "")):
            _emit(primary_level, value_text)
        for suspect in getattr(component, "suspected", ()) or ():
            suspect_levels = getattr(suspect, "levels", ()) or ()
            suspect_level = suspect_levels[-1] if suspect_levels else ""
            _emit(suspect_level, getattr(suspect, "value", ""))
    return slots


_MAIN_LEVEL_FIELDS: tuple[str, ...] = (
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


def ingest_address(
    raw: str,
    *,
    components: Mapping[str, str | None] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AddressSlotStorage:
    """打包地址槽。

    - 若传入 `components`，优先从结构化输入构造 9 级主结构；未传入时保持空结构，依赖扁平组件袋。
    - 扁平组件袋来自 `normalize_pii` 产出的 `ordered_components`（包括 suspect）。
    - `metadata` 可选：如果调用方已持有 detector 的 trace（如 `address_component_trace`），
      可以传入让 suspect 被正确还原——本入口对 metadata 透传，不自行解析。
    """
    raw_text = _clean(raw)
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        raw_text,
        metadata=metadata,
        components=components,
    )

    main_slots: dict[str, SharedSlotStorage] = {}
    for field_name in _MAIN_LEVEL_FIELDS:
        text = _clean(normalized.components.get(field_name))
        if text:
            main_slots[field_name] = SharedSlotStorage(value=text)

    flat_components = _expand_ordered_components(normalized.ordered_components)

    if not main_slots and not flat_components:
        raise ValueError("ingest_address 未识别到任何组件，拒绝生成空地址槽")

    return AddressSlotStorage(
        components=flat_components,
        **main_slots,
    )


def build_persona_document(
    persona_id: str,
    *,
    display_name: str | None = None,
    names: Iterable[NameSlotStorage] | None = None,
    organizations: Iterable[SharedSlotStorage] | None = None,
    addresses: Iterable[AddressSlotStorage] | None = None,
    phones: Iterable[SharedSlotStorage] | None = None,
    emails: Iterable[SharedSlotStorage] | None = None,
    id_numbers: Iterable[SharedSlotStorage] | None = None,
    bank_numbers: Iterable[SharedSlotStorage] | None = None,
    passport_numbers: Iterable[SharedSlotStorage] | None = None,
    driver_licenses: Iterable[SharedSlotStorage] | None = None,
) -> PersonaDocument:
    """把各类 slot 组装为 `PersonaDocument`，便于配合 `JsonPrivacyRepository.merge_and_write`。"""
    persona_id = _clean(persona_id)
    if not persona_id:
        raise ValueError("persona_id 不能为空")

    slots_kwargs: dict[str, list] = {}
    for field_name, value in (
        ("name", list(names) if names else None),
        ("organization", list(organizations) if organizations else None),
        ("address", list(addresses) if addresses else None),
        ("phone", list(phones) if phones else None),
        ("email", list(emails) if emails else None),
        ("id_number", list(id_numbers) if id_numbers else None),
        ("bank_number", list(bank_numbers) if bank_numbers else None),
        ("passport_number", list(passport_numbers) if passport_numbers else None),
        ("driver_license", list(driver_licenses) if driver_licenses else None),
    ):
        if value:
            slots_kwargs[field_name] = value

    if not slots_kwargs:
        raise ValueError("build_persona_document 至少需要一个非空 slot 集合")

    return PersonaDocument(
        persona_id=persona_id,
        display_name=_clean(display_name) or None,
        slots=PersonaSlots(**slots_kwargs),
    )


def build_repository_document(personas: Iterable[PersonaDocument]) -> PrivacyRepositoryDocument:
    """把若干 `PersonaDocument` 包装为 `PrivacyRepositoryDocument`。"""
    return PrivacyRepositoryDocument(true_personas=list(personas))


__all__ = [
    "build_persona_document",
    "build_repository_document",
    "ingest_address",
    "ingest_name",
    "ingest_organization",
]
