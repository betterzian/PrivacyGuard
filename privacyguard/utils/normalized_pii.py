"""统一 PII 归一与实体判定。"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.infrastructure.pii.address.lexicon import collect_components
from privacyguard.infrastructure.pii.detector.lexicon_loader import load_company_suffixes
from privacyguard.utils.pii_value import parse_name_components

_NAME_COMPONENT_KEYS = ("full", "family", "given", "alias", "middle")
_ADDRESS_COMPONENT_KEYS = (
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
_ADDRESS_MATCH_KEYS = ("province", "city", "district", "street_admin", "town", "village", "road", "compound")
_ADDRESS_DETAIL_KEYS = ("building", "unit", "floor", "room")
_LOCAL_ADMIN_KEYS = ("street_admin", "town", "village")
_ADDRESS_COMPONENT_ALIASES = {"street": "road", "state": "province"}
_PUNCT_TRIM_RE = re.compile(r"[\s\-_.,，。:：;；/\\|()（）【】\[\]#]+")
_DIGIT_RE = re.compile(r"\d+")
_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z][A-Za-z .,'\-]{0,80}$")


def normalize_pii(
    attr_type: PIIAttributeType,
    raw_text: str,
    *,
    metadata: Mapping[str, object] | None = None,
    components: Mapping[str, str | None] | None = None,
) -> NormalizedPII:
    """统一归一入口。"""
    normalized_raw = str(raw_text or "")
    if attr_type == PIIAttributeType.NAME:
        return _normalize_name(raw_text=normalized_raw, metadata=metadata, components=components)
    if attr_type == PIIAttributeType.ADDRESS:
        return _normalize_address(raw_text=normalized_raw, metadata=metadata, components=components)
    if attr_type == PIIAttributeType.EMAIL:
        canonical = re.sub(r"\s+", "", normalized_raw).lower()
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.ORGANIZATION:
        canonical = _organization_canonical(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {
        PIIAttributeType.PHONE,
        PIIAttributeType.CARD_NUMBER,
        PIIAttributeType.BANK_ACCOUNT,
        PIIAttributeType.ID_NUMBER,
    }:
        canonical = _digits_only(normalized_raw)
        if attr_type == PIIAttributeType.PHONE:
            canonical = _normalize_phone_digits(canonical)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {PIIAttributeType.PASSPORT_NUMBER, PIIAttributeType.DRIVER_LICENSE}:
        canonical = _alnum_only(normalized_raw).upper()
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.TIME:
        canonical = _compact_component_text(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.DETAILS:
        canonical = _compact_component_text(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    canonical = _compact_component_text(normalized_raw)
    return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)


def same_entity(left: NormalizedPII | None, right: NormalizedPII | None) -> bool:
    """判断两个归一结果是否为同一实体。"""
    if left is None or right is None or left.attr_type != right.attr_type:
        return False
    if left.attr_type == PIIAttributeType.NAME:
        return _same_name(left, right)
    if left.attr_type == PIIAttributeType.ORGANIZATION:
        return _same_organization(left, right)
    if left.attr_type == PIIAttributeType.ADDRESS:
        return _same_address(left, right)
    return bool(left.canonical and left.canonical == right.canonical)


def normalized_primary_text(normalized: NormalizedPII | None) -> str:
    """返回稳定主文本。"""
    if normalized is None:
        return ""
    return normalized.canonical or normalized.raw_text.strip()


def build_match_terms(normalized: NormalizedPII | None) -> tuple[str, ...]:
    """返回统一匹配关键词。"""
    if normalized is None:
        return ()
    return normalized.match_terms


def render_address_text(components: Mapping[str, str | None]) -> str:
    """按稳定顺序渲染结构化地址。"""
    ordered_values = [str(components.get(key) or "").strip() for key in _ADDRESS_COMPONENT_KEYS]
    return "".join(value for value in ordered_values if value)


def _scalar_normalized(attr_type: PIIAttributeType, raw_text: str, canonical: str) -> NormalizedPII:
    canonical_value = canonical.strip()
    match_terms = (canonical_value,) if canonical_value else ()
    identity = {"canonical": canonical_value} if canonical_value else {}
    return NormalizedPII(
        attr_type=attr_type,
        raw_text=raw_text,
        canonical=canonical_value,
        components={},
        match_terms=match_terms,
        identity=identity,
    )


def _normalize_name(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> NormalizedPII:
    name_components = _name_components(raw_text=raw_text, metadata=metadata, components=components)
    full_raw = name_components.get("full", raw_text)
    canonical = _name_canonical(full_raw)
    normalized_components = {
        key: value
        for key, value in ((key, str(name_components.get(key) or "").strip()) for key in _NAME_COMPONENT_KEYS)
        if value
    }
    match_terms = tuple(
        term
        for key in ("full", "family", "given", "alias")
        if (term := normalized_components.get(key))
    )
    identity = {}
    if normalized_components.get("family"):
        identity["family"] = _name_canonical(normalized_components["family"])
    if normalized_components.get("given"):
        identity["given"] = _name_canonical(normalized_components["given"])
    return NormalizedPII(
        attr_type=PIIAttributeType.NAME,
        raw_text=raw_text,
        canonical=canonical,
        components=normalized_components,
        match_terms=_dedupe_terms(match_terms),
        identity=identity,
    )


def _normalize_address(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> NormalizedPII:
    raw_components = _address_components(raw_text=raw_text, metadata=metadata, components=components)
    normalized_components = {
        key: str(raw_components.get(key) or "").strip()
        for key in _ADDRESS_COMPONENT_KEYS
        if str(raw_components.get(key) or "").strip()
    }
    canonical_parts = []
    identity: dict[str, str] = {}
    address_part_values: list[str] = []
    for key in _ADDRESS_COMPONENT_KEYS:
        value = normalized_components.get(key)
        if not value:
            continue
        normalized_value = _compact_component_text(value)
        if not normalized_value:
            continue
        canonical_parts.append(f"{key}={normalized_value}")
        identity[key] = normalized_value
        if key in _ADDRESS_MATCH_KEYS:
            address_part_values.append(normalized_value)
    details_tokens = _address_detail_tokens(normalized_components)
    if address_part_values:
        identity["address_part"] = "|".join(address_part_values)
    if details_tokens:
        identity["details_part"] = "-".join(details_tokens)
    match_terms = tuple(
        normalized_components[key]
        for key in _ADDRESS_MATCH_KEYS
        if normalized_components.get(key)
    )
    return NormalizedPII(
        attr_type=PIIAttributeType.ADDRESS,
        raw_text=raw_text or render_address_text(normalized_components),
        canonical="|".join(canonical_parts),
        components=normalized_components,
        match_terms=_dedupe_terms(match_terms),
        identity=identity,
    )


def _same_name(left: NormalizedPII, right: NormalizedPII) -> bool:
    left_given = left.identity.get("given", "")
    right_given = right.identity.get("given", "")
    if not left_given or not right_given:
        return False
    left_family = left.identity.get("family", "")
    right_family = right.identity.get("family", "")
    if left_family and right_family:
        return left_family == right_family and left_given == right_given
    return left_given == right_given


def _same_organization(left: NormalizedPII, right: NormalizedPII) -> bool:
    left_value = left.canonical
    right_value = right.canonical
    if not left_value or not right_value:
        return False
    shorter, longer = sorted((left_value, right_value), key=len)
    return shorter in longer


def _same_address(left: NormalizedPII, right: NormalizedPII) -> bool:
    for key in ("province", "city", "district"):
        if not _shared_component_subset(left.identity, right.identity, key):
            return False
    if not _local_admin_group_matches(left.identity, right.identity):
        return False
    for key in ("road", "compound"):
        if not _shared_component_subset(left.identity, right.identity, key):
            return False
    left_details = left.identity.get("details_part", "")
    right_details = right.identity.get("details_part", "")
    if left_details and right_details and not _is_detail_subsequence(left_details, right_details):
        return False
    if not left.identity.get("address_part") or not right.identity.get("address_part"):
        return False
    return True


def _shared_component_subset(left: Mapping[str, str], right: Mapping[str, str], key: str) -> bool:
    left_value = left.get(key, "")
    right_value = right.get(key, "")
    if not left_value or not right_value:
        return True
    shorter, longer = sorted((left_value, right_value), key=len)
    return shorter in longer


def _local_admin_group_matches(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    left_values = [left.get(key, "") for key in _LOCAL_ADMIN_KEYS if left.get(key, "")]
    right_values = [right.get(key, "") for key in _LOCAL_ADMIN_KEYS if right.get(key, "")]
    if not left_values or not right_values:
        return True
    for left_value in left_values:
        for right_value in right_values:
            shorter, longer = sorted((left_value, right_value), key=len)
            if shorter in longer:
                return True
    return False


def _is_detail_subsequence(left: str, right: str) -> bool:
    left_tokens = left.split("-") if left else []
    right_tokens = right.split("-") if right else []
    shorter, longer = (left_tokens, right_tokens) if len(left_tokens) <= len(right_tokens) else (right_tokens, left_tokens)
    if not shorter:
        return True
    pointer = 0
    for token in longer:
        if pointer < len(shorter) and token == shorter[pointer]:
            pointer += 1
    return pointer == len(shorter)


def _name_components(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> dict[str, str]:
    if components:
        return {
            key: str(value).strip()
            for key, value in components.items()
            if key in _NAME_COMPONENT_KEYS and str(value or "").strip()
        }
    parsed = parse_name_components(raw_text)
    resolved = {
        "full": parsed.full_text or parsed.original_text or raw_text,
        "family": parsed.family_text or "",
        "given": parsed.given_text or "",
        "middle": parsed.middle_text or "",
    }
    component_values = _metadata_values(metadata, "name_component")
    if "alias" in component_values:
        resolved["alias"] = raw_text.strip()
    return {key: value for key, value in resolved.items() if value}


def _address_components(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> dict[str, str]:
    if components:
        return {
            key: str(value).strip()
            for key, value in components.items()
            if key in _ADDRESS_COMPONENT_KEYS and str(value or "").strip()
        }
    traced = _components_from_address_metadata(metadata)
    if traced:
        return traced
    collected = collect_components(raw_text, locale_profile="mixed")
    resolved: dict[str, str] = {}
    for item in collected:
        component_type = _ADDRESS_COMPONENT_ALIASES.get(item.component_type, item.component_type)
        if component_type not in _ADDRESS_COMPONENT_KEYS:
            continue
        value = str(item.value_text or "").strip()
        if not value:
            continue
        previous = resolved.get(component_type, "")
        if len(value) > len(previous):
            resolved[component_type] = value
    return resolved


def _components_from_address_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    traces = _metadata_values(metadata, "address_component_trace")
    resolved: dict[str, str] = {}
    for item in traces:
        if ":" not in item:
            continue
        component_type, value = item.split(":", 1)
        key = _ADDRESS_COMPONENT_ALIASES.get(component_type.strip(), component_type.strip())
        normalized_value = value.strip()
        if key not in _ADDRESS_COMPONENT_KEYS or not normalized_value:
            continue
        previous = resolved.get(key, "")
        if len(normalized_value) > len(previous):
            resolved[key] = normalized_value
    return resolved


def _metadata_values(metadata: Mapping[str, object] | None, key: str) -> tuple[str, ...]:
    if metadata is None:
        return ()
    raw = metadata.get(key)
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw.strip(),) if raw.strip() else ()
    if isinstance(raw, Iterable):
        values: list[str] = []
        for item in raw:
            text = str(item or "").strip()
            if text:
                values.append(text)
        return tuple(values)
    text = str(raw).strip()
    return (text,) if text else ()


def _normalize_phone_digits(digits: str) -> str:
    if len(digits) == 13 and digits.startswith("86") and re.fullmatch(r"1[3-9]\d{9}", digits[2:]):
        return digits[2:]
    if len(digits) == 11 and digits.startswith("1") and re.fullmatch(r"[2-9]\d{9}", digits[1:]):
        return digits[1:]
    return digits


def _organization_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    changed = True
    while changed:
        changed = False
        for suffix in load_company_suffixes():
            if text.lower().endswith(suffix.lower()) and len(text) > len(suffix):
                text = text[: -len(suffix)].rstrip()
                changed = True
                break
    return _compact_component_text(text)


def _name_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    if _NAME_COMPONENT_RE.fullmatch(text):
        return re.sub(r"\s+", " ", text).strip().lower()
    return "".join(char for char in re.sub(r"\s+", "", text) if char not in "·•・")


def _address_detail_tokens(components: Mapping[str, str]) -> list[str]:
    tokens: list[str] = []
    for key in _ADDRESS_DETAIL_KEYS:
        value = str(components.get(key) or "").strip()
        if not value:
            continue
        digits = _DIGIT_RE.findall(value)
        if digits:
            tokens.append(digits[-1])
    return tokens


def _digits_only(value: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", value or "") if char.isdigit())


def _alnum_only(value: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", value or "") if char.isalnum())


def _compact_component_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    text = _PUNCT_TRIM_RE.sub("", text)
    return text.lower() if any(char.isascii() and char.isalpha() for char in text) else text


def _dedupe_terms(terms: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    for item in terms:
        text = str(item or "").strip()
        if text and text not in ordered:
            ordered.append(text)
    return tuple(ordered)


__all__ = [
    "NormalizedPII",
    "build_match_terms",
    "normalize_pii",
    "normalized_primary_text",
    "render_address_text",
    "same_entity",
]
