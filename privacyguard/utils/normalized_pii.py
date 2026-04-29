"""统一 PII 归一与实体判定。"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import (
    NormalizedAddressComponent,
    NormalizedAddressSuspectEntry,
    NormalizedPII,
)
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_country_geo_aliases,
    load_en_company_suffixes,
    load_zh_company_suffixes,
    load_en_address_suffix_strippers,
    load_en_us_states,
    load_zh_address_suffix_strippers,
    load_zh_control_values,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    OCR_BREAK,
    _OCR_INLINE_GAP_TOKEN,
)
from privacyguard.utils.pii_value import parse_name_components

_NAME_COMPONENT_KEYS = ("full", "family", "given", "alias", "middle")
_ADDRESS_COMPONENT_KEYS = (
    "country",
    "multi_admin",
    "province",
    "city",
    "district",
    "district_city",
    "subdistrict",
    "road",
    "house_number",
    "number",
    "poi",
    "building",
    "unit",
    "room",
    "suite",
    "detail",
    "postal_code",
)
_ADDRESS_MATCH_KEYS = (
    "country",
    "multi_admin",
    "province",
    "city",
    "district",
    "district_city",
    "subdistrict",
    "road",
    "poi",
)
_ADDRESS_DETAIL_KEYS = ("building", "unit", "room", "suite", "detail")
_ADDRESS_COMPONENT_COMPARE_KEYS = (
    "country",
    "multi_admin",
    "province",
    "city",
    "district",
    "district_city",
    "road",
    "subdistrict",
)
_ORDERED_COMPONENT_KEYS = (
    "country",
    "multi_admin",
    "province",
    "city",
    "district",
    "district_city",
    "road",
    "house_number",
    "number",
    "subdistrict",
    "poi",
    "building",
    "unit",
    "room",
    "suite",
    "detail",
    "postal_code",
)
# 单一行政层级字符串。与 detector 侧 _ADMIN_RANK 对齐：DISTRICT_CITY 与 DISTRICT 同级。
_ADMIN_LEVEL_KEYS = ("country", "province", "city", "district", "district_city", "subdistrict")
# 表明"存在行政层级信息"的 key 集合（用于 has_admin_static 预判），subdistrict 语义上偏 detail 不计入。
_HAS_ADMIN_LEVEL_KEYS = frozenset({"country", "province", "city", "district", "district_city"})
_ADMIN_LEVEL_RANK: dict[str, int] = {
    "subdistrict": 1,
    "district": 2,
    "district_city": 2,
    "city": 3,
    "province": 4,
    "country": 5,
}
# MULTI_ADMIN 解释枚举上限，避免病态 trace 爆炸。
_MULTI_ADMIN_INTERP_CAP = 4
# 与 trace 对齐的 POI 终端 key（仅用于 same_entity 比较时剥末尾 key），可选。
_ADDRESS_OPTIONAL_KEYS = frozenset({"poi_key"})
# 旧类型到新类型的别名映射，兼容历史 trace 数据。
_ADDRESS_COMPONENT_ALIASES = {
    "street": "road",
    "state": "province",
    "compound": "poi",
    "street_admin": "subdistrict",
    "town": "subdistrict",
    "village": "subdistrict",
    "house_number": "number",
    "unit": "unit",
    "floor": "detail",
    "room": "room",
    "street_number": "number",
    "zip": "postal_code",
    "zipcode": "postal_code",
    "postal": "postal_code",
    "country_region": "country",
}
_PUNCT_TRIM_RE = re.compile(r"[\s\-_.,，。:：;；/\\|()（）【】\[\]#]+")
_DIGIT_RE = re.compile(r"\d+")
_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z][A-Za-z .,'\-]{0,80}$")
_ZH_NUMERAL_CHARS = set("零〇一二三四五六七八九十百千两")
_AMOUNT_UNIT_RE = re.compile(
    r"(?i)(?:us\$|usd|rmb|cny|eur|gbp|dollars?|yuan|元|美元|欧元|英镑)"
)
_PHONE_US_COUNTRY_CODE_PREFIX_RE = re.compile(r"^\s*(?:\(\+?1\)|\+1)")
_PHONE_US_TRUNK_AREA_PREFIX_RE = re.compile(r"^\s*1[ \-]*\([2-9]\d{2}\)")
_PHONE_CN_MOBILE_RE = re.compile(r"1[3-9]\d{9}")
_PHONE_US_TEN_DIGIT_RE = re.compile(r"[2-9]\d{9}")
_PRECISE_ADDRESS_COMPONENT_KEYS = frozenset({"building", "unit", "room", "suite"})
_EXACT_ADDRESS_COMPONENT_COMPARE_KEYS = _PRECISE_ADDRESS_COMPONENT_KEYS | {"detail"}
_EN_ADDRESS_COMPONENT_PREFIX_PATTERNS: dict[str, re.Pattern[str]] = {
    "unit": re.compile(r"^(?:apartment|apt|unit)\b[\s\-:.,#]*", re.IGNORECASE),
    "room": re.compile(r"^(?:room|rm)\b[\s\-:.,#]*", re.IGNORECASE),
    "suite": re.compile(r"^(?:suite|ste)\b[\s\-:.,#]*", re.IGNORECASE),
    "building": re.compile(r"^(?:building|bldg|tower|block)\b[\s\-:.,#]*", re.IGNORECASE),
    "detail": re.compile(r"^(?:floor|fl|level|lvl|lot|slip|space|spc)\b[\s\-:.,#]*", re.IGNORECASE),
}


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
        canonical_hint = _metadata_canonical_value(metadata)
        canonical = _organization_canonical(canonical_hint or normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {
        PIIAttributeType.PHONE,
        PIIAttributeType.BANK_NUMBER,
        PIIAttributeType.ID_NUMBER,
    }:
        canonical = _digits_only(normalized_raw)
        if attr_type == PIIAttributeType.PHONE:
            canonical = _normalize_phone_digits(canonical, raw_text=normalized_raw, metadata=metadata)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {PIIAttributeType.PASSPORT_NUMBER, PIIAttributeType.DRIVER_LICENSE, PIIAttributeType.ALNUM}:
        canonical = _alnum_only(normalized_raw).upper()
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.LICENSE_PLATE:
        canonical = _license_plate_canonical(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.TIME:
        canonical = _compact_component_text(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.AMOUNT:
        canonical = _amount_canonical(normalized_raw)
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
    if not raw_components:
        return _fallback_address_normalized(raw_text)
    ordered_components = _address_ordered_components(metadata=metadata, components=components)
    component_precision_mode = _address_prefers_component_precision_raw(raw_text, raw_components, ordered_components)
    normalized_components = {
        key: str(raw_components.get(key) or "").strip()
        for key in _ADDRESS_COMPONENT_KEYS
        if str(raw_components.get(key) or "").strip()
    }
    # POI 与「最后一个 key」成对来自 trace，不参与 canonical 拼接字段集合。
    if str(raw_components.get("poi_key") or "").strip():
        normalized_components["poi_key"] = str(raw_components["poi_key"]).strip()
    canonical_parts = []
    identity: dict[str, str] = {}
    address_part_values: list[str] = []
    for key in _ADDRESS_COMPONENT_KEYS:
        value = normalized_components.get(key)
        if not value:
            continue
        normalized_value = _canonicalize_address_component_value(key, value)
        if not normalized_value:
            continue
        canonical_parts.append(f"{key}={normalized_value}")
        identity[key] = normalized_value
        if key in _ADDRESS_MATCH_KEYS:
            address_part_values.append(normalized_value)
    numbers = [] if component_precision_mode else _address_numbers(
        metadata=metadata,
        normalized_components=normalized_components,
    )
    details_tokens = _address_detail_tokens(normalized_components)
    if address_part_values:
        identity["address_part"] = "|".join(address_part_values)
    if numbers and not component_precision_mode:
        canonical_parts.append(f"number=[{','.join(numbers)}]")
    if details_tokens and not component_precision_mode:
        identity["details_part"] = "-".join(details_tokens)
    if pk := normalized_components.get("poi_key"):
        identity["poi_key"] = pk
    match_terms = tuple(
        term
        for key in _ADDRESS_MATCH_KEYS
        if (value := normalized_components.get(key))
        if (term := _address_match_term(key, value))
    )
    # has_admin_static：ordered_components 的任一 level 命中 _HAS_ADMIN_LEVEL_KEYS 即为真。
    # SUBDISTRICT 语义偏 detail，不计入行政层级判定。
    has_admin_static = any(
        any(level in _HAS_ADMIN_LEVEL_KEYS for level in component.level)
        for component in ordered_components
    )
    return NormalizedPII(
        attr_type=PIIAttributeType.ADDRESS,
        raw_text=raw_text or render_address_text(normalized_components),
        canonical="|".join(canonical_parts),
        components=normalized_components,
        match_terms=_dedupe_terms(match_terms),
        identity=identity,
        numbers=tuple(numbers),
        ordered_components=ordered_components,
        has_admin_static=has_admin_static,
    )


def _fallback_address_normalized(raw_text: str) -> NormalizedPII:
    """地址没有任何结构化组件时，退化为 cleantext canonical。"""
    canonical = _address_fallback_cleantext(raw_text)
    match_terms = (canonical,) if canonical else ()
    identity = {"canonical": canonical} if canonical else {}
    return NormalizedPII(
        attr_type=PIIAttributeType.ADDRESS,
        raw_text=raw_text,
        canonical=canonical,
        components={},
        match_terms=match_terms,
        identity=identity,
        ordered_components=(),
    )


def _address_fallback_cleantext(raw_text: str) -> str:
    """复用 detector 候选文本清洗语义，但不做地址正则兜底解析。"""
    cleaned = str(raw_text or "")
    cleaned = cleaned.replace(_OCR_INLINE_GAP_TOKEN, " ")
    cleaned = cleaned.replace(OCR_BREAK, " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" \t\r\n:：-—|,，;；/\\")
    cleaned = re.sub(r"[。！!？?]+$", "", cleaned).strip()
    return cleaned


def _address_match_term(component_key: str, component_value: str) -> str:
    """生成地址组件的匹配 term。

    仅用于 match_terms：去掉组件后缀类别词，让词典匹配更短更稳定。
    例如：city=上海市 -> 上海；district=浦东新区 -> 浦东；compound=阳光小区 -> 阳光。
    """
    value = str(component_value or "").strip()
    if not value:
        return ""
    # 英文地址：match_terms 保留原始大小写与后缀（如 “Harbor Ave”、“North Plaza”），避免过度截断。
    # 中文地址：为了词典匹配稳定性，仍做 suffix-only 裁剪（如 “上海市”->“上海”）。
    compact = _compact_component_text(value)
    if not compact:
        return ""
    if _looks_like_en_text(compact):
        return value
    # 用 scanner 词典派生的 suffix-only 裁剪器作为单一真源，确保 session/local 一致。
    strippers = load_zh_address_suffix_strippers()
    pattern = strippers.get(component_key)
    if pattern is None:
        return compact
    stripped = pattern.sub("", compact).strip()
    return stripped or compact


def _looks_like_en_text(text: str) -> bool:
    """粗略判断文本是否更像英文地址片段。"""
    return any(("A" <= ch <= "Z") or ("a" <= ch <= "z") for ch in text)


def _address_prefers_component_precision_raw(
    raw_text: str,
    components: Mapping[str, str],
    ordered_components: tuple[NormalizedAddressComponent, ...],
) -> bool:
    if any(key in components for key in ("unit", "room", "suite")):
        return True
    if any(component.component_type in {"unit", "room", "suite"} for component in ordered_components):
        return True
    if _looks_like_en_text(raw_text):
        return True
    return any(_looks_like_en_text(str(value or "")) for value in components.values())


def _address_prefers_component_precision(normalized: NormalizedPII) -> bool:
    return _address_prefers_component_precision_raw(
        normalized.raw_text,
        normalized.components,
        normalized.ordered_components,
    )


def _canonicalize_en_address_component_value(component_key: str, value: str) -> str:
    """英文细粒度组件统一去掉类别前缀，避免结构化输入与 detector trace 语义不一致。"""
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    if component_key == "unit":
        text = re.sub(r"^\s*#\s*", "", text)
    pattern = _EN_ADDRESS_COMPONENT_PREFIX_PATTERNS.get(component_key)
    if pattern is not None:
        stripped = pattern.sub("", text, count=1).strip()
        if stripped:
            text = stripped
    return _compact_component_text(text)


def _canonicalize_address_component_value(component_key: str, value: str) -> str:
    """按组件类型生成稳定 canonical。"""
    text = str(value or "").strip()
    if not text:
        return ""
    if component_key == "province":
        return _canonicalize_us_state(text) or _compact_component_text(text)
    if component_key == "country":
        return _canonicalize_en_country(text) or _compact_component_text(text)
    if component_key == "postal_code":
        return re.sub(r"[^0-9-]", "", unicodedata.normalize("NFKC", text))
    if component_key in {"house_number", "number"}:
        return _alnum_only(text).upper()
    if component_key in _PRECISE_ADDRESS_COMPONENT_KEYS or component_key == "detail":
        return _canonicalize_en_address_component_value(component_key, text)
    return _compact_component_text(text)


def _canonicalize_us_state(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    state_map = load_en_us_states()
    upper = text.upper()
    if upper in state_map:
        return upper
    by_name = {name.lower(): code for code, name in state_map.items()}
    return by_name.get(text.lower(), "")


def _canonicalize_en_country(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    alias_key = text.casefold() if text.isascii() else text
    for alias in load_country_geo_aliases():
        item_key = alias.text.casefold() if alias.text.isascii() else alias.text
        if item_key == alias_key:
            return alias.canonical
    return ""


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
    """§7.5 canonical 比较：has_admin 闸门 + admin 多解释枚举。

    流程：
    1. address_part 闸门：任一侧缺则失败。
    2. 顶层 identity（country / province / number / postal_code）：双侧俱存时必须相等。
    3. 非 admin 层（road / poi / building / unit / room / suite / detail）：按 component_type peer 比较，
       并顺带累计 has_admin Case 2（suspect step1 失败 + entry.level ⊂ admin 集合）。
    4. admin 层（country / province / city / district / district_city / subdistrict）：
       走多解释枚举，返回 match / inconclusive / mismatch。
       - match → 计入命中；
       - mismatch → 失败；
       - inconclusive → 若双方 has_admin=True 则失败，否则放行不计命中。
    5. numbers、subdistrict（component_type 视角）、poi list。
    6. substantive_hits / denom > 0.3。
    """
    left_fallback = _is_fallback_address(left)
    right_fallback = _is_fallback_address(right)
    if left_fallback or right_fallback:
        return left_fallback and right_fallback and _same_fallback_address(left, right)

    if not left.identity.get("address_part") or not right.identity.get("address_part"):
        return False

    substantive_hits = 0
    component_precision_mode = _address_prefers_component_precision(left) or _address_prefers_component_precision(right)

    for key in ("country", "province", "number", "postal_code"):
        if not _identity_field_match_if_both_present(left, right, key):
            return False
        if left.identity.get(key) and right.identity.get(key):
            substantive_hits += 1

    if component_precision_mode and _has_precise_component_cross_key_conflict(left, right):
        return False

    # has_admin 动态累计器：static（Case 1）作为起点，非 admin 层再累计 Case 2。
    left_has_admin = left.has_admin_static
    right_has_admin = right.has_admin_static

    # 非 admin 层比较 + has_admin Case 2 累计
    for key in ("road", "poi", "building", "unit", "room", "suite", "detail"):
        ok, left_admin_hit, right_admin_hit = _compare_peer_with_suspect_case2(
            left,
            right,
            key,
            exact_compare=component_precision_mode and key in _EXACT_ADDRESS_COMPONENT_COMPARE_KEYS,
        )
        if not ok:
            return False
        left_has_admin = left_has_admin or left_admin_hit
        right_has_admin = right_has_admin or right_admin_hit
        if _ordered_component_by_type(left, key) and _ordered_component_by_type(right, key):
            substantive_hits += 1

    # admin 层多解释枚举
    admin_result = _compare_admin_levels_with_interpretations(left, right)
    if admin_result == "mismatch":
        return False
    if admin_result == "match":
        substantive_hits += 1
    else:  # inconclusive：双方都 has_admin 才否决
        if left_has_admin and right_has_admin:
            return False

    if not component_precision_mode:
        if left.numbers and right.numbers and not _numbers_match(left.numbers, right.numbers):
            return False
        if left.numbers and right.numbers:
            substantive_hits += 1

    # subdistrict：走非 admin peer 路径；不累计 has_admin（SUBDISTRICT ∉ _HAS_ADMIN_LEVEL_KEYS）
    ok_sd, _lhit_sd, _rhit_sd = _compare_peer_with_suspect_case2(
        left, right, "subdistrict",
    )
    if not ok_sd:
        return False
    if (
        _ordered_component_by_type(left, "subdistrict")
        and _ordered_component_by_type(right, "subdistrict")
    ):
        substantive_hits += 1

    # poi 列表：双向子集
    if not _compare_poi_list(left, right):
        return False

    denom = min(len(left.ordered_components), len(right.ordered_components))
    if denom <= 0:
        return False
    return (substantive_hits / denom) > 0.3


def _is_fallback_address(normalized: NormalizedPII) -> bool:
    """判断地址是否为无组件 fallback 归一结果。"""
    return (
        normalized.attr_type == PIIAttributeType.ADDRESS
        and not normalized.components
        and not normalized.ordered_components
    )


def _same_fallback_address(left: NormalizedPII, right: NormalizedPII) -> bool:
    """无组件地址按 canonical 等值或高覆盖子串判同实体。"""
    left_value = str(left.canonical or "").strip()
    right_value = str(right.canonical or "").strip()
    if not left_value or not right_value:
        return False
    if left_value == right_value:
        return True
    shorter, longer = sorted((left_value, right_value), key=len)
    return shorter in longer and (len(shorter) / len(longer)) > 0.5


def _identity_field_match_if_both_present(
    left: NormalizedPII,
    right: NormalizedPII,
    key: str,
) -> bool:
    left_value = str(left.identity.get(key) or "").strip()
    right_value = str(right.identity.get(key) or "").strip()
    if not left_value or not right_value:
        return True
    return left_value == right_value


def _has_precise_component_cross_key_conflict(left: NormalizedPII, right: NormalizedPII) -> bool:
    """细粒度英文组件若跨槽位对撞，应直接判为不同实体。"""
    for left_key in _PRECISE_ADDRESS_COMPONENT_KEYS:
        if not str(left.identity.get(left_key) or "").strip():
            continue
        for right_key in _PRECISE_ADDRESS_COMPONENT_KEYS:
            if left_key == right_key:
                continue
            if not str(right.identity.get(right_key) or "").strip():
                continue
            if left.identity.get(right_key) or right.identity.get(left_key):
                continue
            return True
    return False


_MIN_POI_LEN = 2


def _ordered_component_by_type(
    normalized: NormalizedPII,
    component_type: str,
) -> NormalizedAddressComponent | None:
    for component in normalized.ordered_components:
        if component.component_type == component_type:
            return component
    return None


def _component_covering_level(
    normalized: NormalizedPII,
    level: str,
    skip: Iterable[NormalizedAddressComponent] | None = None,
) -> NormalizedAddressComponent | None:
    """返回 level 元组中包含 level 且未被 skip 的第一个 component。

    admin 场景的查找入口：优先按 level 查找；兼容旧 component（level 为空）时
    退回按 component_type == level 匹配。non-admin 场景仍用 _ordered_component_by_type。
    """
    skip_ids: set[int] = {id(c) for c in skip} if skip else set()
    for component in normalized.ordered_components:
        if id(component) in skip_ids:
            continue
        if level in component.level or (not component.level and component.component_type == level):
            return component
    return None


def _component_value_text(component: NormalizedAddressComponent | None) -> str:
    if component is None:
        return ""
    if isinstance(component.value, tuple):
        return "|".join(str(item).strip() for item in component.value if str(item).strip())
    return str(component.value or "").strip()


def _suspect_entry_by_level(
    component: NormalizedAddressComponent | None,
    level: str,
) -> NormalizedAddressSuspectEntry | None:
    if component is None:
        return None
    for entry in component.suspected:
        if level in entry.levels:
            return entry
    return None


def _admin_text_subset_either(a: str, b: str) -> bool:
    """行政片段子串互容（短串在长串内即可）。"""
    a, b = (a or "").strip(), (b or "").strip()
    if not a or not b:
        return False
    shorter, longer = sorted((a, b), key=len)
    return shorter in longer


# ---------------------------------------------------------------------------
# PR #6：suspect 3 步 OR 链（带第 1 步失败旗标）+ has_admin Case 2 累计
# ---------------------------------------------------------------------------

def _entry_level_all_admin(entry: NormalizedAddressSuspectEntry) -> bool:
    """entry.level 是否完全落在 admin 层（参与 has_admin 判定）。"""
    return bool(entry.levels) and all(lvl in _HAS_ADMIN_LEVEL_KEYS for lvl in entry.levels)


def _suspect_group_matches_with_flag(
    entry: NormalizedAddressSuspectEntry,
    other_component: NormalizedAddressComponent | None,
    other_normalized: NormalizedPII,
) -> tuple[bool | None, bool]:
    """三步 OR 链（返回 step1_failed 供 has_admin Case 2 使用）。

    返回 (match_result, step1_failed)。
    - step1：surface = entry.value+entry.key，与对侧同 component_type peer.value 双向子串；
      任一为空时也记 step1 失败（保守计 Case 2）。
    - step2：对侧 peer 组件的 suspected 中同 level 的 entry，value 精确相等（策略 A）。
    - step3：对侧按 level 查找覆盖组件，surface 与其 value 双向子串（策略 C）。
    - 三步皆无从判定 → 不否决，返回 True。
    """
    surface = f"{entry.value}{entry.key}".strip()
    other_value = _component_value_text(other_component)

    # 第 1 步：同 component_type peer 双向子串
    if surface and other_value and _admin_text_subset_either(surface, other_value):
        return True, False

    step1_failed = True

    # 第 2 步：对侧 peer suspected 同 level 精确等值
    for level in entry.levels:
        peer_suspected = _suspect_entry_by_level(other_component, level)
        if peer_suspected is not None:
            return (peer_suspected.value.strip() == entry.value.strip()), step1_failed

    bare_value = entry.value.strip()

    # 第 3 步：对侧按 level 查找任一覆盖组件，bare value 与其 value 双向子串
    for level in entry.levels:
        other_level_component = _component_covering_level(other_normalized, level)
        if other_level_component is None:
            continue
        other_level_value = _component_value_text(other_level_component)
        if not bare_value or not other_level_value:
            continue
        return (
            _admin_text_subset_either(bare_value, other_level_value),
            step1_failed,
        )

    # 无从判定 → 不否决
    return True, step1_failed


def _suspect_chain_and_case2(
    component: NormalizedAddressComponent | None,
    other_component: NormalizedAddressComponent | None,
    other_normalized: NormalizedPII,
) -> tuple[bool, bool]:
    """遍历 component.suspected；返回 (chain_ok, admin_hit)。

    - chain_ok：任一 entry 的 OR 链结果 False 即整组失败。
    - admin_hit：any-entry 聚合——entry step1 失败且 entry.level ⊂ admin 集合时累计 Case 2。
    """
    if component is None or not component.suspected:
        return True, False
    chain_ok = True
    admin_hit = False
    for entry in component.suspected:
        result, step1_failed = _suspect_group_matches_with_flag(
            entry, other_component, other_normalized,
        )
        if step1_failed and _entry_level_all_admin(entry):
            admin_hit = True
        if result is False:
            chain_ok = False
    return chain_ok, admin_hit


def _compare_peer_with_suspect_case2(
    left: NormalizedPII,
    right: NormalizedPII,
    component_type: str,
    *,
    exact_compare: bool = False,
) -> tuple[bool, bool, bool]:
    """非 admin 层级（road / poi / building / detail / subdistrict）的同 component_type 比较。

    返回 (match_ok, left_admin_from_suspect, right_admin_from_suspect)。
    - match_ok：值层双向子串通过且双侧 suspect OR 链整体未否决。
    - left_admin_from_suspect / right_admin_from_suspect：各侧在本层遍历中聚合的 Case 2 信号。
    """
    left_component = _ordered_component_by_type(left, component_type)
    right_component = _ordered_component_by_type(right, component_type)

    if left_component is None and right_component is None:
        return True, False, False

    # 值层比较：任一为 None 时跳过，双边都有则双向子串
    if left_component is not None and right_component is not None:
        left_value = _component_value_text(left_component)
        right_value = _component_value_text(right_component)
        if exact_compare:
            if (
                _canonicalize_address_component_value(component_type, left_value)
                != _canonicalize_address_component_value(component_type, right_value)
            ):
                return False, False, False
        elif not _admin_text_subset_either(left_value, right_value):
            return False, False, False

    left_ok, left_admin_hit = _suspect_chain_and_case2(
        left_component, right_component, right,
    )
    right_ok, right_admin_hit = _suspect_chain_and_case2(
        right_component, left_component, left,
    )
    if not left_ok or not right_ok:
        return False, left_admin_hit, right_admin_hit

    return True, left_admin_hit, right_admin_hit


# ---------------------------------------------------------------------------
# PR #6：admin 层三态比较器（多解释枚举 + suspect 补救）
# ---------------------------------------------------------------------------

def _admin_value_match(a: str, b: str) -> bool:
    """admin 同层 component↔component 值比较。

    值已剥 KEY，采用双向子串（短串为长串前/子串），允许 "浦东"="浦东新区" 同地判定。
    多解释枚举下每 component 仅固定一层，不会出现"北京"⊂"北京市朝阳"式跨层假阳。
    """
    return _admin_text_subset_either(a, b)


def _canonicalize_for_admin_compare(level: str, value: str) -> str:
    """admin 层级值比较前的 canonical 化：
    - EN province（state 别名）/ country 统一到标准名；
    - 其他层走 _canonicalize_address_component_value 的通用归一（例如 _compact_component_text）。
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    canon = _canonicalize_address_component_value(level, raw)
    return canon or raw


def _admin_value_at_level(
    normalized: NormalizedPII,
    level: str,
    interpretation: dict,
) -> str | None:
    """取本侧在 level 层的 component value（硬值，已 canonicalize）。

    - interpretation 中 multi component 仅在被固定到 level 时才贡献；
    - 单层 component 只要 level 在其 level 元组里即贡献；兼容旧 component（level 空）按 component_type 匹配。
    """
    for c in normalized.ordered_components:
        if id(c) in interpretation:
            if interpretation[id(c)] == level:
                v = _component_value_text(c)
                return _canonicalize_for_admin_compare(level, v) if v else None
            continue
        if level in c.level or (not c.level and c.component_type == level):
            v = _component_value_text(c)
            return _canonicalize_for_admin_compare(level, v) if v else None
    return None


def _level_candidates(
    normalized: NormalizedPII,
    level: str,
    interpretation: dict,
) -> set[str]:
    """某侧在 level 层的候选值集合 = 硬值（受 interpretation 约束） ∪ suspect 裸 value。

    候选值在入集合前统一 canonicalize，保证 "California" 与 "CA"、"苏州" 与 "苏州市" 等别名可比。
    """
    out: set[str] = set()

    def _add(raw: str) -> None:
        canon = _canonicalize_for_admin_compare(level, raw)
        if canon:
            out.add(canon)

    for c in normalized.ordered_components:
        if id(c) in interpretation:
            if interpretation[id(c)] == level:
                _add(_component_value_text(c))
        else:
            if level in c.level or (not c.level and c.component_type == level):
                _add(_component_value_text(c))
        for s in c.suspected:
            if level in s.levels and s.value:
                _add(s.value.strip())
    return out


def _suspect_chain_consistent_at_level(
    left: NormalizedPII,
    right: NormalizedPII,
    level: str,
    left_interp: dict,
    right_interp: dict,
) -> bool:
    """单侧硬值缺失时的层级一致性判定。

    两侧候选集（硬值 + suspect 裸 value）任一为空视为 True（单缺不证伪）；
    两侧都有候选则需存在一对满足 _admin_text_subset_either，否则显式冲突。
    """
    left_set = _level_candidates(left, level, left_interp)
    right_set = _level_candidates(right, level, right_interp)
    if not left_set or not right_set:
        return True
    for a in left_set:
        for b in right_set:
            if _admin_text_subset_either(a, b):
                return True
    return False


def _suspect_chain_can_reconcile(
    left: NormalizedPII,
    right: NormalizedPII,
    level: str,
    left_interp: dict,
    right_interp: dict,
) -> bool:
    """双侧硬值都存在但精确不等时的 suspect 补救。

    仅用裸 value 候选集补救；不再依赖 suspect surface。
    """
    left_set = _level_candidates(left, level, left_interp)
    right_set = _level_candidates(right, level, right_interp)
    if not left_set or not right_set:
        return False
    return _sets_subset_either(left_set, right_set)


def _admin_match_under_interpretation(
    left: NormalizedPII,
    right: NormalizedPII,
    left_interp: dict,
    right_interp: dict,
) -> str:
    """某种解释下逐 admin level 比较，返回 match / inconclusive / mismatch。

    单侧硬值缺失时用候选集（硬值 + suspect 裸 value）判定：
    - 两侧候选集俱空 / 双方都真空 → 本层不贡献也不冲突；
    - 单侧候选空 → 本层真单缺，不证伪也不命中；
    - 双方候选都非空 → 必须存在一对子串互容，否则显式冲突。候选互容时计 matched。
    """
    matched_any = False
    for level in _ADMIN_LEVEL_KEYS:
        left_value = _admin_value_at_level(left, level, left_interp)
        right_value = _admin_value_at_level(right, level, right_interp)

        if left_value is None and right_value is None:
            # 双侧硬值均缺：仍要看候选集是否存在显式冲突
            left_set = _level_candidates(left, level, left_interp)
            right_set = _level_candidates(right, level, right_interp)
            if not left_set or not right_set:
                continue  # 真双缺
            # 双侧都有候选：需要一对互容
            if _sets_subset_either(left_set, right_set):
                matched_any = True
                continue
            return "mismatch"

        if left_value is None or right_value is None:
            left_set = _level_candidates(left, level, left_interp)
            right_set = _level_candidates(right, level, right_interp)
            if not left_set or not right_set:
                continue  # 单侧真缺
            if _sets_subset_either(left_set, right_set):
                matched_any = True
                continue
            return "mismatch"

        if _admin_value_match(left_value, right_value):
            matched_any = True
            continue

        if _suspect_chain_can_reconcile(
            left, right, level, left_interp, right_interp,
        ):
            matched_any = True
            continue
        return "mismatch"

    return "match" if matched_any else "inconclusive"


def _sets_subset_either(left_set: set[str], right_set: set[str]) -> bool:
    """双候选集存在一对满足 _admin_text_subset_either 即 True。"""
    for a in left_set:
        for b in right_set:
            if _admin_text_subset_either(a, b):
                return True
    return False


def _iter_admin_interpretations(
    multis: list[NormalizedAddressComponent],
):
    """逐 MULTI_ADMIN component 在其 level 元组内取一层的笛卡尔积；
    每次 yield 一个 {id(component): level_str} dict。"""
    if not multis:
        yield {}
        return
    from itertools import product
    level_sets = [tuple(m.level) for m in multis]
    keys = [id(m) for m in multis]
    for combo in product(*level_sets):
        yield dict(zip(keys, combo))


def _admin_match_simplified(left: NormalizedPII, right: NormalizedPII) -> str:
    """k 过大时的降级路径：逐 admin level 聚合所有候选值；
    - 双方都有候选且存在一对子串互容 → 本层命中；
    - 双方都有候选但无任何对匹配 → 本层 mismatch；
    - 单侧有候选 → 视为本层无冲突也不命中。
    聚合后：任一层 mismatch → 整体 mismatch；有命中 → match；否则 inconclusive。
    """
    empty_interp: dict = {}
    any_match = False
    for level in _ADMIN_LEVEL_KEYS:
        left_set = _level_candidates(left, level, empty_interp)
        right_set = _level_candidates(right, level, empty_interp)
        if not left_set and not right_set:
            continue
        if not left_set or not right_set:
            continue
        ok = False
        for a in left_set:
            for b in right_set:
                if _admin_text_subset_either(a, b):
                    ok = True
                    break
            if ok:
                break
        if ok:
            any_match = True
        else:
            return "mismatch"
    return "match" if any_match else "inconclusive"


def _compare_admin_levels_with_interpretations(
    left: NormalizedPII,
    right: NormalizedPII,
) -> str:
    """admin 层三态比较（match / mismatch / inconclusive）。

    聚合规则（与 0.2 对齐）：
    - 任一解释 match → 整体 match；
    - 否则任一解释 inconclusive → 整体 inconclusive；
    - 否则（均 mismatch） → 整体 mismatch。
    """
    left_multis = [
        c for c in left.ordered_components
        if c.component_type == "multi_admin" or len(c.level) >= 2
    ]
    right_multis = [
        c for c in right.ordered_components
        if c.component_type == "multi_admin" or len(c.level) >= 2
    ]

    # 枚举量兜底
    if len(left_multis) + len(right_multis) > _MULTI_ADMIN_INTERP_CAP:
        return _admin_match_simplified(left, right)

    any_inconclusive = False
    for left_interp in _iter_admin_interpretations(left_multis):
        for right_interp in _iter_admin_interpretations(right_multis):
            result = _admin_match_under_interpretation(
                left, right, left_interp, right_interp,
            )
            if result == "match":
                return "match"
            if result == "inconclusive":
                any_inconclusive = True
    return "inconclusive" if any_inconclusive else "mismatch"


def _compare_poi_list(left: NormalizedPII, right: NormalizedPII) -> bool:
    """POI 列表比较（§6.5）。

    每个 POI 仅允许去掉 trace 中的「最后一个 key」后再做子串 subset；不得去掉链上被穿透的中间 key。
    A×B 任一对满足 subset_either 即 PASS。
    """
    left_poi = left.identity.get("poi", "")
    right_poi = right.identity.get("poi", "")
    if not left_poi or not right_poi:
        return True
    left_items = [s.strip() for s in left_poi.split("|") if s.strip()]
    right_items = [s.strip() for s in right_poi.split("|") if s.strip()]
    if not left_items or not right_items:
        return True
    left_keys = [s.strip() for s in (left.identity.get("poi_key") or "").split("|")]
    right_keys = [s.strip() for s in (right.identity.get("poi_key") or "").split("|")]
    for i, a in enumerate(left_items):
        ak = left_keys[i] if i < len(left_keys) else ""
        a_cmp = _strip_terminal_poi_key(a, ak)
        for j, b in enumerate(right_items):
            bk = right_keys[j] if j < len(right_keys) else ""
            b_cmp = _strip_terminal_poi_key(b, bk)
            if _poi_subset_either(a_cmp, b_cmp) and min(len(a_cmp), len(b_cmp)) >= _MIN_POI_LEN:
                return True
    return False


def _strip_terminal_poi_key(value: str, terminal_key: str) -> str:
    """仅当 value 以「最后一个 key」结尾时去掉该后缀；不处理穿透在中间的文字。"""
    v = (value or "").strip()
    k = (terminal_key or "").strip()
    if not k or not v.endswith(k):
        return v
    return v[: -len(k)].strip() or v


def _poi_subset_either(a: str, b: str) -> bool:
    """POI 子集：纯子串互容，不做任意类别词后缀剥离。"""
    if not a or not b:
        return False
    shorter, longer = sorted((a, b), key=len)
    return shorter in longer


def _numbers_match(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """号码判定。

    规则：
    1. 先按逆序单调子序列计算命中数。
    2. 命中数相对最长一方的覆盖率必须严格大于 40%。
    3. 当最短一方长度小于等于 2 时，要求最短一方全部命中。
    """
    return _numbers_sequence_match(left, right)


def _numbers_sequence_match(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """号码序列判定：从末尾往前做逆序一致的子序列匹配。"""
    if not left and not right:
        return True
    if not left or not right:
        return False
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    s = list(reversed(shorter))
    l = list(reversed(longer))
    pointer = 0
    matched = 0
    for token in l:
        if pointer < len(s) and token == s[pointer]:
            matched += 1
            pointer += 1
            if pointer == len(s):
                break
    longer_len = max(len(left), len(right))
    if longer_len <= 0:
        return True
    if (matched / longer_len) <= 0.4:
        return False
    if len(shorter) <= 2 and matched != len(shorter):
        return False
    return True


def _parse_one_component_suspected(segment: str) -> tuple[NormalizedAddressSuspectEntry, ...]:
    """解析单组件 suspected JSON 串。"""
    text = str(segment or "").strip()
    if not text:
        return ()
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(raw, list):
        return ()
    parsed: list[NormalizedAddressSuspectEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        raw_levels = item.get("levels")
        if not isinstance(raw_levels, (list, tuple)):
            continue
        levels = tuple(
            str(level or "").strip()
            for level in raw_levels
            if str(level or "").strip()
        )
        value = str(item.get("value") or "").strip()
        key = str(item.get("key") or "").strip()
        origin = str(item.get("origin") or "").strip()
        if not levels or not value or origin not in {"value", "key"}:
            continue
        parsed.append(NormalizedAddressSuspectEntry(
            levels=levels,
            value=value,
            key=key,
            origin=origin,
        ))
    return tuple(parsed)


def _component_suspected_tuple_from_metadata(
    metadata: Mapping[str, object] | None,
) -> tuple[tuple[NormalizedAddressSuspectEntry, ...], ...]:
    """从 address_component_suspected 列表解析，顺序与 detector 组件顺序一致。"""
    if not metadata:
        return ()
    raw = metadata.get("address_component_suspected")
    if not isinstance(raw, list):
        return ()
    return tuple(_parse_one_component_suspected(str(item or "")) for item in raw)


_DISPLAY_LEVEL_BY_COMPONENT_KEY: dict[str, str] = {
    "country": "country",
    "province": "prov",
    "city": "city",
    "district": "dist",
    "district_city": "dist",
    "subdistrict": "dist",
    "road": "road",
    "number": "road",
    "house_number": "road",
    "poi": "dtl",
    "building": "dtl",
    "unit": "dtl",
    "room": "dtl",
    "suite": "dtl",
    "detail": "dtl",
    "postal_code": "",
}
# SPEC 拼接顺序：固定 COUNTRY→PROV→CITY→DIST→ROAD→DTL。
_DISPLAY_LEVEL_ORDER: tuple[str, ...] = ("country", "prov", "city", "dist", "road", "dtl")


def _derive_display_level(component_type: str, level_tuple: tuple[str, ...]) -> str:
    """为 NormalizedAddressComponent 推导 display 短码。

    - MULTI_ADMIN：取 level 元组中 rank 最低的行政层级映射（例：("province","city") → "city"）；
      元组为空或无行政层级时回退为 "city"。
    - 其它 component_type：直接按映射表取；命中 postal_code 或未知类型返回空串。
    """
    ct = str(component_type or "").strip()
    if ct == "multi_admin":
        if level_tuple:
            ranked = sorted(
                level_tuple,
                key=lambda lvl: _ADMIN_LEVEL_RANK.get(lvl, 10**9),
            )
            for lvl in ranked:
                mapped = _DISPLAY_LEVEL_BY_COMPONENT_KEY.get(lvl, "")
                if mapped:
                    return mapped
        return "city"
    return _DISPLAY_LEVEL_BY_COMPONENT_KEY.get(ct, "")


def address_display_spec(normalized: NormalizedPII) -> str:
    """按 COUNTRY/PROV/CITY/DIST/ROAD/DTL 顺序生成地址占位符 SPEC 后缀。

    - 只扫描 `normalized.ordered_components` 里 display_level 非空的条目；
    - 去重后按固定顺序用 "-" 拼（同一 display level 多次仅保留一次）；
    - 全空或非地址归一返回空字符串（调用方据此决定是否追加 `.SPEC`）。
    """
    if normalized is None or normalized.attr_type != PIIAttributeType.ADDRESS:
        return ""
    seen: set[str] = set()
    for component in normalized.ordered_components:
        level = (component.display_level or "").strip()
        if level:
            seen.add(level)
    if not seen:
        return ""
    return "-".join(level.upper() for level in _DISPLAY_LEVEL_ORDER if level in seen)


def _address_ordered_components(
    *,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> tuple[NormalizedAddressComponent, ...]:
    """构造地址组件级归一结果。"""
    if components:
        return _ordered_components_from_direct_components(components)
    return _ordered_components_from_metadata(metadata)


def _ordered_components_from_direct_components(
    components: Mapping[str, str | None],
) -> tuple[NormalizedAddressComponent, ...]:
    """结构化 components 直传时，按固定层级顺序生成组件。"""
    ordered: list[NormalizedAddressComponent] = []
    normalized_components: dict[str, str] = {}
    for raw_key, value in components.items():
        key = _ADDRESS_COMPONENT_ALIASES.get(str(raw_key or "").strip(), str(raw_key or "").strip())
        text = str(value or "").strip()
        if key in _ADDRESS_COMPONENT_KEYS or key in _ADDRESS_OPTIONAL_KEYS:
            if text:
                normalized_components[key] = text
    poi_key_raw = str(normalized_components.get("poi_key") or "").strip()
    poi_keys = tuple(part.strip() for part in poi_key_raw.split("|") if part.strip())
    for component_type in _ORDERED_COMPONENT_KEYS:
        raw_value = str(normalized_components.get(component_type) or "").strip()
        if not raw_value:
            continue
        if component_type == "poi":
            values = tuple(part.strip() for part in raw_value.split("|") if part.strip())
            if not values:
                continue
            value: str | tuple[str, ...] = values[0] if len(values) == 1 else values
            key: str | tuple[str, ...]
            if not poi_keys:
                key = ""
            elif len(poi_keys) == 1:
                key = poi_keys[0]
            else:
                key = poi_keys
        else:
            value = raw_value
            key = ""
        # 结构化直传无 trace，level 默认等于 component_type。
        level_tuple = (component_type,)
        ordered.append(NormalizedAddressComponent(
            component_type=component_type,
            level=level_tuple,
            value=value,
            key=key,
            suspected=(),
            display_level=_derive_display_level(component_type, level_tuple),
        ))
    return tuple(ordered)


def _ordered_components_from_metadata(
    metadata: Mapping[str, object] | None,
) -> tuple[NormalizedAddressComponent, ...]:
    """从 detector metadata 重建组件顺序与组件级 suspected。"""
    trace_raw = _metadata_values(metadata, "address_component_trace")
    level_raw = _metadata_values(metadata, "address_component_level")
    trace_entries = _parse_address_trace_entries_with_levels(trace_raw, level_raw)
    if not trace_entries:
        return ()
    key_entries = _parse_address_trace_entries(_metadata_values(metadata, "address_component_key_trace"))
    suspected_entries = _component_suspected_tuple_from_metadata(metadata)

    ordered: list[NormalizedAddressComponent] = []
    trace_index = 0
    key_index = 0
    component_index = 0

    while trace_index < len(trace_entries):
        component_type, value, level_tuple = trace_entries[trace_index]
        suspected = suspected_entries[component_index] if component_index < len(suspected_entries) else ()
        component_index += 1

        if component_type == "poi":
            values = [value]
            first_level = level_tuple
            trace_index += 1
            while trace_index < len(trace_entries) and trace_entries[trace_index][0] == "poi":
                values.append(trace_entries[trace_index][1])
                trace_index += 1
            keys: list[str] = []
            while key_index < len(key_entries) and key_entries[key_index][0] == "poi" and len(keys) < len(values):
                keys.append(key_entries[key_index][1])
                key_index += 1
            poi_level_tuple = first_level or ("poi",)
            ordered.append(NormalizedAddressComponent(
                component_type="poi",
                level=poi_level_tuple,
                value=tuple(values) if len(values) > 1 else values[0],
                key=tuple(keys) if len(keys) > 1 else (keys[0] if keys else ""),
                suspected=tuple(suspected),
                display_level=_derive_display_level("poi", poi_level_tuple),
            ))
            continue

        key_value = ""
        if key_index < len(key_entries) and key_entries[key_index][0] == component_type:
            key_value = key_entries[key_index][1]
            key_index += 1
        effective_level_tuple = level_tuple or (component_type,)
        ordered.append(NormalizedAddressComponent(
            component_type=component_type,
            level=effective_level_tuple,
            value=value,
            key=key_value,
            suspected=tuple(suspected),
            display_level=_derive_display_level(component_type, effective_level_tuple),
        ))
        trace_index += 1

    return tuple(ordered)


def _parse_address_trace_entries(items: tuple[str, ...]) -> list[tuple[str, str]]:
    """把 trace 列表解析成标准化的组件项。"""
    entries: list[tuple[str, str]] = []
    for item in items:
        if ":" not in item:
            continue
        raw_type, raw_value = item.split(":", 1)
        component_type = _ADDRESS_COMPONENT_ALIASES.get(raw_type.strip(), raw_type.strip())
        value = raw_value.strip()
        if component_type in _ADDRESS_COMPONENT_KEYS and value:
            entries.append((component_type, value))
    return entries


def _parse_address_trace_entries_with_levels(
    trace_items: tuple[str, ...],
    level_items: tuple[str, ...],
) -> list[tuple[str, str, tuple[str, ...]]]:
    """把 trace 与并行 level 列表解析成带层级的组件项。

    - trace_items 与 level_items 按原始 detector 顺序一一对应；
      level_items 缺失或短于 trace_items 时，缺位条目回退为空元组（调用方再兜底为 component_type）。
    - level 字符串格式：单层 "road" / "province"；MULTI_ADMIN 以 `|` 分隔。
    """
    entries: list[tuple[str, str, tuple[str, ...]]] = []
    for idx, item in enumerate(trace_items):
        if ":" not in item:
            continue
        raw_type, raw_value = item.split(":", 1)
        component_type = _ADDRESS_COMPONENT_ALIASES.get(raw_type.strip(), raw_type.strip())
        value = raw_value.strip()
        if component_type not in _ADDRESS_COMPONENT_KEYS or not value:
            continue
        level_tuple: tuple[str, ...] = ()
        if idx < len(level_items):
            raw_level = str(level_items[idx] or "").strip()
            if raw_level:
                parts = tuple(
                    _ADDRESS_COMPONENT_ALIASES.get(p.strip(), p.strip())
                    for p in raw_level.split("|")
                    if p.strip()
                )
                level_tuple = tuple(p for p in parts if p in _ADMIN_LEVEL_KEYS or p in _ADDRESS_COMPONENT_KEYS)
        entries.append((component_type, value, level_tuple))
    return entries


def _address_numbers(
    *,
    metadata: Mapping[str, object] | None,
    normalized_components: Mapping[str, str],
) -> list[str]:
    """按地址从左到右提取非精细地址的附属数字序列。"""
    tokens: list[str] = []
    # 优先使用 addressstack 的 trace（天然保持组件生成顺序）。
    if metadata:
        trace = metadata.get("address_component_trace")
        if isinstance(trace, list):
            for item in trace:
                if not isinstance(item, str) or ":" not in item:
                    continue
                comp_type, value = item.split(":", 1)
                comp_type = comp_type.strip()
                value = value.strip()
                if comp_type in _ADDRESS_DETAIL_KEYS:
                    tokens.extend(_extract_number_tokens(value))
            return [t for t in tokens if t]
    # fallback：无 trace 时按 detail keys 顺序提取（仅用于 components 直传场景）。
    for key in _ADDRESS_DETAIL_KEYS:
        if value := str(normalized_components.get(key) or "").strip():
            tokens.extend(_extract_number_tokens(value))
    return [t for t in tokens if t]


@lru_cache(maxsize=1)
def _zh_control_value_lookup() -> tuple[dict[str, str], tuple[int, ...]]:
    mapping = {item.text: item.normalized for item in load_zh_control_values()}
    lengths = tuple(sorted({len(text) for text in mapping}, reverse=True))
    return mapping, lengths


def _is_ascii_alnum_char(char: str) -> bool:
    return char.isascii() and char.isalnum()


def _extract_number_tokens(value: str) -> list[str]:
    """从 value 中抽取数字、天干地支或混合编号 token。"""
    text = str(value or "").strip()
    if not text:
        return []
    mapping, lengths = _zh_control_value_lookup()
    tokens: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        longest: str | None = None
        for length in lengths:
            end = index + length
            if end > len(text):
                continue
            candidate = text[index:end]
            if candidate in mapping:
                longest = candidate
                break
        if longest is not None:
            current.append(mapping[longest])
            index += len(longest)
            continue
        char = text[index]
        if _is_ascii_alnum_char(char):
            current.append(char.upper() if char.isalpha() else char)
            index += 1
            continue
        if current:
            tokens.append("".join(current))
            current = []
        index += 1
    if current:
        tokens.append("".join(current))
    if not tokens:
        return []
    with_digits = [token for token in tokens if any(ch.isdigit() for ch in token)]
    if with_digits:
        return with_digits + [token for token in tokens if not any(ch.isdigit() for ch in token) and len(token) == 1]
    return [token for token in tokens if len(token) == 1 or any(not ch.isascii() for ch in token)]


def _parse_zh_numeral(text: str) -> int | None:
    """把常见中文数字（<=9999）转成 int。只处理纯数字表达，失败返回 None。"""
    s = str(text or "").strip()
    if not s:
        return None
    s = s.replace("〇", "零")
    if any(ch not in _ZH_NUMERAL_CHARS for ch in s):
        return None
    digit_map = {"零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
    unit_map = {"十": 10, "百": 100, "千": 1000}
    total = 0
    num = 0
    unit = 1
    # 从右向左解析（适配“二百零一”“十二”“十”等）。
    for ch in reversed(s):
        if ch in digit_map:
            num += digit_map[ch] * unit
        elif ch in unit_map:
            u = unit_map[ch]
            if u > unit:
                unit = u
            else:
                # 不规范写法，放弃。
                return None
            if num == 0:
                # “十/百/千”前省略“一”
                num = 1 * unit
                unit = 1
                total += num
                num = 0
                unit = 1
        else:
            return None
    total += num
    if total <= 0:
        return None
    if total > 9999:
        return None
    return total


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
    canonical = _metadata_canonical_value(metadata)
    parsed = parse_name_components(canonical or raw_text)
    resolved = {
        "full": parsed.full_text or parsed.original_text or raw_text,
        "family": parsed.family_text or "",
        "given": parsed.given_text or "",
        "middle": parsed.middle_text or "",
    }
    component_values = _metadata_values(metadata, "name_component")
    matched_text = raw_text.strip()
    if matched_text:
        if "family" in component_values:
            resolved["family"] = matched_text
        if "given" in component_values:
            resolved["given"] = matched_text
        if "middle" in component_values:
            resolved["middle"] = matched_text
    if "alias" in component_values:
        resolved["alias"] = matched_text
    return {key: value for key, value in resolved.items() if value}


def _address_components(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> dict[str, str]:
    if components:
        allowed = frozenset(_ADDRESS_COMPONENT_KEYS) | _ADDRESS_OPTIONAL_KEYS
        resolved: dict[str, str] = {}
        for raw_key, value in components.items():
            key = _ADDRESS_COMPONENT_ALIASES.get(str(raw_key or "").strip(), str(raw_key or "").strip())
            if key not in allowed:
                continue
            text = str(value or "").strip()
            if not text:
                continue
            resolved[key] = text
        return resolved
    traced = _components_from_address_metadata(metadata)
    if traced:
        return traced
    return {}


def _components_from_address_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    traces = _metadata_values(metadata, "address_component_trace")
    key_traces = _metadata_values(metadata, "address_component_key_trace")
    resolved: dict[str, str] = {}
    poi_vals_order: list[str] = []
    poi_keys_order: list[str] = []
    for item in key_traces:
        if ":" not in item:
            continue
        ct, kpart = item.split(":", 1)
        ck = _ADDRESS_COMPONENT_ALIASES.get(ct.strip(), ct.strip())
        if ck != "poi":
            continue
        kk = kpart.strip()
        if kk:
            poi_keys_order.append(kk)
    for item in traces:
        if ":" not in item:
            continue
        component_type, value = item.split(":", 1)
        key = _ADDRESS_COMPONENT_ALIASES.get(component_type.strip(), component_type.strip())
        normalized_value = value.strip()
        if key not in _ADDRESS_COMPONENT_KEYS or not normalized_value:
            continue
        if key == "poi":
            poi_vals_order.append(normalized_value)
            continue
        previous = resolved.get(key, "")
        if len(normalized_value) > len(previous):
            resolved[key] = normalized_value
    if poi_vals_order:
        poi_pairs = [
            (v, poi_keys_order[i] if i < len(poi_keys_order) else "")
            for i, v in enumerate(poi_vals_order)
        ]
        deduped = _dedupe_poi_pairs(poi_pairs)
        resolved["poi"] = "|".join(p[0] for p in deduped)
        resolved["poi_key"] = "|".join(p[1] for p in deduped)
    return resolved


def _dedupe_poi_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """POI 列表去重：被更长 value 包含的短 value 剔除，与 trace 中最后一个 key 成对保留。"""
    if not pairs:
        return []
    val_to_key: dict[str, str] = {}
    for v, k in pairs:
        val_to_key.setdefault(v, k)
    sorted_vals = sorted({p[0] for p in pairs}, key=len, reverse=True)
    kept_vals: list[str] = []
    for v in sorted_vals:
        if not any(v in kept and v != kept for kept in kept_vals):
            kept_vals.append(v)
    return [(v, val_to_key.get(v, "")) for v in kept_vals]


def _dedupe_poi_values(values: list[str]) -> list[str]:
    """POI 列表去重：被更长值包含的短值剔除。"""
    pairs = [(v, "") for v in values]
    return [p[0] for p in _dedupe_poi_pairs(pairs)]


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


def _metadata_canonical_value(metadata: Mapping[str, object] | None) -> str:
    values = _metadata_values(metadata, "canonical")
    return values[0] if values else ""


def _normalize_phone_digits(
    digits: str,
    *,
    raw_text: str = "",
    metadata: Mapping[str, object] | None = None,
) -> str:
    phone_region = (_metadata_values(metadata, "phone_region")[:1] or ("",))[0].lower()
    if phone_region == "cn":
        if len(digits) == 13 and digits.startswith("86") and _PHONE_CN_MOBILE_RE.fullmatch(digits[2:]):
            return digits[2:]
        return digits
    if phone_region == "us":
        if len(digits) == 11 and digits.startswith("1") and _is_valid_us_phone_digits(digits[1:]):
            return digits[1:]
        return digits
    if len(digits) == 13 and digits.startswith("86") and _PHONE_CN_MOBILE_RE.fullmatch(digits[2:]):
        return digits[2:]
    normalized_text = unicodedata.normalize("NFKC", raw_text or "")
    if (
        len(digits) == 11
        and digits.startswith("1")
        and _is_valid_us_phone_digits(digits[1:])
        and (
            _PHONE_US_COUNTRY_CODE_PREFIX_RE.match(normalized_text)
            or _PHONE_US_TRUNK_AREA_PREFIX_RE.match(normalized_text)
        )
    ):
        return digits[1:]
    return digits


def _is_valid_us_phone_digits(digits: str) -> bool:
    return len(digits) == 10 and digits.isdigit() and bool(_PHONE_US_TEN_DIGIT_RE.fullmatch(digits))


def _organization_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    changed = True
    while changed:
        changed = False
        for entry in (*load_zh_company_suffixes(), *load_en_company_suffixes()):
            if text.lower().endswith(entry.text.lower()) and len(text) > len(entry.text):
                text = text[: -len(entry.text)].rstrip()
                changed = True
                break
    return _compact_component_text(text)


def _name_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    if _NAME_COMPONENT_RE.fullmatch(text):
        return _fold_english_name_il(re.sub(r"\s+", " ", text).strip().lower())
    return "".join(char for char in re.sub(r"\s+", "", text) if char not in "·•・")


def _fold_english_name_il(value: str) -> str:
    """英文姓名 canonical 中将 i/l 统一折叠，降低 OCR 竖线类误差影响。"""
    return value.translate(str.maketrans({"i": "l", "l": "l"}))


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


def _license_plate_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "").strip()
    if not text:
        return ""
    prefix = ""
    remainder = text
    if remainder and "\u4e00" <= remainder[0] <= "\u9fff":
        prefix = remainder[0]
        remainder = remainder[1:]
    return prefix + _alnum_only(remainder).upper()


def _amount_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "")
    if not text:
        return ""
    text = _AMOUNT_UNIT_RE.sub("", text)
    text = text.replace("$", "").replace("¥", "").replace("€", "").replace("£", "")
    text = re.sub(r"\s+", "", text)
    match = re.search(r"\d+(?:\.\d{2})?", text)
    return match.group(0) if match else ""


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
    "NormalizedAddressComponent",
    "NormalizedPII",
    "build_match_terms",
    "normalize_pii",
    "normalized_primary_text",
    "render_address_text",
    "same_entity",
]
