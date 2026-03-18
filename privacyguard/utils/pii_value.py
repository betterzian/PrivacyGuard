"""PII 值的 canonicalization 与 persona 替换辅助工具。"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.text import normalize_text

_DIRECT_CONTROLLED = {"北京市", "上海市", "天津市", "重庆市"}
_ADDRESS_ROAD_SUFFIXES = ("路", "街", "大道", "道", "巷", "弄", "胡同")
_MIN_ADDRESS_LOCAL_ALIAS_LEN = 4
_ADDRESS_DETAIL_EXPLICIT_SUFFIX_PATTERN = re.compile(r"(?:路|街|大道|道|巷|弄|胡同|号院|号楼|栋|幢|座|单元|室|层|号)$")
_ADDRESS_DETAIL_SIGNAL_PATTERN = re.compile(
    r"(?:\d|路|街|大道|道|巷|弄|胡同|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍|号院|号楼|栋|幢|座|单元|室|层|号)"
)
_ROAD_STEM_BLOCKLIST_PATTERN = re.compile(
    r"(?:一期|二期|三期|四期|五期|六期|七期|八期|九期|十期|小区|花园|公寓|大厦|园区|宿舍|家园|楼|栋|单元|室|城)$"
)
_LIKELY_ROAD_STEM_PATTERN = re.compile(r"[一-龥A-Za-z]{2,8}(?:东|西|南|北|中)$")
_PROVINCE_ALIASES = {
    "北京市": "北京市",
    "北京": "北京市",
    "上海市": "上海市",
    "上海": "上海市",
    "天津市": "天津市",
    "天津": "天津市",
    "重庆市": "重庆市",
    "重庆": "重庆市",
    "河北省": "河北省",
    "河北": "河北省",
    "山西省": "山西省",
    "山西": "山西省",
    "辽宁省": "辽宁省",
    "辽宁": "辽宁省",
    "吉林省": "吉林省",
    "吉林": "吉林省",
    "黑龙江省": "黑龙江省",
    "黑龙江": "黑龙江省",
    "江苏省": "江苏省",
    "江苏": "江苏省",
    "浙江省": "浙江省",
    "浙江": "浙江省",
    "安徽省": "安徽省",
    "安徽": "安徽省",
    "福建省": "福建省",
    "福建": "福建省",
    "江西省": "江西省",
    "江西": "江西省",
    "山东省": "山东省",
    "山东": "山东省",
    "河南省": "河南省",
    "河南": "河南省",
    "湖北省": "湖北省",
    "湖北": "湖北省",
    "湖南省": "湖南省",
    "湖南": "湖南省",
    "广东省": "广东省",
    "广东": "广东省",
    "海南省": "海南省",
    "海南": "海南省",
    "四川省": "四川省",
    "四川": "四川省",
    "贵州省": "贵州省",
    "贵州": "贵州省",
    "云南省": "云南省",
    "云南": "云南省",
    "陕西省": "陕西省",
    "陕西": "陕西省",
    "甘肃省": "甘肃省",
    "甘肃": "甘肃省",
    "青海省": "青海省",
    "青海": "青海省",
    "台湾省": "台湾省",
    "台湾": "台湾省",
    "内蒙古自治区": "内蒙古自治区",
    "内蒙古": "内蒙古自治区",
    "广西壮族自治区": "广西壮族自治区",
    "广西": "广西壮族自治区",
    "西藏自治区": "西藏自治区",
    "西藏": "西藏自治区",
    "宁夏回族自治区": "宁夏回族自治区",
    "宁夏": "宁夏回族自治区",
    "新疆维吾尔自治区": "新疆维吾尔自治区",
    "新疆": "新疆维吾尔自治区",
    "香港特别行政区": "香港特别行政区",
    "香港": "香港特别行政区",
    "澳门特别行政区": "澳门特别行政区",
    "澳门": "澳门特别行政区",
}
_CITY_PATTERN = re.compile(r"^(?P<city>[^0-9]{1,16}?(?:自治州|地区|盟|市))")
_DISTRICT_PATTERN = re.compile(r"^(?P<district>[^0-9]{1,16}?(?:新区|自治县|自治旗|区|县|旗|市))")
_NAME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000·•・")
_PHONE_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—()（）")
_ID_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—")
_EMAIL_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
_ADDRESS_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000,，;；:：、()（）")
_ORG_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")


@dataclass(slots=True)
class AddressComponents:
    """结构化地址组件。"""

    original_text: str
    province_text: str | None = None
    city_text: str | None = None
    district_text: str | None = None
    detail_text: str | None = None
    province_key: str | None = None
    city_key: str | None = None
    district_key: str | None = None
    detail_key: str | None = None

    @property
    def granularity(self) -> str:
        if self.detail_text:
            return "detail"
        if self.district_text:
            return "district"
        if self.city_text:
            return "city"
        if self.province_text:
            return "province"
        return "raw"


def canonicalize_pii_value(attr_type: PIIAttributeType, value: str) -> str:
    """按属性类型返回稳定 canonical key。"""
    cleaned = _compact_text(value)
    if not cleaned:
        return ""
    if attr_type == PIIAttributeType.NAME:
        return cleaned.replace(" ", "")
    if attr_type == PIIAttributeType.ORGANIZATION:
        return re.sub(r"\s+", "", cleaned)
    if attr_type == PIIAttributeType.PHONE:
        return re.sub(r"[\s\-()]+", "", cleaned)
    if attr_type == PIIAttributeType.ID_NUMBER:
        return re.sub(r"\s+", "", cleaned).upper()
    if attr_type == PIIAttributeType.EMAIL:
        return cleaned.replace(" ", "")
    if attr_type == PIIAttributeType.ADDRESS:
        return canonicalize_address_text(cleaned)
    return normalize_text(value)


def canonicalize_address_text(value: str) -> str:
    """将地址文本转换为结构化 canonical key。"""
    components = parse_address_components(value)
    if components.province_key or components.city_key or components.district_key:
        parts = [
            components.province_key,
            components.city_key,
            components.district_key,
            components.detail_key,
        ]
        return "|".join(part for part in parts if part)
    return _compact_text(value)


def persona_slot_replacement(attr_type: PIIAttributeType, source_text: str, slot_value: str) -> str:
    """根据源文本粒度生成 persona 槽位替换值。"""
    if attr_type != PIIAttributeType.ADDRESS:
        return slot_value
    source_components = parse_address_components(source_text)
    slot_components = parse_address_components(slot_value)
    rendered = render_address_by_granularity(slot_components, source_components.granularity)
    return rendered or slot_value


def build_match_text(attr_type: PIIAttributeType, value: str) -> tuple[str, list[int]]:
    """构造用于容错匹配的压缩文本及其到原文的索引映射。"""
    match_chars: list[str] = []
    index_map: list[int] = []
    for index, char in enumerate(str(value)):
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            if _is_ignorable_match_char(attr_type, normalized_char):
                continue
            match_chars.append(normalized_char.lower() if normalized_char.isascii() else normalized_char)
            index_map.append(index)
    return ("".join(match_chars), index_map)


def dictionary_match_variants(attr_type: PIIAttributeType, value: str) -> set[str]:
    """为本地隐私库词条生成可直接用于 OCR 容错匹配的候选变体。"""
    raw_value = str(value).strip()
    variants: set[str] = set()
    _add_match_variant(variants, attr_type, raw_value)
    if attr_type != PIIAttributeType.ADDRESS:
        return variants

    components = parse_address_components(raw_value)
    assembled = "".join(
        part
        for part in (
            components.province_text,
            components.city_text if components.city_text != components.province_text else None,
            components.district_text,
            components.detail_text,
        )
        if part
    )
    _add_match_variant(variants, attr_type, assembled)
    if components.province_text and components.city_text and components.province_text.endswith("省"):
        _add_match_variant(
            variants,
            attr_type,
            "".join(
                part
                for part in (
                    components.province_text[:-1],
                    components.city_text,
                    components.district_text,
                    components.detail_text,
                )
                if part
            ),
        )
    if components.province_text in _DIRECT_CONTROLLED:
        _add_match_variant(
            variants,
            attr_type,
            "".join(
                part
                for part in (
                    components.province_text[:-1],
                    components.district_text,
                    components.detail_text,
                )
                if part
            ),
        )
    for alias in _address_detail_aliases(raw_value, components):
        _add_match_variant(variants, attr_type, alias)
    return variants


def parse_address_components(value: str) -> AddressComponents:
    """按中国地址常见层级粗粒度拆解地址。"""
    compact = _compact_text(value)
    components = AddressComponents(original_text=compact)
    if not compact:
        return components

    remaining = compact
    for alias, canonical in sorted(_PROVINCE_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if remaining.startswith(alias):
            components.province_text = canonical
            components.province_key = canonical
            remaining = remaining[len(alias):]
            break

    if components.province_text in _DIRECT_CONTROLLED:
        components.city_text = components.province_text
        components.city_key = components.province_text
        if remaining.startswith(components.city_text):
            remaining = remaining[len(components.city_text):]
    else:
        city_match = _CITY_PATTERN.match(remaining)
        if city_match is not None:
            components.city_text = city_match.group("city")
            components.city_key = components.city_text
            remaining = remaining[city_match.end():]
        else:
            remaining, inferred_city, inferred_district = _infer_suffixless_city_district(remaining)
            if inferred_city is not None:
                components.city_text = inferred_city
                components.city_key = inferred_city
            if inferred_district is not None:
                components.district_text = inferred_district
                components.district_key = inferred_district

    if components.district_text is None:
        district_match = _DISTRICT_PATTERN.match(remaining)
        if district_match is not None:
            components.district_text = district_match.group("district")
            components.district_key = components.district_text
            remaining = remaining[district_match.end():]

    remaining = remaining.strip()
    if remaining:
        components.detail_text = remaining
        components.detail_key = remaining
    return components


def render_address_by_granularity(components: AddressComponents, granularity: str) -> str:
    """按指定粒度输出地址前缀。"""
    if not components.original_text:
        return ""
    if granularity == "raw":
        return components.original_text
    parts: list[str] = []
    if components.province_text:
        parts.append(components.province_text)
    if granularity in {"city", "district", "detail"} and components.city_text and components.city_text != components.province_text:
        parts.append(components.city_text)
    if granularity in {"district", "detail"} and components.district_text:
        parts.append(components.district_text)
    if granularity == "detail" and components.detail_text:
        parts.append(components.detail_text)
    rendered = "".join(parts)
    return rendered or components.original_text


def _compact_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = re.sub(r"\s+", "", normalized).strip()
    return normalized.lower() if re.search(r"[A-Za-z]", normalized) else normalized


def _add_match_variant(target: set[str], attr_type: PIIAttributeType, value: str) -> None:
    match_text, _ = build_match_text(attr_type, value)
    if match_text:
        target.add(match_text)


def _address_detail_aliases(raw_value: str, components: AddressComponents) -> set[str]:
    alias_texts: set[str] = set()
    detail_sources = {components.detail_text or ""}
    if not components.detail_text:
        detail_sources.add(_extract_detail_like_tail(raw_value))
    district_prefixes = {components.district_text or ""}
    for detail in detail_sources:
        compact_detail = _compact_text(detail)
        if not compact_detail:
            continue
        for road_alias in _detail_road_aliases(compact_detail):
            alias_texts.add(road_alias)
            for district in district_prefixes:
                if district and not road_alias.startswith(district):
                    alias_texts.add(f"{district}{road_alias}")
    return {item for item in alias_texts if item}


def _extract_detail_like_tail(raw_value: str) -> str:
    compact = _compact_text(raw_value)
    if not compact:
        return ""
    match = re.search(r"([一-龥A-Za-z]{2,16})(?:\d+[A-Za-z一-龥号室层栋单元]*)?$", compact)
    if match is None:
        return compact
    return match.group(1)


def _detail_road_aliases(detail_text: str) -> set[str]:
    aliases: set[str] = set()
    explicit_match = re.search(r"([一-龥A-Za-z]{2,16}(?:路|街|大道|道|巷|弄|胡同))", detail_text)
    if explicit_match is not None:
        explicit_alias = explicit_match.group(1)
        if len(explicit_alias) >= _MIN_ADDRESS_LOCAL_ALIAS_LEN:
            aliases.add(explicit_alias)
        return aliases

    stem = re.sub(r"(?:\d+[A-Za-z一-龥号室层栋单元]*)$", "", detail_text).strip()
    if not stem:
        stem = detail_text
    stem = stem[-6:]
    if len(stem) >= 3 and _is_likely_road_stem(stem):
        aliases.add(stem[-3:])
    expanded = set()
    for alias in aliases:
        for suffix in _ADDRESS_ROAD_SUFFIXES:
            candidate = f"{alias}{suffix}"
            if len(candidate) >= _MIN_ADDRESS_LOCAL_ALIAS_LEN:
                expanded.add(candidate)
    return expanded


def _infer_suffixless_city_district(remaining: str) -> tuple[str, str | None, str | None]:
    """对“广东广州天河体育西102”这类省后无后缀写法做保守拆分。"""
    compact = _compact_text(remaining)
    if not compact:
        return remaining, None, None
    for city_len in range(2, 5):
        for district_len in range(2, 5):
            if city_len + district_len >= len(compact):
                continue
            city = compact[:city_len]
            district = compact[city_len:city_len + district_len]
            detail = compact[city_len + district_len:]
            if _looks_like_detail_signal(detail):
                return detail, city, district
    for city_len in range(2, 5):
        if city_len >= len(compact):
            continue
        city = compact[:city_len]
        detail = compact[city_len:]
        if _looks_like_detail_signal(detail):
            return detail, city, None
    return remaining, None, None


def _looks_like_detail_signal(detail: str) -> bool:
    compact = _compact_text(detail)
    if len(compact) < 2:
        return False
    return bool(_ADDRESS_DETAIL_SIGNAL_PATTERN.search(compact))


def _is_likely_road_stem(stem: str) -> bool:
    compact = _compact_text(stem)
    if len(compact) < 3:
        return False
    if _ADDRESS_DETAIL_EXPLICIT_SUFFIX_PATTERN.search(compact):
        return True
    if _ROAD_STEM_BLOCKLIST_PATTERN.search(compact):
        return False
    return bool(_LIKELY_ROAD_STEM_PATTERN.fullmatch(compact))


def _is_ignorable_match_char(attr_type: PIIAttributeType, char: str) -> bool:
    if attr_type == PIIAttributeType.NAME:
        return char in _NAME_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.PHONE:
        return char in _PHONE_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ID_NUMBER:
        return char in _ID_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.EMAIL:
        return char in _EMAIL_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ADDRESS:
        return char in _ADDRESS_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ORGANIZATION:
        return char in _ORG_MATCH_IGNORABLE
    return char.isspace()
