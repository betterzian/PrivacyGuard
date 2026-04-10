"""PII 文本解析与匹配辅助工具。"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_country_aliases,
    load_en_address_keyword_groups,
    load_en_us_states,
    load_zh_compound_surnames,
    load_zh_country_prefix_aliases,
)
from privacyguard.utils.text import normalize_text

_DIRECT_CONTROLLED = {"北京市", "上海市", "天津市", "重庆市"}
_ADDRESS_DETAIL_SIGNAL_PATTERN = re.compile(
    r"(?:\d|路|街|大道|道|巷|弄|胡同|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍|号院|号楼|栋|幢|座|单元|室|层|号)"
)
# 省级 alias 不再维护；中文地址按 geo 词典/检测链路解析，不在此做省级别名归一。
_PROVINCE_ALIASES: dict[str, str] = {}
_COUNTRY_PREFIX_ALIASES = load_zh_country_prefix_aliases()

_DELETED_INTERNAL_ZH_ADMIN_ALIAS_TABLES = True
@lru_cache(maxsize=1)
def _en_address_street_suffixes() -> tuple[str, ...]:
    for group in load_en_address_keyword_groups():
        if group.component_type.value == "road":
            return tuple(str(k).strip().lower() for k in group.keywords if str(k).strip())
    return ()


@lru_cache(maxsize=1)
def _en_address_unit_prefixes() -> tuple[str, ...]:
    accepted = {"detail"}
    prefixes: list[str] = []
    for group in load_en_address_keyword_groups():
        if group.component_type.value not in accepted:
            continue
        for kw in group.keywords:
            text = str(kw).strip().lower()
            if text:
                prefixes.append(text)
    prefixes.append("#")
    return tuple(sorted(set(prefixes), key=len, reverse=True))


_EN_ADDRESS_COUNTRY_ALIASES = load_en_address_country_aliases()
_EN_US_STATE_NAMES = load_en_us_states()

@lru_cache(maxsize=1)
def _en_us_state_aliases() -> dict[str, str]:
    aliases: dict[str, str] = {code.lower(): code for code in _EN_US_STATE_NAMES}
    aliases.update({name.lower(): code for code, name in _EN_US_STATE_NAMES.items()})
    return aliases
_COMMON_COMPOUND_SURNAMES = set(load_zh_compound_surnames())
_CITY_PATTERN = re.compile(r"^(?P<city>[^0-9]{1,16}?(?:自治州|地区|盟|市))")
_DISTRICT_PATTERN = re.compile(r"^(?P<district>[^0-9]{1,16}?(?:新区|自治县|自治旗|区|县|旗|市))")
_ZH_BUILDING_PATTERN = re.compile(r"(?P<building>[0-9A-Za-z一二三四五六七八九十百零两]+(?:号楼|栋|幢|座|单元))$")
_ZH_ROOM_PATTERN = re.compile(r"(?P<room>[0-9A-Za-z一二三四五六七八九十百零两]+(?:室|房|层|户))$")
@lru_cache(maxsize=1)
def _EN_STREET_SUFFIX_PATTERN() -> re.Pattern[str]:
    suffixes = _en_address_street_suffixes()
    escaped = "|".join(map(re.escape, suffixes)) if suffixes else r"$^"
    return re.compile(rf"\b(?:{escaped})\.?\b", re.IGNORECASE)
_EN_ADDRESS_PO_BOX_PATTERN = re.compile(r"^\s*P\.?\s*O\.?\s*Box\s+\d{1,10}\s*$", re.IGNORECASE)
@lru_cache(maxsize=1)
def _EN_ADDRESS_UNIT_PATTERN() -> re.Pattern[str]:
    prefixes = _en_address_unit_prefixes()
    escaped = "|".join(map(re.escape, prefixes)) if prefixes else r"$^"
    return re.compile(
        rf"(?P<unit>(?:#|(?:{escaped})\.?)\s*[A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?)$",
        re.IGNORECASE,
    )
_EN_ADDRESS_POSTAL_PATTERN = re.compile(r"(?P<postal>\d{5}(?:-\d{4})?)$")
@lru_cache(maxsize=1)
def _EN_ADDRESS_STREET_PREFIX_PATTERN() -> re.Pattern[str]:
    suffixes = _en_address_street_suffixes()
    unit_prefixes = _en_address_unit_prefixes()
    street_suffix_alt = "|".join(map(re.escape, suffixes)) if suffixes else r"$^"
    unit_prefix_alt = "|".join(map(re.escape, unit_prefixes)) if unit_prefixes else r"$^"
    return re.compile(
        rf"^(?P<street>(?:P\.?\s*O\.?\s*Box\s+\d{{1,10}}|\d{{1,6}}[A-Za-z0-9\-]*\s+[A-Za-z0-9.'\- ]{{2,80}}?\b"
        rf"(?:{street_suffix_alt})\.?(?:\s+(?:N|S|E|W|NE|NW|SE|SW))?"
        rf"(?:\s+(?:#|(?:{unit_prefix_alt})\.?)\s*[A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?)?))"
        rf"(?:\s+(?P<rest>.+))?$",
        re.IGNORECASE,
    )
@lru_cache(maxsize=1)
def _EN_US_STATE_PATTERN() -> re.Pattern[str]:
    state_name_alt = "|".join(sorted((re.escape(name) for name in _EN_US_STATE_NAMES.values()), key=len, reverse=True)) if _EN_US_STATE_NAMES else r"$^"
    state_code_alt = "|".join(sorted(_EN_US_STATE_NAMES.keys(), key=len, reverse=True)) if _EN_US_STATE_NAMES else r"$^"
    return re.compile(rf"(?P<state>(?:{state_name_alt}|{state_code_alt}))$", re.IGNORECASE)
_NAME_SPACE_CHARS = set(" \t\r\n\f\v\u3000")
_NAME_MATCH_IGNORABLE = _NAME_SPACE_CHARS | set("·•・0123456789０１２３４５６７８９")
_PHONE_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：+＋")
_BANK_NUMBER_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_PASSPORT_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_DRIVER_LICENSE_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_ID_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_EMAIL_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
_ALNUM_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•/\\|:：")
_TIME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
_ADDRESS_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000,，;；:：、()（）.-/#")
_LOCATION_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000,，;；:：、()（）")
_ORG_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
_TIME_PATTERN = re.compile(r"^(?P<hour>[01]?\d|2[0-3])[:：](?P<minute>[0-5]\d)(?:[:：](?P<second>[0-5]\d))?$")
_EMAIL_AT_EQUIVALENTS = {"＠", "﹫"}
_EMAIL_DOT_EQUIVALENTS = {".", "．", "。", "｡", ",", "，", "、", "﹒", "·", "•", "・"}
_MASK_EQUIVALENTS_COMMON = {
    "＊",
    "●",
    "○",
    "◦",
    "◯",
    "⚫",
    "⚪",
    "■",
    "□",
    "▪",
    "▫",
    "█",
    "▇",
    "▉",
    "◆",
    "◇",
    "★",
    "☆",
    "※",
    "×",
    "✕",
    "✖",
    "╳",
}
_MASK_EQUIVALENTS_WITH_X = _MASK_EQUIVALENTS_COMMON | {"x", "X"}


@dataclass(slots=True)
class AddressComponents:
    """结构化地址组件。"""

    original_text: str
    locale: str = "raw"
    country_text: str | None = None
    province_text: str | None = None
    city_text: str | None = None
    district_text: str | None = None
    street_text: str | None = None
    building_text: str | None = None
    room_text: str | None = None
    postal_code_text: str | None = None
    detail_text: str | None = None
    country_key: str | None = None
    province_key: str | None = None
    city_key: str | None = None
    district_key: str | None = None
    street_key: str | None = None
    building_key: str | None = None
    room_key: str | None = None
    postal_code_key: str | None = None
    detail_key: str | None = None

    @property
    def granularity(self) -> str:
        if any((self.street_text, self.building_text, self.room_text, self.postal_code_text, self.detail_text)):
            return "detail"
        if self.district_text:
            return "district"
        if self.city_text:
            return "city"
        if self.country_text and not self.province_text:
            return "country"
        if self.province_text:
            return "province"
        return "raw"


@dataclass(slots=True)
class NameComponents:
    """结构化姓名组件。"""

    original_text: str
    locale: str = "raw"
    full_text: str = ""
    family_text: str | None = None
    given_text: str | None = None
    middle_text: str | None = None


def classify_content_shape_attr(value: str | None) -> PIIAttributeType:
    """按内容形态粗分为 TIME / NUMERIC / ALNUM / TEXTUAL；其余一律为 OTHER（兜底）。

    ``OTHER`` 表示未被 TIME / NUMERIC / ALNUM / TEXTUAL 规则容纳的内容：仅符号、空白、空串等。

    - 时钟时间片段（如 ``14:07``、``08:09:10``）：TIME
    - 仅数字与少量符号（无 Unicode 字母）：NUMERIC
    - 字母与数字并存：ALNUM
    - 仅文字与少量符号（无数字；字母含拉丁与中日韩等）：TEXTUAL
    - 其它任意情况：OTHER
    """
    if value is None:
        return PIIAttributeType.OTHER
    text = str(value)
    if not text.strip():
        return PIIAttributeType.OTHER
    if compact_time_value(text):
        return PIIAttributeType.TIME
    has_letter = any(char.isalpha() for char in text)
    has_digit = any(char.isdigit() for char in text)
    if has_letter and has_digit:
        return PIIAttributeType.ALNUM
    if has_digit and not has_letter:
        return PIIAttributeType.NUMERIC
    if has_letter and not has_digit:
        return PIIAttributeType.TEXTUAL
    return PIIAttributeType.OTHER


def compact_time_value(value: str) -> str:
    """将时钟时间文本归一为 ``HH:MM`` 或 ``HH:MM:SS``。"""
    compact = _compact_text(value)
    matched = _TIME_PATTERN.fullmatch(compact)
    if matched is None:
        return ""
    hour = int(matched.group("hour"))
    minute = matched.group("minute")
    second = matched.group("second")
    if second is not None:
        return f"{hour:02d}:{minute}:{second}"
    return f"{hour:02d}:{minute}"

def build_match_text(attr_type: PIIAttributeType, value: str) -> tuple[str, list[int]]:
    """构造用于容错匹配的压缩文本及其到原文的索引映射。"""
    if attr_type == PIIAttributeType.NAME:
        return _build_name_match_text(value)
    return _build_generic_match_text(attr_type, value)


def _build_generic_match_text(attr_type: PIIAttributeType, value: str) -> tuple[str, list[int]]:
    """构造非姓名类型的容错匹配文本。"""
    match_chars: list[str] = []
    index_map: list[int] = []
    for index, char in enumerate(str(value)):
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            normalized_char = _normalize_match_char(attr_type, normalized_char)
            if _is_ignorable_match_char(attr_type, normalized_char):
                continue
            match_chars.append(normalized_char.lower() if normalized_char.isascii() else normalized_char)
            index_map.append(index)
    return ("".join(match_chars), index_map)


def _build_name_match_text(value: str) -> tuple[str, list[int]]:
    """构造姓名匹配文本。

    中文姓名继续忽略空格与中点类噪声；英文姓名保留 token 间空格，
    不再把 ``Alice Johnson`` 压成 ``alicejohnson``。
    """
    raw_value = str(value or "")
    if parse_name_components(raw_value).locale != "en_us":
        return _build_generic_match_text(PIIAttributeType.NAME, raw_value)

    match_chars: list[str] = []
    index_map: list[int] = []
    previous_is_space = True
    for index, char in enumerate(raw_value):
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            if normalized_char in _NAME_SPACE_CHARS:
                if not match_chars or previous_is_space:
                    continue
                match_chars.append(" ")
                index_map.append(index)
                previous_is_space = True
                continue
            normalized_char = _normalize_match_char(PIIAttributeType.NAME, normalized_char)
            if normalized_char in (_NAME_MATCH_IGNORABLE - _NAME_SPACE_CHARS):
                continue
            match_chars.append(normalized_char.lower() if normalized_char.isascii() else normalized_char)
            index_map.append(index)
            previous_is_space = False
    if match_chars and match_chars[-1] == " ":
        match_chars.pop()
        index_map.pop()
    return ("".join(match_chars), index_map)


def canonicalize_name_text(
    value: str,
    *,
    allow_ocr_noise: bool = False,
    lower_ascii: bool = True,
) -> str:
    """按中英文差异归一姓名文本。

    中文姓名沿用紧凑形式；英文姓名保留 token 间空格，不再生成无空格主规范形。
    """
    original = unicodedata.normalize("NFKC", str(value or ""))
    components = parse_name_components(original)
    if components.locale == "en_us":
        normalized = re.sub(r"\s+", " ", original).strip()
        if allow_ocr_noise:
            normalized = re.sub(r"[0-9０-９]+", "", normalized)
            normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized.lower() if lower_ascii else normalized

    compact = "".join(
        char
        for char in re.sub(r"\s+", "", original).strip()
        if char not in _NAME_MATCH_IGNORABLE
    )
    if allow_ocr_noise:
        compact = re.sub(r"[0-9０-９]+", "", compact)
    return compact.lower() if lower_ascii and re.search(r"[A-Za-z]", compact) else compact

def address_components_from_levels(
    *,
    original_text: str | None = None,
    locale: str | None = None,
    country_text: str | None = None,
    province_text: str | None = None,
    city_text: str | None = None,
    district_text: str | None = None,
    street_text: str | None = None,
    building_text: str | None = None,
    room_text: str | None = None,
    postal_code_text: str | None = None,
    detail_text: str | None = None,
) -> AddressComponents:
    """由结构化层级值构造 AddressComponents。"""
    resolved_locale = locale or _detect_address_locale(
        country_text,
        province_text,
        city_text,
        district_text,
        street_text,
        building_text,
        room_text,
        postal_code_text,
        detail_text,
        original_text,
    )
    composed_detail = detail_text
    if not composed_detail:
        detail_parts = [part for part in (street_text, building_text, room_text) if part]
        composed_detail = " ".join(detail_parts) if resolved_locale == "en_us" else "".join(detail_parts)
    components = AddressComponents(
        original_text=original_text or "",
        locale=resolved_locale,
        country_text=country_text,
        province_text=province_text,
        city_text=city_text,
        district_text=district_text,
        street_text=street_text,
        building_text=building_text,
        room_text=room_text,
        postal_code_text=postal_code_text,
        detail_text=composed_detail,
        country_key=_address_component_key(country_text),
        province_key=_address_component_key(province_text, state_hint=True),
        city_key=_address_component_key(city_text),
        district_key=_address_component_key(district_text),
        street_key=_address_component_key(street_text),
        building_key=_address_component_key(building_text),
        room_key=_address_component_key(room_text),
        postal_code_key=_address_component_key(postal_code_text),
        detail_key=_address_component_key(composed_detail),
    )
    if not components.original_text:
        components.original_text = render_address_components(
            components,
            include_country=bool(country_text),
            granularity="detail",
        )
    return components


def parse_address_components(value: str) -> AddressComponents:
    """按 locale-aware 规则拆解地址。"""
    original = _normalize_address_parse_text(value)
    if not original:
        return AddressComponents(original_text="")
    if _looks_like_en_address_text(original):
        return _parse_en_address_components(original)
    return _parse_zh_address_components(original)


def parse_name_components(value: str) -> NameComponents:
    """按中英文常见顺序拆解姓名。"""
    original = re.sub(r"\s+", " ", str(value or "")).strip()
    if not original:
        return NameComponents(original_text="", full_text="")
    if re.fullmatch(r"[A-Za-z][A-Za-z ,.'\-]{0,80}", original):
        return _parse_en_name_components(original)
    compact = re.sub(r"\s+", "", original)
    if re.fullmatch(r"[一-龥·]{1,8}", compact):
        return _parse_zh_name_components(compact)
    return NameComponents(original_text=original, full_text=original)


def name_component_order(components: NameComponents) -> tuple[str, ...]:
    """根据源文本样式返回姓名组件顺序。"""
    if components.locale == "zh_cn":
        return ("family", "given")
    if components.locale == "en_us":
        if "," in (components.original_text or ""):
            return ("family", "given", "middle")
        return ("given", "middle", "family")
    return ("full",)


def name_display_units(
    components: NameComponents,
    *,
    order: tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    """将姓名组件转换为指定顺序上的文本单元。"""
    resolved_order = tuple(order) if order is not None else name_component_order(components)
    units: list[str] = []
    for component_name in resolved_order:
        if component_name == "full":
            if components.full_text:
                units.append(components.full_text)
            continue
        if component_name == "family" and components.family_text:
            units.append(components.family_text)
            continue
        if component_name == "given" and components.given_text:
            units.append(components.given_text)
            continue
        if component_name == "middle" and components.middle_text:
            units.append(components.middle_text)
    return units or ([components.full_text] if components.full_text else [])


def render_name_like_source(
    target_components: NameComponents,
    source_components: NameComponents,
    *,
    component_hint: str | None = None,
) -> str | None:
    """根据源姓名粒度返回目标姓名的对应片段。"""
    if not target_components.full_text:
        return None
    resolved_hint = component_hint or _infer_name_component_hint(source_components)
    if resolved_hint == "family" and target_components.family_text:
        return target_components.family_text
    if resolved_hint == "given" and target_components.given_text:
        return target_components.given_text
    if resolved_hint == "middle" and target_components.middle_text:
        return target_components.middle_text
    if resolved_hint == "full" and target_components.full_text:
        return _render_full_name_like_source(target_components, source_components) or target_components.full_text
    return target_components.full_text


def address_display_units(
    components: AddressComponents,
    *,
    include_country: bool = False,
    granularity: str = "detail",
    detail_mode: str | None = None,
) -> list[str]:
    """将地址组件转换为显示顺序上的文本单元。"""
    if not components.original_text and not any(
        (
            components.country_text,
            components.province_text,
            components.city_text,
            components.district_text,
            components.street_text,
            components.building_text,
            components.room_text,
            components.postal_code_text,
            components.detail_text,
        )
    ):
        return []
    if granularity == "raw":
        return [components.original_text] if components.original_text else []
    if components.locale == "en_us":
        return _en_address_display_units(
            components,
            include_country=include_country,
            granularity=granularity,
            detail_mode=detail_mode,
        )
    return _zh_address_display_units(
        components,
        include_country=include_country,
        granularity=granularity,
        detail_mode=detail_mode,
    )


def render_address_components(
    components: AddressComponents,
    *,
    include_country: bool = False,
    granularity: str = "detail",
    detail_mode: str | None = None,
) -> str:
    """按 locale-aware 规则渲染地址文本。"""
    units = address_display_units(
        components,
        include_country=include_country,
        granularity=granularity,
        detail_mode=detail_mode,
    )
    if not units:
        return components.original_text
    if components.locale == "en_us":
        return ", ".join(unit for unit in units if unit)
    return "".join(unit for unit in units if unit)


def _parse_zh_name_components(value: str) -> NameComponents:
    full_text = re.sub(r"\s+", "", value)
    if not full_text:
        return NameComponents(original_text="", full_text="")
    if "·" in full_text:
        family_text, given_text = full_text.split("·", 1)
        return NameComponents(
            original_text=full_text,
            locale="zh_cn",
            full_text=full_text,
            family_text=family_text or None,
            given_text=given_text or None,
        )
    if len(full_text) == 1:
        return NameComponents(
            original_text=full_text,
            locale="zh_cn",
            full_text=full_text,
            given_text=full_text,
        )
    if len(full_text) >= 3 and full_text[:2] in _COMMON_COMPOUND_SURNAMES:
        return NameComponents(
            original_text=full_text,
            locale="zh_cn",
            full_text=full_text,
            family_text=full_text[:2],
            given_text=full_text[2:] or None,
        )
    return NameComponents(
        original_text=full_text,
        locale="zh_cn",
        full_text=full_text,
        family_text=full_text[:1],
        given_text=full_text[1:] or None,
    )


def _parse_en_name_components(value: str) -> NameComponents:
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized:
        return NameComponents(original_text="", full_text="")
    if "," in normalized:
        family_raw, remainder = [part.strip() for part in normalized.split(",", 1)]
        tokens = [token for token in re.split(r"\s+", remainder) if token]
        given_text = tokens[0] if tokens else None
        middle_text = " ".join(tokens[1:]) or None
        return NameComponents(
            original_text=normalized,
            locale="en_us",
            full_text=normalized,
            family_text=family_raw or None,
            given_text=given_text,
            middle_text=middle_text,
        )
    tokens = [token for token in re.split(r"\s+", normalized) if token]
    if len(tokens) == 1:
        return NameComponents(
            original_text=normalized,
            locale="en_us",
            full_text=normalized,
            given_text=tokens[0],
        )
    return NameComponents(
        original_text=normalized,
        locale="en_us",
        full_text=normalized,
        family_text=tokens[-1],
        given_text=tokens[0],
        middle_text=" ".join(tokens[1:-1]) or None,
    )


def _infer_name_component_hint(components: NameComponents) -> str | None:
    if not components.full_text:
        return None
    if components.family_text and components.given_text:
        return "full"
    if components.family_text and not components.given_text:
        return "family"
    if components.given_text and not components.family_text:
        return "given"
    if components.middle_text and not components.family_text and not components.given_text:
        return "middle"
    return None


def _render_full_name_like_source(
    target_components: NameComponents,
    source_components: NameComponents,
) -> str | None:
    units = name_display_units(
        target_components,
        order=name_component_order(source_components),
    )
    if not units:
        return target_components.full_text
    if source_components.locale == "zh_cn":
        separator = "·" if "·" in (source_components.original_text or "") and len(units) >= 2 else ""
        return separator.join(units)
    if source_components.locale == "en_us":
        if "," in (source_components.original_text or "") and units:
            head = units[0]
            tail = " ".join(units[1:])
            return f"{head}, {tail}" if tail else head
        return " ".join(units)
    return target_components.full_text


def render_address_like_source(slot_components: AddressComponents, source_components: AddressComponents) -> str:
    """根据源地址粒度，从 persona 地址中生成匹配粒度的渲染文本。"""
    granularity = source_components.granularity
    if granularity == "raw":
        return render_address_components(
            slot_components,
            include_country=bool(source_components.country_text),
            granularity="detail",
        )
    detail_mode = _address_detail_mode_from_source(source_components)
    proxy = address_components_from_levels(
        locale=slot_components.locale or source_components.locale,
        country_text=slot_components.country_text if source_components.country_text else None,
        province_text=slot_components.province_text if source_components.province_text else None,
        city_text=slot_components.city_text if source_components.city_text else None,
        district_text=slot_components.district_text if source_components.district_text else None,
        street_text=slot_components.street_text if source_components.street_text else None,
        building_text=slot_components.building_text if source_components.building_text else None,
        room_text=slot_components.room_text if source_components.room_text else None,
        postal_code_text=slot_components.postal_code_text if source_components.postal_code_text else None,
        detail_text=slot_components.detail_text if source_components.detail_text else None,
    )
    rendered = render_address_components(
        proxy,
        include_country=bool(source_components.country_text),
        granularity=granularity,
        detail_mode=detail_mode,
    )
    if rendered:
        return rendered
    return render_address_components(slot_components, granularity="detail")


def render_address_by_granularity(components: AddressComponents, granularity: str) -> str:
    """按指定粒度输出地址文本。"""
    return render_address_components(components, granularity=granularity)


def _parse_zh_address_components(value: str) -> AddressComponents:
    compact = _compact_text(value)
    components = AddressComponents(original_text=compact, locale="zh_cn")
    if not compact:
        return components

    remaining = compact
    for alias, canonical in sorted(_COUNTRY_PREFIX_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if remaining.startswith(alias):
            components.country_text = canonical
            components.country_key = canonical
            remaining = remaining[len(alias):]
            break

    # 不再做省级别名替换：省市区应由 detector 的 geo 词典解析提供结构化结果。

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
        street_text, building_text, room_text = _split_zh_detail_components(remaining)
        components.street_text = street_text
        components.building_text = building_text
        components.room_text = room_text
        components.detail_text = remaining
        components.street_key = _address_component_key(street_text)
        components.building_key = _address_component_key(building_text)
        components.room_key = _address_component_key(room_text)
        components.detail_key = _address_component_key(remaining)
    return components


def _parse_en_address_components(value: str) -> AddressComponents:
    original = _normalize_address_parse_text(value)
    working = original.rstrip(", ")
    components = AddressComponents(original_text=original, locale="en_us")

    working, country_text = _extract_en_trailing_country(working)
    if country_text:
        components.country_text = country_text
        components.country_key = _address_component_key(country_text)

    working, postal_code = _extract_en_trailing_postal(working)
    if postal_code:
        components.postal_code_text = postal_code
        components.postal_code_key = postal_code

    working, province_text = _extract_en_trailing_state(working)
    if province_text:
        components.province_text = province_text
        components.province_key = _address_component_key(province_text, state_hint=True)

    working = working.strip(", ")
    street_segment = ""
    locality_segment = ""
    district_segment = ""
    segments = [segment.strip() for segment in working.split(",") if segment.strip()]

    if len(segments) >= 2:
        street_segment = segments[0]
        locality_segment = segments[-1]
        if len(segments) > 2:
            district_segment = ", ".join(segments[1:-1])
    elif len(segments) == 1:
        segment = segments[0]
        extracted_street, trailing_locality = _extract_en_street_prefix(segment)
        if extracted_street:
            street_segment = extracted_street
            locality_segment = trailing_locality
        elif components.province_text or components.postal_code_text or components.country_text:
            if _looks_like_en_street_segment(segment):
                street_segment = segment
            else:
                locality_segment = segment
        else:
            street_segment = segment

    if locality_segment:
        locality_parts = [part.strip() for part in locality_segment.split(",") if part.strip()]
        if locality_parts:
            components.city_text = locality_parts[-1]
            components.city_key = _address_component_key(components.city_text)
            if len(locality_parts) > 1:
                district_segment = ", ".join(locality_parts[:-1]) if not district_segment else district_segment
    if district_segment:
        components.district_text = district_segment
        components.district_key = _address_component_key(district_segment)

    if street_segment:
        street_text, building_text = _split_en_street_and_unit(street_segment)
        components.street_text = street_text
        components.building_text = building_text
        components.street_key = _address_component_key(street_text)
        components.building_key = _address_component_key(building_text)
        detail_parts = [part for part in (street_text, building_text) if part]
        components.detail_text = " ".join(detail_parts) if detail_parts else street_segment
        components.detail_key = _address_component_key(components.detail_text)
    elif components.postal_code_text:
        components.detail_text = components.postal_code_text
        components.detail_key = components.postal_code_key

    return components


def _zh_address_display_units(
    components: AddressComponents,
    *,
    include_country: bool,
    granularity: str,
    detail_mode: str | None,
) -> list[str]:
    units: list[str] = []
    if include_country and components.country_text:
        units.append(components.country_text)
    if granularity in {"province", "city", "district", "detail"} and components.province_text:
        units.append(components.province_text)
    if granularity in {"city", "district", "detail"} and components.city_text and components.city_text != components.province_text:
        units.append(components.city_text)
    if granularity in {"district", "detail"} and components.district_text:
        units.append(components.district_text)
    if granularity != "detail":
        return [unit for unit in units if unit]
    if detail_mode == "street":
        if components.street_text:
            units.append(components.street_text)
        elif components.detail_text:
            units.append(components.detail_text)
        return [unit for unit in units if unit]
    if detail_mode == "building_room":
        if components.building_text:
            units.append(components.building_text)
        if components.room_text:
            units.append(components.room_text)
        elif not components.building_text and components.detail_text:
            units.append(components.detail_text)
        return [unit for unit in units if unit]
    for value in (components.street_text, components.building_text, components.room_text):
        if value:
            units.append(value)
    if not any((components.street_text, components.building_text, components.room_text)) and components.detail_text:
        units.append(components.detail_text)
    return [unit for unit in units if unit]


def _en_address_display_units(
    components: AddressComponents,
    *,
    include_country: bool,
    granularity: str,
    detail_mode: str | None,
) -> list[str]:
    if granularity == "country":
        return [components.country_text] if components.country_text else []
    if granularity == "province":
        locality = ", ".join(
            part
            for part in (components.province_text, components.country_text if include_country else None)
            if part
        )
        units = [locality] if locality else []
        return units or ([components.original_text] if components.original_text else [])
    if granularity == "city":
        state_postal = " ".join(part for part in (components.province_text, components.postal_code_text) if part)
        locality = ", ".join(
            part
            for part in (components.city_text, state_postal, components.country_text if include_country else None)
            if part
        )
        units = [locality] if locality else []
        return units or ([components.original_text] if components.original_text else [])
    if granularity == "district":
        state_postal = " ".join(part for part in (components.province_text, components.postal_code_text) if part)
        locality = ", ".join(
            part
            for part in (
                components.district_text,
                components.city_text,
                state_postal,
                components.country_text if include_country else None,
            )
            if part
        )
        units = [locality] if locality else []
        return units or ([components.original_text] if components.original_text else [])

    line_1_parts: list[str] = []
    if detail_mode == "street":
        if components.street_text:
            line_1_parts.append(components.street_text)
    elif detail_mode == "building_room":
        for part in (components.building_text, components.room_text):
            if part:
                line_1_parts.append(part)
    else:
        for part in (components.street_text, components.building_text, components.room_text):
            if part:
                line_1_parts.append(part)

    state_postal = " ".join(part for part in (components.province_text, components.postal_code_text) if part)
    units = []
    if line_1_parts:
        units.append(" ".join(line_1_parts))
    locality = ", ".join(
        part
        for part in (
            components.district_text,
            components.city_text,
            state_postal,
            components.country_text if include_country else None,
        )
        if part
    )
    if locality:
        units.append(locality)
    return units or ([components.original_text] if components.original_text else [])


def _address_detail_mode_from_source(components: AddressComponents) -> str | None:
    if components.granularity != "detail":
        return None
    has_admin = any((components.country_text, components.province_text, components.city_text, components.district_text))
    has_street = bool(components.street_text)
    has_building = bool(components.building_text or components.room_text)
    has_postal = bool(components.postal_code_text)
    if has_street and not has_building and not has_postal and not has_admin:
        return "street"
    if not has_street and has_building and not has_postal and not has_admin:
        return "building_room"
    return "tail"


def _normalize_address_parse_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).strip()
    normalized = re.sub(r"[\t\r\n\f\v\u3000]+", " ", normalized)
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    normalized = re.sub(r"\s{2,}", " ", normalized)
    return normalized.strip(" ,")


def _detect_address_locale(*values: str | None) -> str:
    joined = " ".join(str(value) for value in values if value)
    if _looks_like_en_address_text(joined):
        return "en_us"
    return "zh_cn"


def _looks_like_en_address_text(value: str) -> bool:
    text = _normalize_address_parse_text(value)
    if not text:
        return False
    if not any(char.isascii() and char.isalpha() for char in text):
        return False
    if _EN_ADDRESS_PO_BOX_PATTERN.search(text):
        return True
    if _EN_ADDRESS_UNIT_PATTERN().fullmatch(text):
        return True
    if _EN_STREET_SUFFIX_PATTERN().search(text):
        return True
    if _EN_ADDRESS_POSTAL_PATTERN.search(text):
        return True
    return "," in text or bool(re.search(r"\b\d{1,6}\s+[A-Za-z]", text))


def _split_zh_detail_components(detail: str) -> tuple[str | None, str | None, str | None]:
    compact = _compact_text(detail)
    if not compact:
        return (None, None, None)
    remaining = compact
    room_text: str | None = None
    room_match = _ZH_ROOM_PATTERN.search(remaining)
    if room_match is not None:
        room_text = room_match.group("room")
        remaining = remaining[:room_match.start()].strip()
    building_text: str | None = None
    building_match = _ZH_BUILDING_PATTERN.search(remaining)
    if building_match is not None:
        building_text = building_match.group("building")
        remaining = remaining[:building_match.start()].strip()
    street_text = remaining or None
    if street_text is None and building_text is None and room_text is None:
        street_text = compact
    return (street_text, building_text, room_text)


def _split_en_street_and_unit(street_segment: str) -> tuple[str | None, str | None]:
    cleaned = _normalize_address_parse_text(street_segment)
    if not cleaned:
        return (None, None)
    if _EN_ADDRESS_PO_BOX_PATTERN.fullmatch(cleaned):
        return (cleaned, None)
    unit_match = _EN_ADDRESS_UNIT_PATTERN().search(cleaned)
    if unit_match is None:
        return (cleaned, None)
    unit_text = unit_match.group("unit").strip()
    street_text = cleaned[:unit_match.start()].rstrip(", ").strip()
    return (street_text or None, unit_text or None)


def _extract_en_trailing_country(value: str) -> tuple[str, str | None]:
    working = value.rstrip(", ")
    lower = working.lower()
    for alias, canonical in sorted(_EN_ADDRESS_COUNTRY_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if lower.endswith(alias):
            prefix = working[: len(working) - len(alias)].rstrip(", ")
            if not prefix or prefix.endswith(",") or prefix.endswith(" "):
                return (prefix.rstrip(", "), canonical)
            return (working, None)
    return (working, None)


def _extract_en_trailing_postal(value: str) -> tuple[str, str | None]:
    working = value.rstrip(", ")
    match = _EN_ADDRESS_POSTAL_PATTERN.search(working)
    if match is None:
        return (working, None)
    postal = match.group("postal")
    prefix = working[:match.start()].rstrip(", ")
    return (prefix, postal)


def _extract_en_trailing_state(value: str) -> tuple[str, str | None]:
    working = value.rstrip(", ")
    match = _EN_US_STATE_PATTERN().search(working)
    if match is None:
        return (working, None)
    state_text = match.group("state").strip()
    state_key = _normalize_us_state_key(state_text)
    if state_key is None:
        return (working, None)
    prefix = working[:match.start()].rstrip(", ")
    return (prefix, state_text)


def _extract_en_street_prefix(value: str) -> tuple[str | None, str]:
    cleaned = _normalize_address_parse_text(value)
    if not cleaned:
        return (None, "")
    match = _EN_ADDRESS_STREET_PREFIX_PATTERN().match(cleaned)
    if match is None:
        return (None, cleaned)
    street_text = match.group("street").strip()
    rest = (match.group("rest") or "").strip(" ,")
    return (street_text, rest)


def _looks_like_en_street_segment(value: str) -> bool:
    cleaned = _normalize_address_parse_text(value)
    if not cleaned:
        return False
    if _EN_ADDRESS_PO_BOX_PATTERN.fullmatch(cleaned):
        return True
    if _EN_STREET_SUFFIX_PATTERN().search(cleaned):
        return True
    return bool(re.search(r"^\d{1,6}\s+[A-Za-z]", cleaned))


def _address_component_key(value: str | None, *, state_hint: bool = False) -> str | None:
    if not value:
        return None
    normalized = unicodedata.normalize("NFKC", str(value)).strip()
    if not normalized:
        return None
    if state_hint:
        state_key = _normalize_us_state_key(normalized)
        if state_key:
            return state_key
    if any(char.isascii() and char.isalpha() for char in normalized):
        return re.sub(r"[^0-9A-Za-z]+", "", normalized).lower() or None
    return _compact_text(normalized) or None


def _normalize_us_state_key(value: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", str(value)).strip().lower().replace(".", "")
    normalized = re.sub(r"\s+", " ", normalized)
    return _en_us_state_aliases().get(normalized)


def _compact_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = re.sub(r"\s+", "", normalized).strip()
    return normalized.lower() if re.search(r"[A-Za-z]", normalized) else normalized

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

def _is_ignorable_match_char(attr_type: PIIAttributeType, char: str) -> bool:
    if attr_type == PIIAttributeType.NAME:
        return char in _NAME_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.PHONE:
        return char in _PHONE_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.BANK_NUMBER:
        return char in _BANK_NUMBER_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.PASSPORT_NUMBER:
        return char in _PASSPORT_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.DRIVER_LICENSE:
        return char in _DRIVER_LICENSE_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ID_NUMBER:
        return char in _ID_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.EMAIL:
        return char in _EMAIL_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.TIME:
        return char in _TIME_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ALNUM:
        return char in _ALNUM_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.NUMERIC:
        return char in _ALNUM_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.OTHER:
        return char in _ALNUM_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.TEXTUAL:
        return char in _ORG_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ADDRESS:
        return char in _ADDRESS_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ORGANIZATION:
        return char in _ORG_MATCH_IGNORABLE
    return char.isspace()


def _normalize_email_char(char: str) -> str:
    if char in _EMAIL_AT_EQUIVALENTS:
        return "@"
    if char in _EMAIL_DOT_EQUIVALENTS:
        return "."
    return char


def _normalize_match_char(attr_type: PIIAttributeType, char: str) -> str:
    char = _normalize_mask_char(attr_type, char)
    if attr_type == PIIAttributeType.EMAIL:
        return _normalize_email_char(char)
    if attr_type == PIIAttributeType.TIME and char == "：":
        return ":"
    return char


def _normalize_mask_char(attr_type: PIIAttributeType, char: str) -> str:
    if attr_type in {PIIAttributeType.PHONE, PIIAttributeType.BANK_NUMBER}:
        if char in _MASK_EQUIVALENTS_WITH_X:
            return "*"
    if attr_type in {
        PIIAttributeType.ID_NUMBER,
        PIIAttributeType.PASSPORT_NUMBER,
        PIIAttributeType.DRIVER_LICENSE,
        PIIAttributeType.EMAIL,
    }:
        if char in _MASK_EQUIVALENTS_COMMON:
            return "*"
    return char
