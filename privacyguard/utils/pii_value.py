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
_NAME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000·•・0123456789０１２３４５６７８９")
_PHONE_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：+＋")
_CARD_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_BANK_ACCOUNT_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_PASSPORT_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_DRIVER_LICENSE_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_ID_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•()（）[]【】/\\|:：")
_EMAIL_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
_OTHER_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000-－—_.,，。·•/\\|:：")
_ADDRESS_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000,，;；:：、()（）")
_ORG_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000")
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
        return compact_phone_value(cleaned)
    if attr_type == PIIAttributeType.CARD_NUMBER:
        return compact_card_number_value(cleaned)
    if attr_type == PIIAttributeType.BANK_ACCOUNT:
        return compact_bank_account_value(cleaned)
    if attr_type == PIIAttributeType.PASSPORT_NUMBER:
        return compact_passport_value(cleaned)
    if attr_type == PIIAttributeType.DRIVER_LICENSE:
        return compact_driver_license_value(cleaned)
    if attr_type == PIIAttributeType.ID_NUMBER:
        return compact_id_value(cleaned)
    if attr_type == PIIAttributeType.EMAIL:
        return compact_email_value(cleaned)
    if attr_type == PIIAttributeType.ADDRESS:
        return canonicalize_address_text(cleaned)
    if attr_type == PIIAttributeType.OTHER:
        return compact_other_code_value(cleaned)
    return normalize_text(value)


def compact_phone_value(value: str) -> str:
    """压缩手机号/电话文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.PHONE, char)
        if char in _PHONE_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars)


def compact_id_value(value: str) -> str:
    """压缩身份证文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.ID_NUMBER, char)
        if char in _ID_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars).upper()


def compact_card_number_value(value: str) -> str:
    """压缩卡号文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.CARD_NUMBER, char)
        if char in _CARD_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars)


def compact_bank_account_value(value: str) -> str:
    """压缩银行账号文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.BANK_ACCOUNT, char)
        if char in _BANK_ACCOUNT_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars)


def compact_passport_value(value: str) -> str:
    """压缩护照号文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.PASSPORT_NUMBER, char)
        if char in _PASSPORT_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars).upper()


def compact_driver_license_value(value: str) -> str:
    """压缩驾驶证号文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.DRIVER_LICENSE, char)
        if char in _DRIVER_LICENSE_MATCH_IGNORABLE:
            continue
        chars.append(char)
    return "".join(chars).upper()


def compact_email_value(value: str) -> str:
    """压缩邮箱文本，并把常见 OCR 误读的 at/dot 归一。"""
    compact = _compact_text(value)
    chars: list[str] = []
    for char in compact:
        char = _normalize_mask_char(PIIAttributeType.EMAIL, char)
        if char in _EMAIL_MATCH_IGNORABLE:
            continue
        chars.append(_normalize_email_char(char))
    return "".join(chars)


def compact_other_code_value(value: str) -> str:
    """压缩编号/卡号类文本，忽略常见 OCR 分隔噪声。"""
    compact = _compact_text(value)
    return "".join(char for char in compact if char not in _OTHER_MATCH_IGNORABLE).upper()


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
            normalized_char = _normalize_match_char(attr_type, normalized_char)
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
        for masked_variant in _high_precision_mask_variants(attr_type, raw_value):
            _add_match_variant(variants, attr_type, masked_variant)
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
    for shorthand in _address_shorthand_variants(components):
        _add_match_variant(variants, attr_type, shorthand)
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


def _high_precision_mask_variants(attr_type: PIIAttributeType, value: str) -> set[str]:
    if attr_type == PIIAttributeType.PHONE:
        return _masked_phone_variants(value)
    if attr_type == PIIAttributeType.CARD_NUMBER:
        return _masked_numeric_variants(compact_card_number_value(value), prefix_len=4, suffix_len=4, min_mask_len=5)
    if attr_type == PIIAttributeType.BANK_ACCOUNT:
        return _masked_numeric_variants(compact_bank_account_value(value), prefix_len=4, suffix_len=4, min_mask_len=4)
    if attr_type == PIIAttributeType.ID_NUMBER:
        return _masked_numeric_variants(compact_id_value(value), prefix_len=6, suffix_len=4, min_mask_len=4)
    if attr_type == PIIAttributeType.PASSPORT_NUMBER:
        return _masked_alnum_variants(compact_passport_value(value), prefix_len=2, suffix_len=4, min_mask_len=3)
    if attr_type == PIIAttributeType.DRIVER_LICENSE:
        return _masked_alnum_variants(compact_driver_license_value(value), prefix_len=6, suffix_len=4, min_mask_len=4)
    if attr_type == PIIAttributeType.EMAIL:
        return _masked_email_variants(value)
    return set()


def _masked_phone_variants(value: str) -> set[str]:
    compact = compact_phone_value(value)
    if not re.fullmatch(r"1[3-9]\d{9}", compact):
        return set()
    prefix = compact[:3]
    suffix = compact[-4:]
    masked_middle_len = len(compact) - 7
    masked_tail_len = len(compact) - 3
    masked_head_len = len(compact) - 4
    variants = {
        f"{prefix}{'*' * masked_middle_len}{suffix}",
        f"{prefix}{'*' * masked_tail_len}",
        f"{'*' * masked_head_len}{suffix}",
    }
    return {item for item in variants if item != compact}


def _masked_numeric_variants(value: str, *, prefix_len: int, suffix_len: int, min_mask_len: int) -> set[str]:
    compact = _compact_text(value).upper()
    if not re.fullmatch(r"[\dX]{8,30}", compact):
        return set()
    variants: set[str] = set()
    if len(compact) - prefix_len >= min_mask_len:
        variants.add(f"{compact[:prefix_len]}{'*' * (len(compact) - prefix_len)}")
    if len(compact) - suffix_len >= min_mask_len:
        variants.add(f"{'*' * (len(compact) - suffix_len)}{compact[-suffix_len:]}")
    if len(compact) - prefix_len - suffix_len >= min_mask_len:
        variants.add(f"{compact[:prefix_len]}{'*' * (len(compact) - prefix_len - suffix_len)}{compact[-suffix_len:]}")
    return {item for item in variants if item != compact}


def _masked_alnum_variants(value: str, *, prefix_len: int, suffix_len: int, min_mask_len: int) -> set[str]:
    compact = _compact_text(value).upper()
    if not re.fullmatch(r"[A-Z0-9]{6,30}", compact):
        return set()
    variants: set[str] = set()
    if len(compact) - prefix_len >= min_mask_len:
        variants.add(f"{compact[:prefix_len]}{'*' * (len(compact) - prefix_len)}")
    if len(compact) - suffix_len >= min_mask_len:
        variants.add(f"{'*' * (len(compact) - suffix_len)}{compact[-suffix_len:]}")
    if len(compact) - prefix_len - suffix_len >= min_mask_len:
        variants.add(f"{compact[:prefix_len]}{'*' * (len(compact) - prefix_len - suffix_len)}{compact[-suffix_len:]}")
    return {item for item in variants if item != compact}


def _masked_email_variants(value: str) -> set[str]:
    compact = compact_email_value(value)
    if not re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", compact):
        return set()
    local, domain = compact.split("@", 1)
    if not local or not domain:
        return set()
    variants: set[str] = set()
    if len(local) >= 1:
        exact_tail_mask_len = max(1, len(local) - 1)
        variants.add(f"{local[:1]}{'*' * exact_tail_mask_len}@{domain}")
        variants.add(f"{'*' * len(local)}@{domain}")
        variants.add(f"{local[:1]}{'*' * max(3, exact_tail_mask_len)}@{domain}")
        variants.add(f"{'*' * max(3, len(local))}@{domain}")
    return {item for item in variants if item != compact}


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


def _address_shorthand_variants(components: AddressComponents) -> set[str]:
    variants: set[str] = set()
    province_forms = _address_component_forms(components.province_text, keep_suffixes=("省",))
    city_forms = _address_component_forms(components.city_text, keep_suffixes=("市", "自治州", "地区", "盟"))
    district_forms = _address_component_forms(components.district_text, keep_suffixes=("区", "县", "旗", "市", "新区", "自治县", "自治旗"))
    detail_forms = _address_detail_forms(components.detail_text)
    for province in province_forms:
        for city in city_forms or {""}:
            for district in district_forms or {""}:
                for detail in detail_forms or {""}:
                    candidate = "".join(part for part in (province, city, district, detail) if part)
                    if candidate and candidate != components.original_text:
                        variants.add(candidate)
    return variants


def _address_component_forms(value: str | None, *, keep_suffixes: tuple[str, ...]) -> set[str]:
    if not value:
        return set()
    forms = {value}
    for suffix in keep_suffixes:
        if value.endswith(suffix) and len(value) > len(suffix):
            forms.add(value[: -len(suffix)])
    return {item for item in forms if item}


def _address_detail_forms(value: str | None) -> set[str]:
    if not value:
        return set()
    forms = {value}
    compact = _compact_text(value)
    if compact.endswith("号") and len(compact) > 1:
        forms.add(compact[:-1])
    forms.add(re.sub(r"(路|街|大道|道|巷|弄|胡同)(\d+[A-Za-z一-龥号室层栋单元]*)$", r"\2", compact))
    forms.add(re.sub(r"(路|街|大道|道|巷|弄|胡同)(\d+)$", r"\2", compact))
    cleaned_forms = {item for item in forms if item}
    if compact.endswith("号") and len(compact) > 1:
        cleaned_forms.update(item[:-1] for item in list(cleaned_forms) if item.endswith("号") and len(item) > 1)
    return cleaned_forms


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
    if attr_type == PIIAttributeType.CARD_NUMBER:
        return char in _CARD_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.BANK_ACCOUNT:
        return char in _BANK_ACCOUNT_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.PASSPORT_NUMBER:
        return char in _PASSPORT_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.DRIVER_LICENSE:
        return char in _DRIVER_LICENSE_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.ID_NUMBER:
        return char in _ID_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.EMAIL:
        return char in _EMAIL_MATCH_IGNORABLE
    if attr_type == PIIAttributeType.OTHER:
        return char in _OTHER_MATCH_IGNORABLE
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
    return char


def _normalize_mask_char(attr_type: PIIAttributeType, char: str) -> str:
    if attr_type in {PIIAttributeType.PHONE, PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}:
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
