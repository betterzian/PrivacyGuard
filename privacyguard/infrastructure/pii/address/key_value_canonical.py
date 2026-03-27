"""将地址文本按中文组件解析规则稳定为 ``key=value|…`` canonical。"""

from __future__ import annotations

import re
import unicodedata

from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.pii.address.types import AddressComponent

_KNOWN_ADDR_CANON_KEYS = frozenset(
    {"province", "city", "district", "street", "poi", "compound", "building", "room", "detail", "postal"}
)
_CANON_PART_ORDER = ("province", "city", "district", "street", "poi", "compound", "building", "room", "detail", "postal")


def _normalize_preformatted_address_canonical(text: str) -> str:
    slots: dict[str, str] = {}
    for part in (p.strip() for p in text.split("|") if p.strip()):
        key, sep, val = part.partition("=")
        if not sep:
            continue
        key_l = key.strip().lower()
        if key_l in _KNOWN_ADDR_CANON_KEYS and val.strip():
            slots[key_l] = val.strip()
    parts = [f"{key}={slots[key]}" for key in _CANON_PART_ORDER if key in slots]
    return "|".join(parts)


def _is_preformatted_address_canonical(text: str) -> bool:
    parts = [p.strip() for p in text.split("|") if p.strip()]
    if not parts:
        return False
    if any("=" not in p for p in parts):
        return False
    for p in parts:
        key, sep, val = p.partition("=")
        if not sep or not val.strip():
            return False
        if key.strip().lower() not in _KNOWN_ADDR_CANON_KEYS:
            return False
    return True


def has_cjk_characters(text: str) -> bool:
    """是否包含中日韩统一表意文字（用于标签字段值脚本判定）。"""
    return any("\u4e00" <= ch <= "\u9fff" for ch in (text or ""))


def zh_label_address_has_parse_components(text: str) -> bool:
    """中文解析器是否从文本中抽取出至少一处地名或地址属性片段。"""
    return bool(parse_zh_components((text or "").strip()))


def _compact_detail_payload(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = re.sub(r"\s+", "", normalized).strip()
    return normalized.lower() if re.search(r"[A-Za-z]", normalized) else normalized


def address_key_value_canonical_from_zh(text: str) -> str:
    """经 ``parse_zh_components`` 分解为 key=value；已是 canonical 串时只做规范化，避免重复解析。"""
    stripped = (text or "").strip()
    if not stripped:
        return ""
    if _is_preformatted_address_canonical(stripped):
        return _normalize_preformatted_address_canonical(stripped)
    components = parse_zh_components(stripped)
    if components:
        return canonicalize_address_components_key_value(components)
    detail = _compact_detail_payload(stripped)
    return f"detail={detail}" if detail else ""


def canonicalize_address_components_key_value(components: tuple[AddressComponent, ...]) -> str:
    """与检测流水线一致的 key=value 拼接（供组件元组直接序列化）。"""
    slots: dict[str, str] = {}

    def _put(key: str, val: str) -> None:
        compact = val.strip()
        if compact and key not in slots:
            slots[key] = compact

    def _strip_suffix(t: str, suffixes: tuple[str, ...]) -> str:
        cleaned = t.strip()
        for suffix in sorted(suffixes, key=len, reverse=True):
            if cleaned.endswith(suffix) and len(cleaned) > len(suffix):
                return cleaned[: -len(suffix)]
        return cleaned

    def _normalize_component_text(t: str, ctype: str) -> str:
        if ctype in {"province", "state"}:
            return _strip_suffix(t, ("特别行政区", "自治区", "省", "市", "state", "province"))
        if ctype == "city":
            return _strip_suffix(t, ("自治州", "地区", "盟", "市", "city"))
        if ctype in {"district", "county"}:
            return _strip_suffix(t, ("自治县", "自治旗", "新区", "区", "县", "旗", "市", "county", "district"))
        if ctype in {"road", "street", "po_box"}:
            return _strip_suffix(t, ("大道", "胡同", "街", "路", "道", "巷", "弄", "street", "road", "avenue", "blvd"))
        if ctype == "compound":
            return _strip_suffix(
                t,
                (
                    "小区",
                    "社区",
                    "花园",
                    "公寓",
                    "大厦",
                    "园区",
                    "家园",
                    "苑",
                    "庭",
                    "府",
                    "湾",
                    "community",
                    "garden",
                    "apartment",
                    "apartments",
                    "residence",
                    "residences",
                    "building",
                    "tower",
                    "park",
                ),
            )
        if ctype == "poi":
            return _strip_suffix(t, ("广场", "中心", "公园", "学校", "医院", "车站", "plaza", "center", "park"))
        return t.strip()

    def _canonical_numeric(t: str) -> str:
        digits = re.findall(r"\d+", t)
        if digits:
            return "".join(digits)
        zh = _chinese_numeral_to_int(t)
        if zh is not None:
            return str(zh)
        en = _english_numeral_to_int(t)
        if en is not None:
            return str(en)
        return ""

    for component in sorted(components, key=lambda item: item.start_offset):
        ctype = component.component_type
        t = component.text
        if ctype in {"province", "state"}:
            _put("province", _normalize_component_text(t, ctype))
            continue
        if ctype == "city":
            _put("city", _normalize_component_text(t, ctype))
            continue
        if ctype in {"district", "county"}:
            _put("district", _normalize_component_text(t, ctype))
            continue
        if ctype in {"road", "street", "po_box"}:
            _put("street", _normalize_component_text(t, ctype))
            continue
        if ctype == "compound":
            _put("compound", _normalize_component_text(t, ctype))
            continue
        if ctype == "poi":
            _put("poi", _normalize_component_text(t, ctype))
            continue
        if ctype in {"building", "unit", "floor"}:
            _put("building", _canonical_numeric(t))
            continue
        if ctype == "room":
            _put("room", _canonical_numeric(t))
            continue
        if ctype == "postal_code":
            _put("postal", t)
            continue
        _put("detail", t)

    order = ("province", "city", "district", "street", "poi", "compound", "building", "room", "detail", "postal")
    parts = [f"{key}={slots[key]}" for key in order if key in slots]
    return "|".join(parts)


_ZH_DIGIT = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_EN_DIGIT = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
}
_EN_TEENS = {
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
}
_EN_TENS = {
    "twenty": 20,
    "thirty": 30,
    "forty": 40,
    "fifty": 50,
    "sixty": 60,
    "seventy": 70,
    "eighty": 80,
    "ninety": 90,
}


def _chinese_numeral_to_int(text: str) -> int | None:
    chars = [ch for ch in text if ch in _ZH_DIGIT or ch in {"十", "百", "千"}]
    if not chars:
        return None
    compact = "".join(chars)
    if all(ch in _ZH_DIGIT for ch in compact):
        return int("".join(str(_ZH_DIGIT[ch]) for ch in compact))
    total = 0
    section = 0
    number = 0
    unit_map = {"十": 10, "百": 100, "千": 1000}
    for ch in compact:
        if ch in _ZH_DIGIT:
            number = _ZH_DIGIT[ch]
            continue
        unit = unit_map.get(ch)
        if unit is None:
            continue
        if number == 0:
            number = 1
        section += number * unit
        number = 0
    total += section + number
    return total if total > 0 else None


def _english_numeral_to_int(text: str) -> int | None:
    tokens = [tok for tok in re.split(r"[^A-Za-z]+", text.lower()) if tok]
    if not tokens:
        return None
    if all(tok in _EN_DIGIT for tok in tokens):
        return int("".join(str(_EN_DIGIT[tok]) for tok in tokens))
    value = 0
    current = 0
    seen = False
    for tok in tokens:
        if tok in _EN_DIGIT:
            current += _EN_DIGIT[tok]
            seen = True
            continue
        if tok in _EN_TEENS:
            current += _EN_TEENS[tok]
            seen = True
            continue
        if tok in _EN_TENS:
            current += _EN_TENS[tok]
            seen = True
            continue
        if tok == "hundred":
            current = max(1, current) * 100
            seen = True
            continue
        if tok == "thousand":
            value += max(1, current) * 1000
            current = 0
            seen = True
            continue
        return None
    result = value + current
    return result if seen and result >= 0 else None
