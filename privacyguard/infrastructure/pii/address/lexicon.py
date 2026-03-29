"""新地址子系统的词法规则。"""

from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.types import AddressComponent

_HARD_STOP_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[;；。！？!?]"),
    re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
    re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
    re.compile(r"(?<!\w)(?:\(\d{3}\)\s*|\d{3}[-. ]?)\d{3}[-. ]\d{4}(?!\w)"),
)

_ZH_COMPONENT_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    ("province", re.compile(r"[一-龥]{2,8}(?:特别行政区|自治区|省)"), False),
    ("city", re.compile(r"(?:北京|上海|天津|重庆)市|[一-龥]{2,8}(?:自治州|地区|盟|市)"), False),
    ("district", re.compile(r"[一-龥A-Za-z0-9]{1,12}(?:区|县|旗)"), False),
    ("street_admin", re.compile(r"[一-龥A-Za-z0-9]{1,12}街道"), False),
    ("town", re.compile(r"[一-龥A-Za-z0-9]{1,12}(?:镇|乡)"), False),
    ("village", re.compile(r"[一-龥A-Za-z0-9]{1,16}(?:村|社区)"), False),
    ("road", re.compile(r"[一-龥A-Za-z0-9]{1,24}(?:大道|胡同|路|街|道|巷|弄)"), False),
    ("compound", re.compile(r"[一-龥A-Za-z0-9]{1,24}(?:小区|公寓|大厦|园区|社区|花园|家园|苑|庭|府|湾|宿舍)"), False),
    ("building", re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+(?:号楼|栋|幢|座|楼)"), True),
    ("unit", re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+单元"), True),
    ("floor", re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+层"), True),
    ("room", re.compile(r"[0-9A-Za-z]+(?:室|房|户)"), True),
    ("postal_code", re.compile(r"(?<!\d)\d{6}(?!\d)"), False),
)

_EN_COMPONENT_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    (
        "street",
        re.compile(
            r"\b\d{1,6}[A-Za-z0-9\-]*\s+[A-Za-z0-9.'\- ]{1,80}?"
            r"\b(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct|place|pl|parkway|pkwy|terrace|ter|circle|cir|way|highway|hwy)\.?\b"
            r"(?:\s+(?:n|s|e|w|ne|nw|se|sw))?",
            re.IGNORECASE,
        ),
        False,
    ),
    ("unit", re.compile(r"(?:#\s*[A-Za-z0-9\-]+|\b(?:apt|apartment|suite|ste|unit)\.?\s+[A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?)", re.IGNORECASE), True),
    ("floor", re.compile(r"\b(?:floor|fl)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE), True),
    ("room", re.compile(r"\b(?:room|rm)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE), True),
    ("city", re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}(?=,\s*[A-Z]{2}\b)"), False),
    ("state", re.compile(r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY)\b", re.IGNORECASE), False),
    ("postal_code", re.compile(r"\b\d{5}(?:-\d{4})?\b"), False),
)

_BRIDGEABLE_GAP_RE = re.compile(r"^[\s,，、:/：()（）\\-—#]*$")
_TRAILING_ZH_HOUSE_NUMBER_RE = re.compile(r"^\s*\d{1,6}(?:号|號)(?!\d)")

_ZH_KEY_SUFFIXES: dict[str, tuple[str, ...]] = {
    "province": ("特别行政区", "自治区", "省", "市"),
    "city": ("自治州", "地区", "盟", "市"),
    "district": ("区", "县", "旗"),
    "street_admin": ("街道",),
    "town": ("镇", "乡"),
    "village": ("社区", "村"),
    "road": ("大道", "胡同", "路", "街", "道", "巷", "弄"),
    "compound": ("小区", "公寓", "大厦", "园区", "社区", "花园", "家园", "苑", "庭", "府", "湾", "宿舍"),
    "building": ("号楼", "栋", "幢", "座", "楼"),
    "unit": ("单元",),
    "floor": ("层",),
    "room": ("室", "房", "户"),
}
_EN_KEY_SUFFIXES: dict[str, tuple[str, ...]] = {
    "street": ("street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd", "drive", "dr", "lane", "ln", "court", "ct", "place", "pl", "parkway", "pkwy", "terrace", "ter", "circle", "cir", "way", "highway", "hwy"),
    "unit": ("apt", "apartment", "suite", "ste", "unit", "#"),
    "floor": ("floor", "fl"),
    "room": ("room", "rm"),
}
_ZH_PREFIX_TRIM_PATTERNS: dict[str, re.Pattern[str]] = {
    "city": re.compile(r"(?:.*(?:特别行政区|自治区|省|市))(?P<tail>[一-龥A-Za-z0-9]{1,8}(?:自治州|地区|盟|市))$"),
    "district": re.compile(r"(?:.*(?:特别行政区|自治区|省|市|区|县|旗|盟|地区))(?P<tail>[一-龥A-Za-z0-9]{1,12}(?:区|县|旗))$"),
    "street_admin": re.compile(r"(?:.*(?:特别行政区|自治区|省|市|区|县|旗|盟|地区))(?P<tail>[一-龥A-Za-z0-9]{1,12}街道)$"),
    "town": re.compile(r"(?:.*(?:特别行政区|自治区|省|市|区|县|旗|盟|地区|街道))(?P<tail>[一-龥A-Za-z0-9]{1,12}(?:镇|乡))$"),
    "village": re.compile(r"(?:.*(?:省|市|区|县|旗|盟|地区|街道|镇|乡))(?P<tail>[一-龥A-Za-z0-9]{1,16}(?:村|社区))$"),
    "road": re.compile(r"(?:.*(?:省|市|区|县|旗|盟|地区|街道|镇|乡|村|社区|的))(?P<tail>[一-龥A-Za-z0-9]{1,24}(?:大道|胡同|路|街|道|巷|弄))$"),
    "compound": re.compile(r"(?:.*(?:省|市|区|县|旗|盟|地区|街道|镇|乡|村|社区|路|街|大道|道|巷|弄|胡同|的))(?P<tail>[一-龥A-Za-z0-9]{1,24}(?:小区|公寓|大厦|园区|社区|花园|家园|苑|庭|府|湾|宿舍))$"),
}
_ZH_NUMERALS = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}


def collect_components(text: str, *, locale_profile: str, forbidden_spans: tuple[tuple[int, int], ...] = ()) -> tuple[AddressComponent, ...]:
    matches: list[AddressComponent] = []
    if locale_profile in {"zh_cn", "mixed"} or any("\u4e00" <= ch <= "\u9fff" for ch in text):
        matches.extend(_collect_with_patterns(text, _ZH_COMPONENT_PATTERNS, forbidden_spans, script="zh"))
    if locale_profile in {"en_us", "mixed"} and any("A" <= ch <= "z" for ch in text):
        matches.extend(_collect_with_patterns(text, _EN_COMPONENT_PATTERNS, forbidden_spans, script="en"))
    return tuple(_dedupe_components(matches))


def find_hard_stop(gap: str) -> bool:
    if "\n\n" in gap or "\r\n\r\n" in gap:
        return True
    return any(pattern.search(gap) is not None for pattern in _HARD_STOP_TEXT_PATTERNS)


def can_bridge_gap(gap: str) -> bool:
    if gap == "":
        return True
    return _BRIDGEABLE_GAP_RE.fullmatch(gap) is not None


def extend_tail(text: str, end: int, tail_component_type: str) -> int:
    tail = text[end:]
    if tail_component_type in {"road", "street"}:
        house = _TRAILING_ZH_HOUSE_NUMBER_RE.match(tail)
        if house is not None:
            return end + house.end()
    return end


def trim_narrative_suffix(text: str) -> str:
    trimmed = text.rstrip()
    for suffix in ("里", "内", "附近", "旁边", "门口", "周边"):
        if trimmed.endswith(suffix):
            return trimmed[: -len(suffix)].rstrip()
    return trimmed


def component_sort_key(component: AddressComponent) -> tuple[int, int, str]:
    return (component.start, component.end, component.component_type)


def _collect_with_patterns(
    text: str,
    patterns: tuple[tuple[str, re.Pattern[str], bool], ...],
    forbidden_spans: tuple[tuple[int, int], ...],
    *,
    script: str,
) -> list[AddressComponent]:
    results: list[AddressComponent] = []
    for component_type, pattern, is_detail in patterns:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if any(not (end <= left or start >= right) for left, right in forbidden_spans):
                continue
            raw = match.group(0).strip(" ,，")
            if not raw:
                continue
            raw_start = start + match.group(0).find(raw)
            component = _normalize_component(
                component_type=component_type,
                raw_text=raw,
                raw_start=raw_start,
                is_detail=is_detail,
                script=script,
            )
            if component is None:
                continue
            results.append(component)
    return results


def _normalize_component(
    *,
    component_type: str,
    raw_text: str,
    raw_start: int,
    is_detail: bool,
    script: str,
) -> AddressComponent | None:
    component_text = _trim_embedded_prefix(component_type, raw_text, script=script)
    if not component_text:
        return None
    relative_start = raw_text.rfind(component_text)
    if relative_start < 0:
        relative_start = 0
    component_start = raw_start + relative_start
    component_end = component_start + len(component_text)
    value_raw, key_text = _split_component_text(component_type, component_text, script=script)
    if not value_raw and not key_text:
        return None
    if value_raw:
        value_relative_start = component_text.find(value_raw)
        if value_relative_start < 0:
            value_relative_start = 0
        value_relative_end = value_relative_start + len(value_raw)
    else:
        value_relative_start = 0
        value_relative_end = 0
    if key_text:
        key_relative_start = component_text.rfind(key_text)
        if key_relative_start < 0:
            key_relative_start = max(value_relative_end, len(component_text) - len(key_text))
    else:
        key_relative_start = value_relative_end
    value_text = _normalize_component_value(component_type, value_raw, script=script)
    if not value_text and not key_text:
        return None
    return AddressComponent(
        component_type=component_type,
        text=component_text,
        start=component_start,
        end=component_end,
        value_text=value_text or value_raw,
        value_start=component_start + value_relative_start,
        value_end=component_start + value_relative_end,
        key_text=key_text,
        key_start=component_start + key_relative_start,
        key_end=component_start + key_relative_start + len(key_text),
        is_detail=is_detail,
    )


def _trim_embedded_prefix(component_type: str, raw_text: str, *, script: str) -> str:
    if script != "zh":
        return raw_text.strip()
    pattern = _ZH_PREFIX_TRIM_PATTERNS.get(component_type)
    if pattern is None:
        return raw_text.strip()
    match = pattern.match(raw_text)
    if match is None:
        return raw_text.strip()
    return match.group("tail").strip()


def _split_component_text(component_type: str, text: str, *, script: str) -> tuple[str, str]:
    if script == "en" and component_type in {"unit", "floor", "room"}:
        prefix_match = re.match(r"(?i)^(apt|apartment|suite|ste|unit|floor|fl|room|rm)\.?\s+([A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?)$", text)
        if prefix_match is not None:
            return prefix_match.group(2), prefix_match.group(1)
        hash_match = re.match(r"^#\s*([A-Za-z0-9\-]+)$", text)
        if hash_match is not None:
            return hash_match.group(1), "#"
    suffixes = _ZH_KEY_SUFFIXES if script == "zh" else _EN_KEY_SUFFIXES
    for suffix in suffixes.get(component_type, ()):
        if text.lower().endswith(suffix.lower()) and len(text) > len(suffix):
            return text[: -len(suffix)], text[-len(suffix) :]
    return text, ""


def _normalize_component_value(component_type: str, value_text: str, *, script: str) -> str:
    raw = value_text.strip()
    if not raw:
        return ""
    if component_type in {"building", "unit", "floor", "room"}:
        normalized = _normalize_detail_value(raw)
        return normalized or raw
    if script == "en":
        return raw
    return raw


def _normalize_detail_value(text: str) -> str:
    alnum = re.sub(r"[^A-Za-z0-9一二三四五六七八九十百零两〇]", "", text)
    if alnum and re.search(r"[A-Za-z]", alnum):
        return alnum
    numeric = _canonical_numeric(text)
    return numeric or alnum


def _canonical_numeric(text: str) -> str:
    digits = re.findall(r"\d+", text)
    if digits:
        return "".join(digits)
    zh_number = _chinese_numeral_to_int(text)
    if zh_number is not None:
        return str(zh_number)
    return ""


def _chinese_numeral_to_int(text: str) -> int | None:
    chars = [ch for ch in text if ch in _ZH_NUMERALS or ch in {"十", "百", "千"}]
    if not chars:
        return None
    compact = "".join(chars)
    if all(ch in _ZH_NUMERALS for ch in compact):
        return int("".join(str(_ZH_NUMERALS[ch]) for ch in compact))
    total = 0
    section = 0
    number = 0
    unit_map = {"十": 10, "百": 100, "千": 1000}
    for ch in compact:
        if ch in _ZH_NUMERALS:
            number = _ZH_NUMERALS[ch]
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


def _dedupe_components(components: list[AddressComponent]) -> list[AddressComponent]:
    if not components:
        return []
    ordered = sorted(components, key=lambda item: (item.start, item.end, -(item.end - item.start), item.component_type))
    kept: list[AddressComponent] = []
    for candidate in ordered:
        duplicate = next(
            (
                existing
                for existing in kept
                if existing.start == candidate.start
                and existing.end == candidate.end
                and existing.component_type == candidate.component_type
            ),
            None,
        )
        if duplicate is not None:
            continue
        if kept and candidate.start < kept[-1].end and candidate.end <= kept[-1].end:
            if (candidate.end - candidate.start) <= (kept[-1].end - kept[-1].start):
                continue
            kept[-1] = candidate
            continue
        kept.append(candidate)
    return kept
