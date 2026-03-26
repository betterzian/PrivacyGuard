from __future__ import annotations

import re
from typing import Iterable

from privacyguard.infrastructure.pii.address.types import AddressComponentMatch
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _ADDRESS_FIELD_KEYWORDS,
    _BUILTIN_GEO_LEXICON,
    _EMAIL_FIELD_KEYWORDS,
    _ID_FIELD_KEYWORDS,
    _OCR_SEMANTIC_BREAK_TOKEN,
    _PHONE_FIELD_KEYWORDS,
)

_ZH_CONNECTORS = {"", " ", ",", "，", "、", ":", "：", "-", "－", "—", "/", "#", "的", _OCR_SEMANTIC_BREAK_TOKEN}
_EN_CONNECTORS = {"", " ", ",", ", ", "-", " - ", "#", _OCR_SEMANTIC_BREAK_TOKEN}
_MASKED_END_RE = re.compile(r"(?:\s*(?:\.{3,}|…+|[*＊]{2,}|[xX]{2,}|某+))$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(
    r"(?:\+?1[\s\-._()]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2}|1[3-9]\d)[\s\-._()]*[0-9xX*＊]{2,4}[\s\-._()]*[0-9xX*＊]{2,4}"
)
_TIME_RE = re.compile(r"(?:[01]?\d|2[0-3])[:：][0-5]\d(?:[:：][0-5]\d)?")
_PRICE_RE = re.compile(r"(?:¥|￥|\$)\s*\d")
_ORDER_RE = re.compile(r"(?:订单号|单号|order\s*#?)", re.IGNORECASE)

_ZH_ROAD_RE = re.compile(r"[一-龥A-Za-z0-9]{2,24}(?:路|街|大道|道|巷|弄|胡同)")
_ZH_COMPOUND_RE = re.compile(r"[一-龥A-Za-z0-9]{1,28}(?:小区|公寓|大厦|园区|社区|花园|家园|苑|庭|府|湾|宿舍|广场|公园|景区|商圈|机场|车站|站)")
_ZH_BUILDING_RE = re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+(?:号楼|栋|幢|座|楼)")
_ZH_UNIT_RE = re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+单元")
_ZH_FLOOR_RE = re.compile(r"[0-9A-Za-z]+层")
_ZH_ROOM_RE = re.compile(r"[0-9A-Za-z]+(?:室|房|户)")
_ZH_POSTAL_RE = re.compile(r"\b\d{6}\b")
_ZH_ADMIN_RE = re.compile(r"[一-龥]{2,12}(?:特别行政区|自治区|自治州|省|市|新区|自治县|自治旗|区|县|旗|乡|镇|街道)")

_EN_PO_BOX_RE = re.compile(r"\bP\.?\s*O\.?\s*Box\s+\d{1,10}\b", re.IGNORECASE)
_EN_STREET_RE = re.compile(
    r"\b\d{1,6}[A-Za-z0-9\-]*\s+[A-Za-z0-9.'\- ]{1,80}?"
    r"\b(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct|place|pl|parkway|pkwy|terrace|ter|circle|cir|way|highway|hwy)\.?\b"
    r"(?:\s+(?:n|s|e|w|ne|nw|se|sw))?",
    re.IGNORECASE,
)
_EN_UNIT_RE = re.compile(
    r"\b(?:#|apt|apartment|suite|ste|unit|floor|fl|room|rm)\.?\s*[A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?",
    re.IGNORECASE,
)
_EN_FLOOR_RE = re.compile(r"\b(?:floor|fl)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE)
_EN_ROOM_RE = re.compile(r"\b(?:room|rm)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE)
_EN_POSTAL_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
_EN_STATE_RE = re.compile(
    r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY)\b",
    re.IGNORECASE,
)

_SOFT_STOP_TOKENS = {
    "branch",
    "check in",
    "company",
    "hospital",
    "school",
    "store",
    "travel",
    "university",
    "work",
    "上班",
    "公司",
    "出发",
    "吃饭",
    "商店",
    "大学",
    "学校",
    "工作",
    "店",
    "医院",
    "集合",
}
_PUBLIC_PLACE_SUFFIXES = (
    "airport",
    "park",
    "plaza",
    "station",
    "store",
    "branch",
    "机场",
    "公园",
    "商圈",
    "广场",
    "景区",
    "站",
    "车站",
    "门店",
)
_ORG_SUFFIX_TOKENS = (
    "bank",
    "college",
    "company",
    "group",
    "hospital",
    "institute",
    "school",
    "university",
    "事务所",
    "公司",
    "医院",
    "大学",
    "学院",
    "学校",
    "工作室",
    "银行",
    "集团",
)
_LEADING_NOISE_RE = re.compile(
    r"^(?:\s*(?:请)?(?:在|住在|我住在|我住|位于|地址在|住址在|家住|现住|居住于|收货到|寄往|寄到|送到|派送至|发往|前往|来自|发自|located at|live at|lives at|resides at|ship to|send to|deliver to|from)\s*)",
    re.IGNORECASE,
)
_LABEL_RE = re.compile(
    rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?:{'|'.join(sorted((re.escape(item) for item in _ADDRESS_FIELD_KEYWORDS), key=len, reverse=True))})\s*(?:[:：=]|是|为|is|was|at)?\s*",
    re.IGNORECASE,
)
_FIELD_KEYWORD_RE = re.compile(
    "|".join(
        sorted(
            (
                re.escape(item)
                for item in (
                    *_ADDRESS_FIELD_KEYWORDS,
                    *_PHONE_FIELD_KEYWORDS,
                    *_EMAIL_FIELD_KEYWORDS,
                    *_ID_FIELD_KEYWORDS,
                )
            ),
            key=len,
            reverse=True,
        )
    ),
    re.IGNORECASE,
)


def build_label_pattern() -> re.Pattern[str]:
    return _LABEL_RE


def iter_address_components(text: str, *, locale_profile: str) -> tuple[AddressComponentMatch, ...]:
    matches: list[AddressComponentMatch] = []
    if locale_profile in {"zh_cn", "mixed"}:
        matches.extend(_iter_zh_components(text))
    if locale_profile in {"en_us", "mixed"}:
        matches.extend(_iter_en_components(text))
    return tuple(_dedupe_component_matches(matches))


def masked_tail_match(text: str) -> re.Match[str] | None:
    return _MASKED_END_RE.search(text)


def address_connectors() -> frozenset[str]:
    return frozenset(_ZH_CONNECTORS | _EN_CONNECTORS)


def is_connector_text(text: str) -> bool:
    if text in address_connectors():
        return True
    compact = text.replace(_OCR_SEMANTIC_BREAK_TOKEN, "").strip()
    return compact in {"", ",", "，", "、", "-", "－", "—", "#", "的", "(", ")", "（", "）"}


def hard_stop_matches(text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for pattern, name in (
        (_EMAIL_RE, "email"),
        (_PHONE_RE, "phone"),
        (_TIME_RE, "time"),
        (_PRICE_RE, "price"),
        (_ORDER_RE, "order"),
    ):
        match = pattern.search(text)
        if match is not None:
            hits.append((match.start(), name))
    return sorted(hits, key=lambda item: item[0])


def find_field_keyword(text: str) -> re.Match[str] | None:
    return _FIELD_KEYWORD_RE.search(text)


def public_place_suffixes() -> tuple[str, ...]:
    return _PUBLIC_PLACE_SUFFIXES


def organization_suffix_tokens() -> tuple[str, ...]:
    return _ORG_SUFFIX_TOKENS


def soft_stop_tokens() -> frozenset[str]:
    return frozenset(_SOFT_STOP_TOKENS)


def leading_noise_pattern() -> re.Pattern[str]:
    return _LEADING_NOISE_RE


def _iter_zh_components(text: str) -> Iterable[AddressComponentMatch]:
    for match in _ZH_ADMIN_RE.finditer(text):
        yield AddressComponentMatch(_zh_admin_type(match.group(0)), match.start(), match.end(), match.group(0), "strong")
    for token in _iter_builtin_geo_tokens(text):
        yield token
    for iterator, component_type in (
        (_ZH_ROAD_RE.finditer(text), "road"),
        (_ZH_COMPOUND_RE.finditer(text), "compound"),
        (_ZH_BUILDING_RE.finditer(text), "building"),
        (_ZH_UNIT_RE.finditer(text), "unit"),
        (_ZH_FLOOR_RE.finditer(text), "floor"),
        (_ZH_ROOM_RE.finditer(text), "room"),
        (_ZH_POSTAL_RE.finditer(text), "postal_code"),
    ):
        for item in iterator:
            yield AddressComponentMatch(component_type, item.start(), item.end(), item.group(0), "strong")


def _iter_en_components(text: str) -> Iterable[AddressComponentMatch]:
    for iterator, component_type in (
        (_EN_PO_BOX_RE.finditer(text), "po_box"),
        (_EN_STREET_RE.finditer(text), "street"),
        (_EN_UNIT_RE.finditer(text), "unit"),
        (_EN_FLOOR_RE.finditer(text), "floor"),
        (_EN_ROOM_RE.finditer(text), "room"),
        (_EN_POSTAL_RE.finditer(text), "postal_code"),
        (_EN_STATE_RE.finditer(text), "state"),
    ):
        for item in iterator:
            yield AddressComponentMatch(component_type, item.start(), item.end(), item.group(0), "strong")


def _iter_builtin_geo_tokens(text: str) -> Iterable[AddressComponentMatch]:
    from privacyguard.infrastructure.pii.rule_based_detector_shared import _LOCATION_CLUE_MATCHER

    seen: set[tuple[int, int]] = set()
    for start, end, token in _LOCATION_CLUE_MATCHER.finditer(text):
        if (start, end) in seen:
            continue
        seen.add((start, end))
        if token in _BUILTIN_GEO_LEXICON.provinces:
            component_type = "province"
        elif token in _BUILTIN_GEO_LEXICON.cities:
            component_type = "city"
        elif token in _BUILTIN_GEO_LEXICON.districts:
            component_type = "district"
        elif token in _BUILTIN_GEO_LEXICON.local_places:
            component_type = "compound" if token.endswith(("小区", "公寓", "大厦", "园区", "社区", "宿舍")) else "poi"
        else:
            continue
        yield AddressComponentMatch(component_type, start, end, token, "medium")


def _dedupe_component_matches(matches: list[AddressComponentMatch]) -> list[AddressComponentMatch]:
    kept: list[AddressComponentMatch] = []
    for candidate in sorted(matches, key=lambda item: (item.start, -(item.end - item.start), item.component_type)):
        replaced = False
        for index, previous in enumerate(kept):
            if previous.start == candidate.start and previous.end == candidate.end:
                if _component_rank(candidate.component_type) > _component_rank(previous.component_type):
                    kept[index] = candidate
                replaced = True
                break
            if not (candidate.end <= previous.start or candidate.start >= previous.end):
                if (candidate.end - candidate.start) > (previous.end - previous.start) and _component_rank(candidate.component_type) >= _component_rank(previous.component_type):
                    kept[index] = candidate
                replaced = True
                break
        if not replaced:
            kept.append(candidate)
    return sorted(kept, key=lambda item: (item.start, item.end))


def _component_rank(component_type: str) -> int:
    order = {
        "room": 9,
        "floor": 8,
        "unit": 7,
        "building": 6,
        "street": 5,
        "road": 5,
        "po_box": 5,
        "compound": 4,
        "district": 3,
        "city": 2,
        "province": 1,
        "state": 1,
        "postal_code": 1,
        "poi": 1,
    }
    return order.get(component_type, 0)


def _zh_admin_type(value: str) -> str:
    if value.endswith(("省", "自治区", "特别行政区")):
        return "province"
    if value.endswith(("市", "自治州", "地区", "盟")):
        return "city"
    return "district"
