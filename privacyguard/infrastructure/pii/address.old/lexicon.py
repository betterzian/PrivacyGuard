from __future__ import annotations

import re
from typing import Iterable

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.labels import _LABEL_SPECS
from privacyguard.infrastructure.pii.address.types import AddressComponentMatch
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _ADDRESS_FIELD_KEYWORDS,
    _BUILTIN_EN_GEO_LEXICON,
    _BUILTIN_GEO_LEXICON,
    _BUILTIN_UI_BLACKLIST_EN,
    _BUILTIN_UI_BLACKLIST_ZH,
    _EN_GEO_TIER_A_STATE_PATTERN,
    _EMAIL_FIELD_KEYWORDS,
    _ID_FIELD_KEYWORDS,
    _OCR_SEMANTIC_BREAK_TOKEN,
    _PHONE_FIELD_KEYWORDS,
)

_ZH_CONNECTORS = {"", " ", ",", "，", "、", ":", "：", "-", "－", "—", "/", "#", "的"}
_EN_CONNECTORS = {"", " ", ",", ", ", "-", " - ", "#"}
_MASKED_END_RE = re.compile(r"(?:\s*(?:\.{3,}|…+|[*＊]{2,}|[xX]{2,}|某+))$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(
    r"(?:\+?1[\s\-._()]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2}|1[3-9]\d)[\s\-._()]*[0-9xX*＊]{2,4}[\s\-._()]*[0-9xX*＊]{2,4}"
)
_TIME_RE = re.compile(r"(?:[01]?\d|2[0-3])[:：][0-5]\d(?:[:：][0-5]\d)?")
_PRICE_RE = re.compile(r"(?:¥|￥|\$)\s*\d")
_ORDER_RE = re.compile(r"(?:订单号|单号|order\s*#?)", re.IGNORECASE)

_ZH_ROAD_RE = re.compile(r"[一-龥A-Za-z0-9]{2,24}(?:路|街|大道|道|巷|弄|胡同)")
_ZH_COMPOUND_RE = re.compile(r"[一-龥A-Za-z0-9]{1,28}(?:小区|公寓|大厦|园区|社区|花园|家园|苑|庭|府|湾|宿舍)")
_ZH_BUILDING_RE = re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+(?:号楼|栋|幢|座|楼)")
_ZH_UNIT_RE = re.compile(r"[0-9A-Za-z一二三四五六七八九十百零两]+单元")
_ZH_FLOOR_RE = re.compile(r"[0-9A-Za-z]+层")
_ZH_ROOM_RE = re.compile(r"[0-9A-Za-z]+(?:室|房|户)")
_ZH_POSTAL_RE = re.compile(r"\b\d{6}\b")
_ZH_STREET_ADMIN_RE = re.compile(r"(?:(?<=^)|(?<=[区县旗\s,，、:：/#-]))[一-龥A-Za-z0-9]{2,8}街道")
_ZH_TOWN_RE = re.compile(r"(?:(?<=^)|(?<=[区县旗\s,，、:：/#-]))[一-龥A-Za-z0-9]{2,8}(?:乡|镇)")
_ZH_VILLAGE_RE = re.compile(r"(?:(?<=[镇乡道区县旗\s,，、:：/#-]))[一-龥A-Za-z0-9]{2,12}(?:村|社区)")

_EN_PO_BOX_RE = re.compile(r"\bP\.?\s*O\.?\s*Box\s+\d{1,10}\b", re.IGNORECASE)
_EN_STREET_RE = re.compile(
    r"\b\d{1,6}[A-Za-z0-9\-]*\s+[A-Za-z0-9.'\- ]{1,80}?"
    r"\b(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct|place|pl|parkway|pkwy|terrace|ter|circle|cir|way|highway|hwy)\.?\b"
    r"(?:\s+(?:n|s|e|w|ne|nw|se|sw))?",
    re.IGNORECASE,
)
_EN_UNIT_RE = re.compile(
    r"(?:#\s*[A-Za-z0-9\-]+|(?:\b(?:apt|apartment|suite|ste|unit|floor|fl|room|rm)\.?\s+[A-Za-z0-9\-]+(?:\s+[A-Za-z0-9\-]+)?))",
    re.IGNORECASE,
)
_EN_FLOOR_RE = re.compile(r"\b(?:floor|fl)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE)
_EN_ROOM_RE = re.compile(r"\b(?:room|rm)\.?\s*[A-Za-z0-9\-]+\b", re.IGNORECASE)
_EN_POSTAL_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
_EN_STATE_RE = re.compile(
    r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY)\b",
    re.IGNORECASE,
)
_EN_STATE_NAME_RE = _EN_GEO_TIER_A_STATE_PATTERN
_EN_CITY_RE = re.compile(
    rf"\b(?:{'|'.join(sorted((re.escape(item) for item in (_BUILTIN_EN_GEO_LEXICON.tier_b_places | _BUILTIN_EN_GEO_LEXICON.tier_c_places)), key=len, reverse=True))})\b",
    re.IGNORECASE,
) if (_BUILTIN_EN_GEO_LEXICON.tier_b_places or _BUILTIN_EN_GEO_LEXICON.tier_c_places) else re.compile(r"(?!x)x")

_ADDRESS_LABEL_KEYWORDS = tuple(
    dict.fromkeys(
        spec.keyword
        for spec in _LABEL_SPECS
        if spec.attr_type == PIIAttributeType.ADDRESS and str(spec.keyword or "").strip()
    )
)
_LABEL_RE = re.compile(
    rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?:{'|'.join(sorted((re.escape(item) for item in _ADDRESS_LABEL_KEYWORDS), key=len, reverse=True))})\s*(?:[:：=]|是|为|is|was|at)?\s*",
    re.IGNORECASE,
)
_ALL_FIELD_KEYWORDS = tuple(
    dict.fromkeys(
        spec.keyword
        for spec in _LABEL_SPECS
        if str(spec.keyword or "").strip()
    )
)
_FIELD_KEYWORD_RE = re.compile(
    rf"(?:^|[\s{{\[\(（【<「『\"',，;；/\\|｜])(?P<label>{'|'.join(sorted((re.escape(item) for item in _ALL_FIELD_KEYWORDS), key=len, reverse=True))})(?=$|[\s:：=*_?？!！,，.。;；/\\|｜()\[\]{{}}<>《》【】\"'`·•_\-])",
    re.IGNORECASE,
)
_ZH_DIRECT_CONTROLLED_MUNICIPALITIES = frozenset({"北京", "北京市", "上海", "上海市", "天津", "天津市", "重庆", "重庆市"})
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
    break_index = text.find(_OCR_SEMANTIC_BREAK_TOKEN)
    if break_index >= 0:
        hits.append((break_index, "ocr_break"))
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


def _has_zh_keyword_expansion_match(source_text: str, match_start: int, match_end: int, matched_text: str) -> bool:
    for keyword, expansions in _BUILTIN_UI_BLACKLIST_ZH.address_keyword_expansions.items():
        if not matched_text.endswith(keyword):
            continue
        suffix_start = match_end - len(keyword)
        if not 0 <= suffix_start < len(source_text):
            continue
        tail = re.sub(r"\s+", "", source_text[suffix_start:])
        if any(tail.startswith(expansion) for expansion in expansions):
            return True
    return False


def _has_en_keyword_expansion_match(source_text: str, match_start: int, match_end: int, matched_text: str) -> bool:
    lowered_source = source_text.lower()
    lowered_text = matched_text.lower()
    for keyword, expansions in _BUILTIN_UI_BLACKLIST_EN.address_keyword_expansions.items():
        if not lowered_text.endswith(keyword):
            continue
        suffix_start = match_end - len(keyword)
        if not 0 <= suffix_start < len(source_text):
            continue
        tail = lowered_source[suffix_start:]
        if any(tail.startswith(expansion) for expansion in expansions):
            return True
    return False


def _iter_zh_components(text: str) -> Iterable[AddressComponentMatch]:
    for token in _iter_builtin_geo_tokens(text):
        yield token
    for iterator, component_type in (
        (_ZH_STREET_ADMIN_RE.finditer(text), "street_admin"),
        (_ZH_TOWN_RE.finditer(text), "town"),
        (_ZH_VILLAGE_RE.finditer(text), "village"),
        (_ZH_ROAD_RE.finditer(text), "road"),
        (_ZH_COMPOUND_RE.finditer(text), "compound"),
        (_ZH_BUILDING_RE.finditer(text), "building"),
        (_ZH_UNIT_RE.finditer(text), "unit"),
        (_ZH_FLOOR_RE.finditer(text), "floor"),
        (_ZH_ROOM_RE.finditer(text), "room"),
        (_ZH_POSTAL_RE.finditer(text), "postal_code"),
    ):
        for item in iterator:
            if _has_zh_keyword_expansion_match(text, item.start(), item.end(), item.group(0)):
                continue
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
        (_EN_STATE_NAME_RE.finditer(text), "state"),
        (_EN_CITY_RE.finditer(text), "city"),
    ):
        for item in iterator:
            if _has_en_keyword_expansion_match(text, item.start(), item.end(), item.group(0)):
                continue
            strength = "medium" if component_type == "city" else "strong"
            yield AddressComponentMatch(component_type, item.start(), item.end(), item.group(0), strength)


def _iter_builtin_geo_tokens(text: str) -> Iterable[AddressComponentMatch]:
    from privacyguard.infrastructure.pii.rule_based_detector_shared import _GEO_LEXICON_MATCHER

    # 词典可去掉“关键词后缀”，运行时再与后缀绑定成完整地名/地址组件。
    _ZH_SUFFIX_TO_TYPE = {
        "特别行政区": "province",
        "自治区": "province",
        "地区": "district",
        "大道": "road",
        "小区": "compound",
        "公寓": "compound",
        "大厦": "compound",
        "园区": "compound",
        "社区": "compound",
        "宿舍": "compound",
        "省": "province",
        "市": "city",
        "区": "district",
        "县": "district",
        "旗": "district",
        "盟": "district",
        "路": "road",
        "街": "street",
        "道": "road",
        "巷": "street",
        "弄": "street",
    }

    seen: set[tuple[int, int]] = set()
    for start, end, token in _GEO_LEXICON_MATCHER.finditer(text):
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

        # 支持“北京 市”“海淀 区”这类 OCR/分词断开：若紧随其后是行政后缀（允许空白），归并为单个地名事件。
        cursor = end
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        merged_type = component_type
        merged_end = end
        merged_text = token
        for suffix, suffix_type in sorted(_ZH_SUFFIX_TO_TYPE.items(), key=lambda item: len(item[0]), reverse=True):
            if cursor + len(suffix) <= len(text) and text[cursor : cursor + len(suffix)] == suffix:
                merged_type = suffix_type
                merged_end = cursor + len(suffix)
                merged_text = re.sub(r"\s+", "", text[start:merged_end])
                break
        yield AddressComponentMatch(merged_type, start, merged_end, merged_text, "medium")


def _dedupe_component_matches(matches: list[AddressComponentMatch]) -> list[AddressComponentMatch]:
    kept: list[AddressComponentMatch] = []
    for candidate in sorted(matches, key=lambda item: (item.start, -(item.end - item.start), item.component_type)):
        exact_index = next(
            (
                index
                for index, previous in enumerate(kept)
                if previous.start == candidate.start and previous.end == candidate.end
            ),
            None,
        )
        if exact_index is None:
            kept.append(candidate)
            continue
        previous = kept[exact_index]
        if _component_rank(candidate.component_type) >= _component_rank(previous.component_type):
            kept[exact_index] = candidate
    return sorted(kept, key=lambda item: (item.start, item.end))


def _component_rank(component_type: str) -> int:
    order = {
        "room": 9,
        "floor": 8,
        "unit": 7,
        "building": 6,
        "street": 5,
        "road": 5,
        "village": 5,
        "street_admin": 4,
        "town": 4,
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
