from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.lexicon import (
    _ZH_DIRECT_CONTROLLED_MUNICIPALITIES,
    _ZH_BUILDING_RE,
    _ZH_COMPOUND_RE,
    _ZH_FLOOR_RE,
    _ZH_POSTAL_RE,
    _ZH_ROAD_RE,
    _ZH_ROOM_RE,
    _ZH_STREET_ADMIN_RE,
    _ZH_TOWN_RE,
    _ZH_UNIT_RE,
    _ZH_VILLAGE_RE,
    _has_zh_keyword_expansion_match,
    _iter_builtin_geo_tokens,
)
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressComponentMatch

# 向「区」左合并政区名时不在此停：已占用的字符、非汉字、空白会自然截断。
_QU_LEFT_EXTEND_STOP_CHARS = frozenset("在于是的地从向至往及与")

_ZH_COMPONENT_ORDER = {
    "province": 1,
    "city": 2,
    "district": 3,
    "street_admin": 4,
    "town": 4,
    "village": 5,
    "street": 6,
    "road": 6,
    "compound": 7,
    "poi": 7,
    "building": 8,
    "unit": 9,
    "floor": 10,
    "room": 11,
    "postal_code": 12,
}


def parse_zh_components(text: str) -> tuple[AddressComponent, ...]:
    matches = [_normalize_match(match) for match in _iter_raw_zh_matches(text)]
    matches = _collapse_adjacent_admin_duplicates(matches)
    matches = _dedupe_overlapping_matches(matches)
    matches = _append_unmatched_zh_qu_as_district(matches, text)
    components = [
        AddressComponent(
            component_type=match.component_type,
            text=match.text,
            start_offset=match.start,
            end_offset=match.end,
            privacy_level=_privacy_level(match.component_type, match.text),
            confidence=0.9 if match.strength == "strong" else 0.82,
        )
        for match in matches
    ]
    return tuple(sorted(components, key=lambda item: (item.start_offset, item.end_offset, item.component_type)))


def _append_unmatched_zh_qu_as_district(matches: list[AddressComponentMatch], text: str) -> list[AddressComponentMatch]:
    """在 geo 与其它规则之后：凡未被覆盖的「区」，连同其左侧连续的未占用汉字合为一项 district（词表不全时的政区后缀）。"""
    if not text:
        return matches

    def is_occupied(idx: int) -> bool:
        return any(m.start <= idx < m.end for m in matches)

    extra: list[AddressComponentMatch] = []
    for i, ch in enumerate(text):
        if ch != "区":
            continue
        if is_occupied(i):
            continue
        start = i
        j = i - 1
        while j >= 0 and not is_occupied(j):
            cj = text[j]
            if not ("\u4e00" <= cj <= "\u9fff"):
                break
            if cj in _QU_LEFT_EXTEND_STOP_CHARS:
                break
            start = j
            j -= 1
        extra.append(AddressComponentMatch("district", start, i + 1, text[start : i + 1], "medium"))
    if not extra:
        return matches
    combined = matches + extra
    combined.sort(key=lambda item: (item.start, item.end, item.component_type))
    return combined


def _iter_raw_zh_matches(text: str) -> list[AddressComponentMatch]:
    matches: list[AddressComponentMatch] = list(_iter_builtin_geo_tokens(text))
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
            matches.append(AddressComponentMatch(component_type, item.start(), item.end(), item.group(0), "strong"))
    return sorted(matches, key=lambda item: (item.start, item.end, item.component_type))


def _normalize_match(match: AddressComponentMatch) -> AddressComponentMatch:
    component_type = match.component_type
    start = match.start
    text = match.text
    if component_type == "province" and text in _ZH_DIRECT_CONTROLLED_MUNICIPALITIES:
        component_type = "city"
    if component_type == "road" and text.endswith("街"):
        component_type = "street"
    text, start = _trim_embedded_admin_prefix(component_type, text, start)
    if component_type == "compound" and text.startswith("的"):
        text = text[1:]
        start += 1
    return AddressComponentMatch(
        component_type=component_type,
        start=start,
        end=start + len(text),
        text=text,
        strength=match.strength,
    )


def _trim_embedded_admin_prefix(component_type: str, text: str, start: int) -> tuple[str, int]:
    patterns = {
        "street_admin": r"(?:.*(?:省|市|区|县|旗|盟|地区))(?P<tail>[一-龥A-Za-z0-9]{2,8}街道)$",
        "town": r"(?:.*(?:省|市|区|县|旗|盟|地区|街道))(?P<tail>[一-龥A-Za-z0-9]{2,8}(?:乡|镇))$",
        "village": r"(?:.*(?:区|县|旗|镇|乡|街道))(?P<tail>[一-龥A-Za-z0-9]{2,12}(?:村|社区))$",
        "street": r"(?:.*(?:省|市|区|县|旗|镇|乡|街道|的))(?P<tail>[一-龥A-Za-z0-9]{2,24}街)$",
        "road": r"(?:.*(?:省|市|区|县|旗|镇|乡|街道|的))(?P<tail>[一-龥A-Za-z0-9]{2,24}(?:路|大道|道|巷|弄|胡同))$",
        "compound": r"(?:.*(?:省|市|区|县|旗|镇|乡|街道|村|社区|路|街|大道|道|巷|弄|胡同|的))(?P<tail>[一-龥A-Za-z0-9]{1,20}(?:小区|公寓|大厦|园区|社区|花园|家园|苑|庭|府|湾|宿舍))$",
    }
    pattern = patterns.get(component_type)
    if pattern is None:
        return text, start
    match = re.match(pattern, text)
    if match is None:
        return text, start
    tail = match.group("tail")
    relative_start = text.rfind(tail)
    if relative_start < 0:
        return text, start
    return tail, start + relative_start


def _collapse_adjacent_admin_duplicates(matches: list[AddressComponentMatch]) -> list[AddressComponentMatch]:
    collapsed: list[AddressComponentMatch] = []
    for match in sorted(matches, key=lambda item: (item.start, item.end, item.component_type)):
        if not collapsed:
            collapsed.append(match)
            continue
        previous = collapsed[-1]
        if not _is_admin_component(previous.component_type) or not _is_admin_component(match.component_type):
            collapsed.append(match)
            continue
        previous_key = (_normalized_admin_type(previous.component_type), _canonical_admin_token(previous.text))
        current_key = (_normalized_admin_type(match.component_type), _canonical_admin_token(match.text))
        if previous_key != current_key:
            collapsed.append(match)
            continue
        if match.start <= previous.end:
            collapsed[-1] = _prefer_longer_admin(previous, match)
            continue
        gap_text = _between_text_gap(previous, match, matches)
        if gap_text == "":
            collapsed[-1] = _prefer_longer_admin(previous, match)
            continue
        collapsed.append(match)
    return collapsed


def _between_text_gap(
    previous: AddressComponentMatch,
    current: AddressComponentMatch,
    matches: list[AddressComponentMatch],
) -> str:
    if current.start <= previous.end:
        return ""
    # The parser only needs to know whether the OCR split introduced whitespace/punctuation.
    # When there is a true content gap, keep both components.
    return "" if current.start == previous.end else "_"


def _prefer_longer_admin(left: AddressComponentMatch, right: AddressComponentMatch) -> AddressComponentMatch:
    if (right.end - right.start) > (left.end - left.start):
        return right
    return left


def _dedupe_overlapping_matches(matches: list[AddressComponentMatch]) -> list[AddressComponentMatch]:
    kept: list[AddressComponentMatch] = []
    for candidate in sorted(matches, key=lambda item: (item.start, item.end, _component_priority(item.component_type))):
        if not kept:
            kept.append(candidate)
            continue
        previous = kept[-1]
        if candidate.start >= previous.end:
            kept.append(candidate)
            continue
        if candidate.start == previous.start and candidate.end == previous.end:
            if _component_priority(candidate.component_type) >= _component_priority(previous.component_type):
                kept[-1] = candidate
            continue
        if _component_priority(candidate.component_type) > _component_priority(previous.component_type):
            kept[-1] = candidate
    return kept


def _canonical_admin_token(text: str) -> str:
    compact = text.replace("特别行政区", "").replace("自治区", "").replace("自治州", "")
    compact = re.sub(r"(?:省|市|区|县|旗|盟|地区|街道|乡|镇|村|社区)$", "", compact)
    return compact


def _normalized_admin_type(component_type: str) -> str:
    if component_type in {"street_admin", "town", "village"}:
        return component_type
    if component_type in {"province", "city", "district"}:
        return component_type
    return component_type


def _is_admin_component(component_type: str) -> bool:
    return component_type in {"province", "city", "district", "street_admin", "town", "village"}


def _component_priority(component_type: str) -> int:
    return _ZH_COMPONENT_ORDER.get(component_type, 0)


def _privacy_level(component_type: str, text: str) -> str:
    if component_type in {"building", "unit", "floor", "room"}:
        return "fine"
    if component_type == "compound" and text.endswith(("小区", "公寓", "大厦", "宿舍", "社区", "花园", "家园", "苑", "庭", "府", "湾")):
        return "fine"
    if component_type in {"street", "road", "district", "town", "street_admin", "village", "poi", "postal_code"}:
        return "medium"
    return "coarse"
