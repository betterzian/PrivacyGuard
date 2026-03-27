from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.lexicon import iter_address_components
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressComponentMatch

_EN_COMPONENT_ORDER = {
    "country": 1,
    "po_box": 2,
    "street": 3,
    "road": 3,
    "city": 4,
    "district": 4,
    "county": 4,
    "state": 5,
    "postal_code": 6,
    "unit": 7,
    "floor": 8,
    "room": 9,
}


def parse_en_components(text: str) -> tuple[AddressComponent, ...]:
    matches = [_normalize_match(match) for match in iter_address_components(text, locale_profile="en_us")]
    matches = _dedupe_overlaps(matches)
    components = [
        AddressComponent(
            component_type=match.component_type,
            text=match.text,
            start_offset=match.start,
            end_offset=match.end,
            privacy_level=_privacy_level(match.component_type),
            confidence=0.9 if match.strength == "strong" else 0.82,
        )
        for match in matches
    ]
    return tuple(sorted(components, key=lambda item: (item.start_offset, item.end_offset, item.component_type)))


def _normalize_match(match: AddressComponentMatch) -> AddressComponentMatch:
    component_type = match.component_type
    if component_type == "unit" and re.match(r"(?i)(floor|fl)\b", match.text):
        component_type = "floor"
    elif component_type == "unit" and re.match(r"(?i)(room|rm)\b", match.text):
        component_type = "room"
    return AddressComponentMatch(
        component_type=component_type,
        start=match.start,
        end=match.end,
        text=match.text,
        strength=match.strength,
    )


def _dedupe_overlaps(matches: list[AddressComponentMatch]) -> list[AddressComponentMatch]:
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


def _component_priority(component_type: str) -> int:
    return _EN_COMPONENT_ORDER.get(component_type, 0)


def _privacy_level(component_type: str) -> str:
    if component_type in {"unit", "floor", "room"}:
        return "fine"
    if component_type in {"street", "road", "postal_code", "city", "district", "county"}:
        return "medium"
    return "coarse"
