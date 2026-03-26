from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.lexicon import iter_address_components
from privacyguard.infrastructure.pii.address.types import AddressComponent


def parse_en_components(text: str) -> tuple[AddressComponent, ...]:
    components: list[AddressComponent] = []
    street_match = None
    unit_match = None
    postal_match = None
    state_match = None
    for match in iter_address_components(text, locale_profile="en_us"):
        if match.component_type == "street" and street_match is None:
            street_match = match
        elif match.component_type == "unit" and unit_match is None:
            unit_match = match
        elif match.component_type == "postal_code" and postal_match is None:
            postal_match = match
        elif match.component_type == "state" and state_match is None:
            state_match = match
        elif match.component_type == "po_box":
            components.append(_component("po_box", match.text, match.start, match.end, "medium", 0.9))
    if street_match is not None:
        components.append(_component("street", street_match.text, street_match.start, street_match.end, "medium", 0.9))
    if unit_match is not None:
        kind = "floor" if re.match(r"(?i)(floor|fl)\b", unit_match.text) else "unit"
        components.append(_component(kind, unit_match.text, unit_match.start, unit_match.end, "fine", 0.88))
    if state_match is not None:
        components.append(_component("state", state_match.text, state_match.start, state_match.end, "coarse", 0.82))
    if postal_match is not None:
        components.append(_component("postal_code", postal_match.text, postal_match.start, postal_match.end, "medium", 0.84))
    city_component = _city_component(text, components)
    if city_component is not None:
        components.append(city_component)
    return tuple(sorted(components, key=lambda item: (item.start_offset, item.end_offset)))


def _city_component(text: str, components: list[AddressComponent]) -> AddressComponent | None:
    trailing = sorted(
        (item.start_offset, item.end_offset)
        for item in components
        if item.component_type in {"state", "postal_code"}
    )
    leading = sorted(
        (item.start_offset, item.end_offset)
        for item in components
        if item.component_type in {"street", "unit", "floor", "room", "po_box"}
    )
    if not trailing:
        return None
    start = max((end for _, end in leading), default=0)
    end = min(start_offset for start_offset, _ in trailing)
    if end <= start:
        return None
    candidate = text[start:end].strip(" ,")
    if not candidate:
        return None
    match = re.search(r"[A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+){0,3}", candidate)
    if match is None:
        return None
    return _component("city", match.group(0), start + match.start(), start + match.end(), "coarse", 0.8)


def _component(component_type: str, text: str, start: int, end: int, privacy_level: str, confidence: float) -> AddressComponent:
    return AddressComponent(
        component_type=component_type,
        text=text,
        start_offset=start,
        end_offset=end,
        privacy_level=privacy_level,
        confidence=confidence,
    )
