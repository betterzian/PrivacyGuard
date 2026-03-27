from __future__ import annotations

from privacyguard.infrastructure.pii.address.component_parser_en import parse_en_components
from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.pii.address.types import AddressComponentMatch, AddressInput


def collect_component_matches(address_input: AddressInput, *, locale_profile: str) -> tuple[AddressComponentMatch, ...]:
    return tuple(_seed_components(address_input.text, locale_profile=locale_profile))


def _seed_components(text: str, *, locale_profile: str):
    if any("\u4e00" <= char <= "\u9fff" for char in text) or locale_profile == "zh_cn":
        for component in parse_zh_components(text):
            yield AddressComponentMatch(
                component_type=component.component_type,
                start=component.start_offset,
                end=component.end_offset,
                text=component.text,
            )
        return
    for component in parse_en_components(text):
        yield AddressComponentMatch(
            component_type=component.component_type,
            start=component.start_offset,
            end=component.end_offset,
            text=component.text,
        )
