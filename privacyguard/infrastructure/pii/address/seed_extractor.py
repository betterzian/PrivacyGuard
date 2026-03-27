from __future__ import annotations

from privacyguard.infrastructure.pii.address.lexicon import build_label_pattern
from privacyguard.infrastructure.pii.address.component_parser_en import parse_en_components
from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.pii.address.types import AddressComponentMatch, AddressInput, AddressSeed


def collect_component_matches(address_input: AddressInput, *, locale_profile: str) -> tuple[AddressComponentMatch, ...]:
    return tuple(_seed_components(address_input.text, locale_profile=locale_profile))


def extract_seeds(
    address_input: AddressInput,
    *,
    locale_profile: str,
    component_matches: tuple[AddressComponentMatch, ...] | None = None,
) -> tuple[AddressSeed, ...]:
    text = address_input.text
    seeds: list[AddressSeed] = []
    for match in build_label_pattern().finditer(text):
        seeds.append(
            AddressSeed(
                start=match.end(),
                end=match.end(),
                seed_type="label_value",
                matched_by="context_address_field",
                confidence=0.9,
            )
        )
    candidates = component_matches if component_matches is not None else tuple(_seed_components(text, locale_profile=locale_profile))
    for component in candidates:
        seeds.append(
            AddressSeed(
                start=component.start,
                end=component.end,
                seed_type=component.component_type,
                matched_by=f"address_seed_{component.component_type}",
                confidence=_seed_confidence(component.component_type),
            )
        )
    return tuple(_dedupe_seeds(seeds))


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


def _dedupe_seeds(seeds: list[AddressSeed]) -> list[AddressSeed]:
    deduped: dict[tuple[int, int, str], AddressSeed] = {}
    for seed in seeds:
        key = (seed.start, seed.end, seed.seed_type)
        previous = deduped.get(key)
        if previous is None or seed.confidence > previous.confidence:
            deduped[key] = seed
    return sorted(deduped.values(), key=lambda item: (item.start, item.end, -item.confidence))


def _seed_confidence(seed_type: str) -> float:
    return {
        "province": 0.72,
        "city": 0.74,
        "road": 0.8,
        "street": 0.84,
        "compound": 0.82,
        "street_admin": 0.76,
        "town": 0.76,
        "village": 0.74,
        "building": 0.84,
        "unit": 0.82,
        "floor": 0.8,
        "room": 0.84,
        "postal_code": 0.72,
        "po_box": 0.88,
        "district": 0.76,
        "poi": 0.74,
    }.get(seed_type, 0.74)
