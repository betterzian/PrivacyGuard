from __future__ import annotations

from privacyguard.infrastructure.pii.address.lexicon import build_label_pattern, iter_address_components
from privacyguard.infrastructure.pii.address.types import AddressInput, AddressSeed


def extract_seeds(address_input: AddressInput, *, locale_profile: str) -> tuple[AddressSeed, ...]:
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
    for component in iter_address_components(text, locale_profile=locale_profile):
        if component.component_type in {"province", "city"}:
            continue
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
        "road": 0.8,
        "street": 0.84,
        "compound": 0.82,
        "building": 0.84,
        "unit": 0.82,
        "floor": 0.8,
        "room": 0.84,
        "postal_code": 0.72,
        "po_box": 0.88,
        "district": 0.76,
        "poi": 0.74,
    }.get(seed_type, 0.74)
