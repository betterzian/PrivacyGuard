from __future__ import annotations

from privacyguard.infrastructure.pii.address.component_parser_en import parse_en_components
from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.pii.address.lexicon import (
    allow_explicit_label_address_value,
    allow_single_component_address,
    organization_suffix_tokens,
    public_place_suffixes,
)
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult, AddressSpan

_ZH_FINE_COMPOUND_SUFFIXES = ("小区", "公寓", "大厦", "社区", "宿舍", "花园", "家园")
_ZH_COMPONENT_GROUP_ORDER = {
    "country": 0,
    "province": 1,
    "state": 1,
    "city": 2,
    "district": 3,
    "county": 3,
    "street_admin": 4,
    "town": 4,
    "village": 5,
    "street": 6,
    "road": 6,
    "compound": 7,
    "poi": 7,
    "building": 8,
    "unit": 8,
    "floor": 8,
    "room": 8,
    "postal_code": 9,
    "po_box": 9,
}
_EN_COMPONENT_GROUP_ORDER = {
    "country": 4,
    "po_box": 1,
    "street": 1,
    "road": 1,
    "compound": 1,
    "poi": 1,
    "building": 1,
    "unit": 1,
    "floor": 1,
    "room": 1,
    "city": 2,
    "district": 2,
    "county": 2,
    "state": 3,
    "province": 3,
    "postal_code": 4,
}


def classify_spans(
    spans: tuple[AddressSpan, ...],
    *,
    locale_profile: str,
    config: AddressParseConfig,
) -> tuple[AddressParseResult, ...]:
    results: list[AddressParseResult] = []
    for span in spans:
        components = _parse_components(span.text, locale_profile=locale_profile)
        kind = _classify_address_kind(span, components)
        confidence = _result_confidence(span, components, kind)
        if confidence < config.min_confidence:
            continue
        results.append(
            AddressParseResult(
                span=span,
                components=components,
                address_kind=kind,
                confidence=confidence,
            )
        )
    return tuple(_dedupe_results(results))


def _parse_components(text: str, *, locale_profile: str) -> tuple[AddressComponent, ...]:
    if any("\u4e00" <= char <= "\u9fff" for char in text):
        return parse_zh_components(text)
    if locale_profile == "zh_cn":
        return parse_zh_components(text)
    return parse_en_components(text)


def _classify_address_kind(span: AddressSpan, components: tuple[AddressComponent, ...]) -> str:
    text = span.text.strip()
    lowered = text.lower()
    component_types = {component.component_type for component in components}
    organization_like = any(token in lowered for token in organization_suffix_tokens())
    has_explicit_label = span.matched_by == "context_address_field"
    address_like_types = {
        "country",
        "province",
        "city",
        "district",
        "county",
        "street_admin",
        "town",
        "village",
        "street",
        "road",
        "compound",
        "building",
        "unit",
        "floor",
        "room",
        "postal_code",
        "po_box",
        "state",
    }
    if components:
        if len(components) >= 2 and not _components_follow_expected_order(text, components):
            return "unknown"
        if len(components) == 1 and not allow_single_component_address(
            components[0].component_type,
            components[0].text,
            matched_by=span.matched_by,
            source_text=text,
        ):
            return "unknown"
        if organization_like and not any(item in component_types for item in address_like_types - {"compound"}):
            return "organization_like"
        return "private_address"
    if has_explicit_label and allow_explicit_label_address_value(text):
        return "private_address"
    if text and any(lowered.endswith(token) for token in public_place_suffixes()):
        return "private_address"
    return "unknown"


def _result_confidence(span: AddressSpan, components: tuple[AddressComponent, ...], kind: str) -> float:
    confidence = span.confidence
    if kind == "private_address":
        if any(component.privacy_level == "fine" for component in components):
            confidence += 0.04
        elif len(components) >= 2:
            confidence += 0.02
    elif kind == "organization_like":
        confidence -= 0.22
    else:
        confidence -= 0.02
    return max(0.0, min(0.97, confidence))


def _components_follow_expected_order(text: str, components: tuple[AddressComponent, ...]) -> bool:
    group_order = _ZH_COMPONENT_GROUP_ORDER if any("\u4e00" <= char <= "\u9fff" for char in text) else _EN_COMPONENT_GROUP_ORDER
    ordered_groups = [
        group_order.get(component.component_type)
        for component in components
        if group_order.get(component.component_type) is not None
    ]
    if len(ordered_groups) < 2:
        return True
    previous = ordered_groups[0]
    for current in ordered_groups[1:]:
        if current < previous:
            return False
        previous = current
    return True


def _dedupe_results(results: list[AddressParseResult]) -> list[AddressParseResult]:
    deduped: dict[tuple[int, int], AddressParseResult] = {}
    for result in results:
        key = (result.span.start, result.span.end)
        previous = deduped.get(key)
        if previous is None or result.confidence > previous.confidence:
            deduped[key] = result
    ordered = sorted(
        deduped.values(),
        key=lambda item: (-(item.span.end - item.span.start), -item.confidence, item.span.start, item.span.end),
    )
    kept: list[AddressParseResult] = []
    for result in ordered:
        result_types = {component.component_type for component in result.components}
        if any(
            other.span.start <= result.span.start
            and other.span.end >= result.span.end
            and result_types.issubset({component.component_type for component in other.components})
            for other in kept
        ):
            continue
        kept.append(result)
    return sorted(kept, key=lambda item: (item.span.start, item.span.end))
