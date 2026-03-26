from __future__ import annotations

from privacyguard.infrastructure.pii.address.component_parser_en import parse_en_components
from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.pii.address.lexicon import organization_suffix_tokens, public_place_suffixes
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult, AddressSpan

_ZH_FINE_COMPOUND_SUFFIXES = ("小区", "公寓", "大厦", "社区", "宿舍", "花园", "家园")


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
    has_fine = any(component.privacy_level == "fine" for component in components)
    has_street = "road" in component_types or "street" in component_types
    has_locality = bool(component_types & {"province", "state", "city", "district", "postal_code"})
    has_explicit_label = span.matched_by == "context_address_field"
    has_po_box = "po_box" in component_types
    residential_compound = any(
        component.component_type == "compound" and component.text.endswith(_ZH_FINE_COMPOUND_SUFFIXES)
        for component in components
    )
    public_place = any(lowered.endswith(token) for token in public_place_suffixes())
    organization_like = any(token in lowered for token in organization_suffix_tokens())

    if has_po_box or has_fine:
        return "private_address"
    if has_explicit_label and (has_street or has_locality or residential_compound):
        return "private_address"
    if has_street and (has_locality or _has_numbered_street(text)):
        return "private_address"
    if residential_compound and (has_locality or has_street):
        return "private_address"
    if organization_like and not has_locality and not has_street:
        return "organization_like"
    if public_place or (span.terminated_by == "soft_stop" and not has_fine and not has_explicit_label):
        return "public_place"
    if has_locality and (has_street or residential_compound):
        return "private_address"
    return "unknown"


def _result_confidence(span: AddressSpan, components: tuple[AddressComponent, ...], kind: str) -> float:
    confidence = span.confidence
    if kind == "private_address":
        if any(component.privacy_level == "fine" for component in components):
            confidence += 0.04
        elif len(components) >= 2:
            confidence += 0.02
    elif kind == "public_place":
        confidence -= 0.18
    elif kind == "organization_like":
        confidence -= 0.22
    else:
        confidence -= 0.08
    return max(0.0, min(0.97, confidence))


def _has_numbered_street(text: str) -> bool:
    stripped = text.lstrip()
    return bool(stripped) and stripped[0].isdigit()


def _dedupe_results(results: list[AddressParseResult]) -> list[AddressParseResult]:
    deduped: dict[tuple[int, int], AddressParseResult] = {}
    for result in results:
        key = (result.span.start, result.span.end)
        previous = deduped.get(key)
        if previous is None or result.confidence > previous.confidence:
            deduped[key] = result
    return sorted(deduped.values(), key=lambda item: (item.span.start, item.span.end))
