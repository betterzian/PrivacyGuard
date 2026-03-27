from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult
from privacyguard.domain.enums import ProtectionLevel


def emit_candidates(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    parse_results: tuple[AddressParseResult, ...],
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    config: AddressParseConfig,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    for result in parse_results:
        if result.address_kind == "organization_like":
            if config.emit_location_candidates:
                _emit_location_components(
                    detector,
                    collected,
                    raw_text,
                    result,
                    source,
                    bbox,
                    block_id,
                    skip_spans=skip_spans,
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
            continue
        if not _should_emit_whole_address(result, config=config):
            continue
        whole_candidate = _emit_whole_address_candidate(
            detector,
            collected,
            raw_text,
            result,
            source,
            bbox,
            block_id,
            skip_spans=skip_spans,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if whole_candidate is None or not config.emit_component_candidates:
            continue
        for component in result.components:
            _emit_component_candidate(
                detector,
                collected,
                raw_text,
                whole_candidate,
                result,
                component,
                source,
                bbox,
                block_id,
                skip_spans=skip_spans,
            )


def _should_emit_whole_address(result: AddressParseResult, *, config: AddressParseConfig) -> bool:
    if result.address_kind == "unknown":
        return False
    if len(result.components) == 1:
        single = result.components[0]
        if result.span.matched_by != "context_address_field" and single.component_type in {"province", "city", "district", "county", "state"}:
            # 单省/市/区作为“单独地址”的放行由 ProtectionLevel 控制：
            # - STRONG：允许 province/city/district/state/county
            # - BALANCED：允许 city/district（其余拒绝）
            # - WEAK：仅允许字段语境（上面已排除）
            if config.protection_level == ProtectionLevel.STRONG:
                pass
            elif config.protection_level == ProtectionLevel.BALANCED:
                if single.component_type not in {"city", "district"}:
                    return False
            else:
                return False
        if (
            result.span.matched_by != "context_address_field"
            and single.component_type == "compound"
            and single.privacy_level != "fine"
        ):
            return False
    if result.address_kind == "private_address":
        if result.span.matched_by != "context_address_field" and result.components and all(
            component.privacy_level == "coarse" for component in result.components
        ):
            return False
        return True
    if result.span.matched_by == "context_address_field" and (len(result.components) >= 1 or len(result.span.text.strip()) >= 2):
        return True
    if any(component.component_type in {"street", "road", "compound"} for component in result.components) and len(result.components) >= 2:
        return True
    return False


def _emit_whole_address_candidate(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    result: AddressParseResult,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> tuple[str, int, int] | None:
    extracted = detector._extract_match(
        raw_text,
        result.span.start,
        result.span.end,
        cleaner=detector._clean_address_candidate,
        original_text=original_text,
        shadow_index_map=shadow_index_map,
    )
    if extracted is None:
        return None
    value, span_start, span_end = extracted
    component_types = _ordered_unique(component.component_type for component in result.components)
    privacy_levels = _ordered_unique(component.privacy_level for component in result.components)
    component_trace = [f"{component.component_type}:{component.text}" for component in result.components]
    metadata = {
        "address_kind": [result.address_kind],
        "address_terminated_by": [result.span.terminated_by],
        "address_component_type": component_types,
        "address_privacy_level": privacy_levels,
        "address_component_trace": component_trace,
    }
    detector._upsert_candidate(
        collected=collected,
        text=raw_text,
        matched_text=value,
        attr_type=PIIAttributeType.ADDRESS,
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start,
        span_end=span_end,
        confidence=result.confidence,
        matched_by=result.span.matched_by,
        metadata=metadata,
        skip_spans=skip_spans,
    )
    return value, span_start, span_end


def _emit_component_candidate(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    whole_candidate: tuple[str, int, int],
    result: AddressParseResult,
    component: AddressComponent,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
) -> None:
    value, span_start, span_end = whole_candidate
    component_start = _component_start_offset(value, component)
    if component_start is None:
        return
    component_end = component_start + len(component.text)
    if component_end > len(value):
        return
    detector._upsert_candidate(
        collected=collected,
        text=raw_text,
        matched_text=component.text,
        attr_type=PIIAttributeType.ADDRESS,
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start + component_start,
        span_end=span_start + component_end,
        confidence=max(0.0, min(result.confidence - 0.04, component.confidence)),
        matched_by=f"address_component_{component.component_type}",
        metadata={
            "address_kind": [result.address_kind],
            "address_component_type": [component.component_type],
            "address_privacy_level": [component.privacy_level],
            "address_match_origin": [result.span.matched_by],
            "address_component_trace": [f"{component.component_type}:{component.text}"],
        },
        skip_spans=skip_spans,
    )


def _emit_location_components(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    result: AddressParseResult,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> None:
    for component in result.components:
        if component.privacy_level == "fine":
            continue
        extracted = detector._extract_match(
            raw_text,
            result.span.start + component.start_offset,
            result.span.start + component.end_offset,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if extracted is None:
            continue
        value, span_start, span_end = extracted
        detector._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=value,
            attr_type=PIIAttributeType.ADDRESS,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=max(0.0, min(result.confidence - 0.08, component.confidence)),
            matched_by=f"address_component_{component.component_type}",
            metadata={
                "address_kind": [result.address_kind],
                "address_component_type": [component.component_type],
                "address_privacy_level": [component.privacy_level],
                "address_component_trace": [f"{component.component_type}:{component.text}"],
            },
            skip_spans=skip_spans,
        )


def _component_start_offset(value: str, component: AddressComponent) -> int | None:
    direct_start = component.start_offset
    direct_end = component.end_offset
    if 0 <= direct_start < direct_end <= len(value) and value[direct_start:direct_end] == component.text:
        return direct_start
    lowered_value = value.lower()
    lowered_component = component.text.lower()
    index = lowered_value.find(lowered_component)
    if index >= 0:
        return index
    return None


def _ordered_unique(values) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
