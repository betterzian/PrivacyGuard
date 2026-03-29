from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.key_value_canonical import (
    address_key_value_canonical_from_zh,
    has_cjk_characters,
    zh_label_address_has_parse_components,
)
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult
from privacyguard.utils.pii_value import canonicalize_pii_value


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
        if not _emit_single_private_component_allowed(detector, result):
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
            config=config,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if whole_candidate is None:
            continue
        value, span_start, span_end, emit_components = whole_candidate
        if not emit_components or not config.emit_component_candidates:
            continue
        for component in result.components:
            _emit_component_candidate(
                detector,
                collected,
                raw_text,
                (value, span_start, span_end),
                result,
                component,
                source,
                bbox,
                block_id,
                skip_spans=skip_spans,
            )


def _emit_single_private_component_allowed(detector, result: AddressParseResult) -> bool:
    """发射前 UI 黑名单：整段命中「操作/界面类」负例则不放行。

    不使用 ``_is_ui_or_commerce_location_token`` 扫整段 span：营销话术里常含「专区」等词，
    会与流划分的真实地理片段粘连；该类噪声由流侧 keyword expansion 等处理。
    """
    cleaned = detector._clean_address_candidate(result.span.text)
    if not cleaned:
        return False
    return not detector._is_ui_operation_name_token(cleaned)


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
    config: AddressParseConfig,
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> tuple[str, int, int, bool] | None:
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
    if (
        result.span.matched_by == "context_address_field"
        and config.protection_level is ProtectionLevel.STRONG
        and not detector._explicit_label_address_value_allowed(value)
    ):
        return None
    component_types = _ordered_unique(item.component_type for item in result.components)
    privacy_levels = _ordered_unique(item.privacy_level for item in result.components)
    component_trace = [f"{item.component_type}:{item.text}" for item in result.components]
    metadata = {
        "address_kind": [result.address_kind],
        "address_terminated_by": [result.span.terminated_by],
        "address_component_type": component_types,
        "address_privacy_level": privacy_levels,
        "address_component_trace": component_trace,
    }
    label_induced = result.span.matched_by == "context_address_field"
    if label_induced and not zh_label_address_has_parse_components(value) and has_cjk_characters(value):
        canonical_value = canonicalize_pii_value(PIIAttributeType.DETAILS, value)
        detector._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=value,
            attr_type=PIIAttributeType.DETAILS,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=result.confidence,
            matched_by=result.span.matched_by,
            canonical_source_text=canonical_value,
            normalized_text=canonical_value,
            metadata=metadata,
            skip_spans=skip_spans,
        )
        return value, span_start, span_end, False
    canonical_value = address_key_value_canonical_from_zh(value)
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
        canonical_source_text=canonical_value,
        normalized_text=canonical_value,
        metadata=metadata,
        skip_spans=skip_spans,
    )
    return value, span_start, span_end, True


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
    canonical_value = address_key_value_canonical_from_zh(component.text)
    detector._upsert_candidate(
        collected=collected,
        text=raw_text,
        matched_text=component.text,
        attr_type=_component_attr_type(component.component_type),
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start + component_start,
        span_end=span_start + component_end,
        confidence=max(0.0, min(result.confidence - 0.04, component.confidence)),
        matched_by=f"address_component_{component.component_type}",
        canonical_source_text=canonical_value,
        normalized_text=canonical_value,
        metadata={
            "address_kind": [result.address_kind],
            "address_component_type": [component.component_type],
            "address_privacy_level": [component.privacy_level],
            "address_match_origin": [result.span.matched_by],
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


def _component_attr_type(component_type: str) -> PIIAttributeType:
    if component_type in {"building", "unit", "floor", "room"}:
        return PIIAttributeType.DETAILS
    return PIIAttributeType.ADDRESS
