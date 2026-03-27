from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressParseConfig, AddressParseResult


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
            pass
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
    canonical_value = _canonicalize_address_components(result.components)
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
    canonical_value = _canonicalize_address_components((component,))
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
        canonical_value = _canonicalize_address_components((component,))
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
            canonical_source_text=canonical_value,
            normalized_text=canonical_value,
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


def _component_attr_type(component_type: str) -> PIIAttributeType:
    if component_type in {"building", "unit", "floor", "room"}:
        return PIIAttributeType.DETAILS
    return PIIAttributeType.ADDRESS


def _canonicalize_address_components(components: tuple[AddressComponent, ...]) -> str:
    slots: dict[str, str] = {}

    def _put(key: str, value: str) -> None:
        compact = value.strip()
        if compact and key not in slots:
            slots[key] = compact

    def _strip_suffix(text: str, suffixes: tuple[str, ...]) -> str:
        cleaned = text.strip()
        for suffix in sorted(suffixes, key=len, reverse=True):
            if cleaned.endswith(suffix) and len(cleaned) > len(suffix):
                return cleaned[: -len(suffix)]
        return cleaned

    def _normalize_component_text(text: str, ctype: str) -> str:
        if ctype in {"province", "state"}:
            return _strip_suffix(text, ("特别行政区", "自治区", "省", "市", "state", "province"))
        if ctype == "city":
            return _strip_suffix(text, ("自治州", "地区", "盟", "市", "city"))
        if ctype in {"district", "county"}:
            return _strip_suffix(text, ("自治县", "自治旗", "新区", "区", "县", "旗", "市", "county", "district"))
        if ctype in {"road", "street", "po_box"}:
            return _strip_suffix(text, ("大道", "胡同", "街", "路", "道", "巷", "弄", "street", "road", "avenue", "blvd"))
        if ctype == "compound":
            return _strip_suffix(
                text,
                (
                    "小区",
                    "社区",
                    "花园",
                    "公寓",
                    "大厦",
                    "园区",
                    "家园",
                    "苑",
                    "庭",
                    "府",
                    "湾",
                    "community",
                    "garden",
                    "apartment",
                    "apartments",
                    "residence",
                    "residences",
                    "building",
                    "tower",
                    "park",
                ),
            )
        if ctype == "poi":
            return _strip_suffix(text, ("广场", "中心", "公园", "学校", "医院", "车站", "plaza", "center", "park"))
        return text.strip()

    def _canonical_numeric(text: str) -> str:
        digits = re.findall(r"\d+", text)
        if digits:
            return "".join(digits)
        zh = _chinese_numeral_to_int(text)
        if zh is not None:
            return str(zh)
        en = _english_numeral_to_int(text)
        if en is not None:
            return str(en)
        return ""

    for component in sorted(components, key=lambda item: item.start_offset):
        ctype = component.component_type
        text = component.text
        if ctype in {"province", "state"}:
            _put("province", _normalize_component_text(text, ctype))
            continue
        if ctype == "city":
            _put("city", _normalize_component_text(text, ctype))
            continue
        if ctype in {"district", "county"}:
            _put("district", _normalize_component_text(text, ctype))
            continue
        if ctype in {"road", "street", "po_box"}:
            _put("street", _normalize_component_text(text, ctype))
            continue
        if ctype in {"compound"}:
            _put("compound", _normalize_component_text(text, ctype))
            continue
        if ctype in {"poi"}:
            _put("poi", _normalize_component_text(text, ctype))
            continue
        if ctype in {"building", "unit", "floor"}:
            _put("building", _canonical_numeric(text))
            continue
        if ctype == "room":
            _put("room", _canonical_numeric(text))
            continue
        if ctype == "postal_code":
            _put("postal", text)
            continue
        _put("detail", text)

    order = ("province", "city", "district", "street", "poi", "compound", "building", "room", "detail", "postal")
    parts = [f"{key}={slots[key]}" for key in order if key in slots]
    return "|".join(parts)


_ZH_DIGIT = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_EN_DIGIT = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
}
_EN_TEENS = {
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
}
_EN_TENS = {
    "twenty": 20,
    "thirty": 30,
    "forty": 40,
    "fifty": 50,
    "sixty": 60,
    "seventy": 70,
    "eighty": 80,
    "ninety": 90,
}


def _chinese_numeral_to_int(text: str) -> int | None:
    chars = [ch for ch in text if ch in _ZH_DIGIT or ch in {"十", "百", "千"}]
    if not chars:
        return None
    compact = "".join(chars)
    if all(ch in _ZH_DIGIT for ch in compact):
        return int("".join(str(_ZH_DIGIT[ch]) for ch in compact))
    total = 0
    section = 0
    number = 0
    unit_map = {"十": 10, "百": 100, "千": 1000}
    for ch in compact:
        if ch in _ZH_DIGIT:
            number = _ZH_DIGIT[ch]
            continue
        unit = unit_map.get(ch)
        if unit is None:
            continue
        if number == 0:
            number = 1
        section += number * unit
        number = 0
    total += section + number
    return total if total > 0 else None


def _english_numeral_to_int(text: str) -> int | None:
    tokens = [tok for tok in re.split(r"[^A-Za-z]+", text.lower()) if tok]
    if not tokens:
        return None
    if all(tok in _EN_DIGIT for tok in tokens):
        return int("".join(str(_EN_DIGIT[tok]) for tok in tokens))
    value = 0
    current = 0
    seen = False
    for tok in tokens:
        if tok in _EN_DIGIT:
            current += _EN_DIGIT[tok]
            seen = True
            continue
        if tok in _EN_TEENS:
            current += _EN_TEENS[tok]
            seen = True
            continue
        if tok in _EN_TENS:
            current += _EN_TENS[tok]
            seen = True
            continue
        if tok == "hundred":
            current = max(1, current) * 100
            seen = True
            continue
        if tok == "thousand":
            value += max(1, current) * 1000
            current = 0
            seen = True
            continue
        return None
    result = value + current
    return result if seen and result >= 0 else None
