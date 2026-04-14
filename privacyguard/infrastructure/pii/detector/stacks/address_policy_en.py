"""英文地址 stack 的专用规则。

这里仅保留英文 grammar 需要的能力：
1. 英文 KEY 左扩。
2. prefix-key（如 `Apt` / `#`）判定。
3. 英文 HARD clue 子分词。
4. 英文组件后继图。
"""

from __future__ import annotations

import re

from privacyguard.infrastructure.pii.detector.lexicon_loader import load_en_address_keyword_groups
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueFamily,
    ClueRole,
    PIIAttributeType,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _normalize_address_value,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _char_span_to_unit_span, _unit_index_left_of

EN_VALID_SUCCESSORS: dict[AddressComponentType, frozenset[AddressComponentType]] = {
    AddressComponentType.COUNTRY: frozenset(),
    AddressComponentType.PROVINCE: frozenset({
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.DETAIL,
        AddressComponentType.BUILDING,
    }),
    AddressComponentType.CITY: frozenset({
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.DETAIL,
        AddressComponentType.BUILDING,
    }),
    AddressComponentType.DISTRICT: frozenset({
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.DETAIL,
        AddressComponentType.BUILDING,
    }),
    AddressComponentType.SUBDISTRICT: frozenset({
        AddressComponentType.ROAD,
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.DETAIL,
        AddressComponentType.BUILDING,
    }),
    AddressComponentType.HOUSE_NUMBER: frozenset({
        AddressComponentType.ROAD,
    }),
    AddressComponentType.ROAD: frozenset({
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.POI,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.NUMBER: frozenset({
        AddressComponentType.ROAD,
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.POI: frozenset({
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.BUILDING: frozenset({
        AddressComponentType.HOUSE_NUMBER,
        AddressComponentType.ROAD,
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.ROAD,
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.DETAIL: frozenset({
        AddressComponentType.HOUSE_NUMBER,
        AddressComponentType.ROAD,
        AddressComponentType.CITY,
        AddressComponentType.PROVINCE,
        AddressComponentType.POSTAL_CODE,
        AddressComponentType.COUNTRY,
        AddressComponentType.BUILDING,
        AddressComponentType.DETAIL,
    }),
    AddressComponentType.POSTAL_CODE: frozenset({
        AddressComponentType.COUNTRY,
    }),
}


def _en_prefix_keywords() -> set[str]:
    keywords: set[str] = set()
    for group in load_en_address_keyword_groups():
        if group.component_type not in {AddressComponentType.DETAIL, AddressComponentType.BUILDING}:
            continue
        for entry in group.entries:
            text = entry.text.strip().lower()
            if text:
                keywords.add(text)
    keywords.add("#")
    return keywords


_PREFIX_EN_KEYWORDS = _en_prefix_keywords()
_EN_PREFIX_COMPONENTS = frozenset({AddressComponentType.DETAIL, AddressComponentType.BUILDING})
_EN_SUFFIX_COMPONENTS = frozenset({AddressComponentType.ROAD, AddressComponentType.POI})
_DIRECTIONAL_TOKENS = frozenset({"n", "s", "e", "w", "ne", "nw", "se", "sw"})
_ORDINAL_TOKEN_RE = re.compile(r"\d+(?:st|nd|rd|th)$", re.IGNORECASE)


def is_prefix_en_key(text: str) -> bool:
    """判断英文 KEY 是否属于 prefix-key。"""
    return str(text or "").strip().lower() in _PREFIX_EN_KEYWORDS


def is_prefix_en_component(component_type: AddressComponentType | None) -> bool:
    return component_type in _EN_PREFIX_COMPONENTS


def is_suffix_en_component(component_type: AddressComponentType | None) -> bool:
    return component_type in _EN_SUFFIX_COMPONENTS


def en_key_chain_allowed(
    previous_type: AddressComponentType | None,
    current_type: AddressComponentType | None,
) -> bool:
    """英文 KEY -> KEY 连缀规则。"""
    if previous_type is None or current_type is None:
        return False
    if is_prefix_en_component(previous_type) and is_prefix_en_component(current_type):
        return True
    if is_suffix_en_component(previous_type) and is_suffix_en_component(current_type):
        return True
    return False


def _left_expand_en_phrase(pos: int, floor: int, stream: StreamInput) -> int:
    """英文左扩：允许跨空格，把连续英数短语整体并入。"""
    cursor = pos
    left_ui = _unit_index_left_of(stream, cursor)
    saw_token = False
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.char_end > cursor:
            left_ui -= 1
            continue
        if unit.char_end <= floor:
            break
        if unit.kind in {"space", "inline_gap"}:
            cursor = unit.char_start
            left_ui -= 1
            if saw_token:
                continue
            continue
        if unit.kind in {"ascii_word", "digit_run", "alpha_run", "alnum_run"}:
            token = unit.text.strip().lower()
            if token in _DIRECTIONAL_TOKENS or _ORDINAL_TOKEN_RE.fullmatch(token):
                saw_token = True
                cursor = unit.char_start
                left_ui -= 1
                continue
            saw_token = True
            cursor = unit.char_start
            left_ui -= 1
            continue
        break
    return cursor


def _routing_left_value_start_en(context: _RoutingContext, clue: Clue) -> int:
    if context.chain:
        return context.chain[-1].end
    if context.previous_component_end is not None:
        return context.previous_component_end
    return _left_expand_en_phrase(clue.start, 0, context.stream)


def key_left_expand_start_if_deferrable_en(
    context: _RoutingContext,
    clue: Clue,
    comp_type: AddressComponentType,
) -> int | None:
    """英文 suffix-key 存在左值时，返回延迟提交的左边界。"""
    if is_prefix_en_key(clue.text):
        return None
    expand_start = _routing_left_value_start_en(context, clue)
    value = _normalize_address_value(comp_type, context.raw_text[expand_start:clue.start])
    if not value:
        return None
    return expand_start


def sub_tokenize_en(stream: StreamInput, hard_clue: Clue) -> list[Clue]:
    """在 HARD clue span 内扫描英文地址关键词，产出 sub-clue 列表。"""
    from privacyguard.infrastructure.pii.detector.scanner import (
        _POSTAL_CODE_PATTERN,
        _ScanSegment,
        _en_address_key_matcher,
        _en_address_value_matcher,
        _normalize_segment_ascii_match,
        _segment_span_to_raw,
    )

    span_start = hard_clue.start
    span_end = hard_clue.end
    text = stream.text[span_start:span_end]
    if not text.strip():
        return []

    folded = text.lower()
    segment = _ScanSegment(stream=stream, text=text, raw_start=span_start, folded_text=folded)
    sub_clues: list[Clue] = []
    clue_counter = 0

    def _make_id() -> str:
        nonlocal clue_counter
        clue_counter += 1
        return f"sub_{hard_clue.clue_id}_{clue_counter}"

    for matcher in (_en_address_value_matcher(),):
        for match in matcher.find_matches(text, folded_text=folded):
            normalized = _normalize_segment_ascii_match(
                segment,
                match.start,
                match.end,
                match.matched_text,
                match.pattern_text,
                match.ascii_boundary,
            )
            if normalized is None:
                continue
            abs_start, abs_end, matched_text = normalized
            payload = match.payload
            unit_start, unit_end = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=matched_text,
                unit_start=unit_start,
                unit_end=unit_end,
                source_kind="sub_tokenize_value",
                component_type=payload.component_type,
            ))

    for matcher in (_en_address_key_matcher(),):
        for match in matcher.find_matches(text, folded_text=folded):
            normalized = _normalize_segment_ascii_match(
                segment,
                match.start,
                match.end,
                match.matched_text,
                match.pattern_text,
                match.ascii_boundary,
            )
            if normalized is None:
                continue
            abs_start, abs_end, matched_text = normalized
            payload = match.payload
            unit_start, unit_end = _char_span_to_unit_span(stream, abs_start, abs_end)
            sub_clues.append(Clue(
                clue_id=_make_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=abs_start,
                end=abs_end,
                text=matched_text,
                unit_start=unit_start,
                unit_end=unit_end,
                source_kind="sub_tokenize_key",
                component_type=payload.component_type,
            ))

    for token_match in _POSTAL_CODE_PATTERN.finditer(text):
        abs_start, abs_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
        unit_start, unit_end = _char_span_to_unit_span(stream, abs_start, abs_end)
        sub_clues.append(Clue(
            clue_id=_make_id(),
            family=ClueFamily.ADDRESS,
            role=ClueRole.VALUE,
            attr_type=PIIAttributeType.ADDRESS,
            strength=ClaimStrength.SOFT,
            start=abs_start,
            end=abs_end,
            text=token_match.group(0),
            unit_start=unit_start,
            unit_end=unit_end,
            source_kind="sub_tokenize_postal_value",
            component_type=AddressComponentType.POSTAL_CODE,
        ))

    sub_clues.sort(key=lambda clue: (clue.start, -(clue.end - clue.start)))
    deduped: list[Clue] = []
    for clue in sub_clues:
        if any(
            kept.start <= clue.start and clue.end <= kept.end
            and kept.role == clue.role
            and kept.component_type == clue.component_type
            for kept in deduped
        ):
            continue
        deduped.append(clue)

    deduped.sort(key=lambda clue: (clue.start, clue.end))
    return deduped
