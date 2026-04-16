"""英文地址 stack 的专用规则。

这里仅保留英文 grammar 需要的能力：
1. 英文 KEY 左扩。
2. prefix-key（如 `Apt` / `#`）判定。
3. 英文组件后继图。
"""

from __future__ import annotations

import re

from privacyguard.infrastructure.pii.detector.lexicon_loader import load_en_address_keyword_groups
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    Clue,
    PIIAttributeType,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _RoutingContext,
    _build_admin_value_span,
    _normalize_address_value,
)
from privacyguard.infrastructure.pii.detector.stacks.address_state import (
    _ParseState,
    _VALID_SUCCESSORS,
    _segment_admit,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_index_left_of

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


def resolve_standalone_admin_value_group_en(
    state: _ParseState,
    clue_entries: tuple[tuple[int, Clue], ...],
) -> tuple[AddressComponentType, tuple[AddressComponentType, ...]] | None:
    """英文同 span 多层级行政 value 的公共解析。"""
    span = _build_admin_value_span(tuple(clue for _, clue in clue_entries))
    if span is None:
        return None
    available = tuple(
        level
        for level in span.levels
        if _segment_admit(state, level, valid_successors=_VALID_SUCCESSORS)
    )
    if not available:
        return None
    primary = AddressComponentType.CITY if AddressComponentType.CITY in available else available[0]
    return primary, available


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
