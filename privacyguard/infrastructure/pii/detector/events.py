"""构建新 detector 的文字流事件。"""

from __future__ import annotations

import re
from itertools import count

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.input_adapter import build_text_input
from privacyguard.infrastructure.pii.address.seed_extractor import collect_component_matches
from privacyguard.infrastructure.pii.detector.labels import _LABEL_SPECS
from privacyguard.infrastructure.pii.detector.models import (
    ClaimStrength,
    DictionaryEntry,
    EventBundle,
    EventKind,
    StreamEvent,
    StreamInput,
)

_EVENT_IDS = count(1)

_HARD_SOURCE_PRIORITY = {
    "session": 4,
    "local": 3,
    "prompt": 2,
    "regex": 1,
}

_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.CARD_NUMBER: "<card>",
    PIIAttributeType.BANK_ACCOUNT: "<bank_account>",
    PIIAttributeType.PASSPORT_NUMBER: "<passport>",
    PIIAttributeType.DRIVER_LICENSE: "<driver_license>",
}

_HARD_PATTERNS: tuple[tuple[PIIAttributeType, str, re.Pattern[str], int], ...] = (
    (
        PIIAttributeType.EMAIL,
        "regex_email",
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
        120,
    ),
    (
        PIIAttributeType.PHONE,
        "regex_phone_cn",
        re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
        115,
    ),
    (
        PIIAttributeType.PHONE,
        "regex_phone_us",
        re.compile(r"(?<!\w)(?:\(\d{3}\)\s*|\d{3}[-. ]?)\d{3}[-. ]\d{4}(?!\w)"),
        114,
    ),
    (
        PIIAttributeType.ID_NUMBER,
        "regex_id_cn",
        re.compile(r"(?<![\w\d])\d{17}[\dXx](?![\w\d])"),
        110,
    ),
    (
        PIIAttributeType.BANK_ACCOUNT,
        "regex_bank_account",
        re.compile(r"(?<!\d)\d(?:[ -]?\d){11,22}(?!\d)"),
        104,
    ),
    (
        PIIAttributeType.PASSPORT_NUMBER,
        "regex_passport",
        re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{8}(?![A-Za-z0-9])"),
        103,
    ),
)

_ORG_SUFFIX_PATTERN = re.compile(
    r"(?i)(股份有限公司|有限责任公司|有限公司|研究院|实验室|公司|集团|大学|学院|银行|酒店|医院|中心|工作室|事务所"
    r"|incorporated|corporation|company|limited|inc\.?|corp\.?|co\.?|ltd\.?|llc|plc|gmbh|pte|bank|hotel|hospital|clinic|university|college|labs?)"
)
_NAME_SELF_INTRO_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("context_name_self_intro_zh", re.compile(r"(?:我是|我叫|姓名是|名字叫)\s*")),
    ("context_name_self_intro_en", re.compile(r"(?i)\b(?:this is|i am|i'm|my name is|name is)\b\s*")),
)
_ADDRESS_COMPONENT_PRIORITIES = {
    "province": 198,
    "city": 197,
    "district": 196,
    "street_admin": 195,
    "town": 194,
    "village": 193,
    "street": 192,
    "road": 191,
    "compound": 190,
    "poi": 189,
    "building": 188,
    "unit": 187,
    "floor": 186,
    "room": 185,
    "postal_code": 184,
    "po_box": 183,
    "state": 182,
    "county": 181,
}
_ADDRESS_ATTR_SUFFIXES = ("省", "市", "区", "县", "镇", "乡", "村", "路", "街", "道", "巷", "弄", "号", "室", "单元", "层")


def build_event_bundle(
    stream: StreamInput,
    *,
    session_entries: tuple[DictionaryEntry, ...],
    local_entries: tuple[DictionaryEntry, ...],
    locale_profile: str,
) -> EventBundle:
    structured_events = tuple(_collect_structured_events(stream))
    modified_text, modified_to_raw = _build_modified_text(stream.raw_text, structured_events)
    label_events = tuple(_collect_label_events(modified_text, modified_to_raw, locale_profile))
    anchor_events = tuple(_collect_anchor_events(modified_text, modified_to_raw, locale_profile))
    address_events = tuple(_collect_address_component_events(stream, locale_profile=locale_profile))
    dictionary_events = tuple(_collect_dictionary_events(stream, [*session_entries, *local_entries]))
    hard_events = tuple(_resolve_hard_event_conflicts([*structured_events, *dictionary_events]))
    structured_event_ids = {event.event_id for event in structured_events}
    dictionary_event_ids = {event.event_id for event in dictionary_events}
    all_events = tuple(
        sorted(
            [*hard_events, *label_events, *anchor_events, *address_events],
            key=lambda item: (item.start, -item.priority, item.end - item.start),
        )
    )
    return EventBundle(
        modified_text=modified_text,
        modified_to_raw=modified_to_raw,
        structured_events=tuple(event for event in hard_events if event.event_id in structured_event_ids),
        dictionary_events=tuple(event for event in hard_events if event.event_id in dictionary_event_ids),
        label_events=label_events,
        anchor_events=tuple(sorted([*anchor_events, *address_events], key=lambda item: (item.start, item.end, -item.priority))),
        all_events=all_events,
    )


def _collect_structured_events(stream: StreamInput) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    for attr_type, matched_by, pattern, priority in _HARD_PATTERNS:
        for match in pattern.finditer(stream.raw_text):
            text = match.group(0).strip()
            if not text:
                continue
            events.append(
                StreamEvent(
                    event_id=_next_event_id(),
                    kind=EventKind.HARD_VALUE,
                    attr_type=attr_type,
                    start=match.start(),
                    end=match.end(),
                    strength=ClaimStrength.HARD,
                    priority=priority,
                    stack_kind="structured",
                    matched_by=matched_by,
                    payload={
                        "text": text,
                        "placeholder": _PLACEHOLDER_BY_ATTR[attr_type],
                        "metadata": {
                            "matched_by": [matched_by],
                            "hard_source": ["regex"],
                        },
                    },
                )
            )
    return _dedupe_hard_overlaps(events)


def _collect_label_events(modified_text: str, modified_to_raw: tuple[int | None, ...], locale_profile: str) -> list[StreamEvent]:
    del locale_profile
    matches: list[tuple[int, int, LabelSpec]] = []
    for spec in _LABEL_SPECS:
        matches.extend(_iter_label_matches(modified_text, spec))
    accepted: list[tuple[int, int, LabelSpec]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, spec in sorted(
        matches,
        key=lambda item: (-(item[1] - item[0]), -len(item[2].keyword), -item[2].priority, item[0], item[1]),
    ):
        if any(not (end <= left or start >= right) for left, right in occupied):
            continue
        occupied.append((start, end))
        accepted.append((start, end, spec))
    accepted.sort(key=lambda item: (item[0], item[1]))
    events: list[StreamEvent] = []
    for start, end, spec in accepted:
        if _looks_like_placeholder_slice(modified_text, start, end):
            continue
        raw_span = _modified_span_to_raw(modified_to_raw, start, end)
        if raw_span is None:
            continue
        raw_start, raw_end = raw_span
        events.append(
            StreamEvent(
                event_id=_next_event_id(),
                kind=EventKind.LABEL,
                attr_type=spec.attr_type,
                start=raw_start,
                end=raw_end,
                strength=ClaimStrength.SOFT,
                priority=spec.priority,
                stack_kind=spec.stack_kind,
                matched_by=spec.matched_by,
                payload={
                    "keyword": spec.keyword,
                    "component_hint": spec.component_hint,
                    "ocr_matched_by": spec.ocr_matched_by,
                    "trigger_kind": "label" if spec.attr_type == PIIAttributeType.ADDRESS else None,
                },
            )
        )
    return events


def _collect_anchor_events(modified_text: str, modified_to_raw: tuple[int | None, ...], locale_profile: str) -> list[StreamEvent]:
    del locale_profile
    events: list[StreamEvent] = []
    for matched_by, pattern in _NAME_SELF_INTRO_PATTERNS:
        for match in pattern.finditer(modified_text):
            raw_span = _modified_span_to_raw(modified_to_raw, match.start(), match.end())
            if raw_span is None:
                continue
            events.append(
                StreamEvent(
                    event_id=_next_event_id(),
                    kind=EventKind.ANCHOR,
                    attr_type=PIIAttributeType.NAME,
                    start=raw_span[0],
                    end=raw_span[1],
                    strength=ClaimStrength.SOFT,
                    priority=210,
                    stack_kind="name",
                    matched_by=matched_by,
                    payload={"anchor_kind": "self_intro", "component_hint": "full"},
                )
            )
    for match in _ORG_SUFFIX_PATTERN.finditer(modified_text):
        raw_span = _modified_span_to_raw(modified_to_raw, match.start(), match.end())
        if raw_span is None:
            continue
        events.append(
            StreamEvent(
                event_id=_next_event_id(),
                kind=EventKind.ANCHOR,
                attr_type=PIIAttributeType.ORGANIZATION,
                start=raw_span[0],
                end=raw_span[1],
                strength=ClaimStrength.SOFT,
                priority=205,
                stack_kind="organization",
                matched_by="regex_organization_suffix",
                payload={"anchor_kind": "organization_suffix"},
            )
        )
    return events


def _collect_address_component_events(stream: StreamInput, *, locale_profile: str) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    seen: set[tuple[int, int, str]] = set()
    matches = collect_component_matches(build_text_input(stream.raw_text), locale_profile=locale_profile)
    for match in matches:
        key = (match.start, match.end, match.component_type)
        if key in seen:
            continue
        seen.add(key)
        trigger_kind = _address_component_trigger_kind(match.text, match.component_type, match.strength)
        matched_by = f"address_component_{match.component_type}"
        events.append(
            StreamEvent(
                event_id=_next_event_id(),
                kind=EventKind.ANCHOR,
                attr_type=PIIAttributeType.ADDRESS,
                start=match.start,
                end=match.end,
                strength=ClaimStrength.SOFT,
                priority=_ADDRESS_COMPONENT_PRIORITIES.get(match.component_type, 180),
                stack_kind="address",
                matched_by=matched_by,
                payload={
                    "anchor_kind": "address_component",
                    "component_type": match.component_type,
                    "component_strength": match.strength,
                    "component_text": match.text,
                    "trigger_kind": trigger_kind,
                },
            )
        )
    return events


def _address_component_trigger_kind(text: str, component_type: str, strength: str) -> str:
    compact = re.sub(r"\s+", "", str(text or ""))
    if not compact:
        return "component_name"
    if strength != "strong":
        return "component_attr"
    if len(compact) <= 2 and compact.endswith(_ADDRESS_ATTR_SUFFIXES):
        return "component_attr"
    if component_type in {"district", "city", "province"} and len(compact) <= 3:
        return "component_attr"
    return "component_name"


def _collect_dictionary_events(stream: StreamInput, entries: list[DictionaryEntry]) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    seen: set[tuple[PIIAttributeType, int, int, str]] = set()
    for entry in entries:
        for variant in sorted({part for part in entry.variants if part.strip()}, key=len, reverse=True):
            for match in _iter_variant_matches(stream.raw_text, variant):
                key = (entry.attr_type, match.start(), match.end(), entry.matched_by)
                if key in seen:
                    continue
                seen.add(key)
                metadata = {key_name: list(values) for key_name, values in entry.metadata.items()}
                metadata["matched_by"] = [entry.matched_by]
                if entry.matched_by == "dictionary_session":
                    metadata["hard_source"] = ["session"]
                else:
                    metadata["hard_source"] = ["local"]
                events.append(
                    StreamEvent(
                        event_id=_next_event_id(),
                        kind=EventKind.HARD_VALUE,
                        attr_type=entry.attr_type,
                        start=match.start(),
                        end=match.end(),
                        strength=ClaimStrength.HARD,
                        priority=200 if entry.matched_by == "dictionary_session" else 190,
                        stack_kind="structured",
                        matched_by=entry.matched_by,
                        payload={
                            "text": match.group(0),
                            "metadata": metadata,
                            "dictionary_text": entry.text,
                        },
                    )
                )
    return events


def _build_modified_text(text: str, events: tuple[StreamEvent, ...]) -> tuple[str, tuple[int | None, ...]]:
    pieces: list[str] = []
    mapping: list[int | None] = []
    cursor = 0
    for event in sorted(events, key=lambda item: (item.start, item.end)):
        if event.start < cursor:
            continue
        if cursor < event.start:
            unchanged = text[cursor : event.start]
            pieces.append(unchanged)
            mapping.extend(range(cursor, event.start))
        placeholder = str(event.payload.get("placeholder") or "")
        if placeholder:
            pieces.append(placeholder)
            mapping.extend([event.start] * len(placeholder))
        else:
            original = text[event.start : event.end]
            pieces.append(original)
            mapping.extend(range(event.start, event.end))
        cursor = event.end
    if cursor < len(text):
        tail = text[cursor:]
        pieces.append(tail)
        mapping.extend(range(cursor, len(text)))
    return ("".join(pieces), tuple(mapping))


def _iter_label_matches(text: str, spec: LabelSpec) -> list[tuple[int, int, LabelSpec]]:
    escaped = re.escape(spec.keyword)
    pattern = escaped
    flags = re.IGNORECASE if spec.ascii_boundary else 0
    if spec.ascii_boundary:
        pattern = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
    return [(match.start(), match.end(), spec) for match in re.finditer(pattern, text, flags=flags)]


def _iter_variant_matches(text: str, variant: str):
    escaped = re.escape(variant)
    if re.fullmatch(r"[A-Za-z0-9 .,'@_+\-#/&()]+", variant):
        pattern = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
        return re.finditer(pattern, text, flags=re.IGNORECASE)
    return re.finditer(escaped, text)


def _modified_span_to_raw(modified_to_raw: tuple[int | None, ...], start: int, end: int) -> tuple[int, int] | None:
    raw_positions = [position for position in modified_to_raw[start:end] if position is not None]
    if not raw_positions:
        return None
    return (min(raw_positions), max(raw_positions) + 1)


def _looks_like_placeholder_slice(text: str, start: int, end: int) -> bool:
    if not (0 <= start < end <= len(text)):
        return False
    slice_text = text[start:end]
    if slice_text.startswith("<") and slice_text.endswith(">"):
        return True
    left = text.rfind("<", 0, start + 1)
    right = text.find(">", end - 1)
    return left >= 0 and right >= end


def _dedupe_hard_overlaps(events: list[StreamEvent]) -> list[StreamEvent]:
    accepted: list[StreamEvent] = []
    for event in sorted(events, key=lambda item: (item.start, -item.priority, -(item.end - item.start))):
        replaced = False
        for index, existing in enumerate(list(accepted)):
            if event.end <= existing.start or event.start >= existing.end:
                continue
            if event.priority > existing.priority or (event.priority == existing.priority and (event.end - event.start) > (existing.end - existing.start)):
                accepted[index] = event
            replaced = True
            break
        if not replaced:
            accepted.append(event)
    return sorted(accepted, key=lambda item: (item.start, item.end))


def _resolve_hard_event_conflicts(events: list[StreamEvent]) -> list[StreamEvent]:
    """按 session/local/prompt/regex 顺序前置裁掉 hard-hard 冲突。"""
    accepted: list[StreamEvent] = []
    for event in sorted(events, key=lambda item: (item.start, item.end)):
        replaced = False
        event_length = _event_effective_length(event)
        event_source_rank = _hard_source_rank(event)
        for index, existing in enumerate(list(accepted)):
            if event.end <= existing.start or event.start >= existing.end:
                continue
            existing_length = _event_effective_length(existing)
            existing_source_rank = _hard_source_rank(existing)
            if event_length > existing_length:
                accepted[index] = event
                replaced = True
                break
            if event_source_rank > existing_source_rank:
                accepted[index] = event
                replaced = True
                break
            replaced = True
            break
        if not replaced:
            accepted.append(event)
    return sorted(accepted, key=lambda item: (item.start, item.end))


def _event_effective_length(event: StreamEvent) -> int:
    text = str(event.payload.get("text") or "")
    return len(text.strip()) or (event.end - event.start)


def _hard_source_rank(event: StreamEvent) -> int:
    metadata = event.payload.get("metadata")
    if not isinstance(metadata, dict):
        return _HARD_SOURCE_PRIORITY["regex"]
    values = metadata.get("hard_source")
    if isinstance(values, list) and values:
        return _HARD_SOURCE_PRIORITY.get(str(values[0]), _HARD_SOURCE_PRIORITY["regex"])
    return _HARD_SOURCE_PRIORITY["regex"]


def _next_event_id() -> str:
    return f"evt-{next(_EVENT_IDS)}"
