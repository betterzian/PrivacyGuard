"""构建新 detector 的文字流事件。"""

from __future__ import annotations

import re
from itertools import count

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import load_china_geo_lexicon
from privacyguard.infrastructure.pii.address.lexicon import collect_components
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressToken
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
_ZH_ADDRESS_ATTR_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("province", ("特别行政区", "自治区", "省")),
    ("city", ("自治州", "地区", "盟", "市")),
    ("district", ("区", "县", "旗")),
    ("street_admin", ("街道",)),
    ("town", ("镇", "乡")),
    ("village", ("社区", "村")),
    ("road", ("大道", "胡同", "路", "街", "道", "巷", "弄")),
    ("compound", ("小区", "公寓", "大厦", "园区", "社区", "花园", "家园", "苑", "庭", "府", "湾", "宿舍")),
    ("building", ("号楼", "栋", "幢", "座", "楼")),
    ("unit", ("单元",)),
    ("floor", ("层",)),
    ("room", ("室", "房", "户")),
)


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
    address_events = tuple(_collect_address_atomic_events(stream, label_events=label_events, locale_profile=locale_profile))
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


def _collect_address_atomic_events(
    stream: StreamInput,
    *,
    label_events: tuple[StreamEvent, ...],
    locale_profile: str,
) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    label_spans = tuple(
        (event.start, event.end)
        for event in label_events
        if event.attr_type == PIIAttributeType.ADDRESS
    )
    if locale_profile in {"zh_cn", "mixed"}:
        tokens = _collect_zh_address_tokens(stream.raw_text, label_spans=label_spans)
        for token in tokens:
            events.append(_address_token_event(token, label_spans=label_spans))
    if locale_profile in {"en_us", "mixed"} and any("A" <= ch <= "z" for ch in stream.raw_text):
        components = collect_components(
            stream.raw_text,
            locale_profile="en_us",
            forbidden_spans=label_spans,
        )
        for component in components:
            events.extend(_address_component_events(component, label_spans=label_spans))
    return events


def _collect_zh_address_tokens(
    text: str,
    *,
    label_spans: tuple[tuple[int, int], ...],
) -> list[AddressToken]:
    tokens: list[AddressToken] = []
    china_geo = load_china_geo_lexicon()
    direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}
    geo_specs = (
        ("province", tuple(token for token in china_geo.provinces if token not in direct_city_names)),
        ("city", tuple([*china_geo.cities, *sorted(direct_city_names)])),
        ("district", china_geo.districts),
    )
    for component_type, lexicon in geo_specs:
        for token_text in sorted(set(lexicon), key=len, reverse=True):
            for match in re.finditer(re.escape(token_text), text):
                start, end = match.start(), match.end()
                if any(not (end <= left or start >= right) for left, right in label_spans):
                    continue
                tokens.append(
                    AddressToken(
                        component_type=component_type,
                        token_role="name",
                        text=token_text,
                        start=start,
                        end=end,
                    )
                )
    for component_type, keywords in _ZH_ADDRESS_ATTR_KEYWORDS:
        for keyword in keywords:
            for match in re.finditer(re.escape(keyword), text):
                start, end = match.start(), match.end()
                if any(not (end <= left or start >= right) for left, right in label_spans):
                    continue
                tokens.append(
                    AddressToken(
                        component_type=component_type,
                        token_role="attr",
                        text=keyword,
                        start=start,
                        end=end,
                    )
                )
    return _dedupe_address_tokens(tokens)


def _address_component_events(
    component: AddressComponent,
    *,
    label_spans: tuple[tuple[int, int], ...],
) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    matched_by = "context_address_field" if any(0 <= component.start - right <= 2 for _, right in label_spans) else "event_stream_address"
    common_payload = {
        "anchor_kind": "address_component",
        "component": component,
        "component_type": component.component_type,
        "component_start": component.start,
        "component_end": component.end,
        "matched_by": matched_by,
    }
    if _should_emit_address_name_event(component) and component.value_start < component.value_end and component.value_text:
        events.append(
            StreamEvent(
                event_id=_next_event_id(),
                kind=EventKind.ANCHOR,
                attr_type=PIIAttributeType.ADDRESS,
                start=component.value_start,
                end=component.value_end,
                strength=ClaimStrength.SOFT,
                priority=196,
                stack_kind="address",
                matched_by=f"address_{component.component_type}_name",
                payload={
                    **common_payload,
                    "token_role": "name",
                },
            )
        )
    if component.key_start < component.key_end and component.key_text:
        events.append(
            StreamEvent(
                event_id=_next_event_id(),
                kind=EventKind.ANCHOR,
                attr_type=PIIAttributeType.ADDRESS,
                start=component.key_start,
                end=component.key_end,
                strength=ClaimStrength.SOFT,
                priority=195,
                stack_kind="address",
                matched_by=f"address_{component.component_type}_attr",
                payload={
                    **common_payload,
                    "token_role": "attr",
                },
            )
        )
    return events


def _address_token_event(
    token: AddressToken,
    *,
    label_spans: tuple[tuple[int, int], ...],
) -> StreamEvent:
    matched_by = "context_address_field" if any(0 <= token.start - right <= 2 for _, right in label_spans) else "event_stream_address"
    matched_suffix = "name" if token.token_role == "name" else "attr"
    return StreamEvent(
        event_id=_next_event_id(),
        kind=EventKind.ANCHOR,
        attr_type=PIIAttributeType.ADDRESS,
        start=token.start,
        end=token.end,
        strength=ClaimStrength.SOFT,
        priority=196 if token.token_role == "name" else 195,
        stack_kind="address",
        matched_by=f"address_{token.component_type}_{matched_suffix}",
        payload={
            "anchor_kind": "address_token",
            "token": token,
            "component_type": token.component_type,
            "matched_by": matched_by,
            "token_role": token.token_role,
        },
    )


def _should_emit_address_name_event(component: AddressComponent) -> bool:
    return component.component_type in {
        "province",
        "city",
        "district",
        "street_admin",
        "town",
        "village",
        "road",
        "street",
        "state",
        "postal_code",
    }


def _dedupe_address_tokens(tokens: list[AddressToken]) -> list[AddressToken]:
    ordered = sorted(tokens, key=lambda item: (item.start, -(item.end - item.start), item.component_type, item.token_role))
    kept: list[AddressToken] = []
    seen: set[tuple[str, str, int, int, str]] = set()
    occupied_names: list[tuple[int, int]] = []
    occupied_attrs: list[tuple[int, int]] = []
    for token in ordered:
        key = (token.component_type, token.token_role, token.start, token.end, token.text)
        if key in seen:
            continue
        if token.token_role == "name" and any(not (token.end <= left or token.start >= right) for left, right in occupied_names):
            continue
        if token.token_role == "attr" and any(not (token.end <= left or token.start >= right) for left, right in occupied_attrs):
            continue
        seen.add(key)
        kept.append(token)
        if token.token_role == "name":
            occupied_names.append((token.start, token.end))
        if token.token_role == "attr":
            occupied_attrs.append((token.start, token.end))
    return sorted(kept, key=lambda item: (item.start, item.end, item.component_type, item.token_role))


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
