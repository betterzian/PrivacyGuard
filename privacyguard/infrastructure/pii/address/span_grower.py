from __future__ import annotations

from privacyguard.infrastructure.pii.address.lexicon import hard_stop_matches, is_connector_text, masked_tail_match
from privacyguard.infrastructure.pii.address.types import AddressComponentMatch, AddressInput, AddressSeed, AddressSpanDraft
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

_HARD_STOP_CHARS = "。！？!?;\n\r"


def grow_spans(
    address_input: AddressInput,
    seeds: tuple[AddressSeed, ...],
    *,
    locale_profile: str,
    component_matches: tuple[AddressComponentMatch, ...] | None = None,
) -> tuple[AddressSpanDraft, ...]:
    text = address_input.text
    drafts: list[AddressSpanDraft] = []
    all_component_matches = component_matches if component_matches is not None else ()
    for seed in seeds:
        window_start = _scan_left_hard_boundary(text, seed.start)
        window_end = _scan_right_hard_boundary(text, seed.end)
        window_components = _component_matches(window_start, window_end, all_component_matches, locale_profile=locale_profile)
        draft = _grow_from_seed(text, seed, window_components, window_start, window_end)
        if draft is not None:
            drafts.append(draft)
    return tuple(_dedupe_drafts(drafts))


def _component_matches(
    window_start: int,
    window_end: int,
    all_components: tuple[AddressComponentMatch, ...],
    *,
    locale_profile: str,
) -> tuple[AddressComponentMatch, ...]:
    del locale_profile  # keep signature stable for now
    return tuple(
        item
        for item in all_components
        if item.start >= window_start and item.end <= window_end
    )


def _grow_from_seed(
    text: str,
    seed: AddressSeed,
    component_matches: tuple[AddressComponentMatch, ...],
    window_start: int,
    window_end: int,
) -> AddressSpanDraft | None:
    if not component_matches:
        if seed.seed_type != "label_value" or seed.start >= window_end:
            return None
        end = _label_value_end(text, seed.start, window_end)
        if end <= seed.start:
            return None
        return AddressSpanDraft(
            start=seed.start,
            end=end,
            window_start=window_start,
            window_end=window_end,
            seed=seed,
            terminated_by="stream_end",
            evidence=(seed.matched_by,),
        )
    anchor_index = _anchor_component_index(seed, component_matches)
    if anchor_index is None:
        return None
    start_index = anchor_index
    end_index = anchor_index
    while start_index > 0:
        previous = component_matches[start_index - 1]
        current = component_matches[start_index]
        if not _can_bridge(text[previous.end:current.start]):
            break
        start_index -= 1
    while end_index + 1 < len(component_matches):
        current = component_matches[end_index]
        nxt = component_matches[end_index + 1]
        if not _can_bridge(text[current.end:nxt.start]):
            break
        end_index += 1
    start = component_matches[start_index].start
    end = component_matches[end_index].end
    terminated_by = "stream_end"
    tail = text[end:window_end]
    masked_match = masked_tail_match(tail)
    if masked_match is not None and _looks_like_terminal_mask(tail[: masked_match.end()]):
        end += masked_match.end()
        terminated_by = "masked_end"
    elif tail and tail[0] in _HARD_STOP_CHARS:
        terminated_by = "hard_stop"
    return AddressSpanDraft(
        start=start,
        end=end,
        window_start=window_start,
        window_end=window_end,
        seed=seed,
        terminated_by=terminated_by,
        evidence=tuple(dict.fromkeys([seed.matched_by, *(item.component_type for item in component_matches[start_index : end_index + 1])])),
    )


def _anchor_component_index(seed: AddressSeed, component_matches: tuple[AddressComponentMatch, ...]) -> int | None:
    best_index: int | None = None
    best_distance: tuple[int, int] | None = None
    for index, component in enumerate(component_matches):
        if seed.seed_type == "label_value" and component.end <= seed.start:
            continue
        if component.start <= seed.start < component.end or component.start < seed.end <= component.end:
            return index
        distance = (abs(component.start - seed.start), abs(component.end - seed.end))
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_index = index
    return best_index


def _can_bridge(gap_text: str) -> bool:
    stripped = gap_text.strip()
    if not stripped:
        return True
    if is_connector_text(stripped):
        return True
    return stripped in {"的", "之", "·", "•"}


def _looks_like_terminal_mask(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and all(char in ".…*＊xX某 " for char in stripped)


def _label_value_end(text: str, start: int, window_end: int) -> int:
    end = start
    while end < window_end and text[end] not in _HARD_STOP_CHARS:
        end += 1
    return end


def _scan_left_hard_boundary(text: str, index: int) -> int:
    cursor = max(0, min(index, len(text)))
    left_limit = 0
    break_index = text.rfind(_OCR_SEMANTIC_BREAK_TOKEN, 0, cursor)
    if break_index >= 0:
        left_limit = break_index + len(_OCR_SEMANTIC_BREAK_TOKEN)
    while cursor > left_limit:
        if text[cursor - 1] in _HARD_STOP_CHARS:
            break
        cursor -= 1
    return cursor


def _scan_right_hard_boundary(text: str, index: int) -> int:
    cursor = max(0, min(index, len(text)))
    hard_matches = hard_stop_matches(text[cursor:])
    hard_limit = len(text)
    if hard_matches:
        hard_limit = min(hard_limit, cursor + hard_matches[0][0])
    while cursor < min(len(text), hard_limit):
        if text[cursor] in _HARD_STOP_CHARS:
            return cursor
        cursor += 1
    return min(len(text), hard_limit)


def _dedupe_drafts(drafts: list[AddressSpanDraft]) -> list[AddressSpanDraft]:
    deduped: dict[tuple[int, int], AddressSpanDraft] = {}
    for draft in drafts:
        key = (draft.start, draft.end)
        previous = deduped.get(key)
        if previous is None or draft.seed.confidence > previous.seed.confidence:
            deduped[key] = draft
    return sorted(deduped.values(), key=lambda item: (item.start, item.end))
