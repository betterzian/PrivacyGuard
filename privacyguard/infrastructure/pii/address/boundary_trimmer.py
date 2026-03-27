from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.lexicon import (
    find_field_keyword,
    hard_stop_matches,
    leading_noise_pattern,
    masked_tail_match,
    soft_stop_tokens,
)
from privacyguard.infrastructure.pii.address.types import AddressInput, AddressParseConfig, AddressSpan, AddressSpanDraft

_TRAILING_LOCATIVE_RE = re.compile(r"(?:里|内|附近|旁边|门口|周边)\s*$")


def trim_spans(
    address_input: AddressInput,
    drafts: tuple[AddressSpanDraft, ...],
    *,
    config: AddressParseConfig,
) -> tuple[AddressSpan, ...]:
    spans: list[AddressSpan] = []
    for draft in drafts:
        span = _trim_single(address_input.text, draft)
        if span is not None:
            spans.append(span)
    return tuple(_dedupe_spans(spans))


def _trim_single(text: str, draft: AddressSpanDraft) -> AddressSpan | None:
    start = draft.start
    end = draft.end
    prefix = text[draft.window_start:start]
    terminated_by = draft.terminated_by
    noise_match = leading_noise_pattern().match(prefix)
    if noise_match is not None:
        prefix = prefix[noise_match.end():]
    prefix = prefix.strip()
    if prefix and _looks_like_geo_prefix(prefix):
        start = max(draft.window_start, start - len(prefix))
    suffix = text[end:draft.window_end]
    compact_suffix = suffix.lstrip().lower()
    field_match = find_field_keyword(suffix)
    hard_stop_hits = hard_stop_matches(suffix)
    if field_match is not None or hard_stop_hits:
        terminated_by = "hard_stop"
    masked_match = _leading_masked_tail_match(suffix)
    if masked_match is not None:
        end += masked_match.end()
        terminated_by = "masked_end"
    raw_span_text = text[start:end]
    if not raw_span_text:
        return None
    raw_span_text = _TRAILING_LOCATIVE_RE.sub("", raw_span_text)
    left_trim = len(raw_span_text) - len(raw_span_text.lstrip())
    right_trim = len(raw_span_text.rstrip())
    start += left_trim
    span_end = start + max(0, right_trim - left_trim)
    span_text = text[start:span_end]
    if len(span_text.strip()) < 2:
        return None
    if (
        draft.seed.matched_by != "context_address_field"
        and compact_suffix.startswith(("店", "门店", "store", "branch"))
        and _looks_like_short_store_branch_road(span_text)
    ):
        return None
    confidence = _span_confidence(span_text, draft)
    return AddressSpan(
        start=start,
        end=span_end,
        text=span_text,
        matched_by=draft.seed.matched_by,
        confidence=confidence,
        terminated_by=terminated_by,
        evidence=draft.evidence,
    )


def _soft_stop_index(text: str) -> int | None:
    lowered = text.lower()
    best: int | None = None
    for token in soft_stop_tokens():
        index = lowered.find(token)
        if index < 0:
            continue
        if best is None or index < best:
            best = index
    return best


def _leading_masked_tail_match(text: str) -> re.Match[str] | None:
    return re.match(r"\s*(?:\.{3,}|…+|[*＊]{2,}|[xX]{2,}|某+)", text)


def _looks_like_geo_prefix(text: str) -> bool:
    compact = text.replace(" ", "")
    if len(compact) > 12:
        return False
    if not all(char.isalnum() or "\u4e00" <= char <= "\u9fff" or char == "的" for char in compact):
        return False
    return compact.endswith(("省", "市", "区", "县", "旗", "盟", "地区", "镇", "乡", "街道", "村", "社区"))


def _looks_like_short_store_branch_road(text: str) -> bool:
    compact = text.strip()
    return len(compact) <= 3 and compact.endswith(("路", "街"))


def _span_confidence(span_text: str, draft: AddressSpanDraft) -> float:
    confidence = draft.seed.confidence
    if any(token in span_text for token in ("小区", "公寓", "大厦", "栋", "单元", "室", "Apt", "Suite", "Unit", "Floor")):
        confidence += 0.08
    if any(token in span_text for token in ("路", "街", "大道", "Street", "St", "Road", "Rd", "Ave", "Blvd")):
        confidence += 0.04
    if draft.terminated_by == "masked_end":
        confidence -= 0.02
    return max(0.0, min(0.97, confidence))


def _dedupe_spans(spans: list[AddressSpan]) -> list[AddressSpan]:
    deduped: dict[tuple[int, int], AddressSpan] = {}
    for span in spans:
        key = (span.start, span.end)
        previous = deduped.get(key)
        if previous is None or span.confidence > previous.confidence:
            deduped[key] = span
    return sorted(deduped.values(), key=lambda item: (item.start, item.end))
