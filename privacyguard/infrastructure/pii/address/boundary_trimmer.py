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
    # 组织右邻接回退：当左侧仅为粗粒度地名（省/市/国），且其右侧紧邻一个同语种连续的组织名（以组织后缀结尾），
    # 则认为这段更像组织名的一部分，丢弃该地址 span（等组织规则处理）。
    if _should_drop_coarse_geo_before_org(text, span_end, draft):
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


_EN_PREPOSITIONS = frozenset({"of", "in", "at", "on", "for", "to", "from", "by", "with"})


def _should_drop_coarse_geo_before_org(text: str, span_end: int, draft: AddressSpanDraft) -> bool:
    # 仅对“单个粗粒度地名”触发：来自 seed 或 evidence 中的 province/city/country（本管线里 country 很少出现，先按 city/province 处理）
    coarse = {"province", "city", "country", "state"}
    evidence_types = {item for item in draft.evidence if item in coarse or item == "district"}
    if not evidence_types:
        return False
    # 如果 evidence 里出现了 road/building/unit 等细粒度组件，不触发。
    if any(item in draft.evidence for item in ("road", "street", "building", "unit", "floor", "room", "compound", "poi", "postal_code", "district")):
        return False
    # 只允许 city/province/state/country 这类粗粒度参与
    if not evidence_types.issubset(coarse):
        return False

    # 严格 gap：组织必须从 span_end 紧邻开始；不允许空格、符号、OCR break、“的”、介词等。
    if span_end >= len(text):
        return False
    first = text[span_end]
    if first.isspace() or _is_symbol(first):
        return False
    if first == "的":
        return False

    # 取一个同语种连续 run
    run = _take_contiguous_run(text, span_end, max_len=64)
    if not run:
        return False

    # 英文 run：禁止介词（gap 为 0 时主要禁止 “in/of/at ...” 这种开头）
    lowered = run.lower()
    if _looks_english_run(run):
        head = lowered.split(" ", 1)[0]
        if head in _EN_PREPOSITIONS:
            return False

    # 必须以组织后缀结尾
    from privacyguard.infrastructure.pii.rule_based_detector_shared import (
        _EN_ORGANIZATION_STRONG_SUFFIXES,
        _EN_ORGANIZATION_WEAK_SUFFIXES,
        _ORGANIZATION_STRONG_SUFFIXES,
        _ORGANIZATION_WEAK_SUFFIXES,
    )
    suffixes = tuple(
        dict.fromkeys(
            [
                *_ORGANIZATION_STRONG_SUFFIXES,
                *_ORGANIZATION_WEAK_SUFFIXES,
                *_EN_ORGANIZATION_STRONG_SUFFIXES,
                *_EN_ORGANIZATION_WEAK_SUFFIXES,
            ]
        )
    )
    if not any(lowered.endswith(suf.lower()) for suf in suffixes):
        return False
    return True


def _is_symbol(char: str) -> bool:
    # 只要不是字母数字或中日韩统一表意文字，就视为符号（包含各类标点/括号/分隔符）
    return not (char.isalnum() or ("\u4e00" <= char <= "\u9fff"))


def _looks_english_run(text: str) -> bool:
    return any("a" <= ch.lower() <= "z" for ch in text) and not any("\u4e00" <= ch <= "\u9fff" for ch in text)


def _take_contiguous_run(text: str, start: int, *, max_len: int) -> str:
    """取从 start 开始的同语种连续文本，禁止符号、空白、OCR break。"""
    out: list[str] = []
    has_cjk = False
    has_alpha = False
    i = start
    while i < len(text) and len(out) < max_len:
        ch = text[i]
        if ch.isspace() or _is_symbol(ch):
            break
        if ch == "<":
            break
        if "\u4e00" <= ch <= "\u9fff":
            has_cjk = True
        elif ch.isalpha():
            has_alpha = True
        out.append(ch)
        i += 1
    if has_cjk and has_alpha:
        return ""
    return "".join(out).strip()


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
