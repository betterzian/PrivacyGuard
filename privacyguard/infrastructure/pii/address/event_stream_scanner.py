from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.address.lexicon import (
    build_label_pattern,
    find_field_keyword,
    hard_stop_matches,
    is_connector_text,
    masked_tail_match,
)
from privacyguard.infrastructure.pii.address.types import AddressComponentMatch, AddressParseConfig, AddressSpan
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _EN_ORGANIZATION_STRONG_SUFFIXES,
    _EN_ORGANIZATION_WEAK_SUFFIXES,
    _ORGANIZATION_STRONG_SUFFIXES,
    _ORGANIZATION_WEAK_SUFFIXES,
)

_HARD_STOP_CHARS = "。！？!?;\n\r"
_ORG_SUFFIX_TOKENS = tuple(
    dict.fromkeys(
        [
            *_ORGANIZATION_STRONG_SUFFIXES,
            *_ORGANIZATION_WEAK_SUFFIXES,
            *_EN_ORGANIZATION_STRONG_SUFFIXES,
            *_EN_ORGANIZATION_WEAK_SUFFIXES,
        ]
    )
)
_ZH_PREPOSITIONS = ("的", "在", "于", "在于", "地")
_EN_PREPOSITIONS = frozenset({"of", "in", "at", "on", "for", "to", "from", "by", "with"})


@dataclass(frozen=True, slots=True)
class _OrgSuffixEvent:
    start: int
    end: int
    suffix_text: str
    script: str  # "zh" | "en"


def scan_address_and_organization(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], object],
    *,
    raw_text: str,
    component_matches: tuple[AddressComponentMatch, ...],
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    skip_spans: list[tuple[int, int]],
    config: AddressParseConfig,
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> tuple[AddressSpan, ...]:
    """统一事件流：左到右地址栈 + 遇组织后缀触发组织左爬。

    返回地址 spans（组织候选会直接写入 collected）。
    """
    text = raw_text
    geo_events = tuple(sorted(component_matches, key=lambda item: (item.start, item.end, item.component_type)))
    org_events = _collect_org_suffix_events(text)
    label_value_starts = [match.end() for match in build_label_pattern().finditer(text)]

    emitted_org_events: set[tuple[int, int]] = set()

    spans: list[AddressSpan] = []
    i = 0
    while i < len(geo_events):
        stack: list[AddressComponentMatch] = []
        # 起点：允许所有地理事件作为起点（province/city/district 作为弱起点也允许）
        stack.append(geo_events[i])
        j = i
        # 扩展直到不能桥接
        while j + 1 < len(geo_events):
            cur = geo_events[j]
            nxt = geo_events[j + 1]
            gap = text[cur.end : nxt.start]
            if _should_stop_on_gap(gap):
                break
            if not _can_bridge_gap(gap):
                break
            stack.append(nxt)
            j += 1

        # 黑名单校准回退（总回退<=5）
        rollback = 0
        while stack and rollback < 5:
            if stack and _tail_component_is_blacklisted(text, stack[-1]):
                stack.pop()
                rollback += 1
                if not stack or rollback >= 5:
                    break
                continue
            break

        if stack:
            # 遇到组织后缀时，触发组织探测并按规则处理地址回退/截止。
            _handle_org_event_for_stack(
                detector,
                collected,
                text=text,
                stack=stack,
                org_events=org_events,
                emitted_org_events=emitted_org_events,
                source=source,
                bbox=bbox,
                block_id=block_id,
                skip_spans=skip_spans,
                original_text=original_text,
                shadow_index_map=shadow_index_map,
            )

            # 单组件特判：按 ProtectionLevel 放行；字段语境由 matched_by 决定（本扫描器默认非字段语境）
            if len(stack) == 1:
                single = stack[0]
                if not _allow_single_geo_as_address(single.component_type, config.protection_level):
                    stack = []

        if stack:
            start = stack[0].start
            end = stack[-1].end
            terminated_by = "event_stream"
            tail = text[end:]
            masked = masked_tail_match(tail)
            if masked is not None and _looks_like_terminal_mask(tail[: masked.end()]):
                end = min(len(text), end + masked.end())
                terminated_by = "masked_end"
            # 去掉叙述性尾巴（里/内/附近/旁边/门口/周边）
            while end > start and text[end - 1].isspace():
                end -= 1
            for suffix in ("里", "内", "附近", "旁边", "门口", "周边"):
                if text[start:end].endswith(suffix):
                    end -= len(suffix)
                    break
            span_text = text[start:end]
            if len(span_text.strip()) >= 2:
                matched_by = "event_stream_address"
                # 若 span 起点紧跟地址字段标签，视为 context_address_field（兼容旧行为）。
                for value_start in label_value_starts:
                    if 0 <= start - value_start <= 2:
                        matched_by = "context_address_field"
                        break
                spans.append(
                    AddressSpan(
                        start=start,
                        end=end,
                        text=span_text,
                        matched_by=matched_by,
                        confidence=_span_confidence_from_stack(stack),
                        terminated_by=terminated_by,
                        evidence=tuple(dict.fromkeys([item.component_type for item in stack])),
                    )
                )

        # 继续从下一个位置开始（避免 O(n^2) 重复起点）
        i = max(i + 1, j + 1)

    # 对未在地址扫描中触发的组织事件，补做一次独立组织探测。
    _emit_unhandled_org_candidates(
        detector,
        collected,
        text=text,
        org_events=org_events,
        emitted_org_events=emitted_org_events,
        source=source,
        bbox=bbox,
        block_id=block_id,
        skip_spans=skip_spans,
        original_text=original_text,
        shadow_index_map=shadow_index_map,
    )
    return tuple(_dedupe_spans(spans))


def _collect_org_suffix_events(text: str) -> tuple[_OrgSuffixEvent, ...]:
    suffixes = _ORG_SUFFIX_TOKENS
    lowered = text.lower()
    events: list[_OrgSuffixEvent] = []
    for suf in suffixes:
        if not suf:
            continue
        suf_lower = suf.lower()
        start = 0
        while True:
            index = lowered.find(suf_lower, start)
            if index < 0:
                break
            end = index + len(suf_lower)
            # 基于字符集粗判语种
            snippet = text[index:end]
            script = "zh" if any("\u4e00" <= ch <= "\u9fff" for ch in snippet) else "en"
            # 英文后缀必须是 token 边界，避免把 "lab" 命中在 "labs" 里。
            if script == "en" and suf_lower.isalpha():
                left = lowered[index - 1] if index - 1 >= 0 else ""
                right = lowered[end] if end < len(lowered) else ""
                if (left.isalnum() or left == "_") or (right.isalnum() or right == "_"):
                    start = end
                    continue
            events.append(_OrgSuffixEvent(start=index, end=end, suffix_text=text[index:end], script=script))
            start = end
    return tuple(sorted(events, key=lambda e: (e.start, e.end)))


def _should_stop_on_gap(gap: str) -> bool:
    if not gap:
        return False
    if any(ch in _HARD_STOP_CHARS for ch in gap):
        return True
    # 字段切换与硬停（email/phone/time/order/ocr_break）都视为停止
    if find_field_keyword(gap) is not None:
        return True
    hits = hard_stop_matches(gap)
    return bool(hits)


def _can_bridge_gap(gap: str) -> bool:
    stripped = gap.strip()
    if not stripped:
        return True
    if is_connector_text(stripped):
        return True
    return stripped in {"的", "之", "·", "•"}


def _tail_component_is_blacklisted(detector, text: str, component: AddressComponentMatch) -> bool:
    raise NotImplementedError


def _tail_component_is_blacklisted(text: str, component: AddressComponentMatch) -> bool:
    # 只做“keyword expansion”级别的黑名单回退（避免把正常的“小区”这类泛词在多组件地址里弹掉）。
    try:
        from privacyguard.infrastructure.pii.address.lexicon import _has_en_keyword_expansion_match, _has_zh_keyword_expansion_match

        if any("\u4e00" <= ch <= "\u9fff" for ch in component.text):
            return _has_zh_keyword_expansion_match(text, component.start, component.end, component.text)
        return _has_en_keyword_expansion_match(text, component.start, component.end, component.text)
    except Exception:
        return False


def _looks_like_terminal_mask(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and all(char in ".…*＊xX某 " for char in stripped)


def _allow_single_geo_as_address(component_type: str, level: ProtectionLevel) -> bool:
    if level == ProtectionLevel.STRONG:
        return component_type in {"province", "city", "district", "county", "state", "compound", "poi", "road", "street", "po_box", "postal_code"}
    if level == ProtectionLevel.BALANCED:
        return component_type in {"province", "city", "district", "compound", "poi", "road", "street", "po_box", "postal_code"}
    # WEAK：更保守
    return component_type in {"road", "street", "building", "unit", "floor", "room", "po_box", "postal_code"}


def _span_confidence_from_stack(stack: list[AddressComponentMatch]) -> float:
    base = 0.72
    if any(item.component_type in {"building", "unit", "floor", "room"} for item in stack):
        base += 0.12
    if any(item.component_type in {"road", "street"} for item in stack):
        base += 0.08
    if any(item.component_type in {"city", "district", "province", "state"} for item in stack):
        base += 0.04
    if len(stack) >= 3:
        base += 0.04
    return max(0.0, min(0.97, base))


def _emit_org_from_event(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], object],
    *,
    text: str,
    event: _OrgSuffixEvent,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    skip_spans: list[tuple[int, int]],
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
    left_limit: int,
) -> None:
    org_span = _grow_org_left(text, org_suffix_event=event, left_limit=left_limit)
    if org_span is None:
        return
    extracted = detector._extract_match(
        text,
        org_span[1],
        org_span[2],
        cleaner=detector._clean_organization_candidate,
        original_text=original_text,
        shadow_index_map=shadow_index_map,
    )
    if extracted is None:
        return
    value, span_start, span_end = extracted
    if not detector._is_organization_candidate(value, allow_weak_suffix=False):
        return
    detector._upsert_candidate(
        collected=collected,
        text=text,
        matched_text=value,
        attr_type=PIIAttributeType.ORGANIZATION,
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start,
        span_end=span_end,
        confidence=detector._organization_confidence(value, allow_weak_suffix=False),
        matched_by="regex_organization_suffix",
        skip_spans=skip_spans,
    )


def _handle_org_event_for_stack(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], object],
    *,
    text: str,
    stack: list[AddressComponentMatch],
    org_events: tuple[_OrgSuffixEvent, ...],
    emitted_org_events: set[tuple[int, int]],
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    skip_spans: list[tuple[int, int]],
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> None:
    if not stack:
        return
    tail = stack[-1]
    for event in org_events:
        if event.start < tail.end:
            continue
        gap = text[tail.end : event.start]
        if not _org_gap_allowed(gap, script=event.script):
            continue
        event_key = (event.start, event.end)
        if event_key not in emitted_org_events:
            # 距离为 0 时，如果当前地理点是省/市，则回退让给组织；否则地址截止但不回退。
            left_limit = tail.end
            if gap == "" and tail.component_type in {"province", "city"}:
                if len(stack) >= 2:
                    popped = stack.pop()
                    left_limit = popped.start
                else:
                    popped = stack.pop()
                    left_limit = max(0, popped.start)
            _emit_org_from_event(
                detector,
                collected,
                text=text,
                event=event,
                source=source,
                bbox=bbox,
                block_id=block_id,
                skip_spans=skip_spans,
                original_text=original_text,
                shadow_index_map=shadow_index_map,
                left_limit=left_limit,
            )
            emitted_org_events.add(event_key)
        return


def _org_gap_allowed(gap: str, *, script: str) -> bool:
    # 组织触发 gap 规则：允许空 gap；否则必须通过“无硬停/无字段切换/无介词/无符号”约束。
    if gap == "":
        return True
    if any(ch in _HARD_STOP_CHARS for ch in gap):
        return False
    if _OCR_SEMANTIC_BREAK_TOKEN in gap:
        return False
    if find_field_keyword(gap) is not None:
        return False
    if hard_stop_matches(gap):
        return False
    compact = gap.strip()
    if not compact:
        return False
    if any(not (ch.isalnum() or ("\u4e00" <= ch <= "\u9fff")) for ch in compact):
        return False
    if script == "zh":
        return not any(token in compact for token in _ZH_PREPOSITIONS)
    tokens = [item for item in compact.lower().split() if item]
    return not any(item in _EN_PREPOSITIONS for item in tokens)


def _grow_org_left(
    text: str,
    *,
    org_suffix_event: _OrgSuffixEvent,
    left_limit: int,
) -> tuple[str, int, int] | None:
    end = org_suffix_event.end
    start = org_suffix_event.start
    i = start - 1
    script = org_suffix_event.script
    while i >= left_limit:
        ch = text[i]
        if ch in _HARD_STOP_CHARS:
            break
        if text[max(0, i - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : i + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
            break
        # 允许英文组织名内部出现空格（如 "Acme Labs Inc"）
        if script == "en" and ch.isspace():
            i -= 1
            continue
        if ch.isspace() or (not (ch.isalnum() or ("\u4e00" <= ch <= "\u9fff"))):
            break
        if script == "zh" and ("a" <= ch.lower() <= "z"):
            break
        if script == "en" and ("\u4e00" <= ch <= "\u9fff"):
            break
        i -= 1
    start = i + 1
    candidate = text[start:end]
    if len(candidate.strip()) < 2:
        return None
    # 增强边界：前缀若是中英介词/结构助词，则停止（不把介词吞入组织名）。
    lowered_candidate = candidate.lower().strip()
    if any(lowered_candidate.startswith(f"{prep} ") for prep in _EN_PREPOSITIONS):
        return None
    if any(lowered_candidate.startswith(prefix) for prefix in ("的", "在", "于", "在于", "地")):
        return None
    # 必须后缀结尾
    lowered = lowered_candidate
    if not any(lowered.endswith(suf.lower()) for suf in _ORG_SUFFIX_TOKENS):
        return None
    return candidate, start, end


def _emit_unhandled_org_candidates(
    detector,
    collected: dict[tuple[str, str, int | None, int | None], object],
    *,
    text: str,
    org_events: tuple[_OrgSuffixEvent, ...],
    emitted_org_events: set[tuple[int, int]],
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    skip_spans: list[tuple[int, int]],
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...] | None,
) -> None:
    # 对尚未在地址扫描中处理过的组织后缀，补做一次独立探测。
    for event in org_events:
        key = (event.start, event.end)
        if key in emitted_org_events:
            continue
        _emit_org_from_event(
            detector,
            collected,
            text=text,
            event=event,
            source=source,
            bbox=bbox,
            block_id=block_id,
            skip_spans=skip_spans,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
            left_limit=0,
        )
        emitted_org_events.add(key)


def _dedupe_spans(spans: list[AddressSpan]) -> list[AddressSpan]:
    deduped: dict[tuple[int, int], AddressSpan] = {}
    for span in spans:
        key = (span.start, span.end)
        previous = deduped.get(key)
        if previous is None or span.confidence > previous.confidence:
            deduped[key] = span
    return sorted(deduped.values(), key=lambda item: (item.start, item.end))

