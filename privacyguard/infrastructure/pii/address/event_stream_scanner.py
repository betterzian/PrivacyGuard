from __future__ import annotations

from dataclasses import dataclass
import re

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
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
_TRAILING_ROOM_DIGITS_PATTERN = re.compile(r"^\s*(\d{1,4})(?!\d)")
# 与 lexicon 中「名字+关键词」绑定后缀一致：左边界微调仅当组件由该类后缀触发时启用。
_ZH_ADDRESS_KEYWORD_SUFFIXES = tuple(
    sorted(
        (
            "特别行政区",
            "自治区",
            "地区",
            "大道",
            "小区",
            "公寓",
            "大厦",
            "园区",
            "社区",
            "宿舍",
            "省",
            "市",
            "区",
            "县",
            "旗",
            "盟",
            "路",
            "街",
            "道",
            "巷",
            "弄",
        ),
        key=len,
        reverse=True,
    )
)
_EN_ADDRESS_KEYWORD_SUFFIXES = tuple(
    dict.fromkeys(
        (
            "boulevard",
            "blvd",
            "avenue",
            "ave",
            "street",
            "st",
            "road",
            "rd",
            "lane",
            "ln",
            "drive",
            "dr",
            "court",
            "ct",
            "place",
            "pl",
        )
    )
)
_EN_ADDRESS_KEYWORD_SUFFIXES = tuple(sorted(_EN_ADDRESS_KEYWORD_SUFFIXES, key=len, reverse=True))
# 单字行政后缀会与字段关键词规则误撞，左扩时跳过 find_field_keyword 检验。
_ZH_SINGLE_ADMIN_CHARS_FOR_LEFT_EXPAND = frozenset("区县市省镇乡村")


@dataclass(frozen=True, slots=True)
class _OrgSuffixEvent:
    start: int
    end: int
    suffix_text: str
    script: str  # "zh" | "en"


def _head_triggered_by_address_keyword(head: AddressComponentMatch) -> bool:
    raw = head.text.strip()
    if not raw:
        return False
    if any("\u4e00" <= ch <= "\u9fff" for ch in raw):
        return any(len(raw) > len(suf) and raw.endswith(suf) for suf in _ZH_ADDRESS_KEYWORD_SUFFIXES)
    lowered = raw.lower()
    return any(len(raw) > len(suf) and lowered.endswith(suf) for suf in _EN_ADDRESS_KEYWORD_SUFFIXES)


def _zh_prep_strictly_before_index(text: str, char_index: int) -> bool:
    """text[char_index] 左侧、与其之间仅可有空白，且紧挨前缀为中文介词。"""
    if char_index <= 0:
        return False
    pos = char_index - 1
    while pos >= 0 and text[pos].isspace():
        pos -= 1
    if pos < 0:
        return False
    end = pos
    for prep in sorted(_ZH_PREPOSITIONS, key=len, reverse=True):
        begin = end - len(prep) + 1
        if begin >= 0 and text[begin : end + 1] == prep:
            return all(text[k].isspace() for k in range(end + 1, char_index))
    return False


def _en_prep_strictly_before_index(text: str, word_start: int) -> bool:
    """将要吸收的英文词起始于 word_start；其左侧仅空白后紧挨的 token 须为英文介词。"""
    if word_start <= 0:
        return False
    pos = word_start - 1
    while pos >= 0 and text[pos].isspace():
        pos -= 1
    if pos < 0:
        return False
    end = pos + 1
    while pos >= 0 and text[pos].isascii() and (text[pos].isalnum() or text[pos] in "-'"):
        pos -= 1
    token = text[pos + 1 : end].lower()
    return token in _EN_PREPOSITIONS


def _expand_span_start_left_for_keyword_prefix(text: str, start: int, head: AddressComponentMatch) -> int:
    """左扩：默认最多 2 个汉字或 2 个英文词；第 3、4 个字/词仅当该段左缘「紧挨」介词时才允许。"""
    if start <= 0 or not _head_triggered_by_address_keyword(head):
        return start
    head_cjk = any("\u4e00" <= ch <= "\u9fff" for ch in head.text)
    pos = start - 1
    while pos >= 0 and text[pos].isspace():
        pos -= 1
    if pos < 0:
        return start
    left_cjk = "\u4e00" <= text[pos] <= "\u9fff"
    left_latin = text[pos].isascii() and text[pos].isalpha()
    if head_cjk and not left_cjk:
        return start
    if not head_cjk and head.text and re.search(r"[A-Za-z]", head.text):
        if not left_latin:
            return start
        return _expand_en_chars_left(text, start)
    if head_cjk:
        return _expand_zh_chars_left(text, start)
    return start


def _expand_zh_chars_left(text: str, start: int) -> int:
    new_start = start
    pos = start - 1
    taken = 0
    while pos >= 0:
        if taken >= 4:
            break
        ch = text[pos]
        if ch in _HARD_STOP_CHARS:
            break
        if text[max(0, pos - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : pos + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
            break
        if ch.isspace():
            pos -= 1
            continue
        if not ("\u4e00" <= ch <= "\u9fff"):
            break
        blocked = False
        for prep in sorted(_ZH_PREPOSITIONS, key=len, reverse=True):
            if pos + len(prep) <= len(text) and text.startswith(prep, pos):
                blocked = True
                break
        if blocked:
            break
        if taken >= 2 and not _zh_prep_strictly_before_index(text, pos):
            break
        segment = text[pos:start]
        if (
            not (len(segment) == 1 and segment in _ZH_SINGLE_ADMIN_CHARS_FOR_LEFT_EXPAND)
            and find_field_keyword(segment) is not None
        ) or hard_stop_matches(segment):
            break
        new_start = pos
        taken += 1
        pos -= 1
    return new_start


def _expand_en_chars_left(text: str, start: int) -> int:
    new_start = start
    pos = start - 1
    words = 0
    while pos >= 0:
        if words >= 4:
            break
        while pos >= 0 and text[pos].isspace():
            pos -= 1
        if pos < 0:
            break
        ch = text[pos]
        if ch in _HARD_STOP_CHARS:
            break
        if text[max(0, pos - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : pos + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
            break
        if not (ch.isascii() and (ch.isalnum() or ch in "-'")):
            break
        word_end = pos + 1
        while pos >= 0 and text[pos].isascii() and (text[pos].isalnum() or text[pos] in "-'"):
            pos -= 1
        word_start = pos + 1
        token = text[word_start:word_end].lower()
        if token in _EN_PREPOSITIONS:
            break
        if words >= 2 and not _en_prep_strictly_before_index(text, word_start):
            break
        slice_text = text[word_start:start]
        if find_field_keyword(slice_text) is not None or hard_stop_matches(slice_text):
            break
        new_start = word_start
        words += 1
    return new_start


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
    # 与地址在同一扫描器中直接处理组织事件（不在末尾补扫）
    for event in org_events:
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
        emitted_org_events.add((event.start, event.end))

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

        # 黑名单校准回退（总回退<=5）——放在组织联动之后执行。
        rollback = 0
        while stack and rollback < 5:
            if stack and _tail_component_is_blacklisted(text, stack[-1]):
                stack.pop()
                rollback += 1
                if not stack or rollback >= 5:
                    break
                continue
            break

        # 单组件特判：字段语境由 matched_by 决定（本扫描器默认非字段语境）
        if len(stack) == 1:
            single = stack[0]
            if not _allow_single_geo_as_address(single.component_type):
                stack = []

        if stack:
            start = stack[0].start
            start = _expand_span_start_left_for_keyword_prefix(text, start, stack[0])
            end = stack[-1].end
            tail_component = stack[-1]
            if tail_component.component_type in {"building", "unit", "floor"}:
                room_digits = _TRAILING_ROOM_DIGITS_PATTERN.match(text[end:])
                if room_digits is not None:
                    end += room_digits.end()
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


def _allow_single_geo_as_address(component_type: str) -> bool:
    return component_type in {
        "province",
        "city",
        "district",
        "county",
        "state",
        "compound",
        "poi",
        "road",
        "street",
        "po_box",
        "postal_code",
    }


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
        # 距离为 0 时，如果当前地理点是省/市，则回退让给组织；否则地址截止但不回退。
        left_limit = tail.end
        if gap == "" and tail.component_type in {"province", "city"}:
            if len(stack) >= 2:
                popped = stack.pop()
                left_limit = popped.start
            else:
                popped = stack.pop()
                left_limit = max(0, popped.start)
        if event_key not in emitted_org_events:
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


def _dedupe_spans(spans: list[AddressSpan]) -> list[AddressSpan]:
    deduped: dict[tuple[int, int], AddressSpan] = {}
    for span in spans:
        key = (span.start, span.end)
        previous = deduped.get(key)
        if previous is None or span.confidence > previous.confidence:
            deduped[key] = span
    return sorted(deduped.values(), key=lambda item: (item.start, item.end))

