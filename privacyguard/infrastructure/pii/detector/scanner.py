"""Detector 流式 clue 扫描器。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import load_china_geo_lexicon, load_en_geo_lexicon
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_company_suffixes,
    load_en_address_keyword_groups,
    load_en_given_names,
    load_en_surnames,
    load_family_names,
    load_label_specs,
    load_name_start_keywords,
    load_negative_address_words,
    load_negative_name_words,
    load_negative_org_words,
    load_negative_ui_words,
    load_zh_address_keyword_groups,
    load_zh_given_names,
)
from privacyguard.infrastructure.pii.detector.matcher import AhoMatcher, AhoPattern
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    BreakType,
    Clue,
    ClueBundle,
    ClueRole,
    DictionaryEntry,
    NameComponentHint,
    StreamInput,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

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
    PIIAttributeType.BANK_ACCOUNT: "<bank>",
    PIIAttributeType.PASSPORT_NUMBER: "<passport>",
    PIIAttributeType.DRIVER_LICENSE: "<driver_license>",
}

_HARD_PATTERNS: tuple[tuple[PIIAttributeType, str, re.Pattern[str], int], ...] = (
    (PIIAttributeType.EMAIL, "regex_email", re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"), 120),
    (PIIAttributeType.PHONE, "regex_phone_cn", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"), 118),
    (PIIAttributeType.PHONE, "regex_phone_us", re.compile(r"(?<!\w)(?:\(\d{3}\)\s*|\d{3}[-. ]?)\d{3}[-. ]\d{4}(?!\w)"), 117),
    (PIIAttributeType.ID_NUMBER, "regex_id_cn", re.compile(r"(?<![\w\d])\d{17}[\dXx](?![\w\d])"), 115),
    # passport: 仅白名单前缀（中国 E/G/D/P/H/M、美国 C 等）视为 hard clue。
    (PIIAttributeType.PASSPORT_NUMBER, "regex_passport_cn", re.compile(r"(?<![A-Za-z0-9])[EGDPHM]\d{8}(?![A-Za-z0-9])"), 108),
    (PIIAttributeType.PASSPORT_NUMBER, "regex_passport_us", re.compile(r"(?<![A-Za-z0-9])C\d{8}(?![A-Za-z0-9])"), 107),
    # driver_license: 中国驾照为 12 位纯数字。
    (PIIAttributeType.DRIVER_LICENSE, "regex_driver_license_cn", re.compile(r"(?<!\d)\d{12}(?!\d)"), 106),
)

# bank_account 通用正则——命中后额外做 Luhn 校验，通过归 bank_account，否则归 NUMERIC。
_BANK_ACCOUNT_CANDIDATE_PATTERN = re.compile(r"(?<!\d)\d(?:[ -]?\d){11,22}(?!\d)")

# 通用长数字兜底：12+ 位连续数字（可含空格/连字符），未被其他规则归类时归入 NUMERIC。
_GENERIC_NUMBER_PATTERN = re.compile(r"(?<!\d)\d(?:[ \t\-]?\d){11,30}(?!\d)")

_BREAK_PATTERNS: tuple[tuple[BreakType, str, re.Pattern[str]], ...] = (
    (BreakType.PUNCT, "break_punct", re.compile(r"[;；。！？!?]")),
    (BreakType.NEWLINE, "break_newline", re.compile(r"(?:\r?\n){2,}")),
)

_LABEL_FIELD_SEPARATOR_CHARS = ":：-—–=|"
_SEED_ROLES = frozenset({ClueRole.LABEL, ClueRole.START})
_SOFT_CONTENT_ROLES = frozenset(
    {
        ClueRole.SUFFIX,
        ClueRole.KEY,
        ClueRole.VALUE,
        ClueRole.SURNAME,
        ClueRole.GIVEN_NAME,
    }
)
_SOFT_CONTROL_ROLES = frozenset({ClueRole.NEGATIVE, ClueRole.CONNECTOR})

# 数字的非隐私上下文模式。
_NEGATIVE_NUMERIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\d{4}年"),
    re.compile(r"\d{1,3}%"),
    re.compile(r"第\d+[条项页章节]"),
    re.compile(r"No\.\d+"),
    re.compile(r"\d+(?:kg|cm|mm|m|km|g|ml|px|pt|em|rem|dp)\b"),
)

_ASCII_KEYWORD_CHARS_RE = re.compile(r"[A-Za-z0-9 #.'-]+")
_ASCII_LITERAL_CHARS_RE = re.compile(r"[A-Za-z0-9 .,'@_+\-#/&()]+")
_POSTAL_CODE_PATTERN = re.compile(r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)")

# 银行卡 PAN：13–19 位数字，中间可含空格/制表/连字符；须通过 Luhn 校验。
# 优先级高于 regex_bank_account，硬冲突时同长度下先收录的卡号线索优先保留。
_CARD_PAN_PATTERN = re.compile(r"(?<!\d)\d(?:[ \t\-]?\d){12,18}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    """标准 Luhn，用于银行卡号校验（digits 须为纯数字）。"""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for index, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True, slots=True)
class _ScanSegment:
    text: str
    raw_start: int
    folded_text: str


@dataclass(frozen=True, slots=True)
class _AddressPatternPayload:
    component_type: AddressComponentType
    canonical_text: str


def build_clue_bundle(
    stream: StreamInput,
    *,
    ctx: DetectContext,
    session_entries: tuple[DictionaryEntry, ...],
    local_entries: tuple[DictionaryEntry, ...],
    locale_profile: str,
) -> ClueBundle:
    literal_pattern_cache: dict[tuple[str, bool], re.Pattern[str]] = {}
    ocr_break_spans = _find_ocr_break_spans(stream.raw_text)
    hard_clues = _resolve_hard_conflicts(
        [
            *_scan_hard_patterns(ctx, stream.raw_text, ignored_spans=ocr_break_spans),
            *_scan_dictionary_hard_clues(
                ctx,
                stream.raw_text,
                session_entries,
                source_kind="session",
                pattern_cache=literal_pattern_cache,
                ignored_spans=ocr_break_spans,
            ),
            *_scan_dictionary_hard_clues(
                ctx,
                stream.raw_text,
                local_entries,
                source_kind="local",
                pattern_cache=literal_pattern_cache,
                ignored_spans=ocr_break_spans,
            ),
        ]
    )
    scan_segments = _build_soft_scan_segments(stream.raw_text, hard_clues, extra_blocked_spans=ocr_break_spans)
    label_clues = tuple(
        clue
        for segment in scan_segments
        for clue in _scan_label_clues(ctx, segment)
    )
    all_clues = [
        *hard_clues,
        *label_clues,
        *_scan_ocr_break_clues(ctx, ocr_break_spans),
        *(clue for segment in scan_segments for clue in _scan_break_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_name_start_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_family_name_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_en_surname_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_en_given_name_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_zh_given_name_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_connector_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_company_suffix_clues(ctx, segment)),
        *(clue for segment in scan_segments for clue in _scan_address_clues(ctx, segment, locale_profile=locale_profile)),
        *(clue for segment in scan_segments for clue in _scan_negative_clues(ctx, segment)),
    ]
    deduped_clues = _dedupe_clues(all_clues)
    reduced_clues = _resolve_clue_overlaps(stream.raw_text, deduped_clues)
    ordered_clues = tuple(sorted(reduced_clues, key=lambda item: (item.start, -item.priority, item.end)))
    return ClueBundle(all_clues=ordered_clues)


def _scan_hard_patterns(ctx: DetectContext, text: str, *, ignored_spans: tuple[tuple[int, int], ...] = ()) -> list[Clue]:
    clues: list[Clue] = []
    hard_spans: list[tuple[int, int]] = []
    for attr_type, matched_by, pattern, priority in _HARD_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if not value:
                continue
            if _overlaps_any(match.start(), match.end(), ignored_spans):
                continue
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    role=ClueRole.HARD,
                    attr_type=attr_type,
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    priority=priority,
                    source_kind=matched_by,
                    hard_source="regex",
                    placeholder=_PLACEHOLDER_BY_ATTR.get(attr_type, f"<{attr_type.value}>"),
                )
            )
            hard_spans.append((match.start(), match.end()))
    # 银行卡 PAN（Luhn 校验）。
    for match in _CARD_PAN_PATTERN.finditer(text):
        if _overlaps_any(match.start(), match.end(), ignored_spans):
            continue
        value = match.group(0).strip()
        digits = re.sub(r"\D", "", value)
        if not _luhn_valid(digits):
            continue
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.HARD,
                attr_type=PIIAttributeType.CARD_NUMBER,
                start=match.start(),
                end=match.end(),
                text=value,
                priority=114,
                source_kind="regex_card_pan",
                hard_source="regex",
                placeholder=_PLACEHOLDER_BY_ATTR[PIIAttributeType.CARD_NUMBER],
            )
        )
        hard_spans.append((match.start(), match.end()))
    # bank_account 候选：Luhn 通过→bank_account，否则→NUMERIC 兜底。
    for match in _BANK_ACCOUNT_CANDIDATE_PATTERN.finditer(text):
        if _overlaps_any(match.start(), match.end(), ignored_spans):
            continue
        if _overlaps_any(match.start(), match.end(), tuple(hard_spans)):
            continue
        value = match.group(0).strip()
        digits = re.sub(r"\D", "", value)
        if _luhn_valid(digits):
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    role=ClueRole.HARD,
                    attr_type=PIIAttributeType.BANK_ACCOUNT,
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    priority=110,
                    source_kind="regex_bank_account",
                    hard_source="regex",
                    placeholder=_PLACEHOLDER_BY_ATTR[PIIAttributeType.BANK_ACCOUNT],
                )
            )
        else:
            # 不符合 Luhn 的长数字归入 NUMERIC 兜底。
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    role=ClueRole.HARD,
                    attr_type=PIIAttributeType.NUMERIC,
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    priority=90,
                    source_kind="regex_generic_number",
                    hard_source="regex",
                    placeholder="<numeric>",
                )
            )
        hard_spans.append((match.start(), match.end()))
    # 通用长数字兜底：未被以上规则覆盖的长数字串归入 NUMERIC。
    for match in _GENERIC_NUMBER_PATTERN.finditer(text):
        if _overlaps_any(match.start(), match.end(), ignored_spans):
            continue
        if _overlaps_any(match.start(), match.end(), tuple(hard_spans)):
            continue
        value = match.group(0).strip()
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.HARD,
                attr_type=PIIAttributeType.NUMERIC,
                start=match.start(),
                end=match.end(),
                text=value,
                priority=85,
                source_kind="regex_generic_number",
                hard_source="regex",
                placeholder="<numeric>",
            )
        )
    return clues


def _scan_dictionary_hard_clues(
    ctx: DetectContext,
    text: str,
    entries: tuple[DictionaryEntry, ...],
    *,
    source_kind: str,
    pattern_cache: dict[tuple[str, bool], re.Pattern[str]],
    ignored_spans: tuple[tuple[int, int], ...] = (),
) -> list[Clue]:
    clues: list[Clue] = []
    priority = 300 if source_kind == "session" else 290
    for entry in entries:
        for variant in sorted({item for item in entry.variants if str(item).strip()}, key=len, reverse=True):
            for match in _iter_literal_matches(text, variant, pattern_cache=pattern_cache):
                if _overlaps_any(match.start(), match.end(), ignored_spans):
                    continue
                clues.append(
                    Clue(
                        clue_id=ctx.next_clue_id(),
                        role=ClueRole.HARD,
                        attr_type=entry.attr_type,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(0),
                        priority=priority,
                        source_kind=entry.matched_by,
                        hard_source=source_kind,
                        placeholder=_PLACEHOLDER_BY_ATTR.get(entry.attr_type, f"<{entry.attr_type.value}>"),
                        source_metadata={key: list(values) for key, values in entry.metadata.items()},
                    )
                )
    return clues


def _scan_label_clues(ctx: DetectContext, segment: _ScanSegment) -> tuple[Clue, ...]:
    matches: list[tuple[int, int, object]] = []
    for match in _label_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        matches.append((match.start, match.end, match.payload))
    accepted: list[tuple[int, int, object]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, spec in sorted(matches, key=lambda item: (-(item[1] - item[0]), -len(item[2].keyword), -item[2].priority, item[0])):
        if any(not (end <= left or start >= right) for left, right in occupied):
            continue
        occupied.append((start, end))
        accepted.append((start, end, spec))
    clues: list[Clue] = []
    for start, end, spec in sorted(accepted, key=lambda item: (item[0], item[1])):
        raw_start, raw_end = _segment_span_to_raw(segment, start, end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.LABEL,
                attr_type=spec.attr_type,
                start=raw_start,
                end=raw_end,
                text=spec.keyword,
                priority=spec.priority,
                source_kind=spec.source_kind,
                component_hint=spec.component_hint,
                ocr_source_kind=spec.ocr_source_kind,
            )
        )
    return tuple(clues)


def _scan_break_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for break_type, source_kind, pattern in _BREAK_PATTERNS:
        for match in pattern.finditer(segment.text):
            raw_start, raw_end = _segment_span_to_raw(segment, match.start(), match.end())
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    role=ClueRole.BREAK,
                    attr_type=None,
                    start=raw_start,
                    end=raw_end,
                    text=match.group(0),
                    priority=480,
                    source_kind=source_kind,
                    break_type=break_type,
                )
            )
    return _dedupe_clues(clues)


def _scan_ocr_break_clues(ctx: DetectContext, ocr_break_spans: tuple[tuple[int, int], ...]) -> list[Clue]:
    clues: list[Clue] = []
    for start, end in ocr_break_spans:
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.BREAK,
                attr_type=None,
                start=start,
                end=end,
                text=_OCR_SEMANTIC_BREAK_TOKEN,
                priority=500,
                source_kind="break_ocr",
                break_type=BreakType.OCR,
            )
        )
    return clues


def _scan_name_start_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _name_start_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.START,
                attr_type=PIIAttributeType.NAME,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=230,
                source_kind="name_start",
            )
        )
    return _dedupe_clues(clues)


def _scan_family_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _family_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        tail = segment.text[match.end : match.end + 4]
        if any(keyword in tail for keyword in ("省", "市", "区", "县", "旗", "路", "街", "道", "大道", "小区", "单元", "栋", "室", "住址", "地址")):
            continue
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.SURNAME,
                attr_type=PIIAttributeType.NAME,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=220,
                source_kind="family_name",
            )
        )
    return _dedupe_clues(clues)


def _scan_en_surname_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文姓氏，产出 SURNAME clue。"""
    clues: list[Clue] = []
    for match in _en_surname_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.SURNAME,
                attr_type=PIIAttributeType.NAME,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=218,
                source_kind="en_surname",
                component_hint=NameComponentHint.FAMILY,
            )
        )
    return _dedupe_clues(clues)


def _scan_en_given_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文名字（given name），产出 GIVEN_NAME clue。"""
    clues: list[Clue] = []
    for match in _en_given_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.GIVEN_NAME,
                attr_type=PIIAttributeType.NAME,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=215,
                source_kind="en_given_name",
                component_hint=NameComponentHint.GIVEN,
            )
        )
    return _dedupe_clues(clues)


def _scan_zh_given_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描中文名字（given name），产出 GIVEN_NAME clue。"""
    clues: list[Clue] = []
    for match in _zh_given_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.GIVEN_NAME,
                attr_type=PIIAttributeType.NAME,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=210,
                source_kind="zh_given_name",
                component_hint=NameComponentHint.GIVEN,
            )
        )
    return _dedupe_clues(clues)


def _scan_connector_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描连接词/介词，产出 CONNECTOR clue。

    中文：的、得、是、于、去。英文：is、or、at。
    这类 clue 不起栈，但会被 stack 当作软控制信号读取。
    """
    clues: list[Clue] = []
    for match in _connector_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.CONNECTOR,
                attr_type=None,
                start=raw_start,
                end=raw_end,
                text=match.matched_text,
                priority=150,
                source_kind=str(match.payload),
            )
        )
    return _dedupe_clues(clues)


def _scan_company_suffix_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _company_suffix_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.SUFFIX,
                attr_type=PIIAttributeType.ORGANIZATION,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                priority=240,
                source_kind="company_suffix",
            )
        )
    return _dedupe_clues(clues)


def _scan_address_clues(ctx: DetectContext, segment: _ScanSegment, *, locale_profile: str) -> list[Clue]:
    clues: list[Clue] = []
    if locale_profile in {"zh_cn", "mixed"}:
        clues.extend(_scan_zh_address_clues(ctx, segment))
    if locale_profile in {"en_us", "mixed"}:
        clues.extend(_scan_en_address_clues(ctx, segment))
    return _dedupe_clues(clues)


def _scan_zh_address_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _zh_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                priority=205,
                source_kind="geo_db",
                component_type=payload.component_type,
            )
        )
    for match in _zh_address_key_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                priority=204,
                source_kind="address_keyword",
                component_type=payload.component_type,
            )
        )
    return clues


def _scan_en_address_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _en_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                priority=205,
                source_kind="geo_db",
                component_type=payload.component_type,
            )
        )
    for match in _en_address_key_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                start=raw_start,
                end=raw_end,
                text=match.matched_text,
                priority=204,
                source_kind="address_keyword",
                component_type=payload.component_type,
            )
        )
    for token_match in _POSTAL_CODE_PATTERN.finditer(segment.text):
        raw_start, raw_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                start=raw_start,
                end=raw_end,
                text=token_match.group(0),
                priority=203,
                source_kind="postal_value",
                component_type=AddressComponentType.POSTAL_CODE,
            )
        )
    return clues


def _scan_negative_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描负向 clue（黑名单词组 + 数字非隐私上下文模式）。"""
    clues: list[Clue] = []
    # 词组黑名单（AC 多模匹配）。
    for match in _negative_word_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                role=ClueRole.NEGATIVE,
                attr_type=None,
                start=raw_start,
                end=raw_end,
                text=match.matched_text,
                priority=600,
                source_kind=str(match.payload),
            )
        )
    # 数字非隐私上下文模式（年份、百分比、序号、计量单位等）。
    for pattern in _NEGATIVE_NUMERIC_PATTERNS:
        for token_match in pattern.finditer(segment.text):
            raw_start, raw_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    role=ClueRole.NEGATIVE,
                    attr_type=None,
                    start=raw_start,
                    end=raw_end,
                    text=token_match.group(0),
                    priority=600,
                    source_kind="negative_numeric_context",
                )
            )
    return clues


@lru_cache(maxsize=1)
def _negative_word_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=word,
                payload=source_kind,
                ascii_boundary=_needs_ascii_keyword_boundary(word),
            )
            for word, source_kind in _iter_negative_word_specs()
        )
    )


def _iter_negative_word_specs() -> tuple[tuple[str, str], ...]:
    return tuple(
        [
            *((word, "negative_name_word") for word in load_negative_name_words()),
            *((word, "negative_address_word") for word in load_negative_address_words()),
            *((word, "negative_org_word") for word in load_negative_org_words()),
            *((word, "negative_ui_word") for word in load_negative_ui_words()),
        ]
    )


def _resolve_hard_conflicts(clues: list[Clue]) -> tuple[Clue, ...]:
    resolved: list[Clue] = []
    for clue in sorted(clues, key=lambda item: (item.start, item.end, -item.priority)):
        replaced = False
        for index, existing in enumerate(list(resolved)):
            if clue.end <= existing.start or clue.start >= existing.end:
                continue
            if _hard_clue_wins(clue, existing):
                resolved[index] = clue
            replaced = True
            break
        if not replaced:
            resolved.append(clue)
    resolved.sort(key=lambda item: (item.start, item.end, -item.priority))
    return tuple(resolved)


def _hard_clue_wins(incoming: Clue, existing: Clue) -> bool:
    incoming_length = incoming.end - incoming.start
    existing_length = existing.end - existing.start
    if incoming_length != existing_length:
        return incoming_length > existing_length
    return _HARD_SOURCE_PRIORITY.get(str(incoming.hard_source or ""), 0) > _HARD_SOURCE_PRIORITY.get(str(existing.hard_source or ""), 0)


def _build_soft_scan_segments(
    text: str,
    hard_clues: tuple[Clue, ...],
    *,
    extra_blocked_spans: tuple[tuple[int, int], ...] = (),
) -> tuple[_ScanSegment, ...]:
    segments: list[_ScanSegment] = []
    blocked_spans = sorted(
        [(clue.start, clue.end) for clue in hard_clues] + list(extra_blocked_spans),
        key=lambda item: (item[0], item[1]),
    )
    cursor = 0
    for start, end in blocked_spans:
        if start < cursor:
            continue
        if cursor < start:
            segment_text = text[cursor:start]
            segments.append(_ScanSegment(text=segment_text, raw_start=cursor, folded_text=segment_text.lower()))
        cursor = end
    if cursor < len(text):
        segment_text = text[cursor:]
        segments.append(_ScanSegment(text=segment_text, raw_start=cursor, folded_text=segment_text.lower()))
    return tuple(segments)


def _segment_span_to_raw(segment: _ScanSegment, start: int, end: int) -> tuple[int, int]:
    return (segment.raw_start + start, segment.raw_start + end)


def _find_ocr_break_spans(text: str) -> tuple[tuple[int, int], ...]:
    if _OCR_SEMANTIC_BREAK_TOKEN not in text:
        return ()
    return tuple((match.start(), match.end()) for match in re.finditer(re.escape(_OCR_SEMANTIC_BREAK_TOKEN), text))


def _needs_ascii_keyword_boundary(keyword: str) -> bool:
    return bool(_ASCII_KEYWORD_CHARS_RE.fullmatch(keyword))


def _compile_literal_pattern(literal: str, *, ascii_boundary: bool) -> re.Pattern[str]:
    escaped = re.escape(literal)
    if ascii_boundary:
        return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", flags=re.IGNORECASE)
    return re.compile(escaped)


def _iter_literal_matches(text: str, literal: str, *, pattern_cache: dict[tuple[str, bool], re.Pattern[str]]):
    ascii_boundary = bool(_ASCII_LITERAL_CHARS_RE.fullmatch(literal))
    cache_key = (literal, ascii_boundary)
    pattern = pattern_cache.get(cache_key)
    if pattern is None:
        pattern = _compile_literal_pattern(literal, ascii_boundary=ascii_boundary)
        pattern_cache[cache_key] = pattern
    return pattern.finditer(text)


@lru_cache(maxsize=1)
def _label_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=spec.keyword,
                payload=spec,
                ascii_boundary=spec.ascii_boundary,
            )
            for spec in load_label_specs()
        )
    )


@lru_cache(maxsize=1)
def _name_start_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=keyword,
                payload=keyword,
                ascii_boundary=_needs_ascii_keyword_boundary(keyword),
            )
            for keyword in load_name_start_keywords()
        )
    )


@lru_cache(maxsize=1)
def _family_name_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=surname,
                payload=surname,
                ascii_boundary=_needs_ascii_keyword_boundary(surname),
            )
            for surname in load_family_names()
        )
    )


@lru_cache(maxsize=1)
def _en_surname_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=surname,
                payload=surname,
                ascii_boundary=True,
            )
            for surname in load_en_surnames()
        )
    )


@lru_cache(maxsize=1)
def _en_given_name_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=name,
                payload=name,
                ascii_boundary=True,
            )
            for name in load_en_given_names()
        )
    )


@lru_cache(maxsize=1)
def _zh_given_name_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=name,
                payload=name,
                ascii_boundary=_needs_ascii_keyword_boundary(name),
            )
            for name in load_zh_given_names()
        )
    )


# 连接词/介词：中文（的、得、是、于、去）、英文（is、or、at）。
_CONNECTOR_SPECS: tuple[tuple[str, str], ...] = (
    ("的", "connector_zh"),
    ("得", "connector_zh"),
    ("是", "connector_zh"),
    ("于", "connector_zh"),
    ("去", "connector_zh"),
    ("is", "connector_en"),
    ("or", "connector_en"),
    ("at", "connector_en"),
)


@lru_cache(maxsize=1)
def _connector_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=word,
                payload=source_kind,
                ascii_boundary=_needs_ascii_keyword_boundary(word),
            )
            for word, source_kind in _CONNECTOR_SPECS
        )
    )


@lru_cache(maxsize=1)
def _company_suffix_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=suffix,
                payload=suffix,
                ascii_boundary=_needs_ascii_keyword_boundary(suffix),
            )
            for suffix in load_company_suffixes()
        )
    )


@lru_cache(maxsize=1)
def _zh_address_value_matcher() -> AhoMatcher:
    lexicon = load_china_geo_lexicon()
    direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}
    geo_specs = (
        (AddressComponentType.PROVINCE, tuple(item for item in lexicon.provinces if item not in direct_city_names)),
        (AddressComponentType.CITY, tuple([*lexicon.cities, *sorted(direct_city_names)])),
        (AddressComponentType.DISTRICT, lexicon.districts),
    )
    patterns: list[AhoPattern] = []
    for component_type, names in geo_specs:
        for name in sorted(set(names), key=len, reverse=True):
            patterns.append(
                AhoPattern(
                    text=name,
                    payload=_AddressPatternPayload(component_type=component_type, canonical_text=name),
                    ascii_boundary=_needs_ascii_keyword_boundary(name),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _zh_address_key_matcher() -> AhoMatcher:
    patterns: list[AhoPattern] = []
    for group in load_zh_address_keyword_groups():
        for keyword in group.keywords:
            patterns.append(
                AhoPattern(
                    text=keyword,
                    payload=_AddressPatternPayload(component_type=group.component_type, canonical_text=keyword),
                    ascii_boundary=_needs_ascii_keyword_boundary(keyword),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _en_address_value_matcher() -> AhoMatcher:
    lexicon = load_en_geo_lexicon()
    geo_specs = (
        (AddressComponentType.STATE, tuple([*lexicon.tier_a_state_names, *lexicon.tier_a_state_codes])),
        (AddressComponentType.CITY, lexicon.tier_b_places),
    )
    patterns: list[AhoPattern] = []
    for component_type, names in geo_specs:
        for name in sorted(set(names), key=len, reverse=True):
            patterns.append(
                AhoPattern(
                    text=name,
                    payload=_AddressPatternPayload(component_type=component_type, canonical_text=name),
                    ascii_boundary=_needs_ascii_keyword_boundary(name),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _en_address_key_matcher() -> AhoMatcher:
    patterns: list[AhoPattern] = []
    for group in load_en_address_keyword_groups():
        for keyword in group.keywords:
            patterns.append(
                AhoPattern(
                    text=keyword,
                    payload=_AddressPatternPayload(component_type=group.component_type, canonical_text=keyword),
                    ascii_boundary=_needs_ascii_keyword_boundary(keyword),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


def _dedupe_clues(clues: list[Clue]) -> list[Clue]:
    """只去掉完全同义的 clue，不在这里做覆盖裁决。"""

    seen: set[tuple[object, ...]] = set()
    ordered: list[Clue] = []
    for clue in sorted(
        clues,
        key=lambda item: (
            item.start,
            -(item.end - item.start),
            -item.priority,
            item.role.value,
            item.attr_type.value if item.attr_type is not None else "",
            item.component_type or "",
            item.break_type or "",
        ),
    ):
        key = (
            clue.role,
            clue.attr_type,
            clue.component_type,
            clue.component_hint,
            clue.break_type,
            clue.hard_source,
            clue.source_kind,
            clue.start,
            clue.end,
            clue.text.lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        ordered.append(clue)
    return sorted(ordered, key=lambda item: (item.start, item.end, -item.priority))


def _resolve_clue_overlaps(raw_text: str, clues: list[Clue]) -> list[Clue]:
    """按显式矩阵裁决 scanner clue 重叠关系。"""

    survivors = list(clues)
    hard_spans = tuple((clue.start, clue.end) for clue in survivors if clue.role == ClueRole.HARD)
    survivors = [
        clue
        for clue in survivors
        if clue.role == ClueRole.HARD or not _overlaps_any(clue.start, clue.end, hard_spans)
    ]

    break_spans = tuple((clue.start, clue.end) for clue in survivors if clue.role == ClueRole.BREAK)
    survivors = [
        clue
        for clue in survivors
        if clue.role in {ClueRole.HARD, ClueRole.BREAK} or not _overlaps_any(clue.start, clue.end, break_spans)
    ]

    seed_winner_ids = {
        clue.clue_id
        for clue in _resolve_seed_conflicts(
            [clue for clue in survivors if clue.role in _SEED_ROLES]
        )
    }
    survivors = [
        clue
        for clue in survivors
        if clue.role not in _SEED_ROLES or clue.clue_id in seed_winner_ids
    ]

    seed_spans = tuple((clue.start, clue.end) for clue in survivors if clue.role in _SEED_ROLES)
    survivors = [
        clue
        for clue in survivors
        if clue.role not in _SOFT_CONTROL_ROLES or not _overlaps_any(clue.start, clue.end, seed_spans)
    ]

    start_spans = tuple((clue.start, clue.end) for clue in survivors if clue.role == ClueRole.START)
    survivors = [
        clue
        for clue in survivors
        if clue.role not in _SOFT_CONTENT_ROLES or not _overlaps_any(clue.start, clue.end, start_spans)
    ]

    dropped_ids: set[str] = set()
    label_clues = [clue for clue in survivors if clue.role == ClueRole.LABEL]
    soft_clues = [clue for clue in survivors if clue.role in _SOFT_CONTENT_ROLES]
    break_clues = [clue for clue in survivors if clue.role == ClueRole.BREAK]
    break_start_map = _build_break_start_map(break_clues)
    break_end_map = _build_break_end_map(break_clues)
    for label in label_clues:
        overlapping_soft = [
            clue
            for clue in soft_clues
            if clue.clue_id not in dropped_ids and _clues_overlap(label, clue)
        ]
        if not overlapping_soft:
            continue
        same_attr_conflicts = [clue for clue in overlapping_soft if clue.attr_type == label.attr_type]
        if _label_loses_to_same_attr_soft(raw_text, label, same_attr_conflicts, break_start_map, break_end_map):
            dropped_ids.add(label.clue_id)
            for clue in overlapping_soft:
                if clue.attr_type != label.attr_type:
                    dropped_ids.add(clue.clue_id)
            continue
        for clue in overlapping_soft:
            dropped_ids.add(clue.clue_id)

    return [
        clue
        for clue in survivors
        if clue.clue_id not in dropped_ids
    ]


def _resolve_seed_conflicts(seed_clues: list[Clue]) -> list[Clue]:
    """在重叠的 label/start 连通块内只保留一个 winner。"""

    if not seed_clues:
        return []
    sorted_clues = sorted(seed_clues, key=lambda item: (item.start, item.end, -item.priority))
    groups: list[list[Clue]] = []
    current_group: list[Clue] = [sorted_clues[0]]
    current_end = sorted_clues[0].end
    for clue in sorted_clues[1:]:
        if clue.start < current_end:
            current_group.append(clue)
            current_end = max(current_end, clue.end)
            continue
        groups.append(current_group)
        current_group = [clue]
        current_end = clue.end
    groups.append(current_group)
    return [max(group, key=_seed_winner_key) for group in groups]


def _seed_winner_key(clue: Clue) -> tuple[int, int, int, int]:
    return (
        clue.end - clue.start,
        clue.priority,
        -clue.start,
        clue.end,
    )


def _label_loses_to_same_attr_soft(
    raw_text: str,
    label_clue: Clue,
    same_attr_conflicts: list[Clue],
    break_start_map: dict[int, list[Clue]],
    break_end_map: dict[int, list[Clue]],
) -> bool:
    """同属性 label vs soft content：先比长度，等长再看字段边界。"""

    if not same_attr_conflicts:
        return False
    label_length = label_clue.end - label_clue.start
    for clue in same_attr_conflicts:
        clue_length = clue.end - clue.start
        if label_length > clue_length:
            continue
        if label_length < clue_length:
            return True
        if not _label_wins_equal_length_conflict(raw_text, label_clue, break_start_map, break_end_map):
            return True
    return False


def _label_wins_equal_length_conflict(
    raw_text: str,
    label_clue: Clue,
    break_start_map: dict[int, list[Clue]],
    break_end_map: dict[int, list[Clue]],
) -> bool:
    """等长冲突时，优先保留更像字段标题的 label。"""

    if _has_label_field_separator_after(raw_text, label_clue):
        return True
    return _label_is_wrapped_by_boundaries(raw_text, label_clue, break_start_map, break_end_map)


def _has_label_field_separator_after(raw_text: str, label_clue: Clue) -> bool:
    index = _skip_whitespace_right(raw_text, label_clue.end)
    return index < len(raw_text) and raw_text[index] in _LABEL_FIELD_SEPARATOR_CHARS


def _label_is_wrapped_by_boundaries(
    raw_text: str,
    label_clue: Clue,
    break_start_map: dict[int, list[Clue]],
    break_end_map: dict[int, list[Clue]],
) -> bool:
    return (
        _is_left_label_boundary(raw_text, label_clue.start, break_end_map)
        and _is_right_label_boundary(raw_text, label_clue.end, break_start_map)
    )


def _build_break_start_map(break_clues: list[Clue]) -> dict[int, list[Clue]]:
    mapping: dict[int, list[Clue]] = {}
    for clue in break_clues:
        mapping.setdefault(clue.start, []).append(clue)
    return mapping


def _build_break_end_map(break_clues: list[Clue]) -> dict[int, list[Clue]]:
    mapping: dict[int, list[Clue]] = {}
    for clue in break_clues:
        mapping.setdefault(clue.end, []).append(clue)
    return mapping


def _is_left_label_boundary(raw_text: str, start: int, break_end_map: dict[int, list[Clue]]) -> bool:
    index = start
    while index > 0:
        if index in break_end_map:
            return True
        previous = raw_text[index - 1]
        if previous.isspace():
            index -= 1
            continue
        return False
    return True


def _is_right_label_boundary(raw_text: str, end: int, break_start_map: dict[int, list[Clue]]) -> bool:
    index = end
    while index < len(raw_text):
        if index in break_start_map:
            return True
        current = raw_text[index]
        if current.isspace():
            index += 1
            continue
        return False
    return True


def _skip_whitespace_right(raw_text: str, start: int) -> int:
    index = start
    while index < len(raw_text) and raw_text[index].isspace():
        index += 1
    return index


def _clues_overlap(left: Clue, right: Clue) -> bool:
    return not (left.end <= right.start or left.start >= right.end)


def _overlaps_any(start: int, end: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)
