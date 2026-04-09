"""Detector 流式 clue 扫描器。"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import load_en_geo_lexicon, load_zh_geo_lexicon
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
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
    DictionaryEntry,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK, _OCR_INLINE_GAP_TOKEN

_HARD_SOURCE_PRIORITY = {
    "session": 4,
    "local": 3,
    "prompt": 2,
    "regex": 1,
}

_FAMILY_ORDER: dict[ClueFamily, int] = {
    ClueFamily.ADDRESS: 0,
    ClueFamily.NAME: 1,
    ClueFamily.ORGANIZATION: 2,
    ClueFamily.STRUCTURED: 3,
    ClueFamily.CONTROL: 4,
}


def _family_order(family: ClueFamily) -> int:
    return _FAMILY_ORDER.get(family, 99)


def _attr_to_family(attr_type: PIIAttributeType | None) -> ClueFamily:
    """从 attr_type 推导 ClueFamily。"""
    if attr_type is None:
        return ClueFamily.CONTROL
    _MAP = {
        PIIAttributeType.NAME: ClueFamily.NAME,
        PIIAttributeType.ORGANIZATION: ClueFamily.ORGANIZATION,
        PIIAttributeType.ADDRESS: ClueFamily.ADDRESS,
    }
    return _MAP.get(attr_type, ClueFamily.STRUCTURED)

_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.BANK_NUMBER: "<bank>",
    PIIAttributeType.PASSPORT_NUMBER: "<passport>",
    PIIAttributeType.DRIVER_LICENSE: "<driver_license>",
}

_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")

# 与 ``pii_value._TIME_PATTERN`` 一致的时钟片段（时 0–23，分/秒 0–59，冒号半角/全角）。
_TIME_CLOCK_STRICT = r"(?:[01]?\d|2[0-3])[:：][0-5]\d(?:[:：][0-5]\d)?"

# 时间/日期模式——先行匹配并排除，防止其中的数字被当作候选片段。
_TIME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("time_datetime", re.compile(rf"\d{{4}}[-/]\d{{1,2}}[-/]\d{{1,2}}(?:[T ]{_TIME_CLOCK_STRICT})?")),
    ("time_date_mdy", re.compile(r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}")),
    ("time_clock", re.compile(_TIME_CLOCK_STRICT)),
    ("time_zh_date", re.compile(r"\d{4}年\d{1,2}月\d{1,2}日")),
)

# 以下三类需在左右两侧满足「空白 / OCR 块界 / 链内间隙」之一（或紧贴文本首尾），避免粘在语句或数值中间。
_TIME_KINDS_WITH_TOKEN_BOUNDARY = frozenset({"time_datetime", "time_date_mdy", "time_clock"})


def _time_match_adjacent_ok(text: str, start: int, end: int) -> bool:
    """TIME 匹配片段左侧与右侧是否仅邻接空白、``OCR_BREAK``、``inline_gap`` 标记或串首/串尾。"""
    if start < 0 or end > len(text) or start > end:
        return False
    if start > 0:
        left_ch = text[start - 1]
        if left_ch.isspace() or left_ch == _OCR_INLINE_GAP_TOKEN:
            pass
        elif len(OCR_BREAK) <= start and text[start - len(OCR_BREAK) : start] == OCR_BREAK:
            pass
        else:
            return False
    if end < len(text):
        right_ch = text[end]
        if right_ch.isspace() or right_ch == _OCR_INLINE_GAP_TOKEN:
            pass
        elif end + len(OCR_BREAK) <= len(text) and text[end : end + len(OCR_BREAK)] == OCR_BREAK:
            pass
        else:
            return False
    return True

# 通用数字片段：允许常见“电话号码写法”的连接符。
# 目的：把 "+86 139-1234-1234" 这类写法抽成一个片段，后续再在 structured stack 中统一去连接符/去国家码做校验。
_DIGIT_FRAGMENT_PATTERN = re.compile(r"\+?\d(?:[ \-()]*\d)*")

# 混合片段：字母数字混合（至少包含一个数字和一个字母）。
_ALNUM_FRAGMENT_PATTERN = re.compile(r"(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]+")

_BREAK_PATTERNS: tuple[tuple[BreakType, str, re.Pattern[str]], ...] = (
    (BreakType.PUNCT, "break_punct", re.compile(r"[;；。！？!?]")),
    (BreakType.NEWLINE, "break_newline", re.compile(r"(?:\r?\n){2,}")),
)

_LABEL_FIELD_SEPARATOR_CHARS = ":：-—–=|"
# 标签边界：匹配到的 label 前方或后方至少有一侧满足此集合中的 unit kind，
# 或处于文本起止位置。防止自然语句中嵌入的关键词被误识别为标签。
_LABEL_BOUNDARY_UNIT_KINDS = frozenset({"punct", "inline_gap", "ocr_break"})
_SEED_ROLES = frozenset({ClueRole.LABEL, ClueRole.START})
_SOFT_CONTENT_ROLES = frozenset(
    {
        ClueRole.SUFFIX,
        ClueRole.KEY,
        ClueRole.VALUE,
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
    }
)
_START_MASKED_SOFT_ROLES = frozenset(
    {
        ClueRole.SUFFIX,
        ClueRole.KEY,
        ClueRole.VALUE,
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
    }
)
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
    stream: StreamInput
    text: str
    raw_start: int
    folded_text: str
    gap_offsets: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class _AddressPatternPayload:
    component_type: AddressComponentType
    canonical_text: str


_DictionaryMetadataItems = tuple[tuple[str, tuple[str, ...]], ...]
_DictionaryMatcherSignature = tuple[tuple[PIIAttributeType, tuple[str, ...], str, _DictionaryMetadataItems], ...]


@dataclass(frozen=True, slots=True)
class _DictionaryMatchPayload:
    attr_type: PIIAttributeType
    matched_by: str
    metadata_items: _DictionaryMetadataItems
    emission_order: int


def build_clue_bundle(
    stream: StreamInput,
    *,
    ctx: DetectContext,
    session_entries: tuple[DictionaryEntry, ...],
    local_entries: tuple[DictionaryEntry, ...],
    locale_profile: str,
) -> ClueBundle:
    """两遍扫描构建 ClueBundle。

    Pass 1 — STRUCTURED clue 扫描与裁决，确定屏蔽区间。
    Pass 2 — segment-major 词典/soft clue 扫描，事件扫描线裁决。
    """
    all_ocr_spans = _find_ocr_break_spans(stream)
    ocr_break_only_spans = _find_ocr_break_only_spans(stream)
    session_name_entries = tuple(entry for entry in session_entries if entry.attr_type == PIIAttributeType.NAME)
    local_name_entries = tuple(entry for entry in local_entries if entry.attr_type == PIIAttributeType.NAME)
    session_non_structured_entries = tuple(
        entry
        for entry in session_entries
        if entry.attr_type in {PIIAttributeType.ORGANIZATION, PIIAttributeType.ADDRESS}
    )
    local_non_structured_entries = tuple(
        entry
        for entry in local_entries
        if entry.attr_type in {PIIAttributeType.ORGANIZATION, PIIAttributeType.ADDRESS}
    )

    # ── Pass 1: STRUCTURED clue 扫描与裁决 ──
    structured_clues = _resolve_structured_conflicts(
        _scan_hard_patterns(ctx, stream, ignored_spans=all_ocr_spans)
    )

    # ── Pass 2: segment-major clue 扫描 ──
    # 分块依据：STRUCTURED clue span + ocr_break span。段内去除 inline_gap。
    scan_segments = _build_soft_scan_segments(stream, structured_clues, ocr_break_spans=ocr_break_only_spans)
    soft_clues: list[Clue] = []
    for segment in scan_segments:
        soft_clues.extend(_scan_org_address_dictionary_clues(ctx, segment, session_non_structured_entries, source_kind="session"))
        soft_clues.extend(_scan_org_address_dictionary_clues(ctx, segment, local_non_structured_entries, source_kind="local"))
        soft_clues.extend(_scan_name_dictionary_clues(ctx, segment, session_name_entries, source_kind="session"))
        soft_clues.extend(_scan_name_dictionary_clues(ctx, segment, local_name_entries, source_kind="local"))
        soft_clues.extend(_scan_label_clues(ctx, segment))
        soft_clues.extend(_scan_break_clues(ctx, segment))
        soft_clues.extend(_scan_name_start_clues(ctx, segment))
        soft_clues.extend(_scan_family_name_clues(ctx, segment))
        soft_clues.extend(_scan_en_surname_clues(ctx, segment))
        soft_clues.extend(_scan_en_given_name_clues(ctx, segment))
        soft_clues.extend(_scan_zh_given_name_clues(ctx, segment))
        soft_clues.extend(_scan_company_suffix_clues(ctx, segment))
        soft_clues.extend(_scan_address_clues(ctx, segment, locale_profile=locale_profile))
        soft_clues.extend(_scan_negative_clues(ctx, segment))

    # ── 事件扫描线裁决 ──
    all_clues = [*structured_clues, *_scan_ocr_break_clues(ctx, stream, ocr_break_only_spans), *soft_clues]
    all_clues_with_units = _attach_unit_spans(stream, all_clues)
    resolved_clues = _sweep_resolve(stream, all_clues_with_units)
    ordered_clues = tuple(sorted(resolved_clues, key=lambda item: (item.start, _family_order(item.family), item.end)))
    return ClueBundle(all_clues=ordered_clues)


def _scan_hard_patterns(ctx: DetectContext, stream: StreamInput, *, ignored_spans: tuple[tuple[int, int], ...] = ()) -> list[Clue]:
    """提取 hard clue：先排除 email/time，再提取通用数字/混合候选片段。

    scanner 只负责提取，不做 phone/id/bank 等规则验证；验证与词典反查由 stack 完成。
    """
    text = stream.text
    clues: list[Clue] = []
    excluded_spans: list[tuple[int, int]] = list(ignored_spans)

    # ── 2a: 先行匹配 email ──
    for match in _EMAIL_PATTERN.finditer(text):
        value = match.group(0).strip()
        if not value:
            continue
        if _overlaps_any(match.start(), match.end(), excluded_spans):
            continue
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.EMAIL,
                strength=ClaimStrength.HARD,
                start=match.start(),
                end=match.end(),
                text=value,
                source_kind="regex_email",
                source_metadata={"hard_source": ["regex"], "placeholder": ["<email>"]},
            )
        )
        excluded_spans.append((match.start(), match.end()))

    # ── 2a: 先行匹配 time/date ──
    for source_kind, pattern in _TIME_PATTERNS:
        for match in pattern.finditer(text):
            if source_kind in _TIME_KINDS_WITH_TOKEN_BOUNDARY and not _time_match_adjacent_ok(
                text, match.start(), match.end()
            ):
                continue
            value = match.group(0).strip()
            if not value:
                continue
            if _overlaps_any(match.start(), match.end(), excluded_spans):
                continue
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    role=ClueRole.VALUE,
                    attr_type=PIIAttributeType.TIME,
                    strength=ClaimStrength.HARD,
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    source_kind=source_kind,
                    source_metadata={"hard_source": ["regex"], "placeholder": ["<time>"]},
                )
            )
            excluded_spans.append((match.start(), match.end()))

    # ── 2b: 先提取字母数字混合片段，避免其内部数字被提前拆走。 ──
    for match in _ALNUM_FRAGMENT_PATTERN.finditer(text):
        value = match.group(0)
        if _overlaps_any(match.start(), match.end(), excluded_spans):
            continue
        digits = re.sub(r"[^0-9]", "", value)
        if not digits:
            continue
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ALNUM,
                strength=ClaimStrength.HARD,
                start=match.start(),
                end=match.end(),
                text=value,
                source_kind="extract_alnum_fragment",
                source_metadata={
                    "hard_source": ["regex"],
                    "placeholder": ["<alnum>"],
                    "fragment_type": ["ALNUM"],
                    "pure_digits": [digits],
                },
            )
        )
        excluded_spans.append((match.start(), match.end()))

    # ── 2c: 提取纯数字片段 ──
    for match in _DIGIT_FRAGMENT_PATTERN.finditer(text):
        value = match.group(0)
        if _overlaps_any(match.start(), match.end(), excluded_spans):
            continue
        digits = re.sub(r"\D", "", value)
        if len(digits) < 2:
            continue
        # 跳过被 _NEGATIVE_NUMERIC_PATTERNS 命中的片段。
        if _is_negative_numeric(text, match.start(), match.end()):
            continue
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.NUMERIC,
                strength=ClaimStrength.HARD,
                start=match.start(),
                end=match.end(),
                text=value,
                source_kind="extract_digit_fragment",
                source_metadata={
                    "hard_source": ["regex"],
                    "placeholder": ["<numeric>"],
                    "fragment_type": ["NUM"],
                    "pure_digits": [digits],
                },
            )
        )
        excluded_spans.append((match.start(), match.end()))

    return clues


def _is_negative_numeric(text: str, start: int, end: int) -> bool:
    """检查数字片段是否处于非隐私上下文（年份、百分比、序号、计量单位等）。"""
    # 取片段前后一定范围的文本做上下文匹配。
    context_start = max(0, start - 5)
    context_end = min(len(text), end + 10)
    context = text[context_start:context_end]
    for pattern in _NEGATIVE_NUMERIC_PATTERNS:
        for m in pattern.finditer(context):
            # 检查 negative pattern 的匹配是否覆盖了原始片段。
            abs_start = context_start + m.start()
            abs_end = context_start + m.end()
            if abs_start <= start and abs_end >= end:
                return True
    return False


def _scan_dictionary_hard_clues(
    ctx: DetectContext,
    stream: StreamInput | str,
    entries: tuple[DictionaryEntry, ...],
    *,
    source_kind: str,
    ignored_spans: tuple[tuple[int, int], ...] = (),
) -> list[Clue]:
    if isinstance(stream, str):
        stream = build_prompt_stream(stream)
    entries = tuple(entry for entry in entries if entry.attr_type != PIIAttributeType.NAME)
    if not entries:
        return []
    clues: list[Clue] = []
    signature = _dictionary_matcher_signature(entries)
    matcher = _session_dictionary_matcher(signature) if source_kind == "session" else _local_dictionary_matcher(signature)
    matches = matcher.find_matches(stream.text, folded_text=stream.text.lower())
    matches.sort(key=lambda item: (item.payload.emission_order, item.start, item.end))
    for match in matches:
        normalized = _normalize_ascii_match(stream, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        start, end, matched_text = normalized
        if _overlaps_any(start, end, ignored_spans):
            continue
        payload = match.payload
        dict_metadata = {key: list(values) for key, values in payload.metadata_items}
        dict_metadata["hard_source"] = [source_kind]
        dict_metadata["placeholder"] = [_PLACEHOLDER_BY_ATTR.get(payload.attr_type, f"<{payload.attr_type.value}>")]
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=_attr_to_family(payload.attr_type),
                role=ClueRole.VALUE,
                attr_type=payload.attr_type,
                strength=ClaimStrength.HARD,
                start=start,
                end=end,
                text=matched_text,
                source_kind=payload.matched_by,
                source_metadata=dict_metadata,
            )
        )
    return clues


def _scan_org_address_dictionary_clues(
    ctx: DetectContext,
    segment: _ScanSegment,
    entries: tuple[DictionaryEntry, ...],
    *,
    source_kind: str,
) -> list[Clue]:
    """在 pass2 segment 上扫描 org/address 词典条目，产出 HARD clue。"""
    entries = tuple(entry for entry in entries if entry.attr_type != PIIAttributeType.NAME)
    if not entries:
        return []
    clues: list[Clue] = []
    signature = _dictionary_matcher_signature(entries)
    matcher = _session_dictionary_matcher(signature) if source_kind == "session" else _local_dictionary_matcher(signature)
    matches = matcher.find_matches(segment.text, folded_text=segment.folded_text)
    matches.sort(key=lambda item: (item.payload.emission_order, item.start, item.end))
    for match in matches:
        normalized = _normalize_segment_ascii_match(
            segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary,
        )
        if normalized is None:
            continue
        start, end, matched_text = normalized
        payload = match.payload
        dict_metadata = {key: list(values) for key, values in payload.metadata_items}
        dict_metadata["hard_source"] = [source_kind]
        dict_metadata["placeholder"] = [_PLACEHOLDER_BY_ATTR.get(payload.attr_type, f"<{payload.attr_type.value}>")]
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=_attr_to_family(payload.attr_type),
                role=ClueRole.VALUE,
                attr_type=payload.attr_type,
                strength=ClaimStrength.HARD,
                start=start,
                end=end,
                text=matched_text,
                source_kind=payload.matched_by,
                source_metadata=dict_metadata,
            )
        )
    return clues


def _scan_name_dictionary_clues(
    ctx: DetectContext,
    stream: StreamInput | _ScanSegment | str,
    entries: tuple[DictionaryEntry, ...],
    *,
    source_kind: str,
    ignored_spans: tuple[tuple[int, int], ...] = (),
) -> list[Clue]:
    if not entries:
        return []
    if isinstance(stream, str):
        normalized_stream = build_prompt_stream(stream)
        segment: _ScanSegment | None = None
    elif isinstance(stream, _ScanSegment):
        normalized_stream = stream.stream
        segment = stream
    else:
        normalized_stream = stream
        segment = None
    name_entries = tuple(entry for entry in entries if entry.attr_type == PIIAttributeType.NAME)
    if not name_entries:
        return []

    clues: list[Clue] = []
    signature = _dictionary_matcher_signature(name_entries)
    matcher = _session_dictionary_matcher(signature) if source_kind == "session" else _local_dictionary_matcher(signature)
    matches = matcher.find_matches(normalized_stream.text, folded_text=normalized_stream.text.lower())
    matches.sort(key=lambda item: (item.payload.emission_order, item.start, item.end))
    for match in matches:
        if segment is not None:
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
            start, end, matched_text = normalized
        else:
            normalized = _normalize_ascii_match(
                normalized_stream,
                match.start,
                match.end,
                match.matched_text,
                match.pattern_text,
                match.ascii_boundary,
            )
            if normalized is None:
                continue
            start, end, matched_text = normalized
        if _overlaps_any(start, end, ignored_spans):
            continue
        payload = match.payload
        metadata = {key: list(values) for key, values in payload.metadata_items}
        component = _dictionary_name_component(metadata)
        role, hint_value = _dictionary_name_role(component)
        metadata["hard_source"] = [source_kind]
        metadata["name_component_hint"] = [hint_value]
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=role,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.HARD,
                start=start,
                end=end,
                text=matched_text,
                source_kind=payload.matched_by,
                source_metadata=metadata,
            )
        )
    return clues


def _dictionary_name_component(metadata: dict[str, list[str]]) -> str:
    values = metadata.get("name_component", [])
    return str(values[0]).strip().lower() if values else "full"


def _dictionary_name_role(component: str) -> tuple[ClueRole, str]:
    """从字典 name_component 推导 role 和 hint 值字符串。"""
    if component == "family":
        return (ClueRole.FAMILY_NAME, "family")
    if component == "given":
        return (ClueRole.GIVEN_NAME, "given")
    if component == "alias":
        return (ClueRole.ALIAS, "alias")
    if component == "middle":
        return (ClueRole.GIVEN_NAME, "middle")
    return (ClueRole.FULL_NAME, "full")


def _scan_label_clues(ctx: DetectContext, segment: _ScanSegment) -> tuple[Clue, ...]:
    matches: list[tuple[int, int, object]] = []
    for match in _label_matcher().find_matches(segment.text, folded_text=segment.folded_text):
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
        raw_start, raw_end, _matched_text = normalized
        matches.append((raw_start, raw_end, match.payload))
    accepted: list[tuple[int, int, object]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, spec in sorted(matches, key=lambda item: (-(item[1] - item[0]), -len(item[2].keyword), item[2].order_index, item[0])):
        if any(not (end <= left or start >= right) for left, right in occupied):
            continue
        occupied.append((start, end))
        accepted.append((start, end, spec))
    clues: list[Clue] = []
    for start, end, spec in sorted(accepted, key=lambda item: (item[0], item[1])):
        label_metadata: dict[str, list[str]] = {}
        if spec.ocr_source_kind:
            label_metadata["ocr_source_kind"] = [spec.ocr_source_kind]
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=_attr_to_family(spec.attr_type),
                role=ClueRole.LABEL,
                attr_type=spec.attr_type,
                strength=ClaimStrength.SOFT,
                start=start,
                end=end,
                text=spec.keyword,
                source_kind=spec.source_kind,
                source_metadata=label_metadata,
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
                    family=ClueFamily.CONTROL,
                    role=ClueRole.BREAK,
                    attr_type=None,
                    strength=ClaimStrength.SOFT,
                    start=raw_start,
                    end=raw_end,
                    text=match.group(0),
                    source_kind=source_kind,
                    break_type=break_type,
                )
            )
    return _dedupe_clues(clues)


def _scan_ocr_break_clues(
    ctx: DetectContext,
    stream: StreamInput,
    ocr_break_spans: tuple[tuple[int, int], ...],
) -> list[Clue]:
    clues: list[Clue] = []
    for start, end in ocr_break_spans:
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.CONTROL,
                role=ClueRole.BREAK,
                attr_type=None,
                strength=ClaimStrength.SOFT,
                start=start,
                end=end,
                text=stream.text[start:end],
                source_kind="break_ocr",
                break_type=BreakType.OCR,
            )
        )
    return clues


def _scan_name_start_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _name_start_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.START,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                source_kind="name_start",
            )
        )
    return _dedupe_clues(clues)


def _scan_family_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _family_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        tail = segment.text[match.end : match.end + 4]
        if any(keyword in tail for keyword in ("省", "市", "区", "县", "旗", "路", "街", "道", "大道", "小区", "单元", "栋", "室", "住址", "地址")):
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.FAMILY_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                source_kind="family_name",
            )
        )
    return _dedupe_clues(clues)


def _scan_en_surname_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文姓氏，产出 FAMILY_NAME clue。"""
    clues: list[Clue] = []
    for match in _en_surname_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.FAMILY_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                source_kind="en_surname",
            )
        )
    return _dedupe_clues(clues)


def _scan_en_given_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文名字（given name），产出 GIVEN_NAME clue。"""
    clues: list[Clue] = []
    for match in _en_given_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.GIVEN_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                source_kind="en_given_name",
            )
        )
    return _dedupe_clues(clues)


def _scan_zh_given_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描中文名字（given name），产出 GIVEN_NAME clue。"""
    clues: list[Clue] = []
    for match in _zh_given_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.GIVEN_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=str(match.payload),
                source_kind="zh_given_name",
            )
        )
    return _dedupe_clues(clues)


def _scan_company_suffix_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _company_suffix_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ORGANIZATION,
                role=ClueRole.SUFFIX,
                attr_type=PIIAttributeType.ORGANIZATION,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
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
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                source_kind="geo_db",
                component_type=payload.component_type,
            )
        )
    for match in _zh_address_key_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                source_kind="address_keyword",
                component_type=payload.component_type,
            )
        )
    return clues


def _scan_en_address_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _en_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                source_kind="geo_db",
                component_type=payload.component_type,
            )
        )
    for match in _en_address_key_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                source_kind="address_keyword",
                component_type=payload.component_type,
            )
        )
    for token_match in _POSTAL_CODE_PATTERN.finditer(segment.text):
        raw_start, raw_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=token_match.group(0),
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
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.CONTROL,
                role=ClueRole.NEGATIVE,
                attr_type=None,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
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
                    family=ClueFamily.CONTROL,
                    role=ClueRole.NEGATIVE,
                    attr_type=None,
                    strength=ClaimStrength.SOFT,
                    start=raw_start,
                    end=raw_end,
                    text=token_match.group(0),
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


def _resolve_structured_conflicts(clues: list[Clue]) -> tuple[Clue, ...]:
    """hard clue 裁决：仅覆盖“被完全包含”的 clue。

    规则：
    - 若 A 的区间完全包含 B（含相等区间），则 B 被覆盖（移除）。
    - 若两条 clue 仅“部分重叠”，但互不完全包含，则两者都保留。

    实现上仍使用“更长 / 更高来源优先级”的排序来稳定地先处理更强的 clue，
    但冲突判定从“任意重叠即互斥”改为“仅完全包含才覆盖”。
    """
    if not clues:
        return ()
    ranked = sorted(
        clues,
        key=lambda c: (
            -(c.end - c.start),
            -_HARD_SOURCE_PRIORITY.get((c.source_metadata.get("hard_source") or [""])[0], 0),
            c.start,
        ),
    )
    accepted: list[Clue] = []
    for clue in ranked:
        if any(a.start <= clue.start and clue.end <= a.end for a in accepted):
            continue
        accepted = [a for a in accepted if not (clue.start <= a.start and a.end <= clue.end)]
        accepted.append(clue)
    accepted.sort(key=lambda c: (c.start, c.end))
    return tuple(accepted)


def _build_soft_scan_segments(
    stream: StreamInput,
    structured_clues: tuple[Clue, ...],
    *,
    ocr_break_spans: tuple[tuple[int, int], ...] = (),
) -> tuple[_ScanSegment, ...]:
    """构建 pass2 扫描段。

    分块依据：STRUCTURED clue span + ocr_break span。
    段内去除 inline_gap token（直接拼接），构建位置回映表。
    """
    inline_gap_spans = _find_inline_gap_spans(stream)
    blocked_spans = sorted(
        [(clue.start, clue.end) for clue in structured_clues] + list(ocr_break_spans),
        key=lambda item: (item[0], item[1]),
    )
    segments: list[_ScanSegment] = []
    cursor = 0
    for start, end in blocked_spans:
        if start < cursor:
            continue
        if cursor < start:
            segments.append(_build_segment_with_gap_removal(stream, cursor, start, inline_gap_spans))
        cursor = end
    if cursor < len(stream.text):
        segments.append(_build_segment_with_gap_removal(stream, cursor, len(stream.text), inline_gap_spans))
    return tuple(segments)


def _build_segment_with_gap_removal(
    stream: StreamInput,
    raw_start: int,
    raw_end: int,
    inline_gap_spans: tuple[tuple[int, int], ...],
) -> _ScanSegment:
    """构建单个扫描段，去除其中的 inline_gap token 并记录偏移。"""
    gaps_in_range = [
        (gs, ge) for gs, ge in inline_gap_spans
        if gs >= raw_start and ge <= raw_end
    ]
    if not gaps_in_range:
        seg_text = stream.text[raw_start:raw_end]
        return _ScanSegment(stream=stream, text=seg_text, raw_start=raw_start, folded_text=seg_text.lower())

    pieces: list[str] = []
    gap_offsets: list[tuple[int, int]] = []
    piece_cursor = raw_start
    cleaned_pos = 0
    for gs, ge in sorted(gaps_in_range):
        if piece_cursor < gs:
            piece = stream.text[piece_cursor:gs]
            pieces.append(piece)
            cleaned_pos += len(piece)
        gap_offsets.append((cleaned_pos, ge - gs))
        piece_cursor = ge
    if piece_cursor < raw_end:
        pieces.append(stream.text[piece_cursor:raw_end])

    seg_text = "".join(pieces)
    return _ScanSegment(
        stream=stream,
        text=seg_text,
        raw_start=raw_start,
        folded_text=seg_text.lower(),
        gap_offsets=tuple(gap_offsets),
    )


def _segment_span_to_raw(segment: _ScanSegment, start: int, end: int) -> tuple[int, int]:
    """将 segment cleaned text 的 [start, end) 映射回 stream 原始位置。"""
    start_offset = sum(gl for gp, gl in segment.gap_offsets if gp <= start)
    end_offset = sum(gl for gp, gl in segment.gap_offsets if gp < end)
    return (segment.raw_start + start + start_offset, segment.raw_start + end + end_offset)


def _attach_unit_spans(stream: StreamInput, clues: list[Clue]) -> list[Clue]:
    return [
        replace(clue, unit_start=_char_span_to_unit_span(stream, clue.start, clue.end)[0], unit_end=_char_span_to_unit_span(stream, clue.start, clue.end)[1])
        for clue in clues
    ]


def _char_span_to_unit_span(stream: StreamInput, start: int, end: int) -> tuple[int, int]:
    if not stream.char_to_unit or start >= end:
        return (0, 0)
    return (stream.char_to_unit[start], stream.char_to_unit[end - 1] + 1)


def _has_label_boundary(stream: StreamInput, raw_start: int, raw_end: int) -> bool:
    """检查 label 匹配区间的前方或后方至少有一侧是标签边界。

    边界条件（满足任一即可）：
    - 处于流文本的起始 / 末尾位置。
    - 相邻 unit 的 kind 属于 ``_LABEL_BOUNDARY_UNIT_KINDS``（punct / inline_gap / ocr_break）。
    """
    if not stream.char_to_unit:
        return True
    unit_start, unit_end = _char_span_to_unit_span(stream, raw_start, raw_end)
    if unit_start >= unit_end:
        return True
    # 左侧：起始位置或相邻 unit 为边界类型。
    if unit_start == 0 or stream.units[unit_start - 1].kind in _LABEL_BOUNDARY_UNIT_KINDS:
        return True
    # 右侧：末尾位置或相邻 unit 为边界类型。
    if unit_end >= len(stream.units) or stream.units[unit_end].kind in _LABEL_BOUNDARY_UNIT_KINDS:
        return True
    return False


_LABEL_START_CONNECTOR_SKIPPABLE_UNIT_KINDS = frozenset({"space", "inline_gap"})


def _try_convert_label_to_start(stream: StreamInput, clue: Clue) -> Clue | None:
    """尝试将 LABEL 转为 START：后面紧跟"是"或"is"（英文允许跳过空白 unit）则合并。"""
    if not stream.units or clue.unit_end >= len(stream.units):
        return None
    next_idx = clue.unit_end
    # 中文：紧邻的下一个 unit 是"是"。
    if stream.units[next_idx].text == "是":
        target = stream.units[next_idx]
        return replace(
            clue,
            role=ClueRole.START,
            end=target.char_end,
            unit_end=next_idx + 1,
            text=stream.text[clue.start : target.char_end],
        )
    # 英文：跳过空白/gap unit，检查下一个实质 unit 是否为 "is"。
    scan = next_idx
    while scan < len(stream.units) and stream.units[scan].kind in _LABEL_START_CONNECTOR_SKIPPABLE_UNIT_KINDS:
        scan += 1
    if scan < len(stream.units) and stream.units[scan].text.lower() == "is":
        target = stream.units[scan]
        return replace(
            clue,
            role=ClueRole.START,
            end=target.char_end,
            unit_end=scan + 1,
            text=stream.text[clue.start : target.char_end],
        )
    return None


def _normalize_ascii_match(
    stream: StreamInput,
    start: int,
    end: int,
    matched_text: str,
    pattern_text: str,
    ascii_boundary: bool,
) -> tuple[int, int, str] | None:
    if not ascii_boundary:
        return (start, end, matched_text)
    if not stream.char_to_unit or start < 0 or end > len(stream.text) or start >= end:
        return None
    unit_start, unit_end = _char_span_to_unit_span(stream, start, end)
    if unit_start >= unit_end:
        return None
    first_unit = stream.units[unit_start]
    last_unit = stream.units[unit_end - 1]
    if unit_start == unit_end - 1 and first_unit.kind == "ascii_word":
        if not _ascii_unit_text_matches(first_unit.text, pattern_text):
            return None
        return (first_unit.char_start, first_unit.char_end, first_unit.text)
    if start != first_unit.char_start or end != last_unit.char_end:
        return None
    return (start, end, matched_text)


def _ascii_unit_text_matches(unit_text: str, pattern_text: str) -> bool:
    folded_unit = unit_text.lower()
    folded_pattern = pattern_text.lower()
    return folded_unit in {
        folded_pattern,
        f"{folded_pattern}s",
        f"{folded_pattern}es",
    }


def _normalize_segment_ascii_match(
    segment: _ScanSegment,
    start: int,
    end: int,
    matched_text: str,
    pattern_text: str,
    ascii_boundary: bool,
) -> tuple[int, int, str] | None:
    raw_s, raw_e = _segment_span_to_raw(segment, start, end)
    normalized = _normalize_ascii_match(
        segment.stream,
        raw_s,
        raw_e,
        matched_text,
        pattern_text,
        ascii_boundary,
    )
    if normalized is None:
        return None
    raw_start, raw_end, text = normalized
    return (raw_start, raw_end, text)


def _find_ocr_break_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """返回 ocr_break 和 inline_gap 的 unit span（pass1 排除用）。"""
    spans = [
        (unit.char_start, unit.char_end)
        for unit in stream.units
        if unit.kind in {"inline_gap", "ocr_break"}
    ]
    return tuple(spans)


def _find_ocr_break_only_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """仅返回 ocr_break span（分块边界、BREAK clue 来源）。"""
    return tuple(
        (unit.char_start, unit.char_end)
        for unit in stream.units
        if unit.kind == "ocr_break"
    )


def _find_inline_gap_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """返回 inline_gap span（段内去除用）。"""
    return tuple(
        (unit.char_start, unit.char_end)
        for unit in stream.units
        if unit.kind == "inline_gap"
    )


def _needs_ascii_keyword_boundary(keyword: str) -> bool:
    return bool(_ASCII_KEYWORD_CHARS_RE.fullmatch(keyword))


def _dictionary_matcher_signature(entries: tuple[DictionaryEntry, ...]) -> _DictionaryMatcherSignature:
    return tuple(
        (
            entry.attr_type,
            _dictionary_match_terms(entry.match_terms),
            entry.matched_by,
            _dictionary_metadata_items(entry.metadata),
        )
        for entry in entries
    )


def _dictionary_match_terms(match_terms: tuple[str, ...]) -> tuple[str, ...]:
    ordered = tuple(dict.fromkeys(term for raw in match_terms if (term := str(raw).strip())))
    return tuple(sorted(ordered, key=len, reverse=True))


def _dictionary_metadata_items(metadata: dict[str, list[str]]) -> _DictionaryMetadataItems:
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for key in sorted(metadata):
        values = metadata[key]
        normalized.append((key, tuple(dict.fromkeys(str(item) for item in values if str(item)))))
    return tuple(normalized)


def _dictionary_matcher_patterns(signature: _DictionaryMatcherSignature) -> tuple[AhoPattern, ...]:
    patterns: list[AhoPattern] = []
    emission_order = 0
    for attr_type, variants, matched_by, metadata_items in signature:
        for variant in variants:
            patterns.append(
                AhoPattern(
                    text=variant,
                    payload=_DictionaryMatchPayload(
                        attr_type=attr_type,
                        matched_by=matched_by,
                        metadata_items=metadata_items,
                        emission_order=emission_order,
                    ),
                    ascii_boundary=bool(_ASCII_LITERAL_CHARS_RE.fullmatch(variant)),
                )
            )
            emission_order += 1
    return tuple(patterns)


def _build_dictionary_matcher(signature: _DictionaryMatcherSignature) -> AhoMatcher:
    return AhoMatcher.from_patterns(_dictionary_matcher_patterns(signature))


@lru_cache(maxsize=8)
def _local_dictionary_matcher(signature: _DictionaryMatcherSignature) -> AhoMatcher:
    return _build_dictionary_matcher(signature)


@lru_cache(maxsize=64)
def _session_dictionary_matcher(signature: _DictionaryMatcherSignature) -> AhoMatcher:
    return _build_dictionary_matcher(signature)


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
    lexicon = load_zh_geo_lexicon()
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
            _family_order(item.family),
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
            clue.strength,
            clue.break_type,
            clue.source_kind,
            clue.start,
            clue.end,
            clue.text.lower(),
        )
        if key in seen:
            continue
        # 同类型线索覆盖：若 clue 完全包含于已保留线索，且 role/attr/component_type 相同，则子 clue 被覆盖丢弃。
        # 典型：district KEY “新区” 覆盖 “区”。
        covered = False
        for kept in reversed(ordered):
            if kept.start <= clue.start and clue.end <= kept.end:
                if (
                    kept.role == clue.role
                    and kept.attr_type == clue.attr_type
                    and kept.component_type == clue.component_type
                    and kept.strength == clue.strength
                ):
                    covered = True
                    break
            if kept.start < clue.start and kept.end <= clue.start:
                # 已离开可能覆盖范围。
                break
        if covered:
            continue
        seen.add(key)
        ordered.append(clue)
    return sorted(ordered, key=lambda item: (item.start, _family_order(item.family), item.end))


def _sweep_resolve(stream: StreamInput, clues: list[Clue]) -> list[Clue]:
    """事件扫描线裁决所有 clue 重叠。

    1. 扫描轮 1：STRUCTURED / BREAK 遮蔽，同时收集 seed 连通块；LABEL 当场做边界判断与 START 转换。
    2. Seed 裁决：完全包含→大的覆盖；否则保留 start 更靠后的。
    3. 扫描轮 2：seed 依赖规则。
    4. 姓名组件覆盖。
    5. Label vs soft content：完全包含→大的覆盖；其余保留。
    """
    if not clues:
        return []
    unit_len = len(stream.units)
    deduped = _dedupe_clues(clues)

    # ── 轮 1：STRUCTURED / BREAK 遮蔽 + seed 连通块 + label 边界/START 转换 ──
    survivors, seed_groups = _sweep_pass1(stream, deduped, unit_len)

    # ── Seed 裁决 ──
    seed_winner_ids: set[str] = set()
    for group in seed_groups:
        for winner in _resolve_seed_group(group):
            seed_winner_ids.add(winner.clue_id)
    survivors = [
        clue for clue in survivors
        if clue.role not in _SEED_ROLES or clue.clue_id in seed_winner_ids
    ]

    # ── 轮 2：seed 依赖规则 ──
    survivors = _sweep_pass2(survivors, unit_len)

    # ── 姓名组件覆盖 ──
    survivors = _apply_name_component_coverage(survivors)

    # ── Label vs soft content ──
    return _label_vs_soft_filter(survivors)


def _build_events(
    clues: list[Clue],
    unit_len: int,
) -> tuple[list[list[Clue]], list[list[Clue]]]:
    """构建 unit 轴上的 start / end 事件数组。"""
    start_events: list[list[Clue]] = [[] for _ in range(unit_len + 1)]
    end_events: list[list[Clue]] = [[] for _ in range(unit_len + 1)]
    for clue in clues:
        start_events[clue.unit_start].append(clue)
        end_events[clue.unit_end].append(clue)
    return start_events, end_events


def _sweep_pass1(
    stream: StreamInput,
    clues: list[Clue],
    unit_len: int,
) -> tuple[list[Clue], list[list[Clue]]]:
    """扫描轮 1（unit 轴）：STRUCTURED / BREAK 遮蔽 + seed 连通块收集 + LABEL 边界/START 转换。

    STRUCTURED 和 BREAK 无条件保留并形成活跃区间；
    其他 soft clue 落在活跃区间内则过滤。
    LABEL 先尝试拼接"是"/"is"转 START；否则走边界过滤。
    """
    start_events, end_events = _build_events(clues, unit_len)

    active_structured = 0
    active_break = 0
    survivors: list[Clue] = []

    seed_groups: list[list[Clue]] = []
    cur_seed_group: list[Clue] = []
    seed_group_end = -1

    for pos in range(unit_len + 1):
        for clue in end_events[pos]:
            if clue.family == ClueFamily.STRUCTURED and clue.role not in _SEED_ROLES:
                active_structured -= 1
            elif clue.role == ClueRole.BREAK:
                active_break -= 1

        if cur_seed_group and pos >= seed_group_end:
            seed_groups.append(cur_seed_group)
            cur_seed_group = []
            seed_group_end = -1

        for clue in start_events[pos]:
            role = clue.role

            if clue.family == ClueFamily.STRUCTURED and role not in _SEED_ROLES:
                active_structured += 1
                survivors.append(clue)
                continue
            if role == ClueRole.BREAK:
                active_break += 1
                survivors.append(clue)
                continue

            if active_structured > 0:
                continue
            if active_break > 0:
                continue

            # LABEL 当场判定：先尝试拼接"是"/"is"转 START，再走边界过滤。
            if role == ClueRole.LABEL:
                converted = _try_convert_label_to_start(stream, clue)
                if converted is not None:
                    clue = converted
                    role = ClueRole.START
                elif not _has_label_boundary(stream, clue.start, clue.end):
                    continue

            survivors.append(clue)

            if role in _SEED_ROLES:
                if clue.unit_start < seed_group_end:
                    cur_seed_group.append(clue)
                else:
                    if cur_seed_group:
                        seed_groups.append(cur_seed_group)
                    cur_seed_group = [clue]
                seed_group_end = max(seed_group_end, clue.unit_end)

    if cur_seed_group:
        seed_groups.append(cur_seed_group)

    return survivors, seed_groups


def _resolve_seed_group(group: list[Clue]) -> list[Clue]:
    """Seed 连通块裁决。完全包含→大的覆盖；部分重叠→保留 start 更靠后的。"""
    if len(group) <= 1:
        return list(group)
    # 按 start 降序处理：start 大的先入队，后续只需检查是否被已有 survivor 覆盖或重叠。
    ranked = sorted(group, key=lambda c: (-c.start, -(c.end - c.start)))
    survivors: list[Clue] = []
    for clue in ranked:
        if any(s.start <= clue.start and clue.end <= s.end for s in survivors):
            continue
        survivors = [s for s in survivors if not (clue.start <= s.start and s.end <= clue.end)]
        if any(_clues_overlap(clue, s) for s in survivors):
            continue
        survivors.append(clue)
    return survivors


def _sweep_pass2(clues: list[Clue], unit_len: int) -> list[Clue]:
    """扫描轮 2（unit 轴）：seed 遮蔽 soft_control，START 遮蔽 soft_content。"""
    start_events, end_events = _build_events(clues, unit_len)

    active_seed = 0
    active_start = 0
    survivors: list[Clue] = []

    for pos in range(unit_len + 1):
        for clue in end_events[pos]:
            if clue.role in _SEED_ROLES:
                active_seed -= 1
                if clue.role == ClueRole.START:
                    active_start -= 1

        for clue in start_events[pos]:
            role = clue.role

            if role in _SEED_ROLES:
                active_seed += 1
                if role == ClueRole.START:
                    active_start += 1
                survivors.append(clue)
                continue

            if role in _START_MASKED_SOFT_ROLES and active_start > 0:
                continue

            survivors.append(clue)

    return survivors


def _apply_name_component_coverage(clues: list[Clue]) -> list[Clue]:
    """姓名组件覆盖裁决。

    FULL_NAME / ALIAS 仅在完全包含时做覆盖，部分重叠都保留。
    """
    full_name_winners = _resolve_name_component_overlap_winners(
        [clue for clue in clues if clue.role == ClueRole.FULL_NAME]
    )
    full_name_ids = {clue.clue_id for clue in full_name_winners}

    alias_candidates = [
        clue
        for clue in clues
        if clue.role == ClueRole.ALIAS
        and not any(_clues_overlap(clue, full_name) for full_name in full_name_winners)
    ]
    alias_winners = _resolve_name_component_overlap_winners(alias_candidates)
    alias_ids = {clue.clue_id for clue in alias_winners}

    blocked_name_clues = [*full_name_winners, *alias_winners]
    survivors: list[Clue] = []
    for clue in clues:
        if clue.role == ClueRole.FULL_NAME:
            if clue.clue_id in full_name_ids:
                survivors.append(clue)
            continue
        if clue.role == ClueRole.ALIAS:
            if clue.clue_id in alias_ids:
                survivors.append(clue)
            continue
        if clue.role in {ClueRole.FAMILY_NAME, ClueRole.GIVEN_NAME}:
            if any(_clues_overlap(clue, blocker) for blocker in blocked_name_clues):
                continue
        survivors.append(clue)
    return survivors


def _resolve_name_component_overlap_winners(clues: list[Clue]) -> list[Clue]:
    """姓名组件重叠裁决：仅完全包含时做覆盖，部分重叠都保留。"""
    if not clues:
        return []
    survivors: list[Clue] = []
    for clue in clues:
        if any(
            other.start <= clue.start and clue.end <= other.end
            and (other.start < clue.start or clue.end < other.end)
            for other in clues
            if other.clue_id != clue.clue_id
        ):
            continue
        survivors.append(clue)
    return sorted(survivors, key=lambda c: (c.start, c.end))


def _label_vs_soft_filter(clues: list[Clue]) -> list[Clue]:
    """Label vs soft content 裁决。

    完全包含→大的覆盖小的；其余情况（完全重合、部分重叠）→两者都保留。
    """
    label_clues = [c for c in clues if c.role == ClueRole.LABEL]
    soft_content_clues = [c for c in clues if c.role in _SOFT_CONTENT_ROLES]
    if not label_clues or not soft_content_clues:
        return clues

    dropped_ids: set[str] = set()
    for label in label_clues:
        if label.clue_id in dropped_ids:
            continue
        for soft in soft_content_clues:
            if soft.clue_id in dropped_ids:
                continue
            if not _clues_overlap(label, soft):
                continue
            # 严格包含（区间不完全相等时一方包含另一方）→大的覆盖小的。
            label_contains = label.start <= soft.start and soft.end <= label.end and (label.start < soft.start or soft.end < label.end)
            soft_contains = soft.start <= label.start and label.end <= soft.end and (soft.start < label.start or label.end < soft.end)
            if label_contains:
                dropped_ids.add(soft.clue_id)
            elif soft_contains:
                dropped_ids.add(label.clue_id)

    return [c for c in clues if c.clue_id not in dropped_ids]


def _skip_whitespace_right(raw_text: str, start: int) -> int:
    index = start
    while index < len(raw_text) and raw_text[index].isspace():
        index += 1
    return index


def _clues_overlap(left: Clue, right: Clue) -> bool:
    return not (left.end <= right.start or left.start >= right.end)


def _overlaps_any(start: int, end: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)
