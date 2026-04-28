"""Detector 流式 clue 扫描器。"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import GeoEntry, load_en_geo_lexicon, load_zh_geo_lexicon
from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_company_suffixes,
    load_en_company_values,
    load_zh_company_suffixes,
    load_zh_company_values,
    load_en_address_country_aliases,
    load_en_address_keyword_groups,
    load_en_given_names,
    load_en_surnames,
    load_label_specs,
    load_name_start_keywords,
    load_negative_address_words,
    load_negative_name_words,
    load_negative_org_words,
    load_negative_ui_words,
    load_zh_address_keyword_groups,
    load_zh_compound_surnames,
    load_zh_control_values,
    load_zh_license_plate_values,
    load_zh_single_surname_claim_strengths,
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
    InspireEntry,
    NEGATIVE_SCOPES,
    StreamInput,
    UnitBucket,
)
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import _normalize_address_value
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_index_at_or_after, valid_left_numeral_for_zh_address_key
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK, _OCR_INLINE_GAP_TOKEN, is_any_break
from privacyguard.infrastructure.pii.detector.zh_name_rules import compact_zh_name_text

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
    ClueFamily.LICENSE_PLATE: 3,
    ClueFamily.STRUCTURED: 4,
    ClueFamily.CONTROL: 5,
}


def _family_order(family: ClueFamily) -> int:
    return _FAMILY_ORDER.get(family, 99)


def _is_address_postal_value_clue(clue: Clue) -> bool:
    return (
        clue.family == ClueFamily.ADDRESS
        and clue.role == ClueRole.VALUE
        and clue.component_type == AddressComponentType.POSTAL_CODE
    )


def _attr_to_family(attr_type: PIIAttributeType | None) -> ClueFamily:
    """从 attr_type 推导 ClueFamily。"""
    if attr_type is None:
        return ClueFamily.CONTROL
    _MAP = {
        PIIAttributeType.NAME: ClueFamily.NAME,
        PIIAttributeType.ORGANIZATION: ClueFamily.ORGANIZATION,
        PIIAttributeType.ADDRESS: ClueFamily.ADDRESS,
        PIIAttributeType.LICENSE_PLATE: ClueFamily.LICENSE_PLATE,
    }
    return _MAP.get(attr_type, ClueFamily.STRUCTURED)

_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.BANK_NUMBER: "<bank>",
    PIIAttributeType.LICENSE_PLATE: "<license_plate>",
    PIIAttributeType.AMOUNT: "<amount>",
}

_EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}"
)
_TRAILING_PUNCT_CHARS = ".,;:!?)]}。！？；：，、）】》」』"
_DIRECT_DELIMITER_PUNCT_CHARS = ",;，、；)]}）】》」』"

# 与 ``pii_value._TIME_PATTERN`` 一致的时钟片段（时 0–23，分/秒 0–59，冒号半角/全角）。
_TIME_CLOCK_STRICT = r"(?:[01]?\d|2[0-3])[:：][0-5]\d(?:[:：][0-5]\d)?"
_TIME_DATE_YMD = r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}"
_TIME_DATE_MDY = r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}"
_TIME_DATE_MD_CLOCK = rf"\d{{1,2}}/\d{{1,2}}\s+{_TIME_CLOCK_STRICT}"
_TIME_DATE_ZH_YMD = r"\d{4}年\d{1,2}月\d{1,2}日"
_TIME_DATE_ZH_MD = r"\d{1,2}月\d{1,2}日"

# 时间/日期模式——先行匹配并排除，防止其中的数字被当作候选片段。
_TIME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("time_datetime", re.compile(rf"{_TIME_DATE_YMD}(?:[T ]{_TIME_CLOCK_STRICT})?")),
    ("time_date_mdy", re.compile(_TIME_DATE_MDY)),
    ("time_md_clock", re.compile(_TIME_DATE_MD_CLOCK)),
    ("time_zh_datetime", re.compile(rf"{_TIME_DATE_ZH_YMD}(?:\s*{_TIME_CLOCK_STRICT})?")),
    ("time_zh_md_datetime", re.compile(rf"{_TIME_DATE_ZH_MD}(?:\s*{_TIME_CLOCK_STRICT})?")),
    ("time_clock", re.compile(_TIME_CLOCK_STRICT)),
)

# 以下模式需在左右两侧满足「空白 / OCR 块界 / 链内间隙」之一（或紧贴文本首尾），避免粘在语句或数值中间。
_TIME_KINDS_WITH_TOKEN_BOUNDARY = frozenset(
    {"time_datetime", "time_date_mdy", "time_md_clock", "time_clock", "time_zh_datetime", "time_zh_md_datetime"}
)

_AMOUNT_CURRENCY_PREFIX = r"(?i:US\$|USD|RMB|CNY|EUR|GBP|[$¥€£])"
_AMOUNT_CURRENCY_SUFFIX = r"(?i:USD|RMB|CNY|EUR|GBP|元|美元|欧元|英镑|dollars?|yuan)"
_AMOUNT_NUMBER_CORE = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?"
_AMOUNT_DECIMAL_CORE = r"(?:\d{1,3}(?:,\d{3})+|\d+)\.\d{2}"
_AMOUNT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "amount_currency",
        re.compile(
            rf"(?<![A-Za-z0-9.])(?:"
            rf"{_AMOUNT_CURRENCY_PREFIX}\s*{_AMOUNT_NUMBER_CORE}(?:\s*{_AMOUNT_CURRENCY_SUFFIX})?"
            rf"|"
            rf"{_AMOUNT_NUMBER_CORE}\s*{_AMOUNT_CURRENCY_SUFFIX}"
            rf")"
        ),
    ),
    ("amount_decimal", re.compile(rf"(?<![A-Za-z0-9.]){_AMOUNT_DECIMAL_CORE}")),
)


def _match_right_boundary_allows_trailing_punct(text: str, end: int) -> bool:
    """允许右侧是空白、OCR 断点或单个尾随句读标点。"""

    if end < 0 or end > len(text):
        return False
    if end == len(text):
        return True
    right_ch = text[end]
    if right_ch.isspace() or right_ch == _OCR_INLINE_GAP_TOKEN:
        return True
    if end + len(OCR_BREAK) <= len(text) and text[end : end + len(OCR_BREAK)] == OCR_BREAK:
        return True
    if right_ch in _TRAILING_PUNCT_CHARS:
        if right_ch in _DIRECT_DELIMITER_PUNCT_CHARS:
            return True
        if end + 1 == len(text):
            return True
        next_ch = text[end + 1]
        if next_ch.isspace() or next_ch == _OCR_INLINE_GAP_TOKEN:
            return True
        if end + 1 + len(OCR_BREAK) <= len(text) and text[end + 1 : end + 1 + len(OCR_BREAK)] == OCR_BREAK:
            return True
        if next_ch.isdigit() or (next_ch.isascii() and (next_ch.isalpha() or next_ch in "._-%+")):
            return False
        return True
    if right_ch.isdigit() or (right_ch.isascii() and (right_ch.isalpha() or right_ch in "._-")):
        return False
    return True


def _time_match_adjacent_ok(text: str, start: int, end: int) -> bool:
    """TIME 匹配片段左侧与右侧不能粘在 ASCII 词元或连续数字内部。"""
    if start < 0 or end > len(text) or start > end:
        return False
    if start > 0:
        left_ch = text[start - 1]
        if left_ch.isspace() or left_ch == _OCR_INLINE_GAP_TOKEN:
            pass
        elif len(OCR_BREAK) <= start and text[start - len(OCR_BREAK) : start] == OCR_BREAK:
            pass
        elif left_ch.isdigit() or (left_ch.isascii() and (left_ch.isalpha() or left_ch in "._-")):
            return False
        else:
            pass
    if not _match_right_boundary_allows_trailing_punct(text, end):
        right_ch = text[end]
        if right_ch.isdigit() or (right_ch.isascii() and (right_ch.isalpha() or right_ch in "._-")):
            return False
    return True


def _email_match_right_boundary_ok(text: str, end: int) -> bool:
    """校验邮箱右边界，允许句末标点落在匹配之外。"""

    if _match_right_boundary_allows_trailing_punct(text, end):
        return True
    right_ch = text[end]
    if right_ch.isascii() and (right_ch.isalnum() or right_ch in "._%+-"):
        return False
    return True


_ALNUM_SYMBOL_JOINERS = "._+-/"
_ALNUM_SYMBOL_JOINER_CLASS = re.escape(_ALNUM_SYMBOL_JOINERS)


def _alnum_fragment_shape(value: str) -> str:
    """返回 ALNUM 粗形态；空串表示不应作为 ALNUM 片段提交。"""
    if not any(ch.isascii() and ch.isalpha() for ch in value):
        return ""
    if any(ch.isdigit() for ch in value):
        return "mixed_alnum"
    if any(ch in _ALNUM_SYMBOL_JOINERS for ch in value):
        return "alpha_symbolic"
    return ""


def _numeric_fragment_shape(value: str) -> str:
    """返回 NUM 粗形态。"""
    return "numeric_symbolic" if any(not ch.isdigit() for ch in value) else "numeric"

# 通用数字片段：允许常见“电话号码/编号写法”的连接符。
# 目的：把 "+86 139-1234-1234"、"123_456" 这类写法抽成一个片段，后续再在 structured stack 中统一校验。
_DIGIT_FRAGMENT_PATTERN = re.compile(r"\+?\d(?:[ \-()_]*\d)*")
_PHONE_JOINER_PATTERN = r"[ \-()]*"
_CN_PHONE_BODY_PATTERN = rf"1[3-9](?:{_PHONE_JOINER_PATTERN}\d){{9}}"
_US_PHONE_BODY_PATTERN = rf"[2-9](?:{_PHONE_JOINER_PATTERN}\d){{2}}(?:{_PHONE_JOINER_PATTERN}[2-9])(?:{_PHONE_JOINER_PATTERN}\d){{6}}"
_US_PHONE_AFTER_AREA_PATTERN = rf"[2-9](?:{_PHONE_JOINER_PATTERN}\d){{2}}(?:{_PHONE_JOINER_PATTERN}\d){{4}}"
_PHONE_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "cn_country_code_paren",
        "cn",
        "86",
        re.compile(rf"(?<![A-Za-z0-9])\(\+?86\){_PHONE_JOINER_PATTERN}{_CN_PHONE_BODY_PATTERN}(?![A-Za-z0-9])"),
    ),
    (
        "cn_country_code",
        "cn",
        "86",
        re.compile(rf"(?<![A-Za-z0-9])\+?86{_PHONE_JOINER_PATTERN}{_CN_PHONE_BODY_PATTERN}(?![A-Za-z0-9])"),
    ),
    (
        "us_country_code_paren",
        "us",
        "1",
        re.compile(rf"(?<![A-Za-z0-9])\(\+?1\){_PHONE_JOINER_PATTERN}{_US_PHONE_BODY_PATTERN}(?![A-Za-z0-9])"),
    ),
    (
        "us_country_code",
        "us",
        "1",
        re.compile(rf"(?<![A-Za-z0-9])\+1{_PHONE_JOINER_PATTERN}{_US_PHONE_BODY_PATTERN}(?![A-Za-z0-9])"),
    ),
    (
        "us_trunk_area_paren",
        "us",
        "1",
        re.compile(rf"(?<![A-Za-z0-9])1[ \-]*\([2-9]\d{{2}}\){_PHONE_JOINER_PATTERN}{_US_PHONE_AFTER_AREA_PATTERN}(?![A-Za-z0-9])"),
    ),
)

# 含 ASCII 字母的结构化片段：字母数字混合，或纯英文带 `_` / `-` / `.` / `+` / `/`。
_ALNUM_FRAGMENT_PATTERN = re.compile(
    rf"(?=[A-Za-z0-9{_ALNUM_SYMBOL_JOINER_CLASS}]*[A-Za-z])(?:"
    rf"(?=[A-Za-z0-9{_ALNUM_SYMBOL_JOINER_CLASS}]*\d)[A-Za-z0-9]+(?:[{_ALNUM_SYMBOL_JOINER_CLASS}][A-Za-z0-9]+)*"
    rf"|"
    rf"(?=[A-Za-z0-9{_ALNUM_SYMBOL_JOINER_CLASS}]*[{_ALNUM_SYMBOL_JOINER_CLASS}])[A-Za-z0-9]+(?:[{_ALNUM_SYMBOL_JOINER_CLASS}][A-Za-z0-9]+)+"
    rf")"
)

_BREAK_PATTERNS: tuple[tuple[BreakType, str, re.Pattern[str]], ...] = (
    (BreakType.PUNCT, "break_punct", re.compile(r"[;；。！？!?]")),
    (BreakType.NEWLINE, "break_newline", re.compile(r"(?:\r?\n){2,}")),
)

# 英文限定词列表——在 PII 检测中作为结构性 BREAK：
# 真正的地名/组织名不接受冠词或限定词（如 "the street" 是泛指，不是 PII）。
_ENGLISH_DETERMINERS = frozenset({
    "the", "a", "an",
    "this", "that", "these", "those",
    "my", "your", "his", "her", "its", "our", "their",
    "some", "any", "every", "each", "no",
})
_DETERMINER_PATTERN = re.compile(
    r"\b(" + "|".join(sorted(_ENGLISH_DETERMINERS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

_LABEL_FIELD_SEPARATOR_CHARS = ":：-—–=|"
_EN_LABEL_DIRECT_SEPARATOR_CHARS = frozenset(":：-—–")
# 标签边界：匹配到的 label 前方或后方至少有一侧满足此集合中的 unit kind，
# 或处于文本起止位置。防止自然语句中嵌入的关键词被误识别为标签。
_LABEL_BOUNDARY_UNIT_KINDS = frozenset({"punct", "inline_gap", "ocr_break"})
_SEED_ROLES = frozenset({ClueRole.LABEL, ClueRole.START})
_PARSER_FAMILY_ORDER: tuple[ClueFamily, ...] = (
    ClueFamily.STRUCTURED,
    ClueFamily.LICENSE_PLATE,
    ClueFamily.ADDRESS,
    ClueFamily.NAME,
    ClueFamily.ORGANIZATION,
)
_START_ROLES_BY_FAMILY: dict[ClueFamily, frozenset[ClueRole]] = {
    ClueFamily.STRUCTURED: frozenset({ClueRole.VALUE}),
    ClueFamily.LICENSE_PLATE: frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.VALUE}),
    ClueFamily.ADDRESS: frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.VALUE, ClueRole.KEY}),
    ClueFamily.NAME: frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.FAMILY_NAME, ClueRole.GIVEN_NAME, ClueRole.FULL_NAME, ClueRole.ALIAS, ClueRole.VALUE}),
    ClueFamily.ORGANIZATION: frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.SUFFIX, ClueRole.VALUE}),
}
# 数字的非隐私上下文模式。
_NEGATIVE_NUMERIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\d{4}年"),
    re.compile(r"\d{1,3}%"),
    re.compile(r"第\d+[条项页章节]"),
    re.compile(r"No\.\d+"),
    re.compile(r"\d+(?:kg|cm|mm|m|km|g|ml|px|pt|em|rem|dp)\b"),
)
_NEGATIVE_SCOPE_BY_SOURCE_KIND: dict[str, str] = {
    "negative_name_word": "name",
    "negative_address_word": "address",
    "negative_org_word": "organization",
    "negative_ui_word": "ui",
    "negative_numeric_context": "generic",
}

_ASCII_KEYWORD_CHARS_RE = re.compile(r"[A-Za-z0-9 #.'-]+")
_ASCII_LITERAL_CHARS_RE = re.compile(r"[A-Za-z0-9 .,'@_+\-#/&()]+")
_POSTAL_CODE_PATTERN = re.compile(r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)")
_EN_DIRECTIONAL_TOKENS = frozenset({"n", "s", "e", "w", "ne", "nw", "se", "sw"})
_EN_ORDINAL_TOKEN_RE = re.compile(r"\d+(?:st|nd|rd|th)$", re.IGNORECASE)
_EN_SUFFIX_PHRASE_COMPONENTS = frozenset({
    AddressComponentType.POI,
    AddressComponentType.BUILDING,
})
_EN_FL_FLOOR_KEYWORDS = frozenset({"fl", "floor"})


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
    gap_positions: tuple[int, ...] = ()
    gap_prefix_lengths: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class _AddressPatternPayload:
    component_type: AddressComponentType
    canonical_text: str
    strength: ClaimStrength = ClaimStrength.SOFT


@dataclass(frozen=True, slots=True)
class _ControlValuePayload:
    normalized_number: str
    kind: str


@dataclass(frozen=True, slots=True)
class _LicensePlateValuePayload:
    normalized_prefix: str
    kind: str


_DictionaryMetadataItems = tuple[tuple[str, tuple[str, ...]], ...]
_DictionaryMatcherSignature = tuple[tuple[PIIAttributeType, tuple[str, ...], str, _DictionaryMetadataItems], ...]


@dataclass(frozen=True, slots=True)
class _DictionaryMatchPayload:
    attr_type: PIIAttributeType
    matched_by: str
    metadata_items: _DictionaryMetadataItems
    emission_order: int


@dataclass(frozen=True, slots=True)
class _ScanUnitSpans:
    all_ocr_spans: tuple[tuple[int, int], ...] = ()
    ocr_break_only_spans: tuple[tuple[int, int], ...] = ()
    inline_gap_spans: tuple[tuple[int, int], ...] = ()


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
    scan_unit_spans = _collect_scan_unit_spans(stream)
    ocr_break_only_spans = scan_unit_spans.ocr_break_only_spans
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
        _scan_hard_patterns(ctx, stream, ignored_spans=ocr_break_only_spans)
    )

    # ── Pass 2: segment-major clue 扫描 ──
    # 分块依据：STRUCTURED clue span + ocr_break span。段内去除 inline_gap。
    scan_segments = _build_soft_scan_segments(
        stream,
        structured_clues,
        ocr_break_spans=ocr_break_only_spans,
        inline_gap_spans=scan_unit_spans.inline_gap_spans,
    )
    soft_clues: list[Clue] = []
    negative_clues: list[Clue] = []
    for segment in scan_segments:
        soft_clues.extend(_scan_org_address_dictionary_clues(ctx, segment, session_non_structured_entries, source_kind="session"))
        soft_clues.extend(_scan_org_address_dictionary_clues(ctx, segment, local_non_structured_entries, source_kind="local"))
        soft_clues.extend(_scan_name_dictionary_clues(ctx, segment, session_name_entries, source_kind="session"))
        soft_clues.extend(_scan_name_dictionary_clues(ctx, segment, local_name_entries, source_kind="local"))
        soft_clues.extend(_scan_label_clues(ctx, segment))
        soft_clues.extend(_scan_break_clues(ctx, segment))
        soft_clues.extend(_scan_determiner_break_clues(ctx, segment))
        soft_clues.extend(_scan_name_start_clues(ctx, segment))
        soft_clues.extend(_scan_family_name_clues(ctx, segment))
        soft_clues.extend(_scan_en_surname_clues(ctx, segment))
        soft_clues.extend(_scan_en_given_name_clues(ctx, segment))
        soft_clues.extend(_scan_company_suffix_clues(ctx, segment))
        soft_clues.extend(_scan_company_value_clues(ctx, segment))
        soft_clues.extend(_scan_address_clues(ctx, segment, locale_profile=locale_profile))
        soft_clues.extend(_scan_license_plate_value_clues(ctx, segment, locale_profile=locale_profile))
        soft_clues.extend(_scan_control_value_clues(ctx, segment, locale_profile=locale_profile))
        negative_clues.extend(_scan_negative_clues(ctx, segment))
    if locale_profile == "mixed" or locale_profile.startswith("en"):
        soft_clues.extend(_scan_en_address_postal_clues_full_stream(ctx, stream))

    deduped_negative_clues = _dedupe_clues(negative_clues) if negative_clues else []

    # ── 事件扫描线裁决 ──
    all_clues = [*structured_clues, *_scan_ocr_break_clues(ctx, stream, ocr_break_only_spans), *soft_clues]
    resolved_clues, inspire_entries = _sweep_resolve(
        stream,
        all_clues,
        locale_profile=locale_profile,
    )
    ordered_clues = tuple(sorted(resolved_clues, key=lambda item: (item.start, _family_order(item.family), item.end)))
    return ClueBundle(
        all_clues=ordered_clues,
        unit_index=_build_unit_index(
            stream,
            ordered_clues,
            tuple(deduped_negative_clues),
            tuple(inspire_entries),
        ),
        negative_clues=tuple(deduped_negative_clues),
        inspire_entries=tuple(inspire_entries),
    )


def _scan_hard_patterns(ctx: DetectContext, stream: StreamInput, *, ignored_spans: tuple[tuple[int, int], ...] = ()) -> list[Clue]:
    """提取 hard clue：先排除 email/time，再提取通用数字/混合候选片段。

    scanner 只负责提取，不做 phone/id/bank 等规则验证；验证与词典反查由 stack 完成。
    """
    clues: list[Clue] = []
    excluded_spans: list[tuple[int, int]] = list(ignored_spans)
    for segment in _build_hard_scan_segments(stream, ignored_spans=ignored_spans):
        clues.extend(_scan_hard_patterns_segment(ctx, segment, excluded_spans=excluded_spans))
    return clues


def _build_hard_scan_segments(
    stream: StreamInput,
    *,
    ignored_spans: tuple[tuple[int, int], ...],
) -> tuple[_ScanSegment, ...]:
    """构建 hard scan 视图：OCR_BREAK 分段，段内去除 inline_gap。"""
    break_spans = tuple(sorted(set((*_find_ocr_break_only_spans(stream), *ignored_spans))))
    return _build_soft_scan_segments(
        stream,
        (),
        ocr_break_spans=break_spans,
        inline_gap_spans=_find_inline_gap_spans(stream),
    )


def _scan_hard_patterns_segment(
    ctx: DetectContext,
    segment: _ScanSegment,
    *,
    excluded_spans: list[tuple[int, int]],
) -> list[Clue]:
    text = segment.text
    stream = segment.stream
    clues: list[Clue] = []

    def _raw_match_span(match: re.Match[str]) -> tuple[int, int]:
        return _segment_span_to_raw(segment, match.start(), match.end())

    # ── 2a: 先行匹配 email ──
    for match in _EMAIL_PATTERN.finditer(text):
        raw_start, raw_end = _raw_match_span(match)
        cleaned_end = match.end()
        value = match.group(0).strip()
        if not value:
            continue
        if not _email_match_right_boundary_ok(text, cleaned_end):
            continue
        if _overlaps_any(raw_start, raw_end, excluded_spans):
            continue
        _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.EMAIL,
                strength=ClaimStrength.HARD,
                start=raw_start,
                end=raw_end,
                text=value,
                unit_start=_us,
                unit_last=_ue,
                source_kind="regex_email",
                source_metadata={"hard_source": ["regex"], "placeholder": ["<email>"]},
            )
        )
        excluded_spans.append((raw_start, raw_end))

    # ── 2a: 先行匹配 time/date ──
    for source_kind, pattern in _TIME_PATTERNS:
        for match in pattern.finditer(text):
            raw_start, raw_end = _raw_match_span(match)
            if source_kind in _TIME_KINDS_WITH_TOKEN_BOUNDARY and not _time_match_adjacent_ok(text, match.start(), match.end()):
                continue
            value = match.group(0).strip()
            if not value:
                continue
            if _overlaps_any(raw_start, raw_end, excluded_spans):
                continue
            _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    role=ClueRole.VALUE,
                    attr_type=PIIAttributeType.TIME,
                    strength=ClaimStrength.HARD,
                    start=raw_start,
                    end=raw_end,
                    text=value,
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind=source_kind,
                    source_metadata={"hard_source": ["regex"], "placeholder": ["<time>"]},
                )
            )
            excluded_spans.append((raw_start, raw_end))

    # ── 2b: 先行匹配金额，避免金额小数被拆成通用片段。 ──
    for source_kind, pattern in _AMOUNT_PATTERNS:
        for match in pattern.finditer(text):
            raw_start, raw_end = _raw_match_span(match)
            cleaned_end = match.end()
            value = match.group(0).strip()
            if not value:
                continue
            if not _match_right_boundary_allows_trailing_punct(text, cleaned_end):
                continue
            if _overlaps_any(raw_start, raw_end, excluded_spans):
                continue
            _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    role=ClueRole.VALUE,
                    attr_type=PIIAttributeType.AMOUNT,
                    strength=ClaimStrength.HARD,
                    start=raw_start,
                    end=raw_end,
                    text=value,
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind=source_kind,
                    source_metadata={"hard_source": ["regex"], "placeholder": ["<amount>"]},
                )
            )
            excluded_spans.append((raw_start, raw_end))

    # ── 2c: 先提取含 ASCII 字母的结构化片段，避免其内部数字被提前拆走。 ──
    for match in _ALNUM_FRAGMENT_PATTERN.finditer(text):
        value = match.group(0)
        raw_start, raw_end = _raw_match_span(match)
        if _overlaps_any(raw_start, raw_end, excluded_spans):
            continue
        fragment_shape = _alnum_fragment_shape(value)
        if not fragment_shape:
            continue
        digits = re.sub(r"[^0-9]", "", value)
        _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
        source_metadata = {
            "hard_source": ["regex"],
            "placeholder": ["<alnum>"],
            "fragment_type": ["ALNUM"],
            "fragment_shape": [fragment_shape],
        }
        if digits:
            source_metadata["pure_digits"] = [digits]
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ALNUM,
                strength=ClaimStrength.HARD,
                start=raw_start,
                end=raw_end,
                text=value,
                unit_start=_us,
                unit_last=_ue,
                source_kind="extract_alnum_fragment",
                source_metadata=source_metadata,
            )
        )
        excluded_spans.append((raw_start, raw_end))

    # ── 2d: 先提取带国家码 / 括号结构的 phone-like 数字段，避免被通用数字片段拆碎。 ──
    for phone_pattern, phone_region, phone_country_code, pattern in _PHONE_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            raw_start, raw_end = _raw_match_span(match)
            if _overlaps_any(raw_start, raw_end, excluded_spans):
                continue
            digits = re.sub(r"\D", "", value)
            if len(digits) < 10:
                continue
            _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    role=ClueRole.VALUE,
                    attr_type=PIIAttributeType.NUM,
                    strength=ClaimStrength.HARD,
                    start=raw_start,
                    end=raw_end,
                    text=value,
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind="extract_digit_fragment",
                    source_metadata={
                        "hard_source": ["regex"],
                        "placeholder": ["<num>"],
                        "fragment_type": ["NUM"],
                        "fragment_shape": [_numeric_fragment_shape(value)],
                        "pure_digits": [digits],
                        "phone_region": [phone_region],
                        "phone_pattern": [phone_pattern],
                        "phone_country_code": [phone_country_code],
                    },
                )
            )
            excluded_spans.append((raw_start, raw_end))

    # ── 2e: 提取纯数字片段 ──
    for match in _DIGIT_FRAGMENT_PATTERN.finditer(text):
        value = match.group(0)
        raw_start, raw_end = _raw_match_span(match)
        if _overlaps_any(raw_start, raw_end, excluded_spans):
            continue
        digits = re.sub(r"\D", "", value)
        if len(digits) < 2:
            continue
        # 跳过被 _NEGATIVE_NUMERIC_PATTERNS 命中的片段。
        if _is_negative_numeric(text, match.start(), match.end()):
            continue
        _us, _ue = _char_span_to_unit_span(stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.STRUCTURED,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.NUM,
                strength=ClaimStrength.HARD,
                start=raw_start,
                end=raw_end,
                text=value,
                unit_start=_us,
                unit_last=_ue,
                source_kind="extract_digit_fragment",
                source_metadata={
                    "hard_source": ["regex"],
                    "placeholder": ["<num>"],
                    "fragment_type": ["NUM"],
                    "fragment_shape": [_numeric_fragment_shape(value)],
                    "pure_digits": [digits],
                },
            )
        )
        excluded_spans.append((raw_start, raw_end))

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


_CLAIM_STRENGTH_METADATA_KEYS: tuple[str, ...] = (
    "claim_strength",
    "address_component_strength",
)


def _dictionary_claim_strength(metadata: dict[str, list[str]], matched_text: str) -> ClaimStrength:
    """决定词典命中 clue 的 ClaimStrength。

    - 若 metadata 显式携带预置强度（`claim_strength` 或 `address_component_strength`）→ 直接采用。
    - 否则按"去除空白/非词字符后的有效字符数"兜底：1→WEAK，≤3→SOFT，其他→HARD。
      CJK 与字母数字均计入有效字符，避免把"南京"这种两字组件识别成 HARD。
    """
    for key in _CLAIM_STRENGTH_METADATA_KEYS:
        raw_values = metadata.get(key) if metadata else None
        if not raw_values:
            continue
        raw = str(raw_values[0]).strip().lower()
        if not raw:
            continue
        try:
            return ClaimStrength(raw)
        except ValueError:
            # 兼容大小写/enum.name 入参：尝试按枚举名反查一次。
            for member in ClaimStrength:
                if member.name.lower() == raw:
                    return member
            continue
    effective = re.sub(r"[\s\W_]+", "", str(matched_text or ""), flags=re.UNICODE)
    length = len(effective)
    if length <= 1:
        return ClaimStrength.WEAK
    if length <= 3:
        return ClaimStrength.SOFT
    return ClaimStrength.HARD


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
        _us, _ue = _char_span_to_unit_span(stream, start, end)
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
                unit_start=_us,
                unit_last=_ue,
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
        strength = _dictionary_claim_strength(dict_metadata, matched_text)
        _us, _ue = _char_span_to_unit_span(segment.stream, start, end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=_attr_to_family(payload.attr_type),
                role=ClueRole.VALUE,
                attr_type=payload.attr_type,
                strength=strength,
                start=start,
                end=end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
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
        match_text = normalized_stream.text
        folded_text = normalized_stream.text.lower()
    elif isinstance(stream, _ScanSegment):
        normalized_stream = stream.stream
        segment = stream
        # segment 模式下必须只在段内文本上匹配；否则得到的是整条流的绝对坐标，
        # 再交给 `_normalize_segment_ascii_match` 会把 `raw_start` 重复叠加，产生错位甚至越界 span。
        match_text = stream.text
        folded_text = stream.folded_text
    else:
        normalized_stream = stream
        segment = None
        match_text = normalized_stream.text
        folded_text = normalized_stream.text.lower()
    name_entries = tuple(entry for entry in entries if entry.attr_type == PIIAttributeType.NAME)
    if not name_entries:
        return []

    clues: list[Clue] = []
    signature = _dictionary_matcher_signature(name_entries)
    matcher = _session_dictionary_matcher(signature) if source_kind == "session" else _local_dictionary_matcher(signature)
    matches = matcher.find_matches(match_text, folded_text=folded_text)
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
        metadata["name_component_hint"] = [hint_value]
        is_zh_family = component == "family" and _is_cjk_text(matched_text)
        if is_zh_family:
            # 中文单字姓走专用的姓氏流行度降级表，不走字数兜底。
            metadata.update(_zh_surname_metadata(matched_text, from_dictionary=True))
            strength = _zh_surname_claim_strength(matched_text) or ClaimStrength.SOFT
        else:
            metadata["hard_source"] = [source_kind]
            strength = _dictionary_claim_strength(metadata, matched_text)
        _us, _ue = _char_span_to_unit_span(normalized_stream, start, end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=role,
                attr_type=PIIAttributeType.NAME,
                strength=strength,
                start=start,
                end=end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
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
        label_metadata = _seed_metadata(
            segment=segment,
            raw_start=start,
            raw_end=end,
            seed_kind="label",
            extra_metadata=label_metadata,
        )
        _us, _ue = _char_span_to_unit_span(segment.stream, start, end)
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
                unit_start=_us,
                unit_last=_ue,
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
            _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind=source_kind,
                    break_type=break_type,
                )
            )
    return _dedupe_clues(clues)


def _scan_determiner_break_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文限定词，生成 BREAK clue。

    真正的地名/组织名不接受冠词（the Main Street ✗，Main Street ✓），
    因此限定词标志着泛指用法的边界，功能上等同于标点 BREAK。
    """
    clues: list[Clue] = []
    for match in _DETERMINER_PATTERN.finditer(segment.text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start(), match.end())
        text = segment.stream.text
        # ASCII word boundary 双重确认：避免在 CJK 上下文中误触。
        if raw_start > 0 and text[raw_start - 1].isascii() and text[raw_start - 1].isalnum():
            continue
        if raw_end < len(text) and text[raw_end].isascii() and text[raw_end].isalnum():
            continue
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                unit_start=_us,
                unit_last=_ue,
                source_kind="break_determiner",
                break_type=BreakType.DETERMINER,
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
        _us, _ue = _char_span_to_unit_span(stream, start, end)
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
                unit_start=_us,
                unit_last=_ue,
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
        metadata = _seed_metadata(
            segment=segment,
            raw_start=raw_start,
            raw_end=raw_end,
            seed_kind="start",
        )
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                unit_start=_us,
                unit_last=_ue,
                source_kind="name_start",
                source_metadata=metadata,
            )
        )
    return _dedupe_clues(clues)


@lru_cache(maxsize=1)
def _zh_single_surname_strength_map() -> dict[str, ClaimStrength]:
    mapping: dict[str, ClaimStrength] = {}
    for strength, surnames in load_zh_single_surname_claim_strengths().items():
        for surname in surnames:
            mapping[surname] = strength
    return mapping


def _zh_surname_claim_strength(surname: str) -> ClaimStrength | None:
    """返回中文姓氏的 claim_strength；复姓固定为 ``HARD``。"""
    compact = compact_zh_name_text(surname)
    if compact in set(load_zh_compound_surnames()):
        return ClaimStrength.HARD
    return _zh_single_surname_strength_map().get(compact)


def _scan_family_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _family_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        surname_text = str(match.payload)
        metadata = _zh_surname_metadata(surname_text, from_dictionary=False)
        strength = _zh_surname_claim_strength(surname_text) or ClaimStrength.SOFT
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.FAMILY_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=strength,
                start=raw_start,
                end=raw_end,
                text=surname_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="family_name",
                source_metadata=metadata,
            )
        )
    return _dedupe_clues(clues)


def _scan_en_surname_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文姓氏，产出 FAMILY_NAME clue（strength 来自分级词典）。"""
    clues: list[Clue] = []
    for match in _en_surname_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        entry = match.payload
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.FAMILY_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=entry.strength,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="en_surname",
            )
        )
    return _dedupe_clues(clues)


def _scan_en_given_name_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描英文名字（given name），产出 GIVEN_NAME clue（strength 来自分级词典）。"""
    clues: list[Clue] = []
    for match in _en_given_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        entry = match.payload
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.NAME,
                role=ClueRole.GIVEN_NAME,
                attr_type=PIIAttributeType.NAME,
                strength=entry.strength,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="en_given_name",
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
        entry = match.payload
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ORGANIZATION,
                role=ClueRole.SUFFIX,
                attr_type=PIIAttributeType.ORGANIZATION,
                strength=entry.strength,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="company_suffix",
            )
        )
    return _dedupe_clues(clues)


def _scan_company_value_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    """扫描已知公司名（VALUE），用于组织名起栈。"""
    clues: list[Clue] = []
    for match in _company_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        normalized = _normalize_segment_ascii_match(
            segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary,
        )
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        entry = match.payload
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ORGANIZATION,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ORGANIZATION,
                strength=entry.strength,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="company_value",
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


def _scan_license_plate_value_clues(
    ctx: DetectContext,
    segment: _ScanSegment,
    *,
    locale_profile: str,
) -> list[Clue]:
    if locale_profile not in {"zh_cn", "mixed"}:
        return []
    clues: list[Clue] = []
    for match in _zh_license_plate_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
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
        raw_start, raw_end, matched_text = normalized
        payload = match.payload
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.LICENSE_PLATE,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.LICENSE_PLATE,
                strength=ClaimStrength.SOFT,
                start=raw_start,
                end=raw_end,
                text=matched_text,
                unit_start=_us,
                unit_last=_ue,
                source_kind="lexicon_license_plate_prefix_zh",
                source_metadata={
                    "matched_by": ["lexicon_license_plate_prefix_zh"],
                    "value_kind": [payload.kind],
                    "normalized_prefix": [payload.normalized_prefix],
                },
            )
        )
    return _dedupe_clues(clues)


def _scan_control_value_clues(ctx: DetectContext, segment: _ScanSegment, *, locale_profile: str) -> list[Clue]:
    clues: list[Clue] = []
    if locale_profile in {"zh_cn", "mixed"}:
        for match in _zh_control_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
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
            raw_start, raw_end, matched_text = normalized
            payload = match.payload
            _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.CONTROL,
                    role=ClueRole.VALUE,
                    attr_type=None,
                    strength=ClaimStrength.SOFT,
                    start=raw_start,
                    end=raw_end,
                    text=matched_text,
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind="control_value_zh",
                    source_metadata={
                        "control_kind": ["number"],
                        "control_value_kind": [payload.kind],
                        "normalized_number": [payload.normalized_number],
                    },
                )
            )
    if locale_profile in {"en_us", "mixed"}:
        for match in _en_control_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
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
            raw_start, raw_end, matched_text = normalized
            _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
            clues.append(
                Clue(
                    clue_id=ctx.next_clue_id(),
                    family=ClueFamily.CONTROL,
                    role=ClueRole.VALUE,
                    attr_type=None,
                    strength=ClaimStrength.SOFT,
                    start=raw_start,
                    end=raw_end,
                    text=matched_text,
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind="control_value_en",
                    source_metadata={"control_kind": ["copula_en"]},
                )
            )
    return _dedupe_clues(clues)


# ── weak 关键字数字前缀提升规则 ────────────────────────────────


# 中文 weak 关键字前缀强化策略：
# 1. 先用共享规则判断左前缀是否合法；
# 2. 只有这组 key 在合法后会被直接提升为 HARD；
# 3. 号/其他 key 不额外提升，保持词表原强度。
_ZH_WEAK_PROMOTE_TO_HARD = frozenset({"层", "楼", "室", "房", "户", "弄"})


def _promote_weak_zh_keyword(
    stream: StreamInput,
    raw_start: int,
    strength: ClaimStrength,
    canonical_text: str,
) -> ClaimStrength:
    """统一的 weak 关键字提升入口。

    先复用共享的中文地址左前缀校验规则；校验通过后，再按 scanner 自己的
    promotion policy 决定是否升级强度。
    """
    if strength != ClaimStrength.WEAK:
        return strength
    prefix = valid_left_numeral_for_zh_address_key(stream, raw_start, canonical_text)
    if prefix.kind == "none":
        return strength
    if canonical_text in _ZH_WEAK_PROMOTE_TO_HARD:
        return ClaimStrength.HARD
    return strength


def _scan_zh_address_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _zh_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, _matched_text = normalized
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=payload.strength,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                unit_start=_us,
                unit_last=_ue,
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
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        strength = _promote_weak_zh_keyword(
            segment.stream, raw_start, payload.strength, payload.canonical_text,
        )
        key_clue = Clue(
            clue_id=ctx.next_clue_id(),
            family=ClueFamily.ADDRESS,
            role=ClueRole.KEY,
            attr_type=PIIAttributeType.ADDRESS,
            strength=strength,
            start=raw_start,
            end=raw_end,
            text=payload.canonical_text,
            unit_start=_us,
            unit_last=_ue,
            source_kind="address_keyword",
            component_type=payload.component_type,
        )
        clues.append(_try_promote_address_key_to_derived_label(key_clue, segment.stream))
    return clues


def _scan_en_address_clues(ctx: DetectContext, segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _en_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        normalized = _normalize_segment_ascii_match(segment, match.start, match.end, match.matched_text, match.pattern_text, match.ascii_boundary)
        if normalized is None:
            continue
        raw_start, raw_end, matched_text = normalized
        if not _should_emit_en_address_value_match(
            segment.stream,
            raw_start,
            raw_end,
            matched_text=matched_text,
            component_type=payload.component_type,
        ):
            continue
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=payload.strength,
                start=raw_start,
                end=raw_end,
                text=payload.canonical_text,
                unit_start=_us,
                unit_last=_ue,
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
        if not _should_emit_en_address_key_match(
            segment.stream,
            raw_start,
            raw_end,
            matched_text=matched_text,
            component_type=payload.component_type,
        ):
            continue
        if payload.component_type == AddressComponentType.ROAD:
            raw_end = _extend_en_road_key_end_with_direction(segment.stream, raw_end)
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
        key_clue = Clue(
            clue_id=ctx.next_clue_id(),
            family=ClueFamily.ADDRESS,
            role=ClueRole.KEY,
            attr_type=PIIAttributeType.ADDRESS,
            strength=payload.strength,
            start=raw_start,
            end=raw_end,
            text=matched_text,
            unit_start=_us,
            unit_last=_ue,
            source_kind="address_keyword",
            component_type=payload.component_type,
        )
        key_clue = _try_promote_address_key_to_derived_label(key_clue, segment.stream)
        clues.append(key_clue)
        if key_clue.role == ClueRole.KEY:
            phrase_value_clue = _build_en_suffix_phrase_value_clue(
                ctx,
                segment.stream,
                raw_start=raw_start,
                raw_end=raw_end,
                matched_text=matched_text,
                component_type=payload.component_type,
                strength=payload.strength,
            )
            if phrase_value_clue is not None:
                clues.append(phrase_value_clue)
    for token_match in _POSTAL_CODE_PATTERN.finditer(segment.text):
        raw_start, raw_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                unit_start=_us,
                unit_last=_ue,
                source_kind="postal_value",
                component_type=AddressComponentType.POSTAL_CODE,
            )
        )
    return clues


def _scan_en_address_postal_clues_full_stream(ctx: DetectContext, stream: StreamInput) -> list[Clue]:
    """ZIP code 需要绕开 structured 分段，直接在整条英文流上补扫。"""
    clues: list[Clue] = []
    for token_match in _POSTAL_CODE_PATTERN.finditer(stream.text):
        _us, _ue = _char_span_to_unit_span(stream, token_match.start(), token_match.end())
        clues.append(
            Clue(
                clue_id=ctx.next_clue_id(),
                family=ClueFamily.ADDRESS,
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                strength=ClaimStrength.SOFT,
                start=token_match.start(),
                end=token_match.end(),
                text=token_match.group(0),
                unit_start=_us,
                unit_last=_ue,
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
        if _should_skip_en_address_negative_match(
            segment.stream,
            raw_start,
            raw_end,
            matched_text=matched_text,
            source_kind=str(match.payload),
        ):
            continue
        _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                unit_start=_us,
                unit_last=_ue,
                source_kind=str(match.payload),
                source_metadata={"negative_scope": [_negative_scope_for_source_kind(str(match.payload))]},
            )
        )
    # 数字非隐私上下文模式（年份、百分比、序号、计量单位等）。
    for pattern in _NEGATIVE_NUMERIC_PATTERNS:
        for token_match in pattern.finditer(segment.text):
            raw_start, raw_end = _segment_span_to_raw(segment, token_match.start(), token_match.end())
            _us, _ue = _char_span_to_unit_span(segment.stream, raw_start, raw_end)
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
                    unit_start=_us,
                    unit_last=_ue,
                    source_kind="negative_numeric_context",
                    source_metadata={"negative_scope": ["generic"]},
                )
            )
    return clues


def _should_skip_en_address_negative_match(
    stream: StreamInput,
    start: int,
    end: int,
    *,
    matched_text: str,
    source_kind: str,
) -> bool:
    """避免把明显带门牌号的 `Main Street` 误判成英文地址负向短语。"""
    if source_kind != "negative_address_word":
        return False
    if str(matched_text or "").strip().lower() != "main street":
        return False
    previous = _previous_non_space_unit(stream, start)
    if previous is None:
        return False
    token = previous.text.strip()
    return any(char.isdigit() for char in token)


def _is_short_floor_number_unit(unit) -> bool:
    if unit.kind == "digit_run":
        digits = "".join(char for char in unit.text if char.isdigit())
        return 0 < len(digits) <= 2
    if unit.kind == "alnum_run":
        token = unit.text.strip()
        return 0 < len(token) <= 3 and any(char.isdigit() for char in token)
    return False


def _unit_index_left_of_char(stream: StreamInput, char_index: int) -> int:
    if char_index <= 0 or not stream.char_to_unit:
        return -1
    return stream.char_to_unit[char_index - 1]


def _next_non_space_unit(stream: StreamInput, char_index: int):
    if char_index < 0 or char_index >= len(stream.text) or not stream.units:
        return None
    ui = _unit_index_at_or_after(stream, char_index)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.kind not in {"space", "inline_gap"}:
            return unit
        ui += 1
    return None


def _previous_non_space_unit(stream: StreamInput, char_index: int):
    ui = _unit_index_left_of_char(stream, char_index)
    while 0 <= ui < len(stream.units):
        unit = stream.units[ui]
        if unit.kind not in {"space", "inline_gap"}:
            return unit
        ui -= 1
    return None


def _en_fl_context_kind(stream: StreamInput, start: int, end: int, *, matched_text: str) -> str | None:
    token = str(matched_text or "").strip()
    lowered = token.lower()
    if lowered not in _EN_FL_FLOOR_KEYWORDS:
        return None
    previous = _previous_non_space_unit(stream, start)
    next_unit = _next_non_space_unit(stream, end)
    if (
        (previous is not None and _is_short_floor_number_unit(previous))
        or (next_unit is not None and _is_short_floor_number_unit(next_unit))
    ):
        return "floor"
    if lowered == "floor":
        return None
    if token.isupper() and len(token) == 2:
        return "state"
    if previous is not None and previous.kind == "punct" and previous.text in ",，":
        return "state"
    if next_unit is not None and bool(_POSTAL_CODE_PATTERN.fullmatch(next_unit.text)):
        return "state"
    return None


def _should_emit_en_address_value_match(
    stream: StreamInput,
    start: int,
    end: int,
    *,
    matched_text: str,
    component_type: AddressComponentType,
) -> bool:
    if component_type == AddressComponentType.PROVINCE and str(matched_text or "").strip().lower() == "fl":
        return _en_fl_context_kind(stream, start, end, matched_text=matched_text) != "floor"
    return True


def _should_emit_en_address_key_match(
    stream: StreamInput,
    start: int,
    end: int,
    *,
    matched_text: str,
    component_type: AddressComponentType,
) -> bool:
    if component_type == AddressComponentType.DETAIL and str(matched_text or "").strip().lower() in _EN_FL_FLOOR_KEYWORDS:
        return _en_fl_context_kind(stream, start, end, matched_text=matched_text) == "floor"
    return True


def _en_titlecase_like_token(token: str) -> bool:
    stripped = str(token or "").strip()
    if not stripped:
        return False
    if stripped.isupper() and stripped.isalpha():
        return len(stripped) <= 4
    return stripped[0].isalpha() and stripped[0].isupper()


def _en_suffix_phrase_token_allowed(token: str, *, component_type: AddressComponentType) -> bool:
    lowered = str(token or "").strip().lower()
    if not lowered:
        return False
    if component_type == AddressComponentType.ROAD:
        return (
            lowered in _EN_DIRECTIONAL_TOKENS
            or bool(_EN_ORDINAL_TOKEN_RE.fullmatch(lowered))
            or _en_titlecase_like_token(token)
        )
    return _en_titlecase_like_token(token)


def _en_suffix_phrase_start(stream: StreamInput, key_start: int, *, component_type: AddressComponentType) -> int | None:
    if not stream.units or key_start <= 0:
        return None
    ui = _unit_index_left_of_char(stream, key_start)
    earliest_start: int | None = None
    token_count = 0
    while 0 <= ui < len(stream.units):
        unit = stream.units[ui]
        if unit.kind in {"space", "inline_gap"}:
            ui -= 1
            continue
        if unit.kind == "punct" or unit.kind == "ocr_break" or any(is_any_break(char) for char in unit.text):
            break
        token = unit.text.strip()
        if not _en_suffix_phrase_token_allowed(token, component_type=component_type):
            break
        earliest_start = unit.char_start
        token_count += 1
        if token_count >= 3:
            break
        ui -= 1
    return earliest_start if token_count > 0 else None


def _next_non_space_unit_after_direction(stream: StreamInput, direction_end: int):
    if direction_end >= len(stream.text):
        return None
    ui = _unit_index_at_or_after(stream, direction_end)
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.kind in {"space", "inline_gap"}:
            ui += 1
            continue
        return unit
    return None


def _extend_en_road_key_end_with_direction(stream: StreamInput, raw_end: int) -> int:
    if raw_end >= len(stream.text) or not stream.units:
        return raw_end
    direction_unit = _next_non_space_unit(stream, raw_end)
    if direction_unit is None:
        return raw_end
    token = direction_unit.text.strip().lower()
    if token not in _EN_DIRECTIONAL_TOKENS:
        return raw_end
    next_unit = _next_non_space_unit_after_direction(stream, direction_unit.char_end)
    if next_unit is not None and next_unit.kind not in {"punct", "ocr_break"}:
        return raw_end
    return direction_unit.char_end


def _build_en_suffix_phrase_value_clue(
    ctx: DetectContext,
    stream: StreamInput,
    *,
    raw_start: int,
    raw_end: int,
    matched_text: str,
    component_type: AddressComponentType,
    strength: ClaimStrength,
) -> Clue | None:
    if component_type not in _EN_SUFFIX_PHRASE_COMPONENTS:
        return None
    phrase_start = _en_suffix_phrase_start(stream, raw_start, component_type=component_type)
    if phrase_start is None or phrase_start >= raw_start:
        return None
    phrase_text = clean_value(stream.text[phrase_start:raw_end])
    if not phrase_text:
        return None
    normalized = _normalize_address_value(component_type, stream.text[phrase_start:raw_end])
    if not normalized:
        return None
    unit_start, unit_last = _char_span_to_unit_span(stream, phrase_start, raw_end)
    return Clue(
        clue_id=ctx.next_clue_id(),
        family=ClueFamily.ADDRESS,
        role=ClueRole.VALUE,
        attr_type=PIIAttributeType.ADDRESS,
        strength=strength,
        start=phrase_start,
        end=raw_end,
        text=phrase_text,
        unit_start=unit_start,
        unit_last=unit_last,
        source_kind=f"address_phrase_{component_type.value}",
        component_type=component_type,
        source_metadata={"derived_from_keyword": [matched_text]},
    )


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


def _negative_scope_for_source_kind(source_kind: str) -> str:
    """把 negative source_kind 映射到稳定的运行时 scope。"""
    return _NEGATIVE_SCOPE_BY_SOURCE_KIND.get(str(source_kind or ""), "generic")


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
    """STRUCTURED 线索也走统一的同属性裁决。"""
    if not clues:
        return ()
    ordered = sorted(clues, key=lambda c: (c.start, c.end, _family_order(c.family)))
    return tuple(_resolve_same_attr_clues(ordered))


def _build_soft_scan_segments(
    stream: StreamInput,
    structured_clues: tuple[Clue, ...],
    *,
    ocr_break_spans: tuple[tuple[int, int], ...] = (),
    inline_gap_spans: tuple[tuple[int, int], ...] | None = None,
) -> tuple[_ScanSegment, ...]:
    """构建 pass2 扫描段。

    分块依据：STRUCTURED clue span + ocr_break span。
    段内去除 inline_gap token（直接拼接），构建位置回映表。
    """
    gap_spans = _find_inline_gap_spans(stream) if inline_gap_spans is None else inline_gap_spans
    blocked_spans = sorted(
        [(clue.start, clue.end) for clue in structured_clues] + list(ocr_break_spans),
        key=lambda item: (item[0], item[1]),
    )
    segments: list[_ScanSegment] = []
    cursor = 0
    gap_cursor = 0
    for start, end in blocked_spans:
        if start < cursor:
            continue
        if cursor < start:
            segment, gap_cursor = _build_segment_with_gap_removal_with_cursor(
                stream,
                cursor,
                start,
                gap_spans,
                gap_cursor,
            )
            segments.append(segment)
        cursor = end
    if cursor < len(stream.text):
        segment, _ = _build_segment_with_gap_removal_with_cursor(
            stream,
            cursor,
            len(stream.text),
            gap_spans,
            gap_cursor,
        )
        segments.append(segment)
    return tuple(segments)


def _build_segment_with_gap_removal(
    stream: StreamInput,
    raw_start: int,
    raw_end: int,
    inline_gap_spans: tuple[tuple[int, int], ...],
) -> _ScanSegment:
    """构建单个扫描段，去除其中的 inline_gap token 并记录偏移。"""
    segment, _ = _build_segment_with_gap_removal_with_cursor(
        stream,
        raw_start,
        raw_end,
        inline_gap_spans,
        0,
    )
    return segment


def _build_segment_with_gap_removal_with_cursor(
    stream: StreamInput,
    raw_start: int,
    raw_end: int,
    inline_gap_spans: tuple[tuple[int, int], ...],
    gap_cursor: int,
) -> tuple[_ScanSegment, int]:
    """按有序 gap 游标构建扫描段，避免每个 segment 重扫全部 inline gap。"""
    while gap_cursor < len(inline_gap_spans) and inline_gap_spans[gap_cursor][1] <= raw_start:
        gap_cursor += 1
    if gap_cursor >= len(inline_gap_spans) or inline_gap_spans[gap_cursor][0] >= raw_end:
        seg_text = stream.text[raw_start:raw_end]
        return (_ScanSegment(stream=stream, text=seg_text, raw_start=raw_start, folded_text=seg_text.lower()), gap_cursor)

    pieces: list[str] = []
    gap_offsets: list[tuple[int, int]] = []
    gap_positions: list[int] = []
    gap_prefix_lengths: list[int] = []
    piece_cursor = raw_start
    cleaned_pos = 0
    cumulative_gap_length = 0
    next_gap_cursor = gap_cursor
    while next_gap_cursor < len(inline_gap_spans):
        gs, ge = inline_gap_spans[next_gap_cursor]
        if gs >= raw_end:
            break
        if piece_cursor < gs:
            piece = stream.text[piece_cursor:gs]
            pieces.append(piece)
            cleaned_pos += len(piece)
        gap_length = ge - gs
        gap_offsets.append((cleaned_pos, gap_length))
        gap_positions.append(cleaned_pos)
        cumulative_gap_length += gap_length
        gap_prefix_lengths.append(cumulative_gap_length)
        piece_cursor = ge
        next_gap_cursor += 1
    if piece_cursor < raw_end:
        pieces.append(stream.text[piece_cursor:raw_end])

    seg_text = "".join(pieces)
    return (
        _ScanSegment(
            stream=stream,
            text=seg_text,
            raw_start=raw_start,
            folded_text=seg_text.lower(),
            gap_offsets=tuple(gap_offsets),
            gap_positions=tuple(gap_positions),
            gap_prefix_lengths=tuple(gap_prefix_lengths),
        ),
        next_gap_cursor,
    )


def _segment_gap_prefix_total(segment: _ScanSegment, cleaned_pos: int, *, include_equal: bool) -> int:
    """查询 cleaned 位置前累计移除的 gap 长度。"""
    if not segment.gap_positions:
        return 0
    if include_equal:
        index = bisect_right(segment.gap_positions, cleaned_pos) - 1
    else:
        index = bisect_left(segment.gap_positions, cleaned_pos) - 1
    if index < 0:
        return 0
    return segment.gap_prefix_lengths[index]


def _segment_span_to_raw(segment: _ScanSegment, start: int, end: int) -> tuple[int, int]:
    """将 segment cleaned text 的 [start, end) 映射回 stream 原始位置。"""
    start_offset = _segment_gap_prefix_total(segment, start, include_equal=True)
    end_offset = _segment_gap_prefix_total(segment, end, include_equal=False)
    return (segment.raw_start + start + start_offset, segment.raw_start + end + end_offset)


def _segment_raw_end(segment: _ScanSegment) -> int:
    """返回 segment 在原始流中的右边界。"""
    _raw_start, raw_end = _segment_span_to_raw(segment, len(segment.text), len(segment.text))
    return raw_end


def _is_cjk_text(text: str) -> bool:
    compact = compact_zh_name_text(text)
    return bool(compact) and all("\u4e00" <= char <= "\u9fff" for char in compact)


def _zh_surname_metadata(text: str, *, from_dictionary: bool) -> dict[str, list[str]]:
    """为中文姓氏 clue 补充 scanner 元数据。"""
    compact = compact_zh_name_text(text)
    metadata: dict[str, list[str]] = {}
    strength = _zh_surname_claim_strength(compact)
    if compact in set(load_zh_compound_surnames()):
        metadata["surname_match_kind"] = ["compound"]
        metadata["surname_claim_strength"] = [ClaimStrength.HARD.value]
    elif len(compact) == 1 and strength is not None:
        metadata["surname_match_kind"] = ["single"]
        metadata["surname_claim_strength"] = [strength.value]
    else:
        metadata["surname_match_kind"] = ["compound" if len(compact) > 1 else "single"]
        metadata["surname_claim_strength"] = [ClaimStrength.SOFT.value]
    if from_dictionary:
        metadata["surname_from_dictionary"] = ["1"]
    return metadata


def _segment_trimmed_unit_bounds(segment: _ScanSegment) -> tuple[int, int] | None:
    """返回 segment 去掉空白与 inline gap 后的 unit 边界。"""
    stream = segment.stream
    raw_end = _segment_raw_end(segment)
    unit_start, unit_last = _char_span_to_unit_span(stream, segment.raw_start, raw_end)
    if unit_last < unit_start:
        return None
    left = unit_start
    while left <= unit_last and stream.units[left].kind in {"space", "inline_gap"}:
        left += 1
    right = unit_last
    while right >= left and stream.units[right].kind in {"space", "inline_gap"}:
        right -= 1
    if left > right:
        return None
    return (left, right)


def _seed_side_is_blank_or_boundary(stream: StreamInput, *, unit_index: int, is_left: bool) -> bool:
    if is_left:
        if unit_index <= 0:
            return True
        prev = stream.units[unit_index - 1]
        return prev.kind in {"space", *_LABEL_BOUNDARY_UNIT_KINDS}
    if unit_index >= len(stream.units):
        return True
    nxt = stream.units[unit_index]
    return nxt.kind in {"space", *_LABEL_BOUNDARY_UNIT_KINDS}


def _has_label_connector_after(stream: StreamInput, unit_last: int) -> bool:
    scan = unit_last + 1
    while scan < len(stream.units) and stream.units[scan].kind in {"space", "inline_gap"}:
        scan += 1
    if scan >= len(stream.units):
        return False
    unit = stream.units[scan]
    return unit.kind == "punct" and unit.text in _LABEL_FIELD_SEPARATOR_CHARS


def _seed_metadata(
    *,
    segment: _ScanSegment,
    raw_start: int,
    raw_end: int,
    seed_kind: str,
    extra_metadata: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """为 LABEL/START 生成统一的边界元数据。"""
    stream = segment.stream
    metadata = {key: list(values) for key, values in (extra_metadata or {}).items()}
    unit_start, unit_last = _char_span_to_unit_span(stream, raw_start, raw_end)
    trimmed_bounds = _segment_trimmed_unit_bounds(segment)
    seed_is_left_edge = False
    seed_is_right_edge = False
    seed_segment_ratio = 0.0
    if trimmed_bounds is not None:
        trimmed_start, trimmed_last = trimmed_bounds
        seed_is_left_edge = unit_start == trimmed_start
        seed_is_right_edge = unit_last == trimmed_last
        trimmed_raw_start = stream.units[trimmed_start].char_start
        trimmed_raw_end = stream.units[trimmed_last].char_end
        trimmed_length = max(1, trimmed_raw_end - trimmed_raw_start)
        seed_segment_ratio = round((raw_end - raw_start) / trimmed_length, 4)

    seed_has_connector_after = _has_label_connector_after(stream, unit_last)
    seed_surrounded = _seed_side_is_blank_or_boundary(stream, unit_index=unit_start, is_left=True) and _seed_side_is_blank_or_boundary(
        stream,
        unit_index=unit_last + 1,
        is_left=False,
    )
    seed_locale = _resolve_seed_locale(
        stream,
        raw_start=raw_start,
        raw_end=raw_end,
        locale_profile=str(stream.metadata.get("locale_profile", "mixed")),
    )
    metadata["seed_is_left_edge"] = ["1" if seed_is_left_edge else "0"]
    metadata["seed_is_right_edge"] = ["1" if seed_is_right_edge else "0"]
    metadata["seed_has_connector_after"] = ["1" if seed_has_connector_after else "0"]
    metadata["seed_surrounded_by_boundary"] = ["1" if seed_surrounded else "0"]
    metadata["seed_segment_ratio"] = [f"{seed_segment_ratio:.4f}"]
    metadata["seed_kind"] = [seed_kind]
    metadata["seed_locale"] = [seed_locale]
    return metadata


def _unit_flag(unit) -> str | None:
    """将 stream unit 映射为 unit bucket flag。"""
    if unit.kind == "ocr_break":
        return "OCR_BREAK"
    if unit.kind == "inline_gap":
        return "INLINE_GAP"
    if unit.kind == "space" or (unit.text or "").isspace():
        return "SPACE"
    if unit.kind == "punct":
        return unit.text
    return None


def _negative_scopes_for_clue(clue: Clue) -> tuple[str, ...]:
    """读取 negative clue 的 scope；缺失时做兼容兜底。"""
    values = tuple(
        scope
        for scope in (clue.source_metadata.get("negative_scope") or ())
        if scope in NEGATIVE_SCOPES
    )
    if values:
        return values
    inferred = _NEGATIVE_SCOPE_BY_SOURCE_KIND.get(clue.source_kind)
    if inferred is not None:
        return (inferred,)
    # 手写测试 clue 可能没有 source_kind / metadata，默认保留旧“全局 negative”语义。
    return NEGATIVE_SCOPES


def _build_unit_index(
    stream: StreamInput,
    clues: tuple[Clue, ...],
    negative_clues: tuple[Clue, ...],
    inspire_entries: tuple[InspireEntry, ...] = (),
) -> tuple[UnitBucket, ...]:
    """按 survivor clue 与 negative clue 构建 unit bucket。"""
    unit_count = len(stream.units)
    builders = [
            {
                "flag": _unit_flag(unit),
                "structured": [],
                "license_plate": [],
                "address": [],
            "name": [],
            "organization": [],
                "covering": [],
                "inspire": [],
                "break_start": False,
                "negative_cover_scopes": set(),
                "negative_start_scopes": set(),
            }
            for unit in stream.units
        ]

    family_key = {
        ClueFamily.STRUCTURED: "structured",
        ClueFamily.LICENSE_PLATE: "license_plate",
        ClueFamily.ADDRESS: "address",
        ClueFamily.NAME: "name",
        ClueFamily.ORGANIZATION: "organization",
    }
    for clue_index, clue in enumerate(clues):
        if 0 <= clue.unit_start < unit_count and clue.family in family_key:
            builders[clue.unit_start][family_key[clue.family]].append(clue_index)
        if 0 <= clue.unit_start < unit_count and clue.role == ClueRole.BREAK:
            builders[clue.unit_start]["break_start"] = True
        if clue.unit_last < clue.unit_start:
            continue
        for ui in range(max(0, clue.unit_start), min(unit_count - 1, clue.unit_last) + 1):
            builders[ui]["covering"].append(clue_index)

    for inspire_index, inspire in enumerate(inspire_entries):
        if 0 <= inspire.unit_start < unit_count:
            builders[inspire.unit_start]["inspire"].append(inspire_index)

    for clue in negative_clues:
        if clue.unit_last < clue.unit_start:
            continue
        start = max(0, clue.unit_start)
        end = min(unit_count - 1, clue.unit_last)
        if start >= unit_count:
            continue
        scopes = _negative_scopes_for_clue(clue)
        builders[start]["negative_start_scopes"].update(scopes)
        for ui in range(start, end + 1):
            builders[ui]["negative_cover_scopes"].update(scopes)

    buckets: list[UnitBucket] = []
    for builder in builders:
        can_start_parser = tuple(
            family
            for family in _PARSER_FAMILY_ORDER
            if any(
                clues[clue_index].role in _START_ROLES_BY_FAMILY[family]
                for clue_index in builder[family.value]
            )
        )
        buckets.append(
            UnitBucket(
                flag=builder["flag"],
                structured_clues=tuple(builder["structured"]),
                license_plate_clues=tuple(builder["license_plate"]),
                address_clues=tuple(builder["address"]),
                name_clues=tuple(builder["name"]),
                organization_clues=tuple(builder["organization"]),
                covering_clues=tuple(builder["covering"]),
                inspire_entries=tuple(builder["inspire"]),
                can_start_parser=can_start_parser,
                break_start=bool(builder["break_start"]),
                negative_cover_scopes=tuple(sorted(builder["negative_cover_scopes"])),
                negative_start_scopes=tuple(sorted(builder["negative_start_scopes"])),
            )
        )
    return tuple(buckets)


def _char_span_to_unit_span(stream: StreamInput, start: int, end: int) -> tuple[int, int]:
    if not stream.char_to_unit or start >= end:
        return (0, -1)
    return (stream.char_to_unit[start], stream.char_to_unit[end - 1])


def _has_label_boundary(stream: StreamInput, raw_start: int, raw_end: int) -> bool:
    """检查 label 匹配区间的前方或后方至少有一侧是标签边界。

    边界条件（满足任一即可）：
    - 处于流文本的起始 / 末尾位置。
    - 相邻 unit 的 kind 属于 ``_LABEL_BOUNDARY_UNIT_KINDS``（punct / inline_gap / ocr_break）。
    """
    if not stream.char_to_unit:
        return True
    unit_start, unit_last = _char_span_to_unit_span(stream, raw_start, raw_end)
    if unit_last < unit_start:
        return True
    # 左侧：起始位置或相邻 unit 为边界类型。
    if unit_start == 0 or stream.units[unit_start - 1].kind in _LABEL_BOUNDARY_UNIT_KINDS:
        return True
    # 右侧：末尾位置或相邻 unit 为边界类型。
    if unit_last + 1 >= len(stream.units) or stream.units[unit_last + 1].kind in _LABEL_BOUNDARY_UNIT_KINDS:
        return True
    return False


def _has_cjk_char(text: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in str(text or ""))


def _is_non_empty_seed_probe_unit(unit) -> bool:
    if unit.kind in {"space", "inline_gap", "ocr_break", "punct"}:
        return False
    return bool(str(unit.text or "").strip())


def _resolve_seed_locale(
    stream: StreamInput,
    *,
    raw_start: int,
    raw_end: int,
    locale_profile: str,
) -> str:
    """按 locale_profile 与邻近脚本，产出 LABEL/START 的 seed_locale。"""
    profile = str(locale_profile or "mixed").strip().lower()
    if profile == "zh_cn":
        return "zh"
    if profile == "en_us":
        return "en"
    if not stream.units or not stream.char_to_unit or raw_start >= raw_end:
        return "zh" if _has_cjk_char(stream.text[raw_start:raw_end]) else "en"

    unit_start, unit_last = _char_span_to_unit_span(stream, raw_start, raw_end)
    saw_probe_unit = False
    left_probe = unit_start - 1
    while left_probe >= 0:
        if _is_non_empty_seed_probe_unit(stream.units[left_probe]):
            saw_probe_unit = True
            if _has_cjk_char(stream.units[left_probe].text):
                return "zh"
            break
        left_probe -= 1

    right_probe = unit_last + 1
    while right_probe < len(stream.units):
        if _is_non_empty_seed_probe_unit(stream.units[right_probe]):
            saw_probe_unit = True
            if _has_cjk_char(stream.units[right_probe].text):
                return "zh"
            break
        right_probe += 1

    if saw_probe_unit:
        return "en"
    return "zh" if _has_cjk_char(stream.text[raw_start:raw_end]) else "en"


def _zh_label_has_direct_seed_break_after(stream: StreamInput, clue: Clue) -> bool:
    if not stream.units or clue.unit_last + 1 >= len(stream.units):
        return False
    next_unit = stream.units[clue.unit_last + 1]
    if next_unit.kind in {"space", "inline_gap", "ocr_break"}:
        return True
    return next_unit.kind == "punct" and next_unit.text in _LABEL_FIELD_SEPARATOR_CHARS


def _en_label_has_direct_seed_break_after(stream: StreamInput, clue: Clue) -> bool:
    """英文 label direct 仅接受明确字段分隔，不把单空格当 direct。"""
    if not stream.units or clue.unit_last + 1 >= len(stream.units):
        return False
    next_units = stream.units[clue.unit_last + 1 : clue.unit_last + 3]
    if len(next_units) >= 2 and all(unit.kind == "space" for unit in next_units[:2]):
        return True
    for unit in next_units:
        if unit.kind in {"inline_gap", "ocr_break"}:
            return True
        if unit.kind == "punct" and unit.text in _EN_LABEL_DIRECT_SEPARATOR_CHARS:
            return True
    return False


_ADDRESS_DERIVED_LABEL_GAP_KINDS = frozenset({"ocr_break", "inline_gap"})


def _is_address_derived_label(clue: Clue) -> bool:
    return (
        clue.family == ClueFamily.ADDRESS
        and clue.role == ClueRole.LABEL
        and "derived_from_address_key" in clue.source_metadata
    )


def _has_address_derived_label_left_boundary(stream: StreamInput, clue: Clue) -> bool:
    if not stream.units or clue.unit_start <= 0:
        return False
    prev_unit = stream.units[clue.unit_start - 1]
    if prev_unit.kind in _ADDRESS_DERIVED_LABEL_GAP_KINDS:
        return clue.unit_last + 1 < len(stream.units) and stream.units[clue.unit_last + 1].kind in _ADDRESS_DERIVED_LABEL_GAP_KINDS
    if clue.unit_start < 2 or clue.unit_last + 2 > len(stream.units):
        return False
    return all(unit.kind == "space" for unit in stream.units[clue.unit_start - 2: clue.unit_start]) and all(
        unit.kind == "space" for unit in stream.units[clue.unit_last + 1: clue.unit_last + 3]
    )


def _try_promote_address_key_to_derived_label(clue: Clue, stream: StreamInput) -> Clue:
    if clue.family != ClueFamily.ADDRESS or clue.role != ClueRole.KEY:
        return clue
    if not _has_address_derived_label_left_boundary(stream, clue):
        return clue
    levels = clue.component_levels or ((clue.component_type,) if clue.component_type is not None else ())
    metadata = {key: list(values) for key, values in clue.source_metadata.items()}
    metadata["derived_from_address_key"] = [clue.text]
    metadata["seed_kind"] = ["label"]
    return replace(
        clue,
        role=ClueRole.LABEL,
        strength=ClaimStrength.SOFT,
        source_kind="address_keyword_derived_label",
        source_metadata=metadata,
        component_levels=tuple(levels),
    )


def _has_label_direct_seed_break_after(
    stream: StreamInput,
    clue: Clue,
    *,
    locale_profile: str,
) -> bool:
    """判断非结构化 label 右侧是否满足 direct seed 条件。"""
    if _is_address_derived_label(clue):
        return True
    if clue.family not in {ClueFamily.NAME, ClueFamily.ORGANIZATION}:
        return _zh_label_has_direct_seed_break_after(stream, clue)
    seed_locale = (clue.source_metadata.get("seed_locale") or [None])[0]
    if seed_locale not in {"zh", "en"}:
        seed_locale = _resolve_seed_locale(
            stream,
            raw_start=clue.start,
            raw_end=clue.end,
            locale_profile=locale_profile,
        )
    if seed_locale == "zh":
        return _zh_label_has_direct_seed_break_after(stream, clue)
    return _en_label_has_direct_seed_break_after(stream, clue)


def _build_inspire_entry(clue: Clue) -> InspireEntry | None:
    """将降级的 label 转成 inspire side channel。"""
    if clue.attr_type is None or clue.family == ClueFamily.CONTROL:
        return None
    return InspireEntry(
        attr_type=clue.attr_type,
        family=clue.family,
        start=clue.start,
        end=clue.end,
        unit_start=clue.unit_start,
        unit_last=clue.unit_last,
        clue_id=clue.clue_id,
    )


_LABEL_START_CONNECTOR_SKIPPABLE_UNIT_KINDS = frozenset({"space", "inline_gap"})


def _try_convert_label_to_start(stream: StreamInput, clue: Clue) -> Clue | None:
    """尝试将 LABEL 转为 START：后面紧跟"是"或"is"（英文允许跳过空白 unit）则合并。"""
    def _as_start(target_unit_index: int) -> Clue:
        metadata = {key: list(values) for key, values in clue.source_metadata.items()}
        metadata["seed_kind"] = ["start"]
        return replace(
            clue,
            role=ClueRole.START,
            end=stream.units[target_unit_index].char_end,
            unit_last=target_unit_index,
            text=stream.text[clue.start : stream.units[target_unit_index].char_end],
            source_metadata=metadata,
        )

    if not stream.units or clue.unit_last + 1 >= len(stream.units):
        return None
    next_idx = clue.unit_last + 1
    # 中文：紧邻的下一个 unit 是"是"。
    if stream.units[next_idx].text == "是":
        return _as_start(next_idx)
    # 英文：跳过空白/gap unit，检查下一个实质 unit 是否为 "is"。
    scan = next_idx
    while scan < len(stream.units) and stream.units[scan].kind in _LABEL_START_CONNECTOR_SKIPPABLE_UNIT_KINDS:
        scan += 1
    if scan < len(stream.units) and stream.units[scan].text.lower() == "is":
        return _as_start(scan)
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
    unit_start, unit_last = _char_span_to_unit_span(stream, start, end)
    if unit_last < unit_start:
        return None
    first_unit = stream.units[unit_start]
    last_unit = stream.units[unit_last]
    if unit_start == unit_last and first_unit.kind == "ascii_word":
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


def _collect_scan_unit_spans(stream: StreamInput) -> _ScanUnitSpans:
    """一次遍历提取扫描阶段需要的 break / gap span。"""
    all_ocr_spans: list[tuple[int, int]] = []
    ocr_break_only_spans: list[tuple[int, int]] = []
    inline_gap_spans: list[tuple[int, int]] = []
    for unit in stream.units:
        span = (unit.char_start, unit.char_end)
        if unit.kind == "ocr_break":
            all_ocr_spans.append(span)
            ocr_break_only_spans.append(span)
            continue
        if unit.kind == "inline_gap":
            all_ocr_spans.append(span)
            inline_gap_spans.append(span)
    return _ScanUnitSpans(
        all_ocr_spans=tuple(all_ocr_spans),
        ocr_break_only_spans=tuple(ocr_break_only_spans),
        inline_gap_spans=tuple(inline_gap_spans),
    )


def _find_ocr_break_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """返回 ocr_break 和 inline_gap 的 unit span（pass1 排除用）。"""
    return _collect_scan_unit_spans(stream).all_ocr_spans


def _find_ocr_break_only_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """仅返回 ocr_break span（分块边界、BREAK clue 来源）。"""
    return _collect_scan_unit_spans(stream).ocr_break_only_spans


def _find_inline_gap_spans(stream: StreamInput) -> tuple[tuple[int, int], ...]:
    """返回 inline_gap span（段内去除用）。"""
    return _collect_scan_unit_spans(stream).inline_gap_spans


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
    all_surnames = [
        *load_zh_compound_surnames(),
        *[
            surname
            for surnames in load_zh_single_surname_claim_strengths().values()
            for surname in surnames
        ],
    ]
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=surname,
                payload=surname,
                ascii_boundary=_needs_ascii_keyword_boundary(surname),
            )
            for surname in sorted(set(all_surnames), key=len, reverse=True)
        )
    )


@lru_cache(maxsize=1)
def _en_surname_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=entry.text,
                payload=entry,
                ascii_boundary=True,
            )
            for entry in load_en_surnames()
        )
    )


@lru_cache(maxsize=1)
def _en_given_name_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=entry.text,
                payload=entry,
                ascii_boundary=True,
            )
            for entry in load_en_given_names()
        )
    )


@lru_cache(maxsize=1)
def _company_suffix_matcher() -> AhoMatcher:
    """合并中英文组织后缀词典，各自保留独立 strength。"""
    seen: set[str] = set()
    patterns: list[AhoPattern] = []
    for entry in (*load_zh_company_suffixes(), *load_en_company_suffixes()):
        if entry.text in seen:
            continue
        seen.add(entry.text)
        patterns.append(
            AhoPattern(
                text=entry.text,
                payload=entry,
                ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
            )
        )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _company_value_matcher() -> AhoMatcher:
    """合并中英文已知公司名词典。"""
    seen: set[str] = set()
    patterns: list[AhoPattern] = []
    for entry in (*load_zh_company_values(), *load_en_company_values()):
        if entry.text in seen:
            continue
        seen.add(entry.text)
        patterns.append(
            AhoPattern(
                text=entry.text,
                payload=entry,
                ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
            )
        )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _zh_address_value_matcher() -> AhoMatcher:
    lexicon = load_zh_geo_lexicon()
    # 直辖市 / 特别行政区不再做 scanner 端的 special-case 搬运：
    # 词典已在 provinces 与 cities 两层同时登记（例：北京 ∈ provinces.soft ∩ cities.soft），
    # 由下方 dual-emit 机制自然注册为 (PROVINCE, CITY) 两条 clue，
    # 落到 _flush_chain_as_standalone 时再按 _DraftComponent.level 元组合并为 MULTI_ADMIN。
    geo_specs: tuple[tuple[AddressComponentType, tuple[GeoEntry, ...]], ...] = (
        (AddressComponentType.PROVINCE, lexicon.provinces),
        (AddressComponentType.CITY, lexicon.cities),
        (AddressComponentType.DISTRICT, lexicon.districts),
        # 县级市（张家港等）独立注册为 DISTRICT_CITY；与 DISTRICT 同 rank、共享 SINGLE_OCCUPY 槽位。
        (AddressComponentType.DISTRICT_CITY, lexicon.district_cities),
    )
    patterns: list[AhoPattern] = []
    # 中文行政 value 允许同文案多层级并存（如“朝阳”可同时是 city/district），
    # 后续交给地址 stack 的 suspect/route 机制在上下文中消歧。
    seen: set[tuple[AddressComponentType, str]] = set()
    for component_type, entries in geo_specs:
        for entry in sorted(entries, key=lambda e: len(e.text), reverse=True):
            dedupe_key = (component_type, entry.text)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            patterns.append(
                AhoPattern(
                    text=entry.text,
                    payload=_AddressPatternPayload(
                        component_type=component_type,
                        canonical_text=entry.text,
                        strength=entry.strength,
                    ),
                    ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _zh_control_value_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=item.text,
                payload=_ControlValuePayload(
                    normalized_number=item.normalized,
                    kind=item.kind,
                ),
                ascii_boundary=False,
            )
            for item in load_zh_control_values()
        )
    )


@lru_cache(maxsize=1)
def _en_control_value_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=text,
                payload=text,
                ascii_boundary=True,
            )
            for text in ("is", "are", "am")
        )
    )


@lru_cache(maxsize=1)
def _zh_license_plate_value_matcher() -> AhoMatcher:
    return AhoMatcher.from_patterns(
        tuple(
            AhoPattern(
                text=item.text,
                payload=_LicensePlateValuePayload(
                    normalized_prefix=item.normalized,
                    kind=item.kind,
                ),
                ascii_boundary=False,
            )
            for item in load_zh_license_plate_values()
        )
    )


@lru_cache(maxsize=1)
def _zh_address_key_matcher() -> AhoMatcher:
    patterns: list[AhoPattern] = []
    for group in load_zh_address_keyword_groups():
        for entry in group.entries:
            patterns.append(
                AhoPattern(
                    text=entry.text,
                    payload=_AddressPatternPayload(
                        component_type=group.component_type,
                        canonical_text=entry.text,
                        strength=entry.strength,
                    ),
                    ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _en_address_value_matcher() -> AhoMatcher:
    lexicon = load_en_geo_lexicon()
    country_aliases = load_en_address_country_aliases()
    geo_entry_specs: tuple[tuple[AddressComponentType, tuple[GeoEntry, ...]], ...] = (
        (AddressComponentType.PROVINCE, tuple([*lexicon.state_names, *lexicon.state_codes])),
        (AddressComponentType.CITY, lexicon.cities),
        # Borough/行政区登记为 DISTRICT，与 city 解耦；同一文本若兼具多层级由下游按
        # (component_type, text) 去重后组合为 MULTI_ADMIN（参见 §6.1）。
        (AddressComponentType.DISTRICT, lexicon.districts),
    )
    # 国家别名去重后以 SOFT 补入。
    country_names = tuple(
        sorted(
            {canonical.strip() for canonical in country_aliases.values() if canonical.strip()},
            key=len,
            reverse=True,
        )
    )
    patterns: list[AhoPattern] = []
    # §6.1：按 (component_type, text) 去重，使同一串 (如 "New York") 可同时登记为 state+city，
    # 交给下游 address stack 通过 _DraftComponent.level 元组合并为 MULTI_ADMIN。
    seen: set[tuple[AddressComponentType, str]] = set()
    for component_type, entries in geo_entry_specs:
        for entry in sorted(entries, key=lambda e: len(e.text), reverse=True):
            dedupe_key = (component_type, entry.text.lower())
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            patterns.append(
                AhoPattern(
                    text=entry.text,
                    payload=_AddressPatternPayload(
                        component_type=component_type,
                        canonical_text=entry.text,
                        strength=entry.strength,
                    ),
                    ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
                )
            )
    for name in country_names:
        dedupe_key = (AddressComponentType.COUNTRY, name.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        patterns.append(
            AhoPattern(
                text=name,
                payload=_AddressPatternPayload(
                    component_type=AddressComponentType.COUNTRY,
                    canonical_text=name,
                    strength=ClaimStrength.SOFT,
                ),
                ascii_boundary=_needs_ascii_keyword_boundary(name),
            )
        )
    for alias, canonical in sorted(country_aliases.items(), key=lambda item: len(item[0]), reverse=True):
        alias_text = alias.strip()
        canonical_text = canonical.strip()
        if not alias_text or not canonical_text:
            continue
        patterns.append(
            AhoPattern(
                text=alias_text,
                payload=_AddressPatternPayload(
                    component_type=AddressComponentType.COUNTRY,
                    canonical_text=canonical_text,
                ),
                ascii_boundary=_needs_ascii_keyword_boundary(alias_text),
            )
        )
    return AhoMatcher.from_patterns(tuple(patterns))


@lru_cache(maxsize=1)
def _en_address_key_matcher() -> AhoMatcher:
    patterns: list[AhoPattern] = []
    for group in load_en_address_keyword_groups():
        for entry in group.entries:
            patterns.append(
                AhoPattern(
                    text=entry.text,
                    payload=_AddressPatternPayload(
                        component_type=group.component_type,
                        canonical_text=entry.text,
                        strength=entry.strength,
                    ),
                    ascii_boundary=_needs_ascii_keyword_boundary(entry.text),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


def _dedupe_clues(clues: list[Clue]) -> list[Clue]:
    """只去掉字段完全一致的重复 clue。"""

    seen: set[tuple[object, ...]] = set()
    ordered: list[Clue] = []
    for clue in clues:
        key = (
            clue.family,
            clue.role,
            clue.attr_type,
            clue.component_type,
            clue.component_levels,
            clue.strength,
            clue.break_type,
            clue.source_kind,
            clue.start,
            clue.end,
            clue.text,
            clue.unit_start,
            clue.unit_last,
            tuple(
                (meta_key, tuple(meta_values))
                for meta_key, meta_values in sorted(clue.source_metadata.items())
            ),
        )
        if key in seen:
            continue
        seen.add(key)
        ordered.append(clue)
    return ordered


def _resolve_same_attr_clues(clues: Sequence[Clue]) -> list[Clue]:
    """同属性裁决只比较 strength 与 span。"""
    buckets: dict[PIIAttributeType, list[Clue]] = {}
    for clue in clues:
        if clue.attr_type is None:
            continue
        buckets.setdefault(clue.attr_type, []).append(clue)
    if not buckets:
        return list(clues)

    kept_by_id: dict[str, Clue] = {}
    for bucket in buckets.values():
        accepted: list[Clue] = []
        for incoming in bucket:
            drop_incoming = False
            beaten_indices: list[int] = []
            for index, existing in enumerate(accepted):
                if not _clues_overlap(existing, incoming):
                    continue
                if _clues_same_exact_span(existing, incoming):
                    existing_rank = _claim_strength_rank(existing.strength)
                    incoming_rank = _claim_strength_rank(incoming.strength)
                    if existing_rank > incoming_rank:
                        drop_incoming = True
                        break
                    if incoming_rank > existing_rank:
                        beaten_indices.append(index)
                        continue
                    if existing.attr_type == PIIAttributeType.ADDRESS and existing.role == incoming.role:
                        accepted[index] = _merge_exact_equal_address_clues(existing, incoming)
                        drop_incoming = True
                        break
                    if existing.role == ClueRole.ALIAS and incoming.role != ClueRole.ALIAS:
                        beaten_indices.append(index)
                        continue
                    drop_incoming = True
                    break
                outcome = _same_attr_overlap_winner(existing, incoming)
                if outcome == "existing":
                    drop_incoming = True
                    break
                if outcome == "incoming":
                    beaten_indices.append(index)
            if drop_incoming:
                continue
            for index in reversed(beaten_indices):
                del accepted[index]
            accepted.append(incoming)
        for clue in accepted:
            kept_by_id[clue.clue_id] = clue

    return [
        kept_by_id.get(clue.clue_id, clue)
        for clue in clues
        if clue.attr_type is None or clue.clue_id in kept_by_id
    ]


def _clues_same_exact_span(left: Clue, right: Clue) -> bool:
    """判断两条 clue 是否命中同一段 char/unit 区间。"""
    return (
        left.start == right.start
        and left.end == right.end
        and left.unit_start == right.unit_start
        and left.unit_last == right.unit_last
    )


def _clue_component_levels(clue: Clue) -> tuple[AddressComponentType, ...]:
    """统一读取地址 clue 的层级真相。"""
    if clue.component_levels:
        return tuple(clue.component_levels)
    if clue.component_type is None:
        return ()
    return (clue.component_type,)


def _ordered_component_levels(levels: Sequence[AddressComponentType]) -> tuple[AddressComponentType, ...]:
    """稳定整理层级顺序：先行政层级，再保留其他首次出现顺序。"""
    rank = {
        AddressComponentType.PROVINCE: 0,
        AddressComponentType.CITY: 1,
        AddressComponentType.DISTRICT: 2,
        AddressComponentType.DISTRICT_CITY: 3,
        AddressComponentType.SUBDISTRICT: 4,
    }
    seen: list[AddressComponentType] = []
    for level in levels:
        if level not in seen:
            seen.append(level)
    admins = sorted((level for level in seen if level in rank), key=lambda item: rank[item])
    others = [level for level in seen if level not in rank]
    return tuple([*admins, *others])


def _derived_component_type(levels: Sequence[AddressComponentType]) -> AddressComponentType | None:
    ordered = _ordered_component_levels(levels)
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    return AddressComponentType.MULTI_ADMIN


def _merge_exact_equal_address_clues(existing: Clue, incoming: Clue) -> Clue:
    """把 exact-equal 地址 clue 合并成单条 survivor。"""
    merged_levels = _ordered_component_levels([
        *_clue_component_levels(existing),
        *_clue_component_levels(incoming),
    ])
    merged_metadata = {
        key: list(values)
        for key, values in existing.source_metadata.items()
    }
    for key, values in incoming.source_metadata.items():
        bucket = merged_metadata.setdefault(key, [])
        for value in values:
            if value not in bucket:
                bucket.append(value)
    return replace(
        existing,
        component_type=_derived_component_type(merged_levels),
        component_levels=merged_levels,
        source_metadata=merged_metadata,
    )


def _same_attr_overlap_winner(existing: Clue, incoming: Clue) -> str:
    """返回同属性重叠时应保留的一侧。"""
    existing_rank = _claim_strength_rank(existing.strength)
    incoming_rank = _claim_strength_rank(incoming.strength)
    if existing_rank > incoming_rank:
        return "existing"
    if incoming_rank > existing_rank:
        return "incoming"
    if existing.start == incoming.start and existing.end == incoming.end:
        return "both"
    if _strictly_contains(existing, incoming):
        return "existing"
    if _strictly_contains(incoming, existing):
        return "incoming"
    existing_len = existing.end - existing.start
    incoming_len = incoming.end - incoming.start
    if existing_len > incoming_len:
        return "existing"
    if incoming_len > existing_len:
        return "incoming"
    return "incoming"


def _sweep_resolve(
    stream: StreamInput,
    clues: list[Clue],
    *,
    locale_profile: str = "mixed",
) -> tuple[list[Clue], list[InspireEntry]]:
    """按“跨属性遮蔽 + 同属性裁决”两层规则收敛 clue。"""
    if not clues:
        return [], []
    unit_len = len(stream.units)
    deduped = _dedupe_clues(clues)

    # ── 轮 1：STRUCTURED / BREAK 遮蔽 + seed 连通块 + label direct/inspire 分流 ──
    survivors, seed_groups, inspire_entries = _sweep_pass1(
        stream,
        deduped,
        unit_len,
        locale_profile=locale_profile,
    )

    # ── Seed 裁决 ──
    seed_winner_ids: set[str] = set()
    for group in seed_groups:
        for winner in _resolve_seed_group(group):
            seed_winner_ids.add(winner.clue_id)
    survivors = [
        clue for clue in survivors
        if clue.role not in _SEED_ROLES or clue.clue_id in seed_winner_ids
    ]

    # ── 普通 clue 的同属性裁决 ──
    protected_ids = {
        clue.clue_id
        for clue in survivors
        if clue.role in _SEED_ROLES
        or clue.role == ClueRole.BREAK
        or clue.family in {ClueFamily.STRUCTURED, ClueFamily.CONTROL}
    }
    ordinary = [
        clue
        for clue in survivors
        if clue.clue_id not in protected_ids
    ]
    ordinary_resolved = _resolve_same_attr_clues(ordinary)
    ordinary_by_id = {clue.clue_id: clue for clue in ordinary_resolved}
    survivors = [
        ordinary_by_id.get(clue.clue_id, clue)
        for clue in survivors
        if clue.clue_id in protected_ids or clue.clue_id in ordinary_by_id
    ]

    # ── seed 严格包含普通 clue ──
    return _apply_seed_containment_coverage(survivors), inspire_entries


def _build_events(
    clues: list[Clue],
    unit_len: int,
) -> tuple[list[list[Clue]], list[list[Clue]]]:
    """构建 unit 轴上的 start / end 事件数组。"""
    start_events: list[list[Clue]] = [[] for _ in range(unit_len + 1)]
    end_events: list[list[Clue]] = [[] for _ in range(unit_len + 1)]
    for clue in clues:
        start_events[clue.unit_start].append(clue)
        end_events[clue.unit_last].append(clue)
    return start_events, end_events


def _sweep_pass1(
    stream: StreamInput,
    clues: list[Clue],
    unit_len: int,
    *,
    locale_profile: str = "mixed",
) -> tuple[list[Clue], list[list[Clue]], list[InspireEntry]]:
    """扫描轮 1（unit 轴）：STRUCTURED / BREAK 遮蔽 + seed 连通块收集 + LABEL direct/inspire 分流。

    STRUCTURED 和 BREAK 无条件保留并形成活跃区间；
    其他 soft clue 落在活跃区间内则过滤。
    LABEL 先尝试拼接"是"/"is"转 START。
    - STRUCTURED label 满足边界时保留为 direct LABEL，否则降级为 inspire。
    - 非 STRUCTURED label 若右侧满足 direct seed break，则保留为 direct LABEL。
    - 否则降级为 inspire side channel，不进入 parser seed 流程。
    """
    start_events, end_events = _build_events(clues, unit_len)

    active_structured = 0
    active_break = 0
    survivors: list[Clue] = []
    inspire_entries: list[InspireEntry] = []

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

            if active_structured > 0 and not _is_address_postal_value_clue(clue):
                continue
            if active_break > 0:
                continue

            # LABEL 当场判定：先尝试拼接"是"/"is"转 START，再做 direct/inspire 分流。
            if role == ClueRole.LABEL:
                converted = _try_convert_label_to_start(stream, clue)
                if converted is not None:
                    clue = converted
                    role = ClueRole.START
                elif clue.family == ClueFamily.STRUCTURED:
                    if not _has_label_boundary(stream, clue.start, clue.end):
                        inspire = _build_inspire_entry(clue)
                        if inspire is not None:
                            inspire_entries.append(inspire)
                        continue
                elif not _has_label_direct_seed_break_after(
                    stream,
                    clue,
                    locale_profile=locale_profile,
                ):
                    inspire = _build_inspire_entry(clue)
                    if inspire is not None:
                        inspire_entries.append(inspire)
                    continue

            survivors.append(clue)

            if role in _SEED_ROLES:
                if clue.unit_start < seed_group_end:
                    cur_seed_group.append(clue)
                else:
                    if cur_seed_group:
                        seed_groups.append(cur_seed_group)
                    cur_seed_group = [clue]
                seed_group_end = max(seed_group_end, clue.unit_last)

    if cur_seed_group:
        seed_groups.append(cur_seed_group)

    return survivors, seed_groups, inspire_entries


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


def _apply_seed_containment_coverage(clues: list[Clue]) -> list[Clue]:
    """seed 严格包含普通 clue 时，直接删除被包含的 clue。

    这里只做单向裁决：LABEL/START 作为 seed 覆盖普通 clue；
    普通 clue 即使更长，也不会反向删除 seed。
    """
    seed_clues = [c for c in clues if c.role in _SEED_ROLES]
    covered_candidates = [
        c
        for c in clues
        if c.role not in _SEED_ROLES and c.role != ClueRole.BREAK and c.family != ClueFamily.CONTROL
    ]
    if not seed_clues or not covered_candidates:
        return clues

    dropped_ids: set[str] = set()
    for seed in seed_clues:
        if seed.clue_id in dropped_ids:
            continue
        for clue in covered_candidates:
            if clue.clue_id in dropped_ids:
                continue
            if not _clues_overlap(seed, clue):
                continue
            if seed.start <= clue.start and clue.end <= seed.end and (seed.start < clue.start or clue.end < seed.end):
                dropped_ids.add(clue.clue_id)

    return [c for c in clues if c.clue_id not in dropped_ids]


def _claim_strength_rank(strength: ClaimStrength) -> int:
    return {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }[strength]


def _strictly_contains(container: Clue, contained: Clue) -> bool:
    return (
        container.start <= contained.start
        and contained.end <= container.end
        and (container.start < contained.start or contained.end < container.end)
    )


def _skip_whitespace_right(raw_text: str, start: int) -> int:
    index = start
    while index < len(raw_text) and raw_text[index].isspace():
        index += 1
    return index


def _clues_overlap(left: Clue, right: Clue) -> bool:
    return not (left.end <= right.start or left.start >= right.end)


def _overlaps_any(start: int, end: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)

    stream.metadata["locale_profile"] = locale_profile
