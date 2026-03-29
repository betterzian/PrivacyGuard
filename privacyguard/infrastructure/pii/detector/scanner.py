"""Detector 流式 clue 扫描器。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from itertools import count

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import load_china_geo_lexicon, load_en_geo_lexicon
from privacyguard.infrastructure.pii.detector.labels import _LABEL_SPECS
from privacyguard.infrastructure.pii.detector.matcher import AhoMatcher, AhoPattern
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    BreakType,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
    DictionaryEntry,
    StreamInput,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

_CLUE_IDS = count(1)

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

_LABEL_FAMILY_BY_ATTR: dict[PIIAttributeType, ClueFamily] = {
    PIIAttributeType.EMAIL: ClueFamily.STRUCTURED,
    PIIAttributeType.PHONE: ClueFamily.STRUCTURED,
    PIIAttributeType.ID_NUMBER: ClueFamily.STRUCTURED,
    PIIAttributeType.CARD_NUMBER: ClueFamily.STRUCTURED,
    PIIAttributeType.BANK_ACCOUNT: ClueFamily.STRUCTURED,
    PIIAttributeType.PASSPORT_NUMBER: ClueFamily.STRUCTURED,
    PIIAttributeType.DRIVER_LICENSE: ClueFamily.STRUCTURED,
    PIIAttributeType.NAME: ClueFamily.NAME,
    PIIAttributeType.ORGANIZATION: ClueFamily.ORGANIZATION,
    PIIAttributeType.ADDRESS: ClueFamily.ADDRESS,
}

_HARD_PATTERNS: tuple[tuple[PIIAttributeType, str, re.Pattern[str], int], ...] = (
    (PIIAttributeType.EMAIL, "regex_email", re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"), 120),
    (PIIAttributeType.PHONE, "regex_phone_cn", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"), 118),
    (PIIAttributeType.PHONE, "regex_phone_us", re.compile(r"(?<!\w)(?:\(\d{3}\)\s*|\d{3}[-. ]?)\d{3}[-. ]\d{4}(?!\w)"), 117),
    (PIIAttributeType.ID_NUMBER, "regex_id_cn", re.compile(r"(?<![\w\d])\d{17}[\dXx](?![\w\d])"), 115),
    (PIIAttributeType.BANK_ACCOUNT, "regex_bank_account", re.compile(r"(?<!\d)\d(?:[ -]?\d){11,22}(?!\d)"), 110),
    (PIIAttributeType.PASSPORT_NUMBER, "regex_passport", re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{8}(?![A-Za-z0-9])"), 108),
    (PIIAttributeType.DRIVER_LICENSE, "regex_driver_license", re.compile(r"(?<![A-Za-z0-9])(?:[A-Z][A-Z0-9\\-]{4,23}|[0-9][A-Z][A-Z0-9\\-]{3,22})(?![A-Za-z0-9])"), 107),
)

_COMPANY_SUFFIXES = (
    "股份有限公司",
    "有限责任公司",
    "有限公司",
    "研究院",
    "实验室",
    "工作室",
    "事务所",
    "集团",
    "公司",
    "大学",
    "学院",
    "银行",
    "酒店",
    "医院",
    "中心",
    "incorporated",
    "corporation",
    "company",
    "limited",
    "inc",
    "corp",
    "co",
    "ltd",
    "llc",
    "plc",
    "gmbh",
    "pte",
    "university",
    "college",
    "bank",
    "hotel",
    "hospital",
    "clinic",
    "lab",
    "labs",
)

_NAME_START_KEYWORDS = (
    "我是",
    "我叫",
    "姓名是",
    "名字叫",
    "this is",
    "i am",
    "i'm",
    "my name is",
    "name is",
)

_COMMON_FAMILY_NAMES = tuple(
    sorted(
        {
            "赵", "钱", "孙", "李", "周", "吴", "郑", "王", "冯", "陈", "褚", "卫", "蒋", "沈", "韩", "杨",
            "朱", "秦", "尤", "许", "何", "吕", "施", "张", "孔", "曹", "严", "华", "金", "魏", "陶", "姜",
            "戚", "谢", "邹", "喻", "柏", "水", "窦", "章", "云", "苏", "潘", "葛", "奚", "范", "彭", "郎",
            "鲁", "韦", "昌", "马", "苗", "凤", "花", "方", "俞", "任", "袁", "柳", "酆", "鲍", "史", "唐",
            "费", "廉", "岑", "薛", "雷", "贺", "倪", "汤", "滕", "殷", "罗", "毕", "郝", "邬", "安", "常",
            "乐", "于", "时", "傅", "皮", "卞", "齐", "康", "伍", "余", "元", "卜", "顾", "孟", "平", "黄",
            "和", "穆", "萧", "尹", "姚", "邵", "湛", "汪", "祁", "毛", "禹", "狄", "米", "贝", "明", "臧",
            "计", "伏", "成", "戴", "谈", "宋", "茅", "庞", "熊", "纪", "舒", "屈", "项", "祝", "董", "梁",
            "杜", "阮", "蓝", "闵", "席", "季", "麻", "强", "贾", "路", "娄", "危", "江", "童", "颜", "郭",
            "梅", "盛", "林", "刁", "钟", "徐", "邱", "骆", "高", "夏", "蔡", "田", "樊", "胡", "凌", "霍",
            "虞", "万", "支", "柯", "昝", "管", "卢", "莫", "经", "房", "裘", "缪", "干", "解", "应", "宗",
            "丁", "宣", "贲", "邓", "郁", "单", "杭", "洪", "包", "诸", "左", "石", "崔", "吉", "钮", "龚",
            "程", "嵇", "邢", "滑", "裴", "陆", "荣", "翁", "荀", "羊", "於", "惠", "甄", "曲", "家", "封",
            "芮", "羿", "储", "靳", "汲", "邴", "糜", "松", "井", "段", "富", "巫", "乌", "焦", "巴", "弓",
            "牧", "隗", "山", "谷", "车", "侯", "宓", "蓬", "全", "郗", "班", "仰", "秋", "仲", "伊", "宫",
            "宁", "仇", "栾", "暴", "甘", "斜", "厉", "戎", "祖", "武", "符", "刘", "景", "詹", "束", "龙",
            "叶", "幸", "司", "韶", "郜", "黎", "蓟", "薄", "印", "宿", "白", "怀", "蒲", "邰", "从", "鄂",
            "索", "咸", "籍", "赖", "卓", "蔺", "屠", "蒙", "池", "乔", "阴", "鬱", "胥", "能", "苍", "双",
            "闻", "莘", "党", "翟", "谭", "贡", "劳", "逄", "姬", "申", "扶", "堵", "冉", "宰", "郦", "雍",
            "却", "璩", "桑", "桂", "濮", "牛", "寿", "通", "边", "扈", "燕", "冀", "郏", "浦", "尚", "农",
            "温", "别", "庄", "晏", "柴", "瞿", "阎", "充", "慕", "连", "茹", "习", "宦", "艾", "鱼", "容",
            "向", "古", "易", "慎", "戈", "廖", "庾", "终", "暨", "居", "衡", "步", "都", "耿", "满", "弘",
            "匡", "国", "文", "寇", "广", "禄", "阙", "东", "欧阳", "司马", "上官", "夏侯", "诸葛", "闻人",
            "东方", "赫连", "皇甫", "尉迟", "公羊", "澹台", "公冶", "宗政", "濮阳", "淳于", "单于", "太叔",
            "申屠", "公孙", "仲孙", "轩辕", "令狐", "钟离", "宇文", "长孙", "慕容", "鲜于", "闾丘", "司徒",
            "司空", "丌官", "司寇", "南宫",
        },
        key=len,
        reverse=True,
    )
)

_ZH_ADDRESS_ATTRS: tuple[tuple[AddressComponentType, tuple[str, ...]], ...] = (
    (AddressComponentType.PROVINCE, ("特别行政区", "自治区", "省")),
    (AddressComponentType.CITY, ("自治州", "地区", "盟", "市")),
    (AddressComponentType.DISTRICT, ("新区", "区", "县", "旗")),
    (AddressComponentType.STREET_ADMIN, ("街道",)),
    (AddressComponentType.TOWN, ("镇", "乡")),
    (AddressComponentType.VILLAGE, ("社区", "村")),
    (AddressComponentType.ROAD, ("大道", "胡同", "路", "街", "道", "巷", "弄")),
    (AddressComponentType.COMPOUND, ("小区", "公寓", "大厦", "园区", "花园", "家园", "苑", "庭", "府", "湾", "宿舍")),
    (AddressComponentType.BUILDING, ("号楼", "栋", "幢", "座", "楼")),
    (AddressComponentType.UNIT, ("单元",)),
    (AddressComponentType.FLOOR, ("层",)),
    (AddressComponentType.ROOM, ("室", "房", "户")),
)

_EN_ADDRESS_ATTRS: tuple[tuple[AddressComponentType, tuple[str, ...]], ...] = (
    (AddressComponentType.STREET, ("street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd", "drive", "dr", "lane", "ln", "court", "ct", "place", "pl", "parkway", "pkwy", "terrace", "ter", "circle", "cir", "way", "highway", "hwy")),
    (AddressComponentType.UNIT, ("apt", "apartment", "suite", "ste", "unit", "#")),
    (AddressComponentType.FLOOR, ("floor", "fl")),
    (AddressComponentType.ROOM, ("room", "rm")),
)

_BREAK_PATTERNS: tuple[tuple[BreakType, str, re.Pattern[str]], ...] = (
    (BreakType.PUNCT, "break_punct", re.compile(r"[;；。！？!?]")),
    (BreakType.NEWLINE, "break_newline", re.compile(r"(?:\r?\n){2,}")),
)

_ASCII_KEYWORD_CHARS_RE = re.compile(r"[A-Za-z0-9 #.'-]+")
_ASCII_LITERAL_CHARS_RE = re.compile(r"[A-Za-z0-9 .,'@_+\-#/&()]+")
_POSTAL_CODE_PATTERN = re.compile(r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)")


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
    session_entries: tuple[DictionaryEntry, ...],
    local_entries: tuple[DictionaryEntry, ...],
    locale_profile: str,
) -> ClueBundle:
    literal_pattern_cache: dict[tuple[str, bool], re.Pattern[str]] = {}
    ocr_break_spans = _find_ocr_break_spans(stream.raw_text)
    hard_clues = _resolve_hard_conflicts(
        [
            *_scan_hard_patterns(stream.raw_text, ignored_spans=ocr_break_spans),
            *_scan_dictionary_hard_clues(
                stream.raw_text,
                session_entries,
                source_kind="session",
                pattern_cache=literal_pattern_cache,
                ignored_spans=ocr_break_spans,
            ),
            *_scan_dictionary_hard_clues(
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
        for clue in _scan_label_clues(segment)
    )
    label_spans = tuple((clue.start, clue.end) for clue in label_clues)
    soft_clues = [
        *label_clues,
        *_scan_ocr_break_clues(ocr_break_spans),
        *(clue for segment in scan_segments for clue in _scan_break_clues(segment)),
        *(clue for segment in scan_segments for clue in _scan_name_start_clues(segment)),
        *(clue for segment in scan_segments for clue in _scan_family_name_clues(segment)),
        *(clue for segment in scan_segments for clue in _scan_company_suffix_clues(segment)),
        *(clue for segment in scan_segments for clue in _scan_address_clues(segment, locale_profile=locale_profile)),
    ]
    soft_clues = [clue for clue in soft_clues if clue in label_clues or not _overlaps_any(clue.start, clue.end, label_spans)]
    all_clues = tuple(sorted([*hard_clues, *soft_clues], key=lambda item: (item.start, -item.priority, item.end)))
    return ClueBundle(all_clues=all_clues)


def _scan_hard_patterns(text: str, *, ignored_spans: tuple[tuple[int, int], ...] = ()) -> list[Clue]:
    clues: list[Clue] = []
    for attr_type, matched_by, pattern, priority in _HARD_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if not value:
                continue
            if _overlaps_any(match.start(), match.end(), ignored_spans):
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    role=ClueRole.HARD,
                    attr_type=attr_type,
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    priority=priority,
                    source_kind=matched_by,
                    hard_source="regex",
                    placeholder=_PLACEHOLDER_BY_ATTR[attr_type],
                )
            )
    return clues


def _scan_dictionary_hard_clues(
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
                        clue_id=_next_clue_id(),
                        family=ClueFamily.STRUCTURED,
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


def _scan_label_clues(segment: _ScanSegment) -> tuple[Clue, ...]:
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
                clue_id=_next_clue_id(),
                family=_LABEL_FAMILY_BY_ATTR[spec.attr_type],
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


def _scan_break_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for break_type, source_kind, pattern in _BREAK_PATTERNS:
        for match in pattern.finditer(segment.text):
            raw_start, raw_end = _segment_span_to_raw(segment, match.start(), match.end())
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.BREAK,
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


def _scan_ocr_break_clues(ocr_break_spans: tuple[tuple[int, int], ...]) -> list[Clue]:
    clues: list[Clue] = []
    for start, end in ocr_break_spans:
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.BREAK,
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


def _scan_name_start_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _name_start_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.NAME,
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


def _scan_family_name_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _family_name_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        tail = segment.text[match.end : match.end + 4]
        if any(keyword in tail for keyword in ("省", "市", "区", "县", "旗", "路", "街", "道", "大道", "小区", "单元", "栋", "室", "住址", "地址")):
            continue
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.NAME,
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


def _scan_company_suffix_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _company_suffix_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.ORGANIZATION,
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


def _scan_address_clues(segment: _ScanSegment, *, locale_profile: str) -> list[Clue]:
    clues: list[Clue] = []
    if locale_profile in {"zh_cn", "mixed"}:
        clues.extend(_scan_zh_address_clues(segment))
    if locale_profile in {"en_us", "mixed"}:
        clues.extend(_scan_en_address_clues(segment))
    return _dedupe_clues(clues)


def _scan_zh_address_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _zh_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
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
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
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


def _scan_en_address_clues(segment: _ScanSegment) -> list[Clue]:
    clues: list[Clue] = []
    for match in _en_address_value_matcher().find_matches(segment.text, folded_text=segment.folded_text):
        payload = match.payload
        raw_start, raw_end = _segment_span_to_raw(segment, match.start, match.end)
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
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
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
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
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
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
            for spec in _LABEL_SPECS
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
            for keyword in sorted(set(_NAME_START_KEYWORDS), key=len, reverse=True)
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
            for surname in _COMMON_FAMILY_NAMES
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
            for suffix in sorted(set(_COMPANY_SUFFIXES), key=len, reverse=True)
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
    for component_type, keywords in _ZH_ADDRESS_ATTRS:
        for keyword in sorted(set(keywords), key=len, reverse=True):
            patterns.append(
                AhoPattern(
                    text=keyword,
                    payload=_AddressPatternPayload(component_type=component_type, canonical_text=keyword),
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
    for component_type, keywords in _EN_ADDRESS_ATTRS:
        for keyword in sorted(set(keywords), key=len, reverse=True):
            patterns.append(
                AhoPattern(
                    text=keyword,
                    payload=_AddressPatternPayload(component_type=component_type, canonical_text=keyword),
                    ascii_boundary=_needs_ascii_keyword_boundary(keyword),
                )
            )
    return AhoMatcher.from_patterns(tuple(patterns))


def _dedupe_clues(clues: list[Clue]) -> list[Clue]:
    seen: set[tuple[object, ...]] = set()
    ordered: list[Clue] = []
    for clue in sorted(
        clues,
        key=lambda item: (
            item.start,
            -(item.end - item.start),
            -item.priority,
            item.family.value,
            item.role.value,
            item.component_type or "",
        ),
    ):
        key = (
            clue.family,
            clue.role,
            clue.component_type,
            clue.start,
            clue.end,
            clue.text.lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        ordered.append(clue)
    occupied: list[tuple[int, int]] = []
    filtered: list[Clue] = []
    for clue in ordered:
        if clue.family == ClueFamily.BREAK:
            filtered.append(clue)
            continue
        if any(not (clue.end <= left or clue.start >= right) for left, right in occupied):
            if clue.role in {ClueRole.LABEL, ClueRole.KEY}:
                continue
        filtered.append(clue)
        if clue.role in {ClueRole.LABEL, ClueRole.KEY, ClueRole.VALUE}:
            occupied.append((clue.start, clue.end))
    return sorted(filtered, key=lambda item: (item.start, item.end, -item.priority))


def _overlaps_any(start: int, end: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)


def _next_clue_id() -> str:
    return f"clue-{next(_CLUE_IDS)}"
