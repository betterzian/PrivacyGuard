"""Clean clue scanner for the detector stream."""

from __future__ import annotations

import re
from itertools import count

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.address.geo_db import load_china_geo_lexicon, load_en_geo_lexicon
from privacyguard.infrastructure.pii.detector.labels import _LABEL_SPECS
from privacyguard.infrastructure.pii.detector.models import Clue, ClueBundle, ClueFamily, DictionaryEntry, StreamInput
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

_ZH_ADDRESS_ATTRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("province", ("特别行政区", "自治区", "省")),
    ("city", ("自治州", "地区", "盟", "市")),
    ("district", ("新区", "区", "县", "旗")),
    ("street_admin", ("街道",)),
    ("town", ("镇", "乡")),
    ("village", ("社区", "村")),
    ("road", ("大道", "胡同", "路", "街", "道", "巷", "弄")),
    ("compound", ("小区", "公寓", "大厦", "园区", "花园", "家园", "苑", "庭", "府", "湾", "宿舍")),
    ("building", ("号楼", "栋", "幢", "座", "楼")),
    ("unit", ("单元",)),
    ("floor", ("层",)),
    ("room", ("室", "房", "户")),
)

_EN_ADDRESS_ATTRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("street", ("street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd", "drive", "dr", "lane", "ln", "court", "ct", "place", "pl", "parkway", "pkwy", "terrace", "ter", "circle", "cir", "way", "highway", "hwy")),
    ("unit", ("apt", "apartment", "suite", "ste", "unit", "#")),
    ("floor", ("floor", "fl")),
    ("room", ("room", "rm")),
)

_BREAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("break_punct", re.compile(r"[;；。！？!?]")),
    ("break_newline", re.compile(r"(?:\r?\n){2,}")),
)


def build_clue_bundle(
    stream: StreamInput,
    *,
    session_entries: tuple[DictionaryEntry, ...],
    local_entries: tuple[DictionaryEntry, ...],
    locale_profile: str,
) -> ClueBundle:
    hard_clues = _resolve_hard_conflicts(
        [
            *_scan_hard_patterns(stream.raw_text),
            *_scan_dictionary_hard_clues(stream.raw_text, session_entries, source_kind="session"),
            *_scan_dictionary_hard_clues(stream.raw_text, local_entries, source_kind="local"),
        ]
    )
    shadow_text, shadow_to_raw = _build_shadow_text(stream.raw_text, hard_clues)
    label_clues = _scan_label_clues(shadow_text, shadow_to_raw)
    label_spans = tuple((clue.start, clue.end) for clue in label_clues)
    soft_clues = [
        *label_clues,
        *_scan_break_clues(shadow_text, shadow_to_raw),
        *_scan_name_start_clues(shadow_text, shadow_to_raw),
        *_scan_family_name_clues(shadow_text, shadow_to_raw),
        *_scan_company_suffix_clues(shadow_text, shadow_to_raw),
        *_scan_address_clues(shadow_text, shadow_to_raw, locale_profile=locale_profile),
    ]
    soft_clues = [clue for clue in soft_clues if clue in label_clues or not _overlaps_any(clue.start, clue.end, label_spans)]
    all_clues = tuple(sorted([*hard_clues, *soft_clues], key=lambda item: (item.start, -item.priority, item.end)))
    return ClueBundle(
        shadow_text=shadow_text,
        shadow_to_raw=shadow_to_raw,
        hard_clues=hard_clues,
        label_clues=label_clues,
        all_clues=all_clues,
    )


def _scan_hard_patterns(text: str) -> list[Clue]:
    clues: list[Clue] = []
    for attr_type, matched_by, pattern, priority in _HARD_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if not value:
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.STRUCTURED,
                    kind=f"hard_{attr_type.value}",
                    start=match.start(),
                    end=match.end(),
                    text=value,
                    priority=priority,
                    hard=True,
                    attr_type=attr_type,
                    matched_by=matched_by,
                    payload={
                        "matched_by": matched_by,
                        "hard_source": "regex",
                        "placeholder": _PLACEHOLDER_BY_ATTR[attr_type],
                    },
                )
            )
    return clues


def _scan_dictionary_hard_clues(text: str, entries: tuple[DictionaryEntry, ...], *, source_kind: str) -> list[Clue]:
    clues: list[Clue] = []
    priority = 300 if source_kind == "session" else 290
    for entry in entries:
        for variant in sorted({item for item in entry.variants if str(item).strip()}, key=len, reverse=True):
            for match in _iter_literal_matches(text, variant):
                clues.append(
                    Clue(
                        clue_id=_next_clue_id(),
                        family=ClueFamily.STRUCTURED,
                        kind=f"hard_{entry.attr_type.value}",
                        start=match.start(),
                        end=match.end(),
                        text=match.group(0),
                        priority=priority,
                        hard=True,
                        attr_type=entry.attr_type,
                        matched_by=entry.matched_by,
                        payload={
                            "matched_by": entry.matched_by,
                            "hard_source": source_kind,
                            "dictionary_text": entry.text,
                            "metadata": {key: list(values) for key, values in entry.metadata.items()},
                            "placeholder": _PLACEHOLDER_BY_ATTR.get(entry.attr_type, f"<{entry.attr_type.value}>"),
                        },
                    )
                )
    return clues


def _scan_label_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> tuple[Clue, ...]:
    matches: list[tuple[int, int, object]] = []
    for spec in _LABEL_SPECS:
        matches.extend(_iter_label_matches(shadow_text, spec))
    accepted: list[tuple[int, int, object]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, spec in sorted(matches, key=lambda item: (-(item[1] - item[0]), -len(item[2].keyword), -item[2].priority, item[0])):
        if any(not (end <= left or start >= right) for left, right in occupied):
            continue
        occupied.append((start, end))
        accepted.append((start, end, spec))
    clues: list[Clue] = []
    for start, end, spec in sorted(accepted, key=lambda item: (item[0], item[1])):
        if _looks_like_placeholder_slice(shadow_text, start, end):
            continue
        raw_span = _shadow_span_to_raw(shadow_to_raw, start, end)
        if raw_span is None:
            continue
        family = {
            "structured": ClueFamily.STRUCTURED,
            "address": ClueFamily.ADDRESS,
            "organization": ClueFamily.ORGANIZATION,
            "name": ClueFamily.NAME,
        }[spec.stack_kind]
        raw_start, raw_end = raw_span
        clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=family,
                    kind=f"{spec.attr_type.value}_label" if spec.attr_type != PIIAttributeType.ORGANIZATION else "organization_label",
                start=raw_start,
                end=raw_end,
                text=spec.keyword,
                    priority=spec.priority,
                    hard=False,
                    attr_type=spec.attr_type,
                    matched_by=spec.matched_by,
                    payload={
                    "matched_by": spec.matched_by,
                    "component_hint": spec.component_hint,
                    "ocr_matched_by": spec.ocr_matched_by,
                    "keyword": spec.keyword,
                },
            )
        )
    return tuple(clues)


def _scan_break_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    if _OCR_SEMANTIC_BREAK_TOKEN in shadow_text:
        for match in re.finditer(re.escape(_OCR_SEMANTIC_BREAK_TOKEN), shadow_text):
            raw_start = _nearest_raw(shadow_to_raw, match.start(), direction="left")
            raw_end = _nearest_raw(shadow_to_raw, match.end() - 1, direction="right")
            if raw_start is None:
                raw_start = 0
            if raw_end is None:
                raw_end = raw_start
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.BREAK,
                    kind="break_ocr",
                    start=raw_start,
                    end=max(raw_start, raw_end),
                    text=_OCR_SEMANTIC_BREAK_TOKEN,
                    priority=500,
                    hard=False,
                    attr_type=None,
                    matched_by="break_ocr",
                )
            )
    for kind, pattern in _BREAK_PATTERNS:
        for match in pattern.finditer(shadow_text):
            raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
            if raw_span is None:
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.BREAK,
                    kind=kind,
                    start=raw_span[0],
                    end=raw_span[1],
                    text=match.group(0),
                    priority=480,
                    hard=False,
                    attr_type=None,
                    matched_by=kind,
                )
            )
    return _dedupe_clues(clues)


def _scan_name_start_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    for keyword in sorted(_NAME_START_KEYWORDS, key=len, reverse=True):
        for match in _iter_keyword_matches(shadow_text, keyword):
            raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
            if raw_span is None:
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.NAME,
                    kind="name_start",
                    start=raw_span[0],
                    end=raw_span[1],
                    text=keyword,
                    priority=230,
                    hard=False,
                    attr_type=PIIAttributeType.NAME,
                    matched_by="name_start",
                    payload={"matched_by": "name_start"},
                )
            )
    return _dedupe_clues(clues)


def _scan_family_name_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    for surname in _COMMON_FAMILY_NAMES:
        for match in re.finditer(re.escape(surname), shadow_text):
            tail = shadow_text[match.end() : match.end() + 4]
            if any(keyword in tail for keyword in ("省", "市", "区", "县", "旗", "路", "街", "道", "大道", "小区", "单元", "栋", "室", "住址", "地址")):
                continue
            raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
            if raw_span is None:
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.NAME,
                    kind="family_name",
                    start=raw_span[0],
                    end=raw_span[1],
                    text=surname,
                    priority=220,
                    hard=False,
                    attr_type=PIIAttributeType.NAME,
                    matched_by="family_name",
                    payload={"matched_by": "family_name"},
                )
            )
    return _dedupe_clues(clues)


def _scan_company_suffix_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    for suffix in sorted(_COMPANY_SUFFIXES, key=len, reverse=True):
        for match in _iter_keyword_matches(shadow_text, suffix):
            raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
            if raw_span is None:
                continue
            clues.append(
                Clue(
                    clue_id=_next_clue_id(),
                    family=ClueFamily.ORGANIZATION,
                    kind="company_suffix",
                    start=raw_span[0],
                    end=raw_span[1],
                    text=suffix,
                    priority=240,
                    hard=False,
                    attr_type=PIIAttributeType.ORGANIZATION,
                    matched_by="company_suffix",
                    payload={"matched_by": "company_suffix"},
                )
            )
    return _dedupe_clues(clues)


def _scan_address_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...], *, locale_profile: str) -> list[Clue]:
    clues: list[Clue] = []
    if locale_profile in {"zh_cn", "mixed"}:
        clues.extend(_scan_zh_address_clues(shadow_text, shadow_to_raw))
    if locale_profile in {"en_us", "mixed"}:
        clues.extend(_scan_en_address_clues(shadow_text, shadow_to_raw))
    return _dedupe_clues(clues)


def _scan_zh_address_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    lexicon = load_china_geo_lexicon()
    direct_city_names = {"北京", "上海", "天津", "重庆", "香港", "澳门"}
    geo_specs = (
        ("province", tuple(item for item in lexicon.provinces if item not in direct_city_names)),
        ("city", tuple([*lexicon.cities, *sorted(direct_city_names)])),
        ("district", lexicon.districts),
    )
    for component_type, names in geo_specs:
        for name in sorted(set(names), key=len, reverse=True):
            for match in re.finditer(re.escape(name), shadow_text):
                raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
                if raw_span is None:
                    continue
                clues.append(
                    Clue(
                        clue_id=_next_clue_id(),
                        family=ClueFamily.ADDRESS,
                        kind=f"address_value_{component_type}",
                        start=raw_span[0],
                        end=raw_span[1],
                        text=name,
                        priority=205,
                        hard=False,
                        attr_type=PIIAttributeType.ADDRESS,
                        matched_by="geo_db",
                        payload={"component_type": component_type, "token_role": "name", "matched_by": "geo_db"},
                    )
                )
    for component_type, keywords in _ZH_ADDRESS_ATTRS:
        for keyword in sorted(set(keywords), key=len, reverse=True):
            for match in re.finditer(re.escape(keyword), shadow_text):
                raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
                if raw_span is None:
                    continue
                clues.append(
                    Clue(
                        clue_id=_next_clue_id(),
                        family=ClueFamily.ADDRESS,
                        kind=f"address_key_{component_type}",
                        start=raw_span[0],
                        end=raw_span[1],
                        text=keyword,
                        priority=204,
                        hard=False,
                        attr_type=PIIAttributeType.ADDRESS,
                        matched_by="address_keyword",
                        payload={"component_type": component_type, "token_role": "attr", "matched_by": "address_keyword"},
                    )
                )
    return clues


def _scan_en_address_clues(shadow_text: str, shadow_to_raw: tuple[int | None, ...]) -> list[Clue]:
    clues: list[Clue] = []
    lexicon = load_en_geo_lexicon()
    geo_specs = (
        ("state", tuple([*lexicon.tier_a_state_names, *lexicon.tier_a_state_codes])),
        ("city", lexicon.tier_b_places),
    )
    for component_type, names in geo_specs:
        for name in sorted(set(names), key=len, reverse=True):
            for match in _iter_keyword_matches(shadow_text, name):
                raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
                if raw_span is None:
                    continue
                clues.append(
                    Clue(
                        clue_id=_next_clue_id(),
                        family=ClueFamily.ADDRESS,
                        kind=f"address_value_{component_type}",
                        start=raw_span[0],
                        end=raw_span[1],
                        text=name,
                        priority=205,
                        hard=False,
                        attr_type=PIIAttributeType.ADDRESS,
                        matched_by="geo_db",
                        payload={"component_type": component_type, "token_role": "name", "matched_by": "geo_db"},
                    )
                )
    for component_type, keywords in _EN_ADDRESS_ATTRS:
        for keyword in sorted(set(keywords), key=len, reverse=True):
            for match in _iter_keyword_matches(shadow_text, keyword):
                raw_span = _shadow_span_to_raw(shadow_to_raw, match.start(), match.end())
                if raw_span is None:
                    continue
                clues.append(
                    Clue(
                        clue_id=_next_clue_id(),
                        family=ClueFamily.ADDRESS,
                        kind=f"address_key_{component_type}",
                        start=raw_span[0],
                        end=raw_span[1],
                        text=match.group(0),
                        priority=204,
                        hard=False,
                        attr_type=PIIAttributeType.ADDRESS,
                        matched_by="address_keyword",
                        payload={"component_type": component_type, "token_role": "attr", "matched_by": "address_keyword"},
                    )
                )
    for token_match in re.finditer(r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)", shadow_text):
        raw_span = _shadow_span_to_raw(shadow_to_raw, token_match.start(), token_match.end())
        if raw_span is None:
            continue
        clues.append(
            Clue(
                clue_id=_next_clue_id(),
                family=ClueFamily.ADDRESS,
                kind="address_value_postal_code",
                start=raw_span[0],
                end=raw_span[1],
                text=token_match.group(0),
                priority=203,
                hard=False,
                attr_type=PIIAttributeType.ADDRESS,
                matched_by="postal_value",
                payload={"component_type": "postal_code", "token_role": "name", "matched_by": "postal_value"},
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
    return _HARD_SOURCE_PRIORITY.get(str(incoming.payload.get("hard_source") or ""), 0) > _HARD_SOURCE_PRIORITY.get(str(existing.payload.get("hard_source") or ""), 0)


def _build_shadow_text(text: str, hard_clues: tuple[Clue, ...]) -> tuple[str, tuple[int | None, ...]]:
    pieces: list[str] = []
    mapping: list[int | None] = []
    cursor = 0
    for clue in sorted(hard_clues, key=lambda item: (item.start, item.end)):
        if clue.start < cursor:
            continue
        if cursor < clue.start:
            unchanged = text[cursor:clue.start]
            pieces.append(unchanged)
            mapping.extend(range(cursor, clue.start))
        placeholder = str(clue.payload.get("placeholder") or "")
        if placeholder:
            pieces.append(placeholder)
            mapping.extend([clue.start] * len(placeholder))
        else:
            original = text[clue.start:clue.end]
            pieces.append(original)
            mapping.extend(range(clue.start, clue.end))
        cursor = clue.end
    if cursor < len(text):
        tail = text[cursor:]
        pieces.append(tail)
        mapping.extend(range(cursor, len(text)))
    return ("".join(pieces), tuple(mapping))


def _iter_label_matches(text: str, spec) -> list[tuple[int, int, object]]:
    escaped = re.escape(spec.keyword)
    if spec.ascii_boundary:
        pattern = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
        flags = re.IGNORECASE
    else:
        pattern = escaped
        flags = 0
    return [(match.start(), match.end(), spec) for match in re.finditer(pattern, text, flags=flags)]


def _iter_literal_matches(text: str, literal: str):
    escaped = re.escape(literal)
    if re.fullmatch(r"[A-Za-z0-9 .,'@_+\-#/&()]+", literal):
        pattern = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
        return re.finditer(pattern, text, flags=re.IGNORECASE)
    return re.finditer(escaped, text)


def _iter_keyword_matches(text: str, keyword: str):
    escaped = re.escape(keyword)
    if re.fullmatch(r"[A-Za-z0-9 #.'-]+", keyword):
        return re.finditer(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", text, flags=re.IGNORECASE)
    return re.finditer(escaped, text)


def _shadow_span_to_raw(mapping: tuple[int | None, ...], start: int, end: int) -> tuple[int, int] | None:
    raw_positions = [position for position in mapping[start:end] if position is not None]
    if not raw_positions:
        return None
    return (min(raw_positions), max(raw_positions) + 1)


def _nearest_raw(mapping: tuple[int | None, ...], index: int, *, direction: str) -> int | None:
    if not mapping:
        return None
    index = max(0, min(index, len(mapping) - 1))
    step = -1 if direction == "left" else 1
    probe = index
    while 0 <= probe < len(mapping):
        if mapping[probe] is not None:
            return mapping[probe]
        probe += step
    return None


def _dedupe_clues(clues: list[Clue]) -> list[Clue]:
    seen: set[tuple[str, int, int, str]] = set()
    ordered: list[Clue] = []
    for clue in sorted(clues, key=lambda item: (item.start, -(item.end - item.start), -item.priority, item.kind)):
        key = (clue.kind, clue.start, clue.end, clue.text.lower())
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
            if clue.kind.endswith("_label") or clue.kind.startswith("address_key_"):
                continue
        filtered.append(clue)
        if clue.kind.endswith("_label") or clue.kind.startswith("address_key_") or clue.kind.startswith("address_value_"):
            occupied.append((clue.start, clue.end))
    return sorted(filtered, key=lambda item: (item.start, item.end, -item.priority))


def _overlaps_any(start: int, end: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)


def _looks_like_placeholder_slice(text: str, start: int, end: int) -> bool:
    if not (0 <= start < end <= len(text)):
        return False
    slice_text = text[start:end]
    if slice_text.startswith("<") and slice_text.endswith(">"):
        return True
    left = text.rfind("<", 0, start + 1)
    right = text.find(">", end - 1)
    return left >= 0 and right >= end


def _next_clue_id() -> str:
    return f"clue-{next(_CLUE_IDS)}"
