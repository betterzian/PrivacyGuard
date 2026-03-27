"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_labels import _field_label_specs
from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _build_patterns(self) -> dict[PIIAttributeType, list[tuple[re.Pattern[str], str, float]]]:
    """构建正则规则集合。"""
    phone_patterns: list[tuple[re.Pattern[str], str, float]] = []
    if self._supports_zh():
        phone_patterns.extend(
            [
                (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "regex_phone_mobile", 0.86),
                (
                    re.compile(r"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•()（）]?\d{4}){2}(?!\d)"),
                    "regex_phone_mobile_sep",
                    0.84,
                ),
                (
                    re.compile(r"(?<!\d)0\d{2,3}(?:[\s\-－—_.,，。·•]?\d){7,8}(?!\d)"),
                    "regex_phone_landline",
                    0.78,
                ),
                (
                    re.compile(rf"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•]?{_MASK_CHAR_CLASS_WITH_X}{{4}})(?:[\s\-－—_.,，。·•]?\d{{4}})(?!\d)"),
                    "regex_phone_masked",
                    0.82,
                ),
                (
                    re.compile(rf"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•]?{_MASK_CHAR_CLASS_WITH_X}){{8}}(?!\d)"),
                    "regex_phone_masked_prefix_only",
                    0.8,
                ),
            ]
        )
    if self._supports_en():
        phone_patterns.extend(
            [
                (
                    re.compile(
                        r"(?<!\w)(?:\+?1[\s\-._()]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s\-._()]*[2-9]\d{2}[\s\-._()]*\d{4}(?!\w)"
                    ),
                    "regex_phone_us",
                    0.84,
                ),
                (
                    re.compile(
                        rf"(?<!\w)(?:\+?1[\s\-._()]*)?(?:\([2-9]\d{{2}}\)|[2-9]\d{{2}})[\s\-._()]*"
                        rf"(?:[2-9]\d{{2}}|\d{{2}}{_MASK_CHAR_CLASS_WITH_X}{{1}})[\s\-._()]*"
                        rf"(?:\d{{4}}|\d{{2}}{_MASK_CHAR_CLASS_WITH_X}{{2}})(?!\w)"
                    ),
                    "regex_phone_us_masked",
                    0.8,
                ),
            ]
        )
    return {
        PIIAttributeType.PHONE: phone_patterns,
        PIIAttributeType.CARD_NUMBER: [
            (
                re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){13,19}(?![A-Za-z0-9])"),
                "regex_card_number",
                0.83,
            ),
            (
                re.compile(rf"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){{4}}(?:{_MASK_CHAR_CLASS_WITH_X}[\s\-－—_.,，。·•]?){{5,15}}(?:\d[\s\-－—_.,，。·•]?){{0,4}}(?![A-Za-z0-9])"),
                "regex_card_number_masked",
                0.81,
            ),
        ],
        PIIAttributeType.BANK_ACCOUNT: [
            (
                re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){10,30}(?![A-Za-z0-9])"),
                "regex_bank_account_number",
                0.78,
            ),
            (
                re.compile(rf"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){{4,8}}(?:{_MASK_CHAR_CLASS_WITH_X}[\s\-－—_.,，。·•]?){{4,26}}(?:\d[\s\-－—_.,，。·•]?){{0,6}}(?![A-Za-z0-9])"),
                "regex_bank_account_masked",
                0.76,
            ),
        ],
        PIIAttributeType.PASSPORT_NUMBER: [
            (
                re.compile(r"(?<![A-Z0-9])[A-Z][\s\-－—_.,，。·•]?\d(?:[\s\-－—_.,，。·•]?\d){7,8}(?![A-Z0-9])", re.IGNORECASE),
                "regex_passport_number",
                0.8,
            ),
            (
                re.compile(
                    rf"(?<![A-Z0-9])(?:[A-Z0-9][\s\-－—_.,，。·•]?){{1,2}}(?:{_MASK_CHAR_CLASS_COMMON}[\s\-－—_.,，。·•]?){{3,12}}"
                    rf"(?:[A-Z0-9][\s\-－—_.,，。·•]?){{0,4}}(?![A-Z0-9])",
                    re.IGNORECASE,
                ),
                "regex_passport_number_masked",
                0.76,
            ),
        ],
        PIIAttributeType.DRIVER_LICENSE: [
            (
                re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])"),
                "regex_driver_license_12",
                0.74,
            ),
            (
                re.compile(r"(?<![A-Za-z0-9])\d{15}(?![A-Za-z0-9])"),
                "regex_driver_license_15",
                0.76,
            ),
            (
                re.compile(r"(?<![A-Z0-9])[A-Z]{1,3}(?:[\s\-－—_.,，。·•]?\d){7,17}(?![A-Z0-9])", re.IGNORECASE),
                "regex_driver_license_alnum",
                0.76,
            ),
            (
                re.compile(rf"(?<![A-Z0-9])(?:[A-Z0-9][\s\-－—_.,，。·•]?){{2,8}}(?:{_MASK_CHAR_CLASS_COMMON}[\s\-－—_.,，。·•]?){{4,16}}(?:[A-Z0-9][\s\-－—_.,，。·•]?){{0,4}}(?![A-Z0-9])", re.IGNORECASE),
                "regex_driver_license_masked",
                0.74,
            ),
        ],
        PIIAttributeType.EMAIL: [
            (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "regex_email", 0.85),
            (
                re.compile(r"[A-Za-z0-9._%+\-]+\s*@\s*[A-Za-z0-9.\-]+\s*\.\s*[A-Za-z]{2,}"),
                "regex_email_spaced",
                0.82,
            ),
            (
                re.compile(r"[A-Za-z0-9._%+\-]+\s*[@＠]\s*[A-Za-z0-9.\-]+\s*[.,，。．、·•]\s*[A-Za-z]{2,}"),
                "regex_email_ocr_noise",
                0.81,
            ),
            (
                re.compile(rf"[A-Za-z0-9._%+\-*＊{_MASK_CHAR_CLASS_COMMON[1:-1]}]+\s*[@＠]\s*[A-Za-z0-9.\-*＊{_MASK_CHAR_CLASS_COMMON[1:-1]}]+\s*(?:\.|[，。．、·•])\s*[A-Za-z*＊]{{2,}}"),
                "regex_email_masked",
                0.79,
            ),
        ],
        PIIAttributeType.ID_NUMBER: [
            (
                re.compile(r"(?<![A-Za-z0-9])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![A-Za-z0-9])"),
                "regex_cn_id_18",
                0.92,
            ),
            (
                re.compile(
                    r"(?<![A-Za-z0-9])[1-9]\d{5}(?:[\s\-－—_.,，。·•]?(?:18|19|20)\d{2})(?:[\s\-－—_.,，。·•]?(?:0[1-9]|1[0-2]))"
                    r"(?:[\s\-－—_.,，。·•]?(?:0[1-9]|[12]\d|3[01]))(?:[\s\-－—_.,，。·•]?\d{3})(?:[\s\-－—_.,，。·•]?[\dXx])(?![A-Za-z0-9])"
                ),
                "regex_cn_id_18_spaced",
                0.9,
            ),
            (re.compile(r"(?<![A-Za-z0-9])[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?![A-Za-z0-9])"), "regex_cn_id_15", 0.82),
            (
                re.compile(
                    r"(?<![A-Za-z0-9])[1-9]\d{7}(?:[\s\-－—_.,，。·•]?(?:0[1-9]|1[0-2]))(?:[\s\-－—_.,，。·•]?(?:0[1-9]|[12]\d|3[01]))"
                    r"(?:[\s\-－—_.,，。·•]?\d{3})(?![A-Za-z0-9])"
                ),
                "regex_cn_id_15_spaced",
                0.8,
            ),
            (re.compile(rf"(?<![A-Za-z0-9])[1-9]\d{{5}}{_MASK_CHAR_CLASS_COMMON}{{8,10}}[\dXx]{{2,4}}(?![A-Za-z0-9])"), "regex_cn_id_masked", 0.86),
            (re.compile(rf"(?<![A-Za-z0-9])[1-9]\d{{5}}{_MASK_CHAR_CLASS_COMMON}{{9,12}}(?![A-Za-z0-9])"), "regex_cn_id_masked_prefix_only", 0.84),
        ],
        PIIAttributeType.TIME: [
            (
                re.compile(r"(?<!\d)(?:[01]?\d|2[0-3])[:：][0-5]\d(?:[:：][0-5]\d)?(?!\d)"),
                "regex_time_clock",
                0.96,
            ),
        ],
    }

def _build_context_rules(self) -> list[tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]]:
    """构建基于字段上下文的检测规则。"""
    rules: list[tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]] = []
    for spec in _field_label_specs():
        if not spec.include_in_context_rules:
            continue
        validator = getattr(self, spec.validator_name)
        rules.append(
            self._build_context_rule(
                keywords=spec.keywords,
                attr_type=spec.attr_type,
                value_pattern=spec.value_pattern,
                confidence=spec.context_confidence,
                matched_by=spec.context_matched_by,
                validator=validator,
            )
        )
    return rules

def _build_self_name_patterns(self) -> list[tuple[re.Pattern[str], str, float]]:
    """构建自我介绍与口语化姓名规则。"""
    patterns: list[tuple[re.Pattern[str], str, float]] = []
    if self._supports_zh():
        patterns.append(
            (
                re.compile(rf"(?:我叫|名叫|叫做|我的名字是)\s*(?P<value>[一-龥·\s0-9]{{2,10}}|[一-龥][*＊xX某]{{1,3}}|{_TEXT_MASK_CHAR_CLASS}{{2,10}})"),
                "context_name_self_intro",
                0.78,
            )
        )
    if self._supports_en():
        patterns.extend(
            [
                (
                    re.compile(
                        r"(?:my\s+name\s+is|i\s+am|i'm|this\s+is)\s*(?P<value>[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,2})",
                        re.IGNORECASE,
                    ),
                    "context_name_self_intro_en",
                    0.76,
                ),
            ]
        )
    return patterns

def _build_masked_text_pattern(self) -> re.Pattern[str]:
    """构建通用重复掩码字符检测模式。"""
    return re.compile(rf"(?P<value>(?P<char>{_TEXT_MASK_CHAR_CLASS})(?:\s*(?P=char)){{2,}})")

def _build_context_rule(
    self,
    keywords: tuple[str, ...],
    attr_type: PIIAttributeType,
    value_pattern: str,
    confidence: float,
    matched_by: str,
    validator: Callable[[str], bool],
) -> tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]:
    """根据关键词动态构建上下文字段规则。"""
    keyword_pattern = "|".join(sorted((re.escape(item) for item in keywords), key=len, reverse=True))
    pattern = re.compile(
        rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?:{keyword_pattern})\s*(?:[:：=]|是|为|is|was|at)?\s*(?P<value>{value_pattern})",
        re.IGNORECASE,
    )
    return (attr_type, pattern, matched_by, confidence, validator)

def _build_field_label_pattern(self) -> re.Pattern[str]:
    """构建用于识别字段标签边界的通用模式。"""
    keyword_pattern = "|".join(sorted((re.escape(item) for item in self._all_field_keywords()), key=len, reverse=True))
    return re.compile(
        rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?P<label>{keyword_pattern})\s*(?:[:：=]|是|为|is|was|at)",
        re.IGNORECASE,
    )

def _build_trailing_field_label_pattern(self) -> re.Pattern[str]:
    """构建用于截断“值 + 下一个字段标签”串联的尾部模式。"""
    keyword_pattern = "|".join(sorted((re.escape(item) for item in self._all_field_keywords()), key=len, reverse=True))
    return re.compile(
        rf"(?P<body>.*?)(?:[\s,，;；/|]*)?(?P<label>{keyword_pattern})$",
        re.IGNORECASE,
    )

def _all_field_keywords(self) -> tuple[str, ...]:
    """汇总所有字段标签关键词，供边界识别复用。"""
    return tuple(
        dict.fromkeys(
            (
                *_NAME_FIELD_KEYWORDS,
                *_NAME_FAMILY_FIELD_KEYWORDS,
                *_NAME_GIVEN_FIELD_KEYWORDS,
                *_NAME_MIDDLE_FIELD_KEYWORDS,
                *_ADDRESS_FIELD_KEYWORDS,
                *_PHONE_FIELD_KEYWORDS,
                *_CARD_FIELD_KEYWORDS,
                *_BANK_ACCOUNT_FIELD_KEYWORDS,
                *_PASSPORT_FIELD_KEYWORDS,
                *_DRIVER_LICENSE_FIELD_KEYWORDS,
                *_EMAIL_FIELD_KEYWORDS,
                *_ID_FIELD_KEYWORDS,
                *_OTHER_FIELD_KEYWORDS,
                *_ORGANIZATION_FIELD_KEYWORDS,
            )
        )
    )
