"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _meets_confidence_threshold(
    self,
    attr_type: PIIAttributeType,
    confidence: float,
    rule_profile: _RuleStrengthProfile,
) -> bool:
    return confidence >= rule_profile.min_confidence_by_attr.get(attr_type, 0.0)

def _clean_extracted_value(self, value: str) -> str:
    """清理上下文提取值两侧的噪声字符。"""
    cleaned = value.strip()
    cleaned = self._strip_ocr_break_edge_noise(cleaned)
    cleaned = re.sub(r"^[\s\[{(<>（【「『\"'`]+", "", cleaned)
    cleaned = re.sub(r"[\s\]})<>）】」』\"'`.,，;；、。！？!?]+$", "", cleaned)
    cleaned = self._strip_ocr_break_edge_noise(cleaned)
    return cleaned.strip()

def _clean_phone_candidate(self, value: str) -> str:
    """为电话 regex 命中保留括号与国际区号前缀。"""
    cleaned = value.strip()
    cleaned = self._strip_ocr_break_edge_noise(cleaned)
    cleaned = re.sub(r"^[\s\[{<（【「『\"'`]+", "", cleaned)
    cleaned = re.sub(r"[\s\]}>）】」』\"'`.,，;；、。！？!?]+$", "", cleaned)
    cleaned = self._strip_ocr_break_edge_noise(cleaned)
    return cleaned.strip()

def _strip_ocr_break_edge_noise(self, value: str) -> str:
    cleaned = value.strip()
    token = _OCR_SEMANTIC_BREAK_TOKEN.strip()
    while True:
        previous = cleaned
        if cleaned.startswith(token):
            cleaned = cleaned[len(token):].lstrip()
        if cleaned.endswith(token):
            cleaned = cleaned[: -len(token)].rstrip()
        if cleaned == previous:
            return cleaned

def _clean_address_candidate(self, value: str) -> str:
    """清理地址候选前后的连接词与标点。"""
    cleaned = self._clean_extracted_value(value)
    cleaned = _LEADING_ADDRESS_NOISE_PATTERN.sub("", cleaned)
    cleaned = _LEADING_ADDRESS_NOISE_PATTERN_EN.sub("", cleaned)
    cleaned = re.sub(r"^(?:地址|住址|详细地址|联系地址|收货地址|户籍地址)\s*(?:[:：=])?\s*", "", cleaned)
    return cleaned.strip()

def _clean_organization_candidate(self, value: str) -> str:
    """清理机构候选前后的上下文噪声。"""
    cleaned = self._clean_extracted_value(value)
    cleaned = _LEADING_ORGANIZATION_NOISE_PATTERN.sub("", cleaned)
    cleaned = _LEADING_ORGANIZATION_NOISE_PATTERN_EN.sub("", cleaned)
    cleaned = _ORGANIZATION_FIELD_PREFIX_PATTERN.sub("", cleaned)
    cleaned = _ORGANIZATION_FIELD_PREFIX_PATTERN_EN.sub("", cleaned)
    cleaned = re.sub(r"^(?:加入|进入|任职|就职|供职|实习|毕业|就读)\s*", "", cleaned)
    return cleaned.strip()

def _is_name_dictionary_match_allowed(self, raw_text: str, span_start: int, span_end: int) -> bool:
    """过滤姓名词条前缀误命中，如“张三丰”不应命中“张三”。

    这里只收紧“姓名后面紧跟另一个中文字符”的情况；像“张三老师”“张三处理”
    这类常见敬称或动作上下文仍允许通过。
    """
    next_char = self._next_significant_char(raw_text, span_end)
    if next_char is None or not self._is_cjk_char(next_char):
        return True
    return next_char in _NAME_DICTIONARY_ALLOWED_NEXT_CHARS

def _next_significant_char(self, raw_text: str, start: int) -> str | None:
    index = max(0, min(start, len(raw_text)))
    while index < len(raw_text):
        current = raw_text[index]
        if current in _NAME_MATCH_IGNORABLE:
            index += 1
            continue
        return current
    return None

def _previous_significant_char(self, raw_text: str, end: int) -> str | None:
    index = min(end, len(raw_text)) - 1
    while index >= 0:
        current = raw_text[index]
        if current in _NAME_MATCH_IGNORABLE:
            index -= 1
            continue
        return current
    return None

def _left_context(self, raw_text: str, start: int, *, size: int = 8) -> str:
    return self._clean_extracted_value(raw_text[max(0, start - size):start])

def _right_context(self, raw_text: str, end: int, *, size: int = 10) -> str:
    return self._clean_extracted_value(raw_text[end:min(len(raw_text), end + size)])

def _starts_with_geo_or_activity(self, value: str) -> bool:
    compact = re.sub(rf"^[\s{re.escape(_OCR_FRAGMENT_DELIMITERS)}:：,，;；]+", "", value)
    if not compact:
        return False
    compact_lower = compact.lower()
    if any(compact.startswith(token) or compact_lower.startswith(token.lower()) for token in _LOCATION_ACTIVITY_TOKENS):
        return True
    return any(compact.startswith(token) or compact_lower.startswith(token.lower()) for token in _LOCATION_CLUE_TOKENS)

def _is_ui_operation_name_token(self, value: str) -> bool:
    compact = re.sub(r"\s+", "", self._clean_extracted_value(value))
    if not compact:
        return False
    return compact in _UI_OPERATION_NAME_WHITELIST or compact.lower() in _UI_OPERATION_NAME_WHITELIST

def _generic_name_confidence(
    self,
    raw_text: str,
    span_start: int,
    span_end: int,
    *,
    value: str,
    source: PIISourceType,
    rule_profile: _RuleStrengthProfile,
) -> float:
    if any(value.endswith(honorific) for honorific in _NAME_HONORIFICS) and not self._looks_like_name_with_title(value):
        return 0.0
    left_char = self._previous_significant_char(raw_text, span_start)
    right_char = self._next_significant_char(raw_text, span_end)
    left_context = self._left_context(raw_text, span_start)
    right_context = self._right_context(raw_text, span_end)
    left_support = any(left_context.endswith(token) for token in (*_NAME_CONTEXT_PREFIX_TOKENS, *_NAME_CONTEXT_CARRIER_TOKENS))
    right_support = (
        right_char is None
        or right_char.isdigit()
        or right_char in _OCR_FRAGMENT_DELIMITERS
        or not self._is_cjk_char(right_char)
    )
    if any(right_context.startswith(token) for token in _NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS) and not left_support:
        return 0.0
    if left_support and (right_support or source == PIISourceType.OCR):
        return 0.96 if rule_profile.level == ProtectionLevel.WEAK else 0.94
    if self._starts_with_geo_or_activity(right_context):
        return 0.96 if rule_profile.level == ProtectionLevel.WEAK else 0.92
    standalone = (left_char is None or not self._is_cjk_char(left_char)) and (
        right_char is None or not self._is_cjk_char(right_char)
    )
    if standalone:
        if source == PIISourceType.OCR:
            return self._ocr_standalone_name_confidence(
                raw_text,
                span_start,
                span_end,
                value=value,
                source=source,
                rule_profile=rule_profile,
            )
        return self._strong_standalone_name_confidence(
            raw_text,
            span_start,
            span_end,
            value=value,
            source=source,
            rule_profile=rule_profile,
        )
    if right_char is not None and right_char.isdigit():
        if source == PIISourceType.OCR:
            ocr_suffix = self._clean_extracted_value(raw_text[span_start:min(len(raw_text), span_end + 8)])
            if self._looks_like_ui_time_metadata(ocr_suffix):
                return 0.0
        if left_support or left_char is None or not self._is_cjk_char(left_char):
            return 0.96 if rule_profile.level == ProtectionLevel.WEAK else 0.94
        return 0.0
    return 0.0

def _ocr_standalone_name_confidence(
    self,
    raw_text: str,
    span_start: int,
    span_end: int,
    *,
    value: str,
    source: PIISourceType,
    rule_profile: _RuleStrengthProfile,
) -> float:
    if source != PIISourceType.OCR or rule_profile.level == ProtectionLevel.WEAK:
        return 0.0
    compact = self._compact_name_value(value, allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG)
    if not compact:
        return 0.0
    if self._is_ui_operation_name_token(compact):
        return 0.0
    if any(compact.endswith(suffix) for suffix in _NAME_STANDALONE_NEGATIVE_SUFFIXES):
        return 0.0
    if any(token in compact for token in _NON_PERSON_TOKENS):
        return 0.0
    is_compound = compact[:2] in _COMMON_COMPOUND_SURNAMES
    if is_compound:
        if not 3 <= len(compact) <= 4:
            return 0.0
    elif not 2 <= len(compact) <= 3:
        return 0.0
    full_text = self._clean_extracted_value(raw_text)
    if full_text == value:
        return 0.82 if rule_profile.level == ProtectionLevel.BALANCED else 0.9
    window = self._clean_extracted_value(raw_text[max(0, span_start - 2):min(len(raw_text), span_end + 2)])
    if value in window and len(window) <= len(value) + 2:
        return 0.74 if rule_profile.level == ProtectionLevel.BALANCED else 0.86
    return 0.0

def _strong_standalone_name_confidence(
    self,
    raw_text: str,
    span_start: int,
    span_end: int,
    *,
    value: str,
    source: PIISourceType,
    rule_profile: _RuleStrengthProfile,
) -> float:
    if rule_profile.level != ProtectionLevel.STRONG:
        return 0.0
    compact = self._compact_name_value(value, allow_ocr_noise=False)
    if not compact:
        return 0.0
    if any(compact.endswith(suffix) for suffix in _NAME_STANDALONE_NEGATIVE_SUFFIXES):
        return 0.0
    if any(token in compact for token in _NON_PERSON_TOKENS):
        return 0.0
    is_compound = compact[:2] in _COMMON_COMPOUND_SURNAMES
    if is_compound:
        if not 3 <= len(compact) <= 4:
            return 0.0
    elif not 2 <= len(compact) <= 3:
        return 0.0
    full_text = self._clean_extracted_value(raw_text)
    if full_text == value:
        return 0.9
    if source == PIISourceType.OCR:
        window = self._clean_extracted_value(raw_text[max(0, span_start - 2):min(len(raw_text), span_end + 2)])
        if value in window and len(window) <= len(value) + 2:
            return 0.86
    return 0.0

def _is_cjk_char(self, char: str) -> bool:
    return bool(char) and "\u4e00" <= char <= "\u9fff"

def _canonical_name_source_text(
    self,
    value: str,
    *,
    reference_text: str | None = None,
    allow_ocr_noise: bool = False,
) -> str | None:
    """为姓名命中生成规范源值，用于 session/mapping 级统一。"""
    compact = self._compact_name_value(value, allow_ocr_noise=allow_ocr_noise)
    if not compact:
        return None
    if reference_text is not None:
        reference_compact = self._compact_name_value(reference_text, allow_ocr_noise=True)
        if reference_compact and compact == reference_compact:
            return reference_compact
        return None
    if not self._is_name_candidate(compact):
        return None
    return compact


def _canonical_name_component_source_text(
    self,
    value: str,
    *,
    component: str,
    allow_ocr_noise: bool = False,
) -> str | None:
    compact = self._compact_name_value(value, allow_ocr_noise=allow_ocr_noise)
    if not compact:
        return None
    if component == "family":
        return compact if self._is_family_name_candidate(compact) else None
    if component == "given":
        return compact if self._is_given_name_candidate(compact) else None
    if component == "middle":
        return compact if self._is_middle_name_candidate(compact) else None
    return self._canonical_name_source_text(compact, allow_ocr_noise=allow_ocr_noise)

def _compact_name_value(self, value: str, *, allow_ocr_noise: bool) -> str:
    return canonicalize_name_text(
        value,
        allow_ocr_noise=allow_ocr_noise,
        lower_ascii=False,
    )

def _is_en_phone_candidate(
    self,
    value: str,
    *,
    allow_plain_local: bool,
) -> bool:
    if not self._supports_en():
        return False
    digits = re.sub(r"\D", "", self._clean_extracted_value(value))
    if re.fullmatch(r"1[2-9]\d{9}", digits):
        return digits[1] not in {"0", "1"} and digits[4] not in {"0", "1"}
    if allow_plain_local and re.fullmatch(r"[2-9]\d{9}", digits):
        return digits[0] not in {"0", "1"} and digits[3] not in {"0", "1"}
    return False

def _is_phone_candidate(self, value: str) -> bool:
    """判断是否为手机号或座机片段。"""
    compact = compact_phone_value(value)
    if bool(
        re.fullmatch(r"1[3-9]\d{9}", compact)
        or re.fullmatch(r"1[3-9]\d[*＊xX]{4}\d{4}", compact)
        or re.fullmatch(r"1[3-9]\d[*＊xX]{8}", compact)
        or re.fullmatch(r"[*＊xX]{7}\d{4}", compact)
        or re.fullmatch(r"0\d{9,11}", compact)
    ):
        return True
    return self._is_en_phone_candidate(value, allow_plain_local=False)

def _is_context_phone_candidate(self, value: str) -> bool:
    return self._is_phone_candidate(value) or self._is_en_phone_candidate(value, allow_plain_local=True)

def _is_card_number_candidate(self, value: str) -> bool:
    """判断是否为银行卡/信用卡号。"""
    compact = compact_card_number_value(value)
    if re.fullmatch(r"\d{13,19}", compact):
        if self._is_phone_candidate(compact) or self._is_id_candidate(compact):
            return False
        return self._passes_luhn(compact)
    if not re.fullmatch(r"[\d*＊xX]{13,19}", compact):
        return False
    if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
        return False
    if (
        not re.fullmatch(r"\d{4}[*＊xX]{5,15}\d{0,4}", compact)
        and not re.fullmatch(r"[*＊xX]{5,15}\d{4}", compact)
    ):
        return False
    return not self._is_phone_candidate(compact)

def _is_context_card_number_candidate(self, value: str) -> bool:
    """显式卡号字段可接受比 free-text 更宽的校验。"""
    compact = compact_card_number_value(value)
    if re.fullmatch(r"\d{13,19}", compact):
        return not self._is_phone_candidate(compact) and not self._is_id_candidate(compact)
    if not re.fullmatch(r"[\d*＊xX]{13,19}", compact):
        return False
    if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
        return False
    return bool(
        re.fullmatch(r"\d{4}[*＊xX]{5,15}\d{0,4}", compact)
        or re.fullmatch(r"[*＊xX]{5,15}\d{4}", compact)
    )

def _is_bank_account_candidate(self, value: str) -> bool:
    """判断是否为银行账号；仅配合显式字段上下文使用。"""
    compact = compact_bank_account_value(value)
    if re.fullmatch(r"\d{10,30}", compact):
        if self._is_phone_candidate(compact):
            return False
        return True
    if not re.fullmatch(r"[\d*＊xX]{10,30}", compact):
        return False
    if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
        return False
    if (
        not re.fullmatch(r"\d{4,6}[*＊xX]{4,26}\d{0,4}", compact)
        and not re.fullmatch(r"[*＊xX]{4,26}\d{4,6}", compact)
    ):
        return False
    return not self._is_phone_candidate(compact)

def _is_passport_candidate(self, value: str) -> bool:
    """判断是否为护照号。"""
    compact = compact_passport_value(value)
    return bool(
        re.fullmatch(r"[A-Z]\d{8}", compact)
        or re.fullmatch(r"[A-Z]\d{7}", compact)
        or re.fullmatch(r"[A-Z]{2}\d{7}", compact)
        or re.fullmatch(r"[A-Z0-9]{1,2}[*＊xX]{3,12}[A-Z0-9]{0,4}", compact)
        or re.fullmatch(r"[*＊xX]{3,12}[A-Z0-9]{2,4}", compact)
    )

def _is_driver_license_candidate(self, value: str) -> bool:
    """判断是否为驾驶证号；仅配合显式字段上下文使用。"""
    compact = compact_driver_license_value(value)
    return bool(
        re.fullmatch(r"\d{12}", compact)
        or re.fullmatch(r"\d{15}", compact)
        or re.fullmatch(r"\d{17}[\dX]", compact)
        or re.fullmatch(r"[A-Z0-9]{10,20}", compact)
        or re.fullmatch(r"[A-Z0-9]{4,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact)
        or re.fullmatch(r"[*＊xX]{4,16}[A-Z0-9]{4,8}", compact)
    )

def _is_email_candidate(self, value: str) -> bool:
    """判断是否为邮箱。"""
    compact = compact_email_value(value)
    if re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", compact):
        return True
    if "*" not in compact and "＊" not in compact:
        return False
    if compact.count("@") != 1:
        return False
    local_part, domain_part = compact.split("@", 1)
    if not local_part or not domain_part or "." not in domain_part:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._%+\-*＊]+", local_part):
        return False
    if not re.fullmatch(r"[A-Za-z0-9.\-*＊]+", domain_part):
        return False
    labels = domain_part.split(".")
    if any(not label for label in labels):
        return False
    if not re.fullmatch(r"[A-Za-z*＊]{2,}", labels[-1]):
        return False
    visible_local = re.sub(r"[*＊xX]", "", local_part)
    visible_domain = re.sub(r"[*＊xX.]", "", domain_part)
    return bool(visible_local or visible_domain)

def _is_id_candidate(self, value: str) -> bool:
    """判断是否为身份证号或脱敏后的身份证号。"""
    compact = compact_id_value(value)
    return bool(
        self._looks_like_cn_id_with_birthdate(compact)
        or re.fullmatch(r"[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}", compact)
        or re.fullmatch(r"[1-9]\d{5}[*＊]{9,12}", compact)
        or re.fullmatch(r"[*＊]{11,16}[\dXx]{2,4}", compact)
    )

def _is_other_candidate(self, value: str) -> bool:
    """判断是否为需要保守脱敏的通用敏感字段。"""
    shape_attr = classify_content_shape_attr(value)
    compact = compact_other_code_value(value)
    if not compact or not (4 <= len(compact) <= 32):
        return False
    if (
        self._is_phone_candidate(compact)
        or self._is_card_number_candidate(compact)
        or self._is_bank_account_candidate(compact)
        or self._is_passport_candidate(compact)
        or self._is_driver_license_candidate(compact)
        or self._is_id_candidate(compact)
        or self._is_email_candidate(compact)
    ):
        return False
    if shape_attr == PIIAttributeType.TIME:
        return True
    if shape_attr == PIIAttributeType.NUMERIC:
        return len(re.sub(r"\D", "", value)) >= 4
    if shape_attr == PIIAttributeType.TEXTUAL:
        return sum(char.isalpha() for char in value) >= 2
    return any(char.isalpha() for char in value) and any(char.isdigit() for char in value)

def _passes_luhn(self, digits: str) -> bool:
    total = 0
    reverse_digits = digits[::-1]
    for index, char in enumerate(reverse_digits):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0

def _is_name_candidate(self, value: str) -> bool:
    """判断是否像姓名。"""
    cleaned = self._clean_extracted_value(value)
    compact = cleaned.replace(" ", "")
    compact_lower = compact.lower()
    if not compact or compact in _NAME_BLACKLIST:
        return False
    if self._is_ui_operation_name_token(compact):
        return False
    if compact in _NON_PERSON_TOKENS:
        return False
    if compact_lower in _NON_PERSON_TOKENS_EN:
        return False
    if any(char.isdigit() for char in compact):
        return False
    if compact in _REGION_TOKENS:
        return False
    if compact in _COMMON_CITY_TOKENS or compact in _COMMON_DISTRICT_TOKENS or compact in _COMMON_BUSINESS_AREA_TOKENS:
        return False
    if _ADDRESS_SUFFIX_PATTERN.search(compact):
        return False
    if self._looks_like_address_candidate(compact):
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z .'\-]{1,40}", cleaned):
        tokens = [token for token in re.split(r"\s+", cleaned.strip()) if token]
        if not tokens or len(tokens) > 3:
            return False
        if any(token.lower() in _NON_PERSON_TOKENS_EN for token in tokens):
            return False
        if any(
            token.lower().rstrip(".") in {suffix.rstrip(".").lower() for suffix in (*_EN_ORGANIZATION_STRONG_SUFFIXES, *_EN_ORGANIZATION_WEAK_SUFFIXES)}
            for token in tokens
        ):
            return False
        if len(tokens) >= 2 and all(re.fullmatch(r"[A-Za-z][A-Za-z'\-]{0,20}", token) for token in tokens):
            return True
        return len(tokens) == 1 and len(tokens[0]) >= 3
    if re.fullmatch(r"[一-龥][*＊xX某]{1,3}", compact):
        return True
    if "·" in compact and re.fullmatch(r"[一-龥]{1,4}·[一-龥]{1,6}", compact):
        return True
    if re.fullmatch(r"[一-龥·]{2,8}", compact):
        if compact[:2] in _COMMON_COMPOUND_SURNAMES:
            return 3 <= len(compact) <= 6
        return compact[0] in _COMMON_SINGLE_CHAR_SURNAMES and 2 <= len(compact) <= 4
    return False


def _is_family_name_candidate(self, value: str) -> bool:
    cleaned = self._clean_extracted_value(value)
    compact = cleaned.replace(" ", "")
    compact_lower = compact.lower()
    if not compact or compact in _NAME_BLACKLIST or any(char.isdigit() for char in compact):
        return False
    if self._is_ui_operation_name_token(compact):
        return False
    if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
        return False
    if compact[:2] in _COMMON_COMPOUND_SURNAMES and len(compact) == 2:
        return True
    if len(compact) == 1 and compact[0] in _COMMON_SINGLE_CHAR_SURNAMES:
        return True
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z'\-]{1,24}", cleaned))


def _is_given_name_candidate(self, value: str) -> bool:
    cleaned = self._clean_extracted_value(value)
    compact = cleaned.replace(" ", "")
    compact_lower = compact.lower()
    if not compact or compact in _NAME_BLACKLIST or any(char.isdigit() for char in compact):
        return False
    if self._is_ui_operation_name_token(compact):
        return False
    if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
        return False
    if re.fullmatch(r"[一-龥·]{1,6}", compact):
        return True
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z'\-]{1,24}", cleaned))


def _is_middle_name_candidate(self, value: str) -> bool:
    cleaned = self._clean_extracted_value(value)
    if not cleaned or any(char.isdigit() for char in cleaned):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z'\-]{1,24}(?:\s+[A-Za-z][A-Za-z'\-]{1,24}){0,2}", cleaned))

def _has_en_organization_suffix(self, value: str, *, allow_weak_suffix: bool) -> tuple[bool, bool]:
    compact = re.sub(r"\s+", " ", self._clean_organization_candidate(value)).strip().lower()
    if not compact:
        return (False, False)
    for suffix in _EN_ORGANIZATION_STRONG_SUFFIXES:
        normalized = suffix.rstrip(".").lower()
        if compact.endswith(f" {normalized}") or compact == normalized:
            return (True, False)
    if allow_weak_suffix:
        for suffix in _EN_ORGANIZATION_WEAK_SUFFIXES:
            normalized = suffix.rstrip(".").lower()
            if compact.endswith(f" {normalized}") or compact == normalized:
                return (False, True)
    return (False, False)

def _is_context_organization_candidate(self, value: str) -> bool:
    cleaned = self._clean_organization_candidate(value)
    compact = re.sub(r"\s+", "", cleaned)
    if not compact or compact in _ORGANIZATION_BLACKLIST:
        return False
    if self._looks_like_address_candidate(compact):
        return False
    if self._is_name_candidate(cleaned):
        return False
    if self._supports_en() and re.fullmatch(r"[A-Za-z][A-Za-z0-9 .&'\-]{2,64}", cleaned):
        tokens = [token for token in re.split(r"\s+", cleaned.strip()) if token]
        return bool(tokens) and len(tokens) <= 8
    return self._is_organization_candidate(value, allow_weak_suffix=True)

def _is_organization_candidate(self, value: str, *, allow_weak_suffix: bool = True) -> bool:
    """判断是否像机构名。"""
    cleaned = self._clean_organization_candidate(value)
    compact = re.sub(r"\s+", "", cleaned)
    if not compact or compact in _ORGANIZATION_BLACKLIST:
        return False
    if compact in _ADDRESS_FIELD_KEYWORDS or compact in _NAME_FIELD_KEYWORDS:
        return False
    if self._looks_like_address_candidate(compact):
        return False
    if self._is_name_candidate(cleaned):
        return False
    if self._supports_en() and re.fullmatch(r"[A-Za-z][A-Za-z0-9 .&'\-]{2,64}", cleaned):
        strong_en, weak_en = self._has_en_organization_suffix(cleaned, allow_weak_suffix=allow_weak_suffix)
        if strong_en or weak_en:
            return len(cleaned.replace(" ", "")) >= 4
    if _ORGANIZATION_STRONG_SUFFIX_PATTERN.search(compact):
        return len(compact) >= 3
    if _ORGANIZATION_WEAK_SUFFIX_PATTERN.search(compact):
        if not allow_weak_suffix:
            return False
        if any(token in compact for token in _ORGANIZATION_SENTENCE_NOISE_TOKENS):
            return False
        return len(compact) >= 4
    return False

def _organization_has_explicit_context(self, raw_text: str, span_start: int, span_end: int) -> bool:
    window = self._match_context_window(raw_text, span_start, span_end, radius=16)
    if self._window_has_keywords(window, _ORGANIZATION_FIELD_KEYWORDS):
        return True
    lowered = window.lower()
    return any(
        token in lowered
        for token in (
            "就职于",
            "任职于",
            "供职于",
            "毕业于",
            "就读于",
            "工作单位",
            "所在单位",
            "我在",
            "当前在",
            "目前在",
            "曾在",
            "work at",
            "works at",
            "worked at",
            "study at",
            "studies at",
            "studied at",
            "employed by",
            "currently at",
            "previously at",
        )
    )

def _looks_like_name_with_title(self, value: str) -> bool:
    """判断是否为带敬称的姓名片段。"""
    if self._supports_en() and re.fullmatch(
        r"(?:mr|mrs|ms|miss|dr|prof)\.?\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,2}",
        value,
        re.IGNORECASE,
    ):
        core = re.sub(r"^(?:mr|mrs|ms|miss|dr|prof)\.?\s+", "", value, flags=re.IGNORECASE)
        return self._is_name_candidate(core)
    if not re.fullmatch(rf"[一-龥·]{{1,5}}(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))})", value):
        return False
    core = value
    for honorific in _NAME_HONORIFICS:
        if core.endswith(honorific):
            core = core[: -len(honorific)]
            break
    if core in _NON_PERSON_TOKENS:
        return False
    if len(core) == 1:
        return core in _COMMON_SINGLE_CHAR_SURNAMES
    return self._is_name_candidate(core)

def _geo_candidate_attr_type(self, value: str) -> PIIAttributeType:
    return PIIAttributeType.LOCATION_CLUE

def _geo_fragment_confidence(
    self,
    raw_text: str,
    span_start: int,
    span_end: int,
    *,
    value: str,
    attr_type: PIIAttributeType,
    is_builtin_token: bool,
    rule_profile: _RuleStrengthProfile,
) -> float:
    """根据几何边界和上下文估计地名/地址碎片置信度。"""
    left_char = self._previous_significant_char(raw_text, span_start)
    right_char = self._next_significant_char(raw_text, span_end)
    left_open = left_char is None or not self._is_cjk_char(left_char)
    right_open = right_char is None or not self._is_cjk_char(right_char)
    right_context = self._right_context(raw_text, span_end)
    cleaned_text = self._clean_extracted_value(raw_text)
    if cleaned_text == value:
        return 0.96 if is_builtin_token else 0.9
    if any(right_context.startswith(token) for token in _GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS):
        if attr_type == PIIAttributeType.LOCATION_CLUE and not right_open:
            return 0.0
    if left_open and right_open:
        return 0.96 if is_builtin_token else 0.9
    if self._starts_with_geo_or_activity(right_context):
        return 0.94 if is_builtin_token else 0.88
    if right_char is not None and right_char.isdigit():
        return 0.92 if is_builtin_token else 0.86
    if attr_type == PIIAttributeType.ADDRESS:
        if left_open or right_open:
            return 0.9 if is_builtin_token else 0.82
        if rule_profile.level == ProtectionLevel.STRONG:
            return 0.76 if is_builtin_token else 0.72
        if rule_profile.level == ProtectionLevel.BALANCED:
            return 0.72 if is_builtin_token else 0.66
        return 0.0
    if left_open or right_open:
        return 0.86 if is_builtin_token else 0.78
    if rule_profile.level == ProtectionLevel.STRONG and (is_builtin_token or len(value) >= 3):
        return 0.72
    return 0.0

def _english_address_confidence(self, value: str) -> float:
    cleaned = self._clean_address_candidate(value)
    if not cleaned or not self._supports_en():
        return 0.0
    score = 0.0
    lowered = cleaned.lower()
    if _EN_PO_BOX_PATTERN.search(cleaned):
        score += 0.62
    if _EN_ADDRESS_NUMBER_PATTERN.search(cleaned):
        score += 0.24
    if _EN_ADDRESS_SUFFIX_PATTERN.search(cleaned):
        score += 0.32
    if _EN_ADDRESS_UNIT_PATTERN.search(cleaned):
        score += 0.12
    if _EN_STATE_OR_REGION_PATTERN.search(cleaned):
        score += 0.12
    if _EN_POSTAL_CODE_PATTERN.search(cleaned):
        score += 0.14
    if any(keyword in lowered for keyword in ("address", "street", "road", "avenue", "boulevard", "drive", "lane", "suite", "unit")):
        score += 0.08
    return min(0.96, score)

def _looks_like_address_candidate(self, value: str, *, min_confidence: float = 0.45) -> bool:
    """判断是否像地址或地址碎片。"""
    cleaned = self._clean_address_candidate(value)
    if not cleaned or len(cleaned) > 80:
        return False
    if cleaned in _ADDRESS_FIELD_KEYWORDS:
        return False
    confidence = self._address_confidence(cleaned)
    if confidence >= min_confidence:
        return True
    return self._looks_like_masked_address_candidate(cleaned, min_confidence=min_confidence)

def _looks_like_masked_address_candidate(
    self,
    value: str,
    *,
    min_confidence: float = 0.45,
    allow_alpha_masks: bool = True,
) -> bool:
    cleaned = self._clean_address_candidate(value)
    compact = re.sub(r"\s+", "", cleaned)
    if not compact:
        return False
    visible = "".join(
        char
        for char in compact
        if char not in _TEXT_MASK_VISUAL_SYMBOLS and char not in {"*", "＊"} and (allow_alpha_masks or char not in _TEXT_MASK_ALPHA_SYMBOLS)
    )
    mask_count = len(compact) - len(visible)
    if mask_count <= 0 or not visible:
        return False
    if not (
        _ADDRESS_SUFFIX_PATTERN.search(compact)
        or _ADDRESS_NUMBER_PATTERN.search(compact)
        or any(token in visible for token in _REGION_TOKENS)
        or any(token in visible for token in _BUILTIN_GEO_LEXICON.address_tokens)
    ):
        return False
    confidence = self._address_confidence(cleaned)
    if mask_count >= 2:
        confidence += 0.12
    if _ADDRESS_NUMBER_PATTERN.search(compact):
        confidence += 0.08
    if _ADDRESS_SUFFIX_PATTERN.search(compact):
        confidence += 0.06
    return confidence >= min_confidence

def _should_collect_full_text_address(
    self,
    raw_text: str,
    cleaned: str,
    *,
    rule_profile: _RuleStrengthProfile,
) -> bool:
    """仅在整段文本本身已经像独立地址片段时才直接收整段。"""
    if _OCR_SEMANTIC_BREAK_TOKEN in raw_text:
        return False
    if not self._looks_like_address_candidate(cleaned, min_confidence=rule_profile.address_min_confidence):
        return False
    base_text = self._clean_extracted_value(raw_text)
    if sum(1 for _ in self.field_label_pattern.finditer(base_text)) > 1:
        return False
    if re.search(r"[，,。！？；;、]", base_text):
        return False
    return len(base_text) - len(cleaned) <= 6

def _address_confidence(self, value: str) -> float:
    """根据地址信号强度计算置信度。"""
    cleaned = self._clean_address_candidate(value)
    if not cleaned:
        return 0.0
    score = 0.0
    suffix_hits = _ADDRESS_SUFFIX_PATTERN.findall(cleaned)
    if any(token in cleaned for token in _REGION_TOKENS):
        score += 0.34
    if any(token in cleaned for token in _BUILTIN_GEO_LEXICON.address_tokens):
        score += 0.24
    if suffix_hits:
        score += min(0.36, 0.18 * len(suffix_hits))
    if _ADDRESS_NUMBER_PATTERN.search(cleaned):
        score += 0.28
    if _STANDALONE_ADDRESS_FRAGMENT_PATTERN.fullmatch(cleaned):
        score += 0.24
    if _SHORT_ADDRESS_TOKEN_PATTERN.fullmatch(cleaned):
        score += 0.10
    if any(keyword in cleaned for keyword in _ADDRESS_FIELD_KEYWORDS):
        score += 0.18
    if len(cleaned) >= 6 and re.fullmatch(rf"[A-Za-z0-9#\-－—()（）·\s一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]+", cleaned):
        score += 0.08
    if re.fullmatch(r"(?:\d{1,5}|[A-Za-z]\d{1,5})(?:号院|号楼|栋|幢|座|单元|室|层|号|户)(?:\d{0,4}(?:室|层|户))?", cleaned):
        score += 0.20
    score = max(score, self._english_address_confidence(cleaned))
    return min(0.96, score)

def _organization_confidence(self, value: str, *, allow_weak_suffix: bool = True) -> float:
    """根据机构后缀与格式特征估算置信度。"""
    cleaned = self._clean_organization_candidate(value)
    compact = re.sub(r"\s+", "", cleaned)
    if not compact:
        return 0.0
    score = 0.0
    strong_en, weak_en = self._has_en_organization_suffix(cleaned, allow_weak_suffix=allow_weak_suffix)
    if _ORGANIZATION_STRONG_SUFFIX_PATTERN.search(compact) or strong_en:
        score += 0.62
    elif _ORGANIZATION_WEAK_SUFFIX_PATTERN.search(compact) or weak_en:
        if not allow_weak_suffix:
            return 0.0
        score += 0.48
    if re.search(r"[A-Za-z]", cleaned):
        score += 0.08
    if any(
        token in compact
        for token in ("大学", "学院", "医院", "银行", "公司", "集团", "法院", "研究院")
    ) or any(
        token in cleaned.lower()
        for token in ("university", "college", "hospital", "bank", "company", "corporation", "institute")
    ):
        score += 0.12
    if len(compact) >= 6:
        score += 0.08
    return min(0.92, score)

def _upsert_candidate(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    text: str,
    matched_text: str,
    attr_type: PIIAttributeType,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    span_start: int | None,
    span_end: int | None,
    confidence: float,
    matched_by: str,
    canonical_source_text: str | None = None,
    metadata: dict[str, list[str]] | None = None,
    skip_spans: list[tuple[int, int]] | None = None,
) -> None:
    """插入候选，或更新已存在候选的置信度与元信息。"""
    if attr_type == PIIAttributeType.PHONE:
        cleaned_text = self._clean_phone_candidate(matched_text)
    else:
        cleaned_text = self._clean_extracted_value(matched_text)
    if not cleaned_text:
        return
    if skip_spans and span_start is not None and span_end is not None:
        if self._overlaps_any_span(span_start, span_end, skip_spans):
            return
    attr_type = self._normalize_fallback_attr_type(attr_type, cleaned_text)
    normalized = canonicalize_pii_value(attr_type, cleaned_text)
    key = (normalized, attr_type.value, span_start, span_end)
    entity_id = self.resolver.build_candidate_id(
        self.detector_mode,
        source.value,
        normalized,
        attr_type.value,
        block_id=block_id,
        span_start=span_start,
        span_end=span_end,
    )
    incoming = PIICandidate(
        entity_id=entity_id,
        text=cleaned_text,
        canonical_source_text=canonical_source_text,
        normalized_text=normalized,
        attr_type=attr_type,
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start,
        span_end=span_end,
        confidence=confidence,
        metadata=self._candidate_metadata(matched_by=matched_by, metadata=metadata),
    )
    previous = collected.get(key)
    if previous is None:
        collected[key] = incoming
        return
    merged_metadata = self._merge_candidate_metadata(previous.metadata, incoming.metadata)
    merged_matched_by = merged_metadata.get("matched_by", [])
    if incoming.confidence > previous.confidence:
        incoming.metadata = merged_metadata
        if incoming.canonical_source_text is None:
            incoming.canonical_source_text = previous.canonical_source_text
        collected[key] = incoming
        return
    previous.metadata = merged_metadata
    if previous.canonical_source_text is None and incoming.canonical_source_text is not None:
        previous.canonical_source_text = incoming.canonical_source_text
    if any(item.startswith("context_") for item in merged_matched_by) and any(item.startswith("regex_") for item in merged_matched_by):
        previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.08)
    elif "heuristic_address_fragment" in merged_matched_by and "regex_address_span" in merged_matched_by:
        previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.06)

def _normalize_fallback_attr_type(self, attr_type: PIIAttributeType, value: str) -> PIIAttributeType:
    if attr_type != PIIAttributeType.OTHER:
        return attr_type
    return classify_content_shape_attr(value)

def _overlaps_any_span(
    self,
    span_start: int,
    span_end: int,
    spans: list[tuple[int, int]],
) -> bool:
    """判断候选区间是否与已保护区间重叠。"""
    for left, right in spans:
        if not (span_end <= left or span_start >= right):
            return True
    return False

def _dictionary_entry_variants(self, attr_type: PIIAttributeType, entry: _LocalDictionaryEntry) -> set[str]:
    """生成本地词条的匹配变体，包含显式 alias。"""
    variants = set(dictionary_match_variants(attr_type, entry.value))
    for alias in entry.aliases:
        variants.update(dictionary_match_variants(attr_type, alias))
    return variants

def _dictionary_match_metadata(self, match: _DictionaryMatch) -> dict[str, list[str]] | None:
    """将本地词库命中携带的实体信息写入 metadata。"""
    merged = dict(match.metadata)
    if match.local_entity_ids:
        merged["local_entity_ids"] = list(match.local_entity_ids)
    return merged or None

def _candidate_metadata(self, matched_by: str, metadata: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    base = {"matched_by": [matched_by]}
    if metadata is None:
        return base
    return self._merge_candidate_metadata(base, metadata)

def _merge_candidate_metadata(
    self,
    left: dict[str, list[str]] | None,
    right: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for source in (left or {}, right or {}):
        for key, values in source.items():
            merged[key] = sorted(set(merged.get(key, [])) | set(values))
    name_components = set(merged.get("name_component", []))
    if name_components:
        specific = [item for item in ("family", "given", "middle") if item in name_components]
        if specific:
            merged["name_component"] = specific
        else:
            merged["name_component"] = [item for item in ("full",) if item in name_components] or sorted(name_components)
    return merged

def _to_attr_type(self, raw_key: str | PIIAttributeType) -> PIIAttributeType | None:
    """将字典键名映射为领域枚举。"""
    if isinstance(raw_key, PIIAttributeType):
        return raw_key
    key = raw_key.strip().lower()
    mapping = {
        "name": PIIAttributeType.NAME,
        "location_clue": PIIAttributeType.LOCATION_CLUE,
        "phone": PIIAttributeType.PHONE,
        "card_number": PIIAttributeType.CARD_NUMBER,
        "card": PIIAttributeType.CARD_NUMBER,
        "credit_card": PIIAttributeType.CARD_NUMBER,
        "bank_card": PIIAttributeType.CARD_NUMBER,
        "debit_card": PIIAttributeType.CARD_NUMBER,
        "bank_account": PIIAttributeType.BANK_ACCOUNT,
        "account_number": PIIAttributeType.BANK_ACCOUNT,
        "passport_number": PIIAttributeType.PASSPORT_NUMBER,
        "passport": PIIAttributeType.PASSPORT_NUMBER,
        "driver_license": PIIAttributeType.DRIVER_LICENSE,
        "driver_license_number": PIIAttributeType.DRIVER_LICENSE,
        "email": PIIAttributeType.EMAIL,
        "address": PIIAttributeType.ADDRESS,
        "id_number": PIIAttributeType.ID_NUMBER,
        "id": PIIAttributeType.ID_NUMBER,
        "organization": PIIAttributeType.ORGANIZATION,
        "time": PIIAttributeType.TIME,
        "numeric": PIIAttributeType.NUMERIC,
        "textual": PIIAttributeType.TEXTUAL,
        "other": PIIAttributeType.OTHER,
    }
    return mapping.get(key)
