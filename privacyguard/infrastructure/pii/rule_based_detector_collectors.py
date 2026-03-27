"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _build_shadow_text(
    self,
    raw_text: str,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
) -> _ShadowTextDocument:
    """将已识别 span 替换为类型占位符，保留后续弱规则所需的局部语义。"""
    protected_candidates = sorted(
        (
            candidate
            for candidate in collected.values()
            if candidate.span_start is not None and candidate.span_end is not None and candidate.span_start < candidate.span_end
        ),
        key=lambda item: (item.span_start, item.span_end),
    )
    shadow_chars: list[str] = []
    index_map: list[int | None] = []
    cursor = 0
    for candidate in protected_candidates:
        span_start = candidate.span_start
        span_end = candidate.span_end
        if span_start is None or span_end is None or span_start < cursor:
            continue
        for index in range(cursor, span_start):
            shadow_chars.append(raw_text[index])
            index_map.append(index)
        token = self._shadow_token(candidate.attr_type)
        for char in token:
            shadow_chars.append(char)
            index_map.append(None)
        cursor = span_end
    for index in range(cursor, len(raw_text)):
        shadow_chars.append(raw_text[index])
        index_map.append(index)
    return _ShadowTextDocument(text="".join(shadow_chars), index_map=tuple(index_map))

def _shadow_token(self, attr_type: PIIAttributeType) -> str:
    mapping = {
        PIIAttributeType.NAME: " <NAME> ",
        PIIAttributeType.PHONE: " <PHONE> ",
        PIIAttributeType.CARD_NUMBER: " <CARD> ",
        PIIAttributeType.BANK_ACCOUNT: " <ACCOUNT> ",
        PIIAttributeType.PASSPORT_NUMBER: " <PASSPORT> ",
        PIIAttributeType.DRIVER_LICENSE: " <DL> ",
        PIIAttributeType.EMAIL: " <EMAIL> ",
        PIIAttributeType.ID_NUMBER: " <ID> ",
        PIIAttributeType.ADDRESS: " <ADDR> ",
        PIIAttributeType.DETAILS: " <ADDR> ",
        PIIAttributeType.ORGANIZATION: " <ORG> ",
        PIIAttributeType.TIME: " <TIME> ",
        PIIAttributeType.NUMERIC: " <NUM> ",
        PIIAttributeType.TEXTUAL: " <TXT> ",
        PIIAttributeType.OTHER: " <CODE> ",
    }
    return mapping[attr_type]


def _name_component_from_matched_by(self, matched_by: str) -> str | None:
    if matched_by == "context_name_family_field":
        return "family"
    if matched_by == "context_name_given_field":
        return "given"
    if matched_by == "context_name_middle_field":
        return "middle"
    if matched_by.startswith("context_name_") or matched_by.startswith("regex_name_") or matched_by.startswith("heuristic_name_"):
        return "full"
    return None


def _name_component_metadata(self, component: str | None) -> dict[str, list[str]] | None:
    if not component:
        return None
    return {"name_component": [component]}

def _collect_dictionary_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    dictionary_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
    skip_spans: list[tuple[int, int]] | None = None,
) -> None:
    """收集本地字典命中。"""
    for attr_type, compiled_index in dictionary_index.items():
        pending_matches: list[_DictionaryMatch] = []
        for match in self._find_index_dictionary_matches(raw_text, attr_type, compiled_index):
            pending_matches.append(match)
        for match in self._select_dictionary_matches(pending_matches):
            canonical_source_text = match.canonical_source_text
            if canonical_source_text is None and attr_type == PIIAttributeType.NAME:
                canonical_source_text = self._canonical_name_source_text(
                    match.matched_text,
                    reference_text=match.source_term,
                    allow_ocr_noise=True,
                )
            if attr_type == PIIAttributeType.NAME and not self._is_name_dictionary_match_allowed(
                raw_text,
                match.span_start,
                match.span_end,
            ):
                continue
            metadata = self._dictionary_match_metadata(match)
            self._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=match.matched_text,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=match.span_start,
                span_end=match.span_end,
                confidence=match.confidence,
                matched_by=match.matched_by,
                canonical_source_text=canonical_source_text,
                metadata=metadata,
                skip_spans=skip_spans,
            )

def _collect_context_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
) -> None:
    """收集字段上下文命中。"""
    for attr_type, pattern, matched_by, confidence, validator in self.context_rules:
        for match in pattern.finditer(raw_text):
            extracted = self._extract_match(raw_text, *match.span("value"))
            if extracted is None:
                continue
            value, span_start, span_end = extracted
            trimmed = self._trim_context_value(raw_text, value, span_start, span_end)
            if trimmed is None:
                continue
            value, span_start, span_end = trimmed
            canonical_source_text = None
            validator_value = value
            metadata = None
            if attr_type == PIIAttributeType.NAME:
                if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                    continue
                component = self._name_component_from_matched_by(matched_by)
                metadata = self._name_component_metadata(component)
                if component is not None:
                    canonical_source_text = self._canonical_name_component_source_text(
                        value,
                        component=component,
                        allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                    )
                else:
                    canonical_source_text = self._canonical_name_source_text(
                        value,
                        allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                    )
                if canonical_source_text:
                    validator_value = canonical_source_text
            if attr_type == PIIAttributeType.ADDRESS and self._contains_mask_char(
                value,
                allow_alpha_masks=True,
            ) and not rule_profile.enable_context_masked_text:
                continue
            candidate_matched_by = matched_by
            candidate_confidence = confidence
            is_valid = bool(value) and validator(validator_value)
            if not is_valid and self._is_context_masked_text_candidate(
                value,
                attr_type=attr_type,
                rule_profile=rule_profile,
            ):
                is_valid = True
                candidate_matched_by = f"{matched_by}_masked"
                candidate_confidence = max(0.62, confidence - 0.14)
            if not is_valid:
                continue
            self._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=value,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=candidate_confidence,
                matched_by=candidate_matched_by,
                canonical_source_text=canonical_source_text,
                metadata=metadata,
                skip_spans=skip_spans,
            )

def _trim_context_value(
    self,
    raw_text: str,
    value: str,
    span_start: int,
    span_end: int,
) -> tuple[str, int, int] | None:
    """截断被贪婪 value_pattern 吞进去的后续字段标签。"""
    current_value = value
    current_end = span_end
    while current_value and current_end < len(raw_text):
        if _FIELD_LABEL_CONNECTOR_PATTERN.match(raw_text[current_end:]) is None:
            break
        match = self.trailing_field_label_pattern.fullmatch(current_value)
        if match is None:
            break
        trimmed = match.group("body").rstrip()
        if not trimmed or trimmed == current_value:
            break
        current_end = span_start + len(trimmed)
        current_value = trimmed
    if not current_value:
        return None
    return current_value, span_start, current_end

def _is_context_masked_text_candidate(
    self,
    value: str,
    *,
    attr_type: PIIAttributeType,
    rule_profile: _RuleStrengthProfile,
) -> bool:
    if not rule_profile.enable_context_masked_text:
        return False
    if attr_type != PIIAttributeType.ADDRESS:
        return False
    return self._looks_like_masked_address_candidate(
        value,
        min_confidence=rule_profile.address_min_confidence,
        allow_alpha_masks=rule_profile.allow_alpha_mask_text,
    )

def _contains_mask_char(self, value: str, *, allow_alpha_masks: bool) -> bool:
    compact = re.sub(r"\s+", "", value or "")
    for char in compact:
        if char in _TEXT_MASK_VISUAL_SYMBOLS or char in {"*", "＊"}:
            return True
        if allow_alpha_masks and char in _TEXT_MASK_ALPHA_SYMBOLS:
            return True
    return False

def _is_repeated_mask_text(
    self,
    value: str,
    *,
    min_run: int,
    allow_alpha_masks: bool,
) -> bool:
    compact = re.sub(r"\s+", "", value or "")
    if len(compact) < min_run:
        return False
    repeated_char = compact[0]
    if any(char != repeated_char for char in compact):
        return False
    if repeated_char not in _TEXT_MASK_SYMBOLS:
        return False
    if not allow_alpha_masks and repeated_char in _TEXT_MASK_ALPHA_SYMBOLS:
        return False
    if repeated_char in _TEXT_MASK_VISUAL_SYMBOLS:
        return True
    return repeated_char in _TEXT_MASK_ALPHA_SYMBOLS

def _collect_regex_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
) -> None:
    """收集格式型正则规则命中。"""
    for attr_type, rule_items in self.patterns.items():
        for pattern, matched_by, confidence in rule_items:
            for match in pattern.finditer(raw_text):
                cleaner = self._clean_phone_candidate if attr_type == PIIAttributeType.PHONE else None
                extracted = self._extract_match(raw_text, *match.span(0), cleaner=cleaner)
                if extracted is None:
                    continue
                matched_text, span_start, span_end = extracted
                resolved = self._resolve_regex_match(
                    raw_text=raw_text,
                    matched_text=matched_text,
                    attr_type=attr_type,
                    matched_by=matched_by,
                    confidence=confidence,
                    span_start=span_start,
                    span_end=span_end,
                )
                if resolved is None:
                    continue
                resolved_attr_type, resolved_matched_by, resolved_confidence, resolved_metadata = resolved
                self._upsert_regex_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=matched_text,
                    attr_type=resolved_attr_type,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=resolved_confidence,
                    matched_by=resolved_matched_by,
                    metadata=resolved_metadata,
                    skip_spans=skip_spans,
                )

def _collect_generic_number_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
) -> None:
    """兜底识别 4 位及以上数字串，避免高精度信息漏检。"""
    for match in _GENERIC_NUMBER_PATTERN.finditer(raw_text):
        extracted = self._extract_match(raw_text, *match.span(0))
        if extracted is None:
            continue
        matched_text, span_start, span_end = extracted
        if skip_spans and span_start is not None and span_end is not None:
            if self._overlaps_any_span(span_start, span_end, skip_spans):
                continue
        digit_count = len(re.sub(r"\D", "", matched_text))
        if digit_count < 4:
            continue
        confidence = 0.98 if digit_count >= 7 else 0.94
        self._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=matched_text,
            attr_type=PIIAttributeType.NUMERIC,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by="regex_generic_number",
            metadata={"digit_count": [str(digit_count)]},
            skip_spans=skip_spans,
        )

def _upsert_regex_candidate(
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
    metadata: dict[str, list[str]] | None = None,
    skip_spans: list[tuple[int, int]] | None = None,
) -> None:
    """在 regex 阶段对同一 span 的高精度数字类型做冲突收敛。"""
    if span_start is None or span_end is None:
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            metadata=metadata,
            skip_spans=skip_spans,
        )
        return
    if not self._is_regex_numeric_candidate_type(attr_type, matched_by):
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            metadata=metadata,
            skip_spans=skip_spans,
        )
        return

    same_span_items = self._same_span_numeric_regex_items(
        collected,
        span_start=span_start,
        span_end=span_end,
    )
    specific_items = [
        item
        for item in same_span_items
        if item[1].attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES
    ]
    ambiguous_items = [
        item
        for item in same_span_items
        if self._is_regex_ambiguous_number_candidate(item[1])
    ]

    incoming_is_ambiguous = attr_type == PIIAttributeType.OTHER and matched_by == "regex_number_ambiguous"
    if incoming_is_ambiguous:
        if specific_items:
            return
        if ambiguous_items:
            self._merge_ambiguous_numeric_candidate(
                candidate=ambiguous_items[0][1],
                metadata=metadata,
                confidence=confidence,
            )
            return
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            metadata=metadata,
            skip_spans=skip_spans,
        )
        return

    same_attr_items = [item for item in specific_items if item[1].attr_type == attr_type]
    conflicting_specific_items = [item for item in specific_items if item[1].attr_type != attr_type]
    if conflicting_specific_items:
        ambiguous_types = {attr_type.value}
        for _, existing in same_span_items:
            if existing.attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES:
                ambiguous_types.add(existing.attr_type.value)
            ambiguous_types.update(existing.metadata.get("ambiguous_numeric_types", []))
        for key, _ in same_span_items:
            collected.pop(key, None)
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=PIIAttributeType.OTHER,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=max(0.8, confidence),
            matched_by="regex_number_ambiguous",
            metadata={"ambiguous_numeric_types": sorted(ambiguous_types)},
            skip_spans=skip_spans,
        )
        return

    if ambiguous_items:
        for key, _ in ambiguous_items:
            collected.pop(key, None)
    if same_attr_items:
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            metadata=metadata,
            skip_spans=skip_spans,
        )
        return
    self._upsert_candidate(
        collected=collected,
        text=text,
        matched_text=matched_text,
        attr_type=attr_type,
        source=source,
        bbox=bbox,
        block_id=block_id,
        span_start=span_start,
        span_end=span_end,
        confidence=confidence,
        matched_by=matched_by,
        metadata=metadata,
        skip_spans=skip_spans,
    )

def _resolve_regex_match(
    self,
    *,
    raw_text: str,
    matched_text: str,
    attr_type: PIIAttributeType,
    matched_by: str,
    confidence: float,
    span_start: int,
    span_end: int,
) -> tuple[PIIAttributeType, str, float, dict[str, list[str]] | None] | None:
    """对 regex 命中的高精度字段做二次校验与歧义降级。"""
    if attr_type == PIIAttributeType.PHONE:
        if self._is_phone_candidate(matched_text):
            return (attr_type, matched_by, confidence, None)
        if matched_by.startswith("regex_phone_us") and self._is_en_phone_candidate(matched_text, allow_plain_local=True):
            return (attr_type, matched_by, confidence, None)
        return None
    if attr_type == PIIAttributeType.EMAIL:
        return (attr_type, matched_by, confidence, None) if self._is_email_candidate(matched_text) else None
    if attr_type == PIIAttributeType.PASSPORT_NUMBER:
        if not self._is_passport_candidate(matched_text):
            return None
        if self._has_other_number_context(raw_text, span_start, span_end):
            return (
                PIIAttributeType.OTHER,
                "regex_number_ambiguous",
                max(0.8, confidence),
                {"ambiguous_numeric_types": [PIIAttributeType.PASSPORT_NUMBER.value]},
            )
        return (attr_type, matched_by, confidence, None)
    if attr_type not in {
        PIIAttributeType.CARD_NUMBER,
        PIIAttributeType.BANK_ACCOUNT,
        PIIAttributeType.DRIVER_LICENSE,
        PIIAttributeType.ID_NUMBER,
    }:
        return (attr_type, matched_by, confidence, None)
    numeric_candidates = self._numeric_candidate_types(matched_text)
    if not numeric_candidates:
        return None
    preferred_attr_type = self._preferred_numeric_attr_type(
        raw_text=raw_text,
        matched_text=matched_text,
        current_attr_type=attr_type,
        matched_by=matched_by,
        numeric_candidates=numeric_candidates,
        span_start=span_start,
        span_end=span_end,
    )
    if preferred_attr_type is not None:
        if preferred_attr_type != attr_type:
            return None
        return (preferred_attr_type, matched_by, confidence, None)
    return (
        PIIAttributeType.OTHER,
        "regex_number_ambiguous",
        max(0.8, confidence),
        {"ambiguous_numeric_types": [item.value for item in sorted(numeric_candidates, key=lambda x: x.value)]},
    )

def _numeric_candidate_types(self, value: str) -> set[PIIAttributeType]:
    """收集一个数字串可能对应的高精度数字类型。"""
    candidates: set[PIIAttributeType] = set()
    if self._is_id_candidate(value):
        candidates.add(PIIAttributeType.ID_NUMBER)
    if self._is_card_number_candidate(value):
        candidates.add(PIIAttributeType.CARD_NUMBER)
    if self._is_bank_account_candidate(value):
        candidates.add(PIIAttributeType.BANK_ACCOUNT)
    if self._is_driver_license_candidate(value):
        candidates.add(PIIAttributeType.DRIVER_LICENSE)
    return candidates

def _preferred_numeric_attr_type(
    self,
    *,
    raw_text: str,
    matched_text: str,
    current_attr_type: PIIAttributeType,
    matched_by: str,
    numeric_candidates: set[PIIAttributeType],
    span_start: int,
    span_end: int,
) -> PIIAttributeType | None:
    """在高精度数字类型冲突时选出可明确归类的类型，否则返回 None。"""
    keyword_bias = self._numeric_keyword_bias(raw_text, span_start, span_end)
    if keyword_bias is not None and keyword_bias in numeric_candidates:
        return keyword_bias
    if PIIAttributeType.ID_NUMBER in numeric_candidates and (
        matched_by.startswith("regex_cn_id") or self._looks_like_cn_id_with_birthdate(matched_text)
    ):
        return PIIAttributeType.ID_NUMBER
    if len(numeric_candidates) == 1:
        return next(iter(numeric_candidates))
    card_compact = compact_card_number_value(matched_text)
    if (
        current_attr_type == PIIAttributeType.CARD_NUMBER
        and PIIAttributeType.CARD_NUMBER in numeric_candidates
        and re.fullmatch(r"\d{13,19}", card_compact)
        and self._passes_luhn(card_compact)
    ):
        return PIIAttributeType.CARD_NUMBER
    bank_compact = compact_bank_account_value(matched_text)
    if (
        current_attr_type == PIIAttributeType.BANK_ACCOUNT
        and PIIAttributeType.BANK_ACCOUNT in numeric_candidates
        and len(re.sub(r"[^0-9*＊xX]", "", bank_compact)) > 19
    ):
        return PIIAttributeType.BANK_ACCOUNT
    driver_compact = compact_driver_license_value(matched_text)
    if (
        current_attr_type == PIIAttributeType.DRIVER_LICENSE
        and PIIAttributeType.DRIVER_LICENSE in numeric_candidates
        and self._is_strong_driver_license_shape(driver_compact)
    ):
        return PIIAttributeType.DRIVER_LICENSE
    if self._has_other_number_context(raw_text, span_start, span_end):
        return None
    if (
        current_attr_type == PIIAttributeType.CARD_NUMBER
        and numeric_candidates == {PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}
    ):
        return None
    return None

def _numeric_keyword_bias(
    self,
    raw_text: str,
    span_start: int,
    span_end: int,
) -> PIIAttributeType | None:
    """根据附近字段关键词给高精度数字优先归类。"""
    window = self._match_context_window(raw_text, span_start, span_end)
    if self._window_has_keywords(window, _CARD_FIELD_KEYWORDS):
        return PIIAttributeType.CARD_NUMBER
    if self._window_has_keywords(window, _BANK_ACCOUNT_FIELD_KEYWORDS):
        return PIIAttributeType.BANK_ACCOUNT
    if self._window_has_keywords(window, _DRIVER_LICENSE_FIELD_KEYWORDS):
        return PIIAttributeType.DRIVER_LICENSE
    if self._window_has_keywords(window, _ID_FIELD_KEYWORDS):
        return PIIAttributeType.ID_NUMBER
    return None

def _has_other_number_context(self, raw_text: str, span_start: int, span_end: int) -> bool:
    """判断命中数字周围是否更像订单号/编号等泛化编号语境。"""
    window = self._match_context_window(raw_text, span_start, span_end)
    return self._window_has_keywords(window, _OTHER_FIELD_KEYWORDS)

def _match_context_window(self, raw_text: str, span_start: int, span_end: int, *, radius: int = 12) -> str:
    left = max(0, span_start - radius)
    right = min(len(raw_text), span_end + radius)
    return raw_text[left:right]

def _window_has_keywords(self, window: str, keywords: tuple[str, ...]) -> bool:
    lowered = window.lower()
    return any(keyword.lower() in lowered for keyword in keywords)

def _looks_like_cn_id_with_birthdate(self, value: str) -> bool:
    compact = compact_id_value(value)
    return bool(
        re.fullmatch(r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]", compact)
        or re.fullmatch(r"[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}", compact)
    )

def _is_non_id_driver_license_shape(self, compact: str) -> bool:
    compact_alnum = re.sub(r"[^A-Z0-9*＊xX]", "", compact.upper())
    return bool(
        re.fullmatch(r"\d{12}", compact_alnum)
        or re.fullmatch(r"\d{15}", compact_alnum)
        or re.fullmatch(r"[A-Z]{1,3}\d{7,17}", compact_alnum)
        or re.fullmatch(r"[A-Z0-9]{2,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact_alnum)
    )

def _is_strong_driver_license_shape(self, compact: str) -> bool:
    compact_alnum = re.sub(r"[^A-Z0-9*＊xX]", "", compact.upper())
    return bool(
        re.fullmatch(r"[A-Z]{1,3}\d{7,17}", compact_alnum)
        or (
            any(char.isalpha() for char in compact_alnum)
            and re.fullmatch(r"[A-Z0-9]{2,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact_alnum)
        )
    )

def _same_span_numeric_regex_items(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    *,
    span_start: int,
    span_end: int,
) -> list[tuple[tuple[str, str, int | None, int | None], PIICandidate]]:
    return [
        (key, candidate)
        for key, candidate in collected.items()
        if candidate.span_start == span_start
        and candidate.span_end == span_end
        and self._is_regex_numeric_candidate(candidate)
    ]

def _is_regex_numeric_candidate(self, candidate: PIICandidate) -> bool:
    matched_by_items = candidate.metadata.get("matched_by", [])
    return any(
        item.startswith("regex_") and self._is_regex_numeric_candidate_type(candidate.attr_type, item)
        for item in matched_by_items
    )

def _is_regex_numeric_candidate_type(self, attr_type: PIIAttributeType, matched_by: str) -> bool:
    return attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES or (
        attr_type == PIIAttributeType.NUMERIC and matched_by == "regex_number_ambiguous"
    )

def _is_regex_ambiguous_number_candidate(self, candidate: PIICandidate) -> bool:
    return candidate.attr_type == PIIAttributeType.NUMERIC and "regex_number_ambiguous" in candidate.metadata.get("matched_by", [])

def _merge_ambiguous_numeric_candidate(
    self,
    *,
    candidate: PIICandidate,
    metadata: dict[str, list[str]] | None,
    confidence: float,
) -> None:
    merged_metadata = self._merge_candidate_metadata(candidate.metadata, metadata or {})
    candidate.metadata = merged_metadata
    candidate.confidence = max(candidate.confidence, confidence)

def _collect_name_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    """收集姓名相关的上下文与敬称规则。"""
    if rule_profile.enable_self_name_patterns:
        for pattern, matched_by, confidence in self.self_name_patterns:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(
                    raw_text,
                    *match.span("value"),
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                canonical_source_text = self._canonical_name_source_text(
                    value,
                    allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                )
                validator_value = canonical_source_text or value
                if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                    continue
                if not self._is_name_candidate(validator_value):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=PIIAttributeType.NAME,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=confidence,
                    matched_by=matched_by,
                    canonical_source_text=canonical_source_text,
                    metadata=self._name_component_metadata("full"),
                    skip_spans=skip_spans,
                )
    if rule_profile.enable_honorific_name_pattern:
        honorific_patterns: list[tuple[re.Pattern[str], str, float]] = []
        if self._supports_zh():
            honorific_patterns.append((self.name_title_pattern, "regex_name_honorific", 0.72))
        if self._supports_en():
            honorific_patterns.append((self.en_name_title_pattern, "regex_name_honorific_en", 0.78))
        for pattern, matched_by, confidence in honorific_patterns:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(
                    raw_text,
                    *match.span("value"),
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                    continue
                canonical_source_text = self._canonical_name_source_text(
                    value,
                    allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                )
                validator_value = canonical_source_text or value
                if not self._looks_like_name_with_title(validator_value):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=PIIAttributeType.NAME,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=confidence,
                    matched_by=matched_by,
                    canonical_source_text=canonical_source_text,
                    metadata=self._name_component_metadata("full"),
                    skip_spans=skip_spans,
                )
def _collect_generic_name_fragment_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    local_skip_spans = list(skip_spans)
    name_matches: list[tuple[re.Match[str], str]] = [
        (match, "heuristic_name_fragment")
        for match in self.generic_name_pattern.finditer(raw_text)
    ]
    if self._supports_en():
        name_matches.extend(
            (match, "heuristic_name_fragment_en")
            for match in self.en_standalone_name_pattern.finditer(raw_text)
        )
    for match, matched_by in name_matches:
        extracted = self._extract_match(
            raw_text,
            *match.span("value"),
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if extracted is None:
            continue
        value, span_start, span_end = extracted
        if span_start is None or span_end is None:
            continue
        if self._overlaps_any_span(span_start, span_end, local_skip_spans):
            continue
        canonical_source_text = self._canonical_name_source_text(
            value,
            allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
        )
        validator_value = canonical_source_text or value
        if not self._is_name_candidate(validator_value):
            continue
        confidence = self._generic_name_confidence(
            original_text or raw_text,
            span_start,
            span_end,
            value=validator_value,
            source=source,
            rule_profile=rule_profile,
        )
        if confidence <= 0.0:
            continue
        self._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=value,
            attr_type=PIIAttributeType.NAME,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            canonical_source_text=canonical_source_text,
            metadata=self._name_component_metadata("full"),
            skip_spans=local_skip_spans,
        )
        local_skip_spans.append((span_start, span_end))

def _collect_masked_text_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    if not rule_profile.enable_standalone_masked_text:
        return
    for match in self.masked_text_pattern.finditer(raw_text):
        extracted = self._extract_match(
            raw_text,
            *match.span("value"),
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if extracted is None:
            continue
        value, span_start, span_end = extracted
        if not self._is_repeated_mask_text(
            value,
            min_run=rule_profile.masked_text_min_run,
            allow_alpha_masks=rule_profile.allow_alpha_mask_text,
        ):
            continue
        confidence = 0.62 if re.sub(r"\s+", "", value)[0] in _TEXT_MASK_VISUAL_SYMBOLS else 0.56
        self._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=value,
            attr_type=PIIAttributeType.OTHER,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by="heuristic_masked_text",
            skip_spans=skip_spans,
        )

def _collect_geo_fragment_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    """用内置地名词库和通用地理后缀规则补充 location clue。"""
    local_skip_spans = list(skip_spans)
    confidence_text = original_text or raw_text
    builtin_matches = sorted(
        _LOCATION_CLUE_MATCHER.finditer(raw_text),
        key=lambda item: (-(item[1] - item[0]), item[0], item[2]),
    )
    for index, end, _token in builtin_matches:
        extracted = self._extract_match(
            raw_text,
            index,
            end,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
        )
        if extracted is None:
            continue
        value, span_start, span_end = extracted
        if self._overlaps_any_span(span_start, span_end, local_skip_spans):
            continue
        confidence = self._geo_fragment_confidence(
            confidence_text,
            span_start,
            span_end,
            value=value,
            attr_type=PIIAttributeType.ADDRESS,
            is_builtin_token=True,
            rule_profile=rule_profile,
        )
        if confidence <= 0.0:
            continue
        self._upsert_candidate(
            collected=collected,
            text=raw_text,
            matched_text=value,
            attr_type=PIIAttributeType.ADDRESS,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by="heuristic_geo_lexicon",
            skip_spans=local_skip_spans,
        )
        local_skip_spans.append((span_start, span_end))
    for pattern in _GENERIC_GEO_FRAGMENT_PATTERNS:
        for match in pattern.finditer(raw_text):
            extracted = self._extract_match(
                raw_text,
                *match.span(0),
                original_text=original_text,
                shadow_index_map=shadow_index_map,
            )
            if extracted is None:
                continue
            value, span_start, span_end = extracted
            if self._overlaps_any_span(span_start, span_end, local_skip_spans):
                continue
            confidence = self._geo_fragment_confidence(
                confidence_text,
                span_start,
                span_end,
                value=value,
                attr_type=PIIAttributeType.ADDRESS,
                is_builtin_token=False,
                rule_profile=rule_profile,
            )
            if confidence <= 0.0:
                continue
            self._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=value,
                attr_type=PIIAttributeType.ADDRESS,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by="heuristic_geo_suffix",
                skip_spans=local_skip_spans,
            )
            local_skip_spans.append((span_start, span_end))

def _collect_organization_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    """收集机构名后缀与就业/就读语境下的机构命中。"""
    organization_patterns = list(_ORGANIZATION_SPAN_PATTERNS)
    if self._supports_en():
        organization_patterns.extend(_EN_ORGANIZATION_SPAN_PATTERNS)
    for pattern in organization_patterns:
        for match in pattern.finditer(raw_text):
            extracted = self._extract_match(
                raw_text,
                *match.span(0),
                cleaner=self._clean_organization_candidate,
                original_text=original_text,
                shadow_index_map=shadow_index_map,
            )
            if extracted is None:
                continue
            value, span_start, span_end = extracted
            allow_weak_suffix = rule_profile.allow_weak_org_suffix or self._organization_has_explicit_context(
                original_text or raw_text,
                span_start,
                span_end,
            )
            if not self._is_organization_candidate(value, allow_weak_suffix=allow_weak_suffix):
                continue
            self._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=value,
                attr_type=PIIAttributeType.ORGANIZATION,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=self._organization_confidence(value, allow_weak_suffix=allow_weak_suffix),
                matched_by="regex_organization_suffix",
                skip_spans=skip_spans,
            )

def _extract_match(
    self,
    raw_text: str,
    start: int,
    end: int,
    cleaner: Callable[[str], str] | None = None,
    *,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> tuple[str, int, int] | None:
    """提取命中文本，并返回清洗后的内容及其在原文中的 span。"""
    snippet = raw_text[start:end]
    cleaned = cleaner(snippet) if cleaner is not None else self._clean_extracted_value(snippet)
    if not cleaned:
        return None
    relative_start = snippet.find(cleaned)
    if relative_start < 0:
        relative_start = snippet.lower().find(cleaned.lower())
    if relative_start < 0:
        return None
    absolute_start = start + relative_start
    absolute_end = absolute_start + len(cleaned)
    if shadow_index_map is not None:
        return self._remap_shadow_span(
            absolute_start,
            absolute_end,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
            cleaner=cleaner,
        )
    return cleaned, absolute_start, absolute_end

def _remap_shadow_span(
    self,
    shadow_start: int,
    shadow_end: int,
    *,
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...],
    cleaner: Callable[[str], str] | None = None,
) -> tuple[str, int, int] | None:
    if original_text is None:
        return None
    covered = [index for index in shadow_index_map[shadow_start:shadow_end] if index is not None]
    if not covered:
        return None
    original_start = min(covered)
    original_end = max(covered) + 1
    if len(covered) != original_end - original_start:
        return None
    return self._extract_match(original_text, original_start, original_end, cleaner=cleaner)

def _find_literal_matches(self, raw_text: str, needle: str) -> list[tuple[str, int, int]]:
    """在原文中查找字典项对应的全部匹配，并返回原文片段与 span。"""
    matches: list[tuple[str, int, int]] = []
    escaped = re.escape(needle)
    for match in re.finditer(escaped, raw_text, re.IGNORECASE):
        matched_text = raw_text[match.start():match.end()]
        matches.append((matched_text, match.start(), match.end()))
    return matches

def _find_index_dictionary_matches(
    self,
    raw_text: str,
    attr_type: PIIAttributeType,
    compiled_index: _CompiledDictionaryIndex,
) -> list[_DictionaryMatch]:
    """用预编译索引执行容错匹配，并返回候选词条命中。"""
    raw_match_text, index_map = build_match_text(attr_type, raw_text)
    if not raw_match_text:
        return []
    matches: list[_DictionaryMatch] = []
    for pos, first_char in enumerate(raw_match_text):
        by_length = compiled_index.by_first_char.get(first_char)
        if by_length is None:
            continue
        for variant_length in compiled_index.lengths_by_first_char.get(first_char, ()):
            end = pos + variant_length
            if end > len(raw_match_text):
                continue
            variant = raw_match_text[pos:end]
            matched_entries = by_length.get(variant_length, {}).get(variant)
            if not matched_entries:
                continue
            raw_start = index_map[pos]
            raw_end = index_map[end - 1] + 1
            matched_text = raw_text[raw_start:raw_end]
            for entry in matched_entries:
                matches.append(
                    _DictionaryMatch(
                        matched_text=matched_text,
                        span_start=raw_start,
                        span_end=raw_end,
                        source_term=entry.source_term,
                        canonical_source_text=entry.canonical_source_text,
                        binding_key=entry.binding_key,
                        local_entity_ids=entry.local_entity_ids,
                        matched_by=entry.matched_by,
                        confidence=entry.confidence,
                        metadata=dict(entry.metadata),
                    )
                )
    return matches

def _select_dictionary_matches(self, matches: list[_DictionaryMatch]) -> list[_DictionaryMatch]:
    """对本地词库命中做唯一性与最长片段裁剪。"""
    if not matches:
        return []
    grouped_by_span: dict[tuple[int, int], list[_DictionaryMatch]] = {}
    for match in matches:
        grouped_by_span.setdefault((match.span_start, match.span_end), []).append(match)

    unique_matches: list[_DictionaryMatch] = []
    for span, items in grouped_by_span.items():
        binding_keys = {item.binding_key for item in items}
        if len(binding_keys) != 1:
            unique_matches.append(self._build_ambiguous_dictionary_match(items))
            continue
        longest = max(items, key=lambda item: len(item.matched_text))
        unique_matches.append(longest)

    ordered = sorted(
        unique_matches,
        key=lambda item: (-(item.span_end - item.span_start), item.span_start, item.span_end),
    )
    selected: list[_DictionaryMatch] = []
    covered_spans: list[tuple[int, int]] = []
    for item in ordered:
        if any(item.span_start >= left and item.span_end <= right for left, right in covered_spans):
            continue
        selected.append(item)
        covered_spans.append((item.span_start, item.span_end))
    return sorted(selected, key=lambda item: (item.span_start, item.span_end))

def _build_ambiguous_dictionary_match(self, items: list[_DictionaryMatch]) -> _DictionaryMatch:
    """将同 span 多实体词库命中降级为“仅识别隐私类型”的候选。"""
    first = max(items, key=lambda item: len(item.matched_text))
    matched_by = f"{first.matched_by}_ambiguous"
    metadata = {
        "ambiguous_binding_keys": sorted({item.binding_key for item in items}),
    }
    session_turn_ids: set[str] = set()
    for item in items:
        session_turn_ids.update(item.metadata.get("session_turn_ids", []))
    if session_turn_ids:
        metadata["session_turn_ids"] = sorted(session_turn_ids)
    return _DictionaryMatch(
        matched_text=first.matched_text,
        span_start=first.span_start,
        span_end=first.span_end,
        source_term=first.matched_text,
        binding_key=f"ambiguous:{matched_by}:{first.span_start}:{first.span_end}",
        canonical_source_text=None,
        local_entity_ids=(),
        matched_by=matched_by,
        confidence=max(item.confidence for item in items),
        metadata=metadata,
    )

def _protected_spans_from_dictionary_hits(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    *,
    rule_profile: _RuleStrengthProfile,
) -> list[tuple[int, int]]:
    """提取本地词库与 session 历史已命中的区间，供后续 rule 扫描避让。"""
    return self._protected_spans_from_candidates(
        collected,
        matched_by_prefixes=("dictionary_",),
        rule_profile=rule_profile,
    )

def _protected_spans_from_candidates(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    *,
    matched_by_prefixes: tuple[str, ...] | None = None,
    rule_profile: _RuleStrengthProfile,
) -> list[tuple[int, int]]:
    """提取已接受候选区间，供更低精度阶段避让。"""
    protected: list[tuple[int, int]] = []
    for candidate in collected.values():
        if not self._meets_confidence_threshold(candidate.attr_type, candidate.confidence, rule_profile):
            continue
        matched_by = candidate.metadata.get("matched_by", [])
        if matched_by_prefixes is not None and not any(
            any(item.startswith(prefix) for prefix in matched_by_prefixes)
            for item in matched_by
        ):
            continue
        if candidate.span_start is None or candidate.span_end is None:
            continue
        protected.append((candidate.span_start, candidate.span_end))
    return protected
