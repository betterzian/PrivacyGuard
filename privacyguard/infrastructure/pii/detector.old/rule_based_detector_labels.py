"""Shared field label specifications for text and OCR detection."""

from __future__ import annotations

from dataclasses import dataclass
import re

from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    PIIAttributeType,
    _ADDRESS_FIELD_KEYWORDS,
    _BANK_ACCOUNT_FIELD_KEYWORDS,
    _CARD_FIELD_KEYWORDS,
    _DRIVER_LICENSE_FIELD_KEYWORDS,
    _EMAIL_FIELD_KEYWORDS,
    _ID_FIELD_KEYWORDS,
    _NAME_FAMILY_FIELD_KEYWORDS,
    _NAME_FIELD_KEYWORDS,
    _NAME_GIVEN_FIELD_KEYWORDS,
    _NAME_MIDDLE_FIELD_KEYWORDS,
    _ORGANIZATION_FIELD_KEYWORDS,
    _OTHER_FIELD_KEYWORDS,
    _PASSPORT_FIELD_KEYWORDS,
    _PHONE_FIELD_KEYWORDS,
    _TEXT_MASK_CHAR_CLASS,
    _MASK_CHAR_CLASS_COMMON,
    _MASK_CHAR_CLASS_WITH_X,
    _ADDRESS_MASK_CHAR_CLASS,
)


@dataclass(frozen=True, slots=True)
class _FieldLabelSpec:
    attr_type: PIIAttributeType
    context_matched_by: str
    ocr_matched_by: str
    keywords: tuple[str, ...]
    value_pattern: str
    validator_name: str
    name_component: str | None = None
    context_confidence: float = 0.9
    ocr_confidence: float = 0.96
    include_in_context_rules: bool = True


_FIELD_LABEL_DECORATION_PATTERN = re.compile(r"[\s:：=*_?？!！,，.。;；/\\|｜()\[\]{}<>《》【】\"'`·•_\-]+")
_FIELD_LABEL_INLINE_CONNECTOR_PATTERN = r"(?:[:：=]|是|为|is|was|at)?"

_FIELD_LABEL_SPECS = (
    _FieldLabelSpec(
        attr_type=PIIAttributeType.NAME,
        context_matched_by="context_name_family_field",
        ocr_matched_by="ocr_label_name_family_field",
        keywords=_NAME_FAMILY_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z][A-Za-z'\- ]{{0,40}}|[一-龥·]{{1,4}}|{_TEXT_MASK_CHAR_CLASS}{{1,4}}",
        validator_name="_is_family_name_candidate",
        name_component="family",
        context_confidence=0.92,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.NAME,
        context_matched_by="context_name_given_field",
        ocr_matched_by="ocr_label_name_given_field",
        keywords=_NAME_GIVEN_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z][A-Za-z'\- ]{{0,40}}|[一-龥·]{{1,6}}|{_TEXT_MASK_CHAR_CLASS}{{1,6}}",
        validator_name="_is_given_name_candidate",
        name_component="given",
        context_confidence=0.92,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.NAME,
        context_matched_by="context_name_middle_field",
        ocr_matched_by="ocr_label_name_middle_field",
        keywords=_NAME_MIDDLE_FIELD_KEYWORDS,
        value_pattern=r"[A-Za-z][A-Za-z'\- ]{0,40}",
        validator_name="_is_middle_name_candidate",
        name_component="middle",
        context_confidence=0.9,
        ocr_confidence=0.97,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.NAME,
        context_matched_by="context_name_field",
        ocr_matched_by="ocr_label_name_field",
        keywords=_NAME_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z][A-Za-z .'\-]{{1,40}}|[一-龥·\s0-9]{{2,12}}|[一-龥][*＊xX某]{{1,3}}|{_TEXT_MASK_CHAR_CLASS}{{2,12}}",
        validator_name="_is_name_candidate",
        name_component="full",
        context_confidence=0.9,
        ocr_confidence=0.97,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.ADDRESS,
        context_matched_by="context_address_field",
        ocr_matched_by="ocr_label_address_field",
        keywords=_ADDRESS_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z0-9#\-－—()（）·\s一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{2,80}}",
        validator_name="_label_address_value_shape_ok",
        context_confidence=0.9,
        ocr_confidence=0.86,
        include_in_context_rules=False,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.PHONE,
        context_matched_by="context_phone_field",
        ocr_matched_by="ocr_label_phone_field",
        keywords=_PHONE_FIELD_KEYWORDS,
        value_pattern=rf"[0-9*＊+＋\-－—_.,，。·•/\\()（）\s{_MASK_CHAR_CLASS_WITH_X[1:-1]}]{{7,32}}",
        validator_name="_is_context_phone_candidate",
        context_confidence=0.88,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.CARD_NUMBER,
        context_matched_by="context_card_field",
        ocr_matched_by="ocr_label_card_field",
        keywords=_CARD_FIELD_KEYWORDS,
        value_pattern=rf"[0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{13,40}}",
        validator_name="_is_context_card_number_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.BANK_ACCOUNT,
        context_matched_by="context_bank_account_field",
        ocr_matched_by="ocr_label_bank_account_field",
        keywords=_BANK_ACCOUNT_FIELD_KEYWORDS,
        value_pattern=rf"[0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{8,40}}",
        validator_name="_is_bank_account_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.PASSPORT_NUMBER,
        context_matched_by="context_passport_field",
        ocr_matched_by="ocr_label_passport_field",
        keywords=_PASSPORT_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{5,24}}",
        validator_name="_is_passport_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.DRIVER_LICENSE,
        context_matched_by="context_driver_license_field",
        ocr_matched_by="ocr_label_driver_license_field",
        keywords=_DRIVER_LICENSE_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z0-9Xx*＊\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{8,32}}",
        validator_name="_is_driver_license_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.EMAIL,
        context_matched_by="context_email_field",
        ocr_matched_by="ocr_label_email_field",
        keywords=_EMAIL_FIELD_KEYWORDS,
        value_pattern=rf"[A-Za-z0-9._%+\-*＊@＠,，。．、·•\s{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{5,80}}",
        validator_name="_is_email_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.ID_NUMBER,
        context_matched_by="context_id_field",
        ocr_matched_by="ocr_label_id_field",
        keywords=_ID_FIELD_KEYWORDS,
        value_pattern=rf"[0-9Xx*＊\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{6,40}}",
        validator_name="_is_id_candidate",
        context_confidence=0.9,
        ocr_confidence=0.98,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.OTHER,
        context_matched_by="context_other_field",
        ocr_matched_by="ocr_label_other_field",
        keywords=_OTHER_FIELD_KEYWORDS,
        value_pattern=r"[A-Za-z0-9一-龥\-\s－—_.,，。·•:：/\\()（）]{4,40}",
        validator_name="_is_other_candidate",
        context_confidence=0.76,
        ocr_confidence=0.88,
    ),
    _FieldLabelSpec(
        attr_type=PIIAttributeType.ORGANIZATION,
        context_matched_by="context_organization_field",
        ocr_matched_by="ocr_label_organization_field",
        keywords=_ORGANIZATION_FIELD_KEYWORDS,
        value_pattern=r"[A-Za-z0-9&()（）·\s一-龥]{2,80}",
        validator_name="_is_context_organization_candidate",
        context_confidence=0.86,
        ocr_confidence=0.88,
    ),
)

_FIELD_LABEL_SPEC_LOOKUP: dict[str, tuple[_FieldLabelSpec, ...]] = {}
_FIELD_LABEL_INLINE_PATTERNS: dict[tuple[str, str], re.Pattern[str]] = {}
_FIELD_LABEL_PURE_PATTERNS: dict[tuple[str, str], re.Pattern[str]] = {}
for _spec in _FIELD_LABEL_SPECS:
    for _keyword in _spec.keywords:
        _normalized_keyword = re.sub(_FIELD_LABEL_DECORATION_PATTERN, "", str(_keyword or "").strip().lower())
        if _normalized_keyword:
            _FIELD_LABEL_SPEC_LOOKUP[_normalized_keyword] = _FIELD_LABEL_SPEC_LOOKUP.get(_normalized_keyword, tuple()) + (_spec,)
        _escaped = re.escape(_keyword)
        _FIELD_LABEL_INLINE_PATTERNS[(_spec.context_matched_by, _keyword)] = re.compile(
            rf"^\s*(?P<label>{_escaped})\s*{_FIELD_LABEL_INLINE_CONNECTOR_PATTERN}\s*(?P<value>.+?)\s*$",
            re.IGNORECASE,
        )
        _FIELD_LABEL_PURE_PATTERNS[(_spec.context_matched_by, _keyword)] = re.compile(
            rf"^\s*(?P<label>{_escaped})[\s:：=*_?？!！,，.。;；/\\|｜()\[\]{{}}<>《》【】\"'`·•_\-]*$",
            re.IGNORECASE,
        )


def _normalize_field_label_token(value: str) -> str:
    return _FIELD_LABEL_DECORATION_PATTERN.sub("", str(value or "").strip().lower())


def _field_label_specs() -> tuple[_FieldLabelSpec, ...]:
    return _FIELD_LABEL_SPECS


def _field_label_specs_for_token(value: str) -> tuple[_FieldLabelSpec, ...]:
    normalized = _normalize_field_label_token(value)
    if not normalized:
        return ()
    return _FIELD_LABEL_SPEC_LOOKUP.get(normalized, ())


def _match_pure_field_labels(value: str) -> tuple[_FieldLabelSpec, ...]:
    text = str(value or "")
    normalized = _normalize_field_label_token(text)
    if not normalized:
        return ()
    matches: list[_FieldLabelSpec] = []
    for spec in _FIELD_LABEL_SPEC_LOOKUP.get(normalized, ()):
        for keyword in spec.keywords:
            if _FIELD_LABEL_PURE_PATTERNS[(spec.context_matched_by, keyword)].match(text):
                matches.append(spec)
                break
    return tuple(dict.fromkeys(matches))


def _match_inline_field_labels(value: str) -> tuple[tuple[_FieldLabelSpec, str, int], ...]:
    text = str(value or "")
    matches: list[tuple[_FieldLabelSpec, str, int, int]] = []
    for spec in _FIELD_LABEL_SPECS:
        for keyword in sorted(spec.keywords, key=len, reverse=True):
            pure_pattern = _FIELD_LABEL_PURE_PATTERNS[(spec.context_matched_by, keyword)]
            if pure_pattern.match(text):
                continue
            pattern = _FIELD_LABEL_INLINE_PATTERNS[(spec.context_matched_by, keyword)]
            match = pattern.match(text)
            if match is None:
                continue
            label_value = match.group("value").strip()
            if not label_value:
                continue
            matches.append((spec, label_value, match.start("value"), len(keyword)))
    deduped: list[tuple[_FieldLabelSpec, str, int]] = []
    seen: set[tuple[str, int]] = set()
    for spec, label_value, start_offset, keyword_len in sorted(matches, key=lambda item: (-item[3], item[2], item[0].context_matched_by)):
        key = (spec.context_matched_by, start_offset)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((spec, label_value, start_offset))
    return tuple(deduped)


__all__ = [
    "_FieldLabelSpec",
    "_field_label_specs",
    "_field_label_specs_for_token",
    "_match_pure_field_labels",
    "_match_inline_field_labels",
    "_normalize_field_label_token",
]
