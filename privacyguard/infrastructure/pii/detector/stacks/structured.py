"""统一结构化属性 stack。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, ClueRole, DictionaryEntry
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun, _build_value_candidate
from privacyguard.infrastructure.pii.detector.stacks.common import is_control_clue
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break

_LOOKUP_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.BANK_NUMBER: "<bank>",
    PIIAttributeType.PASSPORT_NUMBER: "<passport>",
    PIIAttributeType.DRIVER_LICENSE: "<driver_license>",
}

_ID_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CN_CHECK_CODES = "10X98765432"

_ValidatorEntry = tuple[PIIAttributeType, int, str]


def _luhn_valid(digits: str) -> bool:
    """标准 Luhn 校验。"""
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


def _luhn_valid_wide(digits: str) -> bool:
    """宽范围 Luhn 校验。"""
    if not digits.isdigit() or not (12 <= len(digits) <= 22):
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


def _validate_cn_phone(digits: str) -> bool:
    return len(digits) == 11 and digits[0] == "1" and digits[1] in "3456789"


def _validate_us_phone(digits: str) -> bool:
    return len(digits) == 10 and digits[0] in "23456789"


def _validate_cn_id_18(text: str) -> bool:
    if len(text) != 18:
        return False
    body = text[:17]
    if not body.isdigit():
        return False
    check = text[17].upper()
    total = sum(int(body[i]) * _ID_CN_WEIGHTS[i] for i in range(17))
    expected = _ID_CN_CHECK_CODES[total % 11]
    if check != expected:
        return False
    month = int(text[10:12])
    day = int(text[12:14])
    return 1 <= month <= 12 and 1 <= day <= 31


def _validate_cn_id_15(digits: str) -> bool:
    if len(digits) != 15 or not digits.isdigit():
        return False
    month = int(digits[8:10])
    day = int(digits[10:12])
    return 1 <= month <= 12 and 1 <= day <= 31


def _route_validators(*, digits: str, text: str, fragment_type: str) -> _ValidatorEntry | None:
    """按数值形态升级为明确的结构化属性。"""
    if fragment_type != "NUM" or not digits:
        return None

    hits: list[_ValidatorEntry] = []
    n = len(digits)
    if n == 11 and _validate_cn_phone(digits):
        hits.append((PIIAttributeType.PHONE, 118, "validated_phone_cn"))
    if n == 10 and _validate_us_phone(digits):
        hits.append((PIIAttributeType.PHONE, 117, "validated_phone_us"))
    if n == 18 or (len(text) == 18 and text[:17].isdigit() and text[17].upper() == "X"):
        id_text = text if len(text) == 18 else digits
        if _validate_cn_id_18(id_text):
            hits.append((PIIAttributeType.ID_NUMBER, 115, "validated_id_cn_18"))
    if n == 15 and _validate_cn_id_15(digits):
        hits.append((PIIAttributeType.ID_NUMBER, 113, "validated_id_cn_15"))
    if 13 <= n <= 19 and _luhn_valid(digits):
        hits.append((PIIAttributeType.BANK_NUMBER, 114, "validated_bank_number_pan"))
    if 12 <= n <= 22 and _luhn_valid_wide(digits):
        hits.append((PIIAttributeType.BANK_NUMBER, 110, "validated_bank_number_account"))
    if not hits:
        return None
    hits.sort(key=lambda item: -item[1])
    return hits[0]


def _hard_source_for_entry(entry: DictionaryEntry) -> str:
    if entry.matched_by == "dictionary_session":
        return "session"
    return "local"


class StructuredStack(BaseStack):
    """统一处理 STRUCTURED family 的明确值、通用片段与标签绑定。"""

    def run(self) -> StackRun | None:
        if self.clue.strength == ClaimStrength.HARD:
            if self.clue.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}:
                return self._run_fragment()
            return self._build_direct_run()

        if self.clue.role == ClueRole.LABEL:
            return self._try_label_bind()

        return None

    def _run_fragment(self) -> StackRun | None:
        candidate = self._resolve_fragment_candidate(self.clue)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
        )

    def _resolve_fragment_candidate(self, clue) -> CandidateDraft:
        metadata = dict(clue.source_metadata)
        fragment_type = self._fragment_type(clue)
        pure_digits = (metadata.get("pure_digits") or [re.sub(r"\D", "", clue.text)])[0]

        candidate = _build_value_candidate(clue, self.context.stream.source)
        entry = self._lookup_dictionary_entry(clue.text, fragment_type, pure_digits)
        if entry is not None:
            candidate.attr_type = entry.attr_type
            candidate.source_kind = entry.matched_by
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {
                    **{key: list(values) for key, values in entry.metadata.items()},
                    "matched_by": [entry.matched_by],
                    "hard_source": [_hard_source_for_entry(entry)],
                    "placeholder": [_LOOKUP_PLACEHOLDER_BY_ATTR.get(entry.attr_type, f"<{entry.attr_type.value}>")],
                    "original_fragment_type": [fragment_type],
                },
            )
            return candidate

        result = _route_validators(digits=pure_digits, text=clue.text, fragment_type=fragment_type)
        if result is not None:
            attr_type, _priority, source_kind = result
            candidate.attr_type = attr_type
            candidate.source_kind = source_kind
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"validated_by": [source_kind], "original_fragment_type": [fragment_type]},
            )
        return candidate

    def _try_label_bind(self) -> StackRun | None:
        raw_text = self.context.stream.text
        cursor = self.clue.end
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if is_control_clue(clue):
                cursor = max(cursor, clue.end)
                continue
            gap_text = raw_text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return None
            if clue.role == ClueRole.LABEL:
                return None
            if clue.strength == ClaimStrength.HARD and clue.role == ClueRole.VALUE:
                candidate = self._resolve_fragment_candidate(clue) if clue.attr_type in {
                    PIIAttributeType.NUMERIC,
                    PIIAttributeType.ALNUM,
                } else _build_value_candidate(clue, self.context.stream.source)
                if (
                    candidate.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}
                    and self.clue.attr_type is not None
                ):
                    candidate.attr_type = self.clue.attr_type
                    candidate.metadata = merge_metadata(
                        candidate.metadata,
                        {"assigned_by_label_attr": [self.clue.attr_type.value]},
                    )
                candidate.label_clue_ids.add(self.clue.clue_id)
                candidate.metadata = merge_metadata(
                    candidate.metadata,
                    {"bound_label_clue_ids": [self.clue.clue_id]},
                )
                return StackRun(
                    attr_type=candidate.attr_type,
                    candidate=candidate,
                    consumed_ids={self.clue.clue_id, clue.clue_id},
                    handled_label_clue_ids={self.clue.clue_id},
                    next_index=index + 1,
                )
            cursor = max(cursor, clue.end)
        return None

    def _lookup_dictionary_entry(self, text: str, fragment_type: str, digits: str) -> DictionaryEntry | None:
        index = self.context.structured_lookup_index
        if fragment_type == "NUM":
            key = digits
            if key:
                return index.numeric_entries.get(key)
            return None
        key = re.sub(r"[^0-9A-Za-z]", "", text or "").upper()
        if key:
            return index.alnum_entries.get(key)
        return None

    def _fragment_type(self, clue) -> str:
        metadata = dict(clue.source_metadata)
        if metadata.get("fragment_type"):
            return str(metadata["fragment_type"][0]).upper()
        if clue.attr_type == PIIAttributeType.ALNUM:
            return "ALNUM"
        return "NUM"
