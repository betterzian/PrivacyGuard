"""候选构造与启发式判断。"""

from __future__ import annotations

import re
from enum import Enum

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK, _OCR_INLINE_GAP_TOKEN


class NameComponentHint(str, Enum):
    """姓名候选的成分提示，用于验证逻辑。从 ClueRole 推导而来。"""
    FULL = "full"
    FAMILY = "family"
    GIVEN = "given"
    ALIAS = "alias"
    MIDDLE = "middle"

_ORG_SUFFIX_RE = re.compile(
    r"(?i)(股份有限公司|有限责任公司|有限公司|研究院|实验室|工作室|事务所|集团|公司|大学|学院|银行|酒店|医院|中心"
    r"|incorporated|corporation|company|limited|inc\.?|corp\.?|co\.?|ltd\.?|llc|plc|gmbh|pte|university|college|bank|hotel|hospital|clinic|labs?)"
)
_ADDRESS_SIGNAL_RE = re.compile(
    r"(?i)(省|市|区|县|旗|镇|乡|村|路|街|道|巷|弄|小区|公寓|大厦|园区|花园|家园|苑|庭|府|湾|宿舍|栋|幢|座|楼|单元|层|室|房|户"
    r"|street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct|suite|ste|apt|unit|zip)"
)
_LEADING_ADDRESS_LABEL_RE = re.compile(r"^(?:收货地址|家庭住址|联系地址|住址|地址)\s*[:：]?\s*")
_NAME_PRONOUNS = {
    "he", "him", "she", "her", "they", "them", "we", "us", "you", "me", "i", "myself", "pronouns",
}
_NAME_BLOCKLIST_ZH = {"本人", "未知", "匿名", "姓名", "名字"}
_EN_NAME_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z.'\-]{0,30}$")
_ZH_NAME_RE = re.compile(r"^[\u4e00-\u9fff·]{2,8}$")


def build_name_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    component_hint: NameComponentHint,
    unit_start: int = 0,
    unit_end: int = 0,
    label_clue_id: str | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _clean_value(value_text)
    if not _is_plausible_name(cleaned, component_hint=component_hint):
        return None
    offset = value_text.find(cleaned)
    return CandidateDraft(
        attr_type=PIIAttributeType.NAME,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        unit_start=unit_start,
        unit_end=unit_end,
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": [source_kind], "name_component": [component_hint.value]},
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def build_organization_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    unit_start: int = 0,
    unit_end: int = 0,
    label_clue_id: str | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _strip_leading_address_label(_clean_value(value_text))
    if not _is_plausible_organization(cleaned, label_driven=label_driven):
        return None
    offset = value_text.find(cleaned)
    return CandidateDraft(
        attr_type=PIIAttributeType.ORGANIZATION,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        unit_start=unit_start,
        unit_end=unit_end,
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": [source_kind]},
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def build_address_candidate_from_value(
    *,
    source,
    value_text: str,
    value_start: int,
    value_end: int,
    source_kind: str,
    unit_start: int = 0,
    unit_end: int = 0,
    label_clue_id: str | None = None,
    metadata: dict[str, list[str]] | None = None,
    label_driven: bool = False,
) -> CandidateDraft | None:
    del value_end
    cleaned = _clean_value(value_text)
    if not cleaned:
        return None
    offset = value_text.find(cleaned)
    candidate_metadata = {"matched_by": [source_kind], "address_kind": ["private_address"]}
    if metadata:
        candidate_metadata = merge_metadata(candidate_metadata, metadata)
    return CandidateDraft(
        attr_type=PIIAttributeType.ADDRESS,
        start=value_start + max(0, offset),
        end=value_start + max(0, offset) + len(cleaned),
        unit_start=unit_start,
        unit_end=unit_end,
        text=cleaned,
        source=source,
        source_kind=source_kind,
        claim_strength=ClaimStrength.SOFT,
        metadata=candidate_metadata,
        label_clue_ids={label_clue_id} if label_clue_id else set(),
        label_driven=label_driven,
    )


def trim_candidate(
    candidate: CandidateDraft,
    raw_text: str,
    *,
    start: int,
    end: int,
    unit_start: int | None = None,
    unit_end: int | None = None,
) -> CandidateDraft | None:
    if start >= end:
        return None
    segment = raw_text[start:end]
    next_unit_start = candidate.unit_start if unit_start is None else unit_start
    next_unit_end = candidate.unit_end if unit_end is None else unit_end
    metadata_base = candidate.metadata
    if candidate.attr_type == PIIAttributeType.NAME:
        rebuilt = build_name_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            component_hint=name_component_hint(candidate),
            unit_start=next_unit_start,
            unit_end=next_unit_end,
            label_driven=candidate.label_driven,
        )
    elif candidate.attr_type == PIIAttributeType.ORGANIZATION:
        rebuilt = build_organization_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            unit_start=next_unit_start,
            unit_end=next_unit_end,
            label_driven=candidate.label_driven,
        )
    elif candidate.attr_type == PIIAttributeType.ADDRESS:
        metadata_base = {
            key: values
            for key, values in candidate.metadata.items()
            if not key.startswith("address_component") and not key.startswith("address_details")
        }
        rebuilt = build_address_candidate_from_value(
            source=candidate.source,
            value_text=segment,
            value_start=start,
            value_end=end,
            source_kind=candidate.source_kind,
            unit_start=next_unit_start,
            unit_end=next_unit_end,
            metadata=merge_metadata(metadata_base, {"address_match_origin": ["trimmed"]}),
            label_driven=candidate.label_driven,
        )
    else:
        rebuilt = None
    if rebuilt is None:
        return None
    rebuilt.claim_strength = candidate.claim_strength
    rebuilt.metadata = merge_metadata(metadata_base, rebuilt.metadata)
    rebuilt.label_clue_ids = set(candidate.label_clue_ids)
    rebuilt.label_driven = candidate.label_driven
    return rebuilt


def has_organization_suffix(text: str) -> bool:
    return _ORG_SUFFIX_RE.search(str(text or "")) is not None


def organization_suffix_start(text: str) -> int:
    match = _ORG_SUFFIX_RE.search(text)
    return match.start() if match else -1


def has_address_signal(text: str) -> bool:
    return _ADDRESS_SIGNAL_RE.search(str(text or "")) is not None


def looks_like_name_value(text: str, *, component_hint: NameComponentHint = NameComponentHint.FULL) -> bool:
    return _is_plausible_name(_clean_value(text), component_hint=component_hint)


def looks_like_organization_value(text: str, *, label_driven: bool = False) -> bool:
    return _is_plausible_organization(_strip_leading_address_label(_clean_value(text)), label_driven=label_driven)


def name_component_hint(candidate: CandidateDraft) -> NameComponentHint:
    values = candidate.metadata.get("name_component")
    return NameComponentHint(str(values[0])) if values else NameComponentHint.FULL


def clean_value(text: str) -> str:
    return _clean_value(text)


def _clean_value(text: str) -> str:
    cleaned = str(text or "")
    cleaned = cleaned.replace(_OCR_INLINE_GAP_TOKEN, " ")
    cleaned = cleaned.replace(OCR_BREAK, " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" \t\r\n:：-—|,，;；/\\")
    cleaned = re.sub(r"[。！!？?]+$", "", cleaned).strip()
    return cleaned


def _is_plausible_name(text: str, *, component_hint: NameComponentHint) -> bool:
    if not text or len(text) > 80 or "@" in text:
        return False
    if any(char.isdigit() for char in text):
        return False
    compact_lower = re.sub(r"\s+", " ", text).strip().lower()
    if compact_lower in _NAME_PRONOUNS or text in _NAME_BLOCKLIST_ZH:
        return False
    compact_no_space = re.sub(r"\s+", "", text)
    if _ZH_NAME_RE.fullmatch(compact_no_space):
        return True
    tokens = [token for token in re.split(r"\s+", text) if token]
    if component_hint in {NameComponentHint.FAMILY, NameComponentHint.GIVEN, NameComponentHint.ALIAS, NameComponentHint.MIDDLE}:
        return len(tokens) == 1 and _EN_NAME_TOKEN_RE.fullmatch(tokens[0]) is not None
    return 1 <= len(tokens) <= 4 and all(_EN_NAME_TOKEN_RE.fullmatch(token) is not None for token in tokens)


def _is_plausible_organization(text: str, *, label_driven: bool) -> bool:
    if not text or len(text) < 2 or len(text) > 120 or "@" in text:
        return False
    if _ADDRESS_SIGNAL_RE.search(text) and not _ORG_SUFFIX_RE.search(text):
        return False
    if label_driven:
        return True
    return _ORG_SUFFIX_RE.search(text) is not None


def _strip_leading_address_label(text: str) -> str:
    stripped = str(text or "")
    while True:
        updated = _LEADING_ADDRESS_LABEL_RE.sub("", stripped, count=1)
        if updated == stripped:
            return stripped
        stripped = updated.strip()


__all__ = [
    "build_address_candidate_from_value",
    "build_name_candidate_from_value",
    "build_organization_candidate_from_value",
    "clean_value",
    "has_address_signal",
    "has_organization_suffix",
    "looks_like_name_value",
    "looks_like_organization_value",
    "name_component_hint",
    "organization_suffix_start",
    "trim_candidate",
]
