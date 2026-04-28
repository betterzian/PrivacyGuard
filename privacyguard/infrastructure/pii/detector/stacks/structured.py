"""统一结构化属性 stack。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, ClueRole, DictionaryEntry
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun, _build_value_candidate
from privacyguard.infrastructure.pii.detector.structured_validators import (
    normalize_structured_digits_for_phone,
    route_structured_validators,
)

# detector 主路径允许产出的 attr_type 集合；persona 精匹配可额外产出 PASSPORT/DRIVER。
ALLOWED_DETECTOR_OUTPUT_ATTRS = frozenset({
    PIIAttributeType.NAME,
    PIIAttributeType.PHONE,
    PIIAttributeType.BANK_NUMBER,
    PIIAttributeType.ID_NUMBER,
    PIIAttributeType.LICENSE_PLATE,
    PIIAttributeType.EMAIL,
    PIIAttributeType.ADDRESS,
    PIIAttributeType.DETAILS,
    PIIAttributeType.ORGANIZATION,
    PIIAttributeType.TIME,
    PIIAttributeType.AMOUNT,
    PIIAttributeType.NUM,
    PIIAttributeType.ALNUM,
})
PERSONA_ONLY_ATTRS = frozenset({
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
})
_NUMBERISH_LABEL_ATTRS = frozenset({
    PIIAttributeType.PHONE,
    PIIAttributeType.ID_NUMBER,
    PIIAttributeType.BANK_NUMBER,
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
})
_LABEL_BIND_FRAGMENT_TYPES = frozenset({"NUM", "ALNUM"})

_LOOKUP_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.BANK_NUMBER: "<bank>",
    PIIAttributeType.LICENSE_PLATE: "<license_plate>",
    PIIAttributeType.AMOUNT: "<amount>",
}


def _hard_source_for_entry(entry: DictionaryEntry) -> str:
    if entry.matched_by == "dictionary_session":
        return "session"
    return "local"


class StructuredStack(BaseStack):
    """统一处理 STRUCTURED family 的明确值、通用片段与标签绑定。"""

    def run(self) -> StackRun | None:
        if self.clue.role != ClueRole.VALUE or self.clue.strength != ClaimStrength.HARD:
            return None
        if self.clue.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
            return self._run_fragment()
        return self._build_direct_run()

    def _run_fragment(self) -> StackRun | None:
        candidate = self._resolve_fragment_candidate(self.clue)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            frontier_last_unit=candidate.unit_last,
        )

    def _resolve_fragment_candidate(self, clue) -> CandidateDraft:
        metadata = dict(clue.source_metadata)
        fragment_type = self._fragment_type(clue)
        pure_digits = (metadata.get("pure_digits") or [re.sub(r"\D", "", clue.text)])[0]
        pure_digits = normalize_structured_digits_for_phone(pure_digits, metadata=metadata)
        phone_region = str((metadata.get("phone_region") or [""])[0]).strip().lower() or None

        candidate = _build_value_candidate(clue, self.context.stream.source)
        entry = self._lookup_dictionary_entry(clue.text, fragment_type, pure_digits)
        if entry is not None:
            candidate.attr_type = entry.attr_type
            candidate.source_kind = entry.matched_by
            # persona/本地词典的精匹配被视为高可信出口，锁定 attr_type，
            # 避免下游 label 或启发式再次改写。
            if entry.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
                candidate.attr_locked = True
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

        result = route_structured_validators(
            digits=pure_digits,
            text=clue.text,
            fragment_type=fragment_type,
            phone_region=phone_region,
        )
        if result is not None:
            attr_type, source_kind = result
            candidate.attr_type = attr_type
            candidate.source_kind = source_kind
            # H 档 validator 命中直接锁定 attr_type。
            candidate.attr_locked = True
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"validated_by": [source_kind], "original_fragment_type": [fragment_type]},
            )
            candidate = self._try_label_bind(candidate, fragment_type=fragment_type)
        return candidate

    def _try_label_bind(self, candidate: CandidateDraft, *, fragment_type: str) -> CandidateDraft:
        """读取 parser 维护的最近结构化锚点，决定绑定还是退化。"""
        anchor = self.context.recent_structured_anchor
        if anchor is None:
            return candidate
        distance = self.clue.unit_start - anchor.unit_last
        if distance < 0 or distance > 5:
            return candidate
        anchor_clue = self.context.clues[anchor.clue_index]
        if anchor_clue.attr_type is None:
            return candidate
        normalized_fragment_type = str(fragment_type or "").upper()
        if (
            anchor_clue.attr_type in _NUMBERISH_LABEL_ATTRS
            and normalized_fragment_type not in _LABEL_BIND_FRAGMENT_TYPES
        ):
            # 号类 label 只承认 scanner 产出的 NUM / ALNUM 片段。
            return candidate
        if anchor_clue.attr_type == candidate.attr_type:
            candidate.label_clue_ids.add(anchor_clue.clue_id)
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"bound_label_clue_ids": [anchor_clue.clue_id]},
            )
            return candidate
        candidate.attr_type = PIIAttributeType.ALNUM if normalized_fragment_type == "ALNUM" else PIIAttributeType.NUM
        candidate.source_kind = self.clue.source_kind
        candidate.attr_locked = False
        candidate.metadata = merge_metadata(
            candidate.metadata,
            {"label_attr_mismatch": [anchor_clue.attr_type.value]},
        )
        return candidate

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

