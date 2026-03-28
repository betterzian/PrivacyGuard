from __future__ import annotations

from dataclasses import dataclass, field
import re

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.key_value_canonical import address_key_value_canonical_from_zh
from privacyguard.infrastructure.pii.address.pipeline import collect_address_candidates
from privacyguard.infrastructure.pii.rule_based_detector_labels import (
    _FieldLabelSpec,
    _field_label_specs,
    _match_inline_field_labels,
    _match_pure_field_labels,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _COMMON_COMPOUND_SURNAMES,
    _COMMON_SINGLE_CHAR_SURNAMES,
    _NAME_HONORIFICS,
    _OCRPairGeometry,
    _OCR_SEMANTIC_BREAK_TOKEN,
)
from privacyguard.infrastructure.pii.stream_ocr import OCRStreamDocument, build_ocr_stream_document, remap_ocr_span
from privacyguard.utils.pii_value import build_match_text, canonicalize_pii_value, dictionary_match_variants

_LABEL_LEADING_DELIMITERS = frozenset(" \t\r\n{[(" + "（【<「『\"',，;；/\\|｜")
_LABEL_CONNECTOR_PATTERN = re.compile(r"^\s*(?::|：|=|是|为|is|was|at)?\s*", re.IGNORECASE)
_HARD_VALUE_STOP_PATTERN = re.compile(r"[\n\r;；。！？!?]")
_LABEL_ATTR_PRIORITY = {
    PIIAttributeType.EMAIL: 100,
    PIIAttributeType.PHONE: 96,
    PIIAttributeType.ID_NUMBER: 94,
    PIIAttributeType.CARD_NUMBER: 92,
    PIIAttributeType.BANK_ACCOUNT: 90,
    PIIAttributeType.PASSPORT_NUMBER: 88,
    PIIAttributeType.DRIVER_LICENSE: 86,
    PIIAttributeType.NAME: 80,
    PIIAttributeType.ORGANIZATION: 72,
    PIIAttributeType.ADDRESS: 64,
    PIIAttributeType.OTHER: 40,
}
_PROPOSAL_SOURCE_PRIORITY = {
    "label": 90,
    "organization_event": 76,
    "address_event": 72,
    "name_self_intro": 68,
    "name_title": 64,
    "name_generic": 56,
}
_NAME_SELF_INTRO_PATTERNS = (
    (re.compile(r"(?:我叫|名叫|叫做|我的名字是)\s*(?P<value>[一-龥·\s]{2,8})"), "context_name_self_intro", 0.84),
    (
        re.compile(
            r"(?:my\s+name\s+is|i\s+am|i'm|this\s+is)\s*(?P<value>[A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){0,2})",
            re.IGNORECASE,
        ),
        "context_name_self_intro_en",
        0.76,
    ),
)
_EN_NAME_TITLE_PATTERN = re.compile(
    r"(?P<value>(?:mr|mrs|ms|miss|dr|prof)\.?\s+[A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){0,2})",
    re.IGNORECASE,
)
_EN_STANDALONE_NAME_PATTERN = re.compile(
    r"(?<![A-Za-z])(?P<value>[A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){1,2})(?![A-Za-z])"
)


@dataclass(frozen=True, slots=True)
class HardSeed:
    attr_type: PIIAttributeType
    start: int
    end: int
    text: str
    matched_by: str
    confidence: float
    priority: int
    placeholder: str
    canonical_source_text: str | None = None
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LabelEvent:
    spec: _FieldLabelSpec
    keyword: str
    start: int
    end: int
    value_start: int
    priority: int


@dataclass(frozen=True, slots=True)
class ReplacementSpan:
    modified_start: int
    modified_end: int
    raw_start: int
    raw_end: int
    attr_type: PIIAttributeType


@dataclass(frozen=True, slots=True)
class ModifiedText:
    text: str
    modified_to_raw: tuple[int | None, ...]
    replacements: tuple[ReplacementSpan, ...]

    def modified_span_to_raw(self, start: int, end: int) -> tuple[int, int] | None:
        covered = [
            index
            for index in self.modified_to_raw[max(0, start) : min(len(self.modified_to_raw), end)]
            if index is not None
        ]
        if covered:
            return min(covered), max(covered) + 1
        for replacement in self.replacements:
            if replacement.modified_start <= start and end <= replacement.modified_end:
                return replacement.raw_start, replacement.raw_end
        return None

    def next_replacement(self, start: int, *, max_gap: int = 4) -> ReplacementSpan | None:
        for replacement in self.replacements:
            if replacement.modified_start < start:
                continue
            gap = self.text[start:replacement.modified_start]
            if len(gap) > max_gap:
                return None
            if gap and gap.strip():
                return None
            return replacement
        return None


@dataclass(frozen=True, slots=True)
class StrongRegexRule:
    attr_type: PIIAttributeType
    pattern: re.Pattern[str]
    matched_by: str
    confidence: float
    priority: int
    placeholder: str


@dataclass(frozen=True, slots=True)
class CandidateProposal:
    attr_type: PIIAttributeType
    start: int
    end: int
    text: str
    source: PIISourceType
    bbox: object
    block_id: str | None
    confidence: float
    matched_by: str
    canonical_source_text: str | None = None
    metadata: dict[str, list[str]] = field(default_factory=dict)
    claim_source: str = "label"
    claim_priority: int = 0
    label_start: int | None = None
    label_end: int | None = None


@dataclass(slots=True)
class ProposalStack:
    proposal: CandidateProposal
    score: float
    state: str = "active"


@dataclass(frozen=True, slots=True)
class OCRLabelAnchor:
    spec: _FieldLabelSpec
    block_index: int
    label_text: str
    inline_value: str | None = None
    inline_span: tuple[int, int] | None = None


_STRONG_REGEX_RULES = (
    StrongRegexRule(PIIAttributeType.EMAIL, re.compile(r"[A-Za-z0-9._%+\-]+(?:\s*[@＠]\s*[A-Za-z0-9.\-]+\s*(?:\.|[，。．、·•])\s*[A-Za-z]{2,})"), "regex_email", 0.95, 140, " <EMAIL> "),
    StrongRegexRule(PIIAttributeType.ID_NUMBER, re.compile(r"(?<![A-Za-z0-9])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![A-Za-z0-9])"), "regex_id_number", 0.96, 135, " <ID> "),
    StrongRegexRule(PIIAttributeType.PHONE, re.compile(r"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•()（）]?\d{4}){2}(?!\d)"), "regex_phone", 0.92, 130, " <PHONE> "),
    StrongRegexRule(PIIAttributeType.PHONE, re.compile(r"(?<!\w)(?:\+?1[\s\-._()]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s\-._()]*[2-9]\d{2}[\s\-._()]*\d{4}(?!\w)"), "regex_phone_us", 0.91, 129, " <PHONE> "),
    StrongRegexRule(PIIAttributeType.CARD_NUMBER, re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){13,19}(?![A-Za-z0-9])"), "regex_card_number", 0.86, 124, " <CARD> "),
    StrongRegexRule(PIIAttributeType.BANK_ACCOUNT, re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){10,30}(?![A-Za-z0-9])"), "regex_bank_account", 0.83, 120, " <ACCOUNT> "),
    StrongRegexRule(PIIAttributeType.PASSPORT_NUMBER, re.compile(r"(?<![A-Z0-9])[A-Z][\s\-－—_.,，。·•]?\d(?:[\s\-－—_.,，。·•]?\d){7,8}(?![A-Z0-9])", re.IGNORECASE), "regex_passport_number", 0.84, 118, " <PASSPORT> "),
    StrongRegexRule(PIIAttributeType.DRIVER_LICENSE, re.compile(r"(?<![A-Za-z0-9])\d{12,15}(?![A-Za-z0-9])"), "regex_driver_license", 0.8, 115, " <LICENSE> "),
)


class UnifiedStreamDetectorEngine:
    def __init__(self, detector) -> None:
        self.owner = detector
        self.runtime = detector.runtime
        self.detector = self.runtime

    def detect_text(
        self,
        raw_text: str,
        *,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        session_entries,
        local_entries,
        rule_profile,
    ) -> list[PIICandidate]:
        if not raw_text:
            return []

        collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
        hard_seeds = self._collect_hard_seeds(raw_text, session_entries=session_entries, local_entries=local_entries)
        hard_claims = [(seed.attr_type, seed.start, seed.end) for seed in hard_seeds]
        for seed in hard_seeds:
            self.detector._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=seed.text,
                attr_type=seed.attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=seed.start,
                span_end=seed.end,
                confidence=seed.confidence,
                matched_by=seed.matched_by,
                canonical_source_text=seed.canonical_source_text,
                metadata=seed.metadata or None,
            )

        modified = _build_modified_text(raw_text, hard_seeds)
        label_events = _find_label_events(modified.text)
        try:
            self._set_standalone_context(raw_text, tuple(collected.values()))
            self._bind_label_events_to_hard_candidates(
                collected=collected,
                modified=modified,
                events=label_events,
                source=source,
            )
            proposals: list[CandidateProposal] = []
            proposals.extend(self._collect_label_proposals(raw_text=raw_text, modified=modified, events=label_events, source=source, bbox=bbox, block_id=block_id))
            proposals.extend(self._collect_address_and_org_proposals(raw_text=raw_text, modified=modified, source=source, bbox=bbox, block_id=block_id, rule_profile=rule_profile, skip_spans=[(seed.start, seed.end) for seed in hard_seeds]))
            self._set_standalone_context(raw_text, tuple(collected.values()) + tuple(self._proposal_as_candidate(item) for item in proposals))
            proposals.extend(self._collect_name_proposals(raw_text=raw_text, modified=modified, source=source, bbox=bbox, block_id=block_id, rule_profile=rule_profile, skip_spans=[(seed.start, seed.end) for seed in hard_seeds]))
            finalized = self._parse_proposals(proposals, hard_claims=hard_claims)
            self._set_standalone_context(raw_text, tuple(collected.values()) + tuple(self._proposal_as_candidate(item) for item in finalized))
            for proposal in finalized:
                self._upsert_proposal_candidate(collected=collected, raw_text=raw_text, proposal=proposal)
            return [candidate for candidate in collected.values() if self.detector._meets_confidence_threshold(candidate.attr_type, candidate.confidence, rule_profile)]
        finally:
            self._clear_standalone_context()

    def detect_ocr(self, ocr_blocks, *, session_entries, local_entries, rule_profile) -> list[PIICandidate]:
        document = build_ocr_stream_document(ocr_blocks)
        if document is None:
            return []
        self.detector._active_ocr_page_document = document.page_document
        self.detector._active_ocr_scene_index = document.scene_index
        try:
            combined_candidates = self.detect_text(
                document.text,
                source=PIISourceType.OCR,
                bbox=None,
                block_id=None,
                session_entries=session_entries,
                local_entries=local_entries,
                rule_profile=rule_profile,
            )
            remapped = self._remap_ocr_candidates(document, combined_candidates)
            final_by_key = {_candidate_location_key(candidate): candidate for candidate in remapped}
            for candidate in self._collect_ocr_spatial_label_candidates(document, remapped):
                final_by_key[_candidate_location_key(candidate)] = candidate
            return list(final_by_key.values())
        finally:
            self.detector._active_ocr_page_document = None
            self.detector._active_ocr_scene_index = None

    def _collect_hard_seeds(self, raw_text: str, *, session_entries, local_entries) -> list[HardSeed]:
        seeds: list[HardSeed] = []
        seeds.extend(self._collect_regex_seeds(raw_text))
        seeds.extend(self._collect_dictionary_seeds(raw_text, session_entries, priority=150))
        seeds.extend(self._collect_dictionary_seeds(raw_text, local_entries, priority=145))
        return _select_non_overlapping_hard_seeds(seeds)

    def _collect_regex_seeds(self, raw_text: str) -> list[HardSeed]:
        seeds: list[HardSeed] = []
        for rule in _STRONG_REGEX_RULES:
            for match in rule.pattern.finditer(raw_text):
                cleaner = self.detector._clean_phone_candidate if rule.attr_type == PIIAttributeType.PHONE else None
                extracted = self.detector._extract_match(raw_text, match.start(), match.end(), cleaner=cleaner)
                if extracted is None:
                    continue
                value, start, end = extracted
                if not self._seed_validator(rule.attr_type, value):
                    continue
                seeds.append(HardSeed(rule.attr_type, start, end, value, rule.matched_by, rule.confidence, rule.priority, rule.placeholder))
        return seeds

    def _collect_dictionary_seeds(self, raw_text: str, entries_by_attr, *, priority: int) -> list[HardSeed]:
        if not entries_by_attr:
            return []
        seeds: dict[tuple[PIIAttributeType, int, int], HardSeed] = {}
        for attr_type, entries in entries_by_attr.items():
            raw_match_text, index_map = build_match_text(attr_type, raw_text)
            if not raw_match_text:
                continue
            for entry in entries:
                variants = set(dictionary_match_variants(attr_type, entry.value))
                for alias in getattr(entry, "aliases", ()) or ():
                    variants.update(dictionary_match_variants(attr_type, alias))
                for variant in sorted(variants, key=len, reverse=True):
                    if not variant:
                        continue
                    cursor = 0
                    while True:
                        position = raw_match_text.find(variant, cursor)
                        if position < 0:
                            break
                        raw_start = index_map[position]
                        raw_end = index_map[position + len(variant) - 1] + 1
                        key = (attr_type, raw_start, raw_end)
                        seed = HardSeed(attr_type, raw_start, raw_end, raw_text[raw_start:raw_end], entry.matched_by, entry.confidence, priority, _placeholder_for_attr(attr_type), entry.canonical_source_text, dict(entry.metadata))
                        previous = seeds.get(key)
                        if previous is None or seed.confidence >= previous.confidence:
                            seeds[key] = seed
                        cursor = position + len(variant)
        return sorted(seeds.values(), key=lambda item: (item.start, item.end))

    def _bind_label_events_to_hard_candidates(self, *, collected, modified: ModifiedText, events: list[LabelEvent], source: PIISourceType) -> None:
        for event in events:
            existing = modified.next_replacement(event.value_start)
            if existing is not None:
                self._bind_label_to_existing_candidate(collected, event, existing, source=source)

    def _bind_label_to_existing_candidate(self, collected, event: LabelEvent, replacement: ReplacementSpan, *, source: PIISourceType) -> bool:
        compatible = replacement.attr_type == event.spec.attr_type
        if not compatible and {replacement.attr_type, event.spec.attr_type} <= {PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}:
            compatible = True
        if not compatible:
            return False
        candidate = _find_candidate_by_span(collected, attr_type=replacement.attr_type, span_start=replacement.raw_start, span_end=replacement.raw_end)
        if candidate is None:
            return False
        matched_by = _event_matched_by(event, source)
        candidate.metadata = self.detector._merge_candidate_metadata(candidate.metadata, _event_metadata(event, matched_by=matched_by))
        candidate.confidence = min(1.0, max(candidate.confidence, event.spec.ocr_confidence if source == PIISourceType.OCR else event.spec.context_confidence))
        return True

    def _collect_label_proposals(self, *, raw_text: str, modified: ModifiedText, events: list[LabelEvent], source: PIISourceType, bbox: object, block_id: str | None) -> list[CandidateProposal]:
        proposals: list[CandidateProposal] = []
        for event in events:
            existing = modified.next_replacement(event.value_start)
            if existing is not None:
                compatible = existing.attr_type == event.spec.attr_type
                if not compatible and {existing.attr_type, event.spec.attr_type} <= {PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}:
                    compatible = True
                if compatible:
                    continue
            proposal = self._build_label_proposal(raw_text=raw_text, modified=modified, event=event, source=source, bbox=bbox, block_id=block_id)
            if proposal is not None:
                proposals.append(proposal)
        return proposals

    def _build_label_proposal(self, *, raw_text: str, modified: ModifiedText, event: LabelEvent, source: PIISourceType, bbox: object, block_id: str | None) -> CandidateProposal | None:
        raw_span = self._label_value_raw_span(modified, event)
        if raw_span is None:
            return None
        cleaner = None
        if event.spec.attr_type == PIIAttributeType.PHONE:
            cleaner = self.detector._clean_phone_candidate
        elif event.spec.attr_type == PIIAttributeType.ORGANIZATION:
            cleaner = self.detector._clean_organization_candidate
        elif event.spec.attr_type == PIIAttributeType.ADDRESS:
            cleaner = self.detector._clean_address_candidate
        extracted = self.detector._extract_match(raw_text, raw_span[0], raw_span[1], cleaner=cleaner)
        if extracted is None:
            return None
        value, span_start, span_end = extracted
        if source == PIISourceType.OCR and _span_is_internal_ocr_break(raw_text, span_start, span_end):
            return None
        validator = _validator_for_spec(self.detector, event.spec, source=source)
        if not validator(value):
            return None
        canonical_source_text = None
        if event.spec.attr_type == PIIAttributeType.NAME:
            canonical_source_text = _canonical_name_for_spec(self.detector, event.spec, value, source=source)
            if canonical_source_text is None:
                return None
        elif event.spec.attr_type == PIIAttributeType.ORGANIZATION:
            canonical_source_text = canonicalize_pii_value(PIIAttributeType.ORGANIZATION, value)
        elif event.spec.attr_type == PIIAttributeType.ADDRESS:
            canonical_source_text = address_key_value_canonical_from_zh(value)
        confidence = event.spec.ocr_confidence if source == PIISourceType.OCR else event.spec.context_confidence
        if event.spec.attr_type == PIIAttributeType.ORGANIZATION:
            confidence = max(confidence, self.detector._organization_confidence(value, allow_weak_suffix=True))
        matched_by = _event_matched_by(event, source)
        return CandidateProposal(
            attr_type=event.spec.attr_type,
            start=span_start,
            end=span_end,
            text=value,
            source=source,
            bbox=bbox,
            block_id=block_id,
            confidence=confidence,
            matched_by=matched_by,
            canonical_source_text=canonical_source_text,
            metadata=_event_metadata(event, matched_by=matched_by),
            claim_source="label",
            claim_priority=self._proposal_priority("label", event.spec.attr_type, matched_by),
            label_start=event.start,
            label_end=event.end,
        )

    def _label_value_raw_span(self, modified: ModifiedText, event: LabelEvent) -> tuple[int, int] | None:
        slice_start, slice_end = _label_value_window(modified.text, event.value_start)
        if slice_end <= slice_start:
            return None
        pattern = re.compile(event.spec.value_pattern, re.IGNORECASE)
        for match in pattern.finditer(modified.text, slice_start, slice_end):
            if match.end() > match.start():
                return modified.modified_span_to_raw(match.start(), match.end())
        return None

    def _collect_address_and_org_proposals(self, *, raw_text: str, modified: ModifiedText, source: PIISourceType, bbox: object, block_id: str | None, rule_profile, skip_spans: list[tuple[int, int]]) -> list[CandidateProposal]:
        temp_collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
        collect_address_candidates(
            self.detector,
            temp_collected,
            modified.text,
            source,
            bbox,
            block_id,
            skip_spans=skip_spans,
            rule_profile=rule_profile,
            original_text=raw_text,
            shadow_index_map=modified.modified_to_raw,
        )
        proposals: list[CandidateProposal] = []
        for candidate in temp_collected.values():
            proposal = self._proposal_from_candidate(candidate)
            if proposal is not None:
                proposals.append(proposal)
        return proposals

    def _collect_name_proposals(self, *, raw_text: str, modified: ModifiedText, source: PIISourceType, bbox: object, block_id: str | None, rule_profile, skip_spans: list[tuple[int, int]]) -> list[CandidateProposal]:
        proposals: list[CandidateProposal] = []
        local_skip_spans = list(skip_spans)
        for pattern, matched_by, confidence in _NAME_SELF_INTRO_PATTERNS:
            for match in pattern.finditer(modified.text):
                raw_span = modified.modified_span_to_raw(*match.span("value"))
                if raw_span is None:
                    continue
                extracted = self.detector._extract_match(raw_text, raw_span[0], raw_span[1])
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if source == PIISourceType.OCR and _span_is_internal_ocr_break(raw_text, span_start, span_end):
                    continue
                if self.detector._overlaps_any_span(span_start, span_end, local_skip_spans):
                    continue
                canonical = self.detector._canonical_name_source_text(value, allow_ocr_noise=source == PIISourceType.OCR)
                if canonical is None:
                    continue
                proposals.append(CandidateProposal(PIIAttributeType.NAME, span_start, span_end, value, source, bbox, block_id, confidence, matched_by, canonical, {"matched_by": [matched_by]}, "name_self_intro", self._proposal_priority("name_self_intro", PIIAttributeType.NAME, matched_by)))
                local_skip_spans.append((span_start, span_end))
        for pattern, matched_by, base_confidence in _name_title_patterns():
            for match in pattern.finditer(modified.text):
                raw_span = modified.modified_span_to_raw(*match.span("value"))
                if raw_span is None:
                    continue
                extracted = self.detector._extract_match(raw_text, raw_span[0], raw_span[1])
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if source == PIISourceType.OCR and _span_is_internal_ocr_break(raw_text, span_start, span_end):
                    continue
                if self.detector._overlaps_any_span(span_start, span_end, local_skip_spans) or not self.detector._looks_like_name_with_title(value):
                    continue
                canonical = self.detector._canonical_name_source_text(value, allow_ocr_noise=source == PIISourceType.OCR)
                if canonical is None:
                    continue
                proposals.append(CandidateProposal(PIIAttributeType.NAME, span_start, span_end, value, source, bbox, block_id, base_confidence, matched_by, canonical, {"matched_by": [matched_by]}, "name_title", self._proposal_priority("name_title", PIIAttributeType.NAME, matched_by)))
                local_skip_spans.append((span_start, span_end))
        for pattern, matched_by in _generic_name_patterns():
            for match in pattern.finditer(modified.text):
                raw_span = modified.modified_span_to_raw(*match.span("value"))
                if raw_span is None:
                    continue
                extracted = self.detector._extract_match(raw_text, raw_span[0], raw_span[1])
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if source == PIISourceType.OCR and _span_is_internal_ocr_break(raw_text, span_start, span_end):
                    continue
                if self.detector._overlaps_any_span(span_start, span_end, local_skip_spans):
                    continue
                if matched_by == "heuristic_name_fragment_en":
                    confidence = self.detector._standalone_name_confidence(raw_text, span_start, span_end, value=value, source=source, rule_profile=rule_profile)
                else:
                    confidence = self.detector._generic_name_confidence(raw_text, span_start, span_end, value=value, source=source, rule_profile=rule_profile)
                if confidence <= 0.0:
                    continue
                canonical = self.detector._canonical_name_source_text(value, allow_ocr_noise=source == PIISourceType.OCR)
                if canonical is None:
                    continue
                proposals.append(CandidateProposal(PIIAttributeType.NAME, span_start, span_end, value, source, bbox, block_id, confidence, matched_by, canonical, {"matched_by": [matched_by]}, "name_generic", self._proposal_priority("name_generic", PIIAttributeType.NAME, matched_by)))
                local_skip_spans.append((span_start, span_end))
        return proposals

    def _proposal_from_candidate(self, candidate: PIICandidate) -> CandidateProposal | None:
        if candidate.span_start is None or candidate.span_end is None:
            return None
        matched_by_values = candidate.metadata.get("matched_by", [])
        matched_by = matched_by_values[0] if matched_by_values else "stream"
        claim_source = "label"
        if candidate.attr_type in {PIIAttributeType.ADDRESS, PIIAttributeType.DETAILS}:
            claim_source = "address_event"
        elif candidate.attr_type == PIIAttributeType.ORGANIZATION:
            claim_source = "organization_event"
        return CandidateProposal(
            attr_type=candidate.attr_type,
            start=candidate.span_start,
            end=candidate.span_end,
            text=candidate.text,
            source=candidate.source,
            bbox=candidate.bbox,
            block_id=candidate.block_id,
            confidence=candidate.confidence,
            matched_by=matched_by,
            canonical_source_text=candidate.canonical_source_text,
            metadata=dict(candidate.metadata),
            claim_source=claim_source,
            claim_priority=self._proposal_priority(claim_source, candidate.attr_type, matched_by),
        )

    def _proposal_priority(self, claim_source: str, attr_type: PIIAttributeType, matched_by: str) -> int:
        base = _PROPOSAL_SOURCE_PRIORITY.get(claim_source, 48)
        base += int(_LABEL_ATTR_PRIORITY.get(attr_type, 0) / 10)
        if matched_by.startswith("regex_organization_suffix"):
            base += 4
        elif matched_by.startswith("context_"):
            base += 2
        return base

    def _proposal_score(self, proposal: CandidateProposal) -> float:
        score = float(proposal.claim_priority)
        score += proposal.confidence * 20.0
        score += min(6.0, max(0.0, proposal.end - proposal.start) * 0.15)
        if proposal.label_start is not None:
            score += 2.0
        if proposal.claim_source == "organization_event" and proposal.matched_by.startswith("regex_organization_suffix"):
            score += 3.0
        if proposal.claim_source == "name_self_intro":
            score += 2.0
        return score

    def _parse_proposals(self, proposals: list[CandidateProposal], *, hard_claims: list[tuple[PIIAttributeType, int, int]]) -> list[CandidateProposal]:
        if not proposals:
            return []
        deduped: dict[tuple[PIIAttributeType, int, int, str, str], CandidateProposal] = {}
        for proposal in proposals:
            key = (proposal.attr_type, proposal.start, proposal.end, proposal.claim_source, proposal.text)
            previous = deduped.get(key)
            deduped[key] = proposal if previous is None else self._merged_proposal(previous, proposal)
        ordered = sorted(deduped.values(), key=lambda item: (item.start, -self._proposal_score(item), -(item.end - item.start), item.attr_type.value))
        by_start: dict[int, list[CandidateProposal]] = {}
        for proposal in ordered:
            by_start.setdefault(proposal.start, []).append(proposal)
        active: list[ProposalStack] = []
        finalized: list[CandidateProposal] = []
        for position in sorted(by_start):
            active, flushed = self._flush_completed_stacks(active, position)
            finalized.extend(flushed)
            for proposal in sorted(by_start[position], key=lambda item: (self._proposal_score(item), item.claim_priority, item.confidence, item.end - item.start), reverse=True):
                if self._proposal_blocked_by_hard_claim(proposal, hard_claims):
                    continue
                incoming = ProposalStack(proposal=proposal, score=self._proposal_score(proposal))
                rejected = False
                retained: list[ProposalStack] = []
                for current in active:
                    if current.state != "active":
                        continue
                    if not self._stacks_compete(current, incoming):
                        retained.append(current)
                        continue
                    decision = self._resolve_stack_conflict(current, incoming)
                    if decision == "replace":
                        current.state = "rejected"
                        continue
                    if decision == "merge_existing":
                        current.proposal = self._merged_proposal(current.proposal, incoming.proposal)
                        current.score = self._proposal_score(current.proposal)
                        retained.append(current)
                        rejected = True
                        continue
                    if decision == "merge_new":
                        incoming.proposal = self._merged_proposal(incoming.proposal, current.proposal)
                        incoming.score = self._proposal_score(incoming.proposal)
                        current.state = "rejected"
                        continue
                    retained.append(current)
                    rejected = True
                active = [item for item in retained if item.state == "active"]
                if not rejected:
                    active.append(incoming)
                    active.sort(key=lambda item: (item.proposal.end, -item.score, item.proposal.start))
        finalized.extend(self._finalize_active_stacks(active))
        resolved: list[CandidateProposal] = []
        for proposal in sorted(finalized, key=lambda item: (item.start, -self._proposal_score(item), -(item.end - item.start), item.attr_type.value)):
            if self._proposal_blocked_by_hard_claim(proposal, hard_claims):
                continue
            kept = True
            for index, accepted in enumerate(resolved):
                if accepted.end <= proposal.start or proposal.end <= accepted.start:
                    continue
                kept = False
                if accepted.attr_type == proposal.attr_type:
                    resolved[index] = self._merged_proposal(accepted, proposal)
                    break
                if self._proposal_score(proposal) > self._proposal_score(accepted) + 2.5:
                    resolved[index] = proposal
                break
            if kept:
                resolved.append(proposal)
        return sorted(resolved, key=lambda item: (item.start, item.end, item.attr_type.value))

    def _flush_completed_stacks(self, active: list[ProposalStack], position: int) -> tuple[list[ProposalStack], list[CandidateProposal]]:
        remaining: list[ProposalStack] = []
        completed: list[CandidateProposal] = []
        for stack in active:
            if stack.state != "active":
                continue
            if stack.proposal.end <= position:
                completed.append(stack.proposal)
            else:
                remaining.append(stack)
        return remaining, completed

    def _finalize_active_stacks(self, active: list[ProposalStack]) -> list[CandidateProposal]:
        return [stack.proposal for stack in active if stack.state == "active"]

    def _proposal_blocked_by_hard_claim(self, proposal: CandidateProposal, hard_claims: list[tuple[PIIAttributeType, int, int]]) -> bool:
        for _, start, end in hard_claims:
            if proposal.end <= start or proposal.start >= end:
                continue
            return True
        return False

    def _stacks_compete(self, current: ProposalStack, incoming: ProposalStack) -> bool:
        return not (current.proposal.end <= incoming.proposal.start or incoming.proposal.end <= current.proposal.start)

    def _resolve_stack_conflict(self, current: ProposalStack, incoming: ProposalStack) -> str:
        if current.proposal.attr_type == incoming.proposal.attr_type:
            if self._proposal_score(incoming.proposal) > self._proposal_score(current.proposal) + 1.5:
                return "merge_new"
            return "merge_existing"
        if self._proposal_score(incoming.proposal) > self._proposal_score(current.proposal) + 2.5:
            return "replace"
        return "reject_new"

    def _merged_proposal(self, left: CandidateProposal, right: CandidateProposal) -> CandidateProposal:
        keep = left if self._proposal_score(left) >= self._proposal_score(right) else right
        return CandidateProposal(
            attr_type=keep.attr_type,
            start=keep.start,
            end=keep.end,
            text=keep.text,
            source=keep.source,
            bbox=keep.bbox,
            block_id=keep.block_id,
            confidence=max(left.confidence, right.confidence),
            matched_by=keep.matched_by,
            canonical_source_text=keep.canonical_source_text or left.canonical_source_text or right.canonical_source_text,
            metadata=self.detector._merge_candidate_metadata(left.metadata, right.metadata),
            claim_source=keep.claim_source,
            claim_priority=max(left.claim_priority, right.claim_priority),
            label_start=keep.label_start if keep.label_start is not None else left.label_start if left.label_start is not None else right.label_start,
            label_end=keep.label_end if keep.label_end is not None else left.label_end if left.label_end is not None else right.label_end,
        )

    def _proposal_as_candidate(self, proposal: CandidateProposal) -> PIICandidate:
        normalized = canonicalize_pii_value(proposal.attr_type, proposal.text)
        entity_id = self.detector.resolver.build_candidate_id(self.detector.detector_mode, proposal.source.value, normalized, proposal.attr_type.value, block_id=proposal.block_id, span_start=proposal.start, span_end=proposal.end)
        return PIICandidate(entity_id=entity_id, text=proposal.text, canonical_source_text=proposal.canonical_source_text, normalized_text=normalized, attr_type=proposal.attr_type, source=proposal.source, bbox=proposal.bbox, block_id=proposal.block_id, span_start=proposal.start, span_end=proposal.end, confidence=proposal.confidence, metadata=dict(proposal.metadata))

    def _upsert_proposal_candidate(self, *, collected, raw_text: str, proposal: CandidateProposal) -> None:
        self.detector._upsert_candidate(collected=collected, text=raw_text, matched_text=proposal.text, attr_type=proposal.attr_type, source=proposal.source, bbox=proposal.bbox, block_id=proposal.block_id, span_start=proposal.start, span_end=proposal.end, confidence=proposal.confidence, matched_by=proposal.matched_by, canonical_source_text=proposal.canonical_source_text, metadata=proposal.metadata or None)

    def _remap_ocr_candidates(self, document: OCRStreamDocument, combined_candidates: list[PIICandidate]) -> list[PIICandidate]:
        remapped: list[PIICandidate] = []
        for candidate in combined_candidates:
            mapping = remap_ocr_span(document, candidate.span_start, candidate.span_end)
            candidate_copy = candidate.model_copy(deep=True)
            candidate_copy.bbox = mapping.bbox
            candidate_copy.block_id = mapping.block_id
            candidate_copy.span_start = mapping.span_start
            candidate_copy.span_end = mapping.span_end
            if mapping.block_ids:
                candidate_copy.metadata = self.detector._merge_candidate_metadata(candidate_copy.metadata, {"ocr_block_ids": list(mapping.block_ids)})
            remapped.append(candidate_copy)
        return remapped

    def _collect_ocr_spatial_label_candidates(self, document: OCRStreamDocument, existing_candidates: list[PIICandidate]) -> list[PIICandidate]:
        results: list[PIICandidate] = []
        occupied = {_candidate_location_key(candidate) for candidate in existing_candidates}
        anchors = self._collect_ocr_label_anchors(document)
        for anchor in anchors:
            if self._bind_ocr_anchor_to_existing_candidate(document, anchor, [*existing_candidates, *results]):
                continue
            candidate = self._build_ocr_candidate_from_anchor(document, anchor)
            if candidate is None:
                continue
            key = _candidate_location_key(candidate)
            if key in occupied:
                self._bind_ocr_anchor_to_existing_candidate(document, anchor, [*existing_candidates, *results])
                continue
            occupied.add(key)
            results.append(candidate)
        return results

    def _collect_ocr_label_anchors(self, document: OCRStreamDocument) -> list[OCRLabelAnchor]:
        anchors: list[OCRLabelAnchor] = []
        for block_index, block in enumerate(document.blocks):
            if not str(block.text or "").strip():
                continue
            for spec, inline_value, start_offset in _match_inline_field_labels(block.text):
                anchors.append(OCRLabelAnchor(spec=spec, block_index=block_index, label_text=block.text.strip(), inline_value=inline_value, inline_span=(start_offset, len(block.text))))
            for spec in _match_pure_field_labels(block.text):
                anchors.append(OCRLabelAnchor(spec=spec, block_index=block_index, label_text=block.text.strip()))
        return anchors

    def _bind_ocr_anchor_to_existing_candidate(self, document: OCRStreamDocument, anchor: OCRLabelAnchor, candidates: list[PIICandidate]) -> bool:
        best: tuple[PIICandidate, float] | None = None
        for candidate in candidates:
            score = self._ocr_anchor_candidate_score(document, anchor, candidate)
            if score is None:
                continue
            if best is None or score > best[1]:
                best = (candidate, score)
        if best is None:
            return False
        candidate, score = best
        label_block = document.blocks[anchor.block_index]
        metadata: dict[str, list[str]] = {"matched_by": [anchor.spec.ocr_matched_by], "field_label_keyword": [anchor.label_text], "ocr_postpass": ["label_bind"]}
        if label_block.block_id:
            metadata["ocr_label_block_ids"] = [label_block.block_id]
        if anchor.spec.name_component:
            metadata["name_component"] = [anchor.spec.name_component]
        candidate.metadata = self.detector._merge_candidate_metadata(candidate.metadata, metadata)
        candidate.confidence = min(1.0, max(candidate.confidence, min(0.99, score * 0.32 + anchor.spec.ocr_confidence * 0.68)))
        return True

    def _ocr_anchor_candidate_score(self, document: OCRStreamDocument, anchor: OCRLabelAnchor, candidate: PIICandidate) -> float | None:
        if not self._ocr_attr_compatible(anchor.spec.attr_type, candidate.attr_type):
            return None
        block_indices = self._candidate_ocr_block_indices(document, candidate)
        if not block_indices:
            return None
        if anchor.inline_span is not None and len(block_indices) == 1 and block_indices[0] == anchor.block_index and candidate.span_start is not None and candidate.span_start >= anchor.inline_span[0]:
            return 1.0
        best_score: float | None = None
        for block_index in block_indices:
            score = self._score_ocr_label_right_neighbor(document.scene_index, anchor.block_index, block_index, anchor.spec)
            if score is None:
                score = self._score_ocr_label_down_neighbor(document.scene_index, anchor.block_index, block_index, anchor.spec)
            if score is not None and (best_score is None or score > best_score):
                best_score = score
        if best_score is None:
            return None
        if candidate.attr_type == PIIAttributeType.DETAILS and anchor.spec.attr_type == PIIAttributeType.ADDRESS:
            best_score += 0.04
        return best_score

    def _ocr_attr_compatible(self, label_attr: PIIAttributeType, candidate_attr: PIIAttributeType) -> bool:
        if label_attr == candidate_attr:
            return True
        if {label_attr, candidate_attr} <= {PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}:
            return True
        if label_attr == PIIAttributeType.ADDRESS and candidate_attr in {PIIAttributeType.ADDRESS, PIIAttributeType.DETAILS}:
            return True
        return False

    def _candidate_ocr_block_indices(self, document: OCRStreamDocument, candidate: PIICandidate) -> tuple[int, ...]:
        block_ids = tuple(dict.fromkeys([*candidate.metadata.get("ocr_block_ids", []), *candidate.metadata.get("ocr_label_block_ids", []), candidate.block_id]))
        if not block_ids:
            return ()
        index_by_block_id = {block.block_id: index for index, block in enumerate(document.blocks) if block.block_id is not None}
        return tuple(dict.fromkeys(index_by_block_id[block_id] for block_id in block_ids if block_id in index_by_block_id))

    def _build_ocr_candidate_from_anchor(self, document: OCRStreamDocument, anchor: OCRLabelAnchor) -> PIICandidate | None:
        candidates: list[PIICandidate] = []
        if anchor.inline_value:
            block_indices = (anchor.block_index,)
            value_text = anchor.inline_value
            if anchor.spec.attr_type == PIIAttributeType.NAME:
                block_indices, value_text = self._maybe_extend_ocr_name_value(document, block_indices, value_text)
            inline_span = anchor.inline_span if len(block_indices) == 1 else None
            direct = self._build_ocr_direct_candidate(document=document, spec=anchor.spec, value_text=value_text, block_indices=block_indices, inline_span=inline_span)
            if direct is not None:
                candidates.append(self._decorate_ocr_anchor_candidate(document, anchor, direct, relation_score=1.0))
        right_option = self._collect_ocr_right_value_chain(document, anchor.block_index, anchor.spec)
        if right_option is not None:
            block_indices, relation_score = right_option
            value_text = self._join_ocr_block_text(document, block_indices)
            if anchor.inline_value:
                value_text = _join_fragments(anchor.inline_value, value_text)
                block_indices = (anchor.block_index, *block_indices)
            if anchor.spec.attr_type == PIIAttributeType.NAME:
                block_indices, value_text = self._maybe_extend_ocr_name_value(document, block_indices, value_text)
            candidate = self._build_ocr_direct_candidate(document=document, spec=anchor.spec, value_text=value_text, block_indices=tuple(dict.fromkeys(block_indices)), inline_span=None)
            if candidate is not None:
                candidates.append(self._decorate_ocr_anchor_candidate(document, anchor, candidate, relation_score=relation_score))
        down_option = self._collect_ocr_down_value_chain(document, anchor.block_index, anchor.spec)
        if down_option is not None:
            block_indices, relation_score = down_option
            value_text = self._join_ocr_block_text(document, block_indices)
            if anchor.inline_value:
                value_text = _join_fragments(anchor.inline_value, value_text)
                block_indices = (anchor.block_index, *block_indices)
            if anchor.spec.attr_type == PIIAttributeType.NAME:
                block_indices, value_text = self._maybe_extend_ocr_name_value(document, block_indices, value_text)
            candidate = self._build_ocr_direct_candidate(document=document, spec=anchor.spec, value_text=value_text, block_indices=tuple(dict.fromkeys(block_indices)), inline_span=None)
            if candidate is not None:
                candidates.append(self._decorate_ocr_anchor_candidate(document, anchor, candidate, relation_score=relation_score))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item.confidence, len(item.metadata.get("ocr_block_ids", [])), -(item.bbox.y if item.bbox is not None else 0)), reverse=True)
        return candidates[0]

    def _decorate_ocr_anchor_candidate(self, document: OCRStreamDocument, anchor: OCRLabelAnchor, candidate: PIICandidate, *, relation_score: float) -> PIICandidate:
        enriched = candidate.model_copy(deep=True)
        label_block = document.blocks[anchor.block_index]
        metadata: dict[str, list[str]] = {"matched_by": [anchor.spec.ocr_matched_by], "field_label_keyword": [anchor.label_text], "ocr_postpass": ["label_value_search"], "ocr_relation_score": [f"{relation_score:.3f}"]}
        if label_block.block_id:
            metadata["ocr_label_block_ids"] = [label_block.block_id]
        if anchor.spec.name_component:
            metadata["name_component"] = [anchor.spec.name_component]
        enriched.metadata = self.detector._merge_candidate_metadata(enriched.metadata, metadata)
        enriched.confidence = min(1.0, max(enriched.confidence, min(0.99, anchor.spec.ocr_confidence * 0.72 + relation_score * 0.28)))
        return enriched

    def _collect_ocr_right_value_chain(self, document: OCRStreamDocument, label_block_index: int, spec: _FieldLabelSpec) -> tuple[tuple[int, ...], float] | None:
        position = document.scene_index.position_by_block_index.get(label_block_index)
        label_block = document.blocks[label_block_index]
        if position is None or label_block.bbox is None:
            return None
        line_index, item_index = position
        line = document.scene_index.lines[line_index]
        best_anchor: tuple[int, float] | None = None
        for next_block_index in line[item_index + 1 :]:
            block = document.blocks[next_block_index]
            if _match_pure_field_labels(block.text):
                break
            score = self._score_ocr_label_right_neighbor(document.scene_index, label_block_index, next_block_index, spec)
            if score is not None and (best_anchor is None or score > best_anchor[1]):
                best_anchor = (next_block_index, score)
        if best_anchor is None:
            return None
        continuation_blocks, continuation_score = self._collect_ocr_same_line_continuation(document, anchor_block_index=best_anchor[0], spec=spec)
        block_indices = (best_anchor[0], *continuation_blocks)
        relation_score = best_anchor[1] if continuation_score is None else best_anchor[1] * 0.7 + continuation_score * 0.3
        return tuple(dict.fromkeys(block_indices)), relation_score

    def _collect_ocr_down_value_chain(self, document: OCRStreamDocument, label_block_index: int, spec: _FieldLabelSpec) -> tuple[tuple[int, ...], float] | None:
        position = document.scene_index.position_by_block_index.get(label_block_index)
        label_block = document.blocks[label_block_index]
        if position is None or label_block.bbox is None:
            return None
        line_index, _ = position
        best_anchor: tuple[int, float] | None = None
        for next_line_index in range(line_index + 1, min(len(document.scene_index.lines), line_index + 5)):
            line = document.scene_index.lines[next_line_index]
            if not line:
                continue
            if _match_pure_field_labels(document.blocks[line[0]].text):
                break
            for candidate_index in line:
                block = document.blocks[candidate_index]
                if _match_pure_field_labels(block.text):
                    continue
                score = self._score_ocr_label_down_neighbor(document.scene_index, label_block_index, candidate_index, spec)
                if score is not None and (best_anchor is None or score > best_anchor[1]):
                    best_anchor = (candidate_index, score)
            if best_anchor is not None:
                break
        if best_anchor is None:
            return None
        continuation_blocks, continuation_score = self._collect_ocr_same_line_continuation(document, anchor_block_index=best_anchor[0], spec=spec)
        block_indices = (best_anchor[0], *continuation_blocks)
        relation_score = best_anchor[1] if continuation_score is None else best_anchor[1] * 0.68 + continuation_score * 0.32
        return tuple(dict.fromkeys(block_indices)), relation_score

    def _collect_ocr_same_line_continuation(self, document: OCRStreamDocument, *, anchor_block_index: int, spec: _FieldLabelSpec) -> tuple[tuple[int, ...], float | None]:
        position = document.scene_index.position_by_block_index.get(anchor_block_index)
        if position is None:
            return (), None
        line_index, item_index = position
        line = document.scene_index.lines[line_index]
        collected: list[int] = []
        scores: list[float] = []
        previous_block_index = anchor_block_index
        for next_block_index in line[item_index + 1 :]:
            block = document.blocks[next_block_index]
            if _match_pure_field_labels(block.text):
                break
            if self._score_ocr_label_value_block(block, spec) is None:
                break
            successor_score = self._score_horizontal_successor_by_index(document.scene_index, previous_block_index, next_block_index)
            if successor_score is None or successor_score < 0.34:
                break
            collected.append(next_block_index)
            scores.append(successor_score)
            previous_block_index = next_block_index
        if not scores:
            return tuple(collected), None
        return tuple(collected), sum(scores) / len(scores)

    def _score_ocr_label_value_block(self, block, spec: _FieldLabelSpec) -> float | None:
        cleaned = self.detector._clean_extracted_value(block.text)
        if not cleaned:
            return None
        if _match_pure_field_labels(block.text):
            return None
        if len(cleaned) <= 2 and re.fullmatch(r"[\W_?？!！·•]+", cleaned):
            return None
        if spec.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION} and self.detector._looks_like_ui_time_metadata(cleaned):
            return None
        if spec.attr_type == PIIAttributeType.NAME:
            if self.detector._is_ui_operation_name_token(cleaned):
                return None
            alpha_or_cjk = sum(1 for char in cleaned if char.isalpha() or self.detector._is_cjk_char(char))
            return None if alpha_or_cjk == 0 else min(1.0, 0.6 + alpha_or_cjk * 0.08)
        if spec.attr_type in {PIIAttributeType.PHONE, PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT, PIIAttributeType.ID_NUMBER}:
            digit_count = sum(char.isdigit() for char in cleaned)
            return None if digit_count < 4 else min(1.0, 0.58 + digit_count * 0.04)
        if spec.attr_type == PIIAttributeType.EMAIL:
            return 1.0 if "@" in cleaned else 0.52
        if spec.attr_type == PIIAttributeType.ADDRESS:
            alpha_or_cjk = sum(1 for char in cleaned if char.isalpha() or self.detector._is_cjk_char(char))
            if alpha_or_cjk == 0 and not any(char.isdigit() for char in cleaned):
                return None
            return min(1.0, 0.52 + 0.02 * min(24, len(cleaned)))
        if spec.attr_type == PIIAttributeType.ORGANIZATION:
            score = self.detector._organization_confidence(cleaned, allow_weak_suffix=True)
            return score if score > 0 else 0.5
        return 0.6

    def _score_ocr_label_right_neighbor(self, scene_index, label_block_index: int, value_block_index: int, spec: _FieldLabelSpec) -> float | None:
        geometry = self._ocr_pair_geometry(scene_index, label_block_index, value_block_index, direction="right")
        if geometry is None:
            return None
        label_block = scene_index.blocks[label_block_index]
        value_block = scene_index.blocks[value_block_index]
        if label_block.bbox is None or value_block.bbox is None or value_block.bbox.x + value_block.bbox.width <= label_block.bbox.x:
            return None
        value_score = self._score_ocr_label_value_block(value_block, spec)
        if value_score is None:
            return None
        gap_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=6.0, min_px=28.0, max_px=220.0)
        center_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=1.5, min_px=12.0, max_px=52.0)
        if geometry.gap_px > gap_threshold * 1.6 or geometry.center_delta_px > center_threshold * 2.0:
            return None
        score = 1.0
        score -= 0.18 * min(1.0, geometry.gap_px / max(1.0, gap_threshold))
        score -= 0.18 * min(1.0, geometry.center_delta_px / max(1.0, center_threshold))
        score -= 0.12 * min(1.0, max(0.0, geometry.height_ratio - 1.0) / 1.0)
        score += 0.14 * max(0.0, value_score - 0.5)
        if geometry.gap_kind == "token":
            score += 0.04
        score += 0.04 if value_block.score >= 0.94 else 0.0
        return score if score >= 0.34 else None

    def _score_ocr_label_down_neighbor(self, scene_index, label_block_index: int, value_block_index: int, spec: _FieldLabelSpec) -> float | None:
        geometry = self._ocr_pair_geometry(scene_index, label_block_index, value_block_index, direction="down")
        if geometry is None:
            return None
        label_block = scene_index.blocks[label_block_index]
        value_block = scene_index.blocks[value_block_index]
        if label_block.bbox is None or value_block.bbox is None:
            return None
        if self.detector._bbox_center_y(value_block.bbox) <= self.detector._bbox_center_y(label_block.bbox):
            return None
        value_score = self._score_ocr_label_value_block(value_block, spec)
        if value_score is None:
            return None
        vertical_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=4.0, min_px=18.0, max_px=120.0)
        if geometry.vertical_gap_px > vertical_threshold * 1.8:
            return None
        center_x_delta = abs((label_block.bbox.x + label_block.bbox.width / 2) - (value_block.bbox.x + value_block.bbox.width / 2))
        align_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=2.2, min_px=18.0, max_px=84.0)
        if geometry.left_edge_delta_px > align_threshold * 1.8 and center_x_delta > align_threshold * 1.8 and geometry.horizontal_overlap_ratio < 0.18:
            return None
        score = 1.0
        score -= 0.2 * min(1.0, geometry.vertical_gap_px / max(1.0, vertical_threshold))
        score -= 0.14 * min(1.0, min(geometry.left_edge_delta_px, center_x_delta) / max(1.0, align_threshold))
        score += 0.1 * min(1.0, geometry.horizontal_overlap_ratio)
        score += 0.14 * max(0.0, value_score - 0.5)
        score += 0.04 if value_block.score >= 0.94 else 0.0
        return score if score >= 0.34 else None

    def _ocr_pair_geometry(self, scene_index, source_block_index: int, target_block_index: int, *, direction: str) -> _OCRPairGeometry | None:
        cache_key = (source_block_index, target_block_index, direction)
        if cache_key in scene_index.pair_geometry_cache:
            return scene_index.pair_geometry_cache[cache_key]
        if source_block_index < 0 or target_block_index < 0 or source_block_index >= len(scene_index.blocks) or target_block_index >= len(scene_index.blocks):
            scene_index.pair_geometry_cache[cache_key] = None
            return None
        source_block = scene_index.blocks[source_block_index]
        target_block = scene_index.blocks[target_block_index]
        if source_block.bbox is None or target_block.bbox is None:
            scene_index.pair_geometry_cache[cache_key] = None
            return None
        source_box = source_block.bbox
        target_box = target_block.bbox
        min_height = float(min(source_box.height, target_box.height))
        max_height = float(max(source_box.height, target_box.height))
        avg_height = (source_box.height + target_box.height) / 2
        horizontal_gap = max(0.0, float(target_box.x - (source_box.x + source_box.width)))
        vertical_gap = max(0.0, float(target_box.y - (source_box.y + source_box.height)))
        center_delta = abs(self.detector._bbox_center_y(source_box) - self.detector._bbox_center_y(target_box))
        left_edge_delta = abs(source_box.x - target_box.x)
        vertical_overlap = max(0, min(source_box.y + source_box.height, target_box.y + target_box.height) - max(source_box.y, target_box.y))
        vertical_overlap_ratio = vertical_overlap / max(1.0, min_height)
        horizontal_overlap = max(0, min(source_box.x + source_box.width, target_box.x + target_box.width) - max(source_box.x, target_box.x))
        horizontal_overlap_ratio = horizontal_overlap / max(1.0, float(min(source_box.width, target_box.width)))
        gap_kind = self._classify_ocr_horizontal_gap(gap=horizontal_gap, min_height=min_height, avg_height=avg_height) if direction == "right" else None
        geometry = _OCRPairGeometry(source_block_index, target_block_index, direction, min_height, avg_height, max_height, horizontal_gap, vertical_gap, center_delta, left_edge_delta, vertical_overlap_ratio, horizontal_overlap_ratio, max_height / max(1.0, min_height), gap_kind)
        scene_index.pair_geometry_cache[cache_key] = geometry
        return geometry

    def _ocr_horizontal_gap_thresholds(self, *, min_height: float, avg_height: float) -> tuple[float, float]:
        token_gap = self.detector._clamped_ocr_tolerance(min_height, ratio=0.4, min_px=6.0, max_px=12.0)
        word_gap = self.detector._clamped_ocr_tolerance(avg_height, ratio=0.55, min_px=8.0, max_px=18.0)
        return token_gap, max(token_gap, word_gap)

    def _classify_ocr_horizontal_gap(self, *, gap: float, min_height: float, avg_height: float) -> str:
        token_gap, word_gap = self._ocr_horizontal_gap_thresholds(min_height=min_height, avg_height=avg_height)
        if gap <= token_gap:
            return "token"
        if gap <= word_gap:
            return "word"
        return "column"

    def _blocks_semantically_related_by_index(self, scene_index, left_block_index: int, right_block_index: int) -> bool:
        geometry = self._ocr_pair_geometry(scene_index, left_block_index, right_block_index, direction="right")
        if geometry is None or geometry.gap_kind == "column":
            return False
        center_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.3, min_px=4.0, max_px=10.0)
        return not (geometry.vertical_overlap_ratio < 0.38 and geometry.center_delta_px > center_threshold)

    def _score_horizontal_successor_by_index(self, scene_index, left_block_index: int, right_block_index: int) -> float | None:
        geometry = self._ocr_pair_geometry(scene_index, left_block_index, right_block_index, direction="right")
        if geometry is None or not self._blocks_semantically_related_by_index(scene_index, left_block_index, right_block_index) or geometry.gap_kind == "column":
            return None
        _, word_gap = self._ocr_horizontal_gap_thresholds(min_height=geometry.min_height_px, avg_height=geometry.avg_height_px)
        center_threshold = self.detector._clamped_ocr_tolerance(geometry.avg_height_px, ratio=0.3, min_px=4.0, max_px=10.0)
        score = 1.0
        score -= 0.55 * min(1.0, geometry.gap_px / max(1.0, word_gap))
        score -= 0.3 * min(1.0, geometry.center_delta_px / max(1.0, center_threshold))
        score -= 0.15 * min(1.0, max(0.0, geometry.height_ratio - 1.0) / 0.45)
        if geometry.gap_kind == "token":
            score += 0.06
        return max(0.0, score)

    def _maybe_extend_ocr_name_value(self, document: OCRStreamDocument, block_indices: tuple[int, ...], value_text: str) -> tuple[tuple[int, ...], str]:
        if not block_indices:
            return block_indices, value_text
        next_block_index = self._next_block_same_line(document.scene_index, block_indices[-1])
        if next_block_index is None:
            return block_indices, value_text
        next_block = document.blocks[next_block_index]
        if _match_pure_field_labels(next_block.text):
            return block_indices, value_text
        joined = _join_fragments(value_text, next_block.text)
        canonical = self.detector._canonical_name_source_text(joined, allow_ocr_noise=True)
        if canonical is None:
            return block_indices, value_text
        return block_indices + (next_block_index,), joined

    def _next_block_same_line(self, scene_index, block_index: int) -> int | None:
        position = scene_index.position_by_block_index.get(block_index)
        if position is None:
            return None
        line_index, item_index = position
        line = scene_index.lines[line_index]
        if item_index + 1 >= len(line):
            return None
        return line[item_index + 1]

    def _join_ocr_block_text(self, document: OCRStreamDocument, block_indices: tuple[int, ...]) -> str:
        parts: list[str] = []
        previous_index: int | None = None
        for block_index in block_indices:
            if previous_index is not None:
                left = document.blocks[previous_index].text
                right = document.blocks[block_index].text
                if left[-1:].isascii() and left[-1:].isalnum() and right[:1].isascii() and right[:1].isalnum():
                    parts.append(" ")
            parts.append(document.blocks[block_index].text)
            previous_index = block_index
        return "".join(parts)

    def _build_ocr_direct_candidate(self, *, document: OCRStreamDocument, spec: _FieldLabelSpec, value_text: str, block_indices: tuple[int, ...], inline_span: tuple[int, int] | None) -> PIICandidate | None:
        if not value_text or not block_indices:
            return None
        if spec.attr_type == PIIAttributeType.PHONE:
            cleaned = self.detector._clean_phone_candidate(value_text)
        elif spec.attr_type == PIIAttributeType.ORGANIZATION:
            cleaned = self.detector._clean_organization_candidate(value_text)
        elif spec.attr_type == PIIAttributeType.ADDRESS:
            cleaned = self.detector._clean_address_candidate(value_text)
        else:
            cleaned = self.detector._clean_extracted_value(value_text)
        if not cleaned:
            return None
        confidence = spec.ocr_confidence
        canonical_source_text = None
        if spec.attr_type == PIIAttributeType.NAME:
            canonical_source_text = _canonical_name_for_spec(self.detector, spec, cleaned, source=PIISourceType.OCR)
            if canonical_source_text is None:
                return None
        else:
            validator = _validator_for_spec(self.detector, spec, source=PIISourceType.OCR)
            if not validator(cleaned):
                return None
            if spec.attr_type == PIIAttributeType.ORGANIZATION:
                canonical_source_text = canonicalize_pii_value(PIIAttributeType.ORGANIZATION, cleaned)
                confidence = max(confidence, self.detector._organization_confidence(cleaned, allow_weak_suffix=True))
            elif spec.attr_type == PIIAttributeType.ADDRESS:
                canonical_source_text = address_key_value_canonical_from_zh(cleaned)
        attr_type = self.detector._normalize_fallback_attr_type(spec.attr_type, cleaned)
        normalized = canonicalize_pii_value(attr_type, cleaned)
        blocks = [document.blocks[index] for index in block_indices]
        bbox = _combine_bboxes(tuple(block.bbox for block in blocks if block.bbox is not None))
        block_id = blocks[0].block_id if len(blocks) == 1 else None
        span_start = inline_span[0] if len(blocks) == 1 and inline_span is not None else None
        span_end = inline_span[1] if len(blocks) == 1 and inline_span is not None else None
        entity_id = self.detector.resolver.build_candidate_id(self.detector.detector_mode, PIISourceType.OCR.value, normalized, attr_type.value, block_id=block_id, span_start=span_start, span_end=span_end)
        metadata = self.detector._candidate_metadata(matched_by=spec.ocr_matched_by, metadata=_event_metadata_from_spec(spec, matched_by=spec.ocr_matched_by) | {"ocr_block_ids": [block.block_id for block in blocks if block.block_id]})
        return PIICandidate(entity_id=entity_id, text=cleaned, canonical_source_text=canonical_source_text, normalized_text=normalized, attr_type=attr_type, source=PIISourceType.OCR, bbox=bbox, block_id=block_id, span_start=span_start, span_end=span_end, confidence=confidence, metadata=metadata)

    def _seed_validator(self, attr_type: PIIAttributeType, value: str) -> bool:
        if attr_type == PIIAttributeType.EMAIL:
            return self.detector._is_email_candidate(value)
        if attr_type == PIIAttributeType.PHONE:
            return self.detector._is_context_phone_candidate(value)
        if attr_type == PIIAttributeType.ID_NUMBER:
            return self.detector._is_id_candidate(value)
        if attr_type == PIIAttributeType.CARD_NUMBER:
            return self.detector._is_context_card_number_candidate(value)
        if attr_type == PIIAttributeType.BANK_ACCOUNT:
            return self.detector._is_bank_account_candidate(value)
        if attr_type == PIIAttributeType.PASSPORT_NUMBER:
            return self.detector._is_passport_candidate(value)
        if attr_type == PIIAttributeType.DRIVER_LICENSE:
            return self.detector._is_driver_license_candidate(value)
        return bool(value)

    def _set_standalone_context(self, raw_text: str, candidates) -> None:
        self.detector._active_standalone_context_text = raw_text
        self.detector._active_standalone_context_candidates = tuple(candidates)

    def _clear_standalone_context(self) -> None:
        self.detector._active_standalone_context_text = None
        self.detector._active_standalone_context_candidates = ()


def _build_modified_text(raw_text: str, hard_seeds: list[HardSeed]) -> ModifiedText:
    chunks: list[str] = []
    modified_to_raw: list[int | None] = []
    replacements: list[ReplacementSpan] = []
    cursor = 0
    modified_cursor = 0
    for seed in sorted(hard_seeds, key=lambda item: (item.start, item.end)):
        if cursor < seed.start:
            segment = raw_text[cursor:seed.start]
            chunks.append(segment)
            modified_to_raw.extend(range(cursor, seed.start))
            modified_cursor += len(segment)
        placeholder = seed.placeholder
        chunks.append(placeholder)
        modified_to_raw.extend([None] * len(placeholder))
        replacements.append(
            ReplacementSpan(
                modified_start=modified_cursor,
                modified_end=modified_cursor + len(placeholder),
                raw_start=seed.start,
                raw_end=seed.end,
                attr_type=seed.attr_type,
            )
        )
        modified_cursor += len(placeholder)
        cursor = seed.end
    if cursor < len(raw_text):
        tail = raw_text[cursor:]
        chunks.append(tail)
        modified_to_raw.extend(range(cursor, len(raw_text)))
    return ModifiedText(
        text="".join(chunks),
        modified_to_raw=tuple(modified_to_raw),
        replacements=tuple(replacements),
    )


def _select_non_overlapping_hard_seeds(seeds: list[HardSeed]) -> list[HardSeed]:
    selected: list[HardSeed] = []
    for seed in sorted(
        seeds,
        key=lambda item: (
            -item.priority,
            -item.confidence,
            -(item.end - item.start),
            item.start,
            item.end,
        ),
    ):
        if any(not (seed.end <= existing.start or existing.end <= seed.start) for existing in selected):
            continue
        selected.append(seed)
    return sorted(selected, key=lambda item: (item.start, item.end, -item.priority))


def _find_label_events(text: str) -> list[LabelEvent]:
    candidates: list[LabelEvent] = []
    for spec in sorted(
        _field_label_specs(),
        key=lambda item: (
            -_LABEL_ATTR_PRIORITY.get(item.attr_type, 0),
            -max((len(keyword) for keyword in item.keywords), default=0),
            item.context_matched_by,
        ),
    ):
        for keyword in sorted(spec.keywords, key=len, reverse=True):
            pattern = _keyword_pattern(keyword)
            for match in pattern.finditer(text):
                start, end = match.span()
                if not _keyword_leading_boundary_ok(text, start):
                    continue
                if end < len(text):
                    trailing = text[end]
                    if trailing.isascii() and trailing.isalnum():
                        continue
                value_start = _skip_label_connectors(text, end)
                if value_start >= len(text):
                    continue
                if text[value_start : value_start + len(_OCR_SEMANTIC_BREAK_TOKEN)] == _OCR_SEMANTIC_BREAK_TOKEN:
                    continue
                candidates.append(
                    LabelEvent(
                        spec=spec,
                        keyword=keyword,
                        start=start,
                        end=end,
                        value_start=value_start,
                        priority=_LABEL_ATTR_PRIORITY.get(spec.attr_type, 0) + len(keyword),
                    )
                )
    accepted: list[LabelEvent] = []
    for event in sorted(
        candidates,
        key=lambda item: (-item.priority, -(item.end - item.start), item.start, item.spec.context_matched_by),
    ):
        if any(not (event.end <= kept.start or kept.end <= event.start) for kept in accepted):
            continue
        accepted.append(event)
    return sorted(accepted, key=lambda item: (item.start, -item.priority, -(item.end - item.start)))


def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    escaped = re.escape(keyword).replace(r"\ ", r"\s+")
    return re.compile(escaped, re.IGNORECASE)


def _keyword_leading_boundary_ok(text: str, start: int) -> bool:
    if start <= 0:
        return True
    previous = text[start - 1]
    if previous.isspace() or previous in _LABEL_LEADING_DELIMITERS:
        return True
    if previous == ">":
        token_start = max(0, start - len(_OCR_SEMANTIC_BREAK_TOKEN))
        if text[token_start:start] == _OCR_SEMANTIC_BREAK_TOKEN:
            return True
    if previous.isascii() and previous.isalnum():
        return False
    return not ("\u4e00" <= previous <= "\u9fff")


def _skip_label_connectors(text: str, index: int) -> int:
    match = _LABEL_CONNECTOR_PATTERN.match(text[index:])
    if match is None:
        return index
    return index + match.end()


def _label_value_window(text: str, start: int) -> tuple[int, int]:
    if start >= len(text):
        return start, start
    end = min(len(text), start + 96)
    hard_stop = _HARD_VALUE_STOP_PATTERN.search(text, start)
    if hard_stop is not None:
        end = min(end, hard_stop.start())
    break_index = text.find(_OCR_SEMANTIC_BREAK_TOKEN, start, end)
    if break_index >= 0:
        end = min(end, break_index)
    next_label_start: int | None = None
    for spec in _field_label_specs():
        for keyword in spec.keywords:
            match = _keyword_pattern(keyword).search(text, start + 1, end)
            if match is None:
                continue
            label_start = match.start()
            if not _keyword_leading_boundary_ok(text, label_start):
                continue
            if next_label_start is None or label_start < next_label_start:
                next_label_start = label_start
    if next_label_start is not None:
        end = min(end, next_label_start)
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, max(start, end)


def _event_matched_by(event: LabelEvent, source: PIISourceType) -> str:
    return event.spec.ocr_matched_by if source == PIISourceType.OCR else event.spec.context_matched_by


def _event_metadata(event: LabelEvent, *, matched_by: str) -> dict[str, list[str]]:
    metadata = _event_metadata_from_spec(event.spec, matched_by=matched_by)
    metadata["field_label_keyword"] = [event.keyword]
    return metadata


def _event_metadata_from_spec(spec: _FieldLabelSpec, *, matched_by: str) -> dict[str, list[str]]:
    metadata: dict[str, list[str]] = {"matched_by": [matched_by]}
    if spec.name_component:
        metadata["name_component"] = [spec.name_component]
    return metadata


def _find_candidate_by_span(collected, *, attr_type: PIIAttributeType, span_start: int, span_end: int) -> PIICandidate | None:
    for candidate in collected.values():
        if candidate.attr_type != attr_type:
            continue
        if candidate.span_start == span_start and candidate.span_end == span_end:
            return candidate
    return None


def _name_title_patterns() -> tuple[tuple[re.Pattern[str], str, float], ...]:
    zh_titles = "|".join(sorted((re.escape(item) for item in _NAME_HONORIFICS), key=len, reverse=True))
    zh_pattern = re.compile(rf"(?<![一-龥])(?P<value>[一-龥·]{{1,5}}(?:{zh_titles}))(?![一-龥])")
    return (
        (zh_pattern, "heuristic_name_title_zh", 0.78),
        (_EN_NAME_TITLE_PATTERN, "heuristic_name_title_en", 0.72),
    )


def _generic_name_patterns() -> tuple[tuple[re.Pattern[str], str], ...]:
    compound_surnames = "|".join(sorted((re.escape(item) for item in _COMMON_COMPOUND_SURNAMES), key=len, reverse=True))
    single_surnames = "".join(sorted(_COMMON_SINGLE_CHAR_SURNAMES))
    zh_compound = re.compile(rf"(?<![一-龥])(?P<value>(?:{compound_surnames})[一-龥]{{1,2}})(?![一-龥])")
    zh_single = re.compile(rf"(?<![一-龥])(?P<value>[{re.escape(single_surnames)}][一-龥]{{1,2}})(?![一-龥])")
    return (
        (zh_compound, "heuristic_name_fragment_zh"),
        (zh_single, "heuristic_name_fragment_zh"),
        (_EN_STANDALONE_NAME_PATTERN, "heuristic_name_fragment_en"),
    )


def _validator_for_spec(detector, spec: _FieldLabelSpec, *, source: PIISourceType):
    validator = getattr(detector, spec.validator_name)
    if spec.attr_type == PIIAttributeType.NAME and spec.name_component:
        return validator
    if spec.attr_type == PIIAttributeType.ADDRESS and source == PIISourceType.OCR:
        return lambda value: validator(value) or detector._looks_like_masked_address_candidate(value)
    return validator


def _canonical_name_for_spec(detector, spec: _FieldLabelSpec, value: str, *, source: PIISourceType) -> str | None:
    allow_ocr_noise = source == PIISourceType.OCR
    if spec.name_component and hasattr(detector, "_canonical_name_component_source_text"):
        return detector._canonical_name_component_source_text(
            value,
            component=spec.name_component,
            allow_ocr_noise=allow_ocr_noise,
        )
    return detector._canonical_name_source_text(value, allow_ocr_noise=allow_ocr_noise)


def _placeholder_for_attr(attr_type: PIIAttributeType) -> str:
    placeholders = {
        PIIAttributeType.EMAIL: " <EMAIL> ",
        PIIAttributeType.PHONE: " <PHONE> ",
        PIIAttributeType.ID_NUMBER: " <ID> ",
        PIIAttributeType.CARD_NUMBER: " <CARD> ",
        PIIAttributeType.BANK_ACCOUNT: " <ACCOUNT> ",
        PIIAttributeType.PASSPORT_NUMBER: " <PASSPORT> ",
        PIIAttributeType.DRIVER_LICENSE: " <LICENSE> ",
        PIIAttributeType.NAME: " <NAME> ",
        PIIAttributeType.ORGANIZATION: " <ORG> ",
        PIIAttributeType.ADDRESS: " <ADDRESS> ",
        PIIAttributeType.DETAILS: " <DETAILS> ",
        PIIAttributeType.OTHER: " <OTHER> ",
    }
    return placeholders.get(attr_type, f" <{attr_type.value.upper()}> ")


def _combine_bboxes(boxes: tuple[BoundingBox, ...]) -> BoundingBox | None:
    if not boxes:
        return None
    min_x = min(box.x for box in boxes)
    min_y = min(box.y for box in boxes)
    max_x = max(box.x + box.width for box in boxes)
    max_y = max(box.y + box.height for box in boxes)
    return BoundingBox(
        x=max(0, int(min_x)),
        y=max(0, int(min_y)),
        width=max(1, int(max_x - min_x)),
        height=max(1, int(max_y - min_y)),
    )


def _join_fragments(left: str | None, right: str | None) -> str:
    left_text = str(left or "").strip()
    right_text = str(right or "").strip()
    if not left_text:
        return right_text
    if not right_text:
        return left_text
    if left_text[-1:].isascii() and left_text[-1:].isalnum() and right_text[:1].isascii() and right_text[:1].isalnum():
        return f"{left_text} {right_text}"
    return f"{left_text}{right_text}"


def _span_is_internal_ocr_break(text: str, span_start: int, span_end: int) -> bool:
    slice_text = text[max(0, span_start) : max(0, span_end)]
    if not slice_text:
        return False
    normalized = slice_text.replace(_OCR_SEMANTIC_BREAK_TOKEN, "").strip()
    return not normalized


def _candidate_location_key(candidate: PIICandidate) -> tuple[object, ...]:
    ocr_block_ids = tuple(dict.fromkeys(candidate.metadata.get("ocr_block_ids", [])))
    bbox_key = None
    if candidate.bbox is not None:
        bbox_key = (
            candidate.bbox.x,
            candidate.bbox.y,
            candidate.bbox.width,
            candidate.bbox.height,
        )
    return (
        candidate.source.value,
        candidate.attr_type.value,
        candidate.normalized_text,
        candidate.block_id,
        ocr_block_ids,
        candidate.span_start,
        candidate.span_end,
        bbox_key,
    )
