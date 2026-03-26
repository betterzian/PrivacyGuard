from __future__ import annotations

from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.boundary_trimmer import trim_spans
from privacyguard.infrastructure.pii.address.candidate_emitter import emit_candidates
from privacyguard.infrastructure.pii.address.input_adapter import build_text_input
from privacyguard.infrastructure.pii.address.risk_classifier import classify_spans
from privacyguard.infrastructure.pii.address.seed_extractor import extract_seeds
from privacyguard.infrastructure.pii.address.span_grower import grow_spans
from privacyguard.infrastructure.pii.address.types import AddressParseConfig
from privacyguard.infrastructure.pii.rule_based_detector_shared import _RuleStrengthProfile


def collect_address_candidates(
    self,
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    raw_text: str,
    source,
    bbox: object,
    block_id: str | None,
    *,
    skip_spans: list[tuple[int, int]],
    rule_profile: _RuleStrengthProfile,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> None:
    address_input = build_text_input(raw_text)
    seeds = extract_seeds(address_input, locale_profile=self.locale_profile)
    if not seeds:
        return
    drafts = grow_spans(address_input, seeds, locale_profile=self.locale_profile)
    if not drafts:
        return
    config = AddressParseConfig(
        locale_profile=self.locale_profile,
        min_confidence=rule_profile.address_min_confidence,
        field_label_pattern=self.field_label_pattern,
        emit_component_candidates=True,
        emit_location_candidates=False,
    )
    spans = trim_spans(address_input, drafts, config=config)
    if not spans:
        return
    results = classify_spans(spans, locale_profile=self.locale_profile, config=config)
    if not results:
        return
    emit_candidates(
        self,
        collected,
        raw_text,
        results,
        source,
        bbox,
        block_id,
        skip_spans=skip_spans,
        config=config,
        original_text=original_text,
        shadow_index_map=shadow_index_map,
    )
