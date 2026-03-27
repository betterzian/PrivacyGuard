from __future__ import annotations

from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.address.candidate_emitter import emit_candidates
from privacyguard.infrastructure.pii.address.event_stream_scanner import scan_address_and_organization
from privacyguard.infrastructure.pii.address.input_adapter import build_text_input
from privacyguard.infrastructure.pii.address.span_parse import parse_results_from_spans
from privacyguard.infrastructure.pii.address.seed_extractor import collect_component_matches
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
    component_matches = collect_component_matches(address_input, locale_profile=self.locale_profile)
    config = AddressParseConfig(
        locale_profile=self.locale_profile,
        protection_level=rule_profile.level,
        min_confidence=rule_profile.address_min_confidence,
        field_label_pattern=self.field_label_pattern,
        emit_component_candidates=True,
    )
    spans = scan_address_and_organization(
        self,
        collected,
        raw_text=address_input.text,
        component_matches=component_matches,
        source=source,
        bbox=bbox,
        block_id=block_id,
        skip_spans=skip_spans,
        config=config,
        original_text=original_text,
        shadow_index_map=shadow_index_map,
    )
    if not spans:
        return
    results = parse_results_from_spans(
        spans,
        locale_profile=self.locale_profile,
        config=config,
        component_matches=component_matches,
    )
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
