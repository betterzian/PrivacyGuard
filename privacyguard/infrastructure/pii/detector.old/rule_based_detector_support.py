"""Runtime support facade for the unified rule-based detector."""

from __future__ import annotations

import privacyguard.infrastructure.pii.rule_based_detector_collectors as _collectors
import privacyguard.infrastructure.pii.rule_based_detector_dictionary as _dictionary
import privacyguard.infrastructure.pii.rule_based_detector_ocr as _ocr
import privacyguard.infrastructure.pii.rule_based_detector_patterns as _patterns
import privacyguard.infrastructure.pii.rule_based_detector_validation as _validation


class RuleBasedDetectorRuntimeSupport:
    def __init__(self, detector) -> None:
        self.detector = detector
        self._active_ocr_page_document = None
        self._active_ocr_scene_index = None
        self._active_standalone_context_text = None
        self._active_standalone_context_candidates = ()

    def __getattr__(self, name: str):
        return getattr(self.detector, name)

    _resolve_privacy_repository_path = _dictionary._resolve_privacy_repository_path
    _load_dictionary = _dictionary._load_dictionary
    _load_privacy_dictionary = _dictionary._load_privacy_dictionary
    _expand_structured_address_slot = _dictionary._expand_structured_address_slot
    _append_dictionary_values = _dictionary._append_dictionary_values
    _session_dictionary_entries = _dictionary._session_dictionary_entries
    _canonical_dictionary_source_text = _dictionary._canonical_dictionary_source_text
    _rule_profile = _dictionary._rule_profile
    _normalize_confidence_overrides = _dictionary._normalize_confidence_overrides
    _expand_structured_name_slot = _dictionary._expand_structured_name_slot
    _parse_dictionary_item = _dictionary._parse_dictionary_item
    _normalize_aliases = _dictionary._normalize_aliases

    _meets_confidence_threshold = _validation._meets_confidence_threshold
    _clean_extracted_value = _validation._clean_extracted_value
    _clean_phone_candidate = _validation._clean_phone_candidate
    _strip_ocr_break_edge_noise = _validation._strip_ocr_break_edge_noise
    _clean_address_candidate = _validation._clean_address_candidate
    _clean_organization_candidate = _validation._clean_organization_candidate
    _next_significant_char = _validation._next_significant_char
    _previous_significant_char = _validation._previous_significant_char
    _left_context = _validation._left_context
    _right_context = _validation._right_context
    _starts_with_geo_or_activity = _validation._starts_with_geo_or_activity
    _is_ui_operation_name_token = _validation._is_ui_operation_name_token
    _is_ui_or_commerce_location_token = _validation._is_ui_or_commerce_location_token
    _split_en_name_tokens = _validation._split_en_name_tokens
    _is_blacklisted_english_name_phrase = _validation._is_blacklisted_english_name_phrase
    _english_given_name_weight = _validation._english_given_name_weight
    _english_surname_weight = _validation._english_surname_weight
    _english_geo_phrase_weight = _validation._english_geo_phrase_weight
    _nearby_pii_context_score = _validation._nearby_pii_context_score
    _active_ocr_context = _validation._active_ocr_context
    _ocr_span_block_indices = _validation._ocr_span_block_indices
    _contains_field_keyword = _validation._contains_field_keyword
    _ocr_block_pii_context_signal = _validation._ocr_block_pii_context_signal
    _is_relevant_vertical_ocr_neighbor = _validation._is_relevant_vertical_ocr_neighbor
    _ocr_neighbor_pii_context_score = _validation._ocr_neighbor_pii_context_score
    _detected_candidate_context_score = _validation._detected_candidate_context_score
    _standalone_name_confidence = _validation._standalone_name_confidence
    _english_standalone_name_confidence = _validation._english_standalone_name_confidence
    _zh_standalone_name_confidence = _validation._zh_standalone_name_confidence
    _generic_name_confidence = _validation._generic_name_confidence
    _is_cjk_char = _validation._is_cjk_char
    _canonical_name_source_text = _validation._canonical_name_source_text
    _canonical_name_component_source_text = _validation._canonical_name_component_source_text
    _compact_name_value = _validation._compact_name_value
    _is_en_phone_candidate = _validation._is_en_phone_candidate
    _is_phone_candidate = _validation._is_phone_candidate
    _is_context_phone_candidate = _validation._is_context_phone_candidate
    _is_context_card_number_candidate = _validation._is_context_card_number_candidate
    _is_bank_account_candidate = _validation._is_bank_account_candidate
    _is_passport_candidate = _validation._is_passport_candidate
    _is_driver_license_candidate = _validation._is_driver_license_candidate
    _is_email_candidate = _validation._is_email_candidate
    _is_id_candidate = _validation._is_id_candidate
    _is_other_candidate = _validation._is_other_candidate
    _is_name_candidate = _validation._is_name_candidate
    _is_family_name_candidate = _validation._is_family_name_candidate
    _is_given_name_candidate = _validation._is_given_name_candidate
    _is_middle_name_candidate = _validation._is_middle_name_candidate
    _is_context_organization_candidate = _validation._is_context_organization_candidate
    _is_organization_candidate = _validation._is_organization_candidate
    _looks_like_name_with_title = _validation._looks_like_name_with_title
    _explicit_label_address_value_allowed = _validation._explicit_label_address_value_allowed
    _compact_resembles_address_token_shape = _validation._compact_resembles_address_token_shape
    _label_address_value_shape_ok = _validation._label_address_value_shape_ok
    _looks_like_masked_address_candidate = _validation._looks_like_masked_address_candidate
    _has_en_organization_suffix = _validation._has_en_organization_suffix
    _organization_confidence = _validation._organization_confidence
    _upsert_candidate = _validation._upsert_candidate
    _normalize_fallback_attr_type = _validation._normalize_fallback_attr_type
    _overlaps_any_span = _validation._overlaps_any_span
    _dictionary_entry_variants = _validation._dictionary_entry_variants
    _candidate_metadata = _validation._candidate_metadata
    _merge_candidate_metadata = _validation._merge_candidate_metadata
    _to_attr_type = _validation._to_attr_type

    _all_field_keywords = _patterns._all_field_keywords

    _match_context_window = _collectors._match_context_window
    _looks_like_cn_id_with_birthdate = _collectors._looks_like_cn_id_with_birthdate
    _extract_match = _collectors._extract_match
    _remap_shadow_span = _collectors._remap_shadow_span

    _looks_like_ui_time_metadata = _ocr._looks_like_ui_time_metadata
    _bbox_center_y = _ocr._bbox_center_y
    _clamped_ocr_tolerance = _ocr._clamped_ocr_tolerance


__all__ = ["RuleBasedDetectorRuntimeSupport"]
