"""基于规则与字典的 PII 检测器。"""

import privacyguard.infrastructure.pii.address as _address_pipeline
from privacyguard.infrastructure.pii.rule_based_detector_shared import *
import privacyguard.infrastructure.pii.rule_based_detector_collectors as _collectors
import privacyguard.infrastructure.pii.rule_based_detector_dictionary as _dictionary
import privacyguard.infrastructure.pii.rule_based_detector_ocr as _ocr
import privacyguard.infrastructure.pii.rule_based_detector_patterns as _patterns
import privacyguard.infrastructure.pii.rule_based_detector_scan as _scan
import privacyguard.infrastructure.pii.rule_based_detector_validation as _validation


class RuleBasedPIIDetector:
    def __init__(
        self,
        privacy_repository_path: str | Path | None = None,
        detector_mode: str = "rule_based",
        locale_profile: str = "mixed",
        mapping_store: MappingStore | None = None,
        min_confidence_by_attr: dict[PIIAttributeType | str, float] | None = None,
    ) -> None:
        """初始化规则、词典与候选解析服务。"""
        self.detector_mode = detector_mode
        self.locale_profile = self._normalize_locale_profile(locale_profile)
        self.privacy_repository_path = self._resolve_privacy_repository_path(privacy_repository_path)
        self.dictionary = self._load_dictionary(self.privacy_repository_path)
        self.dictionary_index = self._build_dictionary_index(self.dictionary)
        self.mapping_store = mapping_store
        self.min_confidence_by_attr = self._normalize_confidence_overrides(min_confidence_by_attr)
        self.resolver = CandidateResolverService()
        self.patterns = self._build_patterns()
        self.context_rules = self._build_context_rules()
        self.self_name_patterns = self._build_self_name_patterns()
        self.masked_text_pattern = self._build_masked_text_pattern()
        self.field_label_pattern = self._build_field_label_pattern()
        self.trailing_field_label_pattern = self._build_trailing_field_label_pattern()
        compound_surname_pattern = "|".join(
            sorted((re.escape(item) for item in _COMMON_COMPOUND_SURNAMES), key=len, reverse=True)
        )
        single_surname_pattern = f"[{''.join(sorted(_COMMON_SINGLE_CHAR_SURNAMES))}]"
        self.name_title_pattern = re.compile(
            rf"(?P<value>(?:(?:{compound_surname_pattern})[一-龥·]{{1,3}}|(?:{single_surname_pattern})[一-龥·]{{0,2}})"
            rf"(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))}))"
        )
        self.en_name_title_pattern = re.compile(
            r"(?P<value>(?:mr|mrs|ms|miss|dr|prof)\.?\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,2})",
            re.IGNORECASE,
        )
        self.generic_name_pattern = re.compile(
            rf"(?=(?P<value>(?:(?:{compound_surname_pattern})[一-龥·]{{1,2}}|(?:{single_surname_pattern})[一-龥·]{{1,3}})))"
        )
        self.en_standalone_name_pattern = re.compile(
            r"(?<![A-Za-z])(?P<value>[A-Za-z][A-Za-z'\-]{1,24}(?:[ \t]+[A-Za-z][A-Za-z'\-]{1,24}){1,2})(?![A-Za-z])"
        )
        self._active_ocr_page_document: _OCRPageDocument | None = None
        self._active_ocr_scene_index: _OCRSceneIndex | None = None
        self._active_standalone_context_text: str | None = None
        self._active_standalone_context_candidates: tuple[PIICandidate, ...] = ()

    def detect(
        self,
        prompt_text: str,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_id: str | None = None,
        turn_id: int | None = None,
        protection_level: ProtectionLevel | str = ProtectionLevel.STRONG,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> list[PIICandidate]:
        """对 prompt 与 OCR 两路输入执行候选识别。"""
        session_entries = self._session_dictionary_entries(session_id=session_id, turn_id=turn_id)
        session_index = self._build_dictionary_index(session_entries)
        rule_profile = self._rule_profile(protection_level, detector_overrides=detector_overrides)
        candidates: list[PIICandidate] = []
        candidates.extend(
            self._scan_text(
                prompt_text,
                PIISourceType.PROMPT,
                bbox=None,
                block_id=None,
                session_index=session_index,
                local_index=self.dictionary_index,
                rule_profile=rule_profile,
            )
        )
        candidates.extend(
            self._scan_ocr_page(
                ocr_blocks,
                session_index=session_index,
                local_index=self.dictionary_index,
                rule_profile=rule_profile,
            )
        )
        return self.resolver.resolve_candidates(candidates)

    def reload_privacy_dictionary(self) -> None:
        """从 `privacy_repository_path` 重新加载词典与索引；路径未设置或文件缺失时与构造时行为一致。"""
        self.dictionary = self._load_dictionary(self.privacy_repository_path)
        self.dictionary_index = self._build_dictionary_index(self.dictionary)

    def _normalize_locale_profile(self, locale_profile: str) -> str:
        normalized = str(locale_profile or "mixed").strip().lower()
        if normalized not in {"zh_cn", "en_us", "mixed"}:
            raise ValueError(f"unsupported locale_profile: {locale_profile}")
        return normalized

    def _supports_zh(self) -> bool:
        return self.locale_profile in {"zh_cn", "mixed"}

    def _supports_en(self) -> bool:
        return self.locale_profile in {"en_us", "mixed"}

    _resolve_privacy_repository_path = _dictionary._resolve_privacy_repository_path
    _load_dictionary = _dictionary._load_dictionary
    _load_privacy_dictionary = _dictionary._load_privacy_dictionary
    _expand_structured_address_slot = _dictionary._expand_structured_address_slot
    _append_dictionary_values = _dictionary._append_dictionary_values
    _session_dictionary_entries = _dictionary._session_dictionary_entries
    _canonical_dictionary_source_text = _dictionary._canonical_dictionary_source_text
    _rule_profile = _dictionary._rule_profile
    _normalize_confidence_overrides = _dictionary._normalize_confidence_overrides
    _build_dictionary_index = _dictionary._build_dictionary_index
    _expand_structured_name_slot = _dictionary._expand_structured_name_slot
    _parse_dictionary_item = _dictionary._parse_dictionary_item
    _normalize_aliases = _dictionary._normalize_aliases
    _build_patterns = _patterns._build_patterns
    _build_context_rules = _patterns._build_context_rules
    _build_self_name_patterns = _patterns._build_self_name_patterns
    _build_masked_text_pattern = _patterns._build_masked_text_pattern
    _build_context_rule = _patterns._build_context_rule
    _build_field_label_pattern = _patterns._build_field_label_pattern
    _build_trailing_field_label_pattern = _patterns._build_trailing_field_label_pattern
    _all_field_keywords = _patterns._all_field_keywords
    _scan_text = _scan._scan_text
    _scan_ocr_page = _scan._scan_ocr_page
    _build_ocr_page_document = _ocr._build_ocr_page_document
    _build_ocr_scene_index = _ocr._build_ocr_scene_index
    _group_blocks_by_page_line = _ocr._group_blocks_by_page_line
    _collect_ocr_block_chains = _ocr._collect_ocr_block_chains
    _collect_ocr_successor_proposals = _ocr._collect_ocr_successor_proposals
    _horizontal_successor_proposal = _ocr._horizontal_successor_proposal
    _downward_successor_proposal = _ocr._downward_successor_proposal
    _belongs_to_same_page_line = _ocr._belongs_to_same_page_line
    _ocr_horizontal_gap_thresholds = _ocr._ocr_horizontal_gap_thresholds
    _classify_ocr_horizontal_gap = _ocr._classify_ocr_horizontal_gap
    _ocr_pair_geometry = _ocr._ocr_pair_geometry
    _block_join_separator_by_index = _ocr._block_join_separator_by_index
    _blocks_semantically_related_by_index = _ocr._blocks_semantically_related_by_index
    _block_join_separator = _ocr._block_join_separator
    _append_ocr_page_separator = _ocr._append_ocr_page_separator
    _line_join_separator = _ocr._line_join_separator
    _blocks_semantically_related = _ocr._blocks_semantically_related
    _lines_semantically_related = _ocr._lines_semantically_related
    _score_horizontal_successor_by_index = _ocr._score_horizontal_successor_by_index
    _score_horizontal_successor = _ocr._score_horizontal_successor
    _score_vertical_line_successor_by_indices = _ocr._score_vertical_line_successor_by_indices
    _score_vertical_line_successor = _ocr._score_vertical_line_successor
    _score_vertical_block_successor_by_index = _ocr._score_vertical_block_successor_by_index
    _score_vertical_block_successor = _ocr._score_vertical_block_successor
    _looks_like_short_numeric_metadata = _ocr._looks_like_short_numeric_metadata
    _ocr_candidate_block_indices = _ocr._ocr_candidate_block_indices
    _ocr_candidate_signature = _ocr._ocr_candidate_signature
    _collect_ocr_label_adjacency_candidates = _ocr._collect_ocr_label_adjacency_candidates
    _collect_ocr_standalone_name_candidates = _ocr._collect_ocr_standalone_name_candidates
    _ocr_match_covers_standalone_block = _ocr._ocr_match_covers_standalone_block
    _ocr_standalone_scene_mode = _ocr._ocr_standalone_scene_mode
    _ocr_block_is_standalone_name_shape = _ocr._ocr_block_is_standalone_name_shape
    _ocr_single_name_anchor_binding = _ocr._ocr_single_name_anchor_binding
    _ocr_label_specs_for_block = _ocr._ocr_label_specs_for_block
    _is_ocr_pure_label_block = _ocr._is_ocr_pure_label_block
    _build_ocr_label_adjacency_candidate = _ocr._build_ocr_label_adjacency_candidate
    _collect_ocr_right_value_chain = _ocr._collect_ocr_right_value_chain
    _collect_ocr_down_value_chain = _ocr._collect_ocr_down_value_chain
    _collect_ocr_same_line_continuation = _ocr._collect_ocr_same_line_continuation
    _score_ocr_label_value_block = _ocr._score_ocr_label_value_block
    _score_ocr_label_right_neighbor = _ocr._score_ocr_label_right_neighbor
    _score_ocr_label_down_neighbor = _ocr._score_ocr_label_down_neighbor
    _validate_ocr_label_value_chain = _ocr._validate_ocr_label_value_chain
    _validate_ocr_label_value_text = _ocr._validate_ocr_label_value_text
    _build_ocr_inline_label_candidate = _ocr._build_ocr_inline_label_candidate
    _build_ocr_inline_value_candidate = _ocr._build_ocr_inline_value_candidate
    _join_inline_and_ocr_value_text = _ocr._join_inline_and_ocr_value_text
    _join_ocr_block_text = _ocr._join_ocr_block_text
    _build_ocr_block_candidate = _ocr._build_ocr_block_candidate
    _refine_ocr_name_candidate = _ocr._refine_ocr_name_candidate
    _ocr_name_scene_confidence = _ocr._ocr_name_scene_confidence
    _same_line_has_right_time_metadata = _ocr._same_line_has_right_time_metadata
    _next_line_has_preview_text = _ocr._next_line_has_preview_text
    _looks_like_ocr_preview_text = _ocr._looks_like_ocr_preview_text
    _looks_like_ui_time_metadata = _ocr._looks_like_ui_time_metadata
    _looks_like_bracketed_ui_label = _ocr._looks_like_bracketed_ui_label
    _remap_ocr_page_candidate = _ocr._remap_ocr_page_candidate
    _combine_bboxes = _ocr._combine_bboxes
    _bbox_center_y = _ocr._bbox_center_y
    _clamped_ocr_tolerance = _ocr._clamped_ocr_tolerance
    _derive_address_block_candidates = _ocr._derive_address_block_candidates
    _build_shadow_text = _collectors._build_shadow_text
    _shadow_token = _collectors._shadow_token
    _name_component_from_matched_by = _collectors._name_component_from_matched_by
    _name_component_metadata = _collectors._name_component_metadata
    _collect_dictionary_hits = _collectors._collect_dictionary_hits
    _collect_context_hits = _collectors._collect_context_hits
    _trim_context_value = _collectors._trim_context_value
    _is_context_masked_text_candidate = _collectors._is_context_masked_text_candidate
    _contains_mask_char = _collectors._contains_mask_char
    _is_repeated_mask_text = _collectors._is_repeated_mask_text
    _collect_regex_hits = _collectors._collect_regex_hits
    _collect_generic_number_hits = _collectors._collect_generic_number_hits
    _upsert_regex_candidate = _collectors._upsert_regex_candidate
    _resolve_regex_match = _collectors._resolve_regex_match
    _numeric_candidate_types = _collectors._numeric_candidate_types
    _preferred_numeric_attr_type = _collectors._preferred_numeric_attr_type
    _numeric_keyword_bias = _collectors._numeric_keyword_bias
    _has_other_number_context = _collectors._has_other_number_context
    _match_context_window = _collectors._match_context_window
    _window_has_keywords = _collectors._window_has_keywords
    _looks_like_cn_id_with_birthdate = _collectors._looks_like_cn_id_with_birthdate
    _is_non_id_driver_license_shape = _collectors._is_non_id_driver_license_shape
    _is_strong_driver_license_shape = _collectors._is_strong_driver_license_shape
    _same_span_numeric_regex_items = _collectors._same_span_numeric_regex_items
    _is_regex_numeric_candidate = _collectors._is_regex_numeric_candidate
    _is_regex_numeric_candidate_type = _collectors._is_regex_numeric_candidate_type
    _is_regex_ambiguous_number_candidate = _collectors._is_regex_ambiguous_number_candidate
    _merge_ambiguous_numeric_candidate = _collectors._merge_ambiguous_numeric_candidate
    _collect_name_hits = _collectors._collect_name_hits
    _collect_generic_name_fragment_hits = _collectors._collect_generic_name_fragment_hits
    _collect_masked_text_hits = _collectors._collect_masked_text_hits
    _collect_address_candidates = _address_pipeline.collect_address_candidates
    _extract_match = _collectors._extract_match
    _remap_shadow_span = _collectors._remap_shadow_span
    _find_literal_matches = _collectors._find_literal_matches
    _find_index_dictionary_matches = _collectors._find_index_dictionary_matches
    _select_dictionary_matches = _collectors._select_dictionary_matches
    _build_ambiguous_dictionary_match = _collectors._build_ambiguous_dictionary_match
    _protected_spans_from_dictionary_hits = _collectors._protected_spans_from_dictionary_hits
    _protected_spans_from_candidates = _collectors._protected_spans_from_candidates
    _meets_confidence_threshold = _validation._meets_confidence_threshold
    _clean_extracted_value = _validation._clean_extracted_value
    _clean_phone_candidate = _validation._clean_phone_candidate
    _strip_ocr_break_edge_noise = _validation._strip_ocr_break_edge_noise
    _active_ocr_context = _validation._active_ocr_context
    _ocr_span_block_indices = _validation._ocr_span_block_indices
    _contains_field_keyword = _validation._contains_field_keyword
    _ocr_block_pii_context_signal = _validation._ocr_block_pii_context_signal
    _is_relevant_vertical_ocr_neighbor = _validation._is_relevant_vertical_ocr_neighbor
    _ocr_neighbor_pii_context_score = _validation._ocr_neighbor_pii_context_score
    _detected_candidate_context_score = _validation._detected_candidate_context_score
    _clean_address_candidate = _validation._clean_address_candidate
    _clean_organization_candidate = _validation._clean_organization_candidate
    _is_name_dictionary_match_allowed = _validation._is_name_dictionary_match_allowed
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
    _standalone_name_confidence = _validation._standalone_name_confidence
    _english_standalone_name_confidence = _validation._english_standalone_name_confidence
    _zh_standalone_name_confidence = _validation._zh_standalone_name_confidence
    _generic_name_confidence = _validation._generic_name_confidence
    _ocr_standalone_name_confidence = _validation._ocr_standalone_name_confidence
    _strong_standalone_name_confidence = _validation._strong_standalone_name_confidence
    _is_cjk_char = _validation._is_cjk_char
    _canonical_name_source_text = _validation._canonical_name_source_text
    _canonical_name_component_source_text = _validation._canonical_name_component_source_text
    _compact_name_value = _validation._compact_name_value
    _is_en_phone_candidate = _validation._is_en_phone_candidate
    _is_phone_candidate = _validation._is_phone_candidate
    _is_context_phone_candidate = _validation._is_context_phone_candidate
    _is_card_number_candidate = _validation._is_card_number_candidate
    _is_context_card_number_candidate = _validation._is_context_card_number_candidate
    _is_bank_account_candidate = _validation._is_bank_account_candidate
    _is_passport_candidate = _validation._is_passport_candidate
    _is_driver_license_candidate = _validation._is_driver_license_candidate
    _is_email_candidate = _validation._is_email_candidate
    _is_id_candidate = _validation._is_id_candidate
    _is_other_candidate = _validation._is_other_candidate
    _passes_luhn = _validation._passes_luhn
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
    _dictionary_match_metadata = _validation._dictionary_match_metadata
    _candidate_metadata = _validation._candidate_metadata
    _merge_candidate_metadata = _validation._merge_candidate_metadata
    _to_attr_type = _validation._to_attr_type
