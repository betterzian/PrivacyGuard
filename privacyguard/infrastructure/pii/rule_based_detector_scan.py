"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _scan_text(
    self,
    text: str,
    source: PIISourceType,
    bbox: object,
    block_id: str | None,
    *,
    session_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
    local_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
    rule_profile: _RuleStrengthProfile,
) -> list[PIICandidate]:
    """对单段文本执行分层识别。

    顺序按精度从高到低推进，并在组间刷新 protected spans：
    session -> local -> (context + regex) -> organization -> name -> address
    """
    collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
    self._collect_dictionary_hits(
        collected,
        text,
        source,
        bbox,
        block_id,
        dictionary_index=session_index,
    )
    protected_spans = self._protected_spans_from_dictionary_hits(collected, rule_profile=rule_profile)
    self._collect_dictionary_hits(
        collected,
        text,
        source,
        bbox,
        block_id,
        dictionary_index=local_index,
        skip_spans=protected_spans,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    self._collect_context_hits(
        collected,
        text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    self._collect_regex_hits(collected, text, source, bbox, block_id, skip_spans=protected_spans)
    # 组织候选已并入地址事件流扫描（见 address pipeline），此处不再单独扫描。
    name_shadow = self._build_shadow_text(text, collected)
    self._collect_name_hits(
        collected,
        name_shadow.text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
        original_text=text,
        shadow_index_map=name_shadow.index_map,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    address_shadow = self._build_shadow_text(text, collected)
    self._collect_address_candidates(
        collected,
        address_shadow.text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
        original_text=text,
        shadow_index_map=address_shadow.index_map,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    location_shadow = self._build_shadow_text(text, collected)
    self._collect_geo_fragment_hits(
        collected,
        location_shadow.text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
        original_text=text,
        shadow_index_map=location_shadow.index_map,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    self._collect_generic_number_hits(
        collected,
        text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    masked_shadow = self._build_shadow_text(text, collected)
    self._collect_masked_text_hits(
        collected,
        masked_shadow.text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
        original_text=text,
        shadow_index_map=masked_shadow.index_map,
    )
    should_run_standalone = not (
        source == PIISourceType.OCR
        and block_id is None
        and bbox is None
        and getattr(self, "_active_ocr_page_document", None) is not None
    )
    if should_run_standalone:
        previous_context_text = getattr(self, "_active_standalone_context_text", None)
        previous_context_candidates = getattr(self, "_active_standalone_context_candidates", ())
        self._active_standalone_context_text = text
        self._active_standalone_context_candidates = tuple(collected.values())
        try:
            protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
            standalone_shadow = self._build_shadow_text(text, collected)
            self._collect_generic_name_fragment_hits(
                collected,
                standalone_shadow.text,
                source,
                bbox,
                block_id,
                skip_spans=protected_spans,
                rule_profile=rule_profile,
                original_text=text,
                shadow_index_map=standalone_shadow.index_map,
            )
        finally:
            self._active_standalone_context_text = previous_context_text
            self._active_standalone_context_candidates = previous_context_candidates
    return [
        candidate
        for candidate in collected.values()
        if self._meets_confidence_threshold(candidate.attr_type, candidate.confidence, rule_profile)
    ]

def _scan_ocr_page(
    self,
    ocr_blocks: list[OCRTextBlock],
    *,
    session_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
    local_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
    rule_profile: _RuleStrengthProfile,
) -> list[PIICandidate]:
    """将整页 OCR 聚合成单文档扫描，再映射回原始 block。"""
    remapped_candidates: list[PIICandidate] = []
    signature_to_index: dict[tuple[str, str, tuple[str, ...]], int] = {}
    scene_index = self._build_ocr_scene_index(tuple(ocr_blocks))
    document = self._build_ocr_page_document(scene_index)
    if document is None:
        return remapped_candidates
    previous_document = self._active_ocr_page_document
    previous_scene_index = self._active_ocr_scene_index
    self._active_ocr_page_document = document
    self._active_ocr_scene_index = scene_index
    try:
        document_candidates = self._scan_text(
            document.text,
            PIISourceType.OCR,
            bbox=None,
            block_id=None,
            session_index=session_index,
            local_index=local_index,
            rule_profile=rule_profile,
        )
        for candidate in document_candidates:
            remapped = self._remap_ocr_page_candidate(candidate, document)
            if remapped is not None:
                refined = self._refine_ocr_name_candidate(remapped, document, scene_index, rule_profile)
                if refined is not None:
                    signature_to_index[self._ocr_candidate_signature(refined)] = len(remapped_candidates)
                    remapped_candidates.append(refined)
            derived_candidates = self._derive_address_block_candidates(candidate, document)
            for derived_candidate in derived_candidates:
                signature_to_index[self._ocr_candidate_signature(derived_candidate)] = len(remapped_candidates)
                remapped_candidates.append(derived_candidate)
        for candidate in self._collect_ocr_label_adjacency_candidates(document, scene_index, rule_profile):
            signature = self._ocr_candidate_signature(candidate)
            existing_index = signature_to_index.get(signature)
            if existing_index is not None:
                existing = remapped_candidates[existing_index]
                existing.metadata = self._merge_candidate_metadata(existing.metadata, candidate.metadata)
                existing.confidence = max(existing.confidence, candidate.confidence)
                continue
            signature_to_index[signature] = len(remapped_candidates)
            remapped_candidates.append(candidate)
        for candidate in self._collect_ocr_standalone_name_candidates(
            document,
            scene_index,
            tuple(remapped_candidates),
            rule_profile,
        ):
            signature = self._ocr_candidate_signature(candidate)
            existing_index = signature_to_index.get(signature)
            if existing_index is not None:
                existing = remapped_candidates[existing_index]
                existing.metadata = self._merge_candidate_metadata(existing.metadata, candidate.metadata)
                existing.confidence = max(existing.confidence, candidate.confidence)
                continue
            signature_to_index[signature] = len(remapped_candidates)
            remapped_candidates.append(candidate)
    finally:
        self._active_ocr_page_document = previous_document
        self._active_ocr_scene_index = previous_scene_index
    return remapped_candidates
