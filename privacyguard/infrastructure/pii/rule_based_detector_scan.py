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
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
    organization_shadow = self._build_shadow_text(text, collected)
    self._collect_organization_hits(
        collected,
        organization_shadow.text,
        source,
        bbox,
        block_id,
        skip_spans=protected_spans,
        rule_profile=rule_profile,
        original_text=text,
        shadow_index_map=organization_shadow.index_map,
    )
    protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
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
    self._collect_address_hits(
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
    document = self._build_ocr_page_document(ocr_blocks)
    if document is None:
        return remapped_candidates
    scene_index = self._build_ocr_scene_index(document.blocks)
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
                remapped_candidates.append(refined)
        remapped_candidates.extend(self._derive_address_block_candidates(candidate, document))
    return remapped_candidates
