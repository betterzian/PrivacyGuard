"""由基础 ``DecisionContext`` 推导决策策略视图。"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.utils.pii_value import canonicalize_pii_value

_ADDRESS_HINT_TOKENS = ("省", "市", "区", "县", "路", "街", "道", "号", "小区", "公寓")
_HIGH_CANDIDATE_CONFIDENCE = 0.85
_LOW_CANDIDATE_CONFIDENCE = 0.5
_LOW_OCR_BLOCK_SCORE = 0.75
_MASK_CHARS = set("*＊xX×#＃•●○◦◯_＿?？")
_ATTR_LABELS = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.LOCATION_CLUE: "位置",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.CARD_NUMBER: "卡号",
    PIIAttributeType.BANK_ACCOUNT: "银行账号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.OTHER: "敏感信息",
}


@dataclass(slots=True)
class DerivedDecisionPolicyContext:
    raw_refs: dict[str, object]
    candidate_policy_views: list[dict[str, object]]
    page_policy_state: dict[str, object]
    persona_policy_states: list[dict[str, object]]


def derive_policy_context(context: DecisionContext) -> DerivedDecisionPolicyContext:
    refs = raw_refs(context)
    candidate_views = _prebuilt_candidate_policy_views(context)
    page_state = _prebuilt_page_policy_state(context)
    persona_states = _prebuilt_persona_policy_states(context)

    if candidate_views is None:
        candidate_views = _build_candidate_policy_views(context)
    if page_state is None:
        page_state = _build_page_policy_state(context)
    if persona_states is None:
        persona_states = _build_persona_policy_states(context)

    return DerivedDecisionPolicyContext(
        raw_refs=refs,
        candidate_policy_views=candidate_views,
        page_policy_state=page_state,
        persona_policy_states=persona_states,
    )


def raw_refs(context: DecisionContext) -> dict[str, object]:
    refs = getattr(context, "raw_refs", None)
    payload = dict(refs) if isinstance(refs, dict) else {}

    candidate_by_id = payload.get("candidate_by_id")
    if not isinstance(candidate_by_id, dict):
        candidate_by_id = {candidate.entity_id: candidate for candidate in context.candidates}

    ocr_block_by_id = payload.get("ocr_block_by_id")
    if not isinstance(ocr_block_by_id, dict):
        ocr_block_by_id = {block.block_id: block for block in context.ocr_blocks if block.block_id}

    persona_by_id = payload.get("persona_by_id")
    if not isinstance(persona_by_id, dict):
        persona_by_id = {persona.persona_id: persona for persona in context.persona_profiles}

    history_records = payload.get("history_records")
    if not isinstance(history_records, list):
        history_records = list(context.history_records)

    return {
        "prompt_text": payload.get("prompt_text", context.prompt_text),
        "candidate_by_id": candidate_by_id,
        "ocr_block_by_id": ocr_block_by_id,
        "history_records": history_records,
        "persona_by_id": persona_by_id,
        "session_binding": payload.get("session_binding", context.session_binding),
    }


def candidate_policy_views(context: DecisionContext) -> list[dict[str, object]]:
    return derive_policy_context(context).candidate_policy_views


def page_policy_state(context: DecisionContext) -> dict[str, object]:
    return derive_policy_context(context).page_policy_state


def persona_policy_states(context: DecisionContext) -> list[dict[str, object]]:
    return derive_policy_context(context).persona_policy_states


def candidate_by_id(context: DecisionContext) -> dict[str, object]:
    return dict(raw_refs(context).get("candidate_by_id", {}))


def persona_by_id(context: DecisionContext) -> dict[str, object]:
    return dict(raw_refs(context).get("persona_by_id", {}))


def ocr_block_by_id(context: DecisionContext) -> dict[str, object]:
    return dict(raw_refs(context).get("ocr_block_by_id", {}))


def _prebuilt_candidate_policy_views(context: DecisionContext) -> list[dict[str, object]] | None:
    views = getattr(context, "candidate_policy_views", None)
    if not isinstance(views, list):
        return None
    return [view for view in views if isinstance(view, dict)]


def _prebuilt_page_policy_state(context: DecisionContext) -> dict[str, object] | None:
    state = getattr(context, "page_policy_state", None)
    if not isinstance(state, dict):
        return None
    return dict(state)


def _prebuilt_persona_policy_states(context: DecisionContext) -> list[dict[str, object]] | None:
    states = getattr(context, "persona_policy_states", None)
    if not isinstance(states, list):
        return None
    return [state for state in states if isinstance(state, dict)]


def _build_candidate_policy_views(context: DecisionContext) -> list[dict[str, object]]:
    ocr_items = list(context.ocr_blocks)
    candidate_items = list(context.candidates)
    history_records = list(context.history_records)
    block_map = {block.block_id: block for block in ocr_items if block.block_id}
    geometry_bounds = _page_geometry_bounds(ocr_items=ocr_items, candidates=candidate_items)

    attr_counter = Counter(candidate.attr_type for candidate in candidate_items)
    text_counter = Counter((candidate.normalized_text or candidate.text) for candidate in candidate_items)
    alias_by_candidate = {candidate.entity_id: _alias_value(candidate) for candidate in candidate_items}
    alias_counter = Counter(alias_by_candidate.values())
    alias_sources: defaultdict[str, set[PIISourceType]] = defaultdict(set)
    for candidate in candidate_items:
        alias_sources[alias_by_candidate[candidate.entity_id]].add(candidate.source)

    history_alias_counter = Counter(
        alias_value
        for alias_value in (_record_alias_value(record) for record in history_records)
        if alias_value
    )
    history_attr_counter = Counter(record.attr_type for record in history_records)

    return [
        _build_candidate_policy_view(
            candidate=candidate,
            prompt_text=context.prompt_text,
            block_map=block_map,
            history_records=history_records,
            history_alias_counter=history_alias_counter,
            history_attr_counter=history_attr_counter,
            attr_counter=attr_counter,
            text_counter=text_counter,
            geometry_bounds=geometry_bounds,
            alias_value=alias_by_candidate[candidate.entity_id],
            alias_counter=alias_counter,
            alias_sources=alias_sources,
        )
        for candidate in candidate_items
    ]


def _build_page_policy_state(context: DecisionContext) -> dict[str, object]:
    ocr_items = list(context.ocr_blocks)
    candidate_items = list(context.candidates)
    history_records = list(context.history_records)
    protection_level = _normalize_protection_level(context.protection_level)
    source_counter = Counter(candidate.source for candidate in candidate_items)

    candidate_confidences = [candidate.confidence for candidate in candidate_items]
    ocr_scores = [block.score for block in ocr_items]
    candidate_count = len(candidate_items)
    unique_attr_count = len({candidate.attr_type for candidate in candidate_items})
    avg_det_conf = sum(candidate_confidences) / len(candidate_confidences) if candidate_confidences else 0.0
    min_det_conf = min(candidate_confidences) if candidate_confidences else 0.0
    avg_ocr_conf = sum(ocr_scores) / len(ocr_scores) if ocr_scores else 0.0
    min_ocr_conf = min(ocr_scores) if ocr_scores else 0.0
    low_ocr_ratio = (
        sum(score < _LOW_OCR_BLOCK_SCORE for score in ocr_scores) / len(ocr_scores)
        if ocr_scores
        else 0.0
    )

    return {
        "protection_level": protection_level.value,
        "candidate_count_bucket": _bucket_count(candidate_count),
        "unique_attr_count_bucket": _bucket_count(unique_attr_count),
        "avg_det_conf_bucket": _bucket_confidence(avg_det_conf),
        "min_det_conf_bucket": _bucket_confidence(min_det_conf),
        "avg_ocr_conf_bucket": _bucket_confidence(avg_ocr_conf),
        "low_ocr_ratio_bucket": _bucket_ratio(low_ocr_ratio),
        "page_quality_state": _page_quality_state(
            avg_det_conf=avg_det_conf,
            avg_ocr_conf=avg_ocr_conf,
            low_ocr_ratio=low_ocr_ratio,
            has_ocr=bool(ocr_scores),
        ),
        "_prompt_length": len(context.prompt_text),
        "_ocr_block_count": len(ocr_items),
        "_candidate_count": candidate_count,
        "_unique_attr_count": unique_attr_count,
        "_history_record_count": len(history_records),
        "_active_persona_bound": bool(context.session_binding and context.session_binding.active_persona_id),
        "_prompt_has_digits": any(char.isdigit() for char in context.prompt_text),
        "_prompt_has_address_tokens": any(token in context.prompt_text for token in _ADDRESS_HINT_TOKENS),
        "_average_candidate_confidence": avg_det_conf,
        "_min_candidate_confidence": min_det_conf,
        "_high_confidence_candidate_ratio": (
            sum(score >= _HIGH_CANDIDATE_CONFIDENCE for score in candidate_confidences) / len(candidate_confidences)
            if candidate_confidences
            else 0.0
        ),
        "_low_confidence_candidate_ratio": (
            sum(score < _LOW_CANDIDATE_CONFIDENCE for score in candidate_confidences) / len(candidate_confidences)
            if candidate_confidences
            else 0.0
        ),
        "_prompt_candidate_count": source_counter[PIISourceType.PROMPT],
        "_ocr_candidate_count": source_counter[PIISourceType.OCR],
        "_average_ocr_block_score": avg_ocr_conf,
        "_min_ocr_block_score": min_ocr_conf,
        "_low_confidence_ocr_block_ratio": low_ocr_ratio,
    }


def _build_persona_policy_states(context: DecisionContext) -> list[dict[str, object]]:
    active_persona_id = context.session_binding.active_persona_id if context.session_binding else None
    return [
        _build_persona_view(
            persona=persona,
            candidates=list(context.candidates),
            active_persona_id=active_persona_id,
        )
        for persona in context.persona_profiles
    ]


def _build_alias_view(
    *,
    candidate: PIICandidate,
    alias_value: str,
    alias_counter: Counter,
    alias_sources: dict[str, set[PIISourceType]],
    history_alias_counter: Counter,
) -> dict[str, object]:
    return {
        "session_alias": alias_value,
        "same_alias_count_in_turn": alias_counter[alias_value],
        "cross_source_same_alias_flag": len(alias_sources.get(alias_value, set())) > 1,
        "history_alias_exposure_bucket": _bucket_count(history_alias_counter[alias_value]),
        "_history_alias_exposure_count": history_alias_counter[alias_value],
        "_alias_attr_type": candidate.attr_type,
    }


def _build_local_context_view(
    *,
    candidate: PIICandidate,
    prompt_text: str,
    block_map: dict[str, OCRTextBlock],
) -> dict[str, object]:
    covered_block_ids = _covered_block_ids(candidate)
    cross_block_flag = len(covered_block_ids) > 1
    prompt_context = _text_window(
        text=prompt_text,
        source_text=candidate.text,
        start=candidate.span_start if candidate.source == PIISourceType.PROMPT else None,
        end=candidate.span_end if candidate.source == PIISourceType.PROMPT else None,
    )
    ocr_source_text = _merged_ocr_context_text(covered_block_ids=covered_block_ids, block_map=block_map)
    if not ocr_source_text and candidate.block_id and candidate.block_id in block_map:
        ocr_source_text = block_map[candidate.block_id].text
    ocr_context = _text_window(
        text=ocr_source_text,
        source_text=candidate.text,
        start=candidate.span_start if candidate.source == PIISourceType.OCR and not cross_block_flag else None,
        end=candidate.span_end if candidate.source == PIISourceType.OCR and not cross_block_flag else None,
    )
    label_token = _context_label(candidate.attr_type)
    return {
        "cross_block_flag": cross_block_flag,
        "covered_block_count_bucket": _bucket_count(len(covered_block_ids)),
        "prompt_local_context_labelized": _labelize_context(prompt_context, candidate.text, label_token),
        "ocr_local_context_labelized": _labelize_context(ocr_context, candidate.text, label_token),
        "_covered_block_ids": covered_block_ids,
        "_prompt_context": prompt_context,
        "_ocr_context": ocr_context,
    }


def _build_quality_view(
    *,
    candidate: PIICandidate,
    block_map: dict[str, OCRTextBlock],
    local_context_view: dict[str, object],
) -> dict[str, object]:
    covered_block_ids = [str(item) for item in local_context_view.get("_covered_block_ids", [])]
    covered_blocks = [block_map[block_id] for block_id in covered_block_ids if block_id in block_map]
    primary_block = block_map.get(candidate.block_id) if candidate.block_id else (covered_blocks[0] if covered_blocks else None)
    if covered_blocks:
        ocr_local_conf = sum(block.score for block in covered_blocks) / len(covered_blocks)
    elif primary_block is not None:
        ocr_local_conf = primary_block.score
    else:
        ocr_local_conf = 0.0
    return {
        "det_conf_bucket": _bucket_confidence(candidate.confidence),
        "ocr_local_conf_bucket": _bucket_confidence(ocr_local_conf),
        "low_ocr_flag": bool(covered_blocks or primary_block) and ocr_local_conf < _LOW_OCR_BLOCK_SCORE,
        "_ocr_block_score": primary_block.score if primary_block is not None else 0.0,
        "_ocr_block_rotation_degrees": primary_block.rotation_degrees if primary_block is not None else 0.0,
        "_ocr_local_conf": ocr_local_conf,
    }


def _build_persona_view(
    *,
    persona: PersonaProfile,
    candidates: list[PIICandidate],
    active_persona_id: str | None,
) -> dict[str, object]:
    candidate_attrs = {candidate.attr_type for candidate in candidates}
    supported_attrs = set(persona.slots.keys())
    exposure_count = int(persona.stats.get("exposure_count", 0) or 0)
    exposure_bucket = _bucket_count(exposure_count)
    supported_attr_mask = {attr.value: attr in supported_attrs for attr in PIIAttributeType}
    available_slot_mask = {
        attr.value: bool(str(persona.slots.get(attr, "")).strip()) if attr in supported_attrs else False
        for attr in PIIAttributeType
    }
    attr_exposure_buckets = {
        attr.value: exposure_bucket if attr in supported_attrs else "0"
        for attr in PIIAttributeType
    }
    return {
        "persona_id": persona.persona_id,
        "is_active": persona.persona_id == active_persona_id,
        "supported_attr_mask": supported_attr_mask,
        "available_slot_mask": available_slot_mask,
        "attr_exposure_buckets": attr_exposure_buckets,
        "matched_candidate_attr_count": len(candidate_attrs.intersection(supported_attrs)),
        "_slot_count": len(persona.slots),
        "_display_name": persona.display_name,
        "_exposure_count": exposure_count,
        "_last_exposed_session_id": _stats_value_as_str(persona.stats.get("last_exposed_session_id")),
        "_last_exposed_turn_id": _stats_value_as_int(persona.stats.get("last_exposed_turn_id")),
        "_supported_attr_types": sorted(supported_attrs, key=lambda item: item.value),
        "_slots": persona.slots,
    }


def _build_candidate_policy_view(
    *,
    candidate: PIICandidate,
    prompt_text: str,
    block_map: dict[str, OCRTextBlock],
    history_records: list[ReplacementRecord],
    history_alias_counter: Counter,
    history_attr_counter: Counter,
    attr_counter: Counter,
    text_counter: Counter,
    geometry_bounds: tuple[int, int],
    alias_value: str,
    alias_counter: Counter,
    alias_sources: dict[str, set[PIISourceType]],
) -> dict[str, object]:
    alias_view = _build_alias_view(
        candidate=candidate,
        alias_value=alias_value,
        alias_counter=alias_counter,
        alias_sources=alias_sources,
        history_alias_counter=history_alias_counter,
    )
    local_context_view = _build_local_context_view(
        candidate=candidate,
        prompt_text=prompt_text,
        block_map=block_map,
    )
    quality_view = _build_quality_view(
        candidate=candidate,
        block_map=block_map,
        local_context_view=local_context_view,
    )

    history_exact_match_count = _history_exact_match_count(candidate, history_records)
    same_attr_page_count = attr_counter[candidate.attr_type]
    key_text = candidate.normalized_text or candidate.text
    same_text_page_count = text_counter[key_text]
    relative_area, aspect_ratio, center_x, center_y = _geometry_features(candidate.bbox, geometry_bounds)
    normalized_text = candidate.normalized_text or candidate.text
    digit_ratio = _digit_ratio(normalized_text)
    return {
        "candidate_id": candidate.entity_id,
        "attr_type": candidate.attr_type,
        "attr_id": candidate.attr_type.value,
        "source": candidate.source,
        **alias_view,
        "history_exact_match_bucket": _bucket_count(history_exact_match_count),
        "det_conf_bucket": quality_view["det_conf_bucket"],
        "ocr_local_conf_bucket": quality_view["ocr_local_conf_bucket"],
        "low_ocr_flag": quality_view["low_ocr_flag"],
        "cross_block_flag": local_context_view["cross_block_flag"],
        "covered_block_count_bucket": local_context_view["covered_block_count_bucket"],
        "same_attr_page_bucket": _bucket_count(same_attr_page_count),
        "normalized_len_bucket": _bucket_text_length(len(normalized_text)),
        "digit_ratio_bucket": _bucket_ratio(digit_ratio),
        "mask_char_flag": _contains_mask_char(candidate.text),
        "prompt_local_context_labelized": local_context_view["prompt_local_context_labelized"],
        "ocr_local_context_labelized": local_context_view["ocr_local_context_labelized"],
        "_prompt_context": local_context_view["_prompt_context"],
        "_ocr_context": local_context_view["_ocr_context"],
        "_history_attr_exposure_count": history_attr_counter[candidate.attr_type],
        "_history_exact_match_count": history_exact_match_count,
        "_same_attr_page_count": same_attr_page_count,
        "_same_text_page_count": same_text_page_count,
        "_relative_area": relative_area,
        "_aspect_ratio": aspect_ratio,
        "_center_x": center_x,
        "_center_y": center_y,
        "_confidence": candidate.confidence,
        "_ocr_block_score": quality_view["_ocr_block_score"],
        "_ocr_block_rotation_degrees": quality_view["_ocr_block_rotation_degrees"],
        "_ocr_local_conf": quality_view["_ocr_local_conf"],
    }


def _record_alias_value(record: ReplacementRecord) -> str | None:
    source_text = record.canonical_source_text or record.source_text
    if not source_text:
        return None
    try:
        canonical = canonicalize_pii_value(record.attr_type, source_text)
    except Exception:
        canonical = source_text.strip()
    return f"{record.attr_type.value}:{canonical or source_text.strip()}"


def _alias_value(candidate: PIICandidate) -> str:
    source_text = candidate.canonical_source_text or candidate.normalized_text or candidate.text
    try:
        canonical = canonicalize_pii_value(candidate.attr_type, source_text)
    except Exception:
        canonical = source_text.strip()
    stable_value = canonical or source_text.strip() or candidate.entity_id
    return f"{candidate.attr_type.value}:{stable_value}"


def _history_exact_match_count(candidate: PIICandidate, history_records: list[ReplacementRecord]) -> int:
    candidate_source_texts = {
        candidate.text,
        candidate.normalized_text,
        candidate.canonical_source_text or "",
    }
    return sum(
        1
        for record in history_records
        if (record.canonical_source_text or record.source_text) in candidate_source_texts
        or record.source_text in candidate_source_texts
    )


def _covered_block_ids(candidate: PIICandidate) -> list[str]:
    metadata_ids = candidate.metadata.get("ocr_block_ids", [])
    ordered: list[str] = []
    for item in metadata_ids:
        text = str(item).strip()
        if text and text not in ordered:
            ordered.append(text)
    if candidate.block_id and candidate.block_id not in ordered:
        ordered.append(candidate.block_id)
    return ordered


def _merged_ocr_context_text(*, covered_block_ids: list[str], block_map: dict[str, OCRTextBlock]) -> str:
    parts = [block_map[block_id].text for block_id in covered_block_ids if block_id in block_map]
    return " ".join(part for part in parts if part)


def _page_geometry_bounds(
    *,
    ocr_items: list[OCRTextBlock],
    candidates: list[PIICandidate],
) -> tuple[int, int]:
    max_right = 1
    max_bottom = 1
    for item in list(ocr_items) + [candidate for candidate in candidates if candidate.bbox is not None]:
        bbox = item.bbox
        if bbox is None:
            continue
        max_right = max(max_right, bbox.x + bbox.width)
        max_bottom = max(max_bottom, bbox.y + bbox.height)
    return (max_right, max_bottom)


def _geometry_features(
    bbox: BoundingBox | None,
    geometry_bounds: tuple[int, int],
) -> tuple[float, float, float, float]:
    if bbox is None:
        return (0.0, 0.0, 0.0, 0.0)
    max_right, max_bottom = geometry_bounds
    page_area = max(1, max_right * max_bottom)
    relative_area = min(1.0, (bbox.width * bbox.height) / page_area)
    aspect_ratio = bbox.width / max(1, bbox.height)
    center_x = min(1.0, max(0.0, (bbox.x + bbox.width / 2) / max_right))
    center_y = min(1.0, max(0.0, (bbox.y + bbox.height / 2) / max_bottom))
    return (relative_area, aspect_ratio, center_x, center_y)


def _text_window(
    *,
    text: str,
    source_text: str,
    start: int | None,
    end: int | None,
    radius: int = 10,
) -> str:
    if not text:
        return ""
    if start is not None and end is not None and 0 <= start < end <= len(text):
        left = max(0, start - radius)
        right = min(len(text), end + radius)
        return text[left:right]
    if source_text:
        index = text.find(source_text)
        if index >= 0:
            left = max(0, index - radius)
            right = min(len(text), index + len(source_text) + radius)
            return text[left:right]
    return text[: radius * 2]


def _labelize_context(context_text: str, source_text: str, label_token: str) -> str:
    if not context_text:
        return ""
    if source_text and source_text in context_text:
        return context_text.replace(source_text, label_token, 1)
    return context_text


def _context_label(attr_type: PIIAttributeType) -> str:
    return f"[{_ATTR_LABELS.get(attr_type, '敏感信息')}]"


def _contains_mask_char(text: str) -> bool:
    return any(char in _MASK_CHARS for char in text)


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(char.isdigit() for char in text) / max(1, len(text))


def _bucket_count(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 7:
        return "4-7"
    return "8+"


def _bucket_text_length(value: int) -> str:
    if value <= 0:
        return "0"
    if value <= 2:
        return "1-2"
    if value <= 4:
        return "3-4"
    if value <= 8:
        return "5-8"
    return "9+"


def _bucket_confidence(value: float) -> str:
    if value <= 0.0:
        return "none"
    if value < _LOW_CANDIDATE_CONFIDENCE:
        return "low"
    if value < _HIGH_CANDIDATE_CONFIDENCE:
        return "medium"
    return "high"


def _bucket_ratio(value: float) -> str:
    if value <= 0.0:
        return "none"
    if value < 0.34:
        return "low"
    if value < 0.67:
        return "medium"
    return "high"


def _page_quality_state(
    *,
    avg_det_conf: float,
    avg_ocr_conf: float,
    low_ocr_ratio: float,
    has_ocr: bool,
) -> str:
    if avg_det_conf < _LOW_CANDIDATE_CONFIDENCE:
        return "poor"
    if has_ocr and (avg_ocr_conf < _LOW_OCR_BLOCK_SCORE or low_ocr_ratio > 0.5):
        return "poor"
    if avg_det_conf >= _HIGH_CANDIDATE_CONFIDENCE and (not has_ocr or avg_ocr_conf >= _HIGH_CANDIDATE_CONFIDENCE):
        return "good"
    return "mixed"


def _stats_value_as_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _stats_value_as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_protection_level(protection_level: ProtectionLevel | str) -> ProtectionLevel:
    if isinstance(protection_level, ProtectionLevel):
        return protection_level
    normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
    return ProtectionLevel(normalized)
