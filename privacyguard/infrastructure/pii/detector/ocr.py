"""OCR remap、标签绑定与 ownership 后处理。"""

from __future__ import annotations

from dataclasses import dataclass, replace

from privacyguard.domain.enums import PIISourceType, PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, OCRScene, OCRSceneBlock, ParseResult, StreamEvent, StreamInput
from privacyguard.infrastructure.pii.detector.stacks import (
    build_address_candidates_from_value,
    build_name_candidate_from_value,
    build_organization_candidate_from_value,
    has_address_signal,
    has_organization_suffix,
)


@dataclass(frozen=True, slots=True)
class OCROwnershipProposal:
    event: StreamEvent
    label_block: OCRSceneBlock
    candidate_blocks: tuple[OCRSceneBlock, ...]


def apply_ocr_geometry(
    *,
    stream: StreamInput,
    scene: OCRScene,
    bundle,
    parsed: ParseResult,
) -> list[CandidateDraft]:
    remapped = [_remap_candidate(candidate, stream, scene) for candidate in parsed.candidates]
    label_block_ids = {
        block_id
        for event in bundle.label_events
        for block_id in [_event_block_id(stream, event)]
        if block_id
    }
    proposals: list[OCROwnershipProposal] = []
    for event in bundle.label_events:
        if event.event_id in parsed.handled_label_ids:
            continue
        label_block = _event_scene_block(stream, scene, event)
        if label_block is None:
            continue
        bound = _find_existing_bound_candidate(event, label_block, remapped, scene)
        if bound is not None:
            _bind_label_to_candidate(bound, event)
            continue
        candidate_blocks = _find_candidate_blocks(label_block, scene, label_block_ids)
        if not candidate_blocks:
            continue
        proposals.append(
            OCROwnershipProposal(
                event=event,
                label_block=label_block,
                candidate_blocks=candidate_blocks,
            )
        )
    extras: list[CandidateDraft] = []
    for proposal in _resolve_ownership_proposals(proposals):
        generated = _build_candidate_from_blocks(proposal.event, proposal.candidate_blocks)
        if generated is None:
            continue
        extras.append(_remap_candidate(generated, stream, scene))
    return _merge_ocr_candidates([*remapped, *extras])


def _build_candidate_from_blocks(event: StreamEvent, blocks: tuple[OCRSceneBlock, ...]) -> CandidateDraft | None:
    text = " ".join(block.block.text.strip() for block in blocks if block.block.text.strip())
    if not text:
        return None
    start = blocks[0].raw_start
    end = blocks[-1].raw_end
    matched_by = str(event.payload.get("ocr_matched_by") or event.matched_by)
    component_hint = str(event.payload.get("component_hint") or "full")
    if event.attr_type == PIIAttributeType.NAME:
        return build_name_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            matched_by=matched_by,
            component_hint=component_hint,
            label_event_id=event.event_id,
            confidence=0.91,
        )
    if event.attr_type == PIIAttributeType.ADDRESS:
        candidates = build_address_candidates_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            matched_by=matched_by,
            label_event_id=event.event_id,
        )
        return candidates[0] if candidates else None
    if event.attr_type == PIIAttributeType.ORGANIZATION:
        return build_organization_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            matched_by=matched_by,
            label_event_id=event.event_id,
            label_driven=True,
        )
    return None


def _resolve_ownership_proposals(proposals: list[OCROwnershipProposal]) -> list[OCROwnershipProposal]:
    grouped: dict[tuple[str, ...], list[OCROwnershipProposal]] = {}
    for proposal in proposals:
        key = tuple(block.block_id for block in proposal.candidate_blocks)
        grouped.setdefault(key, []).append(proposal)
    resolved: list[OCROwnershipProposal] = []
    for group in grouped.values():
        if len(group) == 1:
            score = _proposal_score(group[0])
            if score[0] > 0:
                resolved.append(group[0])
            continue
        best = max(group, key=_proposal_score)
        if _proposal_score(best)[0] <= 0:
            continue
        resolved.append(best)
    return resolved


def _proposal_score(proposal: OCROwnershipProposal) -> tuple[float, float, float]:
    text = " ".join(block.block.text.strip() for block in proposal.candidate_blocks if block.block.text.strip())
    attr_score = _attribute_segment_score(proposal.event, text)
    geometry_score = _geometry_score(proposal.label_block, proposal.candidate_blocks)
    distance_score = _distance_fallback_score(proposal.label_block, proposal.candidate_blocks)
    return (attr_score, geometry_score, distance_score)


def _attribute_segment_score(event: StreamEvent, text: str) -> float:
    sample = text.strip()
    if not sample:
        return -999.0
    if event.attr_type == PIIAttributeType.NAME:
        score = 0.0
        component_hint = str(event.payload.get("component_hint") or "full")
        if build_name_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=sample,
            value_start=0,
            value_end=len(sample),
            matched_by=event.matched_by,
            component_hint=component_hint,
            confidence=0.9,
        ) is not None:
            score += 1.4
        if has_organization_suffix(sample):
            score -= 2.2
        if has_address_signal(sample):
            score -= 1.8
        return score
    if event.attr_type == PIIAttributeType.ORGANIZATION:
        score = 0.0
        if build_organization_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=sample,
            value_start=0,
            value_end=len(sample),
            matched_by=event.matched_by,
            label_driven=True,
        ) is not None:
            score += 1.2
        if has_organization_suffix(sample):
            score += 2.4
        if has_address_signal(sample):
            score -= 0.5
        return score
    if event.attr_type == PIIAttributeType.ADDRESS:
        score = 0.0
        if build_address_candidates_from_value(
            source=PIISourceType.OCR,
            value_text=sample,
            value_start=0,
            value_end=len(sample),
            matched_by=event.matched_by,
        ):
            score += 1.2
        if has_address_signal(sample):
            score += 2.2
        if has_organization_suffix(sample):
            score -= 0.6
        return score
    return 0.0


def _geometry_score(label_block: OCRSceneBlock, blocks: tuple[OCRSceneBlock, ...]) -> float:
    first = blocks[0]
    if first.line_index == label_block.line_index and first.order_index > label_block.order_index:
        return 2.0 - (_horizontal_gap(label_block, first) / 500.0)
    return 1.0 - (_vertical_score(label_block, first) / 500.0)


def _distance_fallback_score(label_block: OCRSceneBlock, blocks: tuple[OCRSceneBlock, ...]) -> float:
    del label_block, blocks
    return 0.0


def _find_existing_bound_candidate(
    event: StreamEvent,
    label_block: OCRSceneBlock,
    candidates: list[CandidateDraft],
    scene: OCRScene,
) -> CandidateDraft | None:
    ranked: list[tuple[float, CandidateDraft]] = []
    for candidate in candidates:
        if candidate.attr_type != event.attr_type or not candidate.block_ids:
            continue
        anchor_block = _candidate_anchor_block(candidate, scene)
        if anchor_block is None:
            continue
        score = _existing_binding_score(label_block, anchor_block)
        if score <= 0:
            continue
        ranked.append((score, candidate))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _bind_label_to_candidate(candidate: CandidateDraft, event: StreamEvent) -> None:
    candidate.label_event_ids.add(event.event_id)
    metadata = dict(candidate.metadata)
    metadata["bound_label_ids"] = list(dict.fromkeys([*metadata.get("bound_label_ids", []), event.event_id]))
    metadata["matched_by"] = list(dict.fromkeys([*metadata.get("matched_by", []), str(event.payload.get("ocr_matched_by") or event.matched_by)]))
    candidate.metadata = metadata


def _candidate_anchor_block(candidate: CandidateDraft, scene: OCRScene) -> OCRSceneBlock | None:
    for block_id in candidate.block_ids:
        block = scene.id_to_block.get(block_id)
        if block is not None:
            return block
    return None


def _existing_binding_score(label_block: OCRSceneBlock, candidate_block: OCRSceneBlock) -> float:
    if candidate_block.line_index == label_block.line_index and candidate_block.order_index > label_block.order_index:
        return 3.0 - (_horizontal_gap(label_block, candidate_block) / 300.0)
    if candidate_block.line_index in {label_block.line_index + 1, label_block.line_index + 2}:
        return 2.0 - (_vertical_score(label_block, candidate_block) / 300.0)
    return -1.0


def _find_candidate_blocks(
    label_block: OCRSceneBlock,
    scene: OCRScene,
    label_block_ids: set[str],
) -> tuple[OCRSceneBlock, ...]:
    same_line = scene.line_to_blocks.get(label_block.line_index, ())
    right_blocks = [block for block in same_line if block.order_index > label_block.order_index and block.block_id not in label_block_ids]
    if right_blocks:
        first = right_blocks[0]
        if _horizontal_gap(label_block, first) <= max(240, _block_height(label_block) * 8):
            collected = [first]
            for follower in right_blocks[1:]:
                if follower.block_id in label_block_ids:
                    break
                if _horizontal_gap(collected[-1], follower) > max(90, _block_height(follower) * 3):
                    break
                collected.append(follower)
            return tuple(collected)
    for line_index in range(label_block.line_index + 1, label_block.line_index + 3):
        line_blocks = scene.line_to_blocks.get(line_index, ())
        ranked = sorted(
            [block for block in line_blocks if block.block_id not in label_block_ids],
            key=lambda block: (_vertical_score(label_block, block), block.order_index),
        )
        if not ranked:
            continue
        candidate = ranked[0]
        if _vertical_score(label_block, candidate) > max(220, _block_height(label_block) * 6):
            continue
        collected = [candidate]
        followers = [block for block in line_blocks if block.order_index > candidate.order_index and block.block_id not in label_block_ids]
        for follower in followers:
            if _horizontal_gap(collected[-1], follower) > max(90, _block_height(follower) * 3):
                break
            collected.append(follower)
        return tuple(collected)
    return ()


def _remap_candidate(candidate: CandidateDraft, stream: StreamInput, scene: OCRScene) -> CandidateDraft:
    block_refs = []
    for ref in stream.char_refs[candidate.start : candidate.end]:
        if ref is None or ref.block_id is None:
            continue
        if block_refs and block_refs[-1].block_id == ref.block_id:
            continue
        block_refs.append(ref)
    if not block_refs:
        return candidate
    block_ids = tuple(ref.block_id for ref in block_refs if ref.block_id)
    boxes = [scene.id_to_block[block_id].block.bbox for block_id in block_ids if block_id in scene.id_to_block]
    metadata = dict(candidate.metadata)
    metadata["ocr_block_ids"] = list(block_ids)
    first_ref = block_refs[0]
    last_ref = block_refs[-1]
    span_start = first_ref.block_char_index
    span_end = None
    block_id = block_ids[0] if block_ids else None
    if first_ref.block_id == last_ref.block_id and last_ref.block_char_index is not None:
        span_end = last_ref.block_char_index + 1
    return replace(
        candidate,
        block_ids=block_ids,
        block_id=block_id,
        bbox=_union_bbox(boxes),
        span_start=span_start,
        span_end=span_end,
        metadata=metadata,
    )


def _merge_ocr_candidates(candidates: list[CandidateDraft]) -> list[CandidateDraft]:
    merged: list[CandidateDraft] = []
    for candidate in candidates:
        duplicate = next(
            (
                existing
                for existing in merged
                if existing.attr_type == candidate.attr_type
                and existing.block_id == candidate.block_id
                and existing.text == candidate.text
            ),
            None,
        )
        if duplicate is None:
            merged.append(candidate)
            continue
        duplicate.confidence = max(duplicate.confidence, candidate.confidence)
        duplicate.metadata = _merge_metadata(duplicate.metadata, candidate.metadata)
    return merged


def _merge_metadata(left: dict[str, list[str]], right: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for source in (left, right):
        for key, values in source.items():
            merged[key] = list(dict.fromkeys([*merged.get(key, []), *values]))
    return merged


def _event_block_id(stream: StreamInput, event: StreamEvent) -> str | None:
    for ref in stream.char_refs[event.start : event.end]:
        if ref is not None and ref.block_id is not None:
            return ref.block_id
    return None


def _event_scene_block(stream: StreamInput, scene: OCRScene, event: StreamEvent) -> OCRSceneBlock | None:
    block_id = _event_block_id(stream, event)
    if block_id is None:
        return None
    return scene.id_to_block.get(block_id)


def _horizontal_gap(left: OCRSceneBlock, right: OCRSceneBlock) -> int:
    if left.block.bbox is None or right.block.bbox is None:
        return 9999
    return right.block.bbox.x - (left.block.bbox.x + left.block.bbox.width)


def _vertical_score(label: OCRSceneBlock, candidate: OCRSceneBlock) -> int:
    if label.block.bbox is None or candidate.block.bbox is None:
        return 9999
    y_gap = candidate.block.bbox.y - (label.block.bbox.y + label.block.bbox.height)
    x_gap = abs(label.block.bbox.x - candidate.block.bbox.x)
    return y_gap + x_gap


def _block_height(block: OCRSceneBlock) -> int:
    return block.block.bbox.height if block.block.bbox is not None else 20


def _union_bbox(boxes):
    materialized = [box for box in boxes if box is not None]
    if not materialized:
        return None
    min_x = min(box.x for box in materialized)
    min_y = min(box.y for box in materialized)
    max_x = max(box.x + box.width for box in materialized)
    max_y = max(box.y + box.height for box in materialized)
    return materialized[0].model_copy(update={"x": min_x, "y": min_y, "width": max_x - min_x, "height": max_y - min_y})
