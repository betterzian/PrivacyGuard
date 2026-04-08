"""OCR remap、标签绑定与 ownership 后处理。"""

from __future__ import annotations

from dataclasses import dataclass, replace
from statistics import median

from privacyguard.domain.enums import PIISourceType, PIIAttributeType
from privacyguard.infrastructure.pii.detector.candidate_utils import (
    NameComponentHint,
    build_address_candidate_from_value,
    build_name_candidate_from_value,
    build_organization_candidate_from_value,
    has_address_signal,
    has_organization_suffix,
    looks_like_name_value,
    looks_like_organization_value,
)
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    CandidateDraft,
    Clue,
    OCRScene,
    OCRSceneBlock,
    ParseResult,
    PreparedOCRContext,
    StreamInput,
)


@dataclass(frozen=True, slots=True)
class OCROwnershipProposal:
    event: Clue
    label_block: OCRSceneBlock
    candidate_blocks: tuple[OCRSceneBlock, ...]


def apply_ocr_geometry(
    *,
    prepared: PreparedOCRContext,
    bundle,
    parsed: ParseResult,
) -> list[CandidateDraft]:
    stream = prepared.stream
    scene = prepared.scene
    median_h = _scene_median_height(scene)
    remapped = [_remap_candidate(candidate, prepared) for candidate in parsed.candidates]
    label_block_ids = {
        block_id
        for event in bundle.label_clues
        for block_id in [_event_block_id(stream, event)]
        if block_id
    }
    proposals: list[OCROwnershipProposal] = []
    for event in bundle.label_clues:
        if event.clue_id in parsed.handled_label_clue_ids:
            continue
        label_block = _event_scene_block(stream, scene, event)
        if label_block is None:
            continue
        bound = _find_existing_bound_candidate(event, label_block, remapped, scene, median_h=median_h)
        if bound is not None:
            _bind_label_to_candidate(bound, event)
            continue
        candidate_blocks = _find_candidate_blocks(label_block, scene, label_block_ids, median_h=median_h)
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
        extras.append(_remap_candidate(generated, prepared))
    return _merge_ocr_candidates([*remapped, *extras])


def _build_candidate_from_blocks(event: Clue, blocks: tuple[OCRSceneBlock, ...]) -> CandidateDraft | None:
    text = " ".join(block.clean_text.strip() for block in blocks if block.clean_text.strip())
    if not text:
        return None
    start = blocks[0].clean_start
    end = blocks[-1].clean_end
    source_kind = str((event.source_metadata.get("ocr_source_kind") or [event.source_kind])[0])
    # 从 source_metadata 读取 name_component_hint；默认 FULL。
    _hint_raw = (event.source_metadata.get("name_component_hint") or ["full"])[0]
    try:
        component_hint = NameComponentHint(_hint_raw)
    except ValueError:
        component_hint = NameComponentHint.FULL
    if event.attr_type == PIIAttributeType.NAME:
        return build_name_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            source_kind=source_kind,
            component_hint=component_hint,
            label_clue_id=event.clue_id,
            label_driven=True,
        )
    if event.attr_type == PIIAttributeType.ADDRESS:
        candidate = build_address_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            source_kind=source_kind,
            label_clue_id=event.clue_id,
            label_driven=True,
        )
        return candidate
    if event.attr_type == PIIAttributeType.ORGANIZATION:
        return build_organization_candidate_from_value(
            source=PIISourceType.OCR,
            value_text=text,
            value_start=start,
            value_end=end,
            source_kind=source_kind,
            label_clue_id=event.clue_id,
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
    text = " ".join(block.clean_text.strip() for block in proposal.candidate_blocks if block.clean_text.strip())
    attr_score = _attribute_segment_score(proposal.event, text)
    geometry_score = _geometry_score(proposal.label_block, proposal.candidate_blocks)
    distance_score = _distance_fallback_score(proposal.label_block, proposal.candidate_blocks)
    return (attr_score, geometry_score, distance_score)


def _attribute_segment_score(event: Clue, text: str) -> float:
    sample = text.strip()
    if not sample:
        return -999.0
    if event.attr_type == PIIAttributeType.NAME:
        score = 0.0
        _h = (event.source_metadata.get("name_component_hint") or ["full"])[0]
        try:
            _attr_hint = NameComponentHint(_h)
        except ValueError:
            _attr_hint = NameComponentHint.FULL
        if looks_like_name_value(sample, component_hint=_attr_hint):
            score += 1.4
        if has_organization_suffix(sample):
            score -= 2.2
        if has_address_signal(sample):
            score -= 1.8
        return score
    if event.attr_type == PIIAttributeType.ORGANIZATION:
        score = 0.0
        if looks_like_organization_value(sample, label_driven=True):
            score += 1.2
        if has_organization_suffix(sample):
            score += 2.4
        if has_address_signal(sample):
            score -= 0.5
        return score
    if event.attr_type == PIIAttributeType.ADDRESS:
        score = 0.0
        if has_address_signal(sample):
            score += 2.2
        elif len(sample) >= 4:
            score += 0.6
        if has_organization_suffix(sample):
            score -= 0.6
        return score
    return 0.0


def _geometry_score(label_block: OCRSceneBlock, blocks: tuple[OCRSceneBlock, ...]) -> float:
    """几何评分：同行右侧优于下方行。距离越远得分越低。"""
    first = blocks[0]
    if first.line_index == label_block.line_index and first.order_index > label_block.order_index:
        return 2.0 - (_horizontal_gap(label_block, first) / 500.0)
    return 1.0 - (_vertical_score(label_block, first) / 500.0)


def _distance_fallback_score(label_block: OCRSceneBlock, blocks: tuple[OCRSceneBlock, ...]) -> float:
    del label_block, blocks
    return 0.0


def _find_existing_bound_candidate(
    event: Clue,
    label_block: OCRSceneBlock,
    candidates: list[CandidateDraft],
    scene: OCRScene,
    *,
    median_h: float,
) -> CandidateDraft | None:
    ranked: list[tuple[float, CandidateDraft]] = []
    for candidate in candidates:
        if candidate.attr_type != event.attr_type or not candidate.block_ids:
            continue
        anchor_block = _candidate_anchor_block(candidate, scene)
        if anchor_block is None:
            continue
        score = _existing_binding_score(label_block, anchor_block, median_h=median_h)
        if score <= 0:
            continue
        ranked.append((score, candidate))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _bind_label_to_candidate(candidate: CandidateDraft, event: Clue) -> None:
    candidate.label_clue_ids.add(event.clue_id)
    metadata = dict(candidate.metadata)
    metadata["bound_label_clue_ids"] = list(
        dict.fromkeys([*metadata.get("bound_label_clue_ids", []), event.clue_id])
    )
    _ocr_sk = (event.source_metadata.get("ocr_source_kind") or [event.source_kind])[0]
    metadata["matched_by"] = list(dict.fromkeys([*metadata.get("matched_by", []), str(_ocr_sk)]))
    candidate.metadata = metadata


def _candidate_anchor_block(candidate: CandidateDraft, scene: OCRScene) -> OCRSceneBlock | None:
    for block_id in candidate.block_ids:
        block = scene.id_to_block.get(block_id)
        if block is not None:
            return block
    return None


def _existing_binding_score(label_block: OCRSceneBlock, candidate_block: OCRSceneBlock, *, median_h: float) -> float:
    """已有 candidate 与 label 的绑定评分。阈值按 median_h 归一化。"""
    norm = max(median_h, 10.0)
    if candidate_block.line_index == label_block.line_index and candidate_block.order_index > label_block.order_index:
        return 3.0 - (_horizontal_gap(label_block, candidate_block) / (norm * 15.0))
    if candidate_block.line_index in {label_block.line_index + 1, label_block.line_index + 2}:
        return 2.0 - (_vertical_score(label_block, candidate_block) / (norm * 15.0))
    return -1.0


def _find_candidate_blocks(
    label_block: OCRSceneBlock,
    scene: OCRScene,
    label_block_ids: set[str],
    *,
    median_h: float,
) -> tuple[OCRSceneBlock, ...]:
    """宽松空间搜索：不依赖预计算 chain，直接在 scene 中按几何邻近度查找值 block。"""
    lb = label_block.block.bbox
    if lb is None:
        return ()
    label_right = float(lb.x + lb.width)
    label_bottom = float(lb.y + lb.height)
    label_cy = float(lb.y) + float(lb.height) / 2
    label_x = float(lb.x)

    # 搜索半径（以 median_h 为单位）。
    _MAX_H_RIGHT = 8.0
    _MAX_V_DOWN = 3.0

    scored: list[tuple[float, OCRSceneBlock]] = []
    for block in scene.blocks:
        if block.block_id in label_block_ids or block.block_id == label_block.block_id:
            continue
        bb = block.block.bbox
        if bb is None or not block.clean_text.strip():
            continue
        block_cy = float(bb.y) + float(bb.height) / 2

        # 同行右侧：y 中心差 < median_h 且 x 在 label 右边界右侧。
        if abs(block_cy - label_cy) < median_h and float(bb.x) >= label_right:
            h_gap = float(bb.x) - label_right
            if h_gap <= _MAX_H_RIGHT * median_h:
                score = 2.0 - h_gap / (_MAX_H_RIGHT * median_h)
                scored.append((score, block))
                continue

        # 下方：y 起始在 label 底边附近或以下。
        if float(bb.y) >= label_bottom - 0.3 * median_h:
            v_gap = float(bb.y) - label_bottom
            if 0 <= v_gap <= _MAX_V_DOWN * median_h:
                x_offset = abs(float(bb.x) - label_x)
                score = 1.0 - v_gap / (_MAX_V_DOWN * median_h) - x_offset / (_MAX_H_RIGHT * median_h) * 0.3
                scored.append((score, block))

    if not scored:
        return ()
    scored.sort(key=lambda t: t[0], reverse=True)
    return (scored[0][1],)


def _remap_candidate(candidate: CandidateDraft, prepared: PreparedOCRContext) -> CandidateDraft:
    stream = prepared.stream
    scene = prepared.scene
    mapped_refs = [
        ref
        for ref in stream.char_refs[candidate.start : candidate.end]
        if ref is not None and ref.block_id is not None and ref.raw_index is not None
    ]
    if not mapped_refs:
        return candidate
    block_refs = []
    for ref in mapped_refs:
        if block_refs and block_refs[-1].block_id == ref.block_id:
            continue
        block_refs.append(ref)
    block_ids = tuple(ref.block_id for ref in block_refs if ref.block_id)
    boxes = [scene.id_to_block[block_id].block.bbox for block_id in block_ids if block_id in scene.id_to_block]
    metadata = dict(candidate.metadata)
    metadata["ocr_block_ids"] = list(block_ids)
    first_ref = mapped_refs[0]
    last_ref = mapped_refs[-1]
    raw_start = int(first_ref.raw_index)
    raw_end = int(last_ref.raw_index) + 1
    span_start = first_ref.block_char_index
    span_end = None
    block_id = block_ids[0] if block_ids else None
    if first_ref.block_id == last_ref.block_id and last_ref.block_char_index is not None:
        span_end = last_ref.block_char_index + 1
    canonical_text = candidate.canonical_text or candidate.text
    return replace(
        candidate,
        start=raw_start,
        end=raw_end,
        text=prepared.raw_text[raw_start:raw_end],
        canonical_text=canonical_text,
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
        duplicate.metadata = merge_metadata(duplicate.metadata, candidate.metadata)
    return merged


def _event_block_id(stream: StreamInput, event: Clue) -> str | None:
    for ref in stream.char_refs[event.start : event.end]:
        if ref is not None and ref.block_id is not None:
            return ref.block_id
    return None


def _event_scene_block(stream: StreamInput, scene: OCRScene, event: Clue) -> OCRSceneBlock | None:
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


def _scene_median_height(scene: OCRScene) -> float:
    """计算 scene 中所有 block 的中位高度，用于阈值归一化。"""
    heights = [_block_height(block) for block in scene.blocks]
    if not heights:
        return 20.0
    return float(median(heights))


def _union_bbox(boxes):
    materialized = [box for box in boxes if box is not None]
    if not materialized:
        return None
    min_x = min(box.x for box in materialized)
    min_y = min(box.y for box in materialized)
    max_x = max(box.x + box.width for box in materialized)
    max_y = max(box.y + box.height for box in materialized)
    return materialized[0].model_copy(update={"x": min_x, "y": min_y, "width": max_x - min_x, "height": max_y - min_y})
