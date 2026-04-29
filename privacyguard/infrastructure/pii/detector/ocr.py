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
from privacyguard.infrastructure.pii.detector.metadata import (
    GENERIC_CONTEXT_GATE_GEOMETRY,
    GENERIC_CONTEXT_GATE_METADATA,
    merge_metadata,
)
from privacyguard.infrastructure.pii.detector.label_layout import LabelBindingInfo, LabelLayoutManager
from privacyguard.infrastructure.pii.detector.models import (
    CandidateDraft,
    Clue,
    ClueRole,
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
    layout_fallback: bool = False


_GATED_LABEL_ATTRS = frozenset({
    PIIAttributeType.NAME,
    PIIAttributeType.ORGANIZATION,
    PIIAttributeType.ADDRESS,
})
_NUMBERISH_LABEL_ATTRS = frozenset({
    PIIAttributeType.PHONE,
    PIIAttributeType.ID_NUMBER,
    PIIAttributeType.BANK_NUMBER,
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
})
_NUMBERISH_BLOCK_ATTRS = frozenset({
    PIIAttributeType.NUM,
    PIIAttributeType.ALNUM,
})
_CLUE_GATED_LABEL_ATTRS = _GATED_LABEL_ATTRS | _NUMBERISH_LABEL_ATTRS
_BLOCK_CLUE_ROLES_BY_ATTR = {
    PIIAttributeType.NAME: frozenset({
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
        ClueRole.VALUE,
    }),
    PIIAttributeType.ORGANIZATION: frozenset({
        ClueRole.VALUE,
        ClueRole.SUFFIX,
    }),
    PIIAttributeType.ADDRESS: frozenset({
        ClueRole.VALUE,
        ClueRole.KEY,
    }),
}
_ROW_ALIGNMENT_RATIO = 0.15
_RIGHT_MAX_GAP_HEIGHTS = 8.0
_BELOW_MAX_GAP_HEIGHT_RATIO = 1.8
_X_OVERLAP_RATIO = 0.50
_BELOW_LEFT_EDGE_LABEL_WIDTH_RATIO = 0.50
_BLOCKER_HEIGHT_RATIO = 0.80
_ROW_HEIGHT_RATIO_MIN = 0.60
_ROW_HEIGHT_RATIO_MAX = 1.80


class LabelBlockClueGate:
    """限制 label 只能抓取已有可信 clue 的 OCR block。"""

    def __init__(self, *, scene: OCRScene, clues: tuple[Clue, ...]) -> None:
        self._clues_by_block_id: dict[str, tuple[Clue, ...]] = {}
        for block in scene.blocks:
            self._clues_by_block_id[block.block_id] = tuple(
                clue
                for clue in clues
                if _spans_overlap(clue.start, clue.end, block.clean_start, block.clean_end)
            )

    def allows_block(self, event: Clue, block: OCRSceneBlock) -> bool:
        """判断 label 是否允许把该 block 作为待生成 PII 的 value。"""
        if event.attr_type not in _CLUE_GATED_LABEL_ATTRS:
            return True
        block_clues = self._clues_by_block_id.get(block.block_id, ())
        if event.attr_type in _NUMBERISH_LABEL_ATTRS:
            # 号类 label 只能绑定通用结构化片段，不能把普通文字 block 提升为号码类 PII。
            return any(
                clue.attr_type in _NUMBERISH_BLOCK_ATTRS and clue.role == ClueRole.VALUE
                for clue in block_clues
            )
        allowed_roles = _BLOCK_CLUE_ROLES_BY_ATTR.get(event.attr_type, frozenset())
        return any(
            clue.attr_type == event.attr_type and clue.role in allowed_roles
            for clue in block_clues
        )


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
    clue_gate = LabelBlockClueGate(scene=scene, clues=tuple(bundle.all_clues))
    label_events = tuple(bundle.label_clues)
    label_blocks = {
        event.clue_id: block
        for event in label_events
        for block in [_event_scene_block(stream, scene, event)]
        if block is not None
    }
    label_block_ids = {
        block_id
        for event in label_events
        for block_id in [_event_block_id(stream, event)]
        if block_id
    }
    binding_infos: list[LabelBindingInfo] = _parsed_label_bindings(
        label_events=label_events,
        label_blocks=label_blocks,
        candidates=remapped,
        scene=scene,
        median_h=median_h,
    )
    used_label_ids = set(parsed.handled_label_clue_ids)
    stage1_proposals: list[OCROwnershipProposal] = []
    for event in label_events:
        if event.clue_id in parsed.handled_label_clue_ids:
            continue
        label_block = label_blocks.get(event.clue_id)
        if label_block is None:
            continue
        bound = _find_existing_bound_candidate(event, label_block, remapped, scene, median_h=median_h)
        if bound is not None:
            _bind_label_to_candidate(bound, event)
            used_label_ids.add(event.clue_id)
            binding_infos.append(_binding_info(event, label_block, bound, scene=scene, median_h=median_h))
            continue
        candidate_blocks = _find_candidate_blocks(
            event,
            label_block,
            scene,
            label_block_ids,
            median_h=median_h,
            clue_gate=clue_gate,
            require_clue_gate=True,
        )
        if not candidate_blocks:
            continue
        stage1_proposals.append(
            OCROwnershipProposal(
                event=event,
                label_block=label_block,
                candidate_blocks=candidate_blocks,
            )
        )
    extras: list[CandidateDraft] = []
    for proposal in _resolve_ownership_proposals(stage1_proposals):
        generated = _build_candidate_from_blocks(proposal.event, proposal.candidate_blocks)
        if generated is None:
            continue
        extras.append(_remap_candidate(generated, prepared))
        used_label_ids.add(proposal.event.clue_id)
        binding_infos.append(_proposal_binding_info(proposal, scene=scene, median_h=median_h))

    layout_manager = LabelLayoutManager(
        scene=scene,
        label_clues=label_events,
        label_blocks=label_blocks,
        bindings=tuple(binding_infos),
    )
    layout_decisions = layout_manager.evaluate()
    trusted_label_ids = {
        clue_id
        for clue_id, decision in layout_decisions.items()
        if decision.trusted
    }
    fallback_proposals: list[OCROwnershipProposal] = []
    for event in label_events:
        if event.clue_id in used_label_ids or event.clue_id not in trusted_label_ids:
            continue
        label_block = label_blocks.get(event.clue_id)
        if label_block is None:
            continue
        candidate_blocks = _find_candidate_blocks(
            event,
            label_block,
            scene,
            label_block_ids,
            median_h=median_h,
            clue_gate=clue_gate,
            require_clue_gate=False,
        )
        if not candidate_blocks:
            continue
        fallback_proposals.append(
            OCROwnershipProposal(
                event=event,
                label_block=label_block,
                candidate_blocks=candidate_blocks,
                layout_fallback=True,
            )
        )
    for proposal in _resolve_ownership_proposals(fallback_proposals):
        generated = _build_candidate_from_blocks(proposal.event, proposal.candidate_blocks)
        if generated is None:
            continue
        decision = layout_decisions.get(proposal.event.clue_id)
        if decision is not None:
            generated.metadata = merge_metadata(
                generated.metadata,
                {
                    "ocr_label_layout_score": [f"{decision.layout_score:.3f}"],
                    "ocr_label_layout_fallback": ["1"],
                },
            )
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


def _parsed_label_bindings(
    *,
    label_events: tuple[Clue, ...],
    label_blocks: dict[str, OCRSceneBlock],
    candidates: list[CandidateDraft],
    scene: OCRScene,
    median_h: float,
) -> list[LabelBindingInfo]:
    """把 parser 已经处理过的 label-candidate 关系投影成布局证据。"""
    event_by_id = {event.clue_id: event for event in label_events}
    bindings: list[LabelBindingInfo] = []
    seen: set[str] = set()
    for candidate in candidates:
        for label_id in candidate.label_clue_ids:
            if label_id in seen:
                continue
            event = event_by_id.get(label_id)
            label_block = label_blocks.get(label_id)
            if event is None or label_block is None:
                continue
            bindings.append(_binding_info(event, label_block, candidate, scene=scene, median_h=median_h))
            seen.add(label_id)
    return bindings


def _binding_info(
    event: Clue,
    label_block: OCRSceneBlock,
    candidate: CandidateDraft,
    *,
    scene: OCRScene,
    median_h: float,
) -> LabelBindingInfo:
    anchor_block = _candidate_anchor_block(candidate, scene)
    relation = None
    if anchor_block is not None:
        relation = _layout_relation(label_block, anchor_block, scene_blocks=scene.blocks, median_h=median_h)
    return LabelBindingInfo(label_id=event.clue_id, attr_type=event.attr_type, relation=relation)


def _proposal_binding_info(
    proposal: OCROwnershipProposal,
    *,
    scene: OCRScene,
    median_h: float,
) -> LabelBindingInfo:
    relation = _layout_relation(
        proposal.label_block,
        proposal.candidate_blocks[0],
        scene_blocks=scene.blocks,
        median_h=median_h,
    )
    return LabelBindingInfo(
        label_id=proposal.event.clue_id,
        attr_type=proposal.event.attr_type,
        relation=relation,
    )


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
    if proposal.layout_fallback and attr_score <= 0:
        attr_score = 0.1
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
    """几何评分：同行右侧优于下方，距离越远得分越低。"""
    first = blocks[0]
    relation = _layout_relation(label_block, first, scene_blocks=(), median_h=_block_height(label_block))
    if relation == "right":
        return 2.0 - (_horizontal_gap(label_block, first) / 500.0)
    if relation == "below":
        return 1.0 - (_vertical_score(label_block, first) / 500.0)
    return -1.0


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
        if not _candidate_can_bind_label(event, candidate) or not candidate.block_ids:
            continue
        anchor_block = _candidate_anchor_block(candidate, scene)
        if anchor_block is None:
            continue
        score = _existing_binding_score(label_block, anchor_block, scene=scene, median_h=median_h)
        if score <= 0:
            continue
        ranked.append((score, candidate))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _bind_label_to_candidate(candidate: CandidateDraft, event: Clue) -> None:
    candidate.label_clue_ids.add(event.clue_id)
    _ocr_sk = (event.source_metadata.get("ocr_source_kind") or [event.source_kind])[0]
    metadata = {
        "bound_label_clue_ids": [event.clue_id],
        "matched_by": [str(_ocr_sk)],
    }
    if candidate.attr_type in _NUMBERISH_BLOCK_ATTRS:
        metadata[GENERIC_CONTEXT_GATE_METADATA] = [GENERIC_CONTEXT_GATE_GEOMETRY]
    candidate.metadata = merge_metadata(candidate.metadata, metadata)


def _candidate_anchor_block(candidate: CandidateDraft, scene: OCRScene) -> OCRSceneBlock | None:
    for block_id in candidate.block_ids:
        block = scene.id_to_block.get(block_id)
        if block is not None:
            return block
    return None


def _candidate_can_bind_label(event: Clue, candidate: CandidateDraft) -> bool:
    if candidate.attr_type == event.attr_type:
        return True
    return event.attr_type in _NUMBERISH_LABEL_ATTRS and candidate.attr_type in _NUMBERISH_BLOCK_ATTRS


def _existing_binding_score(
    label_block: OCRSceneBlock,
    candidate_block: OCRSceneBlock,
    *,
    scene: OCRScene,
    median_h: float,
) -> float:
    """已有 candidate 与 label 的绑定评分。阈值按 median_h 归一化。"""
    norm = max(median_h, 10.0)
    relation = _layout_relation(label_block, candidate_block, scene_blocks=scene.blocks, median_h=median_h)
    if relation == "right":
        return 3.0 - (_horizontal_gap(label_block, candidate_block) / (norm * 15.0))
    if relation == "below":
        return 2.0 - (_vertical_score(label_block, candidate_block) / (norm * 15.0))
    return -1.0


def _find_candidate_blocks(
    event: Clue,
    label_block: OCRSceneBlock,
    scene: OCRScene,
    label_block_ids: set[str],
    *,
    median_h: float,
    clue_gate: LabelBlockClueGate,
    require_clue_gate: bool,
) -> tuple[OCRSceneBlock, ...]:
    """宽松空间搜索：不依赖预计算 chain，直接在 scene 中按几何邻近度查找值 block。"""
    lb = label_block.block.bbox
    if lb is None:
        return ()
    scored: list[tuple[float, OCRSceneBlock]] = []
    for block in scene.blocks:
        if block.block_id in label_block_ids or block.block_id == label_block.block_id:
            continue
        bb = block.block.bbox
        if bb is None or not block.clean_text.strip():
            continue
        if require_clue_gate and not clue_gate.allows_block(event, block):
            continue
        if not require_clue_gate and not _fallback_block_shape_allowed(event, block, clue_gate):
            continue
        relation = _layout_relation(label_block, block, scene_blocks=scene.blocks, median_h=median_h)
        if relation == "right":
            if not _height_ratio_allowed(label_block, block):
                continue
            h_gap = float(bb.x) - float(lb.x + lb.width)
            attr_score = _attribute_segment_score(event, block.clean_text)
            if not require_clue_gate and attr_score <= 0:
                attr_score = 0.1
            score = attr_score + 2.0 - h_gap / (_RIGHT_MAX_GAP_HEIGHTS * median_h)
            scored.append((score, block))
            continue
        if relation == "below":
            if not _height_ratio_allowed(label_block, block):
                continue
            v_gap = float(bb.y) - float(lb.y + lb.height)
            x_offset = abs(float(bb.x) - float(lb.x))
            attr_score = _attribute_segment_score(event, block.clean_text)
            if not require_clue_gate and attr_score <= 0:
                attr_score = 0.1
            score = attr_score + 1.0 - v_gap / max(median_h, 1.0) - x_offset / max(_RIGHT_MAX_GAP_HEIGHTS * median_h, 1.0) * 0.3
            scored.append((score, block))

    if not scored:
        return ()
    scored.sort(key=lambda t: t[0], reverse=True)
    return (scored[0][1],)


def _fallback_block_shape_allowed(event: Clue, block: OCRSceneBlock, clue_gate: LabelBlockClueGate) -> bool:
    """高可信 label 的 fallback 只做形状筛选，类型最终仍由候选构造校验。"""
    text = block.clean_text.strip()
    if not text:
        return False
    if clue_gate.allows_block(event, block):
        return True
    if event.attr_type == PIIAttributeType.NAME:
        return looks_like_name_value(text)
    if event.attr_type == PIIAttributeType.ORGANIZATION:
        return looks_like_organization_value(text, label_driven=True)
    if event.attr_type == PIIAttributeType.ADDRESS:
        return has_address_signal(text) or len(text) >= 4
    return False


def _height_ratio_allowed(label_block: OCRSceneBlock, value_block: OCRSceneBlock) -> bool:
    lb = label_block.block.bbox
    vb = value_block.block.bbox
    if lb is None or vb is None:
        return False
    ratio = float(vb.height) / max(float(lb.height), 1.0)
    return _ROW_HEIGHT_RATIO_MIN <= ratio <= _ROW_HEIGHT_RATIO_MAX


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


def _spans_overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def _layout_relation(
    label_block: OCRSceneBlock,
    value_block: OCRSceneBlock,
    *,
    scene_blocks: tuple[OCRSceneBlock, ...],
    median_h: float,
) -> str | None:
    """用 bbox 判断 label 与 value 的相对位置，不依赖预计算行号。"""
    if _is_same_row_right(label_block, value_block, median_h=median_h) and not _has_blocking_between(
        label_block,
        value_block,
        scene_blocks=scene_blocks,
        mode="right",
    ):
        return "right"
    if _is_directly_below(label_block, value_block, median_h=median_h) and not _has_blocking_between(
        label_block,
        value_block,
        scene_blocks=scene_blocks,
        mode="below",
    ):
        return "below"
    return None


def _is_same_row_right(label_block: OCRSceneBlock, value_block: OCRSceneBlock, *, median_h: float) -> bool:
    lb = label_block.block.bbox
    vb = value_block.block.bbox
    if lb is None or vb is None:
        return False
    if float(vb.x) < float(lb.x + lb.width):
        return False
    max_gap = _RIGHT_MAX_GAP_HEIGHTS * max(float(median_h), 1.0)
    if float(vb.x) - float(lb.x + lb.width) > max_gap:
        return False
    tolerance = _alignment_tolerance(lb.height, vb.height, median_h)
    label_cy = float(lb.y) + float(lb.height) / 2
    value_cy = float(vb.y) + float(vb.height) / 2
    label_bottom = float(lb.y + lb.height)
    value_bottom = float(vb.y + vb.height)
    return abs(label_cy - value_cy) <= tolerance or abs(label_bottom - value_bottom) <= tolerance


def _is_directly_below(label_block: OCRSceneBlock, value_block: OCRSceneBlock, *, median_h: float) -> bool:
    lb = label_block.block.bbox
    vb = value_block.block.bbox
    if lb is None or vb is None:
        return False
    vertical_gap = float(vb.y) - float(lb.y + lb.height)
    base_height = max(float(lb.height), float(vb.height), float(median_h), 1.0)
    max_gap = base_height * _BELOW_MAX_GAP_HEIGHT_RATIO
    if vertical_gap < 0 or vertical_gap > max_gap:
        return False
    min_width = max(min(float(lb.width), float(vb.width)), 1.0)
    overlap = _x_overlap(lb, vb)
    if overlap >= _X_OVERLAP_RATIO * min_width:
        return True
    return abs(float(lb.x) - float(vb.x)) <= _BELOW_LEFT_EDGE_LABEL_WIDTH_RATIO * max(float(lb.width), 1.0)


def _has_blocking_between(
    label_block: OCRSceneBlock,
    value_block: OCRSceneBlock,
    *,
    scene_blocks: tuple[OCRSceneBlock, ...],
    mode: str,
) -> bool:
    lb = label_block.block.bbox
    vb = value_block.block.bbox
    if lb is None or vb is None:
        return False
    for block in scene_blocks:
        if block.block_id in {label_block.block_id, value_block.block_id}:
            continue
        bb = block.block.bbox
        if bb is None or not block.clean_text.strip():
            continue
        if mode == "right" and _blocks_right_corridor(lb, vb, bb):
            if not _is_ignorable_right_blocker(lb, vb, bb):
                return True
        elif mode == "below" and _blocks_below_corridor(lb, vb, bb):
            if not _is_ignorable_below_blocker(lb, vb, bb):
                return True
    return False


def _blocks_right_corridor(label_box, value_box, other_box) -> bool:
    left = float(label_box.x + label_box.width)
    right = float(value_box.x)
    if right <= left:
        return False
    other_left = float(other_box.x)
    other_right = float(other_box.x + other_box.width)
    if other_right <= left or other_left >= right:
        return False
    top = min(float(label_box.y), float(value_box.y))
    bottom = max(float(label_box.y + label_box.height), float(value_box.y + value_box.height))
    return _interval_overlap(float(other_box.y), float(other_box.y + other_box.height), top, bottom) > 0


def _blocks_below_corridor(label_box, value_box, other_box) -> bool:
    top = float(label_box.y + label_box.height)
    bottom = float(value_box.y)
    if bottom <= top:
        return False
    other_top = float(other_box.y)
    other_bottom = float(other_box.y + other_box.height)
    if other_bottom <= top or other_top >= bottom:
        return False
    left = min(float(label_box.x), float(value_box.x))
    right = max(float(label_box.x + label_box.width), float(value_box.x + value_box.width))
    return _interval_overlap(float(other_box.x), float(other_box.x + other_box.width), left, right) > 0


def _is_ignorable_right_blocker(label_box, value_box, blocker_box) -> bool:
    min_height = min(float(label_box.height), float(value_box.height))
    min_width = min(float(label_box.width), float(value_box.width))
    return float(blocker_box.height) < _BLOCKER_HEIGHT_RATIO * min_height and float(blocker_box.width) < min_width


def _is_ignorable_below_blocker(label_box, value_box, blocker_box) -> bool:
    min_height = min(float(label_box.height), float(value_box.height))
    return float(blocker_box.height) < _BLOCKER_HEIGHT_RATIO * min_height


def _alignment_tolerance(label_height: int, value_height: int, median_h: float) -> float:
    return max(2.0, _ROW_ALIGNMENT_RATIO * max(float(label_height), float(value_height), float(median_h)))


def _x_overlap(left_box, right_box) -> float:
    return _interval_overlap(
        float(left_box.x),
        float(left_box.x + left_box.width),
        float(right_box.x),
        float(right_box.x + right_box.width),
    )


def _interval_overlap(left_start: float, left_end: float, right_start: float, right_end: float) -> float:
    return max(0.0, min(left_end, right_end) - max(left_start, right_start))


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
