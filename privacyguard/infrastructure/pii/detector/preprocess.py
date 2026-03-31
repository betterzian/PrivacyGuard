"""Source preprocessing for prompt and OCR streams."""

from __future__ import annotations

from statistics import mean

from privacyguard.domain.enums import PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector.models import OCRScene, OCRSceneBlock, SourceRef, StreamInput, StreamSpan
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN


def build_prompt_stream(text: str) -> StreamInput:
    raw_text = text or ""
    char_refs = tuple(
        SourceRef(
            source=PIISourceType.PROMPT,
            block_id=None,
            bbox=None,
            block_char_index=index,
        )
        for index, _char in enumerate(raw_text)
    )
    spans = (StreamSpan(kind="prompt_text", start=0, end=len(raw_text)),)
    return StreamInput(
        source=PIISourceType.PROMPT,
        raw_text=raw_text,
        char_refs=char_refs,
        spans=spans,
    )


def build_ocr_stream(blocks: list[OCRTextBlock]) -> tuple[StreamInput, OCRScene]:
    ordered_lines = _group_ocr_lines(blocks)
    raw_chunks: list[str] = []
    char_refs: list[SourceRef | None] = []
    spans: list[StreamSpan] = []
    scene_blocks: list[OCRSceneBlock] = []
    cursor = 0
    order_index = 0

    for line_index, line_blocks in enumerate(ordered_lines):
        if raw_chunks:
            raw_chunks.append(_OCR_SEMANTIC_BREAK_TOKEN)
            spans.append(StreamSpan(kind="ocr_break", start=cursor, end=cursor + len(_OCR_SEMANTIC_BREAK_TOKEN)))
            char_refs.extend([None] * len(_OCR_SEMANTIC_BREAK_TOKEN))
            cursor += len(_OCR_SEMANTIC_BREAK_TOKEN)
        for block_offset, block in enumerate(line_blocks):
            if block_offset:
                raw_chunks.append(" ")
                spans.append(StreamSpan(kind="ocr_inline_gap", start=cursor, end=cursor + 1))
                char_refs.append(None)
                cursor += 1
            block_id = block.block_id or f"ocr-{order_index}"
            block_start = cursor
            text = block.text or ""
            raw_chunks.append(text)
            for char_index, _char in enumerate(text):
                char_refs.append(
                    SourceRef(
                        source=PIISourceType.OCR,
                        block_id=block_id,
                        bbox=block.bbox,
                        block_char_index=char_index,
                    )
                )
            cursor += len(text)
            block_end = cursor
            spans.append(
                StreamSpan(
                    kind="ocr_block",
                    start=block_start,
                    end=block_end,
                    block_id=block_id,
                    bbox=block.bbox,
                )
            )
            scene_blocks.append(
                OCRSceneBlock(
                    block=block.model_copy(deep=True),
                    block_id=block_id,
                    order_index=order_index,
                    line_index=line_index,
                    raw_start=block_start,
                    raw_end=block_end,
                )
            )
            order_index += 1

    scene = _build_scene(scene_blocks)
    stream = StreamInput(
        source=PIISourceType.OCR,
        raw_text="".join(raw_chunks),
        char_refs=tuple(char_refs),
        spans=tuple(spans),
        metadata={"ocr_block_count": len(scene_blocks)},
    )
    return (stream, scene)


def _group_ocr_lines(blocks: list[OCRTextBlock]) -> list[list[OCRTextBlock]]:
    materialized = [block for block in blocks if (block.text or "").strip() and block.bbox is not None]
    sorted_blocks = sorted(
        materialized,
        key=lambda item: (
            _bbox_center_y(item.bbox),
            item.bbox.x if item.bbox is not None else 0,
        ),
    )
    lines: list[list[OCRTextBlock]] = []
    for block in sorted_blocks:
        if not lines:
            lines.append([block])
            continue
        last_line = lines[-1]
        tolerance = _line_tolerance(last_line, block)
        if abs(_line_center(last_line) - _bbox_center_y(block.bbox)) <= tolerance:
            last_line.append(block)
            last_line.sort(key=lambda item: item.bbox.x if item.bbox is not None else 0)
            continue
        lines.append([block])
    return lines


def _build_scene(scene_blocks: list[OCRSceneBlock]) -> OCRScene:
    id_to_block = {item.block_id: item for item in scene_blocks}
    line_to_blocks: dict[int, tuple[OCRSceneBlock, ...]] = {}
    for item in scene_blocks:
        line_to_blocks.setdefault(item.line_index, ())
        line_to_blocks[item.line_index] = tuple([*line_to_blocks[item.line_index], item])
    return OCRScene(
        blocks=tuple(scene_blocks),
        id_to_block=id_to_block,
        line_to_blocks=line_to_blocks,
    )


def _line_center(line_blocks: list[OCRTextBlock]) -> float:
    return mean(_bbox_center_y(block.bbox) for block in line_blocks if block.bbox is not None)


def _line_tolerance(line_blocks: list[OCRTextBlock], block: OCRTextBlock) -> float:
    heights = [entry.bbox.height for entry in line_blocks if entry.bbox is not None]
    candidate_height = block.bbox.height if block.bbox is not None else 20
    return max(18.0, max([candidate_height, *heights]) * 0.75)


def _bbox_center_y(bbox: BoundingBox | None) -> float:
    if bbox is None:
        return 0.0
    return float(bbox.y) + float(bbox.height) / 2.0
