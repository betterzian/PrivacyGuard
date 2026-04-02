"""Prompt 与 OCR 流的预处理。"""

from __future__ import annotations

import unicodedata
from statistics import mean

from privacyguard.domain.enums import PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector.models import (
    OCRScene,
    OCRSceneBlock,
    PreparedOCRContext,
    SourceRef,
    StreamInput,
    StreamSpan,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCR_INLINE_GAP_TOKEN,
    _OCR_SEMANTIC_BREAK_TOKEN,
)

_ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"})
_EDGE_NOISE_CHARS = frozenset("`~^_|/\\.,，。;；:：'\"-—–()[]{}<>《》")


def build_prompt_stream(text: str) -> StreamInput:
    clean_text = text or ""
    char_refs = tuple(
        SourceRef(
            source=PIISourceType.PROMPT,
            block_id=None,
            bbox=None,
            block_char_index=index,
            raw_index=index,
        )
        for index, _char in enumerate(clean_text)
    )
    spans = (StreamSpan(kind="prompt_text", start=0, end=len(clean_text)),)
    return StreamInput(
        source=PIISourceType.PROMPT,
        text=clean_text,
        char_refs=char_refs,
        spans=spans,
    )


def build_ocr_stream(blocks: list[OCRTextBlock]) -> PreparedOCRContext:
    ordered_lines = _group_ocr_lines(blocks)
    raw_chunks: list[str] = []
    raw_char_refs: list[SourceRef | None] = []
    raw_spans: list[StreamSpan] = []
    clean_chunks: list[str] = []
    clean_char_refs: list[SourceRef | None] = []
    clean_spans: list[StreamSpan] = []
    scene_blocks: list[OCRSceneBlock] = []
    raw_cursor = 0
    clean_cursor = 0
    order_index = 0

    for line_index, line_blocks in enumerate(ordered_lines):
        prepared_line = [
            (
                block,
                block.block_id or f"ocr-{order_index + offset}",
                _prepare_ocr_block_text(block.text or ""),
            )
            for offset, block in enumerate(line_blocks)
        ]

        if raw_chunks:
            raw_cursor = _append_synthetic_text(
                token=_OCR_SEMANTIC_BREAK_TOKEN,
                kind="ocr_break",
                chunks=raw_chunks,
                char_refs=raw_char_refs,
                spans=raw_spans,
                cursor=raw_cursor,
            )
        if clean_chunks and any(clean_text for _block, _block_id, (clean_text, _mapping) in prepared_line):
            clean_cursor = _append_synthetic_text(
                token=_OCR_SEMANTIC_BREAK_TOKEN,
                kind="ocr_break",
                chunks=clean_chunks,
                char_refs=clean_char_refs,
                spans=clean_spans,
                cursor=clean_cursor,
            )

        previous_clean_text: str | None = None
        for block_offset, (block, block_id, (clean_text, clean_map)) in enumerate(prepared_line):
            if block_offset:
                raw_cursor = _append_synthetic_text(
                    token=" ",
                    kind="ocr_inline_gap",
                    chunks=raw_chunks,
                    char_refs=raw_char_refs,
                    spans=raw_spans,
                    cursor=raw_cursor,
                )

            raw_start = raw_cursor
            raw_text = block.text or ""
            raw_chunks.append(raw_text)
            for block_char_index, _char in enumerate(raw_text):
                raw_char_refs.append(
                    SourceRef(
                        source=PIISourceType.OCR,
                        block_id=block_id,
                        bbox=block.bbox,
                        block_char_index=block_char_index,
                        raw_index=raw_start + block_char_index,
                    )
                )
            raw_cursor += len(raw_text)
            raw_end = raw_cursor
            raw_spans.append(
                StreamSpan(
                    kind="ocr_block",
                    start=raw_start,
                    end=raw_end,
                    block_id=block_id,
                    bbox=block.bbox,
                )
            )

            if clean_text:
                join_text = _join_clean_blocks(previous_clean_text, clean_text)
                if join_text:
                    clean_cursor = _append_synthetic_text(
                        token=join_text,
                        kind="ocr_inline_gap" if join_text == _OCR_INLINE_GAP_TOKEN else "ocr_join",
                        chunks=clean_chunks,
                        char_refs=clean_char_refs,
                        spans=clean_spans,
                        cursor=clean_cursor,
                    )
                clean_start = clean_cursor
                clean_chunks.append(clean_text)
                for block_char_index in clean_map:
                    if block_char_index is None:
                        clean_char_refs.append(None)
                        continue
                    clean_char_refs.append(
                        SourceRef(
                            source=PIISourceType.OCR,
                            block_id=block_id,
                            bbox=block.bbox,
                            block_char_index=block_char_index,
                            raw_index=raw_start + block_char_index,
                        )
                    )
                clean_cursor += len(clean_text)
                clean_end = clean_cursor
                clean_spans.append(
                    StreamSpan(
                        kind="ocr_block",
                        start=clean_start,
                        end=clean_end,
                        block_id=block_id,
                        bbox=block.bbox,
                    )
                )
                _append_inline_gap_spans(clean_spans, clean_text, clean_start)
                previous_clean_text = clean_text
            else:
                clean_start = clean_cursor
                clean_end = clean_cursor

            scene_blocks.append(
                OCRSceneBlock(
                    block=block.model_copy(deep=True),
                    block_id=block_id,
                    order_index=order_index,
                    line_index=line_index,
                    raw_start=raw_start,
                    raw_end=raw_end,
                    clean_start=clean_start,
                    clean_end=clean_end,
                    clean_text=clean_text,
                    clean_char_to_raw_block_index=clean_map,
                )
            )
            order_index += 1

    scene = _build_scene(scene_blocks)
    stream = StreamInput(
        source=PIISourceType.OCR,
        text="".join(clean_chunks),
        char_refs=tuple(clean_char_refs),
        spans=tuple(clean_spans),
        metadata={"ocr_block_count": len(scene_blocks)},
    )
    return PreparedOCRContext(
        raw_text="".join(raw_chunks),
        stream=stream,
        raw_char_refs=tuple(raw_char_refs),
        raw_spans=tuple(raw_spans),
        scene=scene,
    )


def _prepare_ocr_block_text(text: str) -> tuple[str, tuple[int | None, ...]]:
    chars, raw_indices = _normalize_block_chars(text)
    chars, raw_indices = _rewrite_whitespace(chars, raw_indices)
    chars, raw_indices = _strip_edge_noise(chars, raw_indices)
    clean_text = _apply_ambiguity_fixes("".join(chars))
    return (clean_text, tuple(raw_indices))


def _normalize_block_chars(text: str) -> tuple[list[str], list[int | None]]:
    chars: list[str] = []
    raw_indices: list[int | None] = []
    for raw_index, raw_char in enumerate(text):
        normalized = unicodedata.normalize("NFKC", raw_char)
        for char in normalized:
            rewritten = _normalize_intermediate_char(char)
            if not rewritten:
                continue
            for piece in rewritten:
                chars.append(piece)
                raw_indices.append(raw_index)
    return (chars, raw_indices)


def _normalize_intermediate_char(char: str) -> str:
    if char in _ZERO_WIDTH_CHARS:
        return ""
    if char.isspace():
        return " "
    if unicodedata.category(char).startswith("C"):
        return ""
    return char


def _rewrite_whitespace(chars: list[str], raw_indices: list[int | None]) -> tuple[list[str], list[int | None]]:
    rewritten_chars: list[str] = []
    rewritten_indices: list[int | None] = []
    index = 0
    while index < len(chars):
        current = chars[index]
        if current != " ":
            rewritten_chars.append(current)
            rewritten_indices.append(raw_indices[index])
            index += 1
            continue

        gap_start = index
        while index < len(chars) and chars[index] == " ":
            index += 1
        gap_end = index
        gap_text = _classify_gap(chars, gap_start, gap_end, rewritten_chars)
        if not gap_text:
            continue
        if gap_text == _OCR_INLINE_GAP_TOKEN:
            rewritten_chars.extend(gap_text)
            rewritten_indices.extend([None] * len(gap_text))
            continue
        rewritten_chars.append(gap_text)
        rewritten_indices.append(raw_indices[gap_start])
    return (rewritten_chars, rewritten_indices)


def _classify_gap(
    chars: list[str],
    gap_start: int,
    gap_end: int,
    rewritten_chars: list[str],
) -> str:
    prev_char = rewritten_chars[-1] if rewritten_chars else None
    next_char = chars[gap_end] if gap_end < len(chars) else None
    if prev_char is None or next_char is None:
        return ""
    if _is_punctuation(prev_char) or _is_punctuation(next_char):
        return ""
    if _is_cjk(prev_char) and _is_cjk(next_char):
        if _adjacent_cjk_length_left(chars, gap_start) == 1 or _adjacent_cjk_length_right(chars, gap_end) == 1:
            return ""
        if gap_end - gap_start >= 2:
            return _OCR_INLINE_GAP_TOKEN
        return " "
    return " "


def _strip_edge_noise(chars: list[str], raw_indices: list[int | None]) -> tuple[list[str], list[int | None]]:
    start = 0
    end = len(chars)
    while start < end and _should_strip_edge_char(chars[start]):
        start += 1
    while end > start and _should_strip_edge_char(chars[end - 1]):
        end -= 1
    return (chars[start:end], raw_indices[start:end])


def _should_strip_edge_char(char: str) -> bool:
    return char == " " or char in _EDGE_NOISE_CHARS


def _apply_ambiguity_fixes(text: str) -> str:
    if not text:
        return text
    chars = list(text)
    protected = _protected_mask(text)
    for index, char in enumerate(chars):
        if protected[index]:
            continue
        replacement = _resolve_ambiguous_char(chars, protected, index, char)
        if replacement is not None:
            chars[index] = replacement
    return "".join(chars)


def _protected_mask(text: str) -> list[bool]:
    protected = [False] * len(text)
    start = 0
    while True:
        index = text.find(_OCR_INLINE_GAP_TOKEN, start)
        if index < 0:
            return protected
        for cursor in range(index, index + len(_OCR_INLINE_GAP_TOKEN)):
            protected[cursor] = True
        start = index + len(_OCR_INLINE_GAP_TOKEN)


def _resolve_ambiguous_char(chars: list[str], protected: list[bool], index: int, char: str) -> str | None:
    if char not in {"I", "l", "1", "O", "0", "О"}:
        return None
    prev_char = _adjacent_neighbor(chars, protected, index - 1)
    next_char = _adjacent_neighbor(chars, protected, index + 1)
    if prev_char is None or next_char is None:
        return None
    if _is_ascii_digit(prev_char) and _is_ascii_digit(next_char):
        return "1" if char in {"I", "l", "1"} else "0"
    if _is_ascii_letter(prev_char) and _is_ascii_letter(next_char):
        if prev_char.islower() and next_char.islower():
            return "l" if char in {"I", "l", "1"} else "o"
        return "I" if char in {"I", "l", "1"} else "O"
    return None


def _adjacent_neighbor(chars: list[str], protected: list[bool], index: int) -> str | None:
    if index < 0 or index >= len(chars):
        return None
    if protected[index]:
        return None
    return chars[index]


def _is_ascii_letter(char: str) -> bool:
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _adjacent_cjk_length_left(chars: list[str], gap_start: int) -> int:
    count = 0
    cursor = gap_start - 1
    while cursor >= 0 and _is_cjk(chars[cursor]):
        count += 1
        cursor -= 1
    return count


def _adjacent_cjk_length_right(chars: list[str], gap_end: int) -> int:
    count = 0
    cursor = gap_end
    while cursor < len(chars) and _is_cjk(chars[cursor]):
        count += 1
        cursor += 1
    return count


def _join_clean_blocks(left_text: str | None, right_text: str) -> str:
    if not left_text or not right_text:
        return ""
    left_char = left_text[-1]
    right_char = right_text[0]
    if _is_punctuation(left_char) or _is_punctuation(right_char):
        return ""
    return " "


def _append_synthetic_text(
    *,
    token: str,
    kind: str,
    chunks: list[str],
    char_refs: list[SourceRef | None],
    spans: list[StreamSpan],
    cursor: int,
) -> int:
    if not token:
        return cursor
    chunks.append(token)
    spans.append(StreamSpan(kind=kind, start=cursor, end=cursor + len(token)))
    char_refs.extend([None] * len(token))
    return cursor + len(token)


def _append_inline_gap_spans(spans: list[StreamSpan], text: str, start: int) -> None:
    cursor = 0
    while True:
        index = text.find(_OCR_INLINE_GAP_TOKEN, cursor)
        if index < 0:
            return
        spans.append(
            StreamSpan(
                kind="ocr_inline_gap",
                start=start + index,
                end=start + index + len(_OCR_INLINE_GAP_TOKEN),
            )
        )
        cursor = index + len(_OCR_INLINE_GAP_TOKEN)


def _is_cjk(char: str) -> bool:
    codepoint = ord(char)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x3040 <= codepoint <= 0x30FF
        or 0xAC00 <= codepoint <= 0xD7AF
    )


def _is_punctuation(char: str) -> bool:
    return unicodedata.category(char).startswith("P")


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
