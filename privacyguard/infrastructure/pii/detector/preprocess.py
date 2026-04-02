"""Prompt 与 OCR 流的预处理。"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from statistics import mean

from privacyguard.domain.enums import PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector.models import (
    OCRScene,
    OCRSceneBlock,
    PreparedOCRContext,
    SourceRef,
    StreamInput,
    StreamUnit,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCR_INLINE_GAP_TOKEN,
    _OCR_SEMANTIC_BREAK_TOKEN,
)

_ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"})
_EDGE_NOISE_CHARS = frozenset("`~^_|/\\<>《》")


@dataclass(frozen=True, slots=True)
class _BlockToken:
    kind: str
    text: str
    raw_indices: tuple[int | None, ...]


def build_prompt_stream(text: str) -> StreamInput:
    clean_text = text or ""
    units, char_to_unit = _build_stream_units(clean_text)
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
    return StreamInput(
        source=PIISourceType.PROMPT,
        text=clean_text,
        units=units,
        char_to_unit=char_to_unit,
        char_refs=char_refs,
    )


def build_ocr_stream(
    blocks: list[OCRTextBlock],
    *,
    image_height: int | None = None,
) -> PreparedOCRContext:
    """构建 OCR 流。

    先经过 UI 结构理解层（裁剪→分行→行内切分→区域分割→布局拼接）
    得到语义分组，再按组构建 stream。组间插 semantic break，组内
    不同视觉行之间仅用普通间隔。
    """
    from privacyguard.infrastructure.pii.detector.ui_layout import (
        analyze_ui_layout,
        group_into_lines,
    )

    groups = analyze_ui_layout(blocks, image_height=image_height)

    # 无有效分组时回退：跳过裁剪，直接用旧分行逻辑，每行作为独立组。
    if not groups:
        fallback_lines = _group_ocr_lines(blocks)
        groups_as_lines = [[line] for line in fallback_lines]
        return _build_stream_from_line_groups(groups_as_lines)

    # 每个语义组内部再按视觉行排列，保留行结构供 ocr.py 几何搜索使用。
    groups_as_lines: list[list[list[OCRTextBlock]]] = []
    for group in groups:
        lines = group_into_lines(group.blocks)
        if lines:
            groups_as_lines.append(lines)

    if not groups_as_lines:
        fallback_lines = _group_ocr_lines(blocks)
        groups_as_lines = [[line] for line in fallback_lines]

    return _build_stream_from_line_groups(groups_as_lines)


def _build_stream_from_line_groups(
    groups_as_lines: list[list[list[OCRTextBlock]]],
) -> PreparedOCRContext:
    """从「语义组→视觉行→blocks」三层结构构建 stream。

    - 组间：插入 semantic break。
    - 组内不同视觉行间：普通空格间隔（不插 semantic break）。
    - 同一视觉行内不同 block 间：空格。
    """
    raw_chunks: list[str] = []
    clean_chunks: list[str] = []
    clean_char_refs: list[SourceRef | None] = []
    scene_blocks: list[OCRSceneBlock] = []
    raw_cursor = 0
    clean_cursor = 0
    order_index = 0
    line_index = 0

    for group_idx, group_lines in enumerate(groups_as_lines):
        # 组间插 semantic break。
        if group_idx > 0 and raw_chunks:
            raw_chunks.append(_OCR_SEMANTIC_BREAK_TOKEN)
            raw_cursor += len(_OCR_SEMANTIC_BREAK_TOKEN)
            if clean_chunks:
                _append_clean_token(
                    clean_chunks=clean_chunks,
                    clean_char_refs=clean_char_refs,
                    token=_OCR_SEMANTIC_BREAK_TOKEN,
                )
                clean_cursor += len(_OCR_SEMANTIC_BREAK_TOKEN)

        for local_line_idx, line_blocks in enumerate(group_lines):
            prepared_line = [
                (
                    block,
                    block.block_id or f"ocr-{order_index + offset}",
                    _prepare_ocr_block_text(block.text or ""),
                )
                for offset, block in enumerate(line_blocks)
            ]

            # 组内非首行：用普通空格分隔（不插 semantic break）。
            if local_line_idx > 0 and raw_chunks:
                raw_chunks.append(" ")
                raw_cursor += 1
            # 首组首行之后的组首行由上面的 semantic break 处理，无需额外分隔。

            previous_clean_text: str | None = None
            for block_offset, (block, block_id, (clean_text, clean_raw_indices)) in enumerate(prepared_line):
                if block_offset:
                    raw_chunks.append(" ")
                    raw_cursor += 1

                raw_start = raw_cursor
                raw_text = block.text or ""
                raw_chunks.append(raw_text)
                raw_cursor += len(raw_text)
                raw_end = raw_cursor

                if clean_text:
                    join_text = _join_clean_blocks(previous_clean_text, clean_text)
                    if join_text:
                        _append_clean_token(
                            clean_chunks=clean_chunks,
                            clean_char_refs=clean_char_refs,
                            token=join_text,
                        )
                        clean_cursor += len(join_text)
                    clean_start = clean_cursor
                    clean_chunks.append(clean_text)
                    for raw_block_index in clean_raw_indices:
                        if raw_block_index is None:
                            clean_char_refs.append(None)
                            continue
                        clean_char_refs.append(
                            SourceRef(
                                source=PIISourceType.OCR,
                                block_id=block_id,
                                bbox=block.bbox,
                                block_char_index=raw_block_index,
                                raw_index=raw_start + raw_block_index,
                            )
                        )
                    clean_cursor += len(clean_text)
                    clean_end = clean_cursor
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
                    )
                )
                order_index += 1

            line_index += 1

    stream_text = "".join(clean_chunks)
    units, char_to_unit = _build_stream_units(stream_text)
    stream = StreamInput(
        source=PIISourceType.OCR,
        text=stream_text,
        units=units,
        char_to_unit=char_to_unit,
        char_refs=tuple(clean_char_refs),
        metadata={"ocr_block_count": len(scene_blocks)},
    )
    return PreparedOCRContext(
        raw_text="".join(raw_chunks),
        stream=stream,
        scene=_build_scene(scene_blocks),
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
        normalized = raw_char if unicodedata.category(raw_char).startswith("P") else unicodedata.normalize("NFKC", raw_char)
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
    if not chars:
        return (chars, raw_indices)
    tokens = _tokenize_intermediate(chars, raw_indices)
    gap_outputs = _plan_gap_outputs(tokens)
    rewritten_chars: list[str] = []
    rewritten_indices: list[int | None] = []
    for index, token in enumerate(tokens):
        if token.kind != "space_run":
            rewritten_chars.extend(token.text)
            rewritten_indices.extend(token.raw_indices)
            continue
        output = gap_outputs.get(index, "")
        if not output:
            continue
        if output == " ":
            rewritten_chars.append(" ")
            rewritten_indices.append(token.raw_indices[0] if token.raw_indices else None)
            continue
        if output == _OCR_INLINE_GAP_TOKEN:
            rewritten_chars.extend(output)
            rewritten_indices.extend([None] * len(output))
            continue
        rewritten_chars.extend(output)
        rewritten_indices.extend([None] * len(output))
    return (rewritten_chars, rewritten_indices)


def _tokenize_intermediate(chars: list[str], raw_indices: list[int | None]) -> list[_BlockToken]:
    tokens: list[_BlockToken] = []
    cursor = 0
    while cursor < len(chars):
        char = chars[cursor]
        if char == " ":
            end = cursor + 1
            while end < len(chars) and chars[end] == " ":
                end += 1
            tokens.append(_BlockToken(kind="space_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_cjk(char):
            end = cursor + 1
            while end < len(chars) and _is_cjk(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="cjk_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_ascii_letter(char):
            end = cursor + 1
            while end < len(chars) and _is_ascii_letter(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="ascii_word", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_ascii_digit(char):
            end = cursor + 1
            while end < len(chars) and _is_ascii_digit(chars[end]):
                end += 1
            tokens.append(_BlockToken(kind="digit_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
            cursor = end
            continue
        if _is_punctuation(char):
            tokens.append(_BlockToken(kind="punct", text=char, raw_indices=(raw_indices[cursor],)))
            cursor += 1
            continue
        end = cursor + 1
        while (
            end < len(chars)
            and chars[end] != " "
            and not _is_cjk(chars[end])
            and not _is_ascii_letter(chars[end])
            and not _is_ascii_digit(chars[end])
            and not _is_punctuation(chars[end])
        ):
            end += 1
        tokens.append(_BlockToken(kind="other_run", text="".join(chars[cursor:end]), raw_indices=tuple(raw_indices[cursor:end])))
        cursor = end
    return tokens


def _plan_gap_outputs(tokens: list[_BlockToken]) -> dict[int, str]:
    outputs: dict[int, str] = {}
    handled: set[int] = set()
    for index in range(1, len(tokens) - 3):
        if tokens[index].kind != "space_run":
            continue
        left = tokens[index - 1]
        middle = tokens[index + 1]
        right_gap = tokens[index + 2]
        right = tokens[index + 3]
        if (
            left.kind == "cjk_run"
            and middle.kind == "cjk_run"
            and len(middle.text) == 1
            and right_gap.kind == "space_run"
            and right.kind == "cjk_run"
        ):
            left_len = len(tokens[index].text)
            right_len = len(right_gap.text)
            if abs(left_len - right_len) <= 1:
                outputs[index] = ""
                outputs[index + 2] = ""
            elif left_len < right_len:
                outputs[index] = ""
                outputs[index + 2] = _preserve_gap_text(right_len)
            else:
                outputs[index] = _preserve_gap_text(left_len)
                outputs[index + 2] = ""
            handled.add(index)
            handled.add(index + 2)
    for index, token in enumerate(tokens):
        if token.kind != "space_run":
            continue
        if index in handled:
            continue
        prev_token = tokens[index - 1] if index > 0 else None
        next_token = tokens[index + 1] if index + 1 < len(tokens) else None
        outputs[index] = _default_gap_output(prev_token, next_token, len(token.text))
        if prev_token is None or next_token is None:
            continue
        if prev_token.kind == "cjk_run" and next_token.kind == "cjk_run" and len(next_token.text) == 1:
            outputs[index] = "" if len(token.text) <= 2 else _preserve_gap_text(len(token.text))
            continue
        if (
            prev_token.kind == "cjk_run"
            and len(prev_token.text) == 1
            and next_token.kind == "cjk_run"
            and not _has_left_cjk_attachment(tokens, index)
        ):
            outputs[index] = "" if len(token.text) <= 2 else _preserve_gap_text(len(token.text))
    return outputs


def _has_left_cjk_attachment(tokens: list[_BlockToken], gap_index: int) -> bool:
    return (
        gap_index >= 3
        and tokens[gap_index - 1].kind == "cjk_run"
        and len(tokens[gap_index - 1].text) == 1
        and tokens[gap_index - 2].kind == "space_run"
        and tokens[gap_index - 3].kind == "cjk_run"
    )


def _default_gap_output(prev_token: _BlockToken | None, next_token: _BlockToken | None, gap_len: int) -> str:
    if prev_token is None or next_token is None:
        return ""
    if prev_token.kind == "punct" or next_token.kind == "punct":
        return ""
    if prev_token.kind == "cjk_run" and next_token.kind == "cjk_run":
        return " " if gap_len == 1 else _OCR_INLINE_GAP_TOKEN
    return " "


def _preserve_gap_text(gap_len: int) -> str:
    return " " if gap_len == 1 else _OCR_INLINE_GAP_TOKEN


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
    for token in (_OCR_INLINE_GAP_TOKEN, _OCR_SEMANTIC_BREAK_TOKEN):
        start = 0
        while True:
            index = text.find(token, start)
            if index < 0:
                break
            for cursor in range(index, index + len(token)):
                protected[cursor] = True
            start = index + len(token)
    return protected


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


def _append_clean_token(
    *,
    clean_chunks: list[str],
    clean_char_refs: list[SourceRef | None],
    token: str,
) -> None:
    if not token:
        return
    clean_chunks.append(token)
    clean_char_refs.extend([None] * len(token))


def _join_clean_blocks(left_text: str | None, right_text: str) -> str:
    if not left_text or not right_text:
        return ""
    if _is_punctuation(left_text[-1]) or _is_punctuation(right_text[0]):
        return ""
    return " "


def _build_stream_units(text: str) -> tuple[tuple[StreamUnit, ...], tuple[int, ...]]:
    if not text:
        return ((), ())
    units: list[StreamUnit] = []
    char_to_unit: list[int] = []
    cursor = 0
    while cursor < len(text):
        if text.startswith(_OCR_INLINE_GAP_TOKEN, cursor):
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="inline_gap",
                text=_OCR_INLINE_GAP_TOKEN,
                start=cursor,
                end=cursor + len(_OCR_INLINE_GAP_TOKEN),
            )
            continue
        if text.startswith(_OCR_SEMANTIC_BREAK_TOKEN, cursor):
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="semantic_break",
                text=_OCR_SEMANTIC_BREAK_TOKEN,
                start=cursor,
                end=cursor + len(_OCR_SEMANTIC_BREAK_TOKEN),
            )
            continue
        char = text[cursor]
        if char == " ":
            cursor = _append_unit(units, char_to_unit, kind="space", text=" ", start=cursor, end=cursor + 1)
            continue
        if _is_cjk(char):
            cursor = _append_unit(units, char_to_unit, kind="cjk_char", text=char, start=cursor, end=cursor + 1)
            continue
        if _is_ascii_letter(char):
            end = cursor + 1
            while end < len(text) and _is_ascii_letter(text[end]):
                end += 1
            cursor = _append_unit(
                units,
                char_to_unit,
                kind="ascii_word",
                text=text[cursor:end],
                start=cursor,
                end=end,
            )
            continue
        if _is_ascii_digit(char):
            cursor = _append_unit(units, char_to_unit, kind="digit_char", text=char, start=cursor, end=cursor + 1)
            continue
        if _is_punctuation(char):
            cursor = _append_unit(units, char_to_unit, kind="punct", text=char, start=cursor, end=cursor + 1)
            continue
        cursor = _append_unit(units, char_to_unit, kind="other_char", text=char, start=cursor, end=cursor + 1)
    return (tuple(units), tuple(char_to_unit))


def _append_unit(
    units: list[StreamUnit],
    char_to_unit: list[int],
    *,
    kind: str,
    text: str,
    start: int,
    end: int,
) -> int:
    unit_index = len(units)
    units.append(StreamUnit(kind=kind, text=text, char_start=start, char_end=end))
    char_to_unit.extend([unit_index] * (end - start))
    return end


def _is_cjk(char: str) -> bool:
    codepoint = ord(char)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x3040 <= codepoint <= 0x30FF
        or 0xAC00 <= codepoint <= 0xD7AF
    )


def _is_ascii_letter(char: str) -> bool:
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


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
