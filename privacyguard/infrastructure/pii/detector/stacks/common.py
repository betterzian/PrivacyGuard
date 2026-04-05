"""跨栈共用的基础文本与 span helper。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole, StreamInput
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break


def is_break_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.BREAK


def is_negative_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.NEGATIVE


def is_connector_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.CONNECTOR


def is_control_clue(clue: Clue) -> bool:
    return clue.attr_type is None


def _is_stop_control_clue(clue: Clue) -> bool:
    return clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR}


def _char_span_to_unit_span(stream: StreamInput, start: int, end: int) -> tuple[int, int]:
    if not stream.char_to_unit or start >= end:
        return (0, 0)
    return (stream.char_to_unit[start], stream.char_to_unit[end - 1] + 1)


def _unit_char_start(stream: StreamInput, unit_index: int) -> int:
    if not stream.units:
        return 0
    if unit_index <= 0:
        return 0
    if unit_index >= len(stream.units):
        return len(stream.text)
    return stream.units[unit_index].char_start


def _unit_char_end(stream: StreamInput, unit_index: int) -> int:
    if not stream.units:
        return 0
    if unit_index <= 0:
        return 0
    if unit_index > len(stream.units):
        return len(stream.text)
    return stream.units[unit_index - 1].char_end


def _skip_separators(text: str, start: int) -> int:
    """跳过 label 到 value 之间的空白和轻分隔符。"""
    index = start
    while index < len(text) and (text[index].isspace() or is_soft_break(text[index])):
        index += 1
    return index


def _unit_index_at_or_after(stream: StreamInput, char_index: int) -> int:
    if not stream.char_to_unit or char_index >= len(stream.char_to_unit):
        return len(stream.units)
    ui = stream.char_to_unit[char_index]
    while ui < len(stream.units) and stream.units[ui].char_end <= char_index:
        ui += 1
    return ui


def _unit_index_left_of(stream: StreamInput, char_index: int) -> int:
    if char_index <= 0 or not stream.char_to_unit:
        return -1
    ui = stream.char_to_unit[char_index - 1]
    while ui >= 0 and stream.units[ui].char_start >= char_index:
        ui -= 1
    return ui


def _count_non_space_units(units, start_ui: int, end_ui: int) -> int:
    count = 0
    for ui in range(max(0, start_ui), min(len(units), end_ui)):
        if units[ui].kind != "space":
            count += 1
    return count
