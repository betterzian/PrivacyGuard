"""跨栈共用的基础文本与 span helper。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole, StreamInput, StreamUnit
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break

_ASCII_ALNUM_KINDS = frozenset({"digit_run", "alpha_run", "alnum_run", "ascii_word"})


def is_break_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.BREAK


def is_negative_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.NEGATIVE


def is_control_clue(clue: Clue) -> bool:
    return clue.attr_type is None


def is_control_value_clue(clue: Clue) -> bool:
    return clue.attr_type is None and clue.role == ClueRole.VALUE


def is_control_number_value_clue(clue: Clue) -> bool:
    return (
        is_control_value_clue(clue)
        and (clue.source_metadata.get("control_kind") or [""])[0] == "number"
    )


def control_value_normalized_number(clue: Clue) -> str:
    if not is_control_number_value_clue(clue):
        return ""
    return str((clue.source_metadata.get("normalized_number") or [""])[0]).strip()


def _is_stop_control_clue(clue: Clue) -> bool:
    return clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE}


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


def is_ascii_alnum_like_unit(unit: StreamUnit) -> bool:
    """判定 unit 是否属于可吸收的英数字块。"""
    text = str(unit.text or "")
    return (
        unit.kind in _ASCII_ALNUM_KINDS
        and bool(text)
        and all(char.isascii() and char.isalnum() for char in text)
    )


# ── 数字前缀分析 ──────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class LeftNumeral:
    """关键字左侧紧邻的数字/编号前缀描述。

    kind 取值：
    - ``"ascii_alnum"``   — 12, A3, 501
    - ``"zh_number"``     — 三, 十二, 二十
    - ``"heavenly_stem"`` — 甲, 乙, 丙
    - ``"earthly_branch"``— 子, 丑, 寅
    - ``"none"``          — 无前缀
    """
    kind: str
    digit_count: int    # 等效阿拉伯数字位数
    char_start: int     # 前缀起始 char 偏移
    text: str           # 原始文本


NONE_NUMERAL = LeftNumeral(kind="none", digit_count=0, char_start=-1, text="")

_MAX_ZH_NUMERAL_COLLECT = 4


@lru_cache(maxsize=1)
def _zh_numeral_lookup() -> tuple[dict[str, tuple[str, str]], tuple[int, ...]]:
    """返回 ``{text: (normalized, kind)}`` + 按长度降序排列的长度列表。"""
    from privacyguard.infrastructure.pii.detector.lexicon_loader import load_zh_control_values
    mapping = {item.text: (item.normalized, item.kind) for item in load_zh_control_values()}
    lengths = tuple(sorted({len(t) for t in mapping}, reverse=True))
    return mapping, lengths


def _zh_numeral_digit_count(normalized: str, kind: str) -> int:
    """从 normalized 值推导等效阿拉伯数字位数。"""
    if kind == "zh_number":
        return len(normalized)
    # 天干 / 地支统一算 1 位。
    return 1


def examine_left_numeral(stream: StreamInput, pos: int) -> LeftNumeral:
    """检查 *pos* 左侧紧邻的数字前缀。

    统一处理 ASCII alnum、中文数字（一二三…）、天干地支。
    跳过 inline_gap 后按以下优先级判定：
    1. ASCII alnum unit → 提取 digit_count。
    2. CJK unit → 用 zh_control_values 词表做最长后缀匹配。
    """
    if pos <= 0 or not stream.char_to_unit or not stream.units:
        return NONE_NUMERAL

    # 向左跳过 inline_gap。
    left_ui = _unit_index_left_of(stream, pos)
    while 0 <= left_ui < len(stream.units):
        unit = stream.units[left_ui]
        if unit.kind == "inline_gap" and unit.char_end <= pos:
            left_ui -= 1
            continue
        break

    if left_ui < 0 or left_ui >= len(stream.units):
        return NONE_NUMERAL

    unit = stream.units[left_ui]

    # ── ASCII alnum ──
    if is_ascii_alnum_like_unit(unit):
        text = str(unit.text or "")
        digit_count = sum(1 for ch in text if ch.isdigit())
        return LeftNumeral(
            kind="ascii_alnum", digit_count=digit_count,
            char_start=unit.char_start, text=text,
        )

    # ── CJK → 尝试 zh_control_values 匹配 ──
    if unit.kind != "cjk_char":
        return NONE_NUMERAL

    collected: list[tuple[str, int]] = []  # (char_text, char_start)
    ui = left_ui
    while ui >= 0 and len(collected) < _MAX_ZH_NUMERAL_COLLECT:
        u = stream.units[ui]
        if u.kind == "cjk_char" and len(u.text) == 1 and "\u4e00" <= u.text <= "\u9fff":
            collected.append((u.text, u.char_start))
            ui -= 1
        else:
            break

    if not collected:
        return NONE_NUMERAL

    collected.reverse()  # 转为正序（左→右）

    # 最长后缀匹配：从整段开始逐步缩短左端。
    mapping, _ = _zh_numeral_lookup()
    for start_idx in range(len(collected)):
        candidate = "".join(ch for ch, _ in collected[start_idx:])
        if candidate in mapping:
            normalized, kind = mapping[candidate]
            char_start = collected[start_idx][1]
            return LeftNumeral(
                kind=kind,
                digit_count=_zh_numeral_digit_count(normalized, kind),
                char_start=char_start,
                text=candidate,
            )

    return NONE_NUMERAL
