"""跨栈共用的基础文本与 span helper。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from privacyguard.infrastructure.pii.detector.models import AddressComponentType, Clue, ClueFamily, ClueRole, StreamInput, StreamUnit
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_name_joiner

_ASCII_ALNUM_KINDS = frozenset({"digit_run", "alpha_run", "alnum_run", "ascii_word"})
_LABEL_SEED_SKIPPABLE_SEPARATOR_CHARS = frozenset(":：-—–=|")


class ExpansionBreakPolicy(StrEnum):
    """统一边界判定策略。"""

    ADDRESS_CLUE = "address_clue"
    CLUE_SEQUENCE_BLOCKER = "clue_sequence_blocker"
    ORG_LEFT_BOUNDARY = "org_left_boundary"
    NAME_EN_RIGHT_UNIT = "name_en_right_unit"
    NAME_EN_LEFT_UNIT = "name_en_left_unit"
    NAME_ZH_RIGHT_UNIT = "name_zh_right_unit"
    NAME_ZH_LEFT_UNIT = "name_zh_left_unit"


def need_break(
    policy: ExpansionBreakPolicy,
    flag: str | None,
    *,
    next_unit: StreamUnit | None = None,
    prev_unit: StreamUnit | None = None,
    upper: int | None = None,
    lower: int | None = None,
    left_char: str | None = None,
    right_char: str | None = None,
) -> bool:
    """判断当前一步是否应停止扩张。

    仅返回 bool，不维护任何索引。
    """
    name_unit_policies = {
        ExpansionBreakPolicy.NAME_EN_RIGHT_UNIT,
        ExpansionBreakPolicy.NAME_EN_LEFT_UNIT,
        ExpansionBreakPolicy.NAME_ZH_RIGHT_UNIT,
        ExpansionBreakPolicy.NAME_ZH_LEFT_UNIT,
    }
    if policy == ExpansionBreakPolicy.ADDRESS_CLUE:
        return flag not in {None, ",", "，", "SPACE", "INLINE_GAP"}
    if policy == ExpansionBreakPolicy.CLUE_SEQUENCE_BLOCKER:
        return flag in {"OCR_BREAK"} or (flag is not None and flag not in {",", "，", "SPACE", "INLINE_GAP"})
    if policy == ExpansionBreakPolicy.ORG_LEFT_BOUNDARY:
        return flag in {"OCR_BREAK"} or (flag is not None and flag not in {",", "，", "SPACE", "INLINE_GAP"})
    if policy not in name_unit_policies:
        return False
    is_right_policy = policy in {
        ExpansionBreakPolicy.NAME_EN_RIGHT_UNIT,
        ExpansionBreakPolicy.NAME_ZH_RIGHT_UNIT,
    }
    is_left_policy = policy in {
        ExpansionBreakPolicy.NAME_EN_LEFT_UNIT,
        ExpansionBreakPolicy.NAME_ZH_LEFT_UNIT,
    }
    is_zh_policy = policy in {
        ExpansionBreakPolicy.NAME_ZH_RIGHT_UNIT,
        ExpansionBreakPolicy.NAME_ZH_LEFT_UNIT,
    }
    subject = next_unit if is_right_policy else prev_unit
    if subject is None:
        return flag is not None
    if is_right_policy and upper is not None and subject.char_start >= upper:
        return True
    if is_left_policy and lower is not None and subject.char_end <= lower:
        return True
    if flag == "OCR_BREAK":
        return True
    if flag == "INLINE_GAP":
        return False
    if flag == "SPACE":
        if policy == ExpansionBreakPolicy.NAME_EN_RIGHT_UNIT:
            return not (
                next_unit is not None
                and next_unit.kind == "ascii_word"
                and (upper is None or next_unit.char_start < upper)
            )
        return not (
            prev_unit is not None
            and prev_unit.kind == "ascii_word"
            and (lower is None or prev_unit.char_end > lower)
        )
    if is_zh_policy:
        if subject.kind == "cjk_char":
            return False
        if subject.kind == "punct":
            punct = flag if flag is not None else subject.text
            return not is_name_joiner(punct, left_char, right_char)
        return True
    if subject.kind == "ascii_word":
        return False
    if subject.kind == "punct":
        punct = flag if flag is not None else subject.text
        return not is_name_joiner(punct, left_char, right_char)
    return True


def is_negative_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.NEGATIVE


def is_control_clue(clue: Clue) -> bool:
    return clue.family == ClueFamily.CONTROL


def is_control_value_clue(clue: Clue) -> bool:
    return clue.family == ClueFamily.CONTROL and clue.attr_type is None and clue.role == ClueRole.VALUE


def is_control_number_value_clue(clue: Clue) -> bool:
    return (
        is_control_value_clue(clue)
        and (clue.source_metadata.get("control_kind") or [""])[0] == "number"
    )


def control_value_normalized_number(clue: Clue) -> str:
    if not is_control_number_value_clue(clue):
        return ""
    return str((clue.source_metadata.get("normalized_number") or [""])[0]).strip()


def _char_span_to_unit_span(stream: StreamInput, start: int, end: int) -> tuple[int, int]:
    if not stream.char_to_unit or start >= end:
        return (0, -1)
    return (stream.char_to_unit[start], stream.char_to_unit[end - 1])


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
        return stream.units[0].char_end if unit_index == 0 else 0
    if unit_index >= len(stream.units):
        return len(stream.text)
    return stream.units[unit_index].char_end


def _skip_separators(text: str, start: int) -> int:
    """跳过 label 到 value 之间的空白和轻分隔符。"""
    index = start
    while index < len(text) and (
        text[index].isspace() or _is_label_seed_skippable_separator_char(text[index])
    ):
        index += 1
    return index


def _is_label_seed_skippable_separator_char(char: str) -> bool:
    """统一维护 label/prefix-key 允许跨过的显式分隔符。"""
    return char in _LABEL_SEED_SKIPPABLE_SEPARATOR_CHARS


def _label_seed_start_char(stream: StreamInput, start_char: int) -> int:
    """统一计算 LABEL/START 起栈后的 seed 起点。"""
    if not stream.units:
        return max(0, start_char)
    cursor = max(0, start_char)
    ui = _unit_index_at_or_after(stream, cursor)
    while ui < len(stream.units):
        unit = stream.units[ui]
        unit_text = unit.text or ""
        if unit.char_start < cursor:
            ui += 1
            continue
        if unit.kind == "inline_gap":
            cursor = unit.char_end
            ui += 1
            continue
        if unit.kind == "space" or unit_text.isspace():
            cursor = unit.char_end
            ui += 1
            continue
        if unit.kind == "punct" and _is_label_seed_skippable_separator_char(unit_text):
            cursor = unit.char_end
            ui += 1
            continue
        break
    return cursor


def _family_value_floor_char(context, family: ClueFamily) -> int:
    """统一读取某个语义 family 当前生效的 value floor。"""
    return context.effective_value_floor_char(family)


def _starter_is_before_family_value_floor(context, clue: Clue, family: ClueFamily) -> bool:
    """非 LABEL/START starter 若落在 family floor 左侧则拒绝起栈。"""
    if clue.role in {ClueRole.LABEL, ClueRole.START}:
        return False
    return clue.start < _family_value_floor_char(context, family)


def _floor_clamped_label_seed_start_char(context, family: ClueFamily, start_char: int) -> int:
    """统一计算受 family value floor 约束的 LABEL/START seed 起点。"""
    return max(
        _label_seed_start_char(context.stream, start_char),
        _family_value_floor_char(context, family),
    )


def _clamp_left_boundary_to_value_floor(start: int, floor_char: int) -> int:
    """左扩后的起点不得越过当前 family value floor。"""
    return max(start, floor_char)


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


@dataclass(frozen=True, slots=True)
class ZhAddressLeftNumeralRule:
    """中文地址 key 左侧编号前缀的统一校验窗口。"""

    min_digit_count: int
    max_digit_count: int
    min_ascii_alnum_len: int | None = None
    max_ascii_alnum_len: int | None = None


_ZH_ADDRESS_LEFT_NUMERAL_RULES: dict[str, ZhAddressLeftNumeralRule] = {
    "号": ZhAddressLeftNumeralRule(1, 5, 1, 5),
    "号楼": ZhAddressLeftNumeralRule(1, 4, 1, 5),
    "栋": ZhAddressLeftNumeralRule(1, 4, 1, 5),
    "幢": ZhAddressLeftNumeralRule(1, 4, 1, 5),
    "座": ZhAddressLeftNumeralRule(1, 4, 1, 5),
    "单元": ZhAddressLeftNumeralRule(1, 4, 1, 5),
    "层": ZhAddressLeftNumeralRule(1, 2, 1, 2),
    "楼": ZhAddressLeftNumeralRule(1, 2, 1, 2),
    "室": ZhAddressLeftNumeralRule(1, 4, 1, 4),
    "房": ZhAddressLeftNumeralRule(2, 4, 2, 4),
    "户": ZhAddressLeftNumeralRule(2, 4, 2, 4),
    "弄": ZhAddressLeftNumeralRule(1, 3, 1, 3),
}

_STRICT_ZH_ADDRESS_LEFT_NUMERAL_KEYS = frozenset({
    "号",
    "号楼",
    "栋",
    "幢",
    "座",
    "单元",
    "层",
    "室",
    "房",
    "户",
})


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


def zh_address_left_numeral_rule(key_text: str) -> ZhAddressLeftNumeralRule | None:
    """返回中文地址 key 的统一左前缀校验规则。"""

    return _ZH_ADDRESS_LEFT_NUMERAL_RULES.get(str(key_text or ""))


def zh_address_key_requires_strict_left_numeral(key_text: str) -> bool:
    """判断当前中文地址 key 是否必须独立通过左前缀校验。"""

    return str(key_text or "") in _STRICT_ZH_ADDRESS_LEFT_NUMERAL_KEYS


def _left_numeral_matches_rule(
    prefix: LeftNumeral,
    rule: ZhAddressLeftNumeralRule,
) -> bool:
    if prefix.kind == "none":
        return False
    if prefix.kind == "ascii_alnum":
        text_len = len(prefix.text)
        if prefix.text.isdigit():
            return rule.min_digit_count <= prefix.digit_count <= rule.max_digit_count
        min_len = rule.min_ascii_alnum_len if rule.min_ascii_alnum_len is not None else rule.min_digit_count
        max_len = rule.max_ascii_alnum_len if rule.max_ascii_alnum_len is not None else rule.max_digit_count
        return min_len <= text_len <= max_len
    return rule.min_digit_count <= prefix.digit_count <= rule.max_digit_count


def valid_left_numeral_for_zh_address_key(
    stream: StreamInput,
    pos: int,
    key_text: str,
) -> LeftNumeral:
    """返回符合指定中文地址 key 规则的左前缀；不合法则返回 `NONE_NUMERAL`。"""

    rule = zh_address_left_numeral_rule(key_text)
    if rule is None:
        return NONE_NUMERAL
    prefix = examine_left_numeral(stream, pos)
    if not _left_numeral_matches_rule(prefix, rule):
        return NONE_NUMERAL
    return prefix
