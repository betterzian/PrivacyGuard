"""新主链共享常量与符号分类。"""

from __future__ import annotations


# 用私有区单字符哨兵保留边界语义，避免长占位符拉长 scanner 的扫描文本。
_OCR_SEMANTIC_BREAK_TOKEN = "\uE001"
_OCR_INLINE_GAP_TOKEN = "\uE000"


# ── 符号分类 ──
# 全局只分两档：hard_break（断句）和 soft_break（轻分隔）。
# 语义判断（并列/从属、是否保留）交给各 stack 根据上下文决定。

_HARD_BREAK_CHARS: frozenset[str] = frozenset(";；。！？!?")
"""硬断句符号。跨此边界不合并任何 PII。"""

_SOFT_BREAK_CHARS: frozenset[str] = frozenset(",，、:：-—|/\\()（）")
"""轻分隔符号。是否跳过由各 stack 根据组件关系决定。"""


def is_hard_break(char: str) -> bool:
    """字符是否为硬断句符号。"""
    return char in _HARD_BREAK_CHARS


def is_soft_break(char: str) -> bool:
    """字符是否为轻分隔符号。"""
    return char in _SOFT_BREAK_CHARS


def is_any_break(char: str) -> bool:
    """字符是否为任意断点符号（hard 或 soft）。"""
    return char in _HARD_BREAK_CHARS or char in _SOFT_BREAK_CHARS


# ── 姓名三元组判断 ──
# 符号本身无独立语义，由左右邻居的字符类型决定是否保留。
# 仅以下组合中的符号被视为姓名值的一部分：
#   CJK    + · + CJK     → 少数民族姓名
#   letter + ' + letter  → 英文姓名（O'Brien）
#   letter + - + letter  → 英文姓名（Mary-Jane）
#   letter + . + letter  → 英文姓名缩写（J.K.）

_ZH_NAME_JOINERS: frozenset[str] = frozenset("·•‧")
"""中文姓名内部连接符（含 OCR 常见的圆点变体）。"""

_EN_NAME_JOINERS: frozenset[str] = frozenset("''-.")
"""英文姓名内部连接符。"""


def _is_cjk(char: str) -> bool:
    cp = ord(char)
    return (
        0x3400 <= cp <= 0x4DBF
        or 0x4E00 <= cp <= 0x9FFF
        or 0xF900 <= cp <= 0xFAFF
    )


def _is_ascii_letter(char: str) -> bool:
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


def is_name_joiner(char: str, left: str | None, right: str | None) -> bool:
    """判断 left + char + right 是否构成姓名内部的合法三元组。

    需要左右邻居都存在且满足字符类型约束。
    """
    if left is None or right is None:
        return False
    # CJK + joiner + CJK。
    if char in _ZH_NAME_JOINERS and _is_cjk(left) and _is_cjk(right):
        return True
    # letter + joiner + letter。
    if char in _EN_NAME_JOINERS and _is_ascii_letter(left) and _is_ascii_letter(right):
        return True
    return False


# ── 地址 digit-dash-digit 判断 ──

def is_digit_dash(char: str, left: str | None, right: str | None) -> bool:
    """digit + - + digit：地址门牌/楼层中的数字连接。"""
    if char != "-":
        return False
    if left is None or right is None:
        return False
    return left.isdigit() and right.isdigit()


__all__ = [
    "_OCR_INLINE_GAP_TOKEN",
    "_OCR_SEMANTIC_BREAK_TOKEN",
    "_HARD_BREAK_CHARS",
    "_SOFT_BREAK_CHARS",
    "_ZH_NAME_JOINERS",
    "_EN_NAME_JOINERS",
    "is_hard_break",
    "is_soft_break",
    "is_any_break",
    "is_name_joiner",
    "is_digit_dash",
]
