"""文本归一化与匹配辅助工具。"""

import re
import unicodedata


def normalize_text(text: str) -> str:
    """执行全半角、空白与大小写归一化。"""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized.lower()


def find_all_matches(pattern: re.Pattern[str], text: str) -> list[str]:
    """提取给定正则在文本中的全部命中片段。"""
    return [match.group(0) for match in pattern.finditer(text)]


def is_cjk_text(text: str) -> bool:
    """判断文本在去空白/去标点后是否全部落在 CJK 统一表意区间。

    - 混入拉丁字母/数字/罗马标点均视为非纯 CJK；
    - 空文本视为 False；
    - 单字判别友好：保留中文姓氏/单字名、英文常见名的分流路径。
    """
    if not text:
        return False
    compact = re.sub(r"[\s\W_]+", "", str(text), flags=re.UNICODE)
    if not compact:
        return False
    return all("\u4e00" <= char <= "\u9fff" for char in compact)

