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

