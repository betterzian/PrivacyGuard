"""占位符短码单一真源与格式化/解析工具。

占位符统一格式：

- 通用：``[[TYPE#N]]``
- 地址：``[[ADDR#N.SPEC]]``（SPEC 为去重后按 COUNTRY/PROV/CITY/DIST/ROAD/DTL 顺序拼接）
- 数字/混合：``[[NUM#N.LEN=L]]`` / ``[[ALNUM#N.LEN=L]]``

- 使用 ASCII ``[[`` / ``]]``，避免字体缺字与模板语法冲突。
- ``N`` 为 session 全局下标（跨 attr_type 共享序号）。
"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType

# attr_type → 占位符短码（TYPE 字段的单一真源）。
PLACEHOLDER_TYPE_CODE: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "NAME",
    PIIAttributeType.ORGANIZATION: "ORG",
    PIIAttributeType.ADDRESS: "ADDR",
    PIIAttributeType.PHONE: "PHONE",
    PIIAttributeType.EMAIL: "EMAIL",
    PIIAttributeType.ID_NUMBER: "ID_NUMBER",
    PIIAttributeType.BANK_NUMBER: "BANK_CARD",
    PIIAttributeType.LICENSE_PLATE: "LICENSE_PLATE",
    PIIAttributeType.DRIVER_LICENSE: "DRIVER_LICENSE",
    PIIAttributeType.PASSPORT_NUMBER: "PASSPORT",
    PIIAttributeType.TIME: "TIME",
    PIIAttributeType.AMOUNT: "AMOUNT",
    PIIAttributeType.DETAILS: "DETAIL",
    PIIAttributeType.NUM: "NUM",
    PIIAttributeType.ALNUM: "ALNUM",
}

# 括号字符常量（显式拆出便于统一渲染与解析）。
PLACEHOLDER_LEFT_BRACKET = "[["
PLACEHOLDER_RIGHT_BRACKET = "]]"

# 占位符正则：TYPE 大写英文或下划线；N 数字；SPEC 可选，内部允许大写英文/数字/`=+-`。
PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(
    rf"^{re.escape(PLACEHOLDER_LEFT_BRACKET)}(?P<label>[A-Z_]+)#(?P<index>\d+)(?:\.(?P<spec>[A-Z0-9=+\-]+))?{re.escape(PLACEHOLDER_RIGHT_BRACKET)}$"
)


def attr_type_code(attr_type: PIIAttributeType) -> str:
    """返回 attr_type 对应的占位符短码；未登记时返回空串。"""
    return PLACEHOLDER_TYPE_CODE.get(attr_type, "")


def parse_placeholder(text: str) -> tuple[str, int, str] | None:
    """解析占位符字符串。

    返回 ``(label, index, spec)``；spec 缺失时为空串。解析失败返回 None。
    """
    if not isinstance(text, str):
        return None
    matched = PLACEHOLDER_PATTERN.match(text)
    if matched is None:
        return None
    label = matched.group("label") or ""
    index_str = matched.group("index") or "0"
    spec = matched.group("spec") or ""
    try:
        index = int(index_str)
    except ValueError:
        return None
    return label, index, spec


def format_placeholder(label: str, index: int, spec: str = "") -> str:
    """按约定拼装占位符字符串；label / index 为空或非法时抛错。"""
    label_text = str(label or "").strip()
    if not label_text:
        raise ValueError("format_placeholder 要求 label 非空")
    if index < 0:
        raise ValueError("format_placeholder 要求 index >= 0")
    suffix = f".{spec}" if spec else ""
    return f"{PLACEHOLDER_LEFT_BRACKET}{label_text}#{index}{suffix}{PLACEHOLDER_RIGHT_BRACKET}"


__all__ = [
    "PLACEHOLDER_LEFT_BRACKET",
    "PLACEHOLDER_PATTERN",
    "PLACEHOLDER_RIGHT_BRACKET",
    "PLACEHOLDER_TYPE_CODE",
    "attr_type_code",
    "format_placeholder",
    "parse_placeholder",
]
