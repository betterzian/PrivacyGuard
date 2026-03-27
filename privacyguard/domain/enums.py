"""领域通用枚举定义。"""

from enum import Enum


class ActionType(str, Enum):
    """定义可控的脱敏决策动作类型。"""

    KEEP = "KEEP"
    GENERICIZE = "GENERICIZE"
    PERSONA_SLOT = "PERSONA_SLOT"


class PIISourceType(str, Enum):
    """定义 PII 候选来源。"""

    PROMPT = "prompt"
    OCR = "ocr"


class ProtectionLevel(str, Enum):
    """规则检测保护度（单档）。

    原先 balanced / weak 已废弃；入参中的 ``balanced`` / ``weak`` 会经
    `normalize_protection_level` 归一到本值，规则始终以最强档运行。
    """

    STRONG = "strong"


def normalize_protection_level(_value: ProtectionLevel | str | None = None) -> ProtectionLevel:
    """将任意历史档位字符串归一为 `STRONG`（单档运行）。"""
    return ProtectionLevel.STRONG


class PIIAttributeType(str, Enum):
    """定义常见 PII 属性类别。

    ``OTHER`` 为兜底：凡无法明确归入其余任一细分类（姓名、电话、地址等语义类，或
    TIME / NUMERIC / TEXTUAL 等形态类）的，均应使用 ``OTHER``。

    按字符串形态粗分时：
    - 时钟时间片段（如 ``14:07``、``08:09:10``）为 ``TIME``
    - 仅数字与少量符号为 ``NUMERIC``
    - 仅文字与少量符号为 ``TEXTUAL``
    - 其余（字母与数字并存、仅符号、空白、空串等）为 ``OTHER``
    """

    NAME = "name"
    PHONE = "phone"
    CARD_NUMBER = "card_number"
    BANK_ACCOUNT = "bank_account"
    PASSPORT_NUMBER = "passport_number"
    DRIVER_LICENSE = "driver_license"
    EMAIL = "email"
    ADDRESS = "address"
    DETAILS = "details"
    ID_NUMBER = "id_number"
    ORGANIZATION = "organization"
    TIME = "time"
    NUMERIC = "numeric"
    TEXTUAL = "textual"
    OTHER = "other"
