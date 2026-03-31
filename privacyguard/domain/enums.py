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
    """规则检测保护度（三档）。

    - STRONG: 最高灵敏度，单 surname 即可触发姓名检测。
    - BALANCED: 需 label 或上下文确认才启动 soft 检测。
    - WEAK: 仅 label-driven 和 hard clue（正则/词典）生效。
    """

    STRONG = "strong"
    BALANCED = "balanced"
    WEAK = "weak"


def normalize_protection_level(value: ProtectionLevel | str | None = None) -> ProtectionLevel:
    """将字符串归一为 ProtectionLevel 枚举。无效值默认返回 STRONG。"""
    if value is None:
        return ProtectionLevel.STRONG
    if isinstance(value, ProtectionLevel):
        return value
    normalized = str(value).strip().lower()
    try:
        return ProtectionLevel(normalized)
    except ValueError:
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
