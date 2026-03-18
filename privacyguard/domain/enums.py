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
    """定义规则检测的保护度。"""

    STRONG = "strong"
    BALANCED = "balanced"
    WEAK = "weak"


class PIIAttributeType(str, Enum):
    """定义常见 PII 属性类别。"""

    NAME = "name"
    PHONE = "phone"
    EMAIL = "email"
    ADDRESS = "address"
    ID_NUMBER = "id_number"
    ORGANIZATION = "organization"
    OTHER = "other"
