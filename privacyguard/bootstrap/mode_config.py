"""模式名、默认值与归一化逻辑的单一来源。"""

from privacyguard.api.errors import InvalidConfigurationError

# 默认模式（PrivacyGuard 及各处统一引用）
DEFAULT_DETECTOR_MODE = "rule_based"
DEFAULT_DECISION_MODE = "de_model"

# 规范模式名（与 bootstrap/factories 注册键一致，无别名）
DETECTOR_MODE_ALIASES = {
    "rule_based": "rule_based",
}

DECISION_MODE_ALIASES = {
    "de_model": "de_model",
    "label_only": "label_only",
    "label_persona_mixed": "label_persona_mixed",
}

DEFAULT_FILL_MODE = "mix"
FILL_MODE_ALIASES = {
    "ring": "ring",
    "gradient": "gradient",
    "cv": "cv",
    "mix": "mix",
}


def normalize_detector_mode(detector_mode: str) -> str:
    """将 detector 模式名归一化为内部标准键。"""
    normalized = detector_mode.strip().lower()
    if normalized not in DETECTOR_MODE_ALIASES:
        raise InvalidConfigurationError(f"不支持的 detector_mode: {detector_mode}")
    return DETECTOR_MODE_ALIASES[normalized]


def normalize_decision_mode(decision_mode: str) -> str:
    """将 decision 模式名归一化为内部标准键。"""
    normalized = decision_mode.strip().lower()
    if normalized not in DECISION_MODE_ALIASES:
        raise InvalidConfigurationError(f"不支持的 decision_mode: {decision_mode}")
    return DECISION_MODE_ALIASES[normalized]


def normalize_fill_mode(fill_mode: str) -> str:
    """将截图填充模式名归一化为内部标准键。"""
    normalized = fill_mode.strip().lower()
    if normalized not in FILL_MODE_ALIASES:
        raise InvalidConfigurationError(f"不支持的 fill_mode: {fill_mode}")
    return FILL_MODE_ALIASES[normalized]
