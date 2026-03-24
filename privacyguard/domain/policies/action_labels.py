"""共享动作与层级标签常量。"""

from __future__ import annotations

from privacyguard.domain.enums import ActionType

ACTION_ORDER: tuple[ActionType, ActionType, ActionType] = (
    ActionType.KEEP,
    ActionType.GENERICIZE,
    ActionType.PERSONA_SLOT,
)

PROTECT_LABEL_KEEP = "KEEP"
PROTECT_LABEL_REWRITE = "REWRITE"
PROTECT_ORDER: tuple[str, str] = (
    PROTECT_LABEL_KEEP,
    PROTECT_LABEL_REWRITE,
)

REWRITE_MODE_NONE = "NONE"
REWRITE_MODE_GENERICIZE = ActionType.GENERICIZE.value
REWRITE_MODE_PERSONA_SLOT = ActionType.PERSONA_SLOT.value
REWRITE_MODE_ORDER: tuple[str, str] = (
    REWRITE_MODE_GENERICIZE,
    REWRITE_MODE_PERSONA_SLOT,
)

__all__ = [
    "ACTION_ORDER",
    "PROTECT_LABEL_KEEP",
    "PROTECT_LABEL_REWRITE",
    "PROTECT_ORDER",
    "REWRITE_MODE_NONE",
    "REWRITE_MODE_GENERICIZE",
    "REWRITE_MODE_PERSONA_SLOT",
    "REWRITE_MODE_ORDER",
]
