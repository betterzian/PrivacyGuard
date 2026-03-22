"""领域约束策略导出。"""

from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.domain.policies.generic_placeholder import (
    GENERIC_PLACEHOLDER_LABELS,
    generic_placeholder_label,
    render_generic_replacement_text,
)

__all__ = [
    "ConstraintResolver",
    "GENERIC_PLACEHOLDER_LABELS",
    "generic_placeholder_label",
    "render_generic_replacement_text",
]

