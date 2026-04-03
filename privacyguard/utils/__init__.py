"""通用工具导出。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from privacyguard.utils.image import ensure_supported_image_input
    from privacyguard.utils.normalized_pii import (
        build_match_terms,
        normalize_pii,
        normalized_primary_text,
        render_address_text,
        same_entity,
    )
    from privacyguard.utils.text import normalize_text

__all__ = [
    "build_match_terms",
    "ensure_supported_image_input",
    "normalize_pii",
    "normalize_text",
    "normalized_primary_text",
    "render_address_text",
    "same_entity",
]


def __getattr__(name: str):
    if name == "ensure_supported_image_input":
        from privacyguard.utils.image import ensure_supported_image_input

        return ensure_supported_image_input
    if name == "build_match_terms":
        from privacyguard.utils.normalized_pii import build_match_terms

        return build_match_terms
    if name == "normalize_pii":
        from privacyguard.utils.normalized_pii import normalize_pii

        return normalize_pii
    if name == "normalized_primary_text":
        from privacyguard.utils.normalized_pii import normalized_primary_text

        return normalized_primary_text
    if name == "render_address_text":
        from privacyguard.utils.normalized_pii import render_address_text

        return render_address_text
    if name == "same_entity":
        from privacyguard.utils.normalized_pii import same_entity

        return same_entity
    if name == "normalize_text":
        from privacyguard.utils.text import normalize_text

        return normalize_text
    raise AttributeError(name)
