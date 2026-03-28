"""Minimal text-span helpers retained by the unified detector runtime."""

from __future__ import annotations

from typing import Callable
import re

from privacyguard.utils.pii_value import compact_id_value


def _match_context_window(self, raw_text: str, span_start: int, span_end: int, *, radius: int = 12) -> str:
    left = max(0, span_start - radius)
    right = min(len(raw_text), span_end + radius)
    return raw_text[left:right]


def _looks_like_cn_id_with_birthdate(self, value: str) -> bool:
    compact = compact_id_value(value)
    return bool(
        re.fullmatch(r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]", compact)
        or re.fullmatch(r"[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}", compact)
    )


def _extract_match(
    self,
    raw_text: str,
    start: int,
    end: int,
    cleaner: Callable[[str], str] | None = None,
    *,
    original_text: str | None = None,
    shadow_index_map: tuple[int | None, ...] | None = None,
) -> tuple[str, int, int] | None:
    """Extract a cleaned snippet and return its span in raw or remapped text."""

    snippet = raw_text[start:end]
    cleaned = cleaner(snippet) if cleaner is not None else self._clean_extracted_value(snippet)
    if not cleaned:
        return None
    relative_start = snippet.find(cleaned)
    if relative_start < 0:
        relative_start = snippet.lower().find(cleaned.lower())
    if relative_start < 0:
        return None
    absolute_start = start + relative_start
    absolute_end = absolute_start + len(cleaned)
    if shadow_index_map is not None:
        return self._remap_shadow_span(
            absolute_start,
            absolute_end,
            original_text=original_text,
            shadow_index_map=shadow_index_map,
            cleaner=cleaner,
        )
    return cleaned, absolute_start, absolute_end


def _remap_shadow_span(
    self,
    shadow_start: int,
    shadow_end: int,
    *,
    original_text: str | None,
    shadow_index_map: tuple[int | None, ...],
    cleaner: Callable[[str], str] | None = None,
) -> tuple[str, int, int] | None:
    if original_text is None:
        return None
    covered = [index for index in shadow_index_map[shadow_start:shadow_end] if index is not None]
    if not covered:
        return None
    original_start = min(covered)
    original_end = max(covered) + 1
    if len(covered) != original_end - original_start:
        return None
    return self._extract_match(original_text, original_start, original_end, cleaner=cleaner)


__all__ = [
    "_match_context_window",
    "_looks_like_cn_id_with_birthdate",
    "_extract_match",
    "_remap_shadow_span",
]
