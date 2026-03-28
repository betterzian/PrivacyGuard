"""Minimal OCR helpers retained by the unified detector runtime."""

from __future__ import annotations

import re


def _looks_like_ui_time_metadata(self, text: str) -> bool:
    compact = re.sub(r"\s+", "", self._clean_extracted_value(text))
    if not compact or len(compact) > 16:
        return False
    if re.fullmatch(r"[\d\s:：./\-]{1,6}", compact) and any(char.isdigit() for char in compact):
        return True
    if re.fullmatch(r"(?:20\d{2}/)?\d{1,2}/\d{1,2}", compact):
        return True
    if re.fullmatch(r"(?:昨天|今天|前天|明天)?(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\d{1,2}[:：]\d{2}", compact):
        return True
    if re.fullmatch(r"(?:昨天|今天|前天|明天|刚刚|星期[一二三四五六日天]|周[一二三四五六日天])", compact):
        return True
    if re.fullmatch(
        r"(?:昨天|今天|前天|明天|星期[一二三四五六日天]|周[一二三四五六日天])(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\d{0,2}(?::\d{2})?",
        compact,
    ):
        return True
    if re.fullmatch(r"(?:yesterday|today|tomorrow|justnow|now|mon|tue|wed|thu|fri|sat|sun|am|pm)", compact, re.IGNORECASE):
        return True
    if re.fullmatch(
        r"(?:yesterday|today|tomorrow|mon|tue|wed|thu|fri|sat|sun)?(?:am|pm)?\d{1,2}(?::\d{2})?",
        compact,
        re.IGNORECASE,
    ):
        return True
    return False


def _bbox_center_y(self, bbox) -> float:
    return bbox.y + bbox.height / 2


def _clamped_ocr_tolerance(
    self,
    value: float,
    *,
    ratio: float,
    min_px: float,
    max_px: float,
) -> float:
    return min(max_px, max(min_px, value * ratio))


__all__ = [
    "_looks_like_ui_time_metadata",
    "_bbox_center_y",
    "_clamped_ocr_tolerance",
]
