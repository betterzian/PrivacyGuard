from __future__ import annotations

from privacyguard.infrastructure.pii.address.types import AddressInput
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN


def build_text_input(text: str) -> AddressInput:
    return AddressInput(text=text or "", has_ocr_breaks=_OCR_SEMANTIC_BREAK_TOKEN in (text or ""))
