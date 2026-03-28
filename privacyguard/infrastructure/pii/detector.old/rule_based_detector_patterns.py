"""Minimal field-keyword aggregation retained by the unified detector runtime."""

from __future__ import annotations

from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _ADDRESS_FIELD_KEYWORDS,
    _BANK_ACCOUNT_FIELD_KEYWORDS,
    _CARD_FIELD_KEYWORDS,
    _DRIVER_LICENSE_FIELD_KEYWORDS,
    _EMAIL_FIELD_KEYWORDS,
    _ID_FIELD_KEYWORDS,
    _NAME_FAMILY_FIELD_KEYWORDS,
    _NAME_FIELD_KEYWORDS,
    _NAME_GIVEN_FIELD_KEYWORDS,
    _NAME_MIDDLE_FIELD_KEYWORDS,
    _ORGANIZATION_FIELD_KEYWORDS,
    _OTHER_FIELD_KEYWORDS,
    _PASSPORT_FIELD_KEYWORDS,
    _PHONE_FIELD_KEYWORDS,
)


def _all_field_keywords(self) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            (
                *_NAME_FIELD_KEYWORDS,
                *_NAME_FAMILY_FIELD_KEYWORDS,
                *_NAME_GIVEN_FIELD_KEYWORDS,
                *_NAME_MIDDLE_FIELD_KEYWORDS,
                *_ADDRESS_FIELD_KEYWORDS,
                *_PHONE_FIELD_KEYWORDS,
                *_CARD_FIELD_KEYWORDS,
                *_BANK_ACCOUNT_FIELD_KEYWORDS,
                *_PASSPORT_FIELD_KEYWORDS,
                *_DRIVER_LICENSE_FIELD_KEYWORDS,
                *_EMAIL_FIELD_KEYWORDS,
                *_ID_FIELD_KEYWORDS,
                *_OTHER_FIELD_KEYWORDS,
                *_ORGANIZATION_FIELD_KEYWORDS,
            )
        )
    )


__all__ = ["_all_field_keywords"]
