"""Rewritten stream detector package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

__all__ = ["RuleBasedPIIDetector"]


def __getattr__(name: str):
    if name == "RuleBasedPIIDetector":
        from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

        return RuleBasedPIIDetector
    raise AttributeError(name)
