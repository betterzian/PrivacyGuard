"""PrivacyGuard 项目包入口。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from privacyguard.app.privacy_guard import PrivacyGuard

__all__ = ["PrivacyGuard"]


def __getattr__(name: str):
    if name == "PrivacyGuard":
        from privacyguard.app.privacy_guard import PrivacyGuard

        return PrivacyGuard
    raise AttributeError(name)
