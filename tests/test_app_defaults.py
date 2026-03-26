from __future__ import annotations

import inspect

from privacyguard.app.privacy_guard import PrivacyGuard
from privacyguard.bootstrap.mode_config import DEFAULT_DECISION_MODE


def test_default_decision_mode_is_label_only() -> None:
    assert DEFAULT_DECISION_MODE == "label_only"
    decision_default = inspect.signature(PrivacyGuard.__init__).parameters["decision_mode"].default
    assert decision_default == "label_only"
