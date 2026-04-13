"""英文姓名 stack。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack


class EnNameStack(BaseNameStack):
    """英文姓名 stack。"""

    STACK_LOCALE = "en"
