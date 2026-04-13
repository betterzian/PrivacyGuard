"""中文组织 stack。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.organization_base import BaseOrganizationStack


class ZhOrganizationStack(BaseOrganizationStack):
    """中文组织 stack。"""

    STACK_LOCALE = "zh"
