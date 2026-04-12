"""按栈名组织的 detector stack 包。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack, resolve_address_stack_locale
from privacyguard.infrastructure.pii.detector.stacks.address_base import BaseAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_en import EnAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_zh import ZhAddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackContextLike, StackRun
from privacyguard.infrastructure.pii.detector.stacks.conflict import ConflictOutcome, StackManager
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.registry import StackSpec, get_stack_spec
from privacyguard.infrastructure.pii.detector.stacks.structured import StructuredStack

__all__ = [
    "AddressStack",
    "BaseAddressStack",
    "BaseStack",
    "ConflictOutcome",
    "EnAddressStack",
    "NameStack",
    "OrganizationStack",
    "StackContextLike",
    "StackManager",
    "StackRun",
    "StackSpec",
    "StructuredStack",
    "ZhAddressStack",
    "get_stack_spec",
    "resolve_address_stack_locale",
]
