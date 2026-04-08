"""按栈名组织的 detector stack 包。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackContextLike, StackRun
from privacyguard.infrastructure.pii.detector.stacks.conflict import ConflictOutcome, StackManager
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.registry import StackSpec, get_stack_spec
from privacyguard.infrastructure.pii.detector.stacks.structured import StructuredStack

__all__ = [
    "AddressStack",
    "BaseStack",
    "ConflictOutcome",
    "NameStack",
    "OrganizationStack",
    "StackContextLike",
    "StackManager",
    "StackRun",
    "StackSpec",
    "StructuredStack",
    "get_stack_spec",
]
