"""按栈名组织的 detector stack 包。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackContextLike, StackRun
from privacyguard.infrastructure.pii.detector.stacks.conflict import ConflictOutcome, StackManager
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack
from privacyguard.infrastructure.pii.detector.stacks.numeric_fragment import NumericFragmentStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.registry import StackSpec, get_stack_spec
from privacyguard.infrastructure.pii.detector.stacks.structured import (
    BankAccountStack,
    CardNumberStack,
    DriverLicenseStack,
    EmailStack,
    IdNumberStack,
    NumericStack,
    PassportStack,
    PhoneStack,
    StructuredBaseStack,
)

__all__ = [
    "AddressStack",
    "BankAccountStack",
    "BaseStack",
    "CardNumberStack",
    "ConflictOutcome",
    "DriverLicenseStack",
    "EmailStack",
    "IdNumberStack",
    "NameStack",
    "NumericFragmentStack",
    "NumericStack",
    "OrganizationStack",
    "PassportStack",
    "PhoneStack",
    "StackContextLike",
    "StackManager",
    "StackRun",
    "StackSpec",
    "StructuredBaseStack",
    "get_stack_spec",
]
