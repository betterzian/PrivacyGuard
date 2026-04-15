"""按栈名组织的 detector stack 包。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack, resolve_address_stack_locale
from privacyguard.infrastructure.pii.detector.stacks.address_base import BaseAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_en import EnAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_zh import ZhAddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackContextLike, StackRun
from privacyguard.infrastructure.pii.detector.stacks.conflict import ConflictOutcome, StackManager
from privacyguard.infrastructure.pii.detector.stacks.license_plate import LicensePlateStack
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack, resolve_name_stack_locale
from privacyguard.infrastructure.pii.detector.stacks.name_base import BaseNameStack
from privacyguard.infrastructure.pii.detector.stacks.name_en import EnNameStack
from privacyguard.infrastructure.pii.detector.stacks.name_zh import ZhNameStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack, resolve_organization_stack_locale
from privacyguard.infrastructure.pii.detector.stacks.organization_base import BaseOrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.organization_en import EnOrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.organization_zh import ZhOrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.router import resolve_stack_locale, route_localized_stack
from privacyguard.infrastructure.pii.detector.stacks.registry import StackSpec, get_stack_spec
from privacyguard.infrastructure.pii.detector.stacks.structured import StructuredStack

__all__ = [
    "AddressStack",
    "BaseAddressStack",
    "BaseNameStack",
    "BaseOrganizationStack",
    "BaseStack",
    "ConflictOutcome",
    "EnAddressStack",
    "EnNameStack",
    "EnOrganizationStack",
    "LicensePlateStack",
    "NameStack",
    "OrganizationStack",
    "ZhNameStack",
    "ZhOrganizationStack",
    "StackContextLike",
    "StackManager",
    "StackRun",
    "StackSpec",
    "StructuredStack",
    "ZhAddressStack",
    "get_stack_spec",
    "resolve_address_stack_locale",
    "resolve_name_stack_locale",
    "resolve_organization_stack_locale",
    "resolve_stack_locale",
    "route_localized_stack",
]
