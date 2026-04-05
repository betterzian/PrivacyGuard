"""Stack 注册表。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import ClueRole
from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.structured import (
    BankAccountStack,
    CardNumberStack,
    DriverLicenseStack,
    EmailStack,
    IdNumberStack,
    NumericStack,
    PassportStack,
    PhoneStack,
)


@dataclass(frozen=True, slots=True)
class StackSpec:
    name: str
    attr_type: PIIAttributeType
    stack_cls: type[BaseStack]
    start_roles_by_level: dict[ProtectionLevel, frozenset[ClueRole]]
    soft_priority: int = 0


def _all_levels(*roles: ClueRole) -> dict[ProtectionLevel, frozenset[ClueRole]]:
    allowed = frozenset(roles)
    return {level: allowed for level in ProtectionLevel}


_STRUCTURED_ROLES = _all_levels(ClueRole.LABEL, ClueRole.HARD)
_NAME_ROLES = _all_levels(
    ClueRole.LABEL,
    ClueRole.START,
    ClueRole.FAMILY_NAME,
    ClueRole.GIVEN_NAME,
    ClueRole.FULL_NAME,
    ClueRole.ALIAS,
    ClueRole.HARD,
)

_STACK_SPECS: dict[PIIAttributeType, StackSpec] = {
    PIIAttributeType.EMAIL: StackSpec("email", PIIAttributeType.EMAIL, EmailStack, _STRUCTURED_ROLES),
    PIIAttributeType.PHONE: StackSpec("phone", PIIAttributeType.PHONE, PhoneStack, _STRUCTURED_ROLES),
    PIIAttributeType.ID_NUMBER: StackSpec("id_number", PIIAttributeType.ID_NUMBER, IdNumberStack, _STRUCTURED_ROLES),
    PIIAttributeType.CARD_NUMBER: StackSpec("card_number", PIIAttributeType.CARD_NUMBER, CardNumberStack, _STRUCTURED_ROLES),
    PIIAttributeType.BANK_ACCOUNT: StackSpec("bank_account", PIIAttributeType.BANK_ACCOUNT, BankAccountStack, _STRUCTURED_ROLES),
    PIIAttributeType.PASSPORT_NUMBER: StackSpec("passport_number", PIIAttributeType.PASSPORT_NUMBER, PassportStack, _STRUCTURED_ROLES),
    PIIAttributeType.DRIVER_LICENSE: StackSpec("driver_license", PIIAttributeType.DRIVER_LICENSE, DriverLicenseStack, _STRUCTURED_ROLES),
    PIIAttributeType.NUMERIC: StackSpec("numeric", PIIAttributeType.NUMERIC, NumericStack, _STRUCTURED_ROLES),
    PIIAttributeType.NAME: StackSpec("name", PIIAttributeType.NAME, NameStack, _NAME_ROLES, soft_priority=20),
    PIIAttributeType.ORGANIZATION: StackSpec(
        "organization",
        PIIAttributeType.ORGANIZATION,
        OrganizationStack,
        {
            ProtectionLevel.STRONG: frozenset({ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.HARD}),
            ProtectionLevel.BALANCED: frozenset({ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.HARD}),
            ProtectionLevel.WEAK: frozenset({ClueRole.LABEL, ClueRole.HARD}),
        },
        soft_priority=10,
    ),
    PIIAttributeType.ADDRESS: StackSpec(
        "address",
        PIIAttributeType.ADDRESS,
        AddressStack,
        {
            ProtectionLevel.STRONG: frozenset({ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY, ClueRole.HARD}),
            ProtectionLevel.BALANCED: frozenset({ClueRole.LABEL, ClueRole.VALUE, ClueRole.HARD}),
            ProtectionLevel.WEAK: frozenset({ClueRole.LABEL, ClueRole.HARD}),
        },
        soft_priority=30,
    ),
}


def get_stack_spec(attr_type: PIIAttributeType | None) -> StackSpec | None:
    if attr_type is None:
        return None
    return _STACK_SPECS.get(attr_type)
