"""Stack 注册表行为测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import ClueRole
from privacyguard.infrastructure.pii.detector.stacks import (
    AddressStack,
    BankAccountStack,
    CardNumberStack,
    DriverLicenseStack,
    EmailStack,
    IdNumberStack,
    NameStack,
    NumericFragmentStack,
    NumericStack,
    OrganizationStack,
    PassportStack,
    PhoneStack,
    get_stack_spec,
)


def test_registered_attr_types_expose_expected_name_class_and_priority():
    expected = {
        PIIAttributeType.EMAIL: ("email", EmailStack, 0),
        PIIAttributeType.PHONE: ("phone", PhoneStack, 0),
        PIIAttributeType.ID_NUMBER: ("id_number", IdNumberStack, 0),
        PIIAttributeType.CARD_NUMBER: ("card_number", CardNumberStack, 0),
        PIIAttributeType.BANK_ACCOUNT: ("bank_account", BankAccountStack, 0),
        PIIAttributeType.PASSPORT_NUMBER: ("passport_number", PassportStack, 0),
        PIIAttributeType.DRIVER_LICENSE: ("driver_license", DriverLicenseStack, 0),
        PIIAttributeType.NUMERIC: ("numeric", NumericFragmentStack, 0),
        PIIAttributeType.OTHER: ("other", NumericFragmentStack, 0),
        PIIAttributeType.NAME: ("name", NameStack, 20),
        PIIAttributeType.ORGANIZATION: ("organization", OrganizationStack, 10),
        PIIAttributeType.ADDRESS: ("address", AddressStack, 30),
    }

    for attr_type, (name, stack_cls, soft_priority) in expected.items():
        spec = get_stack_spec(attr_type)
        assert spec is not None
        assert spec.name == name
        assert spec.stack_cls is stack_cls
        assert spec.soft_priority == soft_priority


def test_organization_roles_follow_protection_level():
    spec = get_stack_spec(PIIAttributeType.ORGANIZATION)

    assert spec is not None
    assert spec.start_roles_by_level[ProtectionLevel.STRONG] == frozenset(
        {ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.HARD}
    )
    assert spec.start_roles_by_level[ProtectionLevel.BALANCED] == frozenset(
        {ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.HARD}
    )
    assert spec.start_roles_by_level[ProtectionLevel.WEAK] == frozenset(
        {ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.HARD}
    )


def test_address_roles_follow_protection_level():
    spec = get_stack_spec(PIIAttributeType.ADDRESS)

    assert spec is not None
    assert spec.start_roles_by_level[ProtectionLevel.STRONG] == frozenset(
        {ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY, ClueRole.HARD}
    )
    assert spec.start_roles_by_level[ProtectionLevel.BALANCED] == frozenset(
        {ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY, ClueRole.HARD}
    )
    assert spec.start_roles_by_level[ProtectionLevel.WEAK] == frozenset(
        {ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY, ClueRole.HARD}
    )
