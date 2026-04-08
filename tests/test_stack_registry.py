"""Stack 注册表行为测试。"""

from __future__ import annotations

from privacyguard.infrastructure.pii.detector.models import ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.stacks import (
    AddressStack,
    NameStack,
    OrganizationStack,
    StructuredStack,
    get_stack_spec,
)


def test_registered_families_expose_expected_class_and_priority():
    expected = {
        ClueFamily.STRUCTURED: (StructuredStack, 0),
        ClueFamily.NAME: (NameStack, 20),
        ClueFamily.ORGANIZATION: (OrganizationStack, 10),
        ClueFamily.ADDRESS: (AddressStack, 30),
    }

    for family, (stack_cls, soft_priority) in expected.items():
        spec = get_stack_spec(family)
        assert spec is not None, f"{family} 未注册"
        assert spec.stack_cls is stack_cls
        assert spec.soft_priority == soft_priority


def test_organization_start_roles():
    spec = get_stack_spec(ClueFamily.ORGANIZATION)

    assert spec is not None
    assert spec.start_roles == frozenset({ClueRole.LABEL, ClueRole.SUFFIX, ClueRole.VALUE})


def test_address_start_roles():
    spec = get_stack_spec(ClueFamily.ADDRESS)

    assert spec is not None
    assert spec.start_roles == frozenset({ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY})


def test_control_family_returns_none():
    assert get_stack_spec(ClueFamily.CONTROL) is None
    assert get_stack_spec(None) is None
