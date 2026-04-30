"""Stack 注册表行为测试。"""

from __future__ import annotations

import pytest

from privacyguard.api.errors import InvalidConfigurationError
from privacyguard.bootstrap.mode_config import DEFAULT_DECISION_MODE, normalize_decision_mode
from privacyguard.bootstrap.registry import create_default_registry
from privacyguard.infrastructure import decision
from privacyguard.infrastructure.decision import LabelOnlyDecisionEngine
from privacyguard.infrastructure.pii.detector.models import ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.stacks import (
    AddressStack,
    LicensePlateStack,
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
        ClueFamily.LICENSE_PLATE: (LicensePlateStack, 0),
    }

    for family, (stack_cls, soft_priority) in expected.items():
        spec = get_stack_spec(family)
        assert spec is not None, f"{family} 未注册"
        assert spec.stack_cls is stack_cls
        assert spec.soft_priority == soft_priority


def test_organization_start_roles():
    spec = get_stack_spec(ClueFamily.ORGANIZATION)

    assert spec is not None
    assert spec.start_roles == frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.SUFFIX, ClueRole.VALUE})


def test_address_start_roles():
    spec = get_stack_spec(ClueFamily.ADDRESS)

    assert spec is not None
    assert spec.start_roles == frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.VALUE, ClueRole.KEY})


def test_license_plate_start_roles():
    spec = get_stack_spec(ClueFamily.LICENSE_PLATE)

    assert spec is not None
    assert spec.start_roles == frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.VALUE})


def test_control_family_returns_none():
    assert get_stack_spec(ClueFamily.CONTROL) is None
    assert get_stack_spec(None) is None


def test_decision_mode_only_accepts_label_only():
    """旧决策模式不再作为配置入口暴露。"""
    assert DEFAULT_DECISION_MODE == "label_only"
    assert normalize_decision_mode("label_only") == "label_only"

    for legacy_mode in ("de_model", "label_persona_mixed", "placeholder"):
        with pytest.raises(InvalidConfigurationError):
            normalize_decision_mode(legacy_mode)


def test_default_registry_only_registers_label_only_decision_mode():
    """默认注册表的 decision mode 只保留 label_only。"""
    registry = create_default_registry()
    assert registry.decision_modes == {"label_only": LabelOnlyDecisionEngine}


def test_decision_package_only_exports_label_only():
    """decision 包不再导出已删除的模型或混合决策实现。"""
    assert decision.__all__ == ["LabelOnlyDecisionEngine"]
    assert not hasattr(decision, "DEModelEngine")
    assert not hasattr(decision, "LabelPersonaMixedDecisionEngine")
    assert not hasattr(decision, "DecisionFeatureExtractor")
