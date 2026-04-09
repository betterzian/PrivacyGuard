"""Stack 注册表：以 ClueFamily 为 key 分发到对应 stack 类。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.models import ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack
from privacyguard.infrastructure.pii.detector.stacks.name import NameStack
from privacyguard.infrastructure.pii.detector.stacks.organization import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.structured import StructuredStack


@dataclass(frozen=True, slots=True)
class StackSpec:
    family: ClueFamily
    stack_cls: type[BaseStack]
    start_roles: frozenset[ClueRole]
    soft_priority: int = 0


# —— 各 family 允许起栈的 role 集合 ——

_STRUCTURED_ROLES = frozenset({ClueRole.LABEL, ClueRole.VALUE})
_NAME_ROLES = frozenset({
    ClueRole.LABEL,
    ClueRole.START,
    ClueRole.FAMILY_NAME,
    ClueRole.GIVEN_NAME,
    ClueRole.FULL_NAME,
    ClueRole.ALIAS,
    ClueRole.VALUE,
})
_ORGANIZATION_ROLES = frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.SUFFIX, ClueRole.VALUE})
_ADDRESS_ROLES = frozenset({ClueRole.LABEL, ClueRole.START, ClueRole.VALUE, ClueRole.KEY})

# —— 合法性校验表（开发期断言用） ——

VALID_ROLES: dict[ClueFamily, frozenset[ClueRole]] = {
    ClueFamily.NAME: _NAME_ROLES,
    ClueFamily.ORGANIZATION: _ORGANIZATION_ROLES,
    ClueFamily.ADDRESS: _ADDRESS_ROLES,
    ClueFamily.STRUCTURED: _STRUCTURED_ROLES,
    ClueFamily.CONTROL: frozenset({ClueRole.BREAK, ClueRole.NEGATIVE}),
}

# —— 注册表：4 条 ——

_STACK_SPECS: dict[ClueFamily, StackSpec] = {
    ClueFamily.NAME: StackSpec(
        ClueFamily.NAME, NameStack, _NAME_ROLES, soft_priority=20,
    ),
    ClueFamily.ORGANIZATION: StackSpec(
        ClueFamily.ORGANIZATION, OrganizationStack, _ORGANIZATION_ROLES, soft_priority=10,
    ),
    ClueFamily.ADDRESS: StackSpec(
        ClueFamily.ADDRESS, AddressStack, _ADDRESS_ROLES, soft_priority=30,
    ),
    ClueFamily.STRUCTURED: StackSpec(
        ClueFamily.STRUCTURED, StructuredStack, _STRUCTURED_ROLES,
    ),
}


def get_stack_spec(family: ClueFamily | None) -> StackSpec | None:
    """按 family 查找 stack 规格。CONTROL 类不起栈，返回 None。"""
    if family is None:
        return None
    return _STACK_SPECS.get(family)
