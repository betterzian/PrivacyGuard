"""组织 stack 入口。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import Clue
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.organization_en import EnOrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.organization_zh import ZhOrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.router import resolve_stack_locale, route_localized_stack


def resolve_organization_stack_locale(clue: Clue, clue_index: int, context) -> str:
    """解析当前组织 run 应使用的语法栈。"""
    return resolve_stack_locale(PIIAttributeType.ORGANIZATION, clue, clue_index, context)


@dataclass(slots=True)
class OrganizationStack(BaseStack):
    """对外兼容的组织 stack 分发器。"""

    def _delegate(self) -> BaseStack:
        return route_localized_stack(
            attr_type=PIIAttributeType.ORGANIZATION,
            clue=self.clue,
            clue_index=self.clue_index,
            context=self.context,
            zh_stack_cls=ZhOrganizationStack,
            en_stack_cls=EnOrganizationStack,
        )

    def run(self) -> StackRun | None:
        return self._delegate().run()

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        return self._delegate().shrink(run, blocker_start, blocker_end)
