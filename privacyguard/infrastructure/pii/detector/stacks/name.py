"""姓名 stack 入口。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import Clue
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.name_en import EnNameStack
from privacyguard.infrastructure.pii.detector.stacks.name_zh import ZhNameStack
from privacyguard.infrastructure.pii.detector.stacks.router import resolve_stack_locale, route_localized_stack


def resolve_name_stack_locale(clue: Clue, clue_index: int, context) -> str:
    """解析当前姓名 run 应使用的语法栈。"""
    return resolve_stack_locale(PIIAttributeType.NAME, clue, clue_index, context)


@dataclass(slots=True)
class NameStack(BaseStack):
    """对外兼容的姓名 stack 分发器。"""

    def _delegate(self) -> BaseStack:
        return route_localized_stack(
            attr_type=PIIAttributeType.NAME,
            clue=self.clue,
            clue_index=self.clue_index,
            context=self.context,
            zh_stack_cls=ZhNameStack,
            en_stack_cls=EnNameStack,
        )

    def run(self) -> StackRun | None:
        return self._delegate().run()

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        return self._delegate().shrink(run, blocker_start, blocker_end)
