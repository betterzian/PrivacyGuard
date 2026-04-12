"""地址 stack 入口。

对外仍然暴露 `AddressStack`，内部根据当前 run 的真实语种分发到：
- `ZhAddressStack`
- `EnAddressStack`
"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_index_at_or_after
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _label_seed_address_index,
    _label_seed_start_char,
)
from privacyguard.infrastructure.pii.detector.stacks.address_en import EnAddressStack
from privacyguard.infrastructure.pii.detector.stacks.address_zh import ZhAddressStack


def _has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def _locale_from_text(text: str) -> str:
    return "zh" if _has_cjk(text) else "en"


def resolve_address_stack_locale(clue: Clue, clue_index: int, context) -> str:
    """解析当前地址 run 应使用的语法栈。"""
    del clue_index
    profile = str(context.locale_profile or "mixed").strip().lower()
    if profile == "zh_cn":
        return "zh"
    if profile == "en_us":
        return "en"

    stream = context.stream
    if clue.strength == ClaimStrength.HARD:
        return _locale_from_text(stream.text[clue.start:clue.end])

    if clue.role in {ClueRole.LABEL, ClueRole.START}:
        address_start = _label_seed_start_char(stream, clue.end)
        start_unit = _unit_index_at_or_after(stream, address_start)
        seed_index = _label_seed_address_index(
            context.clues,
            stream,
            address_start,
            start_unit,
            max_units=6,
        )
        if seed_index is not None:
            seed = context.clues[seed_index]
            window_start = max(0, seed.start - 8)
            window_end = min(len(stream.text), seed.end + 8)
            return _locale_from_text(stream.text[window_start:window_end])
        window = stream.text[address_start:min(len(stream.text), address_start + 24)]
        return _locale_from_text(window)

    clue_text = clue.text or stream.text[clue.start:clue.end]
    if _has_cjk(clue_text):
        return "zh"
    window_start = max(0, clue.start - 8)
    window_end = min(len(stream.text), clue.end + 8)
    return _locale_from_text(stream.text[window_start:window_end])


@dataclass(slots=True)
class AddressStack(BaseStack):
    """对外兼容的地址 stack 分发器。"""

    def _delegate(self) -> BaseStack:
        locale = resolve_address_stack_locale(self.clue, self.clue_index, self.context)
        stack_cls = ZhAddressStack if locale == "zh" else EnAddressStack
        return stack_cls(clue=self.clue, clue_index=self.clue_index, context=self.context)

    def run(self) -> StackRun | None:
        return self._delegate().run()

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        return self._delegate().shrink(run, blocker_start, blocker_end)
