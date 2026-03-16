"""还原模块抽象接口。"""

from typing import Protocol

from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.mapping import ReplacementRecord


class RestorationModule(Protocol):
    """定义恢复云端文本的最小接口。"""

    def restore(self, cloud_text: str, records: list[ReplacementRecord]) -> tuple[str, list[RestoredSlot]]:
        """根据替换记录恢复原始文本并返回命中槽位。"""
