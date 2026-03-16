"""映射存储抽象接口。"""

from typing import Protocol

from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding


class MappingStore(Protocol):
    """定义会话映射持久层接口。"""

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """保存某轮替换记录。"""

    def get_replacements(self, session_id: str, turn_id: int | None = None) -> list[ReplacementRecord]:
        """查询会话或会话轮次替换记录。"""

    def get_session_binding(self, session_id: str) -> SessionBinding | None:
        """读取会话绑定信息。"""

    def set_session_binding(self, binding: SessionBinding) -> None:
        """写入会话绑定信息。"""
