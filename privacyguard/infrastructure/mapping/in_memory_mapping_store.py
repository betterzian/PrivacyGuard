"""基于内存的 Mapping Store 实现。"""

from datetime import datetime, timezone

from privacyguard.domain.enums import ActionType
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding


class InMemoryMappingStore:
    """用于开发与测试的内存映射存储。"""

    def __init__(self) -> None:
        """初始化替换记录与会话绑定容器。"""
        self._records: dict[tuple[str, int], dict[str, ReplacementRecord]] = {}
        self._bindings: dict[str, SessionBinding] = {}

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """保存某会话某轮替换记录并执行一致性校验。"""
        self._validate_save_args(session_id=session_id, turn_id=turn_id)
        target: dict[str, ReplacementRecord] = {}
        for record in records:
            if record.action_type == ActionType.KEEP:
                continue
            self._validate_record(record=record, session_id=session_id, turn_id=turn_id)
            target[record.candidate_id] = record
        self._records[(session_id, turn_id)] = target

    def get_replacements(self, session_id: str, turn_id: int | None = None) -> list[ReplacementRecord]:
        """读取会话级或轮次级替换记录。"""
        if turn_id is not None:
            return list(self._records.get((session_id, turn_id), {}).values())
        collected: list[ReplacementRecord] = []
        for (sid, _tid), record_map in self._records.items():
            if sid == session_id:
                collected.extend(record_map.values())
        return collected

    def get_session_binding(self, session_id: str) -> SessionBinding | None:
        """读取会话绑定。"""
        return self._bindings.get(session_id)

    def set_session_binding(self, binding: SessionBinding) -> None:
        """写入会话绑定并更新更新时间。"""
        now = datetime.now(timezone.utc)
        binding.updated_at = now
        if binding.created_at is None:
            binding.created_at = now
        self._bindings[binding.session_id] = binding

    def find_by_replacement_text(self, session_id: str, replacement_text: str) -> list[ReplacementRecord]:
        """按 replacement_text 查询会话内记录。"""
        return [record for record in self.get_replacements(session_id=session_id) if record.replacement_text == replacement_text]

    def find_by_source_text(self, session_id: str, source_text: str) -> list[ReplacementRecord]:
        """按 source_text 查询会话内记录。"""
        return [record for record in self.get_replacements(session_id=session_id) if record.source_text == source_text]

    def _validate_save_args(self, session_id: str, turn_id: int) -> None:
        """校验保存替换记录的关键参数。"""
        if not session_id.strip():
            raise ValueError("session_id 不能为空。")
        if turn_id < 0:
            raise ValueError("turn_id 不能小于 0。")

    def _validate_record(self, record: ReplacementRecord, session_id: str, turn_id: int) -> None:
        """校验替换记录一致性约束。"""
        if record.session_id != session_id:
            raise ValueError("record.session_id 与入参 session_id 不一致。")
        if record.turn_id != turn_id:
            raise ValueError("record.turn_id 与入参 turn_id 不一致。")
        if record.action_type == ActionType.PERSONA_SLOT and not record.persona_id:
            raise ValueError("PERSONA_SLOT 动作必须携带 persona_id。")
