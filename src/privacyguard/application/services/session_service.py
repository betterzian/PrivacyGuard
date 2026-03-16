"""会话状态统一读写服务。"""

from datetime import datetime, timezone

from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository


class SessionService:
    """为会话级 persona 绑定与映射写入提供统一入口。"""

    def __init__(self, mapping_store: MappingStore, persona_repository: PersonaRepository) -> None:
        """注入 mapping store 与 persona repository。"""
        self.mapping_store = mapping_store
        self.persona_repository = persona_repository

    def get_active_persona(self, session_id: str) -> str | None:
        """获取会话当前绑定的 active_persona_id。"""
        binding = self.mapping_store.get_session_binding(session_id)
        if binding is None:
            return None
        return binding.active_persona_id

    def get_or_create_binding(self, session_id: str) -> SessionBinding:
        """读取会话绑定，不存在则创建默认绑定。"""
        binding = self.mapping_store.get_session_binding(session_id)
        if binding is not None:
            return binding
        now = datetime.now(timezone.utc)
        created = SessionBinding(session_id=session_id, created_at=now, updated_at=now, last_turn_id=None)
        self.mapping_store.set_session_binding(created)
        return created

    def bind_active_persona(self, session_id: str, persona_id: str, turn_id: int) -> SessionBinding:
        """将会话显式绑定到指定 persona。"""
        if self.persona_repository.get_persona(persona_id) is None:
            raise ValueError(f"persona 不存在: {persona_id}")
        binding = self.get_or_create_binding(session_id)
        binding.active_persona_id = persona_id
        binding.last_turn_id = turn_id
        binding.updated_at = datetime.now(timezone.utc)
        self.mapping_store.set_session_binding(binding)
        return binding

    def append_turn_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """追加写入某轮替换记录并更新会话时间戳。"""
        self.mapping_store.save_replacements(session_id=session_id, turn_id=turn_id, records=records)
        binding = self.get_or_create_binding(session_id)
        binding.last_turn_id = turn_id
        binding.updated_at = datetime.now(timezone.utc)
        self.mapping_store.set_session_binding(binding)

