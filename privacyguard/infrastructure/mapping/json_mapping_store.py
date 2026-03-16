"""基于 JSON 文件的 Mapping Store 实现。"""

import json
from pathlib import Path

from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore


class JsonMappingStore(InMemoryMappingStore):
    """在内存行为基础上提供 JSON 持久化。"""

    def __init__(self, path: str = "data/mapping_store.json") -> None:
        """初始化存储并尝试从 JSON 文件恢复状态。"""
        super().__init__()
        self.path = Path(path)
        self._load_from_file()

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """保存替换记录并持久化到 JSON。"""
        super().save_replacements(session_id=session_id, turn_id=turn_id, records=records)
        self._flush_to_file()

    def set_session_binding(self, binding: SessionBinding) -> None:
        """保存会话绑定并持久化到 JSON。"""
        super().set_session_binding(binding)
        self._flush_to_file()

    def _load_from_file(self) -> None:
        """从 JSON 文件加载记录与会话绑定。"""
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for item in raw.get("replacements", []):
            record = ReplacementRecord.model_validate(item)
            target = self._records.setdefault((record.session_id, record.turn_id), {})
            target[record.candidate_id] = record
        for item in raw.get("bindings", []):
            binding = SessionBinding.model_validate(item)
            self._bindings[binding.session_id] = binding

    def _flush_to_file(self) -> None:
        """使用原子替换方式安全写入 JSON。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "replacements": [
                record.model_dump(mode="json")
                for record_map in self._records.values()
                for record in record_map.values()
            ],
            "bindings": [binding.model_dump(mode="json") for binding in self._bindings.values()],
        }
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)

