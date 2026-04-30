"""会话状态统一读写服务。

`SessionService` 负责 session 级语义连续性，而不是 turn 级临时状态。

边界约定：

- session 层负责 persona 绑定、alias 生命周期与身份语义连续性
- turn 层负责当前轮替换记录写入，以及 restore 时对当前 turn record 的消费
- 本服务不承担 detector，也不扩展为复杂 linking 模型
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

_SESSION_ALIAS_BINDINGS_KEY = "__session_alias_bindings_v1__"
_SESSION_ALIAS_COUNTERS_KEY = "__session_alias_counters_v1__"
_ALIAS_REUSE_CONFIDENCE = 0.85


class SessionService:
    """为会话级 persona 绑定、alias 生命周期与 turn 记录写入提供统一入口。"""

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
        """读取会话绑定，不存在则创建默认绑定。

        注意：这里的 binding 是 session 级对象，用于承载长期语义连续性；
        不应把 turn 级瞬时替换记录塞进 binding 本体。
        """
        binding = self.mapping_store.get_session_binding(session_id)
        if binding is not None:
            return binding
        now = datetime.now(timezone.utc)
        created = SessionBinding(session_id=session_id, created_at=now, updated_at=now, last_turn_id=None)
        self.mapping_store.set_session_binding(created)
        return created

    def bind_active_persona(self, session_id: str, persona_id: str, turn_id: int) -> SessionBinding:
        """将会话显式绑定到指定 persona。

        这是 session 级语义连续性的组成部分：active persona 一旦绑定，应跨 turn 延续，
        而不是每轮由下游决策逻辑重新发明。
        """
        if self.persona_repository.get_persona(persona_id) is None:
            raise ValueError(f"persona 不存在: {persona_id}")
        binding = self.get_or_create_binding(session_id)
        binding.active_persona_id = persona_id
        binding.last_turn_id = turn_id
        binding.updated_at = datetime.now(timezone.utc)
        self.mapping_store.set_session_binding(binding)
        return binding

    def resolve_session_alias(
        self,
        session_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
        *,
        confidence: float,
    ) -> str:
        """解析或分配 session 级 alias。

        规则保持保守：

        - 只有在“高置信 + same_entity 命中”时才复用 alias
        - 一旦不确定，宁可新建 alias，也不要冒险错复用
        - 错复用比 alias 断裂更危险，因为它会把两个不同实体错误折叠到同一身份上

        该方法不引入复杂 linking；只基于 attr_type 与统一归一结果做保守复用。
        """
        binding = self.get_or_create_binding(session_id)
        alias_bindings = self._load_alias_bindings(binding)
        alias_counters = self._load_alias_counters(binding)
        normalized = normalize_pii(
            attr_type,
            source_text,
            components=None,
        )
        matched_alias = self._find_matching_alias(
            alias_bindings=alias_bindings,
            target=normalized,
        )
        if self._should_reuse_alias(confidence=confidence, matched_alias=matched_alias):
            return matched_alias

        allocated_alias = self._allocate_new_alias(
            attr_type=attr_type,
            alias_counters=alias_counters,
        )
        self._record_alias_binding(
            binding=binding,
            alias_bindings=alias_bindings,
            alias_counters=alias_counters,
            alias=allocated_alias,
            normalized=normalized,
            source_text=source_text,
        )
        return allocated_alias

    def append_turn_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """追加写入某轮替换记录并更新会话时间戳。

        这是 turn 级逻辑：

        - 负责保存当前轮实际发生的替换记录
        - 这些记录随后被 render / mapping / restore 闭环消费

        它不负责决定 session alias；alias 生命周期由 session 级方法负责。
        """
        self.mapping_store.save_replacements(session_id=session_id, turn_id=turn_id, records=records)
        binding = self.get_or_create_binding(session_id)
        binding.last_turn_id = turn_id
        binding.updated_at = datetime.now(timezone.utc)
        self.mapping_store.set_session_binding(binding)

    def _should_reuse_alias(self, *, confidence: float, matched_alias: str | None) -> bool:
        """判断是否允许复用已有 alias。

        复用条件故意保守：

        - 必须已经找到统一 `same_entity` 命中
        - 必须达到高置信阈值

        低置信时即使存在历史 alias，也优先新建，因为错复用比断裂更危险。
        """
        if not matched_alias:
            return False
        return confidence >= _ALIAS_REUSE_CONFIDENCE

    def _allocate_new_alias(
        self,
        *,
        attr_type: PIIAttributeType,
        alias_counters: dict[str, int],
    ) -> str:
        """分配新的 session alias。

        alias 只要求 session 内稳定和可区分，不要求在此处做复杂真值 linking。
        """
        attr_key = attr_type.value
        next_index = int(alias_counters.get(attr_key, 1) or 1)
        alias_counters[attr_key] = next_index + 1
        return f"{attr_key}:{next_index}"

    def _record_alias_binding(
        self,
        *,
        binding: SessionBinding,
        alias_bindings: dict[str, dict[str, object]],
        alias_counters: dict[str, int],
        alias: str,
        normalized: NormalizedPII,
        source_text: str,
    ) -> None:
        """把 alias 绑定写回 session binding metadata。

        为保持 `MappingStore` 兼容，这里只把 alias 状态序列化进 `SessionBinding.metadata`，
        不引入新的持久层接口。
        """
        alias_bindings[alias] = {
            "attr_type": normalized.attr_type.value,
            "normalized": normalized.model_dump(mode="json"),
            "source_text": source_text,
        }
        binding.metadata[_SESSION_ALIAS_BINDINGS_KEY] = json.dumps(alias_bindings, ensure_ascii=False, sort_keys=True)
        binding.metadata[_SESSION_ALIAS_COUNTERS_KEY] = json.dumps(alias_counters, ensure_ascii=False, sort_keys=True)
        binding.updated_at = datetime.now(timezone.utc)
        self.mapping_store.set_session_binding(binding)

    def _find_matching_alias(
        self,
        *,
        alias_bindings: dict[str, dict[str, object]],
        target: NormalizedPII,
    ) -> str | None:
        """查找同一实体的 alias 命中。"""
        for alias, payload in alias_bindings.items():
            if payload.get("attr_type") != target.attr_type.value:
                continue
            normalized_payload = payload.get("normalized")
            if not isinstance(normalized_payload, dict):
                continue
            try:
                candidate = NormalizedPII.model_validate(normalized_payload)
            except Exception:
                continue
            if not same_entity(candidate, target):
                continue
            return alias
        return None

    def _load_alias_bindings(self, binding: SessionBinding) -> dict[str, dict[str, object]]:
        """从 session binding metadata 读取 alias 绑定表。"""
        payload = binding.metadata.get(_SESSION_ALIAS_BINDINGS_KEY, "")
        if not payload:
            return {}
        try:
            loaded = json.loads(payload)
        except (TypeError, ValueError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        normalized: dict[str, dict[str, object]] = {}
        for alias, item in loaded.items():
            if not isinstance(alias, str) or not isinstance(item, dict):
                continue
            normalized[alias] = {
                "attr_type": str(item.get("attr_type", "")).strip(),
                "normalized": item.get("normalized") if isinstance(item.get("normalized"), dict) else {},
                "source_text": str(item.get("source_text", "")).strip(),
            }
        return normalized

    def _load_alias_counters(self, binding: SessionBinding) -> dict[str, int]:
        """从 session binding metadata 读取 alias 计数器。"""
        payload = binding.metadata.get(_SESSION_ALIAS_COUNTERS_KEY, "")
        if not payload:
            return {}
        try:
            loaded = json.loads(payload)
        except (TypeError, ValueError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        normalized: dict[str, int] = {}
        for attr_key, value in loaded.items():
            try:
                normalized[str(attr_key)] = max(1, int(value))
            except (TypeError, ValueError):
                continue
        return normalized
