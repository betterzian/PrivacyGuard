"""会话级占位符分配服务。

三级查找链：
1. session 历史 records → 重建 ``SessionEntityState`` → 命中复用 entity_id；
2. session miss → 查 repo 归一索引（带最小基数阈值）→ 命中分配新 entity_id；
3. repo 也 miss → 分配新 entity_id。

新 entity_id 跨 attr_type 共享：``next_index = max(已有 entity_id) + 1``。
占位符渲染统一走 :func:`render_placeholder`，地址 SPEC 来自"新 PII 自己的"
``address_display_spec``。
"""

from __future__ import annotations

from privacyguard.application.services.session_entity_state import SessionEntityState
from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.domain.policies.generic_placeholder import (
    GENERIC_FRAGMENT_PLACEHOLDER_ATTRS,
    render_placeholder,
)
from privacyguard.infrastructure.pii.json_privacy_repository import (
    IndexedRepoEntity,
    RepoEntityIndex,
)
from privacyguard.utils.normalized_pii import (
    _canonicalize_address_component_value,  # type: ignore[attr-defined]
    address_display_spec,
    normalize_pii,
    same_entity,
)


class SessionPlaceholderAllocator:
    """为 GENERICIZE 动作分配 session 级稳定占位符。"""

    def __init__(
        self,
        mapping_store: MappingStore,
        repo_index: RepoEntityIndex | None = None,
    ) -> None:
        self.mapping_store = mapping_store
        self.repo_index = repo_index

    def assign(self, plan: DecisionPlan) -> DecisionPlan:
        """基于 session 历史与 repo 索引为计划中的 GENERICIZE 动作分配占位符。"""
        session_records = self.mapping_store.get_replacements(plan.session_id)
        entity_states = self._build_session_entity_states(session_records)
        road_bucket = self._build_road_bucket(entity_states)
        next_index = self._build_next_index(session_records, entity_states)

        actions: list[DecisionAction] = []
        for action in plan.actions:
            if action.action_type != ActionType.GENERICIZE or not action.source_text:
                actions.append(action.model_copy(deep=True))
                continue

            normalized = action.normalized_source or normalize_pii(
                action.attr_type,
                action.source_text,
                metadata=action.metadata,
            )

            entity_id, repo_persona_id = self._resolve_entity_id(
                normalized,
                entity_states=entity_states,
                road_bucket=road_bucket,
            )
            if entity_id is None:
                entity_id = next_index
                next_index += 1

            replacement_text = self._render(action, normalized, entity_id)

            # 把当次 PII 并入对应 entity 的累积态，方便同 plan 内后续候选直接复用。
            self._record_assignment(
                entity_states,
                road_bucket,
                entity_id,
                normalized,
            )

            updated = action.model_copy(deep=True)
            updated.replacement_text = replacement_text
            updated.normalized_source = normalized
            updated.entity_id = entity_id
            if repo_persona_id:
                merged_metadata = dict(updated.metadata)
                existing = list(merged_metadata.get("repo_hit_persona_id", ()))
                if repo_persona_id not in existing:
                    existing.append(repo_persona_id)
                merged_metadata["repo_hit_persona_id"] = existing
                updated.metadata = merged_metadata
            actions.append(updated)

        return plan.model_copy(update={"actions": actions}, deep=True)

    # ------------------------------------------------------------------
    # 索引构造
    # ------------------------------------------------------------------

    def _build_session_entity_states(
        self,
        records: list[ReplacementRecord],
    ) -> dict[int, SessionEntityState]:
        """按 entity_id 把同实体 records 折叠为 SessionEntityState。

        - 仅考虑 GENERICIZE 且 entity_id 已分配的记录；
        - 同 entity 的多条 records 走 SessionEntityState.merge 累积。
        """
        states: dict[int, SessionEntityState] = {}
        ordered = sorted(records, key=lambda item: (item.turn_id, item.replacement_id))
        for record in ordered:
            if record.action_type != ActionType.GENERICIZE:
                continue
            if record.entity_id is None:
                continue
            normalized = record.normalized_source or normalize_pii(
                record.attr_type,
                record.source_text,
                metadata=record.metadata,
            )
            existing = states.get(record.entity_id)
            if existing is None:
                states[record.entity_id] = SessionEntityState.from_normalized(
                    record.entity_id, normalized
                )
            else:
                states[record.entity_id] = existing.merge(normalized)
        return states

    def _build_road_bucket(
        self,
        entity_states: dict[int, SessionEntityState],
    ) -> dict[str, list[int]]:
        """按 road canonical 将地址 entity 入桶。"""
        bucket: dict[str, list[int]] = {}
        for entity_id, state in entity_states.items():
            if state.attr_type != PIIAttributeType.ADDRESS:
                continue
            if not state.road_canonical:
                continue
            bucket.setdefault(state.road_canonical, []).append(entity_id)
        return bucket

    def _build_next_index(
        self,
        records: list[ReplacementRecord],
        entity_states: dict[int, SessionEntityState],
    ) -> int:
        """跨 attr_type 全局编号：取已用 entity_id 的 max+1。"""
        max_index = 0
        for record in records:
            if record.entity_id is not None and record.entity_id > max_index:
                max_index = record.entity_id
        for entity_id in entity_states:
            if entity_id > max_index:
                max_index = entity_id
        return max_index + 1

    # ------------------------------------------------------------------
    # 三级查找
    # ------------------------------------------------------------------

    def _resolve_entity_id(
        self,
        target: NormalizedPII,
        *,
        entity_states: dict[int, SessionEntityState],
        road_bucket: dict[str, list[int]],
    ) -> tuple[int | None, str | None]:
        """三级查找。返回 (entity_id, repo_persona_id)。

        - session 命中：返回已存在的 entity_id，repo_persona_id=None；
        - session miss → repo 命中：返回 None（调用方分配新 entity_id），同时给出 persona_id；
        - 全 miss：返回 (None, None)。
        """
        session_hit = self._find_session_hit(target, entity_states, road_bucket)
        if session_hit is not None:
            return session_hit, None

        if self.repo_index is not None:
            repo_hit = self._find_repo_hit(target)
            if repo_hit is not None:
                return None, repo_hit.persona_id

        return None, None

    def _find_session_hit(
        self,
        target: NormalizedPII,
        entity_states: dict[int, SessionEntityState],
        road_bucket: dict[str, list[int]],
    ) -> int | None:
        same_attr_states = [
            state for state in entity_states.values() if state.attr_type == target.attr_type
        ]
        if not same_attr_states:
            return None

        if target.attr_type != PIIAttributeType.ADDRESS:
            for state in same_attr_states:
                if same_entity(state.merged_normalized, target):
                    return state.entity_id
            return None

        target_road = self._target_road_canonical(target)
        if target_road:
            bucket_ids = set(road_bucket.get(target_road, ()))
            for state in same_attr_states:
                if state.entity_id not in bucket_ids:
                    continue
                if same_entity(state.merged_normalized, target):
                    return state.entity_id
            for state in same_attr_states:
                if state.has_road:
                    continue
                if same_entity(state.merged_normalized, target):
                    return state.entity_id
            return None

        for state in same_attr_states:
            if same_entity(state.merged_normalized, target):
                return state.entity_id
        return None

    def _find_repo_hit(self, target: NormalizedPII) -> IndexedRepoEntity | None:
        if self.repo_index is None:
            return None
        if target.attr_type == PIIAttributeType.ADDRESS:
            target_road = self._target_road_canonical(target)
            if target_road:
                for entry in self.repo_index.address_road_bucket.get(target_road, ()):
                    if not entry.meets_min_cardinality():
                        continue
                    if same_entity(entry.normalized, target):
                        return entry
                for entry in self.repo_index.address_road_missing:
                    if not entry.meets_min_cardinality():
                        continue
                    if same_entity(entry.normalized, target):
                        return entry
                return None
            for entry in self.repo_index.candidates_for(PIIAttributeType.ADDRESS):
                if not entry.meets_min_cardinality():
                    continue
                if same_entity(entry.normalized, target):
                    return entry
            return None

        for entry in self.repo_index.candidates_for(target.attr_type):
            if same_entity(entry.normalized, target):
                return entry
        return None

    @staticmethod
    def _target_road_canonical(normalized: NormalizedPII) -> str:
        if normalized.attr_type != PIIAttributeType.ADDRESS:
            return ""
        road_value = str(normalized.components.get("road") or "").strip()
        if not road_value:
            return ""
        return _canonicalize_address_component_value("road", road_value)

    # ------------------------------------------------------------------
    # 渲染与同 plan 累积
    # ------------------------------------------------------------------

    def _render(
        self,
        action: DecisionAction,
        normalized: NormalizedPII,
        entity_id: int,
    ) -> str:
        frag_type_list = action.metadata.get("fragment_type") if action.metadata else None
        frag_type = frag_type_list[0] if frag_type_list else None
        frag_len = (
            len(action.source_text)
            if (frag_type and action.source_text)
            else None
        )
        if action.attr_type in GENERIC_FRAGMENT_PLACEHOLDER_ATTRS and frag_type and frag_len:
            return render_placeholder(
                action.attr_type,
                index=entity_id,
                fragment_type=frag_type,
                fragment_length=frag_len,
            )

        if action.attr_type == PIIAttributeType.ADDRESS:
            spec = address_display_spec(normalized)
            return render_placeholder(
                action.attr_type,
                index=entity_id,
                address_spec=spec,
            )
        return render_placeholder(action.attr_type, index=entity_id)

    def _record_assignment(
        self,
        entity_states: dict[int, SessionEntityState],
        road_bucket: dict[str, list[int]],
        entity_id: int,
        normalized: NormalizedPII,
    ) -> None:
        existing = entity_states.get(entity_id)
        if existing is None:
            new_state = SessionEntityState.from_normalized(entity_id, normalized)
        else:
            new_state = existing.merge(normalized)
        entity_states[entity_id] = new_state

        if new_state.attr_type != PIIAttributeType.ADDRESS:
            return
        # 桶维护：road_canonical 可能因为 merge 后从空变为非空（首次 PII 无 road，第二次有）。
        if existing is not None and existing.road_canonical and existing.road_canonical != new_state.road_canonical:
            stale = road_bucket.get(existing.road_canonical)
            if stale and entity_id in stale:
                stale.remove(entity_id)
                if not stale:
                    road_bucket.pop(existing.road_canonical, None)
        if new_state.road_canonical:
            ids = road_bucket.setdefault(new_state.road_canonical, [])
            if entity_id not in ids:
                ids.append(entity_id)
