"""会话级占位符分配服务。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.policies.generic_placeholder import render_generic_replacement_text
from privacyguard.utils.normalized_pii import normalize_pii, normalized_primary_text, same_entity

_PLACEHOLDER_PATTERN = re.compile(r"^<(?P<label>.+?)(?P<index>\d+)?>$")


class SessionPlaceholderAllocator:
    """为 GENERICIZE 动作分配 session 级稳定占位符。"""

    def __init__(self, mapping_store: MappingStore) -> None:
        self.mapping_store = mapping_store

    def assign(self, plan: DecisionPlan) -> DecisionPlan:
        """基于 session 历史为计划中的通用标签分配唯一占位符。"""
        session_records = self.mapping_store.get_replacements(plan.session_id)
        existing_by_source = self._build_existing_by_source(session_records)
        next_index = self._build_next_index(session_records)

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
            replacement_text = self._find_existing_replacement(existing_by_source, normalized)
            if replacement_text is None:
                # 数字/混合片段使用语义占位符格式。
                frag_type_list = action.metadata.get("fragment_type")
                frag_type = frag_type_list[0] if frag_type_list else None
                frag_len = len(action.source_text) if (frag_type and action.source_text) else None
                replacement_text = render_generic_replacement_text(
                    action.attr_type,
                    source_text=normalized_primary_text(normalized) or action.source_text,
                    index=next_index,
                    fragment_type=frag_type,
                    fragment_length=frag_len,
                )
                existing_by_source.append((action.attr_type, normalized, replacement_text))
                next_index += 1
            updated = action.model_copy(deep=True)
            updated.replacement_text = replacement_text
            updated.normalized_source = normalized
            actions.append(updated)

        return plan.model_copy(update={"actions": actions}, deep=True)

    def _build_existing_by_source(self, records: list[ReplacementRecord]) -> list[tuple[PIIAttributeType, NormalizedPII, str]]:
        ordered = sorted(records, key=lambda item: (item.turn_id, item.replacement_id), reverse=True)
        existing: list[tuple[PIIAttributeType, NormalizedPII, str]] = []
        for record in ordered:
            if record.action_type != ActionType.GENERICIZE:
                continue
            if not record.replacement_text:
                continue
            normalized = record.normalized_source or normalize_pii(
                record.attr_type,
                record.source_text,
                metadata=record.metadata,
            )
            existing.append((record.attr_type, normalized, record.replacement_text))
        return existing

    def _build_next_index(self, records: list[ReplacementRecord]) -> int:
        max_index = 0
        for record in records:
            if record.action_type != ActionType.GENERICIZE or not record.replacement_text:
                continue
            matched = _PLACEHOLDER_PATTERN.match(record.replacement_text)
            if matched is None:
                continue
            index_text = matched.group("index")
            if index_text is None:
                continue
            max_index = max(max_index, int(index_text))
        return max_index + 1 if max_index > 0 else 1

    def _find_existing_replacement(
        self,
        existing_by_source: list[tuple[PIIAttributeType, NormalizedPII, str]],
        target: NormalizedPII,
    ) -> str | None:
        for attr_type, normalized, replacement_text in existing_by_source:
            if attr_type != target.attr_type:
                continue
            if same_entity(normalized, target):
                return replacement_text
        return None

