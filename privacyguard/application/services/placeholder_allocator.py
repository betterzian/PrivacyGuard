"""会话级占位符分配服务。"""

from __future__ import annotations

import re
from collections import defaultdict

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.utils.pii_value import canonicalize_pii_value

_PLACEHOLDER_PREFIX = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.CARD_NUMBER: "卡号",
    PIIAttributeType.BANK_ACCOUNT: "银行账号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.OTHER: "敏感信息",
}
_PLACEHOLDER_PATTERN = re.compile(r"^@(?P<label>.+?)(?P<index>\d+)$")


class SessionPlaceholderAllocator:
    """为 GENERICIZE 动作分配 session 级稳定占位符。"""

    def __init__(self, mapping_store: MappingStore) -> None:
        self.mapping_store = mapping_store

    def assign(self, plan: DecisionPlan) -> DecisionPlan:
        """基于 session 历史为计划中的通用标签分配唯一占位符。"""
        session_records = self.mapping_store.get_replacements(plan.session_id)
        existing_by_source = self._build_existing_by_source(session_records)
        next_indices = self._build_next_indices(session_records)

        actions: list[DecisionAction] = []
        for action in plan.actions:
            if action.action_type != ActionType.GENERICIZE or not action.source_text:
                actions.append(action.model_copy(deep=True))
                continue
            source_key = self._source_key(action.attr_type, action.canonical_source_text or action.source_text)
            replacement_text = existing_by_source.get(source_key)
            if replacement_text is None:
                next_index = next_indices[action.attr_type]
                replacement_text = self._label_for_attr(action.attr_type, next_index)
                existing_by_source[source_key] = replacement_text
                next_indices[action.attr_type] = next_index + 1
            updated = action.model_copy(deep=True)
            updated.replacement_text = replacement_text
            actions.append(updated)

        return plan.model_copy(update={"actions": actions}, deep=True)

    def _build_existing_by_source(self, records: list[ReplacementRecord]) -> dict[tuple[PIIAttributeType, str], str]:
        ordered = sorted(records, key=lambda item: (item.turn_id, item.replacement_id), reverse=True)
        existing: dict[tuple[PIIAttributeType, str], str] = {}
        for record in ordered:
            if record.action_type != ActionType.GENERICIZE:
                continue
            source_text = record.canonical_source_text or record.source_text
            if not source_text or not record.replacement_text:
                continue
            key = self._source_key(record.attr_type, source_text)
            existing.setdefault(key, record.replacement_text)
        return existing

    def _build_next_indices(self, records: list[ReplacementRecord]) -> defaultdict[PIIAttributeType, int]:
        max_indices: defaultdict[PIIAttributeType, int] = defaultdict(int)
        for record in records:
            if record.action_type != ActionType.GENERICIZE or not record.replacement_text:
                continue
            matched = _PLACEHOLDER_PATTERN.match(record.replacement_text)
            if matched is None:
                continue
            expected_label = _PLACEHOLDER_PREFIX.get(record.attr_type, "敏感信息")
            if matched.group("label") != expected_label:
                continue
            max_indices[record.attr_type] = max(max_indices[record.attr_type], int(matched.group("index")))
        return defaultdict(lambda: 1, {attr_type: index + 1 for attr_type, index in max_indices.items()})

    def _source_key(self, attr_type: PIIAttributeType, source_text: str) -> tuple[PIIAttributeType, str]:
        return (attr_type, canonicalize_pii_value(attr_type, source_text))

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int) -> str:
        return f"@{_PLACEHOLDER_PREFIX.get(attr_type, '敏感信息')}{index}"
