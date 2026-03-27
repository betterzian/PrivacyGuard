"""会话级占位符分配服务。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.policies.generic_placeholder import render_generic_replacement_text
from privacyguard.utils.pii_value import canonicalize_pii_value

_PLACEHOLDER_PATTERN = re.compile(r"^<(?P<label>.+?)(?P<index>\d+)?>$")
_ADDRESS_CANONICAL_ORDER = ("province", "city", "district", "street", "poi", "compound", "building", "room", "detail", "postal")
_ADDRESS_MATCH_ORDER = ("province", "city", "district", "street", "poi", "compound", "building", "room")


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
            source_key = self._source_key(action.attr_type, action.canonical_source_text or action.source_text)
            replacement_text = existing_by_source.get(source_key)
            if replacement_text is None and action.attr_type == PIIAttributeType.ADDRESS:
                matched_key = self._find_equivalent_address_key(existing_by_source, source_key[1])
                if matched_key is not None:
                    replacement_text = existing_by_source.get((PIIAttributeType.ADDRESS, matched_key))
            if replacement_text is None and action.attr_type == PIIAttributeType.ORGANIZATION:
                matched_key = self._find_equivalent_organization_key(existing_by_source, source_key[1])
                if matched_key is not None:
                    replacement_text = existing_by_source.get((PIIAttributeType.ORGANIZATION, matched_key))
            if replacement_text is None:
                replacement_text = render_generic_replacement_text(
                    action.attr_type,
                    source_text=action.canonical_source_text or action.source_text,
                    index=next_index,
                )
                existing_by_source[source_key] = replacement_text
                next_index += 1
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

    def _source_key(self, attr_type: PIIAttributeType, source_text: str) -> tuple[PIIAttributeType, str]:
        return (attr_type, canonicalize_pii_value(attr_type, source_text))

    def _find_equivalent_address_key(
        self,
        existing_by_source: dict[tuple[PIIAttributeType, str], str],
        target_canonical: str,
    ) -> str | None:
        target = self._parse_address_canonical(target_canonical)
        if not target:
            return None
        for (attr_type, canonical), _replacement in existing_by_source.items():
            if attr_type != PIIAttributeType.ADDRESS:
                continue
            candidate = self._parse_address_canonical(canonical)
            if not candidate:
                continue
            compared_fields = 0
            all_matched = True
            for field in _ADDRESS_MATCH_ORDER:
                left = target.get(field, "")
                right = candidate.get(field, "")
                if not left or not right:
                    continue
                compared_fields += 1
                if not self._address_field_equivalent(left, right):
                    all_matched = False
                    break
            if compared_fields > 0 and all_matched:
                return canonical
        return None

    def _parse_address_canonical(self, canonical: str) -> dict[str, str]:
        parts = [part.strip() for part in canonical.split("|") if part.strip()]
        if not parts:
            raise ValueError("ADDRESS canonical 不能为空，且必须为 key=value 结构。")
        # 纯新链路：仅接受显式 key=value 结构；旧位置串直接判无效。
        if any("=" not in part for part in parts):
            raise ValueError(f"ADDRESS canonical 非法（仅支持 key=value）：{canonical}")
        parsed: dict[str, str] = {}
        for part in parts:
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in _ADDRESS_CANONICAL_ORDER and value:
                parsed[key] = value
        if not parsed:
            raise ValueError(f"ADDRESS canonical 未包含任何有效字段：{canonical}")
        return parsed

    def _address_field_equivalent(self, left: str, right: str) -> bool:
        normalized_left = self._normalize_address_field(left)
        normalized_right = self._normalize_address_field(right)
        if not normalized_left or not normalized_right:
            return False
        lcp = self._longest_common_prefix_len(normalized_left, normalized_right)
        return lcp == min(len(normalized_left), len(normalized_right))

    def _normalize_address_field(self, value: str) -> str:
        return re.sub(r"\s+", "", value).lower()

    def _longest_common_prefix_len(self, left: str, right: str) -> int:
        size = min(len(left), len(right))
        for index in range(size):
            if left[index] != right[index]:
                return index
        return size

    def _find_equivalent_organization_key(
        self,
        existing_by_source: dict[tuple[PIIAttributeType, str], str],
        target_canonical: str,
    ) -> str | None:
        target = self._normalize_address_field(target_canonical)
        if not target:
            return None
        for (attr_type, canonical), _replacement in existing_by_source.items():
            if attr_type != PIIAttributeType.ORGANIZATION:
                continue
            candidate = self._normalize_address_field(canonical)
            if not candidate:
                continue
            lcp = self._longest_common_prefix_len(target, candidate)
            if lcp == min(len(target), len(candidate)):
                return canonical
        return None

