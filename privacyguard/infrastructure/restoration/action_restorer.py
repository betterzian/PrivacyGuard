"""动作文本还原模块实现。

restore 与 sanitize 对称：

- 含 ``entity_id`` 的 GENERICIZE 记录走"占位符正则 + entity 累积态投射"路径，
  支持云端 LLM 改写 SPEC 精度（如 ``[[ADDR#1.CITY]]`` ↔ ``[[ADDR#1.PROV-CITY-DIST-ROAD-DTL]]``）；
- 无 ``entity_id`` 的记录（如 PERSONA_SLOT）按原字面匹配路径兜底；
- 同实体多 POI 时按 ``select_priority_poi`` 择一（小区/社区 > 楼号 > 广场/停车场）。
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from privacyguard.application.services.session_entity_state import SessionEntityState
from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.policies.placeholder_labels import (
    PLACEHOLDER_LEFT_BRACKET,
    PLACEHOLDER_RIGHT_BRACKET,
    PLACEHOLDER_TYPE_CODE,
)
from privacyguard.domain.policies.poi_priority import select_priority_poi
from privacyguard.utils.normalized_pii import (
    _ADDRESS_COMPONENT_KEYS,  # type: ignore[attr-defined]
    _DISPLAY_LEVEL_BY_COMPONENT_KEY,  # type: ignore[attr-defined]
    normalize_pii,
)

# 在云端文本中搜索的非锚定占位符正则；与 PLACEHOLDER_PATTERN 同结构去掉 ^$。
_PLACEHOLDER_FIND_PATTERN: re.Pattern[str] = re.compile(
    rf"{re.escape(PLACEHOLDER_LEFT_BRACKET)}(?P<label>[A-Z_]+)#(?P<index>\d+)(?:\.(?P<spec>[A-Z0-9=+\-]+))?{re.escape(PLACEHOLDER_RIGHT_BRACKET)}"
)

# label → attr_type 反向表，用于占位符与 entity attr_type 一致性校验。
_LABEL_TO_ATTR: dict[str, PIIAttributeType] = {
    code: attr for attr, code in PLACEHOLDER_TYPE_CODE.items()
}

# DTL 在 entity 无 poi 时的回退字段顺序。
_DTL_FALLBACK_KEYS: tuple[str, ...] = ("building", "unit", "room", "suite", "detail")


class ActionRestorer:
    """根据替换记录将云端文本恢复为真实值。"""

    def restore(
        self,
        cloud_text: str,
        records: list[ReplacementRecord],
    ) -> tuple[str, list[RestoredSlot]]:
        """对 cloud_text 进行还原；同 entity 多次出现按 SPEC 投射各自精度。"""
        entity_records = [
            r for r in records if r.entity_id is not None and r.replacement_text
        ]
        legacy_records = [
            r for r in records if r.entity_id is None and r.replacement_text
        ]

        entity_states = _build_entity_states(entity_records)
        first_record_by_entity = _first_record_per_entity(entity_records)

        restored_slots: list[RestoredSlot] = []
        seen_placeholder_strings: set[str] = set()

        def _resolve(match: re.Match[str]) -> str:
            placeholder = match.group(0)
            label = match.group("label") or ""
            index_str = match.group("index") or ""
            spec = match.group("spec") or ""
            if not label or not index_str:
                return placeholder
            try:
                entity_id = int(index_str)
            except ValueError:
                return placeholder

            state = entity_states.get(entity_id)
            record = first_record_by_entity.get(entity_id)
            if state is None or record is None:
                return placeholder

            attr_from_label = _LABEL_TO_ATTR.get(label)
            # NUM / ALNUM 同 attr 类型；label 不匹配 entity 类型时保留原串以防破坏。
            if attr_from_label is not None and attr_from_label != state.attr_type:
                return placeholder

            value = _project_value(state, spec, record)
            if not value:
                return placeholder

            if placeholder not in seen_placeholder_strings:
                seen_placeholder_strings.add(placeholder)
                restored_slots.append(
                    RestoredSlot(
                        attr_type=state.attr_type.value,
                        value=value,
                        source_placeholder=placeholder,
                    )
                )
            return value

        restored_text = _PLACEHOLDER_FIND_PATTERN.sub(_resolve, cloud_text)

        # legacy 路径：无 entity_id 的记录（如 PERSONA_SLOT）按字面匹配兜底。
        ordered_legacy = sorted(
            legacy_records,
            key=lambda item: (item.turn_id, len(item.replacement_text)),
            reverse=True,
        )
        seen_legacy_placeholders: set[str] = set()
        for record in ordered_legacy:
            placeholder = record.replacement_text
            if placeholder in seen_legacy_placeholders:
                continue
            if placeholder not in restored_text:
                continue
            source_value = (
                record.normalized_source.raw_text
                if record.normalized_source
                else record.source_text
            )
            restored_text = restored_text.replace(placeholder, source_value)
            seen_legacy_placeholders.add(placeholder)
            restored_slots.append(
                RestoredSlot(
                    attr_type=record.attr_type.value,
                    value=source_value,
                    source_placeholder=placeholder,
                )
            )

        return restored_text, restored_slots


# ---------------------------------------------------------------------------
# 内部：entity 累积态构建
# ---------------------------------------------------------------------------


def _build_entity_states(
    records: list[ReplacementRecord],
) -> dict[int, SessionEntityState]:
    """按 entity_id 把同 entity 多条记录折叠为 SessionEntityState（与 allocator 同源逻辑）。"""
    states: dict[int, SessionEntityState] = {}
    ordered = sorted(records, key=lambda item: (item.turn_id, item.replacement_id))
    for record in ordered:
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


def _first_record_per_entity(
    records: list[ReplacementRecord],
) -> dict[int, ReplacementRecord]:
    """每个 entity_id 取首条记录（按 turn_id / replacement_id 排序）。"""
    out: dict[int, ReplacementRecord] = {}
    ordered = sorted(records, key=lambda item: (item.turn_id, item.replacement_id))
    for record in ordered:
        if record.entity_id is None:
            continue
        out.setdefault(record.entity_id, record)
    return out


# ---------------------------------------------------------------------------
# 内部：投射回还原文本
# ---------------------------------------------------------------------------


def _project_value(
    state: SessionEntityState,
    spec: str,
    record: ReplacementRecord,
) -> str:
    """ADDRESS 走 SPEC 投射；非 ADDRESS 直接取 merged_normalized.raw_text 或首条 source_text。"""
    if state.attr_type == PIIAttributeType.ADDRESS:
        return _project_address(state, spec)
    raw = (state.merged_normalized.raw_text or "").strip()
    if raw:
        return raw
    return record.source_text or ""


def _project_address(state: SessionEntityState, spec: str) -> str:
    components = state.merged_normalized.components
    spec_parts = [p.strip() for p in (spec or "").split("-") if p.strip()]
    if not spec_parts:
        return _render_full_address(components)
    parts: list[str] = []
    for token in spec_parts:
        text = _project_address_token(components, token)
        if text:
            parts.append(text)
    if not parts:
        return _render_full_address(components)
    return "".join(parts)


def _render_full_address(components: Mapping[str, str]) -> str:
    """SPEC 缺省 / 全部 token 投射为空时的整址回退（POI 走优先级择一）。"""
    out: list[str] = []
    for ct in _ADDRESS_COMPONENT_KEYS:
        if ct == "poi":
            v = str(components.get("poi") or "").strip()
            if v:
                out.append(
                    select_priority_poi(v, str(components.get("poi_key") or ""))
                )
            continue
        if ct == "poi_key":
            continue
        v = str(components.get(ct) or "").strip()
        if v:
            out.append(v)
    return "".join(out)


def _project_address_token(components: Mapping[str, str], token: str) -> str:
    """单个 SPEC token（PROV / CITY / DIST / ROAD / DTL）投射。"""
    target = token.lower()
    if target == "dtl":
        poi = str(components.get("poi") or "").strip()
        if poi:
            return select_priority_poi(poi, str(components.get("poi_key") or ""))
        out: list[str] = []
        for ct in _DTL_FALLBACK_KEYS:
            v = str(components.get(ct) or "").strip()
            if v:
                out.append(v)
        return "".join(out)

    parts: list[str] = []
    for ct in _ADDRESS_COMPONENT_KEYS:
        if ct in ("poi", "poi_key", "multi_admin"):
            continue
        if _DISPLAY_LEVEL_BY_COMPONENT_KEY.get(ct, "") != target:
            continue
        v = str(components.get(ct) or "").strip()
        if v:
            parts.append(v)
    if not parts and target in {"prov", "city"}:
        ma = str(components.get("multi_admin") or "").strip()
        if ma:
            parts.append(ma)
    return "".join(parts)
