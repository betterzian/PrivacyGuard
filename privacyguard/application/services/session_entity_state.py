"""Session 内 entity 累积状态。

每条 session record 只保存"该次出现"的 normalized snapshot；
``SessionPlaceholderAllocator.assign`` 在分配前把同 entity_id 的 records 按组件
并集 (first-wins) 重建为累积态，供 ``same_entity`` 比对与 road 桶检索使用。

注意：display SPEC 永远按"新 PII 自己的 ordered_components"现场投射，**不走** merged
state；本类只服务于命中判定与桶 key 抽取。
"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.utils.normalized_pii import (
    _ADDRESS_COMPONENT_KEYS,  # type: ignore[attr-defined]
    _canonicalize_address_component_value,  # type: ignore[attr-defined]
    normalize_pii,
)


def _road_canonical_of(normalized: NormalizedPII) -> str:
    """从归一结果抽取 road 桶 key。仅地址有效；缺失返回空串。"""
    if normalized.attr_type != PIIAttributeType.ADDRESS:
        return ""
    road_value = str(normalized.components.get("road") or "").strip()
    if not road_value:
        return ""
    return _canonicalize_address_component_value("road", road_value)


@dataclass(slots=True)
class SessionEntityState:
    """单个 session entity 的累积状态。"""

    entity_id: int
    attr_type: PIIAttributeType
    # 累积态：地址走组件并集重建；其它 attr_type 保持首条原值（字面等值已足够判等）。
    merged_normalized: NormalizedPII
    has_road: bool
    road_canonical: str

    @classmethod
    def from_normalized(cls, entity_id: int, normalized: NormalizedPII) -> "SessionEntityState":
        road_canonical = _road_canonical_of(normalized)
        return cls(
            entity_id=entity_id,
            attr_type=normalized.attr_type,
            merged_normalized=normalized,
            has_road=bool(road_canonical),
            road_canonical=road_canonical,
        )

    def merge(self, new_pii: NormalizedPII) -> "SessionEntityState":
        """把 new_pii 合入当前累积态；返回新 SessionEntityState（不就地修改）。

        - attr_type 不一致直接返回自身（防御）；
        - 非地址：字面等值已经判过，无需 merge，保持首条不变；
        - 地址：按 ``_ADDRESS_COMPONENT_KEYS`` 逐 key first-wins 取并集，
          重新走 ``normalize_pii(components=...)`` 重建 identity / canonical / has_admin_static。
        """
        if self.attr_type != new_pii.attr_type:
            return self
        if self.attr_type != PIIAttributeType.ADDRESS:
            return self

        merged_components: dict[str, str] = {}
        for key in _ADDRESS_COMPONENT_KEYS:
            old_value = str(self.merged_normalized.components.get(key) or "").strip()
            new_value = str(new_pii.components.get(key) or "").strip()
            chosen = old_value or new_value
            if chosen:
                merged_components[key] = chosen
        if not merged_components:
            return self

        rebuilt = normalize_pii(
            PIIAttributeType.ADDRESS,
            self.merged_normalized.raw_text or new_pii.raw_text,
            components=merged_components,
        )
        road_canonical = _road_canonical_of(rebuilt)
        return SessionEntityState(
            entity_id=self.entity_id,
            attr_type=self.attr_type,
            merged_normalized=rebuilt,
            has_road=bool(road_canonical),
            road_canonical=road_canonical,
        )


__all__ = ["SessionEntityState"]
