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
    _dedupe_poi_pairs,  # type: ignore[attr-defined]
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


def _split_pipe(text: str) -> list[str]:
    """按 `|` 拆分 POI / poi_key 串，丢弃空段。"""
    return [s.strip() for s in (text or "").split("|") if s.strip()]


def _union_poi_pairs(
    old_poi: str,
    old_poi_key: str,
    new_poi: str,
    new_poi_key: str,
) -> tuple[str, str]:
    """对 (poi, poi_key) 两条以 `|` 分隔的串做并集去重，保持下标对齐。

    - 同 value 多次出现且 key 有空缺时，优先保留非空 key；
    - 复用 ``_dedupe_poi_pairs`` 按子串包含剔除短串、成对保留 key；
    - 两侧均空时返回空串。
    """
    old_vals = _split_pipe(old_poi)
    old_keys = _split_pipe(old_poi_key)
    new_vals = _split_pipe(new_poi)
    new_keys = _split_pipe(new_poi_key)

    pairs: list[tuple[str, str]] = []
    for vals, keys in ((old_vals, old_keys), (new_vals, new_keys)):
        for i, v in enumerate(vals):
            k = keys[i] if i < len(keys) else ""
            pairs.append((v, k))

    if not pairs:
        return "", ""

    # 同 value 出现多次时：先 fill 出每个 value 的最佳 key（首个非空，否则空）。
    best_key: dict[str, str] = {}
    for v, k in pairs:
        if v not in best_key or (not best_key[v] and k):
            best_key[v] = k
    canonical_pairs = [(v, best_key[v]) for v, _ in pairs]

    deduped = _dedupe_poi_pairs(canonical_pairs)
    return (
        "|".join(p[0] for p in deduped),
        "|".join(p[1] for p in deduped),
    )


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
        - 地址：admin / road / number 等单值字段沿用 first-wins 取并集；
          POI 与 poi_key 走 ``_union_poi_pairs`` 列表语义并集（保留同 entity 多 POI），
          最后走 ``normalize_pii(components=...)`` 重建 identity / canonical / has_admin_static。
        """
        if self.attr_type != new_pii.attr_type:
            return self
        if self.attr_type != PIIAttributeType.ADDRESS:
            return self

        old_components = self.merged_normalized.components
        new_components = new_pii.components

        merged_components: dict[str, str] = {}
        for key in _ADDRESS_COMPONENT_KEYS:
            # POI 单独走列表并集（见下方）；其它字段维持 first-wins。
            if key == "poi":
                continue
            old_value = str(old_components.get(key) or "").strip()
            new_value = str(new_components.get(key) or "").strip()
            chosen = old_value or new_value
            if chosen:
                merged_components[key] = chosen

        union_poi, union_poi_key = _union_poi_pairs(
            str(old_components.get("poi") or ""),
            str(old_components.get("poi_key") or ""),
            str(new_components.get("poi") or ""),
            str(new_components.get("poi_key") or ""),
        )
        if union_poi:
            merged_components["poi"] = union_poi
        if union_poi_key:
            merged_components["poi_key"] = union_poi_key

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
