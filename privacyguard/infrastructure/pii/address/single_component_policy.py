"""单组件地址片段的词典级策略（供按保护强度决定是否向候选池发射）。"""

from __future__ import annotations

import re

from privacyguard.infrastructure.pii.address.lexicon import (
    _ZH_DIRECT_CONTROLLED_MUNICIPALITIES,
    _ZH_SINGLE_COMPONENT_NEGATIVE_EXACT,
    _has_en_single_component_suffix_noise,
    _has_zh_single_component_suffix_noise,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import _BUILTIN_EN_GEO_LEXICON, _BUILTIN_GEO_LEXICON

_ZH_SINGLE_COMPONENT_NEGATIVE_TERMS: dict[str, frozenset[str]] = {
    "road": frozenset({
        "专用",
        "便宜",
        "充值",
        "减免",
        "国家",
        "好物",
        "学生",
        "店铺",
        "旗舰",
        "政府",
        "标签",
        "管理",
        "秒杀",
        "自营",
        "补贴",
        "虚拟",
        "道具",
        "专区",
        "仅剩",
        "限时",
    }),
    "street": frozenset({
        "专用",
        "便宜",
        "充值",
        "减免",
        "国家",
        "好物",
        "学生",
        "店铺",
        "旗舰",
        "政府",
        "标签",
        "管理",
        "秒杀",
        "自营",
        "补贴",
        "虚拟",
        "街区",
        "专区",
        "仅剩",
        "限时",
    }),
    "compound": frozenset({
        "专区",
        "便宜",
        "公司",
        "学校",
        "店铺",
        "政府",
        "标签",
        "管理",
        "自营",
        "补贴",
        "超市",
        "酒店",
        "银行",
        "医院",
    }),
    "town": frozenset({"专区", "标签", "管理", "补贴", "便宜"}),
    "street_admin": frozenset({"专区", "标签", "管理", "补贴", "便宜"}),
    "village": frozenset({"专区", "标签", "管理", "补贴", "便宜"}),
}
_EN_SINGLE_COMPONENT_NEGATIVE_TERMS: dict[str, frozenset[str]] = {
    "road": frozenset({"account", "banner", "buy", "community", "group", "info", "number", "personal", "profile", "switch"}),
    "street": frozenset({"account", "banner", "buy", "community", "group", "info", "number", "personal", "profile", "switch"}),
    "city": frozenset({"account", "banner", "mobile", "number", "phone", "profile"}),
    "state": frozenset({"account", "banner", "number", "phone", "profile"}),
}


def single_component_address_allowed(
    component_type: str,
    text: str,
    *,
    matched_by: str,
    source_text: str | None = None,
) -> bool:
    cleaned = text.strip()
    compact = re.sub(r"\s+", "", cleaned)
    lowered = re.sub(r"\s+", " ", cleaned).strip().lower()
    if not compact:
        return False
    if compact in _ZH_SINGLE_COMPONENT_NEGATIVE_EXACT:
        return False
    if any("\u4e00" <= char <= "\u9fff" for char in compact):
        if _has_zh_single_component_suffix_noise(compact, source_text=source_text):
            return False
        negatives = _ZH_SINGLE_COMPONENT_NEGATIVE_TERMS.get(component_type, frozenset())
        if any(token in compact for token in negatives):
            return False
        if component_type == "province":
            return matched_by == "context_address_field" and compact in _BUILTIN_GEO_LEXICON.provinces
        if component_type == "city":
            return matched_by == "context_address_field" and compact in (
                _BUILTIN_GEO_LEXICON.cities | _ZH_DIRECT_CONTROLLED_MUNICIPALITIES
            )
        if component_type == "district":
            return matched_by == "context_address_field" and compact in _BUILTIN_GEO_LEXICON.districts
        if component_type == "compound":
            return compact in _BUILTIN_GEO_LEXICON.local_places or matched_by == "context_address_field"
        return True

    negatives_en = _EN_SINGLE_COMPONENT_NEGATIVE_TERMS.get(component_type, frozenset())
    if any(token in lowered for token in negatives_en):
        return False
    if _has_en_single_component_suffix_noise(component_type, lowered, source_text=source_text):
        return False
    if component_type == "city":
        return matched_by == "context_address_field" and lowered in (
            _BUILTIN_EN_GEO_LEXICON.tier_b_places | _BUILTIN_EN_GEO_LEXICON.tier_c_places
        )
    if component_type == "state":
        return matched_by == "context_address_field" and (
            lowered in _BUILTIN_EN_GEO_LEXICON.tier_a_state_names
            or lowered in _BUILTIN_EN_GEO_LEXICON.tier_a_state_codes
        )
    return True
