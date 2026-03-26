from __future__ import annotations

from privacyguard.infrastructure.pii.address.lexicon import iter_address_components
from privacyguard.infrastructure.pii.address.types import AddressComponent


def parse_zh_components(text: str) -> tuple[AddressComponent, ...]:
    components: list[AddressComponent] = []
    seen_types: set[str] = set()
    for match in iter_address_components(text, locale_profile="zh_cn"):
        if match.component_type in seen_types and match.component_type not in {"building", "unit", "floor", "room"}:
            continue
        seen_types.add(match.component_type)
        components.append(
            AddressComponent(
                component_type=match.component_type,
                text=match.text,
                start_offset=match.start,
                end_offset=match.end,
                privacy_level=_privacy_level(match.component_type, match.text),
                confidence=0.88 if match.strength == "strong" else 0.8,
            )
        )
    return tuple(components)


def _privacy_level(component_type: str, text: str) -> str:
    if component_type in {"building", "unit", "floor", "room"}:
        return "fine"
    if component_type == "compound" and text.endswith(("小区", "公寓", "大厦", "宿舍", "社区")):
        return "fine"
    if component_type in {"road", "district", "poi", "postal_code"}:
        return "medium"
    return "coarse"
