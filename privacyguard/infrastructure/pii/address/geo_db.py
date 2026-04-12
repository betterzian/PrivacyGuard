"""地址 geo 词库加载。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from privacyguard.infrastructure.pii.lexicon_store import read_scanner_lexicon_json


@dataclass(frozen=True, slots=True)
class ZhGeoLexicon:
    provinces: tuple[str, ...]
    cities: tuple[str, ...]
    districts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnGeoLexicon:
    tier_a_state_names: tuple[str, ...]
    tier_a_state_codes: tuple[str, ...]
    tier_b_places: tuple[str, ...]
    tier_c_places: tuple[str, ...]


@lru_cache(maxsize=1)
def load_zh_geo_lexicon() -> ZhGeoLexicon:
    payload = read_scanner_lexicon_json("zh_geo_lexicon.json")
    return ZhGeoLexicon(
        provinces=tuple(str(item).strip() for item in payload.get("provinces", []) if str(item).strip()),
        cities=tuple(str(item).strip() for item in payload.get("cities", []) if str(item).strip()),
        districts=tuple(str(item).strip() for item in payload.get("districts", []) if str(item).strip()),
    )


@lru_cache(maxsize=1)
def load_en_geo_lexicon() -> EnGeoLexicon:
    payload = read_scanner_lexicon_json("en_geo_lexicon.json")
    return EnGeoLexicon(
        tier_a_state_names=tuple(str(item).strip() for item in payload.get("tier_a_state_names", []) if str(item).strip()),
        tier_a_state_codes=tuple(str(item).strip() for item in payload.get("tier_a_state_codes", []) if str(item).strip()),
        tier_b_places=tuple(str(item).strip() for item in payload.get("tier_b_places", []) if str(item).strip()),
        tier_c_places=tuple(str(item).strip() for item in payload.get("tier_c_places", []) if str(item).strip()),
    )
