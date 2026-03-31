"""地址 geo 词库加载。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ChinaGeoLexicon:
    provinces: tuple[str, ...]
    cities: tuple[str, ...]
    districts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnGeoLexicon:
    tier_a_state_names: tuple[str, ...]
    tier_a_state_codes: tuple[str, ...]
    tier_b_places: tuple[str, ...]


def _data_root() -> Path:
    return Path(__file__).resolve().parents[4] / "data"


@lru_cache(maxsize=1)
def load_china_geo_lexicon() -> ChinaGeoLexicon:
    path = _data_root() / "china_geo_lexicon.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return ChinaGeoLexicon(
        provinces=tuple(str(item).strip() for item in payload.get("provinces", []) if str(item).strip()),
        cities=tuple(str(item).strip() for item in payload.get("cities", []) if str(item).strip()),
        districts=tuple(str(item).strip() for item in payload.get("districts", []) if str(item).strip()),
    )


@lru_cache(maxsize=1)
def load_en_geo_lexicon() -> EnGeoLexicon:
    path = _data_root() / "en_geo_lexicon.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return EnGeoLexicon(
        tier_a_state_names=tuple(str(item).strip() for item in payload.get("tier_a_state_names", []) if str(item).strip()),
        tier_a_state_codes=tuple(str(item).strip() for item in payload.get("tier_a_state_codes", []) if str(item).strip()),
        tier_b_places=tuple(str(item).strip() for item in payload.get("tier_b_places", []) if str(item).strip()),
    )
