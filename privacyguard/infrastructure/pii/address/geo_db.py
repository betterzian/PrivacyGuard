"""地址 geo 词库加载（含 strength 分级）。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from privacyguard.infrastructure.pii.detector.models import ClaimStrength
from privacyguard.infrastructure.pii.lexicon_store import read_scanner_lexicon_json


@dataclass(frozen=True, slots=True)
class GeoEntry:
    """地名条目，含 strength 分级。"""
    text: str
    strength: ClaimStrength


@dataclass(frozen=True, slots=True)
class ZhGeoLexicon:
    provinces: tuple[GeoEntry, ...]
    cities: tuple[GeoEntry, ...]
    districts: tuple[GeoEntry, ...]
    # 县级市（张家港等）。独立字段与 districts 分开承载，与 DISTRICT_CITY 组件类型对应。
    district_cities: tuple[GeoEntry, ...]
    local_places: tuple[GeoEntry, ...]


@dataclass(frozen=True, slots=True)
class EnGeoLexicon:
    state_names: tuple[GeoEntry, ...]
    state_codes: tuple[GeoEntry, ...]
    cities: tuple[GeoEntry, ...]
    # 行政区/城市次级区划（如纽约五个 Borough）。独立承载以与 DISTRICT 组件类型对齐，
    # 避免与 cities 混淆导致 MULTI_ADMIN 解释路径被迫走 city 层级。
    districts: tuple[GeoEntry, ...]


def _parse_tiered_geo(data: object) -> tuple[GeoEntry, ...]:
    """解析 {"hard": [...], "soft": [...], "weak": [...]} 格式的地名分级。"""
    if not isinstance(data, dict):
        return ()
    entries: list[GeoEntry] = []
    for strength_str in ("hard", "soft", "weak"):
        names = data.get(strength_str, [])
        if not isinstance(names, list):
            continue
        strength = ClaimStrength(strength_str)
        for name in names:
            text = str(name).strip()
            if text:
                entries.append(GeoEntry(text=text, strength=strength))
    return tuple(entries)


@lru_cache(maxsize=1)
def load_zh_geo_lexicon() -> ZhGeoLexicon:
    payload = read_scanner_lexicon_json("zh_geo_lexicon.json")
    return ZhGeoLexicon(
        provinces=_parse_tiered_geo(payload.get("provinces", {})),
        cities=_parse_tiered_geo(payload.get("cities", {})),
        districts=_parse_tiered_geo(payload.get("districts", {})),
        # district_cities 字段可缺省（向后兼容）；缺失时返回空元组。
        district_cities=_parse_tiered_geo(payload.get("district_cities", {})),
        local_places=_parse_tiered_geo(payload.get("local_places", {})),
    )


@lru_cache(maxsize=1)
def load_en_geo_lexicon() -> EnGeoLexicon:
    payload = read_scanner_lexicon_json("en_geo_lexicon.json")
    return EnGeoLexicon(
        state_names=_parse_tiered_geo(payload.get("state_names", {})),
        state_codes=_parse_tiered_geo(payload.get("state_codes", {})),
        cities=_parse_tiered_geo(payload.get("cities", {})),
        # districts 字段允许缺省以兼容旧词库；缺失时返回空元组。
        districts=_parse_tiered_geo(payload.get("districts", {})),
    )
