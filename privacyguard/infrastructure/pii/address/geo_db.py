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
    city_provinces: dict[str, tuple[str, ...]]
    districts: tuple[GeoEntry, ...]
    # 县级市（张家港等）。独立字段与 districts 分开承载，与 DISTRICT_CITY 组件类型对应。
    district_cities: tuple[GeoEntry, ...]
    local_places: tuple[GeoEntry, ...]


@dataclass(frozen=True, slots=True)
class EnGeoLexicon:
    state_names: tuple[GeoEntry, ...]
    state_codes: tuple[GeoEntry, ...]
    cities: tuple[GeoEntry, ...]
    city_provinces: dict[str, tuple[str, ...]]
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


def _parse_city_provinces(data: object, *, casefold_keys: bool = False) -> dict[str, tuple[str, ...]]:
    """解析 city -> province aliases 映射。"""
    if not isinstance(data, dict):
        return {}
    mapping: dict[str, tuple[str, ...]] = {}
    for raw_city, raw_provinces in data.items():
        city = str(raw_city).strip()
        if not city:
            continue
        if isinstance(raw_provinces, str):
            values = (raw_provinces,)
        elif isinstance(raw_provinces, list):
            values = tuple(str(value).strip() for value in raw_provinces)
        else:
            values = ()
        provinces = tuple(value for value in values if value)
        if not provinces:
            continue
        key = city.casefold() if casefold_keys else city
        mapping[key] = provinces
    return mapping


def _en_state_aliases(name: str) -> tuple[str, ...]:
    state_codes = read_scanner_lexicon_json("en_us_states.json")
    aliases = [name]
    if isinstance(state_codes, dict):
        for code, full_name in state_codes.items():
            if str(full_name).casefold() == name.casefold():
                aliases.append(str(code).strip())
    return tuple(alias for alias in aliases if alias)


@lru_cache(maxsize=1)
def load_zh_geo_lexicon() -> ZhGeoLexicon:
    payload = read_scanner_lexicon_json("zh_geo_lexicon.json")
    return ZhGeoLexicon(
        provinces=_parse_tiered_geo(payload.get("provinces", {})),
        cities=_parse_tiered_geo(payload.get("cities", {})),
        city_provinces=_parse_city_provinces(payload.get("city_provinces", {})),
        districts=_parse_tiered_geo(payload.get("districts", {})),
        # district_cities 字段可缺省（向后兼容）；缺失时返回空元组。
        district_cities=_parse_tiered_geo(payload.get("district_cities", {})),
        local_places=_parse_tiered_geo(payload.get("local_places", {})),
    )


@lru_cache(maxsize=1)
def load_en_geo_lexicon() -> EnGeoLexicon:
    payload = read_scanner_lexicon_json("en_geo_lexicon.json")
    raw_city_provinces = _parse_city_provinces(payload.get("city_provinces", {}), casefold_keys=True)
    city_provinces = {
        city: tuple(dict.fromkeys(alias for province in provinces for alias in _en_state_aliases(province)))
        for city, provinces in raw_city_provinces.items()
    }
    return EnGeoLexicon(
        state_names=_parse_tiered_geo(payload.get("state_names", {})),
        state_codes=_parse_tiered_geo(payload.get("state_codes", {})),
        cities=_parse_tiered_geo(payload.get("cities", {})),
        city_provinces=city_provinces,
        # districts 字段允许缺省以兼容旧词库；缺失时返回空元组。
        districts=_parse_tiered_geo(payload.get("districts", {})),
    )


def city_parent_provinces(city_text: str) -> tuple[str, ...]:
    """返回 city 在词库中登记的上级省/州别名。"""
    city = str(city_text or "").strip()
    if not city:
        return ()
    zh = load_zh_geo_lexicon().city_provinces.get(city)
    if zh:
        return zh
    return load_en_geo_lexicon().city_provinces.get(city.casefold(), ())
