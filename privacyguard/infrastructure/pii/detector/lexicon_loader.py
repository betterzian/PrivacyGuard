"""Scanner 词典数据加载。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.lexicon_store import read_scanner_lexicon_json
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, ClaimStrength, LabelSpec
from privacyguard.infrastructure.pii.detector.zh_name_rules import ZhNameRules, build_zh_name_rules


@dataclass(frozen=True, slots=True)
class AddressKeyword:
    """单个地址关键字，含 strength 分级。"""
    text: str
    strength: ClaimStrength


@dataclass(frozen=True, slots=True)
class AddressKeywordGroup:
    component_type: AddressComponentType
    entries: tuple[AddressKeyword, ...]


@dataclass(frozen=True, slots=True)
class ControlValueSpec:
    text: str
    normalized: str
    kind: str


def _read_json(filename: str) -> object:
    return read_scanner_lexicon_json(filename)


def _clean_str_list(values: object) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise ValueError("词典文件格式错误：应为字符串数组。")
    return tuple(str(item).strip() for item in values if str(item).strip())


def _clean_str_map(values: object) -> dict[str, str]:
    if not isinstance(values, dict):
        raise ValueError("词典文件格式错误：应为对象（string->string）。")
    cleaned: dict[str, str] = {}
    for raw_k, raw_v in values.items():
        k = str(raw_k).strip()
        v = str(raw_v).strip()
        if k and v:
            cleaned[k] = v
    return cleaned


def _parse_component_type(raw_value: object) -> AddressComponentType:
    return AddressComponentType(str(raw_value).strip())


@lru_cache(maxsize=1)
def load_label_specs() -> tuple[LabelSpec, ...]:
    payload = _read_json("labels.json")
    if not isinstance(payload, list):
        raise ValueError("labels.json 格式错误：根节点应为数组。")
    items: list[LabelSpec] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise ValueError("labels.json 格式错误：条目应为对象。")
        keyword = str(entry.get("keyword", "")).strip()
        if not keyword:
            continue
        items.append(
            LabelSpec(
                keyword=keyword,
                attr_type=PIIAttributeType(str(entry.get("attr_type", "")).strip()),
                order_index=index,
                source_kind=str(entry.get("source_kind", "")).strip(),
                ocr_source_kind=str(entry.get("ocr_source_kind", "")).strip(),
                ascii_boundary=bool(entry.get("ascii_boundary", False)),
            )
        )
    return tuple(items)


@lru_cache(maxsize=1)
def load_name_start_keywords() -> tuple[str, ...]:
    return _clean_str_list(_read_json("name_starts.json"))


@lru_cache(maxsize=1)
def load_zh_name_rules() -> ZhNameRules:
    """加载中文姓名统一规则。"""
    return build_zh_name_rules(_read_json("zh_name_rules.json"))


@lru_cache(maxsize=1)
def load_company_suffixes() -> tuple[str, ...]:
    return tuple(sorted(set(_clean_str_list(_read_json("company_suffixes.json"))), key=len, reverse=True))


def _load_address_groups(filename: str) -> tuple[AddressKeywordGroup, ...]:
    """解析 `{"text": ..., "strength": ...}` 格式的地址关键字组。"""
    payload = _read_json(filename)
    if not isinstance(payload, list):
        raise ValueError(f"{filename} 格式错误：根节点应为数组。")
    groups: list[AddressKeywordGroup] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError(f"{filename} 格式错误：条目应为对象。")
        raw_keywords = entry.get("keywords", [])
        if not isinstance(raw_keywords, list):
            raise ValueError(f"{filename} 格式错误：keywords 应为数组。")
        seen: set[str] = set()
        keywords: list[AddressKeyword] = []
        for item in raw_keywords:
            if not isinstance(item, dict):
                raise ValueError(f"{filename} 格式错误：keyword 条目应为对象。")
            text = str(item.get("text", "")).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            strength = ClaimStrength(str(item.get("strength", "soft")).strip())
            keywords.append(AddressKeyword(text=text, strength=strength))
        # 按长度降序排列，保证长词优先匹配。
        keywords.sort(key=lambda kw: len(kw.text), reverse=True)
        if not keywords:
            continue
        groups.append(
            AddressKeywordGroup(
                component_type=_parse_component_type(entry.get("component_type")),
                entries=tuple(keywords),
            )
        )
    return tuple(groups)


@lru_cache(maxsize=1)
def load_zh_address_keyword_groups() -> tuple[AddressKeywordGroup, ...]:
    return _load_address_groups("zh_address_keywords.json")


@lru_cache(maxsize=1)
def load_en_address_keyword_groups() -> tuple[AddressKeywordGroup, ...]:
    return _load_address_groups("en_address_keywords.json")


def _build_suffix_stripper(groups: tuple[AddressKeywordGroup, ...]) -> dict[str, re.Pattern[str]]:
    """从 address keywords 派生 suffix-only 裁剪正则。

    该裁剪器仅用于上游 `normalize_pii(ADDRESS)` 生成 match_terms，保证 session/local 与 scanner
    使用同一份 `data/scanner_lexicons/*_address_keywords.json` 作为单一真源。
    """
    patterns: dict[str, re.Pattern[str]] = {}
    for group in groups:
        key = group.component_type.value
        if not group.entries:
            continue
        # 仅做 suffix-only 删除，按长度降序拼接，避免短词抢先匹配。
        escaped = [re.escape(entry.text) for entry in group.entries if entry.text]
        if not escaped:
            continue
        patterns[key] = re.compile(rf"(?:{'|'.join(escaped)})$")
    return patterns


@lru_cache(maxsize=1)
def load_zh_address_suffix_strippers() -> dict[str, re.Pattern[str]]:
    """加载中文地址 suffix-only 裁剪器。"""
    return _build_suffix_stripper(load_zh_address_keyword_groups())


@lru_cache(maxsize=1)
def load_en_address_suffix_strippers() -> dict[str, re.Pattern[str]]:
    """加载英文地址 suffix-only 裁剪器。"""
    return _build_suffix_stripper(load_en_address_keyword_groups())


@lru_cache(maxsize=1)
def load_en_address_country_aliases() -> dict[str, str]:
    """加载英文地址国家别名表（小写 alias -> Canonical）。"""
    payload = _clean_str_map(_read_json("en_address_country_aliases.json"))
    return {k.lower(): v for k, v in payload.items()}


@lru_cache(maxsize=1)
def load_en_us_states() -> dict[str, str]:
    """加载美国州代码->州名映射。"""
    payload = _clean_str_map(_read_json("en_us_states.json"))
    return {k.upper(): v for k, v in payload.items()}


@lru_cache(maxsize=1)
def load_zh_country_prefix_aliases() -> dict[str, str]:
    """加载国家前缀别名表（用于剥离“中国/中国大陆/中华人民共和国”等前缀）。"""
    return _clean_str_map(_read_json("zh_country_prefix_aliases.json"))


@lru_cache(maxsize=1)
def load_negative_name_words() -> tuple[str, ...]:
    return _clean_str_list(_read_json("negative_name_words.json"))


@lru_cache(maxsize=1)
def load_negative_address_words() -> tuple[str, ...]:
    return _clean_str_list(_read_json("negative_address_words.json"))


@lru_cache(maxsize=1)
def load_negative_org_words() -> tuple[str, ...]:
    return _clean_str_list(_read_json("negative_org_words.json"))


@lru_cache(maxsize=1)
def load_negative_ui_words() -> tuple[str, ...]:
    return _clean_str_list(_read_json("negative_ui_words.json"))


@lru_cache(maxsize=1)
def load_en_surnames() -> tuple[str, ...]:
    """加载英文姓氏词典，按长度降序排列。"""
    payload = _clean_str_list(_read_json("en_surnames.json"))
    return tuple(sorted(set(payload), key=len, reverse=True))


@lru_cache(maxsize=1)
def load_en_given_names() -> tuple[str, ...]:
    """加载英文名字（given name）词典，按长度降序排列。"""
    payload = _clean_str_list(_read_json("en_given_names.json"))
    return tuple(sorted(set(payload), key=len, reverse=True))


@lru_cache(maxsize=1)
def load_zh_control_values() -> tuple[ControlValueSpec, ...]:
    payload = _read_json("zh_control_values.json")
    if not isinstance(payload, list):
        raise ValueError("zh_control_values.json 格式错误：根节点应为数组。")
    items: list[ControlValueSpec] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError("zh_control_values.json 格式错误：条目应为对象。")
        text = str(entry.get("text", "")).strip()
        normalized = str(entry.get("normalized", "")).strip()
        kind = str(entry.get("kind", "")).strip()
        if not text or not normalized or not kind:
            continue
        key = (text, normalized, kind)
        if key in seen:
            continue
        seen.add(key)
        items.append(ControlValueSpec(text=text, normalized=normalized, kind=kind))
    return tuple(sorted(items, key=lambda item: (len(item.text), item.text), reverse=True))


@lru_cache(maxsize=1)
def load_all_negative_words() -> tuple[str, ...]:
    return tuple(
        sorted(
            set(
                [
                    *load_negative_name_words(),
                    *load_negative_address_words(),
                    *load_negative_org_words(),
                    *load_negative_ui_words(),
                ]
            ),
            key=len,
            reverse=True,
        )
    )


__all__ = [
    "AddressKeyword",
    "AddressKeywordGroup",
    "ControlValueSpec",
    "load_all_negative_words",
    "load_company_suffixes",
    "load_en_address_keyword_groups",
    "load_en_address_country_aliases",
    "load_en_address_suffix_strippers",
    "load_en_given_names",
    "load_en_surnames",
    "load_en_us_states",
    "load_label_specs",
    "load_name_start_keywords",
    "load_negative_address_words",
    "load_negative_name_words",
    "load_negative_org_words",
    "load_negative_ui_words",
    "load_zh_address_keyword_groups",
    "load_zh_control_values",
    "load_zh_address_suffix_strippers",
    "load_zh_country_prefix_aliases",
    "load_zh_name_rules",
]
