"""Scanner 词典数据加载。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.lexicon_store import read_scanner_lexicon_json
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, LabelSpec, NameComponentHint


@dataclass(frozen=True, slots=True)
class AddressKeywordGroup:
    component_type: AddressComponentType
    keywords: tuple[str, ...]


def _read_json(filename: str) -> object:
    return read_scanner_lexicon_json(filename)


def _clean_str_list(values: object) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise ValueError("词典文件格式错误：应为字符串数组。")
    return tuple(str(item).strip() for item in values if str(item).strip())


def _parse_component_type(raw_value: object) -> AddressComponentType:
    return AddressComponentType(str(raw_value).strip())


def _parse_component_hint(raw_value: object) -> NameComponentHint | None:
    if raw_value is None or str(raw_value).strip() == "":
        return None
    return NameComponentHint(str(raw_value).strip())


@lru_cache(maxsize=1)
def load_label_specs() -> tuple[LabelSpec, ...]:
    payload = _read_json("labels.json")
    if not isinstance(payload, list):
        raise ValueError("labels.json 格式错误：根节点应为数组。")
    items: list[LabelSpec] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError("labels.json 格式错误：条目应为对象。")
        keyword = str(entry.get("keyword", "")).strip()
        if not keyword:
            continue
        items.append(
            LabelSpec(
                keyword=keyword,
                attr_type=PIIAttributeType(str(entry.get("attr_type", "")).strip()),
                priority=int(entry.get("priority", 0)),
                source_kind=str(entry.get("source_kind", "")).strip(),
                ocr_source_kind=str(entry.get("ocr_source_kind", "")).strip(),
                component_hint=_parse_component_hint(entry.get("component_hint")),
                ascii_boundary=bool(entry.get("ascii_boundary", False)),
            )
        )
    return tuple(items)


@lru_cache(maxsize=1)
def load_name_start_keywords() -> tuple[str, ...]:
    return _clean_str_list(_read_json("name_starts.json"))


@lru_cache(maxsize=1)
def load_family_names() -> tuple[str, ...]:
    payload = _clean_str_list(_read_json("family_names.json"))
    return tuple(sorted(set(payload), key=len, reverse=True))


@lru_cache(maxsize=1)
def load_company_suffixes() -> tuple[str, ...]:
    return tuple(sorted(set(_clean_str_list(_read_json("company_suffixes.json"))), key=len, reverse=True))


def _load_address_groups(filename: str) -> tuple[AddressKeywordGroup, ...]:
    payload = _read_json(filename)
    if not isinstance(payload, list):
        raise ValueError(f"{filename} 格式错误：根节点应为数组。")
    groups: list[AddressKeywordGroup] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError(f"{filename} 格式错误：条目应为对象。")
        keywords = tuple(sorted(set(_clean_str_list(entry.get('keywords', []))), key=len, reverse=True))
        if not keywords:
            continue
        groups.append(
            AddressKeywordGroup(
                component_type=_parse_component_type(entry.get("component_type")),
                keywords=keywords,
            )
        )
    return tuple(groups)


@lru_cache(maxsize=1)
def load_zh_address_keyword_groups() -> tuple[AddressKeywordGroup, ...]:
    return _load_address_groups("zh_address_keywords.json")


@lru_cache(maxsize=1)
def load_en_address_keyword_groups() -> tuple[AddressKeywordGroup, ...]:
    return _load_address_groups("en_address_keywords.json")


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
def load_zh_given_names() -> tuple[str, ...]:
    """加载中文名字（given name）词典，按长度降序排列。"""
    payload = _clean_str_list(_read_json("zh_given_names.json"))
    return tuple(sorted(set(payload), key=len, reverse=True))


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
    "AddressKeywordGroup",
    "load_all_negative_words",
    "load_company_suffixes",
    "load_en_address_keyword_groups",
    "load_en_given_names",
    "load_en_surnames",
    "load_family_names",
    "load_label_specs",
    "load_name_start_keywords",
    "load_negative_address_words",
    "load_negative_name_words",
    "load_negative_org_words",
    "load_negative_ui_words",
    "load_zh_address_keyword_groups",
    "load_zh_given_names",
]
