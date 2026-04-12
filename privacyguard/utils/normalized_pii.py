"""统一 PII 归一与实体判定。"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import (
    NormalizedAddressComponent,
    NormalizedAddressSuspectEntry,
    NormalizedPII,
)
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_company_suffixes,
    load_en_address_country_aliases,
    load_en_address_suffix_strippers,
    load_en_us_states,
    load_zh_address_suffix_strippers,
)
from privacyguard.utils.pii_value import parse_name_components

_NAME_COMPONENT_KEYS = ("full", "family", "given", "alias", "middle")
_ADDRESS_COMPONENT_KEYS = (
    "country",
    "province",
    "city",
    "district",
    "subdistrict",
    "road",
    "house_number",
    "number",
    "poi",
    "building",
    "detail",
    "postal_code",
)
_ADDRESS_MATCH_KEYS = ("province", "city", "district", "subdistrict", "road", "poi")
_ADDRESS_DETAIL_KEYS = ("building", "detail")
_ADDRESS_COMPONENT_COMPARE_KEYS = ("province", "city", "district", "road", "subdistrict")
_ORDERED_COMPONENT_KEYS = (
    "country",
    "province",
    "city",
    "district",
    "road",
    "house_number",
    "number",
    "subdistrict",
    "poi",
    "building",
    "detail",
    "postal_code",
)
# 与 trace 对齐的 POI 终端 key（仅用于 same_entity 比较时剥末尾 key），可选。
_ADDRESS_OPTIONAL_KEYS = frozenset({"poi_key"})
# 旧类型到新类型的别名映射，兼容历史 trace 数据。
_ADDRESS_COMPONENT_ALIASES = {
    "street": "road",
    "state": "province",
    "compound": "poi",
    "street_admin": "subdistrict",
    "town": "subdistrict",
    "village": "subdistrict",
    "unit": "detail",
    "floor": "detail",
    "room": "detail",
    "street_number": "number",
    "zip": "postal_code",
    "zipcode": "postal_code",
    "postal": "postal_code",
    "country_region": "country",
}
_PUNCT_TRIM_RE = re.compile(r"[\s\-_.,，。:：;；/\\|()（）【】\[\]#]+")
_DIGIT_RE = re.compile(r"\d+")
_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z][A-Za-z .,'\-]{0,80}$")
_ZH_NUMERAL_CHARS = set("零〇一二三四五六七八九十百千两")


def normalize_pii(
    attr_type: PIIAttributeType,
    raw_text: str,
    *,
    metadata: Mapping[str, object] | None = None,
    components: Mapping[str, str | None] | None = None,
) -> NormalizedPII:
    """统一归一入口。"""
    normalized_raw = str(raw_text or "")
    if attr_type == PIIAttributeType.NAME:
        return _normalize_name(raw_text=normalized_raw, metadata=metadata, components=components)
    if attr_type == PIIAttributeType.ADDRESS:
        return _normalize_address(raw_text=normalized_raw, metadata=metadata, components=components)
    if attr_type == PIIAttributeType.EMAIL:
        canonical = re.sub(r"\s+", "", normalized_raw).lower()
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.ORGANIZATION:
        canonical = _organization_canonical(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {
        PIIAttributeType.PHONE,
        PIIAttributeType.BANK_NUMBER,
        PIIAttributeType.ID_NUMBER,
    }:
        canonical = _digits_only(normalized_raw)
        if attr_type == PIIAttributeType.PHONE:
            canonical = _normalize_phone_digits(canonical)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type in {PIIAttributeType.PASSPORT_NUMBER, PIIAttributeType.DRIVER_LICENSE, PIIAttributeType.ALNUM}:
        canonical = _alnum_only(normalized_raw).upper()
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.TIME:
        canonical = _compact_component_text(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    if attr_type == PIIAttributeType.DETAILS:
        canonical = _compact_component_text(normalized_raw)
        return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)
    canonical = _compact_component_text(normalized_raw)
    return _scalar_normalized(attr_type=attr_type, raw_text=normalized_raw, canonical=canonical)


def same_entity(left: NormalizedPII | None, right: NormalizedPII | None) -> bool:
    """判断两个归一结果是否为同一实体。"""
    if left is None or right is None or left.attr_type != right.attr_type:
        return False
    if left.attr_type == PIIAttributeType.NAME:
        return _same_name(left, right)
    if left.attr_type == PIIAttributeType.ORGANIZATION:
        return _same_organization(left, right)
    if left.attr_type == PIIAttributeType.ADDRESS:
        return _same_address(left, right)
    return bool(left.canonical and left.canonical == right.canonical)


def normalized_primary_text(normalized: NormalizedPII | None) -> str:
    """返回稳定主文本。"""
    if normalized is None:
        return ""
    return normalized.canonical or normalized.raw_text.strip()


def build_match_terms(normalized: NormalizedPII | None) -> tuple[str, ...]:
    """返回统一匹配关键词。"""
    if normalized is None:
        return ()
    return normalized.match_terms


def render_address_text(components: Mapping[str, str | None]) -> str:
    """按稳定顺序渲染结构化地址。"""
    ordered_values = [str(components.get(key) or "").strip() for key in _ADDRESS_COMPONENT_KEYS]
    return "".join(value for value in ordered_values if value)


def _scalar_normalized(attr_type: PIIAttributeType, raw_text: str, canonical: str) -> NormalizedPII:
    canonical_value = canonical.strip()
    match_terms = (canonical_value,) if canonical_value else ()
    identity = {"canonical": canonical_value} if canonical_value else {}
    return NormalizedPII(
        attr_type=attr_type,
        raw_text=raw_text,
        canonical=canonical_value,
        components={},
        match_terms=match_terms,
        identity=identity,
    )


def _normalize_name(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> NormalizedPII:
    name_components = _name_components(raw_text=raw_text, metadata=metadata, components=components)
    full_raw = name_components.get("full", raw_text)
    canonical = _name_canonical(full_raw)
    normalized_components = {
        key: value
        for key, value in ((key, str(name_components.get(key) or "").strip()) for key in _NAME_COMPONENT_KEYS)
        if value
    }
    match_terms = tuple(
        term
        for key in ("full", "family", "given", "alias")
        if (term := normalized_components.get(key))
    )
    identity = {}
    if normalized_components.get("family"):
        identity["family"] = _name_canonical(normalized_components["family"])
    if normalized_components.get("given"):
        identity["given"] = _name_canonical(normalized_components["given"])
    return NormalizedPII(
        attr_type=PIIAttributeType.NAME,
        raw_text=raw_text,
        canonical=canonical,
        components=normalized_components,
        match_terms=_dedupe_terms(match_terms),
        identity=identity,
    )


def _normalize_address(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> NormalizedPII:
    raw_components = _address_components(raw_text=raw_text, metadata=metadata, components=components)
    ordered_components = _address_ordered_components(metadata=metadata, components=components)
    normalized_components = {
        key: str(raw_components.get(key) or "").strip()
        for key in _ADDRESS_COMPONENT_KEYS
        if str(raw_components.get(key) or "").strip()
    }
    # POI 与「最后一个 key」成对来自 trace，不参与 canonical 拼接字段集合。
    if str(raw_components.get("poi_key") or "").strip():
        normalized_components["poi_key"] = str(raw_components["poi_key"]).strip()
    canonical_parts = []
    identity: dict[str, str] = {}
    address_part_values: list[str] = []
    for key in _ADDRESS_COMPONENT_KEYS:
        value = normalized_components.get(key)
        if not value:
            continue
        normalized_value = _canonicalize_address_component_value(key, value)
        if not normalized_value:
            continue
        canonical_parts.append(f"{key}={normalized_value}")
        identity[key] = normalized_value
        if key in _ADDRESS_MATCH_KEYS:
            address_part_values.append(normalized_value)
    numbers = _address_numbers(raw_text=raw_text, metadata=metadata, normalized_components=normalized_components)
    keyed_numbers = _extract_keyed_numbers(metadata)
    details_tokens = _address_detail_tokens(normalized_components)
    if address_part_values:
        identity["address_part"] = "|".join(address_part_values)
    if numbers:
        identity["number"] = ",".join(numbers)
        canonical_parts.append(f"number=[{','.join(numbers)}]")
    if details_tokens:
        identity["details_part"] = "-".join(details_tokens)
    if pk := normalized_components.get("poi_key"):
        identity["poi_key"] = pk
    match_terms = tuple(
        term
        for key in _ADDRESS_MATCH_KEYS
        if (value := normalized_components.get(key))
        if (term := _address_match_term(key, value))
    )
    return NormalizedPII(
        attr_type=PIIAttributeType.ADDRESS,
        raw_text=raw_text or render_address_text(normalized_components),
        canonical="|".join(canonical_parts),
        components=normalized_components,
        match_terms=_dedupe_terms(match_terms),
        identity=identity,
        numbers=tuple(numbers),
        keyed_numbers=keyed_numbers,
        ordered_components=ordered_components,
    )


def _address_match_term(component_key: str, component_value: str) -> str:
    """生成地址组件的匹配 term。

    仅用于 match_terms：去掉组件后缀类别词，让词典匹配更短更稳定。
    例如：city=上海市 -> 上海；district=浦东新区 -> 浦东；compound=阳光小区 -> 阳光。
    """
    value = str(component_value or "").strip()
    if not value:
        return ""
    # 英文地址：match_terms 保留原始大小写与后缀（如 “Harbor Ave”、“North Plaza”），避免过度截断。
    # 中文地址：为了词典匹配稳定性，仍做 suffix-only 裁剪（如 “上海市”->“上海”）。
    compact = _compact_component_text(value)
    if not compact:
        return ""
    if _looks_like_en_text(compact):
        return value
    # 用 scanner 词典派生的 suffix-only 裁剪器作为单一真源，确保 session/local 一致。
    strippers = load_zh_address_suffix_strippers()
    pattern = strippers.get(component_key)
    if pattern is None:
        return compact
    stripped = pattern.sub("", compact).strip()
    return stripped or compact


def _looks_like_en_text(text: str) -> bool:
    """粗略判断文本是否更像英文地址片段。"""
    return any(("A" <= ch <= "Z") or ("a" <= ch <= "z") for ch in text)


def _canonicalize_address_component_value(component_key: str, value: str) -> str:
    """按组件类型生成稳定 canonical。"""
    text = str(value or "").strip()
    if not text:
        return ""
    if component_key == "province":
        return _canonicalize_us_state(text) or _compact_component_text(text)
    if component_key == "country":
        return _canonicalize_en_country(text) or _compact_component_text(text)
    if component_key == "postal_code":
        return re.sub(r"[^0-9-]", "", unicodedata.normalize("NFKC", text))
    if component_key in {"house_number", "number"}:
        return _alnum_only(text).upper()
    return _compact_component_text(text)


def _canonicalize_us_state(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    state_map = load_en_us_states()
    upper = text.upper()
    if upper in state_map:
        return upper
    by_name = {name.lower(): code for code, name in state_map.items()}
    return by_name.get(text.lower(), "")


def _canonicalize_en_country(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    aliases = load_en_address_country_aliases()
    canonical = aliases.get(text.lower())
    if canonical and canonical.lower() == "united states":
        return "US"
    compact = _compact_component_text(text)
    if compact in {"us", "usa", "unitedstates", "unitedstatesofamerica"}:
        return "US"
    return ""

def _same_name(left: NormalizedPII, right: NormalizedPII) -> bool:
    left_given = left.identity.get("given", "")
    right_given = right.identity.get("given", "")
    if not left_given or not right_given:
        return False
    left_family = left.identity.get("family", "")
    right_family = right.identity.get("family", "")
    if left_family and right_family:
        return left_family == right_family and left_given == right_given
    return left_given == right_given


def _same_organization(left: NormalizedPII, right: NormalizedPII) -> bool:
    left_value = left.canonical
    right_value = right.canonical
    if not left_value or not right_value:
        return False
    shorter, longer = sorted((left_value, right_value), key=len)
    return shorter in longer


def _same_address(left: NormalizedPII, right: NormalizedPII) -> bool:
    """§6 canonical 比较顺序：province → city → district → road → numbers → subdistrict → poi。

    除任一步失败立即返回 False 外，要求「实质性成功匹配」占比：成功次数除以
    ``min(len(left.ordered_components), len(right.ordered_components))`` 必须 **严格大于** 0.3；
    单侧缺失而放行的层级不计入成功次数。分母为 0 时返回 False。
    """
    # 必须有实质地址信息。
    if not left.identity.get("address_part") or not right.identity.get("address_part"):
        return False

    substantive_hits = 0

    for key in ("country", "province", "house_number", "postal_code"):
        if not _identity_field_match_if_both_present(left, right, key):
            return False
        if left.identity.get(key) and right.identity.get(key):
            substantive_hits += 1

    # 单层级组件按组件自身的 suspected 比较，不再做地址级合并。
    for key in ("city", "district", "road", "poi", "building", "detail"):
        left_component = _ordered_component_by_type(left, key)
        right_component = _ordered_component_by_type(right, key)
        if left_component is None or right_component is None:
            if not _compare_component_with_suspected(left, right, key):
                return False
            continue
        if not _compare_component_with_suspected(left, right, key):
            return False
        substantive_hits += 1

    # numbers —— 逆序子序列 / keyed。
    if not _numbers_match(left.numbers, right.numbers,
                          left_keyed=left.keyed_numbers, right_keyed=right.keyed_numbers):
        return False
    if _numbers_substantive_pair(left, right):
        substantive_hits += 1

    left_sd = _ordered_component_by_type(left, "subdistrict")
    right_sd = _ordered_component_by_type(right, "subdistrict")
    if left_sd is None or right_sd is None:
        if not _compare_component_with_suspected(left, right, "subdistrict"):
            return False
    else:
        if not _compare_component_with_suspected(left, right, "subdistrict"):
            return False
        substantive_hits += 1

    # poi —— 列表双向子集（仅可去掉各 POI 的最后一个 key，不做任意后缀剥离）。
    if not _compare_poi_list(left, right):
        return False

    denom = min(len(left.ordered_components), len(right.ordered_components))
    if denom <= 0:
        return False
    return (substantive_hits / denom) > 0.3


def _identity_field_match_if_both_present(
    left: NormalizedPII,
    right: NormalizedPII,
    key: str,
) -> bool:
    left_value = str(left.identity.get(key) or "").strip()
    right_value = str(right.identity.get(key) or "").strip()
    if not left_value or not right_value:
        return True
    return left_value == right_value


def _numbers_substantive_pair(left: NormalizedPII, right: NormalizedPII) -> bool:
    """双方是否都带有可比的号码信息（纯数字序列或 keyed 之一非空）。"""
    left_has = bool(left.numbers) or bool(left.keyed_numbers)
    right_has = bool(right.numbers) or bool(right.keyed_numbers)
    return bool(left_has and right_has)


_MIN_POI_LEN = 2


def _compare_component_with_suspected(
    left: NormalizedPII, right: NormalizedPII, key: str,
) -> bool:
    """按组件自身 suspected 比较当前层级。"""
    left_component = _ordered_component_by_type(left, key)
    right_component = _ordered_component_by_type(right, key)
    if left_component is None or right_component is None:
        return True
    left_value = _component_value_text(left_component)
    right_value = _component_value_text(right_component)
    if not _admin_text_subset_either(left_value, right_value):
        return False
    if not _component_suspected_matches(left_component, right_component, right):
        return False
    if not _component_suspected_matches(right_component, left_component, left):
        return False
    return True


def _ordered_component_by_type(
    normalized: NormalizedPII,
    component_type: str,
) -> NormalizedAddressComponent | None:
    for component in normalized.ordered_components:
        if component.component_type == component_type:
            return component
    return None


def _component_value_text(component: NormalizedAddressComponent | None) -> str:
    if component is None:
        return ""
    if isinstance(component.value, tuple):
        return "|".join(str(item).strip() for item in component.value if str(item).strip())
    return str(component.value or "").strip()


def _suspect_entry_by_level(
    component: NormalizedAddressComponent | None,
    level: str,
) -> NormalizedAddressSuspectEntry | None:
    if component is None:
        return None
    for entry in component.suspected:
        if level in entry.levels:
            return entry
    return None


def _suspect_group_matches(
    entry: NormalizedAddressSuspectEntry,
    other_component: NormalizedAddressComponent,
    other_normalized: NormalizedPII,
) -> bool | None:
    """按三步顺序比较一个 suspect group。"""
    surface = f"{entry.value}{entry.key}".strip()
    other_value = _component_value_text(other_component)

    if surface and other_value and surface in other_value:
        return True

    for level in entry.levels:
        peer_suspected = _suspect_entry_by_level(other_component, level)
        if peer_suspected is not None:
            return peer_suspected.value.strip() == entry.value.strip()

    for level in entry.levels:
        other_level_component = _ordered_component_by_type(other_normalized, level)
        if other_level_component is None:
            continue
        other_level_value = _component_value_text(other_level_component)
        if not other_level_value:
            continue
        return other_level_value == entry.value.strip()

    return True


def _component_suspected_matches(
    component: NormalizedAddressComponent,
    other_component: NormalizedAddressComponent,
    other_normalized: NormalizedPII,
) -> bool:
    """逐组比较当前组件自己的 suspected。"""
    if not component.suspected:
        return True

    for entry in component.suspected:
        result = _suspect_group_matches(entry, other_component, other_normalized)
        if result is False:
            return False
    return True


def _admin_text_subset_either(a: str, b: str) -> bool:
    """行政片段子串互容（短串在长串内即可）。"""
    a, b = (a or "").strip(), (b or "").strip()
    if not a or not b:
        return False
    shorter, longer = sorted((a, b), key=len)
    return shorter in longer


def _compare_poi_list(left: NormalizedPII, right: NormalizedPII) -> bool:
    """POI 列表比较（§6.5）。

    每个 POI 仅允许去掉 trace 中的「最后一个 key」后再做子串 subset；不得去掉链上被穿透的中间 key。
    A×B 任一对满足 subset_either 即 PASS。
    """
    left_poi = left.identity.get("poi", "")
    right_poi = right.identity.get("poi", "")
    if not left_poi or not right_poi:
        return True
    left_items = [s.strip() for s in left_poi.split("|") if s.strip()]
    right_items = [s.strip() for s in right_poi.split("|") if s.strip()]
    if not left_items or not right_items:
        return True
    left_keys = [s.strip() for s in (left.identity.get("poi_key") or "").split("|")]
    right_keys = [s.strip() for s in (right.identity.get("poi_key") or "").split("|")]
    for i, a in enumerate(left_items):
        ak = left_keys[i] if i < len(left_keys) else ""
        a_cmp = _strip_terminal_poi_key(a, ak)
        for j, b in enumerate(right_items):
            bk = right_keys[j] if j < len(right_keys) else ""
            b_cmp = _strip_terminal_poi_key(b, bk)
            if _poi_subset_either(a_cmp, b_cmp) and min(len(a_cmp), len(b_cmp)) >= _MIN_POI_LEN:
                return True
    return False


def _strip_terminal_poi_key(value: str, terminal_key: str) -> str:
    """仅当 value 以「最后一个 key」结尾时去掉该后缀；不处理穿透在中间的文字。"""
    v = (value or "").strip()
    k = (terminal_key or "").strip()
    if not k or not v.endswith(k):
        return v
    return v[: -len(k)].strip() or v


def _poi_subset_either(a: str, b: str) -> bool:
    """POI 子集：纯子串互容，不做任意类别词后缀剥离。"""
    if not a or not b:
        return False
    shorter, longer = sorted((a, b), key=len)
    return shorter in longer


def _numbers_match(
    left: tuple[str, ...],
    right: tuple[str, ...],
    left_keyed: dict[str, str] | None = None,
    right_keyed: dict[str, str] | None = None,
) -> bool:
    """号码判定：优先 keyed 路径（共有 key 值相等），fallback 到逆序子序列匹配。"""
    # 路径 1: keyed 比对——仅比较双方共有的 key，值相等即通过。
    if left_keyed and right_keyed:
        common = left_keyed.keys() & right_keyed.keys()
        if common:
            return all(left_keyed[k] == right_keyed[k] for k in common)
    # 路径 2: fallback 到 numbers 逆序子序列匹配。
    return _numbers_sequence_match(left, right)


def _numbers_sequence_match(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """号码序列判定：从末尾往前做逆序一致的子序列匹配，且至少命中 2 个 token。"""
    if not left and not right:
        return True
    if not left or not right:
        return False
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    s = list(reversed(shorter))
    l = list(reversed(longer))
    pointer = 0
    matched = 0
    for token in l:
        if pointer < len(s) and token == s[pointer]:
            matched += 1
            pointer += 1
            if pointer == len(s):
                break
    if pointer != len(s):
        return False
    return matched >= 2


_KEYED_NUMBER_TYPES = {"building", "detail", "number"}


def _parse_one_component_suspected(segment: str) -> tuple[NormalizedAddressSuspectEntry, ...]:
    """解析单组件 suspected JSON 串。"""
    text = str(segment or "").strip()
    if not text:
        return ()
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(raw, list):
        return ()
    parsed: list[NormalizedAddressSuspectEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        raw_levels = item.get("levels")
        if not isinstance(raw_levels, (list, tuple)):
            continue
        levels = tuple(
            str(level or "").strip()
            for level in raw_levels
            if str(level or "").strip()
        )
        value = str(item.get("value") or "").strip()
        key = str(item.get("key") or "").strip()
        origin = str(item.get("origin") or "").strip()
        if not levels or not value or origin not in {"value", "key"}:
            continue
        parsed.append(NormalizedAddressSuspectEntry(
            levels=levels,
            value=value,
            key=key,
            origin=origin,
        ))
    return tuple(parsed)


def _component_suspected_tuple_from_metadata(
    metadata: Mapping[str, object] | None,
) -> tuple[tuple[NormalizedAddressSuspectEntry, ...], ...]:
    """从 address_component_suspected 列表解析，顺序与 detector 组件顺序一致。"""
    if not metadata:
        return ()
    raw = metadata.get("address_component_suspected")
    if not isinstance(raw, list):
        return ()
    return tuple(_parse_one_component_suspected(str(item or "")) for item in raw)


def _address_ordered_components(
    *,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> tuple[NormalizedAddressComponent, ...]:
    """构造地址组件级归一结果。"""
    if components:
        return _ordered_components_from_direct_components(components)
    return _ordered_components_from_metadata(metadata)


def _ordered_components_from_direct_components(
    components: Mapping[str, str | None],
) -> tuple[NormalizedAddressComponent, ...]:
    """结构化 components 直传时，按固定层级顺序生成组件。"""
    ordered: list[NormalizedAddressComponent] = []
    poi_key_raw = str(components.get("poi_key") or "").strip()
    poi_keys = tuple(part.strip() for part in poi_key_raw.split("|") if part.strip())
    for component_type in _ORDERED_COMPONENT_KEYS:
        raw_value = str(components.get(component_type) or "").strip()
        if not raw_value:
            continue
        if component_type == "poi":
            values = tuple(part.strip() for part in raw_value.split("|") if part.strip())
            if not values:
                continue
            value: str | tuple[str, ...] = values[0] if len(values) == 1 else values
            key: str | tuple[str, ...]
            if not poi_keys:
                key = ""
            elif len(poi_keys) == 1:
                key = poi_keys[0]
            else:
                key = poi_keys
        else:
            value = raw_value
            key = ""
        ordered.append(NormalizedAddressComponent(
            component_type=component_type,
            value=value,
            key=key,
            suspected=(),
        ))
    return tuple(ordered)


def _ordered_components_from_metadata(
    metadata: Mapping[str, object] | None,
) -> tuple[NormalizedAddressComponent, ...]:
    """从 detector metadata 重建组件顺序与组件级 suspected。"""
    trace_entries = _parse_address_trace_entries(_metadata_values(metadata, "address_component_trace"))
    if not trace_entries:
        return ()
    key_entries = _parse_address_trace_entries(_metadata_values(metadata, "address_component_key_trace"))
    suspected_entries = _component_suspected_tuple_from_metadata(metadata)

    ordered: list[NormalizedAddressComponent] = []
    trace_index = 0
    key_index = 0
    component_index = 0

    while trace_index < len(trace_entries):
        component_type, value = trace_entries[trace_index]
        suspected = suspected_entries[component_index] if component_index < len(suspected_entries) else ()
        component_index += 1

        if component_type == "poi":
            values = [value]
            trace_index += 1
            while trace_index < len(trace_entries) and trace_entries[trace_index][0] == "poi":
                values.append(trace_entries[trace_index][1])
                trace_index += 1
            keys: list[str] = []
            while key_index < len(key_entries) and key_entries[key_index][0] == "poi" and len(keys) < len(values):
                keys.append(key_entries[key_index][1])
                key_index += 1
            ordered.append(NormalizedAddressComponent(
                component_type="poi",
                value=tuple(values) if len(values) > 1 else values[0],
                key=tuple(keys) if len(keys) > 1 else (keys[0] if keys else ""),
                suspected=tuple(suspected),
            ))
            continue

        key_value = ""
        if key_index < len(key_entries) and key_entries[key_index][0] == component_type:
            key_value = key_entries[key_index][1]
            key_index += 1
        ordered.append(NormalizedAddressComponent(
            component_type=component_type,
            value=value,
            key=key_value,
            suspected=tuple(suspected),
        ))
        trace_index += 1

    return tuple(ordered)


def _parse_address_trace_entries(items: tuple[str, ...]) -> list[tuple[str, str]]:
    """把 trace 列表解析成标准化的组件项。"""
    entries: list[tuple[str, str]] = []
    for item in items:
        if ":" not in item:
            continue
        raw_type, raw_value = item.split(":", 1)
        component_type = _ADDRESS_COMPONENT_ALIASES.get(raw_type.strip(), raw_type.strip())
        value = raw_value.strip()
        if component_type in _ADDRESS_COMPONENT_KEYS and value:
            entries.append((component_type, value))
    return entries


def _extract_keyed_numbers(metadata: Mapping[str, object] | None) -> dict[str, str]:
    """从 address_component_trace + address_component_key_trace 提取有明确 key 的数字。"""
    if not metadata:
        return {}
    trace = metadata.get("address_component_trace")
    key_trace = metadata.get("address_component_key_trace")
    if not isinstance(trace, list) or not isinstance(key_trace, list):
        return {}
    # 收集 key_trace 中出现过的 component_type（有 key 意味着有明确关键字标记）。
    key_set: set[str] = set()
    for entry in key_trace:
        if isinstance(entry, str) and ":" in entry:
            ct, _ = entry.split(":", 1)
            key_set.add(ct.strip())
    keyed: dict[str, str] = {}
    for entry in trace:
        if not isinstance(entry, str) or ":" not in entry:
            continue
        ct, val = entry.split(":", 1)
        ct = ct.strip()
        if ct in _KEYED_NUMBER_TYPES and ct in key_set:
            keyed[ct] = val.strip()
    return keyed


def _address_numbers(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    normalized_components: Mapping[str, str],
) -> list[str]:
    """按地址从左到右出现顺序提取号码序列。"""
    del raw_text
    tokens: list[str] = []
    # 优先使用 addressstack 的 trace（天然保持组件生成顺序）。
    if metadata:
        trace = metadata.get("address_component_trace")
        if isinstance(trace, list):
            for item in trace:
                if not isinstance(item, str) or ":" not in item:
                    continue
                comp_type, value = item.split(":", 1)
                comp_type = comp_type.strip()
                value = value.strip()
                if comp_type in {"building", "detail", "number"}:
                    tokens.extend(_extract_number_tokens(value))
            return [t for t in tokens if t]
    # fallback：无 trace 时按 detail keys 顺序提取（仅用于 components 直传场景）。
    for key in _ADDRESS_DETAIL_KEYS:
        if value := str(normalized_components.get(key) or "").strip():
            tokens.extend(_extract_number_tokens(value))
    return [t for t in tokens if t]


def _extract_number_tokens(value: str) -> list[str]:
    """从 value 中抽取数字或字母 token。"""
    text = str(value or "").strip()
    if not text:
        return []
    # 若包含中文数字且不含阿拉伯数字，尝试整体转为阿拉伯数字。
    if any(ch in _ZH_NUMERAL_CHARS for ch in text) and not any(ch.isdigit() for ch in text):
        parsed = _parse_zh_numeral(text)
        if parsed is not None:
            return [str(parsed)]
    # 其它情况：抽取连续字母/数字段（如 “10A”、“B座”->“B”）。
    raw_tokens = [m.group(0) for m in re.finditer(r"[A-Za-z0-9]+", text)]
    if not raw_tokens:
        return []
    # 过滤：优先保留含数字的 token（7B/1203/10），丢弃 “Apt/Floor/Room” 这类纯字母描述词。
    keep: list[str] = [t for t in raw_tokens if any(ch.isdigit() for ch in t)]
    if keep:
        return keep
    # 若没有数字，允许单字母（如 “A座”->“A”），避免把长英文单词误当作号码。
    return [t for t in raw_tokens if len(t) == 1 and t.isalpha()]


def _parse_zh_numeral(text: str) -> int | None:
    """把常见中文数字（<=9999）转成 int。只处理纯数字表达，失败返回 None。"""
    s = str(text or "").strip()
    if not s:
        return None
    s = s.replace("〇", "零")
    if any(ch not in _ZH_NUMERAL_CHARS for ch in s):
        return None
    digit_map = {"零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
    unit_map = {"十": 10, "百": 100, "千": 1000}
    total = 0
    num = 0
    unit = 1
    # 从右向左解析（适配“二百零一”“十二”“十”等）。
    for ch in reversed(s):
        if ch in digit_map:
            num += digit_map[ch] * unit
        elif ch in unit_map:
            u = unit_map[ch]
            if u > unit:
                unit = u
            else:
                # 不规范写法，放弃。
                return None
            if num == 0:
                # “十/百/千”前省略“一”
                num = 1 * unit
                unit = 1
                total += num
                num = 0
                unit = 1
        else:
            return None
    total += num
    if total <= 0:
        return None
    if total > 9999:
        return None
    return total


def _name_components(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> dict[str, str]:
    if components:
        return {
            key: str(value).strip()
            for key, value in components.items()
            if key in _NAME_COMPONENT_KEYS and str(value or "").strip()
        }
    parsed = parse_name_components(raw_text)
    resolved = {
        "full": parsed.full_text or parsed.original_text or raw_text,
        "family": parsed.family_text or "",
        "given": parsed.given_text or "",
        "middle": parsed.middle_text or "",
    }
    component_values = _metadata_values(metadata, "name_component")
    if "alias" in component_values:
        resolved["alias"] = raw_text.strip()
    return {key: value for key, value in resolved.items() if value}


def _address_components(
    *,
    raw_text: str,
    metadata: Mapping[str, object] | None,
    components: Mapping[str, str | None] | None,
) -> dict[str, str]:
    if components:
        allowed = frozenset(_ADDRESS_COMPONENT_KEYS) | _ADDRESS_OPTIONAL_KEYS
        return {
            key: str(value).strip()
            for key, value in components.items()
            if key in allowed and str(value or "").strip()
        }
    traced = _components_from_address_metadata(metadata)
    if traced:
        return traced
    raise ValueError(
        "normalize_pii(ADDRESS) 不再支持从 raw_text 进行内部正则兜底抽取；"
        "请提供结构化 components，或提供来自 detector/addressstack 的 metadata（含 address_component_trace）。"
    )


def _components_from_address_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    traces = _metadata_values(metadata, "address_component_trace")
    key_traces = _metadata_values(metadata, "address_component_key_trace")
    resolved: dict[str, str] = {}
    poi_vals_order: list[str] = []
    poi_keys_order: list[str] = []
    for item in key_traces:
        if ":" not in item:
            continue
        ct, kpart = item.split(":", 1)
        ck = _ADDRESS_COMPONENT_ALIASES.get(ct.strip(), ct.strip())
        if ck != "poi":
            continue
        kk = kpart.strip()
        if kk:
            poi_keys_order.append(kk)
    for item in traces:
        if ":" not in item:
            continue
        component_type, value = item.split(":", 1)
        key = _ADDRESS_COMPONENT_ALIASES.get(component_type.strip(), component_type.strip())
        normalized_value = value.strip()
        if key not in _ADDRESS_COMPONENT_KEYS or not normalized_value:
            continue
        if key == "poi":
            poi_vals_order.append(normalized_value)
            continue
        previous = resolved.get(key, "")
        if len(normalized_value) > len(previous):
            resolved[key] = normalized_value
    if poi_vals_order:
        poi_pairs = [
            (v, poi_keys_order[i] if i < len(poi_keys_order) else "")
            for i, v in enumerate(poi_vals_order)
        ]
        deduped = _dedupe_poi_pairs(poi_pairs)
        resolved["poi"] = "|".join(p[0] for p in deduped)
        resolved["poi_key"] = "|".join(p[1] for p in deduped)
    return resolved


def _dedupe_poi_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """POI 列表去重：被更长 value 包含的短 value 剔除，与 trace 中最后一个 key 成对保留。"""
    if not pairs:
        return []
    val_to_key: dict[str, str] = {}
    for v, k in pairs:
        val_to_key.setdefault(v, k)
    sorted_vals = sorted({p[0] for p in pairs}, key=len, reverse=True)
    kept_vals: list[str] = []
    for v in sorted_vals:
        if not any(v in kept and v != kept for kept in kept_vals):
            kept_vals.append(v)
    return [(v, val_to_key.get(v, "")) for v in kept_vals]


def _dedupe_poi_values(values: list[str]) -> list[str]:
    """POI 列表去重：被更长值包含的短值剔除。"""
    pairs = [(v, "") for v in values]
    return [p[0] for p in _dedupe_poi_pairs(pairs)]


def _metadata_values(metadata: Mapping[str, object] | None, key: str) -> tuple[str, ...]:
    if metadata is None:
        return ()
    raw = metadata.get(key)
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw.strip(),) if raw.strip() else ()
    if isinstance(raw, Iterable):
        values: list[str] = []
        for item in raw:
            text = str(item or "").strip()
            if text:
                values.append(text)
        return tuple(values)
    text = str(raw).strip()
    return (text,) if text else ()


def _normalize_phone_digits(digits: str) -> str:
    if len(digits) == 13 and digits.startswith("86") and re.fullmatch(r"1[3-9]\d{9}", digits[2:]):
        return digits[2:]
    if len(digits) == 11 and digits.startswith("1") and re.fullmatch(r"[2-9]\d{9}", digits[1:]):
        return digits[1:]
    return digits


def _organization_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    changed = True
    while changed:
        changed = False
        for suffix in load_company_suffixes():
            if text.lower().endswith(suffix.lower()) and len(text) > len(suffix):
                text = text[: -len(suffix)].rstrip()
                changed = True
                break
    return _compact_component_text(text)


def _name_canonical(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    if _NAME_COMPONENT_RE.fullmatch(text):
        return re.sub(r"\s+", " ", text).strip().lower()
    return "".join(char for char in re.sub(r"\s+", "", text) if char not in "·•・")


def _address_detail_tokens(components: Mapping[str, str]) -> list[str]:
    tokens: list[str] = []
    for key in _ADDRESS_DETAIL_KEYS:
        value = str(components.get(key) or "").strip()
        if not value:
            continue
        digits = _DIGIT_RE.findall(value)
        if digits:
            tokens.append(digits[-1])
    return tokens


def _digits_only(value: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", value or "") if char.isdigit())


def _alnum_only(value: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", value or "") if char.isalnum())


def _compact_component_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    text = _PUNCT_TRIM_RE.sub("", text)
    return text.lower() if any(char.isascii() and char.isalpha() for char in text) else text


def _dedupe_terms(terms: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    for item in terms:
        text = str(item or "").strip()
        if text and text not in ordered:
            ordered.append(text)
    return tuple(ordered)


__all__ = [
    "NormalizedAddressComponent",
    "NormalizedPII",
    "build_match_terms",
    "normalize_pii",
    "normalized_primary_text",
    "render_address_text",
    "same_entity",
]
