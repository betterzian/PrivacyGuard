"""统一 PII 归一与实体判定。"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import NormalizedPII
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_company_suffixes,
    load_en_address_suffix_strippers,
    load_zh_address_suffix_strippers,
)
from privacyguard.utils.pii_value import parse_name_components

_NAME_COMPONENT_KEYS = ("full", "family", "given", "alias", "middle")
_ADDRESS_COMPONENT_KEYS = (
    "province",
    "city",
    "district",
    "street_admin",
    "town",
    "village",
    "road",
    "compound",
    "building",
    "unit",
    "floor",
    "room",
    "postal_code",
)
_ADDRESS_MATCH_KEYS = ("province", "city", "district", "street_admin", "town", "village", "road", "compound")
_ADDRESS_DETAIL_KEYS = ("building", "unit", "floor", "room")
_LOCAL_ADMIN_KEYS = ("street_admin", "town", "village")
_ADDRESS_COMPONENT_ALIASES = {"street": "road", "state": "province"}
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
    normalized_components = {
        key: str(raw_components.get(key) or "").strip()
        for key in _ADDRESS_COMPONENT_KEYS
        if str(raw_components.get(key) or "").strip()
    }
    canonical_parts = []
    identity: dict[str, str] = {}
    address_part_values: list[str] = []
    for key in _ADDRESS_COMPONENT_KEYS:
        value = normalized_components.get(key)
        if not value:
            continue
        normalized_value = _compact_component_text(value)
        if not normalized_value:
            continue
        canonical_parts.append(f"{key}={normalized_value}")
        identity[key] = normalized_value
        if key in _ADDRESS_MATCH_KEYS:
            address_part_values.append(normalized_value)
    numbers = _address_numbers(raw_text=raw_text, metadata=metadata, normalized_components=normalized_components)
    details_tokens = _address_detail_tokens(normalized_components)
    if address_part_values:
        identity["address_part"] = "|".join(address_part_values)
    if numbers:
        identity["number"] = ",".join(numbers)
        canonical_parts.append(f"number=[{','.join(numbers)}]")
    if details_tokens:
        # 仍保留 details_part 作为展示/调试信息，但同实体判定不再依赖它。
        identity["details_part"] = "-".join(details_tokens)
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
    for key in ("province", "city", "district"):
        if not _shared_component_subset(left.identity, right.identity, key):
            return False
    if not _local_admin_group_matches(left.identity, right.identity):
        return False
    for key in ("road", "compound"):
        if not _shared_component_subset(left.identity, right.identity, key):
            return False
    if not _numbers_match(left.numbers, right.numbers):
        return False
    if not left.identity.get("address_part") or not right.identity.get("address_part"):
        return False
    return True


def _numbers_match(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """号码序列判定：从末尾往前做逆序一致的子序列匹配，且至少命中 2 个 token。"""
    if not left or not right:
        return False
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    # 逆序对齐：shorter[::-1] 必须是 longer[::-1] 的子序列。
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


def _shared_component_subset(left: Mapping[str, str], right: Mapping[str, str], key: str) -> bool:
    left_value = left.get(key, "")
    right_value = right.get(key, "")
    if not left_value or not right_value:
        return True
    shorter, longer = sorted((left_value, right_value), key=len)
    return shorter in longer


def _local_admin_group_matches(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    left_values = [left.get(key, "") for key in _LOCAL_ADMIN_KEYS if left.get(key, "")]
    right_values = [right.get(key, "") for key in _LOCAL_ADMIN_KEYS if right.get(key, "")]
    if not left_values or not right_values:
        return True
    for left_value in left_values:
        for right_value in right_values:
            shorter, longer = sorted((left_value, right_value), key=len)
            if shorter in longer:
                return True
    return False


def _is_detail_subsequence(left: str, right: str) -> bool:
    left_tokens = left.split("-") if left else []
    right_tokens = right.split("-") if right else []
    shorter, longer = (left_tokens, right_tokens) if len(left_tokens) <= len(right_tokens) else (right_tokens, left_tokens)
    if not shorter:
        return True
    pointer = 0
    for token in longer:
        if pointer < len(shorter) and token == shorter[pointer]:
            pointer += 1
    return pointer == len(shorter)


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
                if comp_type in {"building", "unit", "floor", "room", "number"}:
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
        return {
            key: str(value).strip()
            for key, value in components.items()
            if key in _ADDRESS_COMPONENT_KEYS and str(value or "").strip()
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
    resolved: dict[str, str] = {}
    for item in traces:
        if ":" not in item:
            continue
        component_type, value = item.split(":", 1)
        key = _ADDRESS_COMPONENT_ALIASES.get(component_type.strip(), component_type.strip())
        normalized_value = value.strip()
        if key not in _ADDRESS_COMPONENT_KEYS or not normalized_value:
            continue
        previous = resolved.get(key, "")
        if len(normalized_value) > len(previous):
            resolved[key] = normalized_value
    return resolved


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
    "NormalizedPII",
    "build_match_terms",
    "normalize_pii",
    "normalized_primary_text",
    "render_address_text",
    "same_entity",
]
