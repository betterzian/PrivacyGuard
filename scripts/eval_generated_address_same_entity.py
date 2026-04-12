"""评测生成地址在 detector 与 AndLab_protected 中的地址-only 同址变体识别表现。"""

from __future__ import annotations

import csv
import json
import random
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_keyword_groups,
    load_en_address_suffix_strippers,
    load_zh_address_suffix_strippers,
)
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils.normalized_pii import same_entity as same_entity_fn


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "outputs" / "analysis"
ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"

sys.path.insert(0, str(ANDLAB_ROOT))

from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore  # noqa: E402


SEED = 20260412
SAMPLE_SIZE_PER_LOCALE = 60
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")
ALNUM_RE = re.compile(r"[A-Za-z0-9]+")
DIGIT_RE = re.compile(r"\d+")
ZIP_RE = re.compile(r"^\d{5}$")
COMPONENT_KEYS = (
    "province",
    "city",
    "district",
    "subdistrict",
    "road",
    "number",
    "poi",
    "building",
    "detail",
)
ComponentValue = str | list[str]

ZH_SUFFIX_STRIPPERS = load_zh_address_suffix_strippers()
EN_SUFFIX_STRIPPERS = load_en_address_suffix_strippers()
EN_SUFFIX_KEYWORDS: dict[str, list[str]] = defaultdict(list)

for group in load_en_address_keyword_groups():
    key = group.component_type.value
    keywords = [str(keyword or "").strip().lower() for keyword in group.keywords if str(keyword or "").strip()]
    EN_SUFFIX_KEYWORDS[key].extend(sorted(keywords, key=len, reverse=True))

EN_ROAD_ABBREVIATIONS = {
    "street": "St",
    "avenue": "Ave",
    "road": "Rd",
    "lane": "Ln",
    "drive": "Dr",
    "boulevard": "Blvd",
    "parkway": "Pkwy",
    "terrace": "Ter",
    "circle": "Cir",
    "place": "Pl",
}
EN_BUILDING_ABBREVIATIONS = {
    "building": "Bldg",
    "tower": "Twr",
    "block": "Blk",
}


@dataclass(slots=True)
class AndLabRunResult:
    masked_text: str
    occurrences: list[dict[str, Any]]
    error: str | None = None


class AndLabEvaluator:
    """复用一套映射状态，单次评测时按需清空。"""

    def __init__(self) -> None:
        self.layer = PrivacyProtectionLayer(enabled=True)

    def run_prompt(self, text: str, *, clear: bool) -> AndLabRunResult:
        if clear:
            self.layer.clear_mappings()
        try:
            masked_text, _ = self.layer.anonymize_prompt(text)
        except Exception as exc:  # noqa: BLE001
            return AndLabRunResult(masked_text="", occurrences=[], error=f"{type(exc).__name__}: {exc}")

        occurrences: list[dict[str, Any]] = []
        for match in TOKEN_RE.finditer(masked_text):
            token = match.group(1)
            real_value = self.layer.token_to_real.get(token)
            if not real_value:
                continue
            label = self.layer.real_to_entity_type.get(real_value, "MISC")
            occurrences.append(
                {
                    "token": token,
                    "label": label,
                    "text": real_value,
                    "start": match.start(),
                    "end": match.end(),
                }
            )
        return AndLabRunResult(masked_text=masked_text, occurrences=occurrences)


def _normalize_en_text(text: str) -> str:
    """压实英文空白，只保留正常单词间空格。"""
    normalized = re.sub(r"\s+", " ", str(text or "").strip())
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    return normalized.strip()


def _compact_text(text: str) -> str:
    return re.sub(r"[\s,，。;；:：/\\|()（）【】\[\]#._-]+", "", str(text or "")).strip()


def _extract_number_tokens(value: str) -> list[str]:
    """把 detail/building/number 文本拆成顺序 token，规则与 numbers 展示保持一致。"""
    text = str(value or "").strip()
    if not text:
        return []
    raw_tokens = [match.group(0).upper() for match in ALNUM_RE.finditer(text)]
    if not raw_tokens:
        return []
    with_digits = [token for token in raw_tokens if any(ch.isdigit() for ch in token)]
    if with_digits:
        return with_digits
    return [token for token in raw_tokens if len(token) == 1 and token.isalpha()]


def _normalize_component_value(component_key: str, value: str, locale: str) -> ComponentValue:
    raw = str(value or "").strip()
    if not raw:
        return [] if component_key == "detail" else ""
    if component_key == "number":
        return "".join(ch for ch in raw if ch.isdigit())
    if component_key == "detail":
        return _extract_number_tokens(raw)
    if locale == "zh_cn" and component_key in {"building", "detail"}:
        alnum = "".join(ALNUM_RE.findall(raw)).upper()
        if any(ch.isalpha() for ch in alnum):
            return alnum
        digits = "".join(DIGIT_RE.findall(raw))
        return digits
    compact = _compact_text(raw)
    if not compact:
        return ""
    if locale == "zh_cn":
        pattern = ZH_SUFFIX_STRIPPERS.get(component_key)
        if pattern is None:
            return compact
        stripped = pattern.sub("", compact).strip()
        return stripped or compact
    lowered = compact.lower()
    if component_key == "province":
        return lowered.upper()
    if component_key in {"road", "poi", "building"}:
        for suffix in EN_SUFFIX_KEYWORDS.get(component_key, []):
            if lowered.endswith(suffix) and len(lowered) > len(suffix):
                stem = compact[: len(compact) - len(suffix)]
                if component_key == "building":
                    normalized_stem = "".join(ALNUM_RE.findall(stem)).upper()
                    return normalized_stem or compact.upper()
                return _compact_text(stem).upper()
    return compact.upper()


def _component_match(expected: ComponentValue, actual: ComponentValue) -> tuple[bool, bool]:
    if isinstance(expected, list) or isinstance(actual, list):
        expected_list = [str(item).strip() for item in expected] if isinstance(expected, list) else []
        actual_list = [str(item).strip() for item in actual] if isinstance(actual, list) else []
        if not expected_list or not actual_list:
            return False, False
        if expected_list == actual_list:
            return True, True
        shorter, longer = (
            (expected_list, actual_list)
            if len(expected_list) <= len(actual_list)
            else (actual_list, expected_list)
        )
        pointer = 0
        for token in longer:
            if pointer < len(shorter) and token == shorter[pointer]:
                pointer += 1
                if pointer == len(shorter):
                    break
        return False, pointer == len(shorter)
    if not expected or not actual:
        return False, False
    if expected == actual:
        return True, True
    return False, expected in actual or actual in expected


def _candidate_detail_tokens(candidate) -> list[str]:
    normalized = candidate.normalized_source
    if normalized is None:
        return []
    tokens: list[str] = []
    for component in normalized.ordered_components:
        if component.component_type != "detail":
            continue
        values = component.value if isinstance(component.value, tuple) else (component.value,)
        for value in values:
            tokens.extend(_extract_number_tokens(str(value)))
    if tokens:
        return tokens
    return _extract_number_tokens(str(normalized.components.get("detail", "")))


def _candidate_metric_components(candidate, locale: str) -> dict[str, ComponentValue]:
    normalized = candidate.normalized_source
    if normalized is None:
        return {}
    components = {
        key: _normalize_component_value(key, value, locale)
        for key, value in normalized.components.items()
        if key in COMPONENT_KEYS and str(value or "").strip()
    }
    if detail_tokens := _candidate_detail_tokens(candidate):
        components["detail"] = detail_tokens
    return components


def _candidate_numbers(candidate) -> list[str]:
    normalized = candidate.normalized_source
    if normalized is None:
        return []
    return [str(token).strip().upper() for token in normalized.numbers if str(token).strip()]


def _expected_numbers(components: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ("number", "building", "detail"):
        value = components.get(key)
        if value is not None:
            tokens.extend(_extract_number_tokens(str(value)))
    return tokens


def _display_component_key(key: str) -> str:
    return "details" if key == "detail" else key


def _build_display_components(
    metric_components: dict[str, ComponentValue],
    numbers: list[str],
) -> dict[str, ComponentValue]:
    display: dict[str, ComponentValue] = {}
    for key in COMPONENT_KEYS:
        if key not in metric_components:
            continue
        value = metric_components[key]
        if isinstance(value, list):
            if not value:
                continue
        elif not str(value or "").strip():
            continue
        display[_display_component_key(key)] = value
    if numbers:
        display["numbers"] = numbers
    return display


def _normalize_expected_components(components: dict[str, Any], locale: str) -> dict[str, ComponentValue]:
    return {
        key: _normalize_component_value(key, str(value), locale)
        for key, value in components.items()
        if key in COMPONENT_KEYS and str(value or "").strip()
    }


def _score_candidate(
    expected: dict[str, ComponentValue],
    actual: dict[str, ComponentValue],
) -> tuple[int, int]:
    exact_hits = 0
    partial_hits = 0
    for key, exp_value in expected.items():
        is_exact, is_partial = _component_match(exp_value, actual.get(key, ""))
        if is_exact:
            exact_hits += 1
        elif is_partial:
            partial_hits += 1
    return exact_hits, partial_hits


def _load_records(locale: str) -> list[dict[str, Any]]:
    txt_path = DATA_DIR / ("chinese_addresses.txt" if locale == "zh_cn" else "english_addresses.txt")
    jsonl_path = DATA_DIR / ("chinese_addresses.jsonl" if locale == "zh_cn" else "english_addresses.jsonl")
    txt_lines = [line.strip() for line in txt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    records: list[dict[str, Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if text:
                records.append(json.loads(text))
    if len(txt_lines) != len(records):
        raise ValueError(f"{locale} txt/jsonl 行数不一致：{len(txt_lines)} vs {len(records)}")
    for txt, record in zip(txt_lines, records, strict=True):
        if txt != record["text"]:
            raise ValueError(f"{locale} 文本与真值不一致：{txt} != {record['text']}")
    return records


def _ordered_present_keys(components: dict[str, Any], ordered_keys: tuple[str, ...]) -> list[str]:
    return [key for key in ordered_keys if str(components.get(key, "")).strip()]


def _select_ordered_subset(
    components: dict[str, Any],
    ordered_keys: tuple[str, ...],
    rng: random.Random,
    *,
    min_keep: int,
) -> list[str]:
    present = _ordered_present_keys(components, ordered_keys)
    if len(present) <= min_keep:
        return present
    keep_count = rng.randint(min_keep, len(present))
    chosen = set(rng.sample(present, keep_count))
    return [key for key in present if key in chosen]


def _zh_variant_candidates(record: dict[str, Any], rng: random.Random) -> list[tuple[str, str, dict[str, str]]]:
    components = dict(record["components"])
    candidates: list[tuple[str, str, dict[str, str]]] = []

    admin_keys_all = _ordered_present_keys(components, ("province", "city", "district", "subdistrict"))
    admin_forward = _select_ordered_subset(
        components,
        ("province", "city", "district", "subdistrict"),
        rng,
        min_keep=min(2, len(admin_keys_all)),
    )
    detail_forward = _select_ordered_subset(components, ("poi", "building", "detail"), rng, min_keep=1)
    forward_keys = [*admin_forward, "road", "number", *detail_forward]
    forward_text = "".join(str(components[key]).strip() for key in forward_keys if str(components.get(key, "")).strip())
    if forward_text:
        candidates.append(
            (
                "forward_subset",
                forward_text,
                {key: str(components[key]).strip() for key in forward_keys if str(components.get(key, "")).strip()},
            )
        )

    reverse_head = ["road", "number", *_select_ordered_subset(components, ("poi", "building", "detail"), rng, min_keep=1)]
    reverse_tail = _select_ordered_subset(components, ("district", "city", "province"), rng, min_keep=1)
    reverse_head_text = "".join(str(components[key]).strip() for key in reverse_head if str(components.get(key, "")).strip())
    reverse_tail_values = [str(components[key]).strip() for key in reverse_tail if str(components.get(key, "")).strip()]
    if reverse_head_text and reverse_tail_values:
        candidates.append(
            (
                "reverse_tail_segmented",
                f"{reverse_head_text},{','.join(reverse_tail_values)}",
                {
                    key: str(components[key]).strip()
                    for key in [*reverse_head, *reverse_tail]
                    if str(components.get(key, "")).strip()
                },
            )
        )

    community_head = [*_select_ordered_subset(components, ("subdistrict",), rng, min_keep=0), "road", "number"]
    community_head.extend(_select_ordered_subset(components, ("building", "detail"), rng, min_keep=1))
    community_tail = _select_ordered_subset(components, ("city", "district"), rng, min_keep=1)
    community_text = "".join(str(components[key]).strip() for key in community_head if str(components.get(key, "")).strip())
    community_tail_values = [str(components[key]).strip() for key in community_tail if str(components.get(key, "")).strip()]
    if community_text and community_tail_values:
        candidates.append(
            (
                "reverse_tail_city_district",
                f"{community_text},{''.join(community_tail_values)}",
                {
                    key: str(components[key]).strip()
                    for key in [*community_head, *community_tail]
                    if str(components.get(key, "")).strip()
                },
            )
        )
    return candidates


def _abbreviate_en_road(road: str) -> str:
    words = str(road or "").split()
    if not words:
        return str(road or "")
    suffix = words[-1].lower()
    if suffix in EN_ROAD_ABBREVIATIONS:
        words[-1] = EN_ROAD_ABBREVIATIONS[suffix]
    return " ".join(words)


def _abbreviate_en_building(building: str) -> str:
    words = str(building or "").split()
    if not words:
        return str(building or "")
    head = words[0].lower()
    if head in EN_BUILDING_ABBREVIATIONS:
        words[0] = EN_BUILDING_ABBREVIATIONS[head]
    return " ".join(words)


def _en_variant_candidates(record: dict[str, Any], rng: random.Random) -> list[tuple[str, str, dict[str, str]]]:
    del rng
    components = dict(record["components"])
    number = str(components.get("number", "")).strip()
    road = str(components.get("road", "")).strip()
    city = str(components.get("city", "")).strip()
    province = str(components.get("province", "")).strip()
    detail = str(components.get("detail", "")).strip()
    building = str(components.get("building", "")).strip()
    poi = str(components.get("poi", "")).strip()
    road_short = _abbreviate_en_road(road)
    building_short = _abbreviate_en_building(building)
    detail_is_zip = bool(ZIP_RE.fullmatch(detail))
    postal_tail = f"{province} {detail}" if detail_is_zip and province else province or detail

    candidates: list[tuple[str, str, dict[str, str]]] = []
    if number and road and city and province:
        base_text = _normalize_en_text(f"{number} {road_short}, {city}, {postal_tail}")
        base_components = {"number": number, "road": road, "city": city, "province": province}
        if detail_is_zip:
            base_components["detail"] = detail
        candidates.append(("forward_short", base_text, base_components))

    if detail and not detail_is_zip and number and road and city and province:
        text = _normalize_en_text(f"{detail}, {number} {road_short}, {city}, {province}")
        candidates.append(
            (
                "detail_first",
                text,
                {
                    "detail": detail,
                    "number": number,
                    "road": road,
                    "city": city,
                    "province": province,
                },
            )
        )

    if poi and number and road and city and province:
        text = _normalize_en_text(f"{number} {road_short}, {poi}, {city}, {postal_tail}")
        components_used = {
            "number": number,
            "road": road,
            "poi": poi,
            "city": city,
            "province": province,
        }
        if detail_is_zip:
            components_used["detail"] = detail
        candidates.append(("poi_first", text, components_used))

    if building and number and road and city and province:
        text = _normalize_en_text(f"{number} {road_short}, {building_short}, {city}, {postal_tail}")
        components_used = {
            "number": number,
            "road": road,
            "building": building,
            "city": city,
            "province": province,
        }
        if detail_is_zip:
            components_used["detail"] = detail
        candidates.append(("building_first", text, components_used))

    if building and detail and not detail_is_zip and number and road and city and province:
        text = _normalize_en_text(f"{building_short}, {detail}, {number} {road_short}, {city}, {province}")
        candidates.append(
            (
                "building_detail_mix",
                text,
                {
                    "building": building,
                    "detail": detail,
                    "number": number,
                    "road": road,
                    "city": city,
                    "province": province,
                },
            )
        )
    return candidates


def _build_variant_case(record: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    locale = str(record["locale"])
    original_text = str(record["text"])
    candidates = _zh_variant_candidates(record, rng) if locale == "zh_cn" else _en_variant_candidates(record, rng)
    deduped: list[tuple[str, str, dict[str, str]]] = []
    seen_texts: set[str] = set()
    for style, text, components in candidates:
        normalized_text = text if locale == "zh_cn" else _normalize_en_text(text)
        if not normalized_text or normalized_text in seen_texts:
            continue
        seen_texts.add(normalized_text)
        deduped.append((style, normalized_text, components))
    rng.shuffle(deduped)
    for style, text, components in deduped:
        if text != original_text:
            return {"style": style, "text": text, "components": components}
    return {"style": "identity_fallback", "text": original_text, "components": dict(record["components"])}


def _compose_context(locale: str, address_text: str) -> str:
    """地址-only 实验不再拼接其他 PII。"""
    if locale == "zh_cn":
        return str(address_text).strip()
    return _normalize_en_text(address_text)


def _analyze_detector_candidates(
    candidates: list[Any],
    expected_components: dict[str, ComponentValue],
    locale: str,
) -> dict[str, Any]:
    candidate_metrics = [_candidate_metric_components(candidate, locale) for candidate in candidates]
    candidate_components = [
        _build_display_components(metric_components, _candidate_numbers(candidate))
        for candidate, metric_components in zip(candidates, candidate_metrics, strict=True)
    ]
    best_index = -1
    best_exact = -1
    best_partial = -1
    best_extra = 10**9

    for index, actual in enumerate(candidate_metrics):
        exact_hits, partial_hits = _score_candidate(expected_components, actual)
        extra = len(actual)
        if (exact_hits, partial_hits, -extra) > (best_exact, best_partial, -best_extra):
            best_index = index
            best_exact = exact_hits
            best_partial = partial_hits
            best_extra = extra

    if 0 <= best_index < len(candidates):
        best_text = candidates[best_index].text
        best_components = candidate_components[best_index]
    else:
        best_text = ""
        best_components = {}
        best_exact = 0
        best_partial = 0

    union_exact_keys: set[str] = set()
    union_partial_keys: set[str] = set()
    best_exact_keys: set[str] = set()
    best_partial_keys: set[str] = set()

    for key, exp_value in expected_components.items():
        actual_value = candidate_metrics[best_index].get(key, "") if 0 <= best_index < len(candidate_metrics) else ""
        is_exact, is_partial = _component_match(exp_value, actual_value)
        if is_exact:
            best_exact_keys.add(key)
        elif is_partial:
            best_partial_keys.add(key)

        for actual in candidate_metrics:
            current_exact, current_partial = _component_match(exp_value, actual.get(key, ""))
            if current_exact:
                union_exact_keys.add(key)
                break
            if current_partial:
                union_partial_keys.add(key)

    return {
        "count": len(candidates),
        "best_text": best_text,
        "best_components": best_components,
        "best_exact_hits": best_exact,
        "best_partial_hits": best_partial,
        "best_exact_keys": sorted(best_exact_keys),
        "best_partial_keys": sorted(best_partial_keys),
        "union_exact_keys": sorted(union_exact_keys),
        "union_partial_keys": sorted(union_partial_keys),
        "all_texts": [candidate.text for candidate in candidates],
        "all_components": candidate_components,
        "complete_best_exact": bool(expected_components) and len(best_exact_keys) == len(expected_components),
        "complete_union_exact": bool(expected_components) and len(union_exact_keys) == len(expected_components),
    }


def _is_address_label(label: str) -> bool:
    return label == "ADDRESS" or label.startswith("LOCATION_")


def _address_entities(occurrences: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entity for entity in occurrences if _is_address_label(str(entity.get("label", "")))]


def _analyze_andlab_run(result: AndLabRunResult, expected_text: str) -> dict[str, Any]:
    entities = _address_entities(result.occurrences)
    texts = [str(entity["text"]) for entity in entities]
    exact_hit = any(_compact_text(text) == _compact_text(expected_text) for text in texts)
    partial_hit = any(
        _compact_text(expected_text) in _compact_text(text) or _compact_text(text) in _compact_text(expected_text)
        for text in texts
        if _compact_text(text)
    )
    return {
        "count": len(entities),
        "labels": [entity["label"] for entity in entities],
        "texts": texts,
        "tokens": [entity["token"] for entity in entities],
        "any_hit": bool(entities),
        "exact_hit": exact_hit,
        "partial_hit": partial_hit,
    }


def _is_substantial_address_token(text: str, full_address: str) -> bool:
    token_norm = _compact_text(text)
    full_norm = _compact_text(full_address)
    if not token_norm or not full_norm:
        return False
    return (len(token_norm) / len(full_norm)) >= 0.5


def _bucket_key(count: int) -> str:
    if count <= 0:
        return "zero"
    if count == 1:
        return "one"
    return "multi"


def _empty_detector_component_stats() -> dict[str, defaultdict[str, int]]:
    return {
        "expected_counts": defaultdict(int),
        "best_exact": defaultdict(int),
        "best_partial": defaultdict(int),
        "union_exact": defaultdict(int),
        "union_partial": defaultdict(int),
    }


def _init_detector_summary(locale: str) -> dict[str, Any]:
    return {
        "locale": locale,
        "cases": 0,
        "same_entity": 0,
        "same_entity_when_both_detected": 0,
        "both_detected": 0,
        "full_bucket": Counter(),
        "variant_bucket": Counter(),
        "full_avg_count_total": 0,
        "variant_avg_count_total": 0,
        "full_complete_best_exact": 0,
        "full_complete_union_exact": 0,
        "variant_complete_best_exact": 0,
        "variant_complete_union_exact": 0,
        "full_component": _empty_detector_component_stats(),
        "variant_component": _empty_detector_component_stats(),
    }


def _update_component_stats(
    summary: dict[str, Any],
    kind: str,
    expected_components: dict[str, ComponentValue],
    analysis: dict[str, Any],
) -> None:
    stats = summary[f"{kind}_component"]
    for key in expected_components:
        stats["expected_counts"][key] += 1
    for key in analysis["best_exact_keys"]:
        stats["best_exact"][key] += 1
    for key in analysis["best_partial_keys"]:
        stats["best_partial"][key] += 1
    for key in analysis["union_exact_keys"]:
        stats["union_exact"][key] += 1
    for key in analysis["union_partial_keys"]:
        if key not in analysis["union_exact_keys"]:
            stats["union_partial"][key] += 1


def _finalize_detector_summary(summary: dict[str, Any]) -> dict[str, Any]:
    cases = max(1, int(summary["cases"]))
    both_detected = max(1, int(summary["both_detected"]))
    summary["same_entity_rate"] = round(summary["same_entity"] / cases, 3)
    summary["same_entity_when_both_detected_rate"] = round(summary["same_entity_when_both_detected"] / both_detected, 3)
    summary["full_avg_count"] = round(summary["full_avg_count_total"] / cases, 3)
    summary["variant_avg_count"] = round(summary["variant_avg_count_total"] / cases, 3)
    return summary


def _init_andlab_summary(locale: str) -> dict[str, Any]:
    return {
        "locale": locale,
        "cases": 0,
        "full_bucket": Counter(),
        "variant_bucket": Counter(),
        "full_exact_hit": 0,
        "full_partial_hit": 0,
        "variant_exact_hit": 0,
        "variant_partial_hit": 0,
        "same_token_reuse": 0,
        "same_token_reuse_any": 0,
        "reuse_with_variant_detected": 0,
        "reuse_any_with_variant_detected": 0,
        "variant_detected": 0,
    }


def _finalize_andlab_summary(summary: dict[str, Any]) -> dict[str, Any]:
    cases = max(1, int(summary["cases"]))
    variant_detected = max(1, int(summary["variant_detected"]))
    summary["full_exact_hit_rate"] = round(summary["full_exact_hit"] / cases, 3)
    summary["full_partial_hit_rate"] = round(summary["full_partial_hit"] / cases, 3)
    summary["variant_exact_hit_rate"] = round(summary["variant_exact_hit"] / cases, 3)
    summary["variant_partial_hit_rate"] = round(summary["variant_partial_hit"] / cases, 3)
    summary["same_token_reuse_rate"] = round(summary["same_token_reuse"] / cases, 3)
    summary["same_token_reuse_any_rate"] = round(summary["same_token_reuse_any"] / cases, 3)
    summary["reuse_with_variant_detected_rate"] = round(summary["reuse_with_variant_detected"] / variant_detected, 3)
    summary["reuse_any_with_variant_detected_rate"] = round(summary["reuse_any_with_variant_detected"] / variant_detected, 3)
    return summary


def _evaluate_detector_case(
    detector: RuleBasedPIIDetector,
    locale: str,
    full_context: str,
    variant_context: str,
    full_expected: dict[str, ComponentValue],
    variant_expected: dict[str, ComponentValue],
) -> dict[str, Any]:
    full_candidates = [candidate for candidate in detector.detect(full_context, []) if candidate.attr_type == PIIAttributeType.ADDRESS]
    variant_candidates = [candidate for candidate in detector.detect(variant_context, []) if candidate.attr_type == PIIAttributeType.ADDRESS]
    full_analysis = _analyze_detector_candidates(full_candidates, full_expected, locale)
    variant_analysis = _analyze_detector_candidates(variant_candidates, variant_expected, locale)
    same_entity = any(
        same_entity_fn(left.normalized_source, right.normalized_source)
        for left in full_candidates
        for right in variant_candidates
    )
    return {
        "full": full_analysis,
        "variant": variant_analysis,
        "same_entity": same_entity,
    }


def _evaluate_andlab_case(
    evaluator: AndLabEvaluator,
    full_address: str,
    full_context: str,
    variant_context: str,
    variant_address: str,
) -> dict[str, Any]:
    full_context_run = evaluator.run_prompt(full_context, clear=True)
    variant_context_run = evaluator.run_prompt(variant_context, clear=True)
    registration_run = evaluator.run_prompt(full_address, clear=True)
    reuse_run = evaluator.run_prompt(variant_context, clear=False)

    registration_entities = _address_entities(registration_run.occurrences)
    registered_tokens = {entity["token"] for entity in registration_entities}
    registered_substantial_tokens = {
        entity["token"]
        for entity in registration_entities
        if _is_substantial_address_token(str(entity["text"]), full_address)
    }
    reuse_entities = _address_entities(reuse_run.occurrences)
    same_token_reuse_any = any(entity["token"] in registered_tokens for entity in reuse_entities)
    same_token_reuse = any(entity["token"] in registered_substantial_tokens for entity in reuse_entities)

    return {
        "full_context": _analyze_andlab_run(full_context_run, full_address),
        "variant_context": _analyze_andlab_run(variant_context_run, variant_address),
        "registered_tokens": sorted(registered_tokens),
        "registered_substantial_tokens": sorted(registered_substantial_tokens),
        "reuse": {
            "any_hit": bool(reuse_entities),
            "tokens": [entity["token"] for entity in reuse_entities],
            "texts": [entity["text"] for entity in reuse_entities],
            "labels": [entity["label"] for entity in reuse_entities],
            "same_token_reuse_any": same_token_reuse_any,
            "same_token_reuse": same_token_reuse,
        },
        "raw": {
            "full_context_masked": full_context_run.masked_text,
            "variant_context_masked": variant_context_run.masked_text,
            "reuse_masked": reuse_run.masked_text,
            "registration_masked": registration_run.masked_text,
            "full_context_error": full_context_run.error,
            "variant_context_error": variant_context_run.error,
            "registration_error": registration_run.error,
            "reuse_error": reuse_run.error,
        },
    }


def _rate(hit: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(hit / total) * 100:.1f}%"


def _latency_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"avg_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 0:
        median = (ordered[middle - 1] + ordered[middle]) / 2
    else:
        median = ordered[middle]
    p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
    return {
        "avg_ms": round(sum(ordered) / len(ordered), 3),
        "median_ms": round(median, 3),
        "p95_ms": round(ordered[p95_index], 3),
    }


def _write_summary(path: Path, payload: dict[str, Any]) -> None:
    lines: list[str] = []
    lines.append("# Generated Address Same-Entity Evaluation")
    lines.append("")
    lines.append("## 数据口径")
    lines.append("")
    lines.append(f"- 随机种子：`{payload['seed']}`。")
    lines.append(f"- 每个 locale 抽样：`{payload['sample_size_per_locale']}` 条。")
    lines.append("- 样本来自 `data/generate_data.py` 生成的 txt/jsonl。")
    lines.append("- 中文地址保持无空格；英文地址保持正常单词间单个空格。")
    lines.append("- 变体地址由同一条地址的组件重组得到；本实验只输入地址，不拼接其他类型 PII。")
    lines.append("- `detector` 的“同址”使用 `privacyguard.utils.normalized_pii.same_entity()` 判断。")
    lines.append("- `AndLab_protected` 的“同址”使用先注册完整地址、再检测变体时是否复用同一 token 判断。")
    lines.append("- `details` 按顺序数组展示，并要求与同顺序 token 数组比较；`numbers` 仅用于辅助观察，不单独计入组件命中。")
    lines.append("")

    for locale in ("zh_cn", "en_us"):
        detector_summary = payload["detector_summaries"][locale]
        andlab_summary = payload["andlab_summaries"][locale]
        detector_latency = payload["latency_summaries"][locale]["detector"]
        andlab_latency = payload["latency_summaries"][locale]["andlab"]
        label = "中文" if locale == "zh_cn" else "英文"
        lines.append(f"## {label}")
        lines.append("")
        lines.append("### Detector")
        lines.append("")
        lines.append(f"- 样本数：`{detector_summary['cases']}`")
        lines.append(
            f"- 完整地址输入返回 `0/1/>1` 个地址实体：`{detector_summary['full_bucket'].get('zero', 0)}` / "
            f"`{detector_summary['full_bucket'].get('one', 0)}` / `{detector_summary['full_bucket'].get('multi', 0)}`"
        )
        lines.append(
            f"- 变体地址输入返回 `0/1/>1` 个地址实体：`{detector_summary['variant_bucket'].get('zero', 0)}` / "
            f"`{detector_summary['variant_bucket'].get('one', 0)}` / `{detector_summary['variant_bucket'].get('multi', 0)}`"
        )
        lines.append(f"- 完整地址平均地址实体数：`{detector_summary['full_avg_count']}`")
        lines.append(f"- 变体地址平均地址实体数：`{detector_summary['variant_avg_count']}`")
        lines.append(f"- 同址判定命中：`{detector_summary['same_entity']}` / `{detector_summary['cases']}`")
        lines.append(f"- 双方都检测到地址时的同址判定命中率：`{detector_summary['same_entity_when_both_detected_rate'] * 100:.1f}%`")
        lines.append(
            f"- 完整地址单候选完整精确命中：`{detector_summary['full_complete_best_exact']}` / `{detector_summary['cases']}`，"
            f"多候选并集完整精确命中：`{detector_summary['full_complete_union_exact']}` / `{detector_summary['cases']}`"
        )
        lines.append(
            f"- 变体地址单候选完整精确命中：`{detector_summary['variant_complete_best_exact']}` / `{detector_summary['cases']}`，"
            f"多候选并集完整精确命中：`{detector_summary['variant_complete_union_exact']}` / `{detector_summary['cases']}`"
        )
        lines.append(
            f"- 运行时间：平均 `{detector_latency['avg_ms']}` ms，中位数 `{detector_latency['median_ms']}` ms，"
            f"P95 `{detector_latency['p95_ms']}` ms"
        )
        lines.append("")
        lines.append("| 组件 | 完整地址真值数 | 完整地址最佳精确 | 完整地址并集精确 | 变体真值数 | 变体最佳精确 | 变体并集精确 |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for key in COMPONENT_KEYS:
            full_total = detector_summary["full_component"]["expected_counts"].get(key, 0)
            variant_total = detector_summary["variant_component"]["expected_counts"].get(key, 0)
            if full_total <= 0 and variant_total <= 0:
                continue
            full_best = detector_summary["full_component"]["best_exact"].get(key, 0)
            full_union = detector_summary["full_component"]["union_exact"].get(key, 0)
            variant_best = detector_summary["variant_component"]["best_exact"].get(key, 0)
            variant_union = detector_summary["variant_component"]["union_exact"].get(key, 0)
            lines.append(
                f"| `{_display_component_key(key)}` | {full_total} | {full_best} ({_rate(full_best, full_total)}) | "
                f"{full_union} ({_rate(full_union, full_total)}) | {variant_total} | "
                f"{variant_best} ({_rate(variant_best, variant_total)}) | "
                f"{variant_union} ({_rate(variant_union, variant_total)}) |"
            )
        lines.append("")

        lines.append("### AndLab_protected")
        lines.append("")
        lines.append(
            f"- 完整地址输入返回 `0/1/>1` 个地址实体：`{andlab_summary['full_bucket'].get('zero', 0)}` / "
            f"`{andlab_summary['full_bucket'].get('one', 0)}` / `{andlab_summary['full_bucket'].get('multi', 0)}`"
        )
        lines.append(
            f"- 变体地址输入返回 `0/1/>1` 个地址实体：`{andlab_summary['variant_bucket'].get('zero', 0)}` / "
            f"`{andlab_summary['variant_bucket'].get('one', 0)}` / `{andlab_summary['variant_bucket'].get('multi', 0)}`"
        )
        lines.append(f"- 完整地址精确命中率：`{andlab_summary['full_exact_hit_rate'] * 100:.1f}%`")
        lines.append(f"- 完整地址宽松命中率：`{andlab_summary['full_partial_hit_rate'] * 100:.1f}%`")
        lines.append(f"- 变体地址精确命中率：`{andlab_summary['variant_exact_hit_rate'] * 100:.1f}%`")
        lines.append(f"- 变体地址宽松命中率：`{andlab_summary['variant_partial_hit_rate'] * 100:.1f}%`")
        lines.append(f"- 主地址 span token 复用率：`{andlab_summary['same_token_reuse_rate'] * 100:.1f}%`")
        lines.append(f"- 任一地址子 token 复用率：`{andlab_summary['same_token_reuse_any_rate'] * 100:.1f}%`")
        lines.append(f"- 仅在变体被识别为地址时的主地址 span 复用率：`{andlab_summary['reuse_with_variant_detected_rate'] * 100:.1f}%`")
        lines.append(f"- 仅在变体被识别为地址时的任一子 token 复用率：`{andlab_summary['reuse_any_with_variant_detected_rate'] * 100:.1f}%`")
        lines.append(
            f"- 运行时间：平均 `{andlab_latency['avg_ms']}` ms，中位数 `{andlab_latency['median_ms']}` ms，"
            f"P95 `{andlab_latency['p95_ms']}` ms"
        )
        lines.append("")

        lines.append("### 代表性案例")
        lines.append("")
        same_entity_misses = [
            case for case in payload["cases"]
            if case["locale"] == locale and not case["detector"]["same_entity"]
        ][:3]
        for case in same_entity_misses:
            lines.append(f"- Detector 未判同址：`{case['variant_style']}`")
            lines.append(f"  完整地址：`{case['full_address']}`")
            lines.append(f"  变体地址：`{case['variant_address']}`")
            lines.append(f"  detector 完整候选：`{case['detector']['full']['all_texts']}`")
            lines.append(f"  detector 变体候选：`{case['detector']['variant']['all_texts']}`")
        fragmentation_cases = [
            case for case in payload["cases"]
            if case["locale"] == locale and (case["detector"]["full"]["count"] > 1 or case["detector"]["variant"]["count"] > 1)
        ][:3]
        for case in fragmentation_cases:
            lines.append(f"- Detector 地址碎片化：完整=`{case['detector']['full']['count']}`，变体=`{case['detector']['variant']['count']}`")
            lines.append(f"  完整地址：`{case['full_address']}`")
            lines.append(f"  变体地址：`{case['variant_address']}`")
            lines.append(f"  完整候选：`{case['detector']['full']['all_texts']}`")
            lines.append(f"  变体候选：`{case['detector']['variant']['all_texts']}`")
        andlab_misses = [
            case for case in payload["cases"]
            if case["locale"] == locale and not case["andlab"]["reuse"]["same_token_reuse"]
        ][:3]
        for case in andlab_misses:
            lines.append(f"- AndLab 未复用同 token：`{case['variant_style']}`")
            lines.append(f"  完整地址：`{case['full_address']}`")
            lines.append(f"  变体地址：`{case['variant_address']}`")
            lines.append(f"  变体地址实体：`{case['andlab']['variant_context']['texts']}`")
            lines.append(f"  复用阶段 token：`{case['andlab']['reuse']['tokens']}`")
            lines.append(f"  注册主地址 token：`{case['andlab']['registered_substantial_tokens']}`")
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cases_csv(path: Path, cases: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "locale",
                "id",
                "variant_style",
                "full_address",
                "variant_address",
                "full_context",
                "variant_context",
                "full_expected",
                "variant_expected",
                "detector_same_entity",
                "detector_full_count",
                "detector_variant_count",
                "detector_full_best_text",
                "detector_variant_best_text",
                "detector_full_best_components",
                "detector_variant_best_components",
                "detector_full_all_texts",
                "detector_variant_all_texts",
                "andlab_full_count",
                "andlab_variant_count",
                "andlab_same_token_reuse",
                "andlab_same_token_reuse_any",
                "andlab_variant_texts",
                "andlab_reuse_tokens",
                "detector_elapsed_ms",
                "andlab_elapsed_ms",
            ],
        )
        writer.writeheader()
        for case in cases:
            writer.writerow(
                {
                    "locale": case["locale"],
                    "id": case["id"],
                    "variant_style": case["variant_style"],
                    "full_address": case["full_address"],
                    "variant_address": case["variant_address"],
                    "full_context": case["full_context"],
                    "variant_context": case["variant_context"],
                    "full_expected": json.dumps(case["full_expected"], ensure_ascii=False),
                    "variant_expected": json.dumps(case["variant_expected"], ensure_ascii=False),
                    "detector_same_entity": case["detector"]["same_entity"],
                    "detector_full_count": case["detector"]["full"]["count"],
                    "detector_variant_count": case["detector"]["variant"]["count"],
                    "detector_full_best_text": case["detector"]["full"]["best_text"],
                    "detector_variant_best_text": case["detector"]["variant"]["best_text"],
                    "detector_full_best_components": json.dumps(case["detector"]["full"]["best_components"], ensure_ascii=False),
                    "detector_variant_best_components": json.dumps(case["detector"]["variant"]["best_components"], ensure_ascii=False),
                    "detector_full_all_texts": json.dumps(case["detector"]["full"]["all_texts"], ensure_ascii=False),
                    "detector_variant_all_texts": json.dumps(case["detector"]["variant"]["all_texts"], ensure_ascii=False),
                    "andlab_full_count": case["andlab"]["full_context"]["count"],
                    "andlab_variant_count": case["andlab"]["variant_context"]["count"],
                    "andlab_same_token_reuse": case["andlab"]["reuse"]["same_token_reuse"],
                    "andlab_same_token_reuse_any": case["andlab"]["reuse"]["same_token_reuse_any"],
                    "andlab_variant_texts": json.dumps(case["andlab"]["variant_context"]["texts"], ensure_ascii=False),
                    "andlab_reuse_tokens": json.dumps(case["andlab"]["reuse"]["tokens"], ensure_ascii=False),
                    "detector_elapsed_ms": case["detector_elapsed_ms"],
                    "andlab_elapsed_ms": case["andlab_elapsed_ms"],
                }
            )


def _jsonable_summary(summary: dict[str, Any]) -> dict[str, Any]:
    converted = dict(summary)
    for key in ("full_bucket", "variant_bucket"):
        converted[key] = dict(converted[key])
    for key in ("full_component", "variant_component"):
        if key not in converted:
            continue
        converted[key] = {
            sub_key: dict(values)
            for sub_key, values in converted[key].items()
        }
    return converted


def main() -> None:
    rng = random.Random(SEED)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    selected_records: dict[str, list[dict[str, Any]]] = {
        locale: rng.sample(_load_records(locale), SAMPLE_SIZE_PER_LOCALE)
        for locale in ("zh_cn", "en_us")
    }

    detectors = {
        "zh_cn": RuleBasedPIIDetector(locale_profile="zh_cn"),
        "en_us": RuleBasedPIIDetector(locale_profile="en_us"),
    }
    andlab = AndLabEvaluator()
    andlab.run_prompt("warmup 1200 Harbor Avenue, Seattle, WA 98101", clear=True)

    detector_summaries = {locale: _init_detector_summary(locale) for locale in ("zh_cn", "en_us")}
    andlab_summaries = {locale: _init_andlab_summary(locale) for locale in ("zh_cn", "en_us")}
    detector_latencies: dict[str, list[float]] = {"zh_cn": [], "en_us": []}
    andlab_latencies: dict[str, list[float]] = {"zh_cn": [], "en_us": []}
    cases: list[dict[str, Any]] = []

    for locale in ("zh_cn", "en_us"):
        detector = detectors[locale]
        detector_summary = detector_summaries[locale]
        andlab_summary = andlab_summaries[locale]

        for record in selected_records[locale]:
            variant = _build_variant_case(record, rng)
            full_address = str(record["text"])
            variant_address = str(variant["text"])
            full_context = _compose_context(locale, full_address)
            variant_context = _compose_context(locale, variant_address)
            full_expected_metrics = _normalize_expected_components(dict(record["components"]), locale)
            variant_expected_metrics = _normalize_expected_components(dict(variant["components"]), locale)
            full_expected = _build_display_components(full_expected_metrics, _expected_numbers(dict(record["components"])))
            variant_expected = _build_display_components(
                variant_expected_metrics,
                _expected_numbers(dict(variant["components"])),
            )

            started = time.perf_counter()
            detector_result = _evaluate_detector_case(
                detector,
                locale,
                full_context,
                variant_context,
                full_expected_metrics,
                variant_expected_metrics,
            )
            detector_elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

            started = time.perf_counter()
            andlab_result = _evaluate_andlab_case(andlab, full_address, full_context, variant_context, variant_address)
            andlab_elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

            detector_latencies[locale].append(detector_elapsed_ms)
            andlab_latencies[locale].append(andlab_elapsed_ms)

            detector_summary["cases"] += 1
            detector_summary["full_bucket"][_bucket_key(detector_result["full"]["count"])] += 1
            detector_summary["variant_bucket"][_bucket_key(detector_result["variant"]["count"])] += 1
            detector_summary["full_avg_count_total"] += detector_result["full"]["count"]
            detector_summary["variant_avg_count_total"] += detector_result["variant"]["count"]
            detector_summary["same_entity"] += int(detector_result["same_entity"])
            if detector_result["full"]["count"] > 0 and detector_result["variant"]["count"] > 0:
                detector_summary["both_detected"] += 1
                detector_summary["same_entity_when_both_detected"] += int(detector_result["same_entity"])
            detector_summary["full_complete_best_exact"] += int(detector_result["full"]["complete_best_exact"])
            detector_summary["full_complete_union_exact"] += int(detector_result["full"]["complete_union_exact"])
            detector_summary["variant_complete_best_exact"] += int(detector_result["variant"]["complete_best_exact"])
            detector_summary["variant_complete_union_exact"] += int(detector_result["variant"]["complete_union_exact"])
            _update_component_stats(detector_summary, "full", full_expected_metrics, detector_result["full"])
            _update_component_stats(detector_summary, "variant", variant_expected_metrics, detector_result["variant"])

            andlab_summary["cases"] += 1
            andlab_summary["full_bucket"][_bucket_key(andlab_result["full_context"]["count"])] += 1
            andlab_summary["variant_bucket"][_bucket_key(andlab_result["variant_context"]["count"])] += 1
            andlab_summary["full_exact_hit"] += int(andlab_result["full_context"]["exact_hit"])
            andlab_summary["full_partial_hit"] += int(andlab_result["full_context"]["partial_hit"])
            andlab_summary["variant_exact_hit"] += int(andlab_result["variant_context"]["exact_hit"])
            andlab_summary["variant_partial_hit"] += int(andlab_result["variant_context"]["partial_hit"])
            andlab_summary["same_token_reuse"] += int(andlab_result["reuse"]["same_token_reuse"])
            andlab_summary["same_token_reuse_any"] += int(andlab_result["reuse"]["same_token_reuse_any"])
            andlab_summary["variant_detected"] += int(andlab_result["variant_context"]["any_hit"])
            if andlab_result["variant_context"]["any_hit"]:
                andlab_summary["reuse_with_variant_detected"] += int(andlab_result["reuse"]["same_token_reuse"])
                andlab_summary["reuse_any_with_variant_detected"] += int(andlab_result["reuse"]["same_token_reuse_any"])

            cases.append(
                {
                    "locale": locale,
                    "id": record["id"],
                    "format": record["format"],
                    "variant_style": variant["style"],
                    "full_address": full_address,
                    "variant_address": variant_address,
                    "full_context": full_context,
                    "variant_context": variant_context,
                    "full_expected": full_expected,
                    "variant_expected": variant_expected,
                    "detector": detector_result,
                    "andlab": andlab_result,
                    "detector_elapsed_ms": detector_elapsed_ms,
                    "andlab_elapsed_ms": andlab_elapsed_ms,
                }
            )

    detector_payload = {locale: _jsonable_summary(_finalize_detector_summary(summary)) for locale, summary in detector_summaries.items()}
    andlab_payload = {locale: _jsonable_summary(_finalize_andlab_summary(summary)) for locale, summary in andlab_summaries.items()}
    latency_payload = {
        locale: {
            "detector": _latency_stats(detector_latencies[locale]),
            "andlab": _latency_stats(andlab_latencies[locale]),
        }
        for locale in ("zh_cn", "en_us")
    }

    payload = {
        "seed": SEED,
        "sample_size_per_locale": SAMPLE_SIZE_PER_LOCALE,
        "detector_summaries": detector_payload,
        "andlab_summaries": andlab_payload,
        "latency_summaries": latency_payload,
        "cases": cases,
    }

    summary_path = OUTPUT_DIR / "generated_address_same_entity_summary.md"
    details_path = OUTPUT_DIR / "generated_address_same_entity_details.json"
    cases_path = OUTPUT_DIR / "generated_address_same_entity_cases.csv"

    _write_summary(summary_path, payload)
    details_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_cases_csv(cases_path, cases)

    print(summary_path)
    print(details_path)
    print(cases_path)


if __name__ == "__main__":
    main()
