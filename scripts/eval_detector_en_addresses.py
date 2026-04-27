"""英文合成地址评测脚本。

评估分两部分：
1. 使用 ``data/generate_data.py`` 的英文地址生成器构造 1000 条地址，评估原始地址检测。
2. 基于同一批地址生成随机表面变体，评估完整召回、碎片量、组件准确性与耗时。
"""

from __future__ import annotations

import argparse
import json
import random
import re
import runpy
import statistics
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from privacyguard.infrastructure.pii.detector.lexicon_loader import load_en_us_states
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "tmp" / "eval_detector_en_addresses"

ADDRESS_COUNT_DEFAULT = 1000
ADDRESS_SEED_DEFAULT = 42
VARIANT_SEED_DEFAULT = 20260423

ADDRESS_COMPONENT_KEYS = (
    "province",
    "city",
    "road",
    "number",
    "poi",
    "building",
    "detail",
)
ROAD_SUFFIXES = (
    "boulevard",
    "avenue",
    "street",
    "drive",
    "court",
    "road",
    "lane",
    "blvd",
    "ave",
    "st",
    "dr",
    "ct",
    "rd",
    "ln",
)
BUILDING_PREFIXES = ("building", "tower", "block", "house")
DETAIL_PREFIXES = ("apartment", "apt", "suite", "ste", "unit", "room")
ZIP_PATTERN = re.compile(r"^\d{5}(?:-\d{4})?$")
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9]+")


@dataclass(slots=True)
class PredictionSpan:
    """detector 产出的单个 span。"""

    prediction_index: int
    entity_type: str
    text: str
    start: int
    end: int
    metadata: dict[str, list[str]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="评估英文合成地址与随机变体上的 detector 表现。")
    parser.add_argument("--address-count", type=int, default=ADDRESS_COUNT_DEFAULT, help="生成地址条数。")
    parser.add_argument("--address-seed", type=int, default=ADDRESS_SEED_DEFAULT, help="地址生成随机种子。")
    parser.add_argument("--variant-seed", type=int, default=VARIANT_SEED_DEFAULT, help="变体随机种子。")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="输出目录。")
    return parser.parse_args()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def summarize_numeric(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    sorted_values = sorted(float(value) for value in values)
    p95_index = min(len(sorted_values) - 1, int(round((len(sorted_values) - 1) * 0.95)))
    return {
        "count": float(len(sorted_values)),
        "mean": float(sum(sorted_values) / len(sorted_values)),
        "median": float(statistics.median(sorted_values)),
        "p95": float(sorted_values[p95_index]),
        "min": float(sorted_values[0]),
        "max": float(sorted_values[-1]),
    }


def interval_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> int:
    return max(0, min(end_a, end_b) - max(start_a, start_b))


def interval_union_length(intervals: list[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if end <= start:
            continue
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return sum(end - start for start, end in merged)


def coverage_ratio(span_start: int, span_end: int, predictions: list[dict[str, Any]]) -> float:
    span_length = max(1, span_end - span_start)
    intervals = []
    for prediction in predictions:
        overlap = interval_overlap(span_start, span_end, prediction["start"], prediction["end"])
        if overlap <= 0:
            continue
        intervals.append((max(span_start, prediction["start"]), min(span_end, prediction["end"])))
    return interval_union_length(intervals) / span_length


def detector_build() -> tuple[RuleBasedPIIDetector, float]:
    started = time.perf_counter()
    detector = RuleBasedPIIDetector(locale_profile="en_us")
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return detector, elapsed_ms


def detect_text(detector: RuleBasedPIIDetector, text: str) -> tuple[list[PredictionSpan], list[Any], float]:
    started = time.perf_counter()
    candidates = detector.detect(text, [])
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    predictions: list[PredictionSpan] = []
    for index, candidate in enumerate(candidates, start=1):
        start = int(candidate.span_start or 0)
        end = int(candidate.span_end or (start + len(candidate.text or "")))
        predictions.append(
            PredictionSpan(
                prediction_index=index,
                entity_type=candidate.attr_type.value,
                text=candidate.text,
                start=start,
                end=end,
                metadata={key: list(value) for key, value in candidate.metadata.items()},
            )
        )
    return predictions, candidates, elapsed_ms


def compact_text(text: str) -> str:
    return re.sub(r"\s+", "", str(text or ""))


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip())


def compact_alnum_upper(text: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", unicodedata.normalize("NFKC", str(text or ""))).upper()


def compact_alpha_lower(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", unicodedata.normalize("NFKC", str(text or ""))).lower()


def state_name_to_code(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not text:
        return ""
    state_map = load_en_us_states()
    upper = text.upper()
    if upper in state_map:
        return upper
    by_name = {name.lower(): code for code, name in state_map.items()}
    return by_name.get(text.lower(), "")


def state_code_to_name(code: str) -> str:
    state_map = load_en_us_states()
    return state_map.get(str(code or "").upper(), str(code or ""))


def looks_like_zip(value: str) -> bool:
    return bool(ZIP_PATTERN.fullmatch(normalize_spaces(value)))


def strip_trailing_road_suffix(value: str) -> str:
    text = normalize_spaces(value)
    if not text:
        return ""
    tokens = text.split()
    if tokens and tokens[-1].lower().rstrip(".") in ROAD_SUFFIXES:
        tokens = tokens[:-1]
    return " ".join(tokens) or text


def strip_leading_prefix(value: str, prefixes: tuple[str, ...]) -> str:
    text = normalize_spaces(value)
    if not text:
        return ""
    parts = text.split(maxsplit=1)
    if parts and parts[0].lower().rstrip(".") in prefixes:
        if len(parts) == 2:
            return parts[1]
        return ""
    return text


def normalize_phrase_token_set(text: str) -> set[str]:
    tokens = [token.upper() for token in TOKEN_PATTERN.findall(normalize_spaces(text)) if token]
    if not tokens:
        return set()
    result = set(tokens)
    if len(tokens) > 1:
        result.add("".join(tokens))
    return result


def expected_component_tokens(component_key: str, value: str) -> list[str]:
    text = normalize_spaces(value)
    if not text:
        return []
    if component_key == "province":
        code = state_name_to_code(text)
        return [code] if code else [compact_alnum_upper(text)]
    if component_key == "city":
        return sorted(normalize_phrase_token_set(text))
    if component_key == "road":
        return sorted(normalize_phrase_token_set(strip_trailing_road_suffix(text)))
    if component_key == "number":
        token = compact_alnum_upper(text)
        return [token] if token else []
    if component_key == "poi":
        return sorted(normalize_phrase_token_set(text))
    if component_key == "building":
        stripped = strip_leading_prefix(text, BUILDING_PREFIXES)
        token = compact_alnum_upper(stripped)
        return [token] if token else []
    if component_key == "detail":
        if looks_like_zip(text):
            return [re.sub(r"[^0-9-]", "", text)]
        stripped = strip_leading_prefix(text, DETAIL_PREFIXES)
        token = compact_alnum_upper(stripped)
        return [token] if token else []
    return sorted(normalize_phrase_token_set(text))


def trace_component_key(component_type: str, levels: tuple[str, ...]) -> tuple[str, ...]:
    if component_type in {"house_number", "number"}:
        return ("number",)
    if component_type == "postal_code":
        return ("postal_code",)
    if component_type == "multi_admin":
        mapped = [level for level in levels if level in {"province", "city"}]
        return tuple(mapped)
    if component_type in {"province", "city", "road", "poi", "building", "detail"}:
        return (component_type,)
    return ()


def normalize_trace_value(component_key: str, value: str) -> set[str]:
    text = normalize_spaces(value)
    if not text:
        return set()
    if component_key == "province":
        code = state_name_to_code(text)
        return {code} if code else normalize_phrase_token_set(text)
    if component_key == "city":
        return normalize_phrase_token_set(text)
    if component_key == "road":
        return normalize_phrase_token_set(text)
    if component_key == "number":
        token = compact_alnum_upper(text)
        return {token} if token else set()
    if component_key == "poi":
        return normalize_phrase_token_set(text)
    if component_key == "building":
        token = compact_alnum_upper(text)
        return {token} if token else set()
    if component_key == "detail":
        token = compact_alnum_upper(text)
        return {token} if token else set()
    if component_key == "postal_code":
        token = re.sub(r"[^0-9-]", "", text)
        return {token} if token else set()
    return normalize_phrase_token_set(text)


def parse_address_trace(metadata: dict[str, list[str]]) -> list[dict[str, Any]]:
    traces = list(metadata.get("address_component_trace", []))
    levels = list(metadata.get("address_component_level", []))
    keys = list(metadata.get("address_component_key_trace", []))
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(traces):
        if ":" not in item:
            continue
        component_type, value = item.split(":", 1)
        level_value = levels[index] if index < len(levels) else component_type
        level_tuple = tuple(part.strip() for part in str(level_value).split("|") if part.strip())
        key_text = ""
        if index < len(keys) and ":" in keys[index]:
            key_component_type, key_value = keys[index].split(":", 1)
            if key_component_type.strip() == component_type.strip():
                key_text = key_value.strip()
        entries.append(
            {
                "component_type": component_type.strip(),
                "value": value.strip(),
                "level": level_tuple,
                "key": key_text,
            }
        )
    return entries


def build_fragment_bucket(candidates: list[Any]) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    bucket: dict[str, list[str]] = defaultdict(list)
    trace_entries: list[dict[str, Any]] = []
    for candidate in candidates:
        trace_entries.extend(parse_address_trace({key: list(value) for key, value in candidate.metadata.items()}))
    for entry in trace_entries:
        mapped_keys = trace_component_key(entry["component_type"], entry["level"])
        for mapped_key in mapped_keys:
            normalized_tokens = normalize_trace_value(mapped_key, entry["value"])
            if not normalized_tokens:
                continue
            bucket[mapped_key].extend(sorted(normalized_tokens))
    return bucket, trace_entries


def evaluate_address_components(gt_components: dict[str, str], candidates: list[Any]) -> dict[str, Any]:
    expected_keys = [key for key in ADDRESS_COMPONENT_KEYS if compact_text(gt_components.get(key, ""))]
    bucket, trace_entries = build_fragment_bucket(candidates)
    component_rows: list[dict[str, Any]] = []
    matched_component_count = 0
    fragmented_component_count = 0
    token_hit_count = 0
    token_total = 0
    for key in expected_keys:
        expected_tokens = expected_component_tokens(key, gt_components.get(key, ""))
        if key == "detail" and looks_like_zip(gt_components.get(key, "")):
            predicted_tokens = list(bucket.get("postal_code", []))
        else:
            predicted_tokens = list(bucket.get(key, []))
        if len(predicted_tokens) > 1:
            fragmented_component_count += 1
        predicted_set = set(predicted_tokens)
        row_hit_count = sum(1 for token in expected_tokens if token in predicted_set)
        matched = bool(expected_tokens) and row_hit_count == len(expected_tokens)
        if matched:
            matched_component_count += 1
        token_hit_count += row_hit_count
        token_total += len(expected_tokens)
        component_rows.append(
            {
                "component_type": key,
                "expected": gt_components.get(key, ""),
                "expected_tokens": expected_tokens,
                "predicted_tokens": predicted_tokens,
                "matched": matched,
                "fragment_count": len(predicted_tokens),
            }
        )
    component_total = max(1, len(component_rows))
    token_total = max(1, token_total)
    return {
        "component_rows": component_rows,
        "component_accuracy": matched_component_count / component_total,
        "token_recall": token_hit_count / token_total,
        "trace_fragment_count": len(trace_entries),
        "fragmented_component_count": fragmented_component_count,
    }


def visible_component_subset(components: dict[str, str], keys: tuple[str, ...]) -> dict[str, str]:
    return {
        key: components[key]
        for key in keys
        if compact_text(components.get(key, ""))
    }


def render_address_core(
    components: dict[str, str],
    *,
    state_full_name: bool = False,
    include_country: str | None = None,
    locality_only: bool = False,
    inline_detail: bool = False,
    detached_detail: bool = False,
    front_poi: bool = False,
    front_building: bool = False,
    omit_commas: bool = False,
    drop_auxiliary: bool = False,
) -> str:
    state = state_code_to_name(components.get("province", "")) if state_full_name else components.get("province", "")
    city = components.get("city", "")
    road = components.get("road", "")
    number = components.get("number", "")
    poi = "" if drop_auxiliary else components.get("poi", "")
    building = "" if drop_auxiliary else components.get("building", "")
    detail = "" if drop_auxiliary else components.get("detail", "")
    zip_text = detail if looks_like_zip(detail) else ""
    unit_text = "" if zip_text else detail

    if locality_only:
        locality = ", ".join(part for part in (city, state) if part)
        if include_country:
            locality = ", ".join(part for part in (locality, include_country) if part)
        return locality

    street_segment = " ".join(part for part in (number, road) if part)
    line_segments: list[str] = []
    if front_poi and poi:
        line_segments.append(poi)
        poi = ""
    if front_building and building:
        line_segments.append(building)
        building = ""
    if detached_detail and unit_text:
        line_segments.append(unit_text)
        unit_text = ""
    if street_segment:
        if inline_detail and unit_text:
            street_segment = f"{street_segment} {unit_text}"
            unit_text = ""
        line_segments.append(street_segment)
    if building:
        line_segments.append(building)
    if poi:
        line_segments.append(poi)
    if unit_text:
        line_segments.append(unit_text)

    state_postal = " ".join(part for part in (state, zip_text) if part)
    locality = ", ".join(part for part in (city, state_postal) if part)
    if include_country:
        locality = ", ".join(part for part in (locality, include_country) if part)

    if omit_commas:
        parts = [part for part in (" ".join(line_segments).strip(), city, state, zip_text, include_country) if part]
        return " ".join(parts)
    joined = ", ".join(part for part in (" ".join(line_segments).strip(), locality) if part)
    return joined


def add_variant_candidate(
    registry: dict[tuple[Any, ...], dict[str, Any]],
    *,
    text: str,
    components: dict[str, str],
    format_name: str,
    ops: list[str],
    weight: float,
) -> None:
    normalized_ops = list(dict.fromkeys(op for op in ops if op))
    if not normalized_ops or not text.strip():
        return
    key = (
        format_name,
        text,
        tuple((name, components.get(name, "")) for name in ADDRESS_COMPONENT_KEYS if compact_text(components.get(name, ""))),
    )
    payload = {
        "text": text,
        "components": dict(components),
        "format": format_name,
        "variant_ops": normalized_ops,
        "weight": float(weight),
    }
    existing = registry.get(key)
    if existing is None or payload["weight"] > existing["weight"]:
        registry[key] = payload


def build_reasonable_address_variant_candidates(row: dict[str, Any]) -> list[dict[str, Any]]:
    registry: dict[tuple[Any, ...], dict[str, Any]] = {}
    base = dict(row["components"])

    add_variant_candidate(
        registry,
        text=render_address_core(base, locality_only=True),
        components=visible_component_subset(base, ("city", "province")),
        format_name="semantic_locality_only",
        ops=["semantic_locality_only"],
        weight=0.14,
    )

    add_variant_candidate(
        registry,
        text=render_address_core(base, drop_auxiliary=True),
        components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
        format_name="semantic_core",
        ops=["semantic_core"],
        weight=0.16,
    )

    add_variant_candidate(
        registry,
        text=render_address_core(base, state_full_name=True, drop_auxiliary=True),
        components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
        format_name="semantic_state_full_name",
        ops=["semantic_state_full_name"],
        weight=0.18,
    )

    add_variant_candidate(
        registry,
        text=render_address_core(base, include_country="USA", drop_auxiliary=True),
        components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
        format_name="semantic_country_appended",
        ops=["semantic_country_appended"],
        weight=0.14,
    )

    add_variant_candidate(
        registry,
        text=render_address_core(base, omit_commas=True, drop_auxiliary=True),
        components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
        format_name="semantic_no_comma",
        ops=["semantic_no_comma"],
        weight=0.12,
    )

    if base.get("detail") and not looks_like_zip(base.get("detail", "")):
        add_variant_candidate(
            registry,
            text=render_address_core(base, inline_detail=True),
            components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
            format_name="semantic_unit_inline",
            ops=["semantic_unit_inline"],
            weight=0.16,
        )
        add_variant_candidate(
            registry,
            text=render_address_core(base, detached_detail=True),
            components=visible_component_subset(base, ("city", "province", "road", "number", "detail")),
            format_name="semantic_unit_detached",
            ops=["semantic_unit_detached"],
            weight=0.10,
        )

    if base.get("poi"):
        add_variant_candidate(
            registry,
            text=render_address_core(base, front_poi=True),
            components=visible_component_subset(base, ("city", "province", "road", "number", "poi", "detail")),
            format_name="semantic_poi_fronted",
            ops=["semantic_poi_fronted"],
            weight=0.12,
        )

    if base.get("building"):
        add_variant_candidate(
            registry,
            text=render_address_core(base, front_building=True),
            components=visible_component_subset(base, ("city", "province", "road", "number", "building", "detail")),
            format_name="semantic_building_fronted",
            ops=["semantic_building_fronted"],
            weight=0.12,
        )

    return [candidate for candidate in registry.values() if candidate["text"].strip()]


def generate_addresses(count: int, seed: int) -> list[dict[str, Any]]:
    generator_namespace = runpy.run_path(str(DATA_DIR / "generate_data.py"))
    en_record = generator_namespace["_en_record"]
    random.seed(seed)
    return [dict(en_record(index)) for index in range(1, count + 1)]


def generate_address_variants(rows: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    variants: list[dict[str, Any]] = []
    for row in rows:
        original_components = dict(row["components"])
        candidates = build_reasonable_address_variant_candidates(row)
        if candidates:
            weights = [float(candidate["weight"]) for candidate in candidates]
            selected = rng.choices(candidates, weights=weights, k=1)[0]
            text = str(selected["text"])
            ops = list(selected["variant_ops"])
            format_name = str(selected["format"])
            visible_components = dict(selected["components"])
        else:
            text = str(row["text"])
            ops = ["format_preserved"]
            format_name = str(row["format"])
            visible_components = dict(original_components)
        variants.append(
            {
                "id": row["id"],
                "locale": row["locale"],
                "text": text,
                "format": format_name,
                "source_format": row["format"],
                "components": visible_components,
                "reference_components": original_components,
                "variant_ops": ops,
            }
        )
    return variants


def evaluate_address_row(detector: RuleBasedPIIDetector, row: dict[str, Any], label: str) -> dict[str, Any]:
    text = str(row["text"])
    predictions, candidates, elapsed_ms = detect_text(detector, text)
    address_predictions = [
        {
            "prediction_index": prediction.prediction_index,
            "entity_type": prediction.entity_type,
            "start": prediction.start,
            "end": prediction.end,
            "text": prediction.text,
        }
        for prediction in predictions
        if prediction.entity_type == "address" and interval_overlap(0, len(text), prediction.start, prediction.end) > 0
    ]
    address_candidates = [
        candidate
        for candidate in candidates
        if candidate.attr_type.value == "address" and interval_overlap(0, len(text), int(candidate.span_start or 0), int(candidate.span_end or 0)) > 0
    ]
    exact_complete = any(prediction["start"] <= 0 and prediction["end"] >= len(text) for prediction in address_predictions)
    exact_fragment = bool(address_predictions) and not exact_complete
    scoring_components = dict(row["components"])
    reference_components = dict(row.get("reference_components", row["components"]))
    component_eval = evaluate_address_components(scoring_components, address_candidates)
    return {
        "split": label,
        "id": int(row["id"]),
        "format": row["format"],
        "source_format": row.get("source_format", row["format"]),
        "text": text,
        "text_length": len(text),
        "variant_ops": list(row.get("variant_ops", [])),
        "prediction_count": len(predictions),
        "address_prediction_count": len(address_predictions),
        "status": "exact_complete" if exact_complete else ("exact_fragment" if exact_fragment else "miss"),
        "coverage_ratio": coverage_ratio(0, len(text), address_predictions),
        "piece_count": 1 if exact_complete else len(address_predictions),
        "latency_ms": elapsed_ms,
        "component_accuracy": component_eval["component_accuracy"],
        "component_token_recall": component_eval["token_recall"],
        "trace_fragment_count": component_eval["trace_fragment_count"],
        "fragmented_component_count": component_eval["fragmented_component_count"],
        "component_rows": component_eval["component_rows"],
        "predicted_trace": [
            trace
            for candidate in address_candidates
            for trace in candidate.metadata.get("address_component_trace", [])
        ],
        "gt_components": scoring_components,
        "reference_components": reference_components,
    }


def summarize_address_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    status_counter = Counter(row["status"] for row in rows)
    total = len(rows)
    by_component: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_format: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_variant_op: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_format[row["format"]].append(row)
        for component_row in row["component_rows"]:
            by_component[component_row["component_type"]].append(component_row)
        for op in row.get("variant_ops", []):
            by_variant_op[op].append(row)

    component_summary = {}
    for component_type, component_rows in by_component.items():
        component_summary[component_type] = {
            "count": len(component_rows),
            "match_rate": (
                sum(1 for component_row in component_rows if component_row["matched"]) / len(component_rows)
                if component_rows
                else 0.0
            ),
            "mean_fragment_count": (
                sum(component_row["fragment_count"] for component_row in component_rows) / len(component_rows)
                if component_rows
                else 0.0
            ),
            "fragmented_rate": (
                sum(1 for component_row in component_rows if component_row["fragment_count"] > 1) / len(component_rows)
                if component_rows
                else 0.0
            ),
        }

    format_summary = {}
    for format_name, format_rows in by_format.items():
        format_summary[format_name] = {
            "count": len(format_rows),
            "exact_complete_rate": (
                sum(1 for format_row in format_rows if format_row["status"] == "exact_complete") / len(format_rows)
            ),
            "component_accuracy_mean": (
                sum(format_row["component_accuracy"] for format_row in format_rows) / len(format_rows)
            ),
        }

    variant_op_summary = {}
    for op_name, op_rows in by_variant_op.items():
        variant_op_summary[op_name] = {
            "count": len(op_rows),
            "exact_complete_rate": sum(1 for op_row in op_rows if op_row["status"] == "exact_complete") / len(op_rows),
        }

    return {
        "count": total,
        "status_counter": dict(status_counter),
        "exact_complete_rate": status_counter.get("exact_complete", 0) / total if total else 0.0,
        "exact_fragment_rate": status_counter.get("exact_fragment", 0) / total if total else 0.0,
        "miss_rate": status_counter.get("miss", 0) / total if total else 0.0,
        "component_accuracy_mean": (sum(row["component_accuracy"] for row in rows) / total) if rows else 0.0,
        "component_token_recall_mean": (
            sum(row["component_token_recall"] for row in rows) / total if rows else 0.0
        ),
        "coverage_ratio_mean": (sum(row["coverage_ratio"] for row in rows) / total) if rows else 0.0,
        "trace_fragment_count_mean": (sum(row["trace_fragment_count"] for row in rows) / total) if rows else 0.0,
        "fragmented_component_count_mean": (
            sum(row["fragmented_component_count"] for row in rows) / total if rows else 0.0
        ),
        "latency_ms": summarize_numeric([row["latency_ms"] for row in rows]),
        "per_component": component_summary,
        "per_format": format_summary,
        "per_variant_op": variant_op_summary,
    }


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_summary_markdown(summary: dict[str, Any]) -> str:
    original = summary["synthetic"]["original_summary"]
    variant = summary["synthetic"]["variant_summary"]
    component_keys = sorted(
        set(original["per_component"]).union(variant["per_component"]),
        key=lambda key: ADDRESS_COMPONENT_KEYS.index(key) if key in ADDRESS_COMPONENT_KEYS else 999,
    )
    lines = [
        "# 英文合成地址评估摘要",
        "",
        "## 运行设置",
        f"- detector 初始化耗时：{summary['detector_init_ms']:.2f} ms",
        f"- 地址样本数：{summary['synthetic']['address_count']}",
        "",
        "## 主指标",
        markdown_table(
            ["集合", "完整召回率", "碎片召回率", "漏检率", "组件准确率", "组件 token 召回", "平均碎片数", "平均耗时(ms)"],
            [
                [
                    "原始地址",
                    f"{original['exact_complete_rate']:.4f}",
                    f"{original['exact_fragment_rate']:.4f}",
                    f"{original['miss_rate']:.4f}",
                    f"{original['component_accuracy_mean']:.4f}",
                    f"{original['component_token_recall_mean']:.4f}",
                    f"{original['trace_fragment_count_mean']:.4f}",
                    f"{original['latency_ms']['mean']:.3f}",
                ],
                [
                    "随机变体",
                    f"{variant['exact_complete_rate']:.4f}",
                    f"{variant['exact_fragment_rate']:.4f}",
                    f"{variant['miss_rate']:.4f}",
                    f"{variant['component_accuracy_mean']:.4f}",
                    f"{variant['component_token_recall_mean']:.4f}",
                    f"{variant['trace_fragment_count_mean']:.4f}",
                    f"{variant['latency_ms']['mean']:.3f}",
                ],
            ],
        ),
        "",
        "## 组件准确率",
        markdown_table(
            ["组件", "原始命中率", "变体命中率", "原始平均碎片", "变体平均碎片"],
            [
                [
                    component,
                    f"{original['per_component'].get(component, {}).get('match_rate', 0.0):.4f}",
                    f"{variant['per_component'].get(component, {}).get('match_rate', 0.0):.4f}",
                    f"{original['per_component'].get(component, {}).get('mean_fragment_count', 0.0):.4f}",
                    f"{variant['per_component'].get(component, {}).get('mean_fragment_count', 0.0):.4f}",
                ]
                for component in component_keys
            ],
        ),
        "",
        "## 变体操作",
        markdown_table(
            ["操作", "数量", "完整召回率"],
            [
                [
                    op_name,
                    str(op_summary["count"]),
                    f"{op_summary['exact_complete_rate']:.4f}",
                ]
                for op_name, op_summary in sorted(
                    variant["per_variant_op"].items(),
                    key=lambda item: (-item[1]["count"], item[0]),
                )
            ],
        ),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    detector, detector_init_ms = detector_build()
    detector.detect("1234 Main Street, Seattle, WA 98101", [])

    address_rows = generate_addresses(int(args.address_count), int(args.address_seed))
    variant_rows = generate_address_variants(address_rows, int(args.variant_seed))

    original_address_details = [evaluate_address_row(detector, row, "original") for row in address_rows]
    variant_address_details = [evaluate_address_row(detector, row, "variant") for row in variant_rows]
    original_address_summary = summarize_address_rows(original_address_details)
    variant_address_summary = summarize_address_rows(variant_address_details)

    summary = {
        "detector_init_ms": detector_init_ms,
        "synthetic": {
            "address_count": int(args.address_count),
            "address_seed": int(args.address_seed),
            "variant_seed": int(args.variant_seed),
            "original_summary": original_address_summary,
            "variant_summary": variant_address_summary,
        },
    }

    write_json(output_dir / "summary.json", summary)
    write_jsonl(output_dir / "address_original_details.jsonl", original_address_details)
    write_jsonl(output_dir / "address_variant_details.jsonl", variant_address_details)
    (output_dir / "summary.md").write_text(build_summary_markdown(summary), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "synthetic_original_exact_complete_rate": original_address_summary["exact_complete_rate"],
                "synthetic_variant_exact_complete_rate": variant_address_summary["exact_complete_rate"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
