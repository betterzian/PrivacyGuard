"""中文 detector 论文评估脚本。

评估分三部分：
1. 用 `data/generate_data.py` 的中文地址生成器构造 1000 条地址，并评估原始地址检测。
2. 基于同一批地址生成随机表面变体，评估鲁棒性、组件命中与碎片化。
3. 用两个 1200 条中文数据集做样例级 PII 检测评估，并输出按类型与按样例汇总。
"""

from __future__ import annotations

import argparse
import json
import random
import re
import runpy
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "tmp" / "eval_detector_zh_paper"

ADDRESS_COUNT_DEFAULT = 1000
ADDRESS_SEED_DEFAULT = 42
VARIANT_SEED_DEFAULT = 20260421

TAG_PATTERN = re.compile(r"【PII:([A-Z_]+):(\d+)】(.*?)【/PII】", re.S)
GENERIC_DETECTOR_TYPES = {"num", "alnum"}
ADDRESS_COMPONENT_KEYS = (
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
DATASET_TYPE_TO_DETECTOR: dict[str, str] = {
    "NAME": "name",
    "PHONE": "phone",
    "ORG": "organization",
    "EMAIL": "email",
    "ADDRESS": "address",
    "LICENSE_PLATE": "license_plate",
    "TIME": "time",
    "AMOUNT": "amount",
    "ID_CARD": "id_number",
    "BANK_CARD": "bank_number",
    "PASSPORT_NUMBER": "passport_number",
    "DRIVER_LICENSE": "driver_license",
}
TYPE_DISPLAY_ORDER = (
    "ADDRESS",
    "NAME",
    "PHONE",
    "ORG",
    "ID_CARD",
    "EMAIL",
    "TIME",
    "ORDER_ID",
    "MEMBER_ID",
    "BANK_CARD",
    "TRACKING_ID",
    "BIRTHDAY",
    "ACCOUNT_ID",
    "LICENSE_PLATE",
    "AMOUNT",
)
SUFFIX_PATTERNS: dict[str, tuple[str, ...]] = {
    "province": ("特别行政区", "自治区", "省", "市"),
    "city": ("自治州", "地区", "盟", "市"),
    "district": ("自治县", "新区", "开发区", "区", "县", "市"),
    "subdistrict": ("街道", "镇", "乡"),
    "road": ("大道", "大街", "路", "街", "巷", "道"),
    "poi": ("社区", "大厦", "中心", "家园", "园区"),
    "number": ("号",),
    "building": ("号楼", "栋", "座"),
}
DETAIL_TOKEN_PATTERN = re.compile(r"[A-Za-z]+|\d+")
MATCH_FAMILY_PRIORITY = ("exact_type", "generic_numeric", "wrong_type")
MATCH_FAMILY_FIELD_MAP = {
    "exact_type": "exact_coverage_ratio",
    "generic_numeric": "generic_coverage_ratio",
    "wrong_type": "wrong_type_coverage_ratio",
    "any_type": "any_coverage_ratio",
}
COVERAGE_THRESHOLD_SPECS = (
    ("complete", 1.0),
    ("hit_50", 0.5),
    ("hit_any", 0.0),
)


@dataclass(slots=True)
class TaggedEntity:
    """去标签后样例中的单个 GT 实体。"""

    sample_id: str
    occurrence_index: int
    entity_type: str
    value: str
    start: int
    end: int
    exact_detector_type: str | None
    evaluation_weight: float
    optional_pii: bool
    derived_optional: bool
    must_hide: bool
    annotation_importance: str
    relation_role: str
    canonical_slot: str


@dataclass(slots=True)
class PredictionSpan:
    """detector 产出的预测 span。"""

    prediction_index: int
    entity_type: str
    text: str
    start: int
    end: int
    metadata: dict[str, list[str]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="评估中文 detector 在地址合成集与 1200 样本基准上的表现。")
    parser.add_argument("--address-count", type=int, default=ADDRESS_COUNT_DEFAULT, help="生成地址条数。")
    parser.add_argument("--address-seed", type=int, default=ADDRESS_SEED_DEFAULT, help="地址生成随机种子。")
    parser.add_argument("--variant-seed", type=int, default=VARIANT_SEED_DEFAULT, help="地址变体随机种子。")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="输出目录。")
    return parser.parse_args()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def normalize_for_alignment(text: str) -> str:
    return re.sub(r"\s+", "", str(text or ""))


def compact_text(text: str) -> str:
    return "".join(str(text or "").split())


def strip_suffix(component_type: str, value: str) -> str:
    text = compact_text(value)
    if not text:
        return ""
    for suffix in SUFFIX_PATTERNS.get(component_type, ()):
        if text.endswith(suffix):
            return text[: -len(suffix)] or text
    return text


def detail_tokens(value: str) -> list[str]:
    tokens = DETAIL_TOKEN_PATTERN.findall(compact_text(value))
    return [token.upper() for token in tokens if token]


def component_expected_tokens(component_type: str, value: str) -> list[str]:
    if component_type == "detail":
        return detail_tokens(value)
    stripped = strip_suffix(component_type, value)
    return [stripped.upper() if stripped else ""]


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


def summarize_numeric(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
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


def weighted_rate(rows: list[dict[str, Any]], *, numerator_statuses: set[str], field: str = "evaluation_weight") -> float:
    total_weight = sum(float(row.get(field, 0.0) or 0.0) for row in rows)
    if total_weight <= 0:
        return 0.0
    hit_weight = sum(float(row.get(field, 0.0) or 0.0) for row in rows if row["status"] in numerator_statuses)
    return hit_weight / total_weight


def weighted_boolean_rate(rows: list[dict[str, Any]], *, predicate: Any, field: str = "evaluation_weight") -> float:
    total_weight = sum(float(row.get(field, 0.0) or 0.0) for row in rows)
    if total_weight <= 0:
        return 0.0
    hit_weight = sum(float(row.get(field, 0.0) or 0.0) for row in rows if predicate(row))
    return hit_weight / total_weight


def coverage_meets_threshold(value: float, threshold: float) -> bool:
    numeric_value = float(value or 0.0)
    epsilon = 1e-9
    if threshold >= 1.0:
        return numeric_value >= 1.0 - epsilon
    if threshold <= 0.0:
        return numeric_value > epsilon
    return numeric_value + epsilon >= threshold


def select_exclusive_family(row: dict[str, Any], threshold: float) -> str:
    for family in MATCH_FAMILY_PRIORITY:
        field = MATCH_FAMILY_FIELD_MAP[family]
        if coverage_meets_threshold(float(row.get(field, 0.0) or 0.0), threshold):
            return family
    return "miss"


def summarize_coverage_matrix(
    rows: list[dict[str, Any]],
    *,
    exact_type_supported: bool | None = None,
) -> dict[str, Any]:
    total = len(rows)
    matrix: dict[str, Any] = {}
    for threshold_name, threshold_value in COVERAGE_THRESHOLD_SPECS:
        exclusive_counter = Counter(select_exclusive_family(row, threshold_value) for row in rows)
        exclusive_rates = {
            family: (exclusive_counter.get(family, 0) / total if total else 0.0)
            for family in (*MATCH_FAMILY_PRIORITY, "miss")
        }
        exclusive_rates["any_hit"] = 1.0 - exclusive_rates["miss"] if total else 0.0
        exclusive_weighted_rates = {
            family: weighted_boolean_rate(
                rows,
                predicate=lambda row, threshold_value=threshold_value, family=family: (
                    select_exclusive_family(row, threshold_value) == family
                ),
            )
            for family in (*MATCH_FAMILY_PRIORITY, "miss")
        }
        exclusive_weighted_rates["any_hit"] = weighted_boolean_rate(
            rows,
            predicate=lambda row, threshold_value=threshold_value: (
                select_exclusive_family(row, threshold_value) != "miss"
            ),
        )

        nonexclusive_rates = {}
        nonexclusive_weighted_rates = {}
        for family, field in MATCH_FAMILY_FIELD_MAP.items():
            nonexclusive_rates[family] = (
                sum(1 for row in rows if coverage_meets_threshold(float(row.get(field, 0.0) or 0.0), threshold_value))
                / total
                if total
                else 0.0
            )
            nonexclusive_weighted_rates[family] = weighted_boolean_rate(
                rows,
                predicate=lambda row, threshold_value=threshold_value, field=field: (
                    coverage_meets_threshold(float(row.get(field, 0.0) or 0.0), threshold_value)
                ),
            )

        if exact_type_supported is False:
            exclusive_rates["exact_type"] = None
            exclusive_weighted_rates["exact_type"] = None
            nonexclusive_rates["exact_type"] = None
            nonexclusive_weighted_rates["exact_type"] = None

        matrix[threshold_name] = {
            "threshold_value": threshold_value,
            "count": total,
            "exclusive_rate_by_family": exclusive_rates,
            "exclusive_weighted_rate_by_family": exclusive_weighted_rates,
            "nonexclusive_rate_by_family": nonexclusive_rates,
            "nonexclusive_weighted_rate_by_family": nonexclusive_weighted_rates,
        }
    return matrix


def detector_build() -> tuple[RuleBasedPIIDetector, float]:
    started = time.perf_counter()
    detector = RuleBasedPIIDetector(locale_profile="zh_cn")
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


def strip_pii_tags(text_with_tags: str) -> tuple[str, list[dict[str, Any]]]:
    plain_parts: list[str] = []
    entities: list[dict[str, Any]] = []
    cursor = 0
    plain_cursor = 0
    for occurrence_index, match in enumerate(TAG_PATTERN.finditer(text_with_tags), start=1):
        prefix = text_with_tags[cursor : match.start()]
        plain_parts.append(prefix)
        plain_cursor += len(prefix)
        entity_value = match.group(3)
        entity_start = plain_cursor
        entity_end = entity_start + len(entity_value)
        plain_parts.append(entity_value)
        plain_cursor = entity_end
        entities.append(
            {
                "occurrence_index": occurrence_index,
                "entity_type": match.group(1),
                "value": entity_value,
                "start": entity_start,
                "end": entity_end,
                "tag_id": match.group(2),
            }
        )
        cursor = match.end()
    plain_parts.append(text_with_tags[cursor:])
    return "".join(plain_parts), entities


def merge_entities_with_inventory(
    sample_id: str,
    parsed_entities: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
) -> tuple[list[TaggedEntity], list[dict[str, Any]]]:
    merged: list[TaggedEntity] = []
    mismatches: list[dict[str, Any]] = []
    used_indices: set[int] = set()
    for parsed_index, parsed in enumerate(parsed_entities):
        matched_index: int | None = None
        if parsed_index < len(inventory):
            candidate = inventory[parsed_index]
            if (
                candidate.get("type") == parsed["entity_type"]
                and normalize_for_alignment(candidate.get("value", "")) == normalize_for_alignment(parsed["value"])
            ):
                matched_index = parsed_index
        if matched_index is None:
            for inventory_index, candidate in enumerate(inventory):
                if inventory_index in used_indices:
                    continue
                if (
                    candidate.get("type") == parsed["entity_type"]
                    and normalize_for_alignment(candidate.get("value", "")) == normalize_for_alignment(parsed["value"])
                ):
                    matched_index = inventory_index
                    break
        if matched_index is None:
            candidate = inventory[parsed_index] if parsed_index < len(inventory) else {}
            mismatches.append(
                {
                    "sample_id": sample_id,
                    "occurrence_index": parsed["occurrence_index"],
                    "reason": "inventory_alignment_failed",
                    "parsed_type": parsed["entity_type"],
                    "parsed_value": parsed["value"],
                    "inventory_type": candidate.get("type"),
                    "inventory_value": candidate.get("value"),
                }
            )
        else:
            used_indices.add(matched_index)
            candidate = inventory[matched_index]
        merged.append(
            TaggedEntity(
                sample_id=sample_id,
                occurrence_index=int(parsed["occurrence_index"]),
                entity_type=str(candidate.get("type") or parsed["entity_type"]),
                value=str(candidate.get("value") or parsed["value"]),
                start=int(parsed["start"]),
                end=int(parsed["end"]),
                exact_detector_type=DATASET_TYPE_TO_DETECTOR.get(str(candidate.get("type") or parsed["entity_type"])),
                evaluation_weight=float(candidate.get("evaluation_weight", 0.0) or 0.0),
                optional_pii=bool(candidate.get("optional_pii", False)),
                derived_optional=bool(candidate.get("derived_optional", False)),
                must_hide=bool(candidate.get("must_hide", False)),
                annotation_importance=str(candidate.get("annotation_importance", "")),
                relation_role=str(candidate.get("relation_role", "")),
                canonical_slot=str(candidate.get("canonical_slot", "")),
            )
        )
    if len(parsed_entities) != len(inventory):
        mismatches.append(
            {
                "sample_id": sample_id,
                "reason": "inventory_count_mismatch",
                "parsed_count": len(parsed_entities),
                "inventory_count": len(inventory),
            }
        )
    return merged, mismatches


def evaluate_gt_entity(entity: TaggedEntity, predictions: list[PredictionSpan]) -> dict[str, Any]:
    entity_length = max(1, entity.end - entity.start)
    exact_predictions: list[dict[str, Any]] = []
    generic_predictions: list[dict[str, Any]] = []
    wrong_type_predictions: list[dict[str, Any]] = []
    for prediction in predictions:
        overlap = interval_overlap(entity.start, entity.end, prediction.start, prediction.end)
        if overlap <= 0:
            continue
        record = {
            "prediction_index": prediction.prediction_index,
            "entity_type": prediction.entity_type,
            "start": prediction.start,
            "end": prediction.end,
            "text": prediction.text,
            "overlap_chars": overlap,
            "overlap_ratio": overlap / entity_length,
        }
        if entity.exact_detector_type and prediction.entity_type == entity.exact_detector_type:
            exact_predictions.append(record)
            continue
        if prediction.entity_type in GENERIC_DETECTOR_TYPES:
            generic_predictions.append(record)
            continue
        wrong_type_predictions.append(record)
    exact_complete = any(
        prediction["start"] <= entity.start and prediction["end"] >= entity.end for prediction in exact_predictions
    )
    exact_coverage = coverage_ratio(entity.start, entity.end, exact_predictions)
    generic_coverage = coverage_ratio(entity.start, entity.end, generic_predictions)
    wrong_type_coverage = coverage_ratio(entity.start, entity.end, wrong_type_predictions)
    any_coverage = coverage_ratio(entity.start, entity.end, exact_predictions + generic_predictions + wrong_type_predictions)
    accepted_predictions = exact_predictions if exact_predictions else generic_predictions
    accepted_coverage = coverage_ratio(entity.start, entity.end, accepted_predictions)
    if exact_complete:
        status = "exact_complete"
        piece_count = 1
    elif exact_predictions:
        status = "exact_fragment"
        piece_count = len(exact_predictions)
    elif generic_predictions:
        status = "generic_only"
        piece_count = len(generic_predictions)
    else:
        status = "miss"
        piece_count = 0
    return {
        "sample_id": entity.sample_id,
        "occurrence_index": entity.occurrence_index,
        "entity_type": entity.entity_type,
        "exact_detector_type": entity.exact_detector_type,
        "value": entity.value,
        "start": entity.start,
        "end": entity.end,
        "length": entity_length,
        "status": status,
        "piece_count": piece_count,
        "exact_match_count": len(exact_predictions),
        "generic_match_count": len(generic_predictions),
        "wrong_type_overlap_count": len(wrong_type_predictions),
        "exact_coverage_ratio": exact_coverage,
        "generic_coverage_ratio": generic_coverage,
        "wrong_type_coverage_ratio": wrong_type_coverage,
        "any_coverage_ratio": any_coverage,
        "accepted_coverage_ratio": accepted_coverage,
        "matched_prediction_indices": [prediction["prediction_index"] for prediction in accepted_predictions],
        "matched_prediction_types": [prediction["entity_type"] for prediction in accepted_predictions],
        "evaluation_weight": entity.evaluation_weight,
        "optional_pii": entity.optional_pii,
        "derived_optional": entity.derived_optional,
        "must_hide": entity.must_hide,
        "annotation_importance": entity.annotation_importance,
        "relation_role": entity.relation_role,
        "canonical_slot": entity.canonical_slot,
    }


def classify_prediction(prediction: PredictionSpan, entities: list[TaggedEntity]) -> dict[str, Any]:
    overlapping = [
        entity
        for entity in entities
        if interval_overlap(prediction.start, prediction.end, entity.start, entity.end) > 0
    ]
    if not overlapping:
        label = "background_fp"
        matched_types: list[str] = []
    elif prediction.entity_type in GENERIC_DETECTOR_TYPES:
        label = "generic_overlap"
        matched_types = sorted({entity.entity_type for entity in overlapping})
    elif any(entity.exact_detector_type == prediction.entity_type for entity in overlapping if entity.exact_detector_type):
        label = "exact_overlap"
        matched_types = sorted({entity.entity_type for entity in overlapping})
    else:
        label = "wrong_type_overlap"
        matched_types = sorted({entity.entity_type for entity in overlapping})
    return {
        "prediction_index": prediction.prediction_index,
        "entity_type": prediction.entity_type,
        "start": prediction.start,
        "end": prediction.end,
        "text": prediction.text,
        "label": label,
        "matched_entity_types": matched_types,
    }


def evaluate_dataset_sample(
    sample: dict[str, Any],
    predictions: list[PredictionSpan],
    elapsed_ms: float,
    entity_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    entity_counter = Counter(row["status"] for row in entity_rows)
    prediction_rows = [classify_prediction(prediction, sample["entities"]) for prediction in predictions]
    prediction_counter = Counter(row["label"] for row in prediction_rows)
    entity_count = max(1, len(entity_rows))
    return {
        "sample_id": sample["sample_id"],
        "scene": sample["scene"],
        "category": sample["category"],
        "difficulty": sample["difficulty"],
        "privacy_density": sample["privacy_density"],
        "challenge_tags": list(sample.get("challenge_tags", [])),
        "entity_count": len(entity_rows),
        "exact_complete_count": entity_counter.get("exact_complete", 0),
        "exact_fragment_count": entity_counter.get("exact_fragment", 0),
        "generic_count": entity_counter.get("generic_only", 0),
        "miss_count": entity_counter.get("miss", 0),
        "exact_coverage_mean": (
            sum(row["exact_coverage_ratio"] for row in entity_rows) / entity_count if entity_rows else 0.0
        ),
        "generic_coverage_mean": (
            sum(row["generic_coverage_ratio"] for row in entity_rows) / entity_count if entity_rows else 0.0
        ),
        "wrong_type_coverage_mean": (
            sum(row["wrong_type_coverage_ratio"] for row in entity_rows) / entity_count if entity_rows else 0.0
        ),
        "any_coverage_mean": (sum(row["any_coverage_ratio"] for row in entity_rows) / entity_count if entity_rows else 0.0),
        "accepted_coverage_mean": (
            sum(row["accepted_coverage_ratio"] for row in entity_rows) / entity_count if entity_rows else 0.0
        ),
        "prediction_count": len(predictions),
        "exact_prediction_count": prediction_counter.get("exact_overlap", 0),
        "generic_prediction_count": prediction_counter.get("generic_overlap", 0),
        "wrong_type_prediction_count": prediction_counter.get("wrong_type_overlap", 0),
        "background_fp_count": prediction_counter.get("background_fp", 0),
        "latency_ms": elapsed_ms,
    }


def summarize_entity_table(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    status_counter = Counter(row["status"] for row in rows)
    per_type: dict[str, Any] = {}
    type_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        type_groups[row["entity_type"]].append(row)
    supported_exact_rows = [row for row in rows if row.get("exact_detector_type")]
    unsupported_exact_rows = [row for row in rows if not row.get("exact_detector_type")]
    unsupported_exact_type_counter = Counter(row["entity_type"] for row in unsupported_exact_rows)
    for entity_type in TYPE_DISPLAY_ORDER:
        group = type_groups.get(entity_type, [])
        if not group:
            continue
        group_count = len(group)
        group_counter = Counter(row["status"] for row in group)
        fragment_piece_values = [row["piece_count"] for row in group if row["status"] in {"exact_fragment", "generic_only"}]
        coverage_values = [row["accepted_coverage_ratio"] for row in group]
        support_exact_type = DATASET_TYPE_TO_DETECTOR.get(entity_type) is not None
        per_type[entity_type] = {
            "count": group_count,
            "exact_complete_rate": group_counter.get("exact_complete", 0) / group_count,
            "exact_fragment_rate": group_counter.get("exact_fragment", 0) / group_count,
            "generic_only_rate": group_counter.get("generic_only", 0) / group_count,
            "miss_rate": group_counter.get("miss", 0) / group_count,
            "mean_accepted_coverage_ratio": sum(coverage_values) / group_count,
            "mean_exact_coverage_ratio": sum(row["exact_coverage_ratio"] for row in group) / group_count,
            "mean_generic_coverage_ratio": sum(row["generic_coverage_ratio"] for row in group) / group_count,
            "mean_wrong_type_coverage_ratio": sum(row["wrong_type_coverage_ratio"] for row in group) / group_count,
            "mean_any_coverage_ratio": sum(row["any_coverage_ratio"] for row in group) / group_count,
            "weighted_exact_complete_rate": weighted_rate(group, numerator_statuses={"exact_complete"}),
            "weighted_exact_or_generic_rate": weighted_rate(
                group, numerator_statuses={"exact_complete", "exact_fragment", "generic_only"}
            ),
            "mean_fragment_piece_count_on_non_complete": (
                sum(fragment_piece_values) / len(fragment_piece_values) if fragment_piece_values else 0.0
            ),
            "support_exact_type": support_exact_type,
            "coverage_matrix": summarize_coverage_matrix(group, exact_type_supported=support_exact_type),
        }
    must_hide_rows = [row for row in rows if row["must_hide"]]
    high_importance_rows = [row for row in rows if row["annotation_importance"] == "high"]
    return {
        "entity_count": total,
        "supported_exact_type_count": len(supported_exact_rows),
        "unsupported_exact_type_count": len(unsupported_exact_rows),
        "unsupported_exact_type_breakdown": dict(unsupported_exact_type_counter),
        "status_counter": dict(status_counter),
        "exact_complete_rate": status_counter.get("exact_complete", 0) / total if total else 0.0,
        "exact_fragment_rate": status_counter.get("exact_fragment", 0) / total if total else 0.0,
        "generic_only_rate": status_counter.get("generic_only", 0) / total if total else 0.0,
        "miss_rate": status_counter.get("miss", 0) / total if total else 0.0,
        "mean_exact_coverage_ratio": (sum(row["exact_coverage_ratio"] for row in rows) / total if total else 0.0),
        "mean_generic_coverage_ratio": (sum(row["generic_coverage_ratio"] for row in rows) / total if total else 0.0),
        "mean_wrong_type_coverage_ratio": (
            sum(row["wrong_type_coverage_ratio"] for row in rows) / total if total else 0.0
        ),
        "mean_any_coverage_ratio": (sum(row["any_coverage_ratio"] for row in rows) / total if total else 0.0),
        "mean_accepted_coverage_ratio": (
            sum(row["accepted_coverage_ratio"] for row in rows) / total if total else 0.0
        ),
        "weighted_exact_complete_rate": weighted_rate(rows, numerator_statuses={"exact_complete"}),
        "weighted_exact_or_generic_rate": weighted_rate(
            rows, numerator_statuses={"exact_complete", "exact_fragment", "generic_only"}
        ),
        "coverage_matrix": {
            "all_entities": summarize_coverage_matrix(rows),
            "supported_exact_only": summarize_coverage_matrix(supported_exact_rows, exact_type_supported=True),
        },
        "must_hide_exact_complete_rate": (
            sum(1 for row in must_hide_rows if row["status"] == "exact_complete") / len(must_hide_rows)
            if must_hide_rows
            else 0.0
        ),
        "high_importance_exact_complete_rate": (
            sum(1 for row in high_importance_rows if row["status"] == "exact_complete") / len(high_importance_rows)
            if high_importance_rows
            else 0.0
        ),
        "per_type": per_type,
    }


def summarize_sample_table(rows: list[dict[str, Any]]) -> dict[str, Any]:
    latency_values = [row["latency_ms"] for row in rows]
    return {
        "sample_count": len(rows),
        "latency_ms": summarize_numeric(latency_values),
        "mean_entity_count": (sum(row["entity_count"] for row in rows) / len(rows)) if rows else 0.0,
        "mean_background_fp_count": (sum(row["background_fp_count"] for row in rows) / len(rows)) if rows else 0.0,
        "mean_wrong_type_prediction_count": (
            sum(row["wrong_type_prediction_count"] for row in rows) / len(rows)
        )
        if rows
        else 0.0,
        "samples_with_any_miss": sum(1 for row in rows if row["miss_count"] > 0),
        "samples_with_any_background_fp": sum(1 for row in rows if row["background_fp_count"] > 0),
    }


def load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_dataset(detector: RuleBasedPIIDetector, dataset_path: Path, dataset_label: str) -> dict[str, Any]:
    dataset = load_dataset(dataset_path)
    entity_rows: list[dict[str, Any]] = []
    sample_rows: list[dict[str, Any]] = []
    alignment_mismatches: list[dict[str, Any]] = []
    for sample in dataset["samples"]:
        plain_text, parsed_entities = strip_pii_tags(sample["text_with_tags"])
        entities, mismatches = merge_entities_with_inventory(
            str(sample["sample_id"]),
            parsed_entities,
            list(sample["pii_inventory"]),
        )
        alignment_mismatches.extend(mismatches)
        predictions, _candidates, elapsed_ms = detect_text(detector, plain_text)
        sample_entity_rows = [evaluate_gt_entity(entity, predictions) for entity in entities]
        entity_rows.extend(sample_entity_rows)
        sample_rows.append(
            evaluate_dataset_sample(
                {
                    "sample_id": sample["sample_id"],
                    "scene": sample["scene"],
                    "category": sample["category"],
                    "difficulty": sample["difficulty"],
                    "privacy_density": sample["privacy_density"],
                    "challenge_tags": sample.get("challenge_tags", []),
                    "entities": entities,
                },
                predictions,
                elapsed_ms,
                sample_entity_rows,
            )
        )
    entity_summary = summarize_entity_table(entity_rows)
    sample_summary = summarize_sample_table(sample_rows)
    worst_samples = sorted(
        sample_rows,
        key=lambda row: (
            -row["miss_count"],
            -row["wrong_type_prediction_count"],
            -row["background_fp_count"],
            row["accepted_coverage_mean"],
        ),
    )[:20]
    return {
        "label": dataset_label,
        "dataset_name": dataset["dataset_name"],
        "dataset_path": str(dataset_path),
        "entity_summary": entity_summary,
        "sample_summary": sample_summary,
        "worst_samples": worst_samples,
        "entity_rows": entity_rows,
        "sample_rows": sample_rows,
        "alignment_mismatches": alignment_mismatches,
    }


def render_dense_address(components: dict[str, str], *, include_subdistrict: bool) -> str:
    ordered = [
        components.get("province", ""),
        components.get("city", ""),
        components.get("district", ""),
        components.get("subdistrict", "") if include_subdistrict else "",
        components.get("road", ""),
        components.get("number", ""),
        components.get("poi", ""),
        components.get("building", ""),
        components.get("detail", ""),
    ]
    return "".join(part for part in ordered if part)


def render_spaced_address(components: dict[str, str], *, include_subdistrict: bool) -> str:
    admin = [
        components.get("province", ""),
        components.get("city", ""),
        components.get("district", ""),
        components.get("subdistrict", "") if include_subdistrict else "",
    ]
    body = [
        f"{components.get('road', '')}{components.get('number', '')}",
        components.get("poi", ""),
        components.get("building", ""),
        components.get("detail", ""),
    ]
    return " ".join(part for part in (*admin, *body) if part)


def render_reverse_address(components: dict[str, str], *, segmented_admin: bool, separator: str = ",") -> str:
    body = "".join(
        part
        for part in (
            components.get("road", ""),
            components.get("number", ""),
            components.get("poi", ""),
            components.get("building", ""),
            components.get("detail", ""),
        )
        if part
    )
    admin_parts = [components.get("district", ""), components.get("city", ""), components.get("province", "")]
    if segmented_admin:
        admin = separator.join(part for part in admin_parts if part)
    else:
        admin = "".join(part for part in admin_parts if part)
    return f"{body}{separator}{admin}" if admin else body


def visible_component_subset(components: dict[str, str], keys: tuple[str, ...]) -> dict[str, str]:
    return {
        key: components[key]
        for key in keys
        if compact_text(components.get(key, ""))
    }


def short_admin_text(component_type: str, value: str) -> str:
    stripped = strip_suffix(component_type, value)
    return stripped or compact_text(value)


def short_poi_text(value: str) -> str:
    stripped = strip_suffix("poi", value)
    return stripped or compact_text(value)


def compact_building_text(value: str) -> str:
    text = compact_text(value)
    if text.endswith("号楼"):
        return f"{text[:-2]}栋"
    return text


def compact_detail_text(value: str) -> str:
    text = compact_text(value)
    if text.endswith("室"):
        return text[:-1]
    return text


def building_compact_token(value: str) -> str:
    tokens = DETAIL_TOKEN_PATTERN.findall(compact_building_text(value))
    return tokens[0] if tokens else compact_building_text(value)


def render_unit_variant(building: str, detail: str, *, hyphen_room: bool) -> str:
    building_text = compact_building_text(building)
    detail_text = compact_detail_text(detail)
    detail_parts = detail_tokens(detail)
    if hyphen_room and building_text and len(detail_parts) == 1:
        building_token = building_compact_token(building)
        room = detail_parts[0]
        if building_token and room:
            return f"{building_token}-{room}"
    return f"{building_text}{detail_text}"


def semantic_city_district_text(components: dict[str, str]) -> str:
    city = short_admin_text("city", components.get("city", ""))
    district = short_admin_text("district", components.get("district", ""))
    return "".join(part for part in (city, district) if part)


def semantic_forward_prefix(components: dict[str, str]) -> str:
    city = compact_text(components.get("city", ""))
    district = compact_text(components.get("district", ""))
    return "".join(part for part in (city, district) if part)


def semantic_forward_body(
    components: dict[str, str],
    *,
    include_number: bool,
    hyphen_room: bool,
) -> str:
    road = compact_text(components.get("road", ""))
    number = compact_text(components.get("number", "")) if include_number else ""
    poi = short_poi_text(components.get("poi", ""))
    unit = render_unit_variant(components.get("building", ""), components.get("detail", ""), hyphen_room=hyphen_room)
    return "".join(part for part in (road, number, poi, unit) if part)


def semantic_reverse_tail(components: dict[str, str]) -> str:
    district = short_admin_text("district", components.get("district", ""))
    city = short_admin_text("city", components.get("city", ""))
    return "，".join(part for part in (district, city) if part)


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


def build_reasonable_address_variant_candidates(
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    """生成更接近日常表达的语义地址变体。"""
    registry: dict[tuple[Any, ...], dict[str, Any]] = {}
    base_components = dict(row["components"])
    city_district = semantic_city_district_text(base_components)
    if city_district:
        add_variant_candidate(
            registry,
            text=city_district,
            components=visible_component_subset(base_components, ("city", "district")),
            format_name="semantic_area_only",
            ops=["semantic_area_only"],
            weight=0.22,
        )

    forward_prefix = semantic_forward_prefix(base_components)
    if forward_prefix:
        forward_body = semantic_forward_body(base_components, include_number=False, hyphen_room=False)
        if forward_body:
            add_variant_candidate(
                registry,
                text=f"{forward_prefix}{forward_body}",
                components=visible_component_subset(base_components, ("city", "district", "road", "poi", "building", "detail")),
                format_name="semantic_forward",
                ops=["semantic_forward_without_number"],
                weight=0.34,
            )

        forward_body_with_number = semantic_forward_body(base_components, include_number=True, hyphen_room=False)
        if forward_body_with_number:
            add_variant_candidate(
                registry,
                text=f"{forward_prefix}{forward_body_with_number}",
                components=visible_component_subset(
                    base_components,
                    ("city", "district", "road", "number", "poi", "building", "detail"),
                ),
                format_name="semantic_forward",
                ops=["semantic_forward_with_number"],
                weight=0.26,
            )

        hyphen_body = semantic_forward_body(base_components, include_number=False, hyphen_room=True)
        if hyphen_body and hyphen_body != forward_body:
            add_variant_candidate(
                registry,
                text=f"{forward_prefix}{hyphen_body}",
                components=visible_component_subset(base_components, ("city", "district", "road", "poi", "building", "detail")),
                format_name="semantic_forward",
                ops=["semantic_forward_room_compact"],
                weight=0.08,
            )

    reverse_tail = semantic_reverse_tail(base_components)
    reverse_body = semantic_forward_body(base_components, include_number=False, hyphen_room=False)
    if reverse_body and reverse_tail:
        add_variant_candidate(
            registry,
            text=f"{reverse_body}，{reverse_tail}",
            components=visible_component_subset(base_components, ("city", "district", "road", "poi", "building", "detail")),
            format_name="semantic_reverse",
            ops=["semantic_reverse_without_number"],
            weight=0.18,
        )

    reverse_body_with_number = semantic_forward_body(base_components, include_number=True, hyphen_room=False)
    if reverse_body_with_number and reverse_tail:
        add_variant_candidate(
            registry,
            text=f"{reverse_body_with_number}，{reverse_tail}",
            components=visible_component_subset(
                base_components,
                ("city", "district", "road", "number", "poi", "building", "detail"),
            ),
            format_name="semantic_reverse",
            ops=["semantic_reverse_with_number"],
            weight=0.12,
        )

    hyphen_reverse_body = semantic_forward_body(base_components, include_number=False, hyphen_room=True)
    if hyphen_reverse_body and hyphen_reverse_body != reverse_body and reverse_tail:
        add_variant_candidate(
            registry,
            text=f"{hyphen_reverse_body}，{reverse_tail}",
            components=visible_component_subset(base_components, ("city", "district", "road", "poi", "building", "detail")),
            format_name="semantic_reverse",
            ops=["semantic_reverse_room_compact"],
            weight=0.05,
        )

    return list(registry.values())


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


def generate_addresses(count: int, seed: int) -> list[dict[str, Any]]:
    generator_namespace = runpy.run_path(str(DATA_DIR / "generate_data.py"))
    cn_record = generator_namespace["_cn_record"]
    random.seed(seed)
    rows: list[dict[str, Any]] = []
    for index in range(1, count + 1):
        row = dict(cn_record(index))
        if str(row.get("format")) == "reverse_tail_full":
            components = dict(row["components"])
            row["text"] = render_reverse_address(components, segmented_admin=True, separator=",")
            row["format"] = "reverse_tail_segmented"
        rows.append(row)
    return rows


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
                "level": level_tuple or (component_type.strip(),),
                "key": key_text,
            }
        )
    return entries


def build_fragment_bucket(metadata: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    trace_entries = parse_address_trace(metadata)
    bucket: dict[str, list[str]] = defaultdict(list)
    for entry in trace_entries:
        component_value = entry["value"].strip().upper()
        if not component_value:
            continue
        if entry["component_type"] == "multi_admin":
            for level in entry["level"]:
                bucket[level].append(component_value)
            continue
        target_level = entry["level"][0] if entry["level"] else entry["component_type"]
        bucket[target_level].append(component_value)
    return bucket, trace_entries


def choose_best_address_candidate(candidates: list[Any], gt_length: int) -> Any | None:
    address_candidates = [candidate for candidate in candidates if candidate.attr_type.value == "address"]
    if not address_candidates:
        return None
    return max(
        address_candidates,
        key=lambda candidate: (
            int((candidate.span_start or 0) <= 0 and (candidate.span_end or 0) >= gt_length),
            interval_overlap(0, gt_length, int(candidate.span_start or 0), int(candidate.span_end or 0)),
            int(candidate.span_end or 0) - int(candidate.span_start or 0),
        ),
    )


def evaluate_address_components(gt_components: dict[str, str], candidate: Any | None) -> dict[str, Any]:
    expected_keys = [key for key in ADDRESS_COMPONENT_KEYS if compact_text(gt_components.get(key, ""))]
    if candidate is None:
        component_rows = [
            {
                "component_type": key,
                "expected": gt_components.get(key, ""),
                "expected_tokens": component_expected_tokens(key, gt_components.get(key, "")),
                "predicted_tokens": [],
                "matched": False,
                "fragment_count": 0,
            }
            for key in expected_keys
        ]
        return {
            "component_rows": component_rows,
            "component_accuracy": 0.0,
            "token_recall": 0.0,
            "trace_fragment_count": 0,
            "fragmented_component_count": 0,
        }
    bucket, trace_entries = build_fragment_bucket({key: list(value) for key, value in candidate.metadata.items()})
    component_rows: list[dict[str, Any]] = []
    matched_component_count = 0
    fragmented_component_count = 0
    token_hit_count = 0
    token_total = 0
    for key in expected_keys:
        expected_tokens = [token for token in component_expected_tokens(key, gt_components.get(key, "")) if token]
        predicted_tokens = list(bucket.get(key, []))
        if len(predicted_tokens) > 1:
            fragmented_component_count += 1
        row_hit_count = sum(1 for token in expected_tokens if token.upper() in predicted_tokens)
        matched = row_hit_count == len(expected_tokens) and bool(expected_tokens)
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


def evaluate_address_row(detector: RuleBasedPIIDetector, row: dict[str, Any], label: str) -> dict[str, Any]:
    text = str(row["text"])
    predictions, candidates, elapsed_ms = detect_text(detector, text)
    exact_predictions = [
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
    exact_complete = any(prediction["start"] <= 0 and prediction["end"] >= len(text) for prediction in exact_predictions)
    exact_fragment = bool(exact_predictions) and not exact_complete
    best_candidate = choose_best_address_candidate(candidates, len(text))
    scoring_components = dict(row["components"])
    reference_components = dict(row.get("reference_components", row["components"]))
    component_eval = evaluate_address_components(scoring_components, best_candidate)
    return {
        "split": label,
        "id": int(row["id"]),
        "format": row["format"],
        "source_format": row.get("source_format", row["format"]),
        "text": text,
        "text_length": len(text),
        "variant_ops": list(row.get("variant_ops", [])),
        "prediction_count": len(predictions),
        "address_prediction_count": len(exact_predictions),
        "status": "exact_complete" if exact_complete else ("exact_fragment" if exact_fragment else "miss"),
        "coverage_ratio": coverage_ratio(0, len(text), exact_predictions),
        "piece_count": 1 if exact_complete else len(exact_predictions),
        "latency_ms": elapsed_ms,
        "component_accuracy": component_eval["component_accuracy"],
        "component_token_recall": component_eval["token_recall"],
        "trace_fragment_count": component_eval["trace_fragment_count"],
        "fragmented_component_count": component_eval["fragmented_component_count"],
        "component_rows": component_eval["component_rows"],
        "predicted_components": (
            dict(best_candidate.normalized_source.components) if best_candidate and best_candidate.normalized_source else {}
        ),
        "predicted_trace": (
            list(best_candidate.metadata.get("address_component_trace", [])) if best_candidate is not None else []
        ),
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


def compare_dataset_summaries(structured_summary: dict[str, Any], surface_summary: dict[str, Any]) -> dict[str, Any]:
    structured_entity = structured_summary["entity_summary"]
    surface_entity = surface_summary["entity_summary"]
    compared_types = sorted(
        set(structured_entity["per_type"]).union(surface_entity["per_type"]),
        key=lambda entity_type: TYPE_DISPLAY_ORDER.index(entity_type) if entity_type in TYPE_DISPLAY_ORDER else 999,
    )

    def matrix_rate(
        entity_group: dict[str, Any],
        *,
        scope: str | None,
        threshold: str,
        bucket: str,
        family: str,
    ) -> float | None:
        matrix_root = entity_group.get("coverage_matrix", {})
        if scope is not None:
            matrix_root = matrix_root.get(scope, {})
        matrix = matrix_root.get(threshold, {})
        return matrix.get(bucket, {}).get(family)

    per_type_delta = {}
    for entity_type in compared_types:
        left = structured_entity["per_type"].get(entity_type, {})
        right = surface_entity["per_type"].get(entity_type, {})
        support_exact_type = bool(left.get("support_exact_type") or right.get("support_exact_type"))
        per_type_delta[entity_type] = {
            "support_exact_type": support_exact_type,
            "structured_count": left.get("count", 0),
            "surface_count": right.get("count", 0),
            "structured_exact_complete_rate": matrix_rate(
                left,
                scope=None,
                threshold="complete",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "surface_exact_complete_rate": matrix_rate(
                right,
                scope=None,
                threshold="complete",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "structured_exact_hit_50_rate": matrix_rate(
                left,
                scope=None,
                threshold="hit_50",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "surface_exact_hit_50_rate": matrix_rate(
                right,
                scope=None,
                threshold="hit_50",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "structured_exact_hit_any_rate": matrix_rate(
                left,
                scope=None,
                threshold="hit_any",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "surface_exact_hit_any_rate": matrix_rate(
                right,
                scope=None,
                threshold="hit_any",
                bucket="exclusive_rate_by_family",
                family="exact_type",
            ),
            "structured_any_hit_rate": matrix_rate(
                left,
                scope=None,
                threshold="hit_any",
                bucket="exclusive_rate_by_family",
                family="any_hit",
            ),
            "surface_any_hit_rate": matrix_rate(
                right,
                scope=None,
                threshold="hit_any",
                bucket="exclusive_rate_by_family",
                family="any_hit",
            ),
            "surface_generic_hit_any_rate": matrix_rate(
                right,
                scope=None,
                threshold="hit_any",
                bucket="nonexclusive_rate_by_family",
                family="generic_numeric",
            ),
            "surface_wrong_type_hit_any_rate": matrix_rate(
                right,
                scope=None,
                threshold="hit_any",
                bucket="nonexclusive_rate_by_family",
                family="wrong_type",
            ),
        }
        if support_exact_type:
            per_type_delta[entity_type]["delta_exact_complete_rate"] = (
                float(per_type_delta[entity_type]["surface_exact_complete_rate"] or 0.0)
                - float(per_type_delta[entity_type]["structured_exact_complete_rate"] or 0.0)
            )
        else:
            per_type_delta[entity_type]["delta_exact_complete_rate"] = None
    return {
        "overall": {
            "structured_all_entities": structured_entity["coverage_matrix"]["all_entities"],
            "surface_all_entities": surface_entity["coverage_matrix"]["all_entities"],
            "structured_supported_exact_only": structured_entity["coverage_matrix"]["supported_exact_only"],
            "surface_supported_exact_only": surface_entity["coverage_matrix"]["supported_exact_only"],
        },
        "per_type": per_type_delta,
    }


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def format_rate(value: Any) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.4f}"


def build_summary_markdown(summary: dict[str, Any]) -> str:
    synthetic_original = summary["synthetic"]["original_summary"]
    synthetic_variant = summary["synthetic"]["variant_summary"]
    structured_entity = summary["datasets"]["structured"]["entity_summary"]
    surface_entity = summary["datasets"]["surface"]["entity_summary"]
    comparison = summary["datasets"]["comparison"]
    threshold_labels = {
        "complete": "complete",
        "hit_50": "hit@0.5",
        "hit_any": "hit@>0",
    }
    dataset_overview_rows = []
    for dataset_name, entity_summary in (("structured", structured_entity), ("surface", surface_entity)):
        matrix = entity_summary["coverage_matrix"]["all_entities"]
        for threshold_name, _threshold_value in COVERAGE_THRESHOLD_SPECS:
            exclusive = matrix[threshold_name]["exclusive_rate_by_family"]
            dataset_overview_rows.append(
                [
                    dataset_name,
                    threshold_labels[threshold_name],
                    format_rate(exclusive.get("exact_type")),
                    format_rate(exclusive.get("generic_numeric")),
                    format_rate(exclusive.get("wrong_type")),
                    format_rate(exclusive.get("any_hit")),
                    format_rate(exclusive.get("miss")),
                ]
            )

    supported_diagnostic_rows = []
    for dataset_name, entity_summary in (("structured", structured_entity), ("surface", surface_entity)):
        matrix = entity_summary["coverage_matrix"]["supported_exact_only"]
        for threshold_name, _threshold_value in COVERAGE_THRESHOLD_SPECS:
            diagnostic = matrix[threshold_name]["nonexclusive_rate_by_family"]
            supported_diagnostic_rows.append(
                [
                    dataset_name,
                    threshold_labels[threshold_name],
                    format_rate(diagnostic.get("exact_type")),
                    format_rate(diagnostic.get("generic_numeric")),
                    format_rate(diagnostic.get("wrong_type")),
                    format_rate(diagnostic.get("any_type")),
                ]
            )

    supported_type_rows = []
    unsupported_type_rows = []
    for entity_type in comparison["per_type"]:
        item = comparison["per_type"][entity_type]
        if item["support_exact_type"]:
            supported_type_rows.append(
                [
                    entity_type,
                    format_rate(item["structured_exact_complete_rate"]),
                    format_rate(item["surface_exact_complete_rate"]),
                    format_rate(item["surface_exact_hit_50_rate"]),
                    format_rate(item["surface_exact_hit_any_rate"]),
                    format_rate(item["surface_wrong_type_hit_any_rate"]),
                ]
            )
        else:
            unsupported_type_rows.append(
                [
                    entity_type,
                    str(item["surface_count"]),
                    format_rate(item["structured_any_hit_rate"]),
                    format_rate(item["surface_any_hit_rate"]),
                    format_rate(item["surface_generic_hit_any_rate"]),
                    format_rate(item["surface_wrong_type_hit_any_rate"]),
                ]
            )

    unsupported_exact_breakdown = "、".join(
        f"{entity_type}({count})"
        for entity_type, count in structured_entity["unsupported_exact_type_breakdown"].items()
    )
    lines = [
        "# 中文 detector 论文评估摘要",
        "",
        "## 运行设置",
        f"- detector 初始化耗时：{summary['detector_init_ms']:.2f} ms",
        f"- 地址样本数：{summary['synthetic']['address_count']}",
        f"- 结构化数据集：{summary['datasets']['structured']['dataset_name']}",
        f"- 扰动数据集：{summary['datasets']['surface']['dataset_name']}",
        "",
        "## 合成地址实验",
        markdown_table(
            ["集合", "完整召回率", "碎片召回率", "漏检率", "组件准确率", "组件 token 召回", "平均碎片数", "平均耗时(ms)"],
            [
                [
                    "原始地址",
                    f"{synthetic_original['exact_complete_rate']:.4f}",
                    f"{synthetic_original['exact_fragment_rate']:.4f}",
                    f"{synthetic_original['miss_rate']:.4f}",
                    f"{synthetic_original['component_accuracy_mean']:.4f}",
                    f"{synthetic_original['component_token_recall_mean']:.4f}",
                    f"{synthetic_original['trace_fragment_count_mean']:.4f}",
                    f"{synthetic_original['latency_ms']['mean']:.3f}",
                ],
                [
                    "随机变体",
                    f"{synthetic_variant['exact_complete_rate']:.4f}",
                    f"{synthetic_variant['exact_fragment_rate']:.4f}",
                    f"{synthetic_variant['miss_rate']:.4f}",
                    f"{synthetic_variant['component_accuracy_mean']:.4f}",
                    f"{synthetic_variant['component_token_recall_mean']:.4f}",
                    f"{synthetic_variant['trace_fragment_count_mean']:.4f}",
                    f"{synthetic_variant['latency_ms']['mean']:.3f}",
                ],
            ],
        ),
        "",
        "### 地址组件准确率",
        markdown_table(
            ["组件", "原始命中率", "变体命中率", "原始平均碎片", "变体平均碎片"],
            [
                [
                    component,
                    f"{synthetic_original['per_component'].get(component, {}).get('match_rate', 0.0):.4f}",
                    f"{synthetic_variant['per_component'].get(component, {}).get('match_rate', 0.0):.4f}",
                    f"{synthetic_original['per_component'].get(component, {}).get('mean_fragment_count', 0.0):.4f}",
                    f"{synthetic_variant['per_component'].get(component, {}).get('mean_fragment_count', 0.0):.4f}",
                ]
                for component in ADDRESS_COMPONENT_KEYS
                if component in synthetic_original["per_component"] or component in synthetic_variant["per_component"]
            ],
        ),
        "",
        "## 数据集主指标（互斥归因，全类型）",
        markdown_table(
            ["数据集", "阈值", "exact_type", "generic_numeric", "wrong_type", "any_hit", "miss"],
            dataset_overview_rows,
        ),
        "",
        "## Supported Exact 类型诊断（非互斥）",
        markdown_table(
            ["数据集", "阈值", "exact_type", "generic_numeric", "wrong_type", "any_type"],
            supported_diagnostic_rows,
        ),
        "",
        "## 数据集补充统计",
        markdown_table(
            ["数据集", "supported exact 数", "unsupported exact 数", "平均 accepted 覆盖率", "平均 any 覆盖率", "平均耗时(ms)"],
            [
                [
                    "structured",
                    str(structured_entity["supported_exact_type_count"]),
                    str(structured_entity["unsupported_exact_type_count"]),
                    format_rate(structured_entity["mean_accepted_coverage_ratio"]),
                    format_rate(structured_entity["mean_any_coverage_ratio"]),
                    f"{summary['datasets']['structured']['sample_summary']['latency_ms']['mean']:.3f}",
                ],
                [
                    "surface",
                    str(surface_entity["supported_exact_type_count"]),
                    str(surface_entity["unsupported_exact_type_count"]),
                    format_rate(surface_entity["mean_accepted_coverage_ratio"]),
                    format_rate(surface_entity["mean_any_coverage_ratio"]),
                    f"{summary['datasets']['surface']['sample_summary']['latency_ms']['mean']:.3f}",
                ],
            ],
        ),
        "",
        "## 类型级对比（supported exact）",
        markdown_table(
            ["类型", "structured complete exact", "surface complete exact", "surface hit@0.5 exact", "surface hit@>0 exact", "surface wrong@>0"],
            supported_type_rows,
        ),
        "",
        "## 未支持 Exact 类型",
        f"- structured 未支持 exact detector 的实体共 {structured_entity['unsupported_exact_type_count']} 个：{unsupported_exact_breakdown}",
        markdown_table(
            ["类型", "surface 数量", "structured any@>0", "surface any@>0", "surface generic@>0", "surface wrong@>0"],
            unsupported_type_rows,
        ),
        "",
        "## 最差样例（surface，按 accepted 覆盖率排序）",
        markdown_table(
            ["sample_id", "scene", "miss", "wrong_type", "background_fp", "coverage", "latency(ms)"],
            [
                [
                    row["sample_id"],
                    row["scene"],
                    str(row["miss_count"]),
                    str(row["wrong_type_prediction_count"]),
                    str(row["background_fp_count"]),
                    f"{row['accepted_coverage_mean']:.4f}",
                    f"{row['latency_ms']:.3f}",
                ]
                for row in summary["datasets"]["surface"]["worst_samples"][:10]
            ],
        ),
        "",
    ]
    return "\n".join(section for section in lines if section is not None)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    detector, detector_init_ms = detector_build()
    detector.detect("北京市海淀区中关村街道中山路1号", [])

    address_rows = generate_addresses(int(args.address_count), int(args.address_seed))
    variant_rows = generate_address_variants(address_rows, int(args.variant_seed))

    original_address_details = [evaluate_address_row(detector, row, "original") for row in address_rows]
    variant_address_details = [evaluate_address_row(detector, row, "variant") for row in variant_rows]
    original_address_summary = summarize_address_rows(original_address_details)
    variant_address_summary = summarize_address_rows(variant_address_details)

    structured_result = evaluate_dataset(
        detector,
        DATA_DIR / "dataset" / "privacy_eval_realistic_1200_zh_release_structured.json",
        "structured",
    )
    surface_result = evaluate_dataset(
        detector,
        DATA_DIR / "dataset" / "privacy_eval_realistic_1200_zh_surface_perturbed_benchmark.json",
        "surface",
    )
    comparison = compare_dataset_summaries(structured_result, surface_result)

    summary = {
        "detector_init_ms": detector_init_ms,
        "synthetic": {
            "address_count": int(args.address_count),
            "address_seed": int(args.address_seed),
            "variant_seed": int(args.variant_seed),
            "original_summary": original_address_summary,
            "variant_summary": variant_address_summary,
        },
        "datasets": {
            "structured": {
                "dataset_name": structured_result["dataset_name"],
                "dataset_path": structured_result["dataset_path"],
                "entity_summary": structured_result["entity_summary"],
                "sample_summary": structured_result["sample_summary"],
                "worst_samples": structured_result["worst_samples"],
                "alignment_mismatch_count": len(structured_result["alignment_mismatches"]),
            },
            "surface": {
                "dataset_name": surface_result["dataset_name"],
                "dataset_path": surface_result["dataset_path"],
                "entity_summary": surface_result["entity_summary"],
                "sample_summary": surface_result["sample_summary"],
                "worst_samples": surface_result["worst_samples"],
                "alignment_mismatch_count": len(surface_result["alignment_mismatches"]),
            },
            "comparison": comparison,
        },
    }

    write_json(output_dir / "summary.json", summary)
    write_jsonl(output_dir / "address_original_details.jsonl", original_address_details)
    write_jsonl(output_dir / "address_variant_details.jsonl", variant_address_details)
    write_jsonl(output_dir / "dataset_structured_entity_details.jsonl", structured_result["entity_rows"])
    write_jsonl(output_dir / "dataset_surface_entity_details.jsonl", surface_result["entity_rows"])
    write_jsonl(output_dir / "dataset_structured_sample_summary.jsonl", structured_result["sample_rows"])
    write_jsonl(output_dir / "dataset_surface_sample_summary.jsonl", surface_result["sample_rows"])
    write_json(output_dir / "dataset_structured_alignment_mismatches.json", structured_result["alignment_mismatches"])
    write_json(output_dir / "dataset_surface_alignment_mismatches.json", surface_result["alignment_mismatches"])
    (output_dir / "summary.md").write_text(build_summary_markdown(summary), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "synthetic_original_exact_complete_rate": original_address_summary["exact_complete_rate"],
                "synthetic_variant_exact_complete_rate": variant_address_summary["exact_complete_rate"],
                "structured_exact_complete_rate": structured_result["entity_summary"]["exact_complete_rate"],
                "surface_exact_complete_rate": surface_result["entity_summary"]["exact_complete_rate"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
