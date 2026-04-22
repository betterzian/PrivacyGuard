"""英文结构化数据集上的 detector 实体级评估脚本。"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_PATH = ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_en_release_structured.json"
DEFAULT_OUTPUT_DIR = ROOT / "tmp" / "eval_detector_en_structured"

TAG_PATTERN = re.compile(r"【PII:([A-Z_]+):(\d+)】(.*?)【/PII】", re.S)
GENERIC_DETECTOR_TYPES = {"num", "alnum"}
TYPE_DISPLAY_ORDER = (
    "ADDRESS",
    "NAME",
    "PHONE",
    "ORG",
    "EMAIL",
    "TIME",
    "AMOUNT",
    "LICENSE_PLATE",
    "BANK_CARD",
    "DRIVER_LICENSE",
    "PASSPORT_NUMBER",
    "ID_CARD",
    "ORDER_ID",
    "MEMBER_ID",
    "TRACKING_ID",
    "ACCOUNT_ID",
    "BIRTHDAY",
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
STATUS_ORDER = (
    "exact_complete",
    "exact_fragment",
    "generic_complete",
    "generic_fragment",
    "miss",
)


@dataclass(slots=True)
class TaggedEntity:
    """去标签后文本中的单个 GT 实体。"""

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
    """detector 产出的单个预测 span。"""

    prediction_index: int
    entity_type: str
    text: str
    start: int
    end: int
    metadata: dict[str, list[str]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="评估英文结构化数据集上的 detector 实体级召回与碎片化表现。")
    parser.add_argument("--dataset-path", type=Path, default=DEFAULT_DATASET_PATH, help="结构化数据集路径。")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="输出目录。")
    parser.add_argument("--locale-profile", default="en_us", help="detector 的 locale_profile。")
    parser.add_argument("--limit", type=int, default=None, help="仅评估前 N 个样例，便于快速调试。")
    return parser.parse_args()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_for_alignment(text: Any) -> str:
    return re.sub(r"\s+", "", str(text or ""))


def strip_pii_tags(text_with_tags: str) -> tuple[str, list[dict[str, Any]]]:
    """去掉标记并保留实体在去标签文本中的位置。"""

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
    """将标签解析结果与数据集 inventory 对齐。"""

    merged: list[TaggedEntity] = []
    mismatches: list[dict[str, Any]] = []
    used_indices: set[int] = set()
    for parsed_index, parsed in enumerate(parsed_entities):
        matched_index: int | None = None
        if parsed_index < len(inventory):
            candidate = inventory[parsed_index]
            if (
                candidate.get("type") == parsed["entity_type"]
                and normalize_for_alignment(candidate.get("value")) == normalize_for_alignment(parsed["value"])
            ):
                matched_index = parsed_index
        if matched_index is None:
            for inventory_index, candidate in enumerate(inventory):
                if inventory_index in used_indices:
                    continue
                if (
                    candidate.get("type") == parsed["entity_type"]
                    and normalize_for_alignment(candidate.get("value")) == normalize_for_alignment(parsed["value"])
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
    intervals: list[tuple[int, int]] = []
    for prediction in predictions:
        overlap = interval_overlap(span_start, span_end, prediction["start"], prediction["end"])
        if overlap <= 0:
            continue
        intervals.append((max(span_start, prediction["start"]), min(span_end, prediction["end"])))
    return interval_union_length(intervals) / span_length


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


def detector_build(locale_profile: str) -> tuple[RuleBasedPIIDetector, float]:
    started = time.perf_counter()
    detector = RuleBasedPIIDetector(locale_profile=locale_profile)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return detector, elapsed_ms


def detect_text(detector: RuleBasedPIIDetector, text: str) -> tuple[list[PredictionSpan], float]:
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
    return predictions, elapsed_ms


def evaluate_gt_entity(entity: TaggedEntity, predictions: list[PredictionSpan]) -> dict[str, Any]:
    """评估单个 GT 实体是否被完整或碎片召回。"""

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
    generic_complete = any(
        prediction["start"] <= entity.start and prediction["end"] >= entity.end for prediction in generic_predictions
    )
    exact_coverage = coverage_ratio(entity.start, entity.end, exact_predictions)
    generic_coverage = coverage_ratio(entity.start, entity.end, generic_predictions)
    wrong_type_coverage = coverage_ratio(entity.start, entity.end, wrong_type_predictions)
    any_coverage = coverage_ratio(entity.start, entity.end, exact_predictions + generic_predictions + wrong_type_predictions)

    if exact_complete:
        status = "exact_complete"
        accepted_predictions = exact_predictions
    elif exact_predictions:
        status = "exact_fragment"
        accepted_predictions = exact_predictions
    elif generic_complete:
        status = "generic_complete"
        accepted_predictions = generic_predictions
    elif generic_predictions:
        status = "generic_fragment"
        accepted_predictions = generic_predictions
    else:
        status = "miss"
        accepted_predictions = []

    accepted_coverage = coverage_ratio(entity.start, entity.end, accepted_predictions)
    accepted_piece_count = len(accepted_predictions)
    is_fragment = status in {"exact_fragment", "generic_fragment"}
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
        "match_family": (
            "exact"
            if status.startswith("exact_")
            else "generic"
            if status.startswith("generic_")
            else "miss"
        ),
        "is_complete_recall": status in {"exact_complete", "generic_complete"},
        "is_fragment_recall": is_fragment,
        "accepted_piece_count": accepted_piece_count,
        "fragment_piece_count": accepted_piece_count if is_fragment else 0,
        "fragment_coverage_ratio": accepted_coverage if is_fragment else 0.0,
        "fragment_coverage_percent": accepted_coverage * 100.0 if is_fragment else 0.0,
        "exact_match_count": len(exact_predictions),
        "generic_match_count": len(generic_predictions),
        "wrong_type_overlap_count": len(wrong_type_predictions),
        "exact_coverage_ratio": exact_coverage,
        "generic_coverage_ratio": generic_coverage,
        "wrong_type_coverage_ratio": wrong_type_coverage,
        "any_coverage_ratio": any_coverage,
        "accepted_coverage_ratio": accepted_coverage,
        "accepted_coverage_percent": accepted_coverage * 100.0,
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
        entity for entity in entities if interval_overlap(prediction.start, prediction.end, entity.start, entity.end) > 0
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
    counter = Counter(row["status"] for row in entity_rows)
    fragment_rows = [row for row in entity_rows if row["is_fragment_recall"]]
    prediction_rows = [classify_prediction(prediction, sample["entities"]) for prediction in predictions]
    prediction_counter = Counter(row["label"] for row in prediction_rows)
    entity_count = len(entity_rows)
    return {
        "sample_id": sample["sample_id"],
        "scene": sample["scene"],
        "category": sample["category"],
        "difficulty": sample["difficulty"],
        "privacy_density": sample["privacy_density"],
        "challenge_tags": list(sample.get("challenge_tags", [])),
        "entity_count": entity_count,
        "exact_complete_count": counter.get("exact_complete", 0),
        "exact_fragment_count": counter.get("exact_fragment", 0),
        "generic_complete_count": counter.get("generic_complete", 0),
        "generic_fragment_count": counter.get("generic_fragment", 0),
        "miss_count": counter.get("miss", 0),
        "accepted_complete_rate": (
            (counter.get("exact_complete", 0) + counter.get("generic_complete", 0)) / entity_count if entity_count else 0.0
        ),
        "accepted_fragment_rate": (
            (counter.get("exact_fragment", 0) + counter.get("generic_fragment", 0)) / entity_count if entity_count else 0.0
        ),
        "accepted_recall_rate": (sum(1 for row in entity_rows if row["status"] != "miss") / entity_count if entity_count else 0.0),
        "accepted_coverage_mean": (
            sum(row["accepted_coverage_ratio"] for row in entity_rows) / entity_count if entity_count else 0.0
        ),
        "fragment_piece_count_mean": (
            sum(row["fragment_piece_count"] for row in fragment_rows) / len(fragment_rows) if fragment_rows else 0.0
        ),
        "fragment_coverage_percent_mean": (
            sum(row["fragment_coverage_percent"] for row in fragment_rows) / len(fragment_rows) if fragment_rows else 0.0
        ),
        "prediction_count": len(predictions),
        "exact_prediction_count": prediction_counter.get("exact_overlap", 0),
        "generic_prediction_count": prediction_counter.get("generic_overlap", 0),
        "wrong_type_prediction_count": prediction_counter.get("wrong_type_overlap", 0),
        "background_fp_count": prediction_counter.get("background_fp", 0),
        "latency_ms": elapsed_ms,
    }


def summarize_entity_table(rows: list[dict[str, Any]]) -> dict[str, Any]:
    status_counter = Counter(row["status"] for row in rows)
    type_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        type_groups[row["entity_type"]].append(row)

    def summarize_group(group: list[dict[str, Any]], entity_type: str | None = None) -> dict[str, Any]:
        count = len(group)
        counter = Counter(row["status"] for row in group)
        fragment_rows = [row for row in group if row["is_fragment_recall"]]
        return {
            "count": count,
            "support_exact_type": DATASET_TYPE_TO_DETECTOR.get(entity_type) is not None if entity_type else None,
            "exact_complete_rate": counter.get("exact_complete", 0) / count if count else 0.0,
            "exact_fragment_rate": counter.get("exact_fragment", 0) / count if count else 0.0,
            "generic_complete_rate": counter.get("generic_complete", 0) / count if count else 0.0,
            "generic_fragment_rate": counter.get("generic_fragment", 0) / count if count else 0.0,
            "miss_rate": counter.get("miss", 0) / count if count else 0.0,
            "accepted_complete_rate": (
                (counter.get("exact_complete", 0) + counter.get("generic_complete", 0)) / count if count else 0.0
            ),
            "accepted_fragment_rate": (
                (counter.get("exact_fragment", 0) + counter.get("generic_fragment", 0)) / count if count else 0.0
            ),
            "accepted_recall_rate": (sum(1 for row in group if row["status"] != "miss") / count if count else 0.0),
            "mean_accepted_coverage_percent": (
                sum(row["accepted_coverage_percent"] for row in group) / count if count else 0.0
            ),
            "mean_fragment_piece_count": (
                sum(row["fragment_piece_count"] for row in fragment_rows) / len(fragment_rows) if fragment_rows else 0.0
            ),
            "mean_fragment_coverage_percent": (
                sum(row["fragment_coverage_percent"] for row in fragment_rows) / len(fragment_rows) if fragment_rows else 0.0
            ),
            "median_fragment_piece_count": (
                float(statistics.median([row["fragment_piece_count"] for row in fragment_rows])) if fragment_rows else 0.0
            ),
            "median_fragment_coverage_percent": (
                float(statistics.median([row["fragment_coverage_percent"] for row in fragment_rows]))
                if fragment_rows
                else 0.0
            ),
        }

    ordered_types = [entity_type for entity_type in TYPE_DISPLAY_ORDER if entity_type in type_groups]
    ordered_types.extend(sorted(entity_type for entity_type in type_groups if entity_type not in TYPE_DISPLAY_ORDER))
    return {
        "entity_count": len(rows),
        "status_counter": {status: status_counter.get(status, 0) for status in STATUS_ORDER},
        "exact_complete_rate": status_counter.get("exact_complete", 0) / len(rows) if rows else 0.0,
        "exact_fragment_rate": status_counter.get("exact_fragment", 0) / len(rows) if rows else 0.0,
        "generic_complete_rate": status_counter.get("generic_complete", 0) / len(rows) if rows else 0.0,
        "generic_fragment_rate": status_counter.get("generic_fragment", 0) / len(rows) if rows else 0.0,
        "miss_rate": status_counter.get("miss", 0) / len(rows) if rows else 0.0,
        "accepted_complete_rate": (
            (status_counter.get("exact_complete", 0) + status_counter.get("generic_complete", 0)) / len(rows)
            if rows
            else 0.0
        ),
        "accepted_fragment_rate": (
            (status_counter.get("exact_fragment", 0) + status_counter.get("generic_fragment", 0)) / len(rows)
            if rows
            else 0.0
        ),
        "accepted_recall_rate": (sum(1 for row in rows if row["status"] != "miss") / len(rows) if rows else 0.0),
        "per_type": {entity_type: summarize_group(type_groups[entity_type], entity_type) for entity_type in ordered_types},
        "all_types": summarize_group(rows),
    }


def summarize_sample_table(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sample_count": len(rows),
        "latency_ms": summarize_numeric([row["latency_ms"] for row in rows]),
        "mean_entity_count": (sum(row["entity_count"] for row in rows) / len(rows)) if rows else 0.0,
        "mean_prediction_count": (sum(row["prediction_count"] for row in rows) / len(rows)) if rows else 0.0,
        "mean_background_fp_count": (sum(row["background_fp_count"] for row in rows) / len(rows)) if rows else 0.0,
        "mean_wrong_type_prediction_count": (
            sum(row["wrong_type_prediction_count"] for row in rows) / len(rows) if rows else 0.0
        ),
        "samples_with_any_miss": sum(1 for row in rows if row["miss_count"] > 0),
        "samples_with_any_background_fp": sum(1 for row in rows if row["background_fp_count"] > 0),
        "samples_with_any_fragment": sum(
            1
            for row in rows
            if row["exact_fragment_count"] > 0 or row["generic_fragment_count"] > 0
        ),
    }


def evaluate_dataset(detector: RuleBasedPIIDetector, dataset_path: Path, *, limit: int | None = None) -> dict[str, Any]:
    dataset = load_dataset(dataset_path)
    samples = list(dataset["samples"][:limit] if limit else dataset["samples"])
    entity_rows: list[dict[str, Any]] = []
    sample_rows: list[dict[str, Any]] = []
    prediction_rows: list[dict[str, Any]] = []
    alignment_mismatches: list[dict[str, Any]] = []

    for sample in samples:
        plain_text, parsed_entities = strip_pii_tags(str(sample["text_with_tags"]))
        entities, mismatches = merge_entities_with_inventory(
            str(sample["sample_id"]),
            parsed_entities,
            list(sample["pii_inventory"]),
        )
        alignment_mismatches.extend(mismatches)
        predictions, elapsed_ms = detect_text(detector, plain_text)
        sample_entity_rows = [evaluate_gt_entity(entity, predictions) for entity in entities]
        entity_rows.extend(sample_entity_rows)
        prediction_rows.extend(
            {
                "sample_id": str(sample["sample_id"]),
                **classify_prediction(prediction, entities),
            }
            for prediction in predictions
        )
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

    worst_samples = sorted(
        sample_rows,
        key=lambda row: (
            -row["miss_count"],
            -(row["exact_fragment_count"] + row["generic_fragment_count"]),
            -row["wrong_type_prediction_count"],
            -row["background_fp_count"],
            row["accepted_coverage_mean"],
        ),
    )[:20]
    return {
        "dataset_name": dataset["dataset_name"],
        "dataset_path": str(dataset_path),
        "sample_limit": limit,
        "entity_summary": summarize_entity_table(entity_rows),
        "sample_summary": summarize_sample_table(sample_rows),
        "worst_samples": worst_samples,
        "entity_rows": entity_rows,
        "sample_rows": sample_rows,
        "prediction_rows": prediction_rows,
        "alignment_mismatches": alignment_mismatches,
    }


def main() -> None:
    args = parse_args()
    started = time.perf_counter()
    detector, build_ms = detector_build(args.locale_profile)
    detector.detect("warmup text 123456 abc123", [])
    result = evaluate_dataset(detector, args.dataset_path, limit=args.limit)
    total_ms = (time.perf_counter() - started) * 1000.0

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "dataset_name": result["dataset_name"],
        "dataset_path": result["dataset_path"],
        "sample_limit": result["sample_limit"],
        "locale_profile": args.locale_profile,
        "build_ms": build_ms,
        "total_runtime_ms": total_ms,
        "entity_summary": result["entity_summary"],
        "sample_summary": result["sample_summary"],
        "worst_samples": result["worst_samples"],
        "alignment_mismatch_count": len(result["alignment_mismatches"]),
    }

    write_json(output_dir / "summary.json", summary)
    write_jsonl(output_dir / "entity_details.jsonl", result["entity_rows"])
    write_jsonl(output_dir / "sample_summary.jsonl", result["sample_rows"])
    write_jsonl(output_dir / "prediction_summary.jsonl", result["prediction_rows"])
    write_json(output_dir / "alignment_mismatches.json", result["alignment_mismatches"])

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
