"""综合评测脚本。

覆盖两部分任务：
1. 用 `data/generate_data.py` 生成 1000 条中文地址，并生成随机变体，评估 detector 中文地址栈。
2. 评估四个 realistic 1200 数据集，输出按类型与按样例的召回、碎片化与背景误报统计。
"""

from __future__ import annotations

import argparse
import json
import runpy
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
DEFAULT_OUTPUT_DIR = ROOT / "tmp" / "eval_detector_generated_and_realistic"
ADDRESS_COUNT_DEFAULT = 1000
ADDRESS_SEED_DEFAULT = 42
VARIANT_SEED_DEFAULT = 20260423

DATASET_SPECS = (
    {
        "key": "zh_release_structured",
        "path": ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_zh_release_structured.json",
        "locale_profile": "zh_cn",
    },
    {
        "key": "zh_surface_perturbed",
        "path": ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_zh_surface_perturbed_benchmark.json",
        "locale_profile": "zh_cn",
    },
    {
        "key": "en_release_structured",
        "path": ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_en_release_structured.json",
        "locale_profile": "en_us",
    },
    {
        "key": "en_surface_perturbed",
        "path": ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_en_surface_perturbed_benchmark.json",
        "locale_profile": "en_us",
    },
)

GENERATED_STATUS_RANK = {
    "miss": 0,
    "exact_fragment": 1,
    "exact_complete": 2,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="综合评测生成地址与四个 realistic 数据集。")
    parser.add_argument("--address-count", type=int, default=ADDRESS_COUNT_DEFAULT, help="中文地址生成数量。")
    parser.add_argument("--address-seed", type=int, default=ADDRESS_SEED_DEFAULT, help="中文地址生成随机种子。")
    parser.add_argument("--variant-seed", type=int, default=VARIANT_SEED_DEFAULT, help="地址变体随机种子。")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="输出目录。")
    parser.add_argument("--dataset-limit", type=int, default=None, help="仅评测前 N 个样例，便于调试。")
    return parser.parse_args()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def load_helper(script_name: str) -> dict[str, Any]:
    return runpy.run_path(str(SCRIPTS_DIR / script_name))


def build_dataset_headline(result: dict[str, Any], *, locale_profile: str) -> dict[str, Any]:
    entity_summary = result["entity_summary"]
    sample_summary = result["sample_summary"]
    return {
        "dataset_name": result["dataset_name"],
        "dataset_path": result["dataset_path"],
        "locale_profile": locale_profile,
        "entity_count": entity_summary["entity_count"],
        "sample_count": sample_summary["sample_count"],
        "accepted_recall_rate": entity_summary["accepted_recall_rate"],
        "accepted_complete_rate": entity_summary["accepted_complete_rate"],
        "accepted_fragment_rate": entity_summary["accepted_fragment_rate"],
        "miss_rate": entity_summary["miss_rate"],
        "mean_fragment_piece_count": entity_summary["all_types"]["mean_fragment_piece_count"],
        "mean_fragment_coverage_percent": entity_summary["all_types"]["mean_fragment_coverage_percent"],
        "mean_background_fp_count": sample_summary["mean_background_fp_count"],
        "mean_wrong_type_prediction_count": sample_summary["mean_wrong_type_prediction_count"],
        "latency_ms": sample_summary["latency_ms"],
        "alignment_mismatch_count": len(result["alignment_mismatches"]),
    }


def pick_top_problem_types(entity_summary: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for entity_type, stats in entity_summary["per_type"].items():
        items.append(
            {
                "entity_type": entity_type,
                "count": stats["count"],
                "accepted_recall_rate": stats["accepted_recall_rate"],
                "accepted_fragment_rate": stats["accepted_fragment_rate"],
                "miss_rate": stats["miss_rate"],
                "mean_fragment_piece_count": stats["mean_fragment_piece_count"],
                "mean_fragment_coverage_percent": stats["mean_fragment_coverage_percent"],
            }
        )
    return sorted(
        items,
        key=lambda item: (
            item["accepted_recall_rate"],
            -item["miss_rate"],
            -item["accepted_fragment_rate"],
            -item["mean_fragment_piece_count"],
        ),
    )[:limit]


def compare_paired_datasets(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_key: str,
    right_key: str,
) -> dict[str, Any]:
    return {
        "left": left_key,
        "right": right_key,
        "accepted_recall_rate_delta": right["accepted_recall_rate"] - left["accepted_recall_rate"],
        "accepted_complete_rate_delta": right["accepted_complete_rate"] - left["accepted_complete_rate"],
        "accepted_fragment_rate_delta": right["accepted_fragment_rate"] - left["accepted_fragment_rate"],
        "miss_rate_delta": right["miss_rate"] - left["miss_rate"],
        "mean_fragment_piece_count_delta": right["mean_fragment_piece_count"] - left["mean_fragment_piece_count"],
        "mean_fragment_coverage_percent_delta": (
            right["mean_fragment_coverage_percent"] - left["mean_fragment_coverage_percent"]
        ),
        "mean_background_fp_count_delta": right["mean_background_fp_count"] - left["mean_background_fp_count"],
        "mean_wrong_type_prediction_count_delta": (
            right["mean_wrong_type_prediction_count"] - left["mean_wrong_type_prediction_count"]
        ),
    }


def sort_generated_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: (
            GENERATED_STATUS_RANK.get(str(row["status"]), -1),
            float(row["coverage_ratio"]),
            float(row["component_accuracy"]),
            -float(row["trace_fragment_count"]),
            -float(row["fragmented_component_count"]),
            -float(row["latency_ms"]),
        ),
    )


def evaluate_generated_addresses(
    zh_helper: dict[str, Any],
    detector: Any,
    *,
    address_count: int,
    address_seed: int,
    variant_seed: int,
) -> dict[str, Any]:
    address_rows = zh_helper["generate_addresses"](address_count, address_seed)
    variant_rows = zh_helper["generate_address_variants"](address_rows, variant_seed)
    full_eval_rows = [zh_helper["evaluate_address_row"](detector, row, "full") for row in address_rows]
    variant_eval_rows = [zh_helper["evaluate_address_row"](detector, row, "variant") for row in variant_rows]
    paired_rows = []
    for full_row, variant_row in zip(full_eval_rows, variant_eval_rows, strict=True):
        paired_rows.append(
            {
                "id": full_row["id"],
                "format": full_row["format"],
                "source_format": variant_row["source_format"],
                "variant_format": variant_row["format"],
                "variant_ops": variant_row["variant_ops"],
                "full_status": full_row["status"],
                "variant_status": variant_row["status"],
                "full_coverage_ratio": full_row["coverage_ratio"],
                "variant_coverage_ratio": variant_row["coverage_ratio"],
                "full_piece_count": full_row["piece_count"],
                "variant_piece_count": variant_row["piece_count"],
                "full_trace_fragment_count": full_row["trace_fragment_count"],
                "variant_trace_fragment_count": variant_row["trace_fragment_count"],
                "full_fragmented_component_count": full_row["fragmented_component_count"],
                "variant_fragmented_component_count": variant_row["fragmented_component_count"],
                "full_component_accuracy": full_row["component_accuracy"],
                "variant_component_accuracy": variant_row["component_accuracy"],
                "full_component_token_recall": full_row["component_token_recall"],
                "variant_component_token_recall": variant_row["component_token_recall"],
                "full_latency_ms": full_row["latency_ms"],
                "variant_latency_ms": variant_row["latency_ms"],
                "full_text": full_row["text"],
                "variant_text": variant_row["text"],
                "gt_components": variant_row["reference_components"],
            }
        )
    full_summary = zh_helper["summarize_address_rows"](full_eval_rows)
    variant_summary = zh_helper["summarize_address_rows"](variant_eval_rows)
    return {
        "address_count": address_count,
        "address_seed": address_seed,
        "variant_seed": variant_seed,
        "full_summary": full_summary,
        "variant_summary": variant_summary,
        "comparison": {
            "detected_rate_delta": (
                (1.0 - variant_summary["miss_rate"]) - (1.0 - full_summary["miss_rate"])
            ),
            "exact_complete_rate_delta": (
                variant_summary["exact_complete_rate"] - full_summary["exact_complete_rate"]
            ),
            "coverage_ratio_mean_delta": (
                variant_summary["coverage_ratio_mean"] - full_summary["coverage_ratio_mean"]
            ),
            "component_accuracy_mean_delta": (
                variant_summary["component_accuracy_mean"] - full_summary["component_accuracy_mean"]
            ),
            "trace_fragment_count_mean_delta": (
                variant_summary["trace_fragment_count_mean"] - full_summary["trace_fragment_count_mean"]
            ),
            "fragmented_component_count_mean_delta": (
                variant_summary["fragmented_component_count_mean"] - full_summary["fragmented_component_count_mean"]
            ),
            "latency_mean_ms_delta": (
                variant_summary["latency_ms"]["mean"] - full_summary["latency_ms"]["mean"]
            ),
        },
        "full_rows": full_eval_rows,
        "variant_rows": variant_eval_rows,
        "paired_rows": paired_rows,
        "worst_full_rows": sort_generated_rows(full_eval_rows)[:20],
        "worst_variant_rows": sort_generated_rows(variant_eval_rows)[:20],
    }


def build_report(
    *,
    synthetic_summary: dict[str, Any],
    dataset_headlines: dict[str, dict[str, Any]],
    dataset_problem_types: dict[str, list[dict[str, Any]]],
    paired_deltas: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# Detector 综合评测")
    lines.append("")
    lines.append("## 1. 中文生成地址")
    lines.append("")
    lines.append(
        f"- 原始地址识别率：`{1.0 - synthetic_summary['full_summary']['miss_rate']:.4f}`，"
        f"完整识别率：`{synthetic_summary['full_summary']['exact_complete_rate']:.4f}`。"
    )
    lines.append(
        f"- 变体地址识别率：`{1.0 - synthetic_summary['variant_summary']['miss_rate']:.4f}`，"
        f"完整识别率：`{synthetic_summary['variant_summary']['exact_complete_rate']:.4f}`。"
    )
    lines.append(
        f"- 原始地址平均组件准确率：`{synthetic_summary['full_summary']['component_accuracy_mean']:.4f}`，"
        f"变体平均组件准确率：`{synthetic_summary['variant_summary']['component_accuracy_mean']:.4f}`。"
    )
    lines.append(
        f"- 原始地址平均碎片量：`{synthetic_summary['full_summary']['trace_fragment_count_mean']:.4f}`，"
        f"变体平均碎片量：`{synthetic_summary['variant_summary']['trace_fragment_count_mean']:.4f}`。"
    )
    lines.append("")
    lines.append("## 2. 四个 realistic 数据集")
    lines.append("")
    lines.append("| 数据集 | 接受召回率 | 完整召回率 | 碎片召回率 | 漏检率 | 平均碎片数 | 平均碎片覆盖百分比 | 背景 FP/样例 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, headline in dataset_headlines.items():
        lines.append(
            f"| {key} | {headline['accepted_recall_rate']:.4f} | "
            f"{headline['accepted_complete_rate']:.4f} | {headline['accepted_fragment_rate']:.4f} | "
            f"{headline['miss_rate']:.4f} | {headline['mean_fragment_piece_count']:.2f} | "
            f"{headline['mean_fragment_coverage_percent']:.2f} | {headline['mean_background_fp_count']:.4f} |"
        )
    lines.append("")
    lines.append("## 3. structured -> surface 扰动变化")
    lines.append("")
    for locale, delta in paired_deltas.items():
        lines.append(
            f"- {locale}：接受召回率变化 `"
            f"{delta['accepted_recall_rate_delta']:+.4f}`，完整召回率变化 `"
            f"{delta['accepted_complete_rate_delta']:+.4f}`，碎片召回率变化 `"
            f"{delta['accepted_fragment_rate_delta']:+.4f}`，漏检率变化 `"
            f"{delta['miss_rate_delta']:+.4f}`。"
        )
    lines.append("")
    lines.append("## 4. 各数据集最差类型（前 5）")
    lines.append("")
    for key, rows in dataset_problem_types.items():
        lines.append(f"### {key}")
        lines.append("")
        lines.append("| 类型 | 数量 | 接受召回率 | 碎片召回率 | 漏检率 | 平均碎片数 | 平均碎片覆盖百分比 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for row in rows:
            lines.append(
                f"| {row['entity_type']} | {row['count']} | {row['accepted_recall_rate']:.4f} | "
                f"{row['accepted_fragment_rate']:.4f} | {row['miss_rate']:.4f} | "
                f"{row['mean_fragment_piece_count']:.2f} | {row['mean_fragment_coverage_percent']:.2f} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    started = time.perf_counter()

    zh_helper = load_helper("eval_detector_zh_paper.py")
    dataset_helper = load_helper("eval_detector_en_structured.py")

    detector_build = dataset_helper["detector_build"]
    zh_detector, zh_build_ms = detector_build("zh_cn")
    en_detector, en_build_ms = detector_build("en_us")
    zh_detector.detect("北京市海淀区中关村街道中山路1号", [])
    en_detector.detect("123 Main Street, Seattle, WA 98101", [])

    synthetic_result = evaluate_generated_addresses(
        zh_helper,
        zh_detector,
        address_count=int(args.address_count),
        address_seed=int(args.address_seed),
        variant_seed=int(args.variant_seed),
    )

    dataset_results: dict[str, dict[str, Any]] = {}
    dataset_headlines: dict[str, dict[str, Any]] = {}
    dataset_problem_types: dict[str, list[dict[str, Any]]] = {}
    for spec in DATASET_SPECS:
        detector = zh_detector if spec["locale_profile"] == "zh_cn" else en_detector
        result = dataset_helper["evaluate_dataset"](detector, spec["path"], limit=args.dataset_limit)
        dataset_results[spec["key"]] = result
        dataset_headlines[spec["key"]] = build_dataset_headline(
            result,
            locale_profile=str(spec["locale_profile"]),
        )
        dataset_problem_types[spec["key"]] = pick_top_problem_types(result["entity_summary"])

    paired_deltas = {
        "zh": compare_paired_datasets(
            dataset_headlines["zh_release_structured"],
            dataset_headlines["zh_surface_perturbed"],
            left_key="zh_release_structured",
            right_key="zh_surface_perturbed",
        ),
        "en": compare_paired_datasets(
            dataset_headlines["en_release_structured"],
            dataset_headlines["en_surface_perturbed"],
            left_key="en_release_structured",
            right_key="en_surface_perturbed",
        ),
    }

    total_runtime_ms = (time.perf_counter() - started) * 1000.0
    summary = {
        "detector_build_ms": {
            "zh_cn": zh_build_ms,
            "en_us": en_build_ms,
        },
        "total_runtime_ms": total_runtime_ms,
        "synthetic_generated_addresses": {
            "address_count": synthetic_result["address_count"],
            "address_seed": synthetic_result["address_seed"],
            "variant_seed": synthetic_result["variant_seed"],
            "full_summary": synthetic_result["full_summary"],
            "variant_summary": synthetic_result["variant_summary"],
            "comparison": synthetic_result["comparison"],
        },
        "datasets": dataset_headlines,
        "surface_perturbation_deltas": paired_deltas,
        "dataset_problem_types": dataset_problem_types,
    }

    output_dir = Path(args.output_dir)
    synthetic_dir = output_dir / "synthetic"
    datasets_dir = output_dir / "datasets"
    write_json(output_dir / "summary.json", summary)
    write_json(output_dir / "synthetic_summary.json", synthetic_result)
    write_jsonl(synthetic_dir / "full_address_details.jsonl", synthetic_result["full_rows"])
    write_jsonl(synthetic_dir / "variant_address_details.jsonl", synthetic_result["variant_rows"])
    write_jsonl(synthetic_dir / "paired_address_details.jsonl", synthetic_result["paired_rows"])
    write_json(synthetic_dir / "worst_full_rows.json", synthetic_result["worst_full_rows"])
    write_json(synthetic_dir / "worst_variant_rows.json", synthetic_result["worst_variant_rows"])

    for key, result in dataset_results.items():
        dataset_dir = datasets_dir / key
        headline = dataset_headlines[key]
        write_json(dataset_dir / "summary.json", headline)
        write_jsonl(dataset_dir / "entity_details.jsonl", result["entity_rows"])
        write_jsonl(dataset_dir / "sample_summary.jsonl", result["sample_rows"])
        write_jsonl(dataset_dir / "sample_entity_breakdown.jsonl", result["sample_breakdown"])
        write_jsonl(dataset_dir / "prediction_summary.jsonl", result["prediction_rows"])
        write_json(dataset_dir / "alignment_mismatches.json", result["alignment_mismatches"])
        write_json(dataset_dir / "worst_samples.json", result["worst_samples"])
        write_json(dataset_dir / "worst_sample_breakdown.json", result["worst_sample_breakdown"][:50])

    report = build_report(
        synthetic_summary={
            "full_summary": synthetic_result["full_summary"],
            "variant_summary": synthetic_result["variant_summary"],
        },
        dataset_headlines=dataset_headlines,
        dataset_problem_types=dataset_problem_types,
        paired_deltas=paired_deltas,
    )
    (output_dir / "report.md").write_text(report, encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
