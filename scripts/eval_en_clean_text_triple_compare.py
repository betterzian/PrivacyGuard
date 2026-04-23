"""英文结构化数据集：clean_text 三引擎对比（PrivacyGuard prompt 路径 / AndLab GLiNER+regex / Presidio）。

读取 `text_with_tags`，按与 `eval_detector_en_structured` 相同规则去标签得到 clean_text 与 GT spans，
依次运行：
- RuleBasedPIIDetector（仅 prompt：`detect(text, [])`，内部 `build_prompt_stream`）
- AndLab `PrivacyProtectionLayer._detect_entities`（与仓库内实现一致：GLiNER 优先，空则 regex）
- Presidio `AnalyzerEngine.analyze(..., entities=None)`（全部 recognizer 支持的实体类型）

输出 txt/json/jsonl 与汇总指标，便于与标注隐私对比。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# AndLab：将 utils_mobile 作为顶层包根（`privacy.*`）
ANDLAB_UTILS = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected" / "utils_mobile"
if ANDLAB_UTILS.is_dir():
    sys.path.insert(0, str(ANDLAB_UTILS))

# Presidio 源码树（未 pip 安装时使用）
PRESIDIO_ANALYZER_ROOT = ROOT / "tmp" / "presidio-main" / "presidio-analyzer"
if PRESIDIO_ANALYZER_ROOT.is_dir():
    sys.path.insert(0, str(PRESIDIO_ANALYZER_ROOT))

from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector

_spec = importlib.util.spec_from_file_location(
    "eval_detector_en_structured",
    ROOT / "scripts" / "eval_detector_en_structured.py",
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("无法加载 eval_detector_en_structured 模块")
_ed = importlib.util.module_from_spec(_spec)
sys.modules["eval_detector_en_structured"] = _ed
_spec.loader.exec_module(_ed)

PredictionSpan = _ed.PredictionSpan
TaggedEntity = _ed.TaggedEntity
classify_prediction = _ed.classify_prediction
coverage_ratio = _ed.coverage_ratio
detect_text = _ed.detect_text
detector_build = _ed.detector_build
evaluate_gt_entity = _ed.evaluate_gt_entity
interval_overlap = _ed.interval_overlap
merge_entities_with_inventory = _ed.merge_entities_with_inventory
strip_pii_tags = _ed.strip_pii_tags
write_json = _ed.write_json
write_jsonl = _ed.write_jsonl

# Presidio 实体类型 → 数据集粗粒度类型（用于「类型是否大致一致」辅助统计）
PRESIDIO_TO_DATASET_COARSE: dict[str, str] = {
    "PERSON": "NAME",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "LOCATION": "ADDRESS",
    "DATE_TIME": "TIME",
    "NRP": "NAME",
    "ORGANIZATION": "ORG",
    "ORG": "ORG",
    "CREDIT_CARD": "BANK_CARD",
    "US_BANK_NUMBER": "BANK_CARD",
    "IBAN_CODE": "BANK_CARD",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "US_PASSPORT": "PASSPORT_NUMBER",
    "IP_ADDRESS": "ACCOUNT_ID",
    "URL": "ACCOUNT_ID",
    "MEDICAL_LICENSE": "ID_CARD",
    "US_SSN": "ID_CARD",
    "CRYPTO": "ACCOUNT_ID",
    "UK_NHS": "MEMBER_ID",
}


def _andlab_label_to_coarse(label: str) -> str:
    u = (label or "").upper()
    if "PHONE" in u:
        return "PHONE"
    if "EMAIL" in u:
        return "EMAIL"
    if "CREDIT" in u or "CARD" in u:
        return "BANK_CARD"
    if "NAME" in u or "PERSON" in u or u in {"FIRST_NAME", "LAST_NAME"}:
        return "NAME"
    if "ADDRESS" in u or "LOCATION" in u or "STREET" in u or "CITY" in u or "STATE" in u or "ZIP" in u:
        return "ADDRESS"
    if "PASSPORT" in u:
        return "PASSPORT_NUMBER"
    if "DRIVER" in u or "LICENSE" in u:
        return "DRIVER_LICENSE"
    if "MONEY" in u or "AMOUNT" in u:
        return "AMOUNT"
    if "DOB" in u or "DATE" in u:
        return "TIME"
    if "ORG" in u:
        return "ORG"
    return "OTHER"


def evaluate_gt_span_coverage(
    entity: TaggedEntity,
    predictions: list[dict[str, Any]],
    *,
    coarse_from_pred: Any,
) -> dict[str, Any]:
    """不依赖 PrivacyGuard 类型体系，按 span 覆盖与粗类型一致性统计。"""
    preds_dicts = [
        {"start": int(p["start"]), "end": int(p["end"]), "entity_type": str(p.get("entity_type", ""))}
        for p in predictions
    ]
    any_cov = coverage_ratio(entity.start, entity.end, preds_dicts)
    best_type_match_cov = 0.0
    coarse_gt = entity.entity_type
    for p in predictions:
        coarse_pr = coarse_from_pred(p.get("entity_type", ""))
        if coarse_pr != coarse_gt:
            continue
        ov = interval_overlap(entity.start, entity.end, int(p["start"]), int(p["end"]))
        if ov <= 0:
            continue
        span_len = max(1, entity.end - entity.start)
        best_type_match_cov = max(best_type_match_cov, ov / span_len)
    return {
        "sample_id": entity.sample_id,
        "occurrence_index": entity.occurrence_index,
        "entity_type": entity.entity_type,
        "value": entity.value,
        "start": entity.start,
        "end": entity.end,
        "span_any_coverage": any_cov,
        "span_type_coarse_coverage": best_type_match_cov,
        "full_span_hit": any_cov >= 0.999,
    }


def pg_predictions_to_dicts(preds: list[PredictionSpan]) -> list[dict[str, Any]]:
    return [
        {
            "entity_type": p.entity_type,
            "text": p.text,
            "start": p.start,
            "end": p.end,
            "metadata": p.metadata,
        }
        for p in preds
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="clean_text 三引擎隐私检测对比评估。")
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=ROOT / "data" / "dataset" / "privacy_eval_realistic_1200_en_release_structured.json",
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "tmp" / "eval_en_clean_text_triple")
    parser.add_argument("--locale-profile", default="en_us")
    parser.add_argument("--limit", type=int, default=None, help="仅跑前 N 条，调试用。")
    args = parser.parse_args()

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    dataset = json.loads(args.dataset_path.read_text(encoding="utf-8"))
    samples = list(dataset["samples"][: args.limit] if args.limit else dataset["samples"])

    # 1) clean_text 导出：人类可读 txt + 机器可读 jsonl
    blocks_lines: list[str] = []
    jsonl_rows: list[dict[str, Any]] = []
    for sample in samples:
        sid = str(sample["sample_id"])
        plain, _parsed = strip_pii_tags(str(sample["text_with_tags"]))
        blocks_lines.append(f"===== {sid} =====\n{plain}\n")
        jsonl_rows.append({"sample_id": sid, "clean_text": plain})
    (out / "clean_text_blocks.txt").write_text("\n".join(blocks_lines), encoding="utf-8")
    write_jsonl(out / "clean_texts.jsonl", jsonl_rows)

    # 2) 可选引擎
    try:
        from privacy.layer import PrivacyProtectionLayer  # type: ignore

        andlab_layer_cls = PrivacyProtectionLayer
    except Exception as exc:  # pragma: no cover
        andlab_layer_cls = None
        andlab_import_error = str(exc)
    else:
        andlab_import_error = ""

    presidio_engine = None
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore

        presidio_engine = AnalyzerEngine()
    except Exception as exc:  # pragma: no cover
        presidio_import_error = str(exc)
    else:
        presidio_import_error = ""

    detector, _build_ms = detector_build(args.locale_profile)
    detector.detect("warmup 123 test@example.com", [])

    andlab_shared = andlab_layer_cls(enabled=True) if andlab_layer_cls is not None else None

    per_sample: list[dict[str, Any]] = []
    flat_entities: list[dict[str, Any]] = []

    pg_entity_rows: list[dict[str, Any]] = []
    andlab_cov_rows: list[dict[str, Any]] = []
    presidio_cov_rows: list[dict[str, Any]] = []

    t0 = time.perf_counter()
    for sample in samples:
        sid = str(sample["sample_id"])
        plain, parsed = strip_pii_tags(str(sample["text_with_tags"]))
        entities, _mis = merge_entities_with_inventory(sid, parsed, list(sample["pii_inventory"]))

        pg_preds, pg_ms = detect_text(detector, plain)
        pg_dicts = pg_predictions_to_dicts(pg_preds)

        andlab_preds: list[dict[str, Any]] = []
        andlab_ms = 0.0
        if andlab_shared is not None:
            t_a = time.perf_counter()
            raw = andlab_shared._detect_entities(plain)  # noqa: SLF001 — 与 AndLab 实现一致
            andlab_ms = (time.perf_counter() - t_a) * 1000.0
            for i, (s, e, lab) in enumerate(raw, start=1):
                text = plain[s:e]
                andlab_preds.append({"entity_type": lab, "text": text, "start": s, "end": e, "index": i})

        presidio_preds: list[dict[str, Any]] = []
        presidio_ms = 0.0
        if presidio_engine is not None:
            t_p = time.perf_counter()
            try:
                results = presidio_engine.analyze(text=plain, language="en", entities=None)
            except Exception as exc:
                results = []
                presidio_preds_error = str(exc)
            else:
                presidio_preds_error = ""
            presidio_ms = (time.perf_counter() - t_p) * 1000.0
            for i, r in enumerate(results, start=1):
                presidio_preds.append(
                    {
                        "entity_type": r.entity_type,
                        "text": plain[r.start : r.end],
                        "start": r.start,
                        "end": r.end,
                        "score": float(r.score),
                        "index": i,
                    }
                )
        else:
            presidio_preds_error = presidio_import_error

        for engine, plist in (
            ("privacyguard", pg_dicts),
            ("andlab", andlab_preds),
            ("presidio", presidio_preds),
        ):
            for p in plist:
                flat_entities.append(
                    {
                        "sample_id": sid,
                        "engine": engine,
                        "entity_type": p.get("entity_type"),
                        "start": p["start"],
                        "end": p["end"],
                        "text": p.get("text", plain[p["start"] : p["end"]]),
                    }
                )

        pg_evals = [evaluate_gt_entity(en, pg_preds) for en in entities]
        pg_entity_rows.extend(pg_evals)

        andlab_evals = [
            evaluate_gt_span_coverage(en, andlab_preds, coarse_from_pred=_andlab_label_to_coarse) for en in entities
        ]
        andlab_cov_rows.extend(andlab_evals)

        def _pres_coarse(t: object) -> str:
            return PRESIDIO_TO_DATASET_COARSE.get(str(t), "OTHER")

        pres_evals = [
            evaluate_gt_span_coverage(en, presidio_preds, coarse_from_pred=_pres_coarse) for en in entities
        ]
        presidio_cov_rows.extend(pres_evals)

        pg_pred_class = [classify_prediction(pr, entities) for pr in pg_preds]

        per_sample.append(
            {
                "sample_id": sid,
                "scene": sample.get("scene"),
                "entity_count": len(entities),
                "latency_ms": {
                    "privacyguard": pg_ms,
                    "andlab": andlab_ms,
                    "presidio": presidio_ms,
                },
                "prediction_count": {
                    "privacyguard": len(pg_preds),
                    "andlab": len(andlab_preds),
                    "presidio": len(presidio_preds),
                },
                "privacyguard": {
                    "predictions": pg_dicts,
                    "entity_eval": pg_evals,
                    "prediction_classify": pg_pred_class,
                },
                "andlab": {
                    "predictions": andlab_preds,
                    "entity_span_eval": andlab_evals,
                    "import_error": andlab_import_error,
                },
                "presidio": {
                    "predictions": presidio_preds,
                    "entity_span_eval": pres_evals,
                    "import_error": presidio_import_error or None,
                    "runtime_error": presidio_preds_error or None,
                },
            }
        )

    elapsed = (time.perf_counter() - t0) * 1000.0

    def _summarize_pg(rows: list[dict[str, Any]]) -> dict[str, Any]:
        c = Counter(r["status"] for r in rows)
        n = len(rows) or 1
        return {
            "entity_count": len(rows),
            "accepted_recall_rate": sum(1 for r in rows if r["status"] != "miss") / n,
            "exact_complete_rate": c.get("exact_complete", 0) / n,
            "miss_rate": c.get("miss", 0) / n,
        }

    def _summarize_span(rows: list[dict[str, Any]]) -> dict[str, Any]:
        n = len(rows) or 1
        return {
            "entity_count": len(rows),
            "mean_any_coverage": sum(r["span_any_coverage"] for r in rows) / n,
            "mean_coarse_type_coverage": sum(r["span_type_coarse_coverage"] for r in rows) / n,
            "full_span_hit_rate": sum(1 for r in rows if r["full_span_hit"]) / n,
        }

    summary = {
        "dataset_name": dataset.get("dataset_name"),
        "dataset_path": str(args.dataset_path),
        "sample_count": len(samples),
        "output_dir": str(out),
        "locale_profile": args.locale_profile,
        "total_wall_ms": elapsed,
        "andlab_import_error": andlab_import_error or None,
        "presidio_import_error": presidio_import_error or None,
        "privacyguard_entity_eval": _summarize_pg(pg_entity_rows),
        "andlab_span_eval": _summarize_span(andlab_cov_rows),
        "presidio_span_eval": _summarize_span(presidio_cov_rows),
    }

    write_json(out / "summary.json", summary)
    write_jsonl(out / "all_detected_entities.jsonl", flat_entities)
    write_jsonl(out / "per_sample_full.jsonl", per_sample)

    # 简短报告
    lines = [
        "# clean_text 三引擎对比（英文结构化 1200）",
        "",
        f"- 样例数: {len(samples)}",
        f"- PrivacyGuard（与 `eval_detector_en_structured` 相同实体级口径）: {json.dumps(summary['privacyguard_entity_eval'], ensure_ascii=False)}",
        f"- AndLab（span 任意覆盖 / 粗类型一致覆盖）: {json.dumps(summary['andlab_span_eval'], ensure_ascii=False)}",
        f"- Presidio（span 任意覆盖 / Presidio→数据集粗类型映射）: {json.dumps(summary['presidio_span_eval'], ensure_ascii=False)}",
        "",
        "## 说明",
        "- `clean_text_blocks.txt` / `clean_texts.jsonl`：由 `text_with_tags` 去 【PII:…】 标记后的文本。",
        "- PrivacyGuard：仅 prompt 流 + 与评测脚本一致的类型对齐/碎片化逻辑。",
        "- AndLab：`PrivacyProtectionLayer._detect_entities`，与源码一致（GLiNER 有结果则不用 regex 补齐）。",
        "- Presidio：`analyze(..., entities=None)` 使用注册的全部实体类型。",
        "- AndLab/Presidio 与数据集类型体系不同，除 span 覆盖外仅做粗类型映射辅助，不等同于 PrivacyGuard 的 exact/generic 判定。",
        "",
    ]
    if andlab_import_error:
        lines.append(f"**AndLab 导入失败**: `{andlab_import_error}`")
    if presidio_import_error:
        lines.append(f"**Presidio 导入/初始化失败**: `{presidio_import_error}`")
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
