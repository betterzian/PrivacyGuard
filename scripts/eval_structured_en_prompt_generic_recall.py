"""英文 structured 数据集：clean_text -> detector(prompt) -> 精确/通用召回评测。"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.detector.stacks.structured import (
    ALLOWED_DETECTOR_OUTPUT_ATTRS,
    PERSONA_ONLY_ATTRS,
)
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")

# 数据集 type -> detector 评测 attr
EVAL_LABEL_TO_ATTR: dict[str, PIIAttributeType] = {
    "ADDRESS": PIIAttributeType.ADDRESS,
    "NAME": PIIAttributeType.NAME,
    "PHONE": PIIAttributeType.PHONE,
    "EMAIL": PIIAttributeType.EMAIL,
    "BANK_CARD": PIIAttributeType.BANK_NUMBER,
    "ORG": PIIAttributeType.ORGANIZATION,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE,
    "LICENSE_PLATE": PIIAttributeType.LICENSE_PLATE,
    "TIME": PIIAttributeType.TIME,
    "AMOUNT": PIIAttributeType.AMOUNT,
    "ORDER_ID": PIIAttributeType.ALNUM,
    "TRACKING_ID": PIIAttributeType.ALNUM,
    "MEMBER_ID": PIIAttributeType.ALNUM,
    "ACCOUNT_ID": PIIAttributeType.ALNUM,
    "BIRTHDAY": PIIAttributeType.TIME,
}

SEMANTIC_ATTRS = frozenset(
    {
        PIIAttributeType.NAME,
        PIIAttributeType.ORGANIZATION,
        PIIAttributeType.ADDRESS,
    }
)
GENERIC_RECALL_ATTRS = frozenset({PIIAttributeType.NUM, PIIAttributeType.ALNUM})


def _load_structured(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("structured 根节点应为 object。")
    return obj


def _strip_all_pii_tags(text: str) -> str:
    cleaned = TAG_OPEN_RE.sub("", str(text or ""))
    return TAG_CLOSE_RE.sub("", cleaned)


def _address_micro_match(gt_value: str, cand_text: str) -> bool:
    g = str(gt_value or "").strip()
    c = str(cand_text or "").strip()
    if not g or not c:
        return False
    return g in c or c in g


def _micro_match(attr: PIIAttributeType, gt_value: str, cand_text: str) -> bool:
    if attr == PIIAttributeType.ADDRESS:
        return _address_micro_match(gt_value, cand_text)
    left = normalize_pii(attr, gt_value)
    right = normalize_pii(attr, cand_text)
    return same_entity(left, right)


def _serialize_candidate(sample_id: str, candidate: Any) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "entity_id": candidate.entity_id,
        "attr_type": candidate.attr_type.value,
        "source": candidate.source.value,
        "text": candidate.text,
        "normalized_text": candidate.normalized_text,
        "span_start": candidate.span_start,
        "span_end": candidate.span_end,
        "confidence": candidate.confidence,
        "metadata": candidate.metadata,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="EN structured：detector prompt 评测（精确/通用召回）")
    parser.add_argument(
        "input_json",
        type=Path,
        nargs="?",
        default=Path("data/dataset/privacy_eval_realistic_1200_en_release_structured.json"),
    )
    parser.add_argument(
        "--clean-txt",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_en_full_clean_per_sample.txt"),
    )
    parser.add_argument(
        "--converted-json",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_en_full_clean_samples.json"),
    )
    parser.add_argument(
        "--comparison-json",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_en_prompt_detector_generic_comparison.json"),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_en_prompt_detector_generic_report.json"),
    )
    parser.add_argument(
        "--all-entities-json",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_en_prompt_detector_all_entities.json"),
    )
    parser.add_argument("--locale-profile", default="en_us", choices=("mixed", "zh_cn", "en_us"))
    parser.add_argument(
        "--protection-level",
        default=ProtectionLevel.STRONG.value,
        choices=(ProtectionLevel.STRONG.value, ProtectionLevel.BALANCED.value, ProtectionLevel.WEAK.value),
    )
    args = parser.parse_args()

    t0 = time.perf_counter()
    src = _load_structured(args.input_json)
    raw_samples = src.get("samples")
    if not isinstance(raw_samples, list):
        raise ValueError("缺少 samples 数组。")

    converted: list[dict[str, Any]] = []
    txt_lines: list[str] = []
    for row in raw_samples:
        twt = str(row.get("text_with_tags") or "")
        clean = _strip_all_pii_tags(twt)
        sid = str(row.get("sample_id") or "")
        converted.append(
            {
                "sample_id": sid,
                "category": row.get("category", "unknown"),
                "scene": row.get("scene", ""),
                "text_with_tags": twt,
                "clean_text": clean,
                "pii_inventory": row.get("pii_inventory", []),
            }
        )
        txt_lines.append(f"<<<SAMPLE {sid}>>>")
        txt_lines.append(clean)
        txt_lines.append("<<<END>>>")
        txt_lines.append("")

    args.clean_txt.parent.mkdir(parents=True, exist_ok=True)
    args.clean_txt.write_text("\n".join(txt_lines), encoding="utf-8")
    args.converted_json.parent.mkdir(parents=True, exist_ok=True)
    args.converted_json.write_text(json.dumps(converted, ensure_ascii=False, indent=2), encoding="utf-8")

    detector = RuleBasedPIIDetector(locale_profile=args.locale_profile)
    protection_level = ProtectionLevel(str(args.protection_level))

    all_entities: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []
    observed_pred_attr_counter: Counter[str] = Counter()
    unmapped_label_counter: Counter[str] = Counter()

    per_type: dict[str, Counter[str]] = defaultdict(Counter)
    global_tp_exact = 0
    global_tp_generic = 0
    global_fn = 0
    global_fp = 0
    detect_seconds_total = 0.0
    gt_total = 0

    for row in converted:
        sid = str(row.get("sample_id") or "")
        clean = str(row.get("clean_text") or "")

        gt_items: list[dict[str, Any]] = []
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                unmapped_label_counter[label] += 1
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            gt_items.append(
                {
                    "dataset_type": label,
                    "mapped_attr_type": mapped.value,
                    "value": value,
                }
            )
            gt_total += 1
            per_type[mapped.value]["total"] += 1

        t_det0 = time.perf_counter()
        raw_cands = detector.detect(
            clean,
            [],
            session_id=None,
            turn_id=None,
            protection_level=protection_level,
            detector_overrides=None,
        )
        detect_seconds_total += time.perf_counter() - t_det0

        prompt_candidates: list[dict[str, Any]] = []
        for c in raw_cands:
            if c.source != PIISourceType.PROMPT:
                continue
            serial = _serialize_candidate(sid, c)
            prompt_candidates.append(serial)
            all_entities.append(serial)
            observed_pred_attr_counter[serial["attr_type"]] += 1

        gt_used: set[int] = set()
        cand_used: set[int] = set()
        exact_matches: list[dict[str, Any]] = []
        generic_matches: list[dict[str, Any]] = []

        # 第一阶段：精确召回（类型一致 + 实体一致）
        for gi, gt in enumerate(gt_items):
            gt_attr = PIIAttributeType(gt["mapped_attr_type"])
            gt_val = gt["value"]
            for ci, cand in enumerate(prompt_candidates):
                if ci in cand_used:
                    continue
                if cand["attr_type"] != gt_attr.value:
                    continue
                if not _micro_match(gt_attr, gt_val, cand["text"]):
                    continue
                gt_used.add(gi)
                cand_used.add(ci)
                per_type[gt_attr.value]["exact_tp"] += 1
                exact_matches.append({"gt_index": gi, "pred_index": ci})
                break

        # 第二阶段：通用召回（仅非语义类 GT，允许由 num/alnum 召回）
        for gi, gt in enumerate(gt_items):
            if gi in gt_used:
                continue
            gt_attr = PIIAttributeType(gt["mapped_attr_type"])
            if gt_attr in SEMANTIC_ATTRS:
                continue
            gt_val = gt["value"]
            for ci, cand in enumerate(prompt_candidates):
                if ci in cand_used:
                    continue
                cand_attr = PIIAttributeType(cand["attr_type"])
                if cand_attr not in GENERIC_RECALL_ATTRS:
                    continue
                if not _micro_match(gt_attr, gt_val, cand["text"]):
                    continue
                gt_used.add(gi)
                cand_used.add(ci)
                per_type[gt_attr.value]["generic_tp"] += 1
                generic_matches.append({"gt_index": gi, "pred_index": ci, "pred_attr_type": cand_attr.value})
                break

        sample_tp_exact = len(exact_matches)
        sample_tp_generic = len(generic_matches)
        sample_fn = len(gt_items) - len(gt_used)
        sample_fp = len(prompt_candidates) - len(cand_used)

        global_tp_exact += sample_tp_exact
        global_tp_generic += sample_tp_generic
        global_fn += sample_fn
        global_fp += sample_fp

        false_negatives: list[dict[str, Any]] = []
        for gi, gt in enumerate(gt_items):
            if gi in gt_used:
                continue
            per_type[gt["mapped_attr_type"]]["fn"] += 1
            false_negatives.append(gt)

        false_positives: list[dict[str, Any]] = []
        for ci, cand in enumerate(prompt_candidates):
            if ci in cand_used:
                continue
            false_positives.append(cand)

        comparison_rows.append(
            {
                "sample_id": sid,
                "scene": row.get("scene", ""),
                "text_with_tags": row.get("text_with_tags", ""),
                "clean_text": clean,
                "ground_truth_entities": gt_items,
                "detected_entities": prompt_candidates,
                "exact_matches": exact_matches,
                "generic_matches": generic_matches,
                "false_negatives": false_negatives,
                "false_positives": false_positives,
                "stats": {
                    "gt_count": len(gt_items),
                    "detected_count": len(prompt_candidates),
                    "tp_exact": sample_tp_exact,
                    "tp_generic": sample_tp_generic,
                    "tp_total": sample_tp_exact + sample_tp_generic,
                    "fn": sample_fn,
                    "fp": sample_fp,
                },
            }
        )

    report_per_type: dict[str, dict[str, float | int]] = {}
    for attr_key, bucket in sorted(per_type.items()):
        total = int(bucket["total"])
        exact_tp = int(bucket["exact_tp"])
        generic_tp = int(bucket["generic_tp"])
        fn = int(bucket["fn"])
        report_per_type[attr_key] = {
            "total": total,
            "exact_tp": exact_tp,
            "generic_tp": generic_tp,
            "tp_total": exact_tp + generic_tp,
            "fn": fn,
            "exact_recall": exact_tp / total if total else 0.0,
            "generic_recall": generic_tp / total if total else 0.0,
            "total_recall": (exact_tp + generic_tp) / total if total else 0.0,
            "generic_share_in_recalled": generic_tp / (exact_tp + generic_tp) if (exact_tp + generic_tp) else 0.0,
        }

    tp_total = global_tp_exact + global_tp_generic
    precision = tp_total / (tp_total + global_fp) if (tp_total + global_fp) else 0.0
    recall = tp_total / gt_total if gt_total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    analysis_zh = [
        f"共 {len(converted)} 条样本；GT 总实体 {gt_total}；detector prompt 候选 {len(all_entities)}。",
        f"总体：TP(精确)={global_tp_exact}，TP(通用)={global_tp_generic}，FN={global_fn}，FP={global_fp}。",
        f"总体召回={recall:.4f}，总体精度={precision:.4f}，F1={f1:.4f}。",
        "通用召回规则：仅针对非语义类 GT（非 name/org/address），若被 num/alnum 命中则记为通用召回，不计 FN，也不把该命中计为 FP。",
        "各类型中 generic_recall 表示“该类型有多少比例是由通用召回贡献”，generic_share_in_recalled 表示“该类型已召回部分里有多少来自通用召回”。",
    ]

    out_obj: dict[str, Any] = {
        "inputs": [str(args.input_json.resolve())],
        "clean_txt_path": str(args.clean_txt.resolve()),
        "converted_json_path": str(args.converted_json.resolve()),
        "comparison_json_path": str(args.comparison_json.resolve()),
        "all_entities_json_path": str(args.all_entities_json.resolve()),
        "sample_count": len(converted),
        "locale_profile": args.locale_profile,
        "protection_level": args.protection_level,
        "detector_supported_attrs": {
            "allowed_detector_output_attrs": sorted(attr.value for attr in ALLOWED_DETECTOR_OUTPUT_ATTRS),
            "persona_only_attrs": sorted(attr.value for attr in PERSONA_ONLY_ATTRS),
        },
        "detector_observed_attrs_in_this_eval": dict(observed_pred_attr_counter.most_common()),
        "ground_truth": {
            "gt_total": gt_total,
            "unmapped_dataset_labels": dict(unmapped_label_counter.most_common()),
            "eval_label_to_attr": {k: v.value for k, v in EVAL_LABEL_TO_ATTR.items()},
        },
        "metrics_global": {
            "tp_exact": global_tp_exact,
            "tp_generic": global_tp_generic,
            "tp_total": tp_total,
            "fn": global_fn,
            "fp": global_fp,
            "recall": recall,
            "precision": precision,
            "f1": f1,
        },
        "metrics_per_type": report_per_type,
        "timings": {
            "detect_sum_seconds": round(detect_seconds_total, 4),
            "total_wall_seconds": round(time.perf_counter() - t0, 4),
        },
        "analysis_zh": analysis_zh,
    }

    args.all_entities_json.parent.mkdir(parents=True, exist_ok=True)
    args.all_entities_json.write_text(json.dumps(all_entities, ensure_ascii=False, indent=2), encoding="utf-8")
    args.comparison_json.parent.mkdir(parents=True, exist_ok=True)
    args.comparison_json.write_text(json.dumps(comparison_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n".join(analysis_zh))
    print(f"已写入: {args.output}")


if __name__ == "__main__":
    main()
