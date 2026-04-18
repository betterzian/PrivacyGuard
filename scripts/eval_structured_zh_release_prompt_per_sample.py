"""structured 中文集：清洗 ``text_with_tags`` 后逐条样本跑 detector prompt 路径并评测。

- ``--strip-mode name_only``：仅剥离 ``【PII:NAME:数字】...【/PII】``，其它 ``【PII:...】`` 保留。
- ``--strip-mode all_pii_tags``：去除所有 ``【PII:...】`` 与 ``【/PII】`` 标记，得到与正文一致的 clean_text。
- 每条 ``clean_text`` 单独 ``detect``（空 OCR），再与当条 ``pii_inventory`` 做贪心微对齐。
"""

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
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

EVAL_LABEL_TO_ATTR: dict[str, PIIAttributeType] = {
    "ADDRESS": PIIAttributeType.ADDRESS,
    "NAME": PIIAttributeType.NAME,
    "PHONE": PIIAttributeType.PHONE,
    "EMAIL": PIIAttributeType.EMAIL,
    "ID_CARD": PIIAttributeType.ID_NUMBER,
    "BANK_CARD": PIIAttributeType.BANK_NUMBER,
    "ORG": PIIAttributeType.ORGANIZATION,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE,
}

# 仅姓名槽位：开标签 + 正文 + 关标签 -> 保留正文
NAME_SPAN_RE = re.compile(r"【PII:NAME:\d+】(.*?)【/PII】", re.DOTALL)
TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")


def _load_structured(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("structured 根节点应为 object。")
    return obj


def _strip_name_tags_only(text: str) -> str:
    s = str(text or "")
    prev = None
    while prev != s:
        prev = s
        s = NAME_SPAN_RE.sub(r"\1", s)
    return s


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


def _greedy_match(
    ground_truth: list[tuple[PIIAttributeType, str]],
    prompt_items: list[tuple[PIIAttributeType, str]],
) -> tuple[list[tuple[int, int]], set[int], set[int]]:
    pairs: list[tuple[int, int]] = []
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (attr, value) in enumerate(ground_truth):
        for ci, (c_attr, c_text) in enumerate(prompt_items):
            if ci in cand_used:
                continue
            if c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                pairs.append((gi, ci))
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return pairs, cand_used, gt_hit


def _serialize_inventory_item(item: dict[str, Any], mapped_attr: PIIAttributeType | None) -> dict[str, Any]:
    """将原始 pii_inventory 条目整理成评测输出结构。"""

    return {
        "type": str(item.get("type") or "").strip().upper(),
        "value": str(item.get("value") or "").strip(),
        "mapped_attr_type": mapped_attr.value if mapped_attr else None,
        "sensitivity": item.get("sensitivity"),
        "must_hide": bool(item.get("must_hide", False)),
        "relation_role": item.get("relation_role"),
        "canonical_slot": item.get("canonical_slot"),
        "persona_consistency_key": item.get("persona_consistency_key"),
        "linkability_scope": item.get("linkability_scope"),
        "annotation_importance": item.get("annotation_importance"),
        "evaluation_weight": item.get("evaluation_weight"),
        "optional_pii": item.get("optional_pii"),
        "derived_optional": item.get("derived_optional"),
    }


def _serialize_candidate(sample_id: str, candidate: Any) -> dict[str, Any]:
    """将 detector 候选整理成可直接落盘的字典。"""

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


def _top_counter_items(counter: Counter[str], *, key_name: str, topk: int) -> list[dict[str, Any]]:
    return [{key_name: text, "count": count} for text, count in counter.most_common(topk)]


def _ratio_text(value: float) -> str:
    return f"{value:.4f}"


def _truncate(text: str, limit: int = 88) -> str:
    s = str(text or "").replace("\n", "\\n").strip()
    if len(s) <= limit:
        return s
    return f"{s[: limit - 3]}..."


def _build_markdown_summary(
    *,
    out_obj: dict[str, Any],
    top_fp_text_by_attr: dict[str, list[dict[str, Any]]],
    top_fn_value_by_attr: dict[str, list[dict[str, Any]]],
    worst_samples: list[dict[str, Any]],
) -> str:
    """构造便于人工阅读的 Markdown 评测摘要。"""

    lines: list[str] = [
        "# 中文 structured prompt detector 评测摘要",
        "",
        "## 评测输入",
        "",
        f"- 输入 JSON：`{out_obj['inputs'][0]}`",
        f"- `strip_mode`：`{out_obj['strip_mode']}`",
        f"- `locale_profile`：`{out_obj['locale_profile']}`",
        f"- clean_text TXT：`{out_obj['clean_txt_path']}`",
        f"- 中间样本 JSON：`{out_obj['converted_json_path']}`",
        f"- 逐样本对比 JSON：`{out_obj['comparison_json_path']}`",
        f"- detector 全量候选 JSON：`{out_obj['output_json_path']}`",
        "",
        "## 总体指标",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| 样本数 | {out_obj['sample_count']} |",
        f"| detector prompt 候选总数 | {out_obj['detector_prompt_candidates_total']} |",
        f"| 可对齐 GT 条数 | {out_obj['ground_truth']['inventory_rows_mapped_for_eval']} |",
        f"| TP | {out_obj['micro_match_greedy']['tp']} |",
        f"| FN | {out_obj['micro_match_greedy']['fn']} |",
        f"| FP | {out_obj['micro_match_greedy']['fp']} |",
        f"| Recall | {_ratio_text(out_obj['micro_match_greedy']['recall'])} |",
        f"| Precision | {_ratio_text(out_obj['micro_match_greedy']['precision'])} |",
        f"| 检测累计耗时（秒） | {out_obj['timings']['detect_sum_seconds']} |",
        "",
        "## 各类型表现",
        "",
        "| 类型 | GT | Pred | TP | FN | FP | Recall | Precision |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for attr_key, metrics in out_obj["per_attr_mapped"].items():
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |".format(
                attr_key,
                metrics["gt"],
                metrics["predicted"],
                metrics["tp"],
                metrics["fn"],
                metrics["fp"],
                _ratio_text(float(metrics["recall"])),
                _ratio_text(float(metrics["precision"])),
            )
        )

    lines.extend(["", "## 结论摘要", ""])
    lines.extend(f"- {line}" for line in out_obj["analysis_zh"])

    lines.extend(["", "## 主要漏检", ""])
    if top_fn_value_by_attr:
        for attr_key, rows in top_fn_value_by_attr.items():
            preview = "；".join(f"`{_truncate(row['value'])}` x{row['count']}" for row in rows)
            lines.append(f"- `{attr_key}`：{preview}")
    else:
        lines.append("- 无漏检。")

    lines.extend(["", "## 主要误检", ""])
    if top_fp_text_by_attr:
        for attr_key, rows in top_fp_text_by_attr.items():
            preview = "；".join(f"`{_truncate(row['text'])}` x{row['count']}" for row in rows)
            lines.append(f"- `{attr_key}`：{preview}")
    else:
        lines.append("- 无误检。")

    lines.extend(["", "## 问题样本 Top 20", ""])
    if worst_samples:
        for row in worst_samples:
            missed = "、".join(f"`{_truncate(v)}`" for v in row["missed_values"]) or "无"
            extras = "、".join(f"`{_truncate(v)}`" for v in row["false_positive_texts"]) or "无"
            lines.append(
                f"- `{row['sample_id']}` `{row['scene']}`：TP={row['tp']}，FN={row['fn']}，FP={row['fp']}；漏检={missed}；误检={extras}"
            )
    else:
        lines.append("- 无问题样本。")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="zh structured：清洗后逐样本评测 detector")
    parser.add_argument("input_json", type=Path, help="privacy_eval_realistic_1200_zh_release_structured.json")
    parser.add_argument(
        "--strip-mode",
        choices=("name_only", "all_pii_tags"),
        default="name_only",
        help="name_only：只去 NAME 标签；all_pii_tags：去掉全部 PII 标记（与 eval_structured_zh_release_prompt 一致）。",
    )
    parser.add_argument(
        "--clean-txt",
        type=Path,
        default=None,
        help="逐条 clean_text 文本（默认随 strip-mode 变化）",
    )
    parser.add_argument(
        "--converted-json",
        type=Path,
        default=None,
        help="含 clean_text 与 pii_inventory 的中间 JSON（默认随 strip-mode 变化）",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="评测汇总 JSON（默认随 strip-mode 变化）",
    )
    parser.add_argument(
        "--comparison-json",
        type=Path,
        default=None,
        help="逐样本对比 JSON（包含 GT、命中、漏检、误检）",
    )
    parser.add_argument(
        "--summary-md",
        type=Path,
        default=None,
        help="Markdown 摘要报告",
    )
    parser.add_argument(
        "--locale-profile",
        default="mixed",
        choices=("mixed", "zh_cn", "en_us"),
    )
    parser.add_argument(
        "--protection-level",
        default=ProtectionLevel.STRONG.value,
        choices=(ProtectionLevel.STRONG.value, ProtectionLevel.BALANCED.value, ProtectionLevel.WEAK.value),
        help="规则检测保护度：strong/balanced/weak（默认 strong）。",
    )
    args = parser.parse_args()

    if args.strip_mode == "all_pii_tags":
        if args.clean_txt is None:
            args.clean_txt = Path("outputs/analysis/privacy_eval_realistic_1200_zh_full_clean_per_sample.txt")
        if args.converted_json is None:
            args.converted_json = Path("outputs/analysis/privacy_eval_realistic_1200_zh_full_clean_samples.json")
        if args.output is None:
            args.output = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_full_clean.json")
        if args.comparison_json is None:
            args.comparison_json = Path(
                "outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_full_clean_comparison.json"
            )
        if args.summary_md is None:
            args.summary_md = Path(
                "outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_full_clean_summary.md"
            )
    else:
        if args.clean_txt is None:
            args.clean_txt = Path("outputs/analysis/privacy_eval_realistic_1200_zh_name_stripped_clean_per_sample.txt")
        if args.converted_json is None:
            args.converted_json = Path("outputs/analysis/privacy_eval_realistic_1200_zh_name_stripped_clean_samples.json")
        if args.output is None:
            args.output = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample.json")
        if args.comparison_json is None:
            args.comparison_json = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_comparison.json")
        if args.summary_md is None:
            args.summary_md = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_summary.md")

    t0 = time.perf_counter()
    src = _load_structured(args.input_json)
    raw_samples = src.get("samples")
    if not isinstance(raw_samples, list):
        raise ValueError("缺少 samples 数组。")

    converted: list[dict[str, Any]] = []
    txt_lines: list[str] = []
    strip_fn = _strip_all_pii_tags if args.strip_mode == "all_pii_tags" else _strip_name_tags_only
    for row in raw_samples:
        twt = str(row.get("text_with_tags") or "")
        clean = strip_fn(twt)
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

    all_serializable: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []
    inventory_rows_total = 0
    label_unmapped = Counter()
    gt_by_attr: Counter[str] = Counter()
    tp_by_attr: Counter[str] = Counter()
    pred_by_attr: Counter[str] = Counter()
    fp_by_attr: Counter[str] = Counter()
    fn_by_attr: Counter[str] = Counter()
    fp_text_by_attr: dict[str, Counter[str]] = defaultdict(Counter)
    fn_value_by_attr: dict[str, Counter[str]] = defaultdict(Counter)
    per_sample_tp = 0
    per_sample_fn = 0
    per_sample_fp = 0
    detect_seconds_total = 0.0

    for row in converted:
        sid = str(row.get("sample_id") or "")
        clean = str(row.get("clean_text") or "")
        gt_local: list[tuple[PIIAttributeType, str]] = []
        gt_serializable: list[dict[str, Any]] = []
        unmapped_ground_truth: list[dict[str, Any]] = []
        for item in row.get("pii_inventory") or []:
            inventory_rows_total += 1
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            serialized_item = _serialize_inventory_item(item, mapped)
            if mapped is None:
                label_unmapped[label] += 1
                unmapped_ground_truth.append(serialized_item)
                continue
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            gt_local.append((mapped, val))
            gt_serializable.append(serialized_item)
            gt_by_attr[mapped.value] += 1

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

        prompt_items: list[tuple[PIIAttributeType, str]] = []
        prompt_candidates: list[dict[str, Any]] = []
        for c in raw_cands:
            if c.source != PIISourceType.PROMPT:
                continue
            prompt_items.append((c.attr_type, c.text))
            serialized_candidate = _serialize_candidate(sid, c)
            prompt_candidates.append(serialized_candidate)
            all_serializable.append(serialized_candidate)
            pred_by_attr[c.attr_type.value] += 1

        pairs, cand_used, gt_hit = _greedy_match(gt_local, prompt_items)
        tp = len(gt_hit)
        fn = len(gt_local) - tp
        fp = len(prompt_items) - len(cand_used)
        per_sample_tp += tp
        per_sample_fn += fn
        per_sample_fp += fp

        matched_pairs: list[dict[str, Any]] = []
        for gi, ci in pairs:
            attr_key = gt_local[gi][0].value
            tp_by_attr[attr_key] += 1
            matched_pairs.append(
                {
                    "ground_truth": gt_serializable[gi],
                    "detected": prompt_candidates[ci],
                }
            )

        false_negatives: list[dict[str, Any]] = []
        for gi, gt_item in enumerate(gt_serializable):
            if gi in gt_hit:
                continue
            attr_key = gt_local[gi][0].value
            fn_by_attr[attr_key] += 1
            fn_value_by_attr[attr_key][gt_item["value"][:200]] += 1
            false_negatives.append(gt_item)

        false_positives: list[dict[str, Any]] = []
        for ci, cand_item in enumerate(prompt_candidates):
            if ci in cand_used:
                continue
            attr_key = prompt_items[ci][0].value
            fp_by_attr[attr_key] += 1
            fp_text_by_attr[attr_key][cand_item["text"][:200]] += 1
            false_positives.append(cand_item)

        comparison_rows.append(
            {
                "sample_id": sid,
                "category": row.get("category", "unknown"),
                "scene": row.get("scene", ""),
                "text_with_tags": row.get("text_with_tags", ""),
                "clean_text": clean,
                "ground_truth_entities": gt_serializable,
                "unmapped_ground_truth_entities": unmapped_ground_truth,
                "detected_entities": prompt_candidates,
                "matched_pairs": matched_pairs,
                "false_negatives": false_negatives,
                "false_positives": false_positives,
                "stats": {
                    "ground_truth_count": len(gt_serializable),
                    "detected_count": len(prompt_candidates),
                    "tp": tp,
                    "fn": fn,
                    "fp": fp,
                },
            }
        )

    gt_total = sum(gt_by_attr.values())
    by_type_prompt = Counter(c["attr_type"] for c in all_serializable)
    per_attr: dict[str, dict[str, float | int]] = {}
    for attr_key in sorted(set(gt_by_attr.keys()) | set(pred_by_attr.keys())):
        gt_n = gt_by_attr[attr_key]
        pred_n = pred_by_attr[attr_key]
        tp_n = tp_by_attr[attr_key]
        fn_n = fn_by_attr[attr_key]
        fp_n = fp_by_attr[attr_key]
        per_attr[attr_key] = {
            "gt": gt_n,
            "predicted": pred_n,
            "tp": tp_n,
            "fn": fn_n,
            "fp": fp_n,
            "recall": tp_n / gt_n if gt_n else 0.0,
            "precision": tp_n / pred_n if pred_n else 0.0,
        }

    prec = per_sample_tp / (per_sample_tp + per_sample_fp) if (per_sample_tp + per_sample_fp) else 0.0
    rec = per_sample_tp / gt_total if gt_total else 0.0
    top_fp_text_by_attr = {
        attr_key: _top_counter_items(counter, key_name="text", topk=10)
        for attr_key, counter in sorted(fp_text_by_attr.items())
    }
    top_fn_value_by_attr = {
        attr_key: _top_counter_items(counter, key_name="value", topk=10)
        for attr_key, counter in sorted(fn_value_by_attr.items())
    }
    worst_samples = [
        {
            "sample_id": row["sample_id"],
            "scene": row["scene"],
            "tp": row["stats"]["tp"],
            "fn": row["stats"]["fn"],
            "fp": row["stats"]["fp"],
            "missed_values": [item["value"] for item in row["false_negatives"][:5]],
            "false_positive_texts": [item["text"] for item in row["false_positives"][:5]],
        }
        for row in sorted(
            comparison_rows,
            key=lambda item: (-item["stats"]["fn"], -item["stats"]["fp"], item["stats"]["tp"], item["sample_id"]),
        )[:20]
    ]
    major_fn = "，".join(f"`{attr}` {count} 条" for attr, count in fn_by_attr.most_common(3))
    major_fp = "，".join(f"`{attr}` {count} 条" for attr, count in fp_by_attr.most_common(3))

    out_obj: dict[str, Any] = {
        "inputs": [str(args.input_json.resolve())],
        "strip_mode": args.strip_mode,
        "locale_profile": args.locale_profile,
        "sample_count": len(converted),
        "eval_mode": "per_sample_prompt_then_aggregate",
        "clean_txt_path": str(args.clean_txt.resolve()),
        "converted_json_path": str(args.converted_json.resolve()),
        "comparison_json_path": str(args.comparison_json.resolve()),
        "summary_markdown_path": str(args.summary_md.resolve()),
        "output_json_path": str(args.output.resolve()),
        "timings": {
            "total_wall_seconds": round(time.perf_counter() - t0, 4),
            "detect_sum_seconds": round(detect_seconds_total, 4),
        },
        "detector_prompt_candidates_total": len(all_serializable),
        "detector_prompt_candidates_by_type": dict(sorted(by_type_prompt.items())),
        "ground_truth": {
            "inventory_rows_total": inventory_rows_total,
            "inventory_rows_mapped_for_eval": gt_total,
            "inventory_label_counts_not_in_detector_mapping": dict(label_unmapped.most_common()),
            "eval_label_to_attr": {k: v.value for k, v in EVAL_LABEL_TO_ATTR.items()},
        },
        "micro_match_greedy": {
            "tp": per_sample_tp,
            "fn": per_sample_fn,
            "fp": per_sample_fp,
            "recall": rec,
            "precision": prec,
            "note": "逐样本 detect；候选带 sample_id；TP/FN/FP 为各样本内贪心匹配之和。",
        },
        "per_attr_mapped": per_attr,
        "top_false_positive_texts_by_attr": top_fp_text_by_attr,
        "top_false_negative_values_by_attr": top_fn_value_by_attr,
        "worst_samples": worst_samples,
        "analysis_zh": (
            [
                f"strip_mode=all_pii_tags：已去除全部 ``【PII:...】`` / ``【/PII】``；共 {len(converted)} 条样本逐条 detect，detect 累计约 {detect_seconds_total:.1f}s。",
                f"prompt 候选总数 {len(all_serializable)}；可对齐 inventory {gt_total} 条。",
                f"召回 {rec:.4f}，精度 {prec:.4f}。",
                f"主要漏检类型：{major_fn or '无'}。",
                f"主要误检类型：{major_fp or '无'}。",
                "与仅去 NAME 标签的半标注文本相比，本模式为纯正文，检测难度与 FP 形态更接近线上。",
            ]
            if args.strip_mode == "all_pii_tags"
            else [
                f"strip_mode=name_only：仅去除 NAME 占位标签，其余 ``【PII:...】`` 仍保留；共 {len(converted)} 条样本逐条 detect，detect 累计约 {detect_seconds_total:.1f}s。",
                f"prompt 候选总数 {len(all_serializable)}；可对齐 inventory {gt_total} 条。",
                f"召回 {rec:.4f}，精度 {prec:.4f}。",
                f"主要漏检类型：{major_fn or '无'}。",
                f"主要误检类型：{major_fp or '无'}。",
                "与拼接长串评测相比：无 OCR_BREAK 跨样本干扰，但单条文本更短、上下文更少，指标可能不同。",
            ]
        ),
        "all_prompt_candidates": all_serializable,
    }

    comparison_obj: dict[str, Any] = {
        "inputs": [str(args.input_json.resolve())],
        "strip_mode": args.strip_mode,
        "locale_profile": args.locale_profile,
        "sample_count": len(comparison_rows),
        "comparison_rows": comparison_rows,
    }
    summary_md = _build_markdown_summary(
        out_obj=out_obj,
        top_fp_text_by_attr=top_fp_text_by_attr,
        top_fn_value_by_attr=top_fn_value_by_attr,
        worst_samples=worst_samples,
    )

    args.comparison_json.parent.mkdir(parents=True, exist_ok=True)
    args.comparison_json.write_text(json.dumps(comparison_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    args.summary_md.parent.mkdir(parents=True, exist_ok=True)
    args.summary_md.write_text(summary_md, encoding="utf-8")

    brief = {k: out_obj[k] for k in out_obj if k != "all_prompt_candidates"}
    print(json.dumps(brief, ensure_ascii=False, indent=2))
    print(f"\n已写入逐样本对比: {args.comparison_json}")
    print(f"已写入 Markdown 摘要: {args.summary_md}")
    print(f"已写入全量候选: {args.output}")


if __name__ == "__main__":
    main()
