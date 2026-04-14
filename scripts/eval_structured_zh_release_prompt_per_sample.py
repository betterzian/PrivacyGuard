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
from collections import Counter
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
) -> tuple[set[int], set[int]]:
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (attr, value) in enumerate(ground_truth):
        for ci, (c_attr, c_text) in enumerate(prompt_items):
            if ci in cand_used:
                continue
            if c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return cand_used, gt_hit


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
        "--locale-profile",
        default="mixed",
        choices=("mixed", "zh_cn", "en_us"),
    )
    args = parser.parse_args()

    if args.strip_mode == "all_pii_tags":
        if args.clean_txt is None:
            args.clean_txt = Path("outputs/analysis/privacy_eval_realistic_1200_zh_full_clean_per_sample.txt")
        if args.converted_json is None:
            args.converted_json = Path("outputs/analysis/privacy_eval_realistic_1200_zh_full_clean_samples.json")
        if args.output is None:
            args.output = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample_full_clean.json")
    else:
        if args.clean_txt is None:
            args.clean_txt = Path("outputs/analysis/privacy_eval_realistic_1200_zh_name_stripped_clean_per_sample.txt")
        if args.converted_json is None:
            args.converted_json = Path("outputs/analysis/privacy_eval_realistic_1200_zh_name_stripped_clean_samples.json")
        if args.output is None:
            args.output = Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector_per_sample.json")

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

    all_serializable: list[dict[str, Any]] = []
    inventory_rows_total = 0
    label_unmapped = Counter()
    gt_by_attr: Counter[str] = Counter()
    hit_by_attr: Counter[str] = Counter()
    per_sample_tp = 0
    per_sample_fn = 0
    per_sample_fp = 0
    detect_seconds_total = 0.0

    for row in converted:
        sid = str(row.get("sample_id") or "")
        clean = str(row.get("clean_text") or "")
        gt_local: list[tuple[PIIAttributeType, str]] = []
        for item in row.get("pii_inventory") or []:
            inventory_rows_total += 1
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                label_unmapped[label] += 1
                continue
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            gt_local.append((mapped, val))
            gt_by_attr[mapped.value] += 1

        t_det0 = time.perf_counter()
        raw_cands = detector.detect(
            clean,
            [],
            session_id=None,
            turn_id=None,
            protection_level=ProtectionLevel.STRONG,
            detector_overrides=None,
        )
        detect_seconds_total += time.perf_counter() - t_det0

        prompt_items: list[tuple[PIIAttributeType, str]] = []
        for c in raw_cands:
            if c.source != PIISourceType.PROMPT:
                continue
            prompt_items.append((c.attr_type, c.text))
            all_serializable.append(
                {
                    "sample_id": sid,
                    "entity_id": c.entity_id,
                    "attr_type": c.attr_type.value,
                    "text": c.text,
                    "normalized_text": c.normalized_text,
                    "span_start": c.span_start,
                    "span_end": c.span_end,
                    "confidence": c.confidence,
                }
            )

        cand_used, gt_hit = _greedy_match(gt_local, prompt_items)
        tp = len(gt_hit)
        fn = len(gt_local) - tp
        fp = len(prompt_items) - len(cand_used)
        per_sample_tp += tp
        per_sample_fn += fn
        per_sample_fp += fp
        for gi in gt_hit:
            hit_by_attr[gt_local[gi][0].value] += 1

    gt_total = sum(gt_by_attr.values())
    by_type_prompt = Counter(c["attr_type"] for c in all_serializable)
    per_attr: dict[str, dict[str, float | int]] = {}
    for attr_key in sorted(gt_by_attr.keys()):
        gt_n = gt_by_attr[attr_key]
        hit = hit_by_attr[attr_key]
        per_attr[attr_key] = {"gt": gt_n, "hit": hit, "recall": hit / gt_n if gt_n else 0.0}

    prec = per_sample_tp / (per_sample_tp + per_sample_fp) if (per_sample_tp + per_sample_fp) else 0.0
    rec = per_sample_tp / gt_total if gt_total else 0.0

    out_obj: dict[str, Any] = {
        "inputs": [str(args.input_json.resolve())],
        "strip_mode": args.strip_mode,
        "locale_profile": args.locale_profile,
        "sample_count": len(converted),
        "eval_mode": "per_sample_prompt_then_aggregate",
        "clean_txt_path": str(args.clean_txt.resolve()),
        "converted_json_path": str(args.converted_json.resolve()),
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
        "analysis_zh": (
            [
                f"strip_mode=all_pii_tags：已去除全部 ``【PII:...】`` / ``【/PII】``；共 {len(converted)} 条样本逐条 detect，detect 累计约 {detect_seconds_total:.1f}s。",
                f"prompt 候选总数 {len(all_serializable)}；可对齐 inventory {gt_total} 条。",
                f"召回 {rec:.4f}，精度 {prec:.4f}。",
                "与仅去 NAME 标签的半标注文本相比，本模式为纯正文，检测难度与 FP 形态更接近线上。",
            ]
            if args.strip_mode == "all_pii_tags"
            else [
                f"strip_mode=name_only：仅去除 NAME 占位标签，其余 ``【PII:...】`` 仍保留；共 {len(converted)} 条样本逐条 detect，detect 累计约 {detect_seconds_total:.1f}s。",
                f"prompt 候选总数 {len(all_serializable)}；可对齐 inventory {gt_total} 条。",
                f"召回 {rec:.4f}，精度 {prec:.4f}。",
                "与拼接长串评测相比：无 OCR_BREAK 跨样本干扰，但单条文本更短、上下文更少，指标可能不同。",
            ]
        ),
        "all_prompt_candidates": all_serializable,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    brief = {k: out_obj[k] for k in out_obj if k != "all_prompt_candidates"}
    print(json.dumps(brief, ensure_ascii=False, indent=2))
    print(f"\n已写入全量候选: {args.output}")


if __name__ == "__main__":
    main()
