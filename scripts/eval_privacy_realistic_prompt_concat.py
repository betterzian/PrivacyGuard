"""将多份评测 JSON 的 clean_text 用 ``<OCR_BREAK>`` 拼成单串，走 RuleBased prompt+空 OCR 路径并对比 pii_inventory。

输出 metrics（与 ``outputs/analysis/privacy_eval_realistic_1000_prompt_detector.json`` 口径一致）及
全部 prompt 源候选列表，便于人工抽查。
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

# inventory 标签 -> 检测器属性（未列出的类型不计入 GT 分母，仅统计分布）
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


def _load_samples(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"期望 JSON 数组: {path}")
    return data


def _address_micro_match(gt_value: str, cand_text: str) -> bool:
    g = str(gt_value or "").strip()
    c = str(cand_text or "").strip()
    if not g or not c:
        return False
    return g in c or c in g


def _non_address_micro_match(attr: PIIAttributeType, gt_value: str, cand_text: str) -> bool:
    left = normalize_pii(attr, gt_value)
    right = normalize_pii(attr, cand_text)
    return same_entity(left, right)


def _micro_match(attr: PIIAttributeType, gt_value: str, cand_text: str) -> bool:
    if attr == PIIAttributeType.ADDRESS:
        return _address_micro_match(gt_value, cand_text)
    return _non_address_micro_match(attr, gt_value, cand_text)


def _greedy_match(
    ground_truth: list[tuple[PIIAttributeType, str, str]],
    prompt_candidates: list[tuple[PIIAttributeType, str]],
) -> tuple[set[int], set[int]]:
    """返回 (已匹配的候选下标集合, 已匹配的 GT 下标集合)。"""
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (attr, _sid, value) in enumerate(ground_truth):
        for ci, (c_attr, c_text) in enumerate(prompt_candidates):
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
    parser = argparse.ArgumentParser(description="clean_text 拼接后评测 rule_based detector（prompt 路径）")
    parser.add_argument(
        "json_paths",
        nargs="+",
        type=Path,
        help="privacy_eval_realistic_*.json 路径（按顺序拼接）",
    )
    parser.add_argument(
        "--locale-profile",
        default="mixed",
        choices=("mixed", "zh_cn", "en_us"),
        help="RuleBasedPIIDetector.locale_profile",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_prompt_concat_detector.json"),
        help="汇总 JSON 输出路径",
    )
    args = parser.parse_args()

    t0 = time.perf_counter()
    all_samples: list[dict[str, Any]] = []
    for p in args.json_paths:
        all_samples.extend(_load_samples(p))
    t_load = time.perf_counter()

    parts: list[str] = []
    for row in all_samples:
        ct = str(row.get("clean_text") or "")
        parts.append(ct)
    combined = OCR_BREAK.join(parts)
    t_join = time.perf_counter()

    inventory_rows_total = 0
    label_unmapped_counter: Counter[str] = Counter()
    ground_truth: list[tuple[PIIAttributeType, str, str]] = []
    fn_category_counter: Counter[str] = Counter()

    for row in all_samples:
        sid = str(row.get("sample_id") or "")
        category = str(row.get("category") or "unknown")
        for item in row.get("pii_inventory") or []:
            inventory_rows_total += 1
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                label_unmapped_counter[label] += 1
                continue
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            ground_truth.append((mapped, sid, val))

    detector = RuleBasedPIIDetector(locale_profile=args.locale_profile)
    t_det0 = time.perf_counter()
    raw_candidates = detector.detect(
        combined,
        [],
        session_id=None,
        turn_id=None,
        protection_level=ProtectionLevel.STRONG,
        detector_overrides=None,
    )
    t_det1 = time.perf_counter()

    prompt_items: list[tuple[PIIAttributeType, str]] = []
    serializable_candidates: list[dict[str, Any]] = []
    for c in raw_candidates:
        if c.source != PIISourceType.PROMPT:
            continue
        prompt_items.append((c.attr_type, c.text))
        serializable_candidates.append(
            {
                "entity_id": c.entity_id,
                "attr_type": c.attr_type.value,
                "text": c.text,
                "normalized_text": c.normalized_text,
                "span_start": c.span_start,
                "span_end": c.span_end,
                "confidence": c.confidence,
            }
        )

    cand_used, gt_hit = _greedy_match(ground_truth, prompt_items)
    tp = len(gt_hit)
    fn = len(ground_truth) - tp
    fp = len(prompt_items) - len(cand_used)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / len(ground_truth) if ground_truth else 0.0

    for gi, (attr, sid, value) in enumerate(ground_truth):
        if gi in gt_hit:
            continue
        cat = "unknown"
        for row in all_samples:
            if str(row.get("sample_id") or "") == sid:
                cat = str(row.get("category") or "unknown")
                break
        fn_category_counter[cat] += 1

    by_type_prompt = Counter(c.attr_type.value for c in raw_candidates if c.source == PIISourceType.PROMPT)

    per_attr: dict[str, dict[str, float | int]] = {}
    for attr in sorted({a.value for a in EVAL_LABEL_TO_ATTR.values()}):
        pat = PIIAttributeType(attr)
        gt_n = sum(1 for a, _, _ in ground_truth if a == pat)
        if gt_n == 0:
            continue
        sub_gt = [(i, v) for i, (a, _, v) in enumerate(ground_truth) if a == pat]
        hit = sum(1 for i, _ in sub_gt if i in gt_hit)
        per_attr[attr] = {"gt": gt_n, "hit": hit, "recall": hit / gt_n}

    fn_by_category_top = fn_category_counter.most_common(12)

    analysis_zh = [
        f"拼接 {len(args.json_paths)} 个文件共 {len(all_samples)} 条样本；``{OCR_BREAK}`` 分隔；合并字符数 {len(combined)}。",
        f"locale_profile={args.locale_profile}；prompt 候选总数 {len(prompt_items)}；可对齐 inventory 行数 {len(ground_truth)} / 原始 inventory 总行 {inventory_rows_total}。",
        f"微对齐（贪心、候选不重复）：TP={tp}，FN={fn}，FP={fp}，召回={rec:.4f}，精度={prec:.4f}。",
        "地址 GT 与候选为双向子串互含；其余类型用 ``same_entity(normalize_pii)``。",
    ]
    for attr_key, row in sorted(per_attr.items(), key=lambda kv: (-float(kv[1]["recall"]), kv[0])):
        analysis_zh.append(f"- {attr_key}: GT {row['gt']}，命中 {row['hit']}，召回约 {float(row['recall']):.1%}。")

    out_obj: dict[str, Any] = {
        "inputs": [str(p.resolve()) for p in args.json_paths],
        "locale_profile": args.locale_profile,
        "sample_count": len(all_samples),
        "combined_char_len": len(combined),
        "ocr_break_token": OCR_BREAK,
        "timings": {
            "load_json_seconds": round(t_load - t0, 4),
            "join_text_seconds": round(t_join - t_load, 4),
            "detect_seconds": round(t_det1 - t_det0, 4),
        },
        "detector_prompt_candidates_total": len(prompt_items),
        "detector_prompt_candidates_by_type": dict(sorted(by_type_prompt.items())),
        "ground_truth": {
            "inventory_rows_total": inventory_rows_total,
            "inventory_rows_mapped_for_eval": len(ground_truth),
            "inventory_label_counts_not_in_detector_mapping": dict(label_unmapped_counter.most_common()),
            "eval_label_to_attr": {k: v.value for k, v in EVAL_LABEL_TO_ATTR.items()},
        },
        "micro_match_greedy": {
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "recall": rec,
            "precision": prec,
            "note": "仅在可对齐类型的 inventory 上统计；贪心匹配；每个检测候选最多匹配一条 GT。",
        },
        "per_attr_mapped": per_attr,
        "fn_by_category_top": fn_by_category_top,
        "analysis_zh": analysis_zh,
        "all_prompt_candidates": serializable_candidates,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: out_obj[k] for k in out_obj if k != "all_prompt_candidates"}, ensure_ascii=False, indent=2))
    print(f"\n已写入全量候选到: {args.output}")


if __name__ == "__main__":
    main()
