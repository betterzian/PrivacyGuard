"""分析评测结果：支持“精确召回 + 通用召回”的逐类型评测。

评测口径：
1. 精确召回：候选类型与标注类型映射一致，且值匹配。
2. 通用召回：仅对非语义类（非 NAME/ORG/ADDRESS）标注生效；若被 NUM/ALNUM 候选覆盖则计为通用召回。
3. 通用召回命中的 GT 与候选不计 FN/FP。

默认用于逐样本评测输出（``all_prompt_candidates`` 含 ``sample_id``）与含 ``pii_inventory`` 的样本 JSON。
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

LABEL_TO_EXACT_ATTR: dict[str, PIIAttributeType] = {
    "ADDRESS": PIIAttributeType.ADDRESS,
    "NAME": PIIAttributeType.NAME,
    "PHONE": PIIAttributeType.PHONE,
    "EMAIL": PIIAttributeType.EMAIL,
    "ID_CARD": PIIAttributeType.ID_NUMBER,
    "BANK_CARD": PIIAttributeType.BANK_NUMBER,
    "ORG": PIIAttributeType.ORGANIZATION,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE,
    "LICENSE_PLATE": PIIAttributeType.LICENSE_PLATE,
    "TIME": PIIAttributeType.TIME,
    "BIRTHDAY": PIIAttributeType.TIME,
    "AMOUNT": PIIAttributeType.AMOUNT,
}

SEMANTIC_LABELS = {"NAME", "ORG", "ADDRESS"}
GENERIC_ATTR_TYPES = {PIIAttributeType.NUM, PIIAttributeType.ALNUM}
ATTR_ALIASES = {"numeric": PIIAttributeType.NUM.value}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _normalize_attr(raw: str) -> PIIAttributeType | None:
    key = ATTR_ALIASES.get(str(raw or "").strip().lower(), str(raw or "").strip().lower())
    if not key:
        return None
    try:
        return PIIAttributeType(key)
    except ValueError:
        return None


def _digits(s: str) -> str:
    return "".join(ch for ch in str(s or "") if ch.isdigit())


def _loose_hit(gt_val: str, cand_text: str) -> bool:
    g = str(gt_val or "").strip()
    c = str(cand_text or "").strip()
    if not g or not c:
        return False
    if g in c or c in g:
        return True
    dg, dc = _digits(g), _digits(c)
    if len(dg) >= 8 and dg and dg in dc:
        return True
    return False


def _full_text_match(gt_val: str, cand_text: str) -> bool:
    g = str(gt_val or "").strip()
    c = str(cand_text or "").strip()
    if not g or not c:
        return False
    if "@" in g and "@" in c:
        return g.lower() == c.lower()
    return g == c


def _match_exact_then_generic(
    gt_items: list[dict[str, str]],
    prompt_items: list[tuple[PIIAttributeType, str]],
) -> tuple[set[int], set[int], set[int], set[int]]:
    """按“先精确，再通用”执行贪心匹配并返回命中索引。"""
    cand_used: set[int] = set()
    exact_hit_gt: set[int] = set()
    generic_hit_gt: set[int] = set()

    # 1) 精确召回：类型一致 + 值匹配
    for gi, gt in enumerate(gt_items):
        label = gt["label"]
        value = gt["value"]
        mapped_attr = LABEL_TO_EXACT_ATTR.get(label)
        if mapped_attr is None:
            continue
        for ci, (cand_attr, cand_text) in enumerate(prompt_items):
            if ci in cand_used or cand_attr != mapped_attr:
                continue
            if _micro_match(mapped_attr, value, cand_text):
                cand_used.add(ci)
                exact_hit_gt.add(gi)
                break

    # 2) 通用召回：非语义类 + NUM/ALNUM 覆盖
    for gi, gt in enumerate(gt_items):
        if gi in exact_hit_gt:
            continue
        label = gt["label"]
        if label in SEMANTIC_LABELS:
            continue
        value = gt["value"]
        for ci, (cand_attr, cand_text) in enumerate(prompt_items):
            if ci in cand_used or cand_attr not in GENERIC_ATTR_TYPES:
                continue
            if _loose_hit(value, cand_text):
                cand_used.add(ci)
                generic_hit_gt.add(gi)
                break

    matched_gt = exact_hit_gt | generic_hit_gt
    return cand_used, matched_gt, exact_hit_gt, generic_hit_gt


def main() -> None:
    ap = argparse.ArgumentParser(description="支持精确召回/通用召回的逐类型评测统计")
    ap.add_argument("samples_json", type=Path, help="含 pii_inventory 的样本列表 JSON")
    ap.add_argument("detector_output_json", type=Path, help="含 all_prompt_candidates（带 sample_id）")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/zh_fn_fp_type_agnostic_report.json"),
    )
    ap.add_argument("--topk", type=int, default=20)
    args = ap.parse_args()

    samples: list[dict[str, Any]] = _load_json(args.samples_json)
    if not isinstance(samples, list):
        raise ValueError("samples_json 应为数组。")
    det = _load_json(args.detector_output_json)
    raw_cands = det.get("all_prompt_candidates") or []

    by_sid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in raw_cands:
        sid = str(c.get("sample_id") or "")
        by_sid[sid].append(c)

    fp_text_by_type: dict[str, Counter[str]] = defaultdict(Counter)
    fn_value_by_label: dict[str, Counter[str]] = defaultdict(Counter)
    fp_count_by_attr: Counter[str] = Counter()
    fn_count_by_label: Counter[str] = Counter()
    gt_count_by_label: Counter[str] = Counter()
    exact_hit_by_label: Counter[str] = Counter()
    generic_hit_by_label: Counter[str] = Counter()

    gt_total = 0
    exact_hit_total = 0
    generic_hit_total = 0
    miss = 0

    for row in samples:
        sid = str(row.get("sample_id") or "")
        gt_local: list[dict[str, str]] = []
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            gt_local.append({"label": label, "value": val})
            gt_count_by_label[label] += 1

        cands = by_sid.get(sid, [])
        prompt_items: list[tuple[PIIAttributeType, str]] = []
        cand_serialized: list[dict[str, Any]] = []
        for c in cands:
            attr = _normalize_attr(str(c.get("attr_type") or ""))
            if attr is None:
                continue
            text = str(c.get("text") or "")
            prompt_items.append((attr, text))
            cand_serialized.append(c)

        cand_used, gt_hit, exact_gt_hit, generic_gt_hit = _match_exact_then_generic(gt_local, prompt_items)
        for ci, (attr, text) in enumerate(prompt_items):
            if ci not in cand_used:
                fp_count_by_attr[attr.value] += 1
                fp_text_by_type[attr.value][text.strip()[:200]] += 1
        for gi, gt in enumerate(gt_local):
            if gi not in gt_hit:
                fn_count_by_label[gt["label"]] += 1
                fn_value_by_label[gt["label"]][gt["value"].strip()[:200]] += 1

        for gi, gt in enumerate(gt_local):
            gt_total += 1
            label = gt["label"]
            if gi in exact_gt_hit:
                exact_hit_total += 1
                exact_hit_by_label[label] += 1
            elif gi in generic_gt_hit:
                generic_hit_total += 1
                generic_hit_by_label[label] += 1
            else:
                miss += 1

    top_fp = {k: fp_text_by_type[k].most_common(args.topk) for k in sorted(fp_count_by_attr.keys())}
    top_fn = {k: fn_value_by_label[k].most_common(args.topk) for k in sorted(fn_count_by_label.keys())}

    per_label: dict[str, dict[str, float | int | None]] = {}
    all_labels = sorted(gt_count_by_label.keys())
    for label in all_labels:
        gt_n = gt_count_by_label[label]
        exact_n = exact_hit_by_label[label]
        generic_n = generic_hit_by_label[label]
        miss_n = fn_count_by_label[label]
        recalled = exact_n + generic_n
        per_label[label] = {
            "gt": gt_n,
            "exact_recall_count": exact_n,
            "generic_recall_count": generic_n,
            "miss_count": miss_n,
            "exact_recall_rate": exact_n / gt_n if gt_n else 0.0,
            "generic_recall_rate": generic_n / gt_n if gt_n else 0.0,
            "overall_recall_rate": recalled / gt_n if gt_n else 0.0,
            "generic_share_in_recalled": (generic_n / recalled) if recalled else None,
        }

    fp_total = sum(fp_count_by_attr.values())
    fn_total = sum(fn_count_by_label.values())
    tp_total = exact_hit_total + generic_hit_total

    report = {
        "samples_json": str(args.samples_json.resolve()),
        "detector_output_json": str(args.detector_output_json.resolve()),
        "topk": args.topk,
        "detector_attr_types": [attr.value for attr in PIIAttributeType],
        "semantic_labels": sorted(SEMANTIC_LABELS),
        "generic_attr_types": sorted(attr.value for attr in GENERIC_ATTR_TYPES),
        "overall": {
            "gt_total_all_labels": gt_total,
            "tp_total": tp_total,
            "tp_exact_total": exact_hit_total,
            "tp_generic_total": generic_hit_total,
            "fp_total": fp_total,
            "fn_total": fn_total,
            "recall": tp_total / gt_total if gt_total else 0.0,
            "precision": tp_total / (tp_total + fp_total) if (tp_total + fp_total) else 0.0,
            "generic_share_in_tp": generic_hit_total / tp_total if tp_total else 0.0,
            "note": "TP=精确召回+通用召回；通用召回命中的 NUM/ALNUM 不计 FP，命中的 GT 不计 FN。",
        },
        "per_label": per_label,
        "fp_count_by_attr": dict(fp_count_by_attr.most_common()),
        "fn_count_by_label": dict(fn_count_by_label.most_common()),
        "top_fp_text_by_attr": {k: [{"text": a, "count": b} for a, b in v] for k, v in top_fp.items()},
        "top_fn_ground_truth_value_by_label": {k: [{"value": a, "count": b} for a, b in v] for k, v in top_fn.items()},
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()
