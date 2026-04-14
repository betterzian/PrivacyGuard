"""分析评测结果：各类型 FP/FN 及 TopK；不看类型的隐私命中与完整度。

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


def main() -> None:
    ap = argparse.ArgumentParser(description="FN/FP 分类型 TopK + 不看类型的隐私命中统计")
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
    fn_value_by_type: dict[str, Counter[str]] = defaultdict(Counter)
    fp_count_by_type: Counter[str] = Counter()
    fn_count_by_type: Counter[str] = Counter()

    gt_total = 0
    any_hit = 0
    full_hit = 0
    partial_only = 0
    miss = 0

    for row in samples:
        sid = str(row.get("sample_id") or "")
        gt_local: list[tuple[PIIAttributeType, str]] = []
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                continue
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            gt_local.append((mapped, val))

        cands = by_sid.get(sid, [])
        prompt_items = [(PIIAttributeType(str(c["attr_type"])), str(c.get("text") or "")) for c in cands]

        cand_used, gt_hit = _greedy_match(gt_local, prompt_items)
        for ci, (attr, text) in enumerate(prompt_items):
            if ci not in cand_used:
                fp_count_by_type[attr.value] += 1
                fp_text_by_type[attr.value][text.strip()[:200]] += 1
        for gi, (attr, value) in enumerate(gt_local):
            if gi not in gt_hit:
                fn_count_by_type[attr.value] += 1
                fn_value_by_type[attr.value][value.strip()[:200]] += 1

        texts_only = [str(c.get("text") or "") for c in cands]
        for _attr, gt_val in gt_local:
            gt_total += 1
            has_loose = any(_loose_hit(gt_val, t) for t in texts_only)
            has_full = any(_full_text_match(gt_val, t) for t in texts_only)
            if has_full:
                full_hit += 1
                any_hit += 1
            elif has_loose:
                partial_only += 1
                any_hit += 1
            else:
                miss += 1

    top_fp = {k: fp_text_by_type[k].most_common(args.topk) for k in sorted(fp_count_by_type.keys())}
    top_fn = {k: fn_value_by_type[k].most_common(args.topk) for k in sorted(fn_count_by_type.keys())}

    report = {
        "samples_json": str(args.samples_json.resolve()),
        "detector_output_json": str(args.detector_output_json.resolve()),
        "topk": args.topk,
        "type_aligned_greedy": {
            "fp_count_by_type": dict(fp_count_by_type.most_common()),
            "fn_count_by_type": dict(fn_count_by_type.most_common()),
            "top_fp_text_by_type": {k: [{"text": a, "count": b} for a, b in v] for k, v in top_fp.items()},
            "top_fn_ground_truth_value_by_type": {k: [{"value": a, "count": b} for a, b in v] for k, v in top_fn.items()},
        },
        "type_agnostic_loose": {
            "gt_rows_mapped": gt_total,
            "any_hit_count": any_hit,
            "full_text_match_count": full_hit,
            "partial_loose_only_count": partial_only,
            "completely_missed_count": miss,
            "any_hit_rate": any_hit / gt_total if gt_total else 0.0,
            "full_match_rate": full_hit / gt_total if gt_total else 0.0,
            "partial_only_rate": partial_only / gt_total if gt_total else 0.0,
            "miss_rate": miss / gt_total if gt_total else 0.0,
            "note": "与类型无关：同样本内候选与 GT 子串/长数字串覆盖；完整=去空白字面相等（邮箱忽略大小写）。",
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()
