"""按类型导出 FP 样例并汇总 Top 误报模式。"""

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


def main() -> None:
    ap = argparse.ArgumentParser(description="导出 FP 分类型报告")
    ap.add_argument("detector_output", type=Path, help="包含 all_prompt_candidates 的评测输出 JSON")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_prompt_detector_fp_report.json"),
    )
    ap.add_argument("--topk", type=int, default=30)
    args = ap.parse_args()

    det = _load_json(args.detector_output)
    input_paths = [Path(p) for p in det.get("inputs") or []]
    if not input_paths:
        raise ValueError("detector_output.inputs 为空。")

    samples: list[dict[str, Any]] = []
    for p in input_paths:
        doc = _load_json(p)
        if not isinstance(doc, list):
            raise ValueError(f"输入文件不是样本数组: {p}")
        samples.extend(doc)

    ground_truth: list[tuple[PIIAttributeType, str]] = []
    for row in samples:
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                continue
            val = str(item.get("value") or "").strip()
            if val:
                ground_truth.append((mapped, val))

    candidates: list[dict[str, Any]] = []
    for c in det.get("all_prompt_candidates") or []:
        candidates.append(
            {
                "attr": PIIAttributeType(str(c.get("attr_type"))),
                "text": str(c.get("text") or ""),
                "normalized_text": str(c.get("normalized_text") or ""),
                "span_start": c.get("span_start"),
                "span_end": c.get("span_end"),
            }
        )

    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (g_attr, g_val) in enumerate(ground_truth):
        for ci, cand in enumerate(candidates):
            if ci in cand_used:
                continue
            if cand["attr"] != g_attr:
                continue
            if _micro_match(g_attr, g_val, cand["text"]):
                cand_used.add(ci)
                gt_hit.add(gi)
                break

    fp_indices = [i for i in range(len(candidates)) if i not in cand_used]
    fp_by_type = Counter(candidates[i]["attr"].value for i in fp_indices)

    rows_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    top_texts_by_type: dict[str, list[tuple[str, int]]] = {}
    top_norms_by_type: dict[str, list[tuple[str, int]]] = {}
    for t in fp_by_type:
        idxs = [i for i in fp_indices if candidates[i]["attr"].value == t]
        text_counter = Counter((candidates[i]["text"] or "").strip().lower() for i in idxs)
        norm_counter = Counter((candidates[i]["normalized_text"] or "").strip() for i in idxs)
        top_texts_by_type[t] = text_counter.most_common(args.topk)
        top_norms_by_type[t] = norm_counter.most_common(args.topk)
        rows_by_type[t] = [
            {
                "text": candidates[i]["text"],
                "normalized_text": candidates[i]["normalized_text"],
                "span_start": candidates[i]["span_start"],
                "span_end": candidates[i]["span_end"],
            }
            for i in idxs
        ]

    report = {
        "detector_output": str(args.detector_output.resolve()),
        "inputs": [str(p.resolve()) for p in input_paths],
        "fp_total": len(fp_indices),
        "fp_by_attr_type": dict(fp_by_type.most_common()),
        "top_fp_texts_by_type": {k: [{"text": a, "count": b} for a, b in v] for k, v in top_texts_by_type.items()},
        "top_fp_normalized_by_type": {k: [{"normalized_text": a, "count": b} for a, b in v] for k, v in top_norms_by_type.items()},
        "fp_examples_by_type": rows_by_type,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"fp_total": report["fp_total"], "fp_by_attr_type": report["fp_by_attr_type"]}, ensure_ascii=False, indent=2))
    print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()

