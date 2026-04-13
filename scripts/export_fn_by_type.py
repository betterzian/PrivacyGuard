"""按类型导出 FN 样例并汇总失败模式。"""

from __future__ import annotations

import argparse
import json
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK
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

WORD_RE = re.compile(r"[A-Za-z]+|[\u4e00-\u9fff]+")


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


def _tokens(text: str) -> set[str]:
    return {m.group(0).lower() for m in WORD_RE.finditer(str(text or ""))}


def _digits(text: str) -> str:
    return "".join(ch for ch in str(text or "") if ch.isdigit())


def _sample_idx_by_span(starts: list[int], span_start: int | None, sample_count: int) -> int | None:
    if span_start is None:
        return None
    idx = bisect_right(starts, span_start) - 1
    if idx < 0 or idx >= sample_count:
        return None
    return idx


def _build_failure_mode(
    attr: PIIAttributeType,
    gt_value: str,
    same_type_texts: list[str],
    any_type_rows: list[dict[str, Any]],
) -> str:
    if not same_type_texts:
        if attr in {PIIAttributeType.ID_NUMBER, PIIAttributeType.BANK_NUMBER, PIIAttributeType.DRIVER_LICENSE}:
            overlap_numeric = any(
                row["attr"].value in {"numeric", "alnum", "time"}
                and _digits(row["text"])
                and _digits(gt_value) in _digits(row["text"])
                for row in any_type_rows
            )
            if overlap_numeric:
                return "未产出同类型候选_疑似落入numeric/alnum"
        return "样本内无同类型候选"

    if attr == PIIAttributeType.NAME:
        gt_tokens = _tokens(gt_value)
        if gt_tokens:
            overlaps = [len(gt_tokens & _tokens(c)) for c in same_type_texts]
            if max(overlaps, default=0) > 0:
                return "姓名部分片段命中但未达同实体"
        short_noise = sum(1 for c in same_type_texts if len(c.strip()) <= 3)
        if short_noise >= 3:
            return "姓名短片段噪声过多"
        return "姓名同类型候选存在但归一不一致"

    if attr == PIIAttributeType.ADDRESS:
        if any(_address_micro_match(gt_value, c) for c in same_type_texts):
            return "地址片段命中但被贪心占位"
        if any(len(c.strip()) <= 4 for c in same_type_texts):
            return "地址短词/缩写候选干扰"
        return "地址同类型候选存在但未对齐"

    if attr == PIIAttributeType.EMAIL:
        gt = str(gt_value or "").lower()
        if "@" in gt:
            local, domain = gt.split("@", 1)
            if any(local in str(c).lower() or domain in str(c).lower() for c in same_type_texts):
                return "邮箱局部命中（本地名/域名）但未完整识别"
        return "邮箱同类型候选存在但未匹配"

    if attr == PIIAttributeType.ORGANIZATION:
        gt_tokens = _tokens(gt_value)
        if gt_tokens and any(len(gt_tokens & _tokens(c)) > 0 for c in same_type_texts):
            return "机构名词片段命中但未对齐"
        return "机构同类型候选存在但未匹配"

    return "同类型候选存在但未匹配"


def main() -> None:
    parser = argparse.ArgumentParser(description="导出 FN 样例并汇总失败模式")
    parser.add_argument("detector_output", type=Path, help="评测输出 JSON（需含 all_prompt_candidates）")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_prompt_detector_fn_report.json"),
        help="输出报告路径",
    )
    parser.add_argument("--topk", type=int, default=30, help="Top 模式与示例数")
    args = parser.parse_args()

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

    clean_texts = [str(row.get("clean_text") or "") for row in samples]
    starts: list[int] = []
    cursor = 0
    for i, text in enumerate(clean_texts):
        starts.append(cursor)
        cursor += len(text)
        if i < len(clean_texts) - 1:
            cursor += len(OCR_BREAK)

    gt_rows: list[dict[str, Any]] = []
    for si, row in enumerate(samples):
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            attr = EVAL_LABEL_TO_ATTR.get(label)
            if attr is None:
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            gt_rows.append(
                {
                    "attr": attr,
                    "value": value,
                    "sample_idx": si,
                    "sample_id": str(row.get("sample_id") or ""),
                    "category": str(row.get("category") or "unknown"),
                    "scene": str(row.get("scene") or ""),
                }
            )

    cand_rows: list[dict[str, Any]] = []
    for c in det.get("all_prompt_candidates") or []:
        attr = PIIAttributeType(str(c.get("attr_type")))
        si = _sample_idx_by_span(starts, c.get("span_start"), len(samples))
        cand_rows.append(
            {
                "attr": attr,
                "text": str(c.get("text") or ""),
                "span_start": c.get("span_start"),
                "span_end": c.get("span_end"),
                "sample_idx": si,
                "normalized_text": str(c.get("normalized_text") or ""),
            }
        )

    # greedy match（与评测口径一致）
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, gt in enumerate(gt_rows):
        g_attr = gt["attr"]
        g_val = gt["value"]
        for ci, cand in enumerate(cand_rows):
            if ci in cand_used:
                continue
            if cand["attr"] != g_attr:
                continue
            if _micro_match(g_attr, g_val, cand["text"]):
                cand_used.add(ci)
                gt_hit.add(gi)
                break

    # sample -> candidates 索引
    cands_by_sample: dict[int, list[int]] = defaultdict(list)
    for ci, cand in enumerate(cand_rows):
        si = cand["sample_idx"]
        if si is not None:
            cands_by_sample[si].append(ci)

    fn_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    mode_counter_overall: Counter[str] = Counter()
    mode_counter_by_type: dict[str, Counter[str]] = defaultdict(Counter)
    fn_category_by_type: dict[str, Counter[str]] = defaultdict(Counter)

    for gi, gt in enumerate(gt_rows):
        if gi in gt_hit:
            continue
        si = gt["sample_idx"]
        sample_cis = cands_by_sample.get(si, [])
        same_type = [cand_rows[i] for i in sample_cis if cand_rows[i]["attr"] == gt["attr"]]
        same_type_texts = [row["text"] for row in same_type]
        any_type_rows = [cand_rows[i] for i in sample_cis]

        mode = _build_failure_mode(
            gt["attr"],
            gt["value"],
            same_type_texts=same_type_texts,
            any_type_rows=any_type_rows,
        )

        attr_key = gt["attr"].value
        mode_counter_overall[mode] += 1
        mode_counter_by_type[attr_key][mode] += 1
        fn_category_by_type[attr_key][gt["category"]] += 1

        fn_by_type[attr_key].append(
            {
                "sample_id": gt["sample_id"],
                "category": gt["category"],
                "scene": gt["scene"],
                "ground_truth_value": gt["value"],
                "failure_mode": mode,
                "sample_clean_text": clean_texts[si],
                "same_type_candidates_top5": same_type_texts[:5],
                "sample_candidates_any_type_top8": [
                    {"attr_type": row["attr"].value, "text": row["text"]}
                    for row in any_type_rows[:8]
                ],
            }
        )

    summary_by_type: dict[str, dict[str, Any]] = {}
    for attr_key, rows in fn_by_type.items():
        summary_by_type[attr_key] = {
            "fn_count": len(rows),
            "top_failure_modes": mode_counter_by_type[attr_key].most_common(args.topk),
            "top_categories": fn_category_by_type[attr_key].most_common(args.topk),
        }

    report = {
        "detector_output": str(args.detector_output.resolve()),
        "inputs": [str(p.resolve()) for p in input_paths],
        "fn_total": sum(len(v) for v in fn_by_type.values()),
        "summary": {
            "top_failure_modes_overall": mode_counter_overall.most_common(args.topk),
            "by_type": summary_by_type,
        },
        "fn_examples_by_type": fn_by_type,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "fn_total": report["fn_total"],
                "top_failure_modes_overall": report["summary"]["top_failure_modes_overall"][:10],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()

