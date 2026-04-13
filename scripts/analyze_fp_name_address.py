"""从 detector 输出中抽取 name/address 的 FP 并做分析。

输入：
- outputs/analysis/privacy_eval_realistic_1200_dual_prompt_detector.json（或同结构文件）

做法：
- 复用评测脚本的 GT 映射口径（pii_inventory -> detector attr）
- 对 prompt 候选与 GT 做同口径贪心匹配
- 将未被匹配到任何 GT 的候选视为 FP
- 针对 name/address 输出：分桶统计、典型误报片段、上下文示例
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
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

_WS_RE = re.compile(r"\s+")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _compact(text: str) -> str:
    return _WS_RE.sub(" ", str(text or "").strip())


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
    candidates: list[tuple[PIIAttributeType, str]],
) -> tuple[set[int], set[int]]:
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (attr, value) in enumerate(ground_truth):
        for ci, (c_attr, c_text) in enumerate(candidates):
            if ci in cand_used:
                continue
            if c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return cand_used, gt_hit


@dataclass(slots=True)
class FPCandidate:
    attr_type: str
    text: str
    normalized_text: str
    span_start: int | None
    span_end: int | None


def _context_window(text: str, start: int | None, end: int | None, window: int = 60) -> str:
    if start is None or end is None:
        return ""
    s = max(0, start - window)
    e = min(len(text), end + window)
    snippet = text[s:e]
    return snippet.replace(OCR_BREAK, " [OCR_BREAK] ")


def _bucket_name(text: str) -> str:
    t = str(text or "").strip()
    if not t:
        return "empty"
    if len(t) <= 2:
        return "len<=2"
    if len(t) <= 3:
        return "len<=3"
    if len(t) <= 5:
        return "len<=5"
    lowered = t.lower()
    if lowered in {"i", "me", "my", "mine", "we", "us", "our", "you", "your", "he", "she", "they", "them"}:
        return "pronoun"
    if re.fullmatch(r"[A-Z]{2,4}", t):
        return "all_caps_short"
    if re.fullmatch(r"[A-Za-z]+", t) and t[:1].isupper() and t[1:].islower():
        return "titlecase_single_word"
    if re.fullmatch(r"[A-Za-z][A-Za-z .,'\\-]{0,80}", t):
        return "name_like"
    return "other"


def _bucket_address(text: str, normalized_text: str) -> str:
    t = str(text or "").strip()
    n = str(normalized_text or "").strip().lower()
    if not t:
        return "empty"
    if len(t) <= 2:
        return "len<=2"
    if len(t) <= 4:
        return "len<=4"
    if "province=" in n and "," not in t and len(t) <= 6:
        return "state_abbrev_like"
    if "postal_code=" in n and re.fullmatch(r"\\d{5}", t):
        return "zip_only"
    if re.fullmatch(r"[A-Za-z]{2}", t):
        return "two_letters"
    if re.fullmatch(r"\\d+[A-Za-z]?", t):
        return "house_number_only"
    if "," in t and any(ch.isdigit() for ch in t):
        return "comma_and_digits"
    if any(ch.isdigit() for ch in t):
        return "contains_digits"
    return "other"


def main() -> None:
    ap = argparse.ArgumentParser(description="分析 name/address FP（基于已有 detector 输出）")
    ap.add_argument(
        "detector_output",
        type=Path,
        help="outputs/analysis/*_prompt_detector.json（含 all_prompt_candidates）",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/fp_name_address_report.json"),
        help="输出报告 JSON 路径",
    )
    ap.add_argument("--topk", type=int, default=50, help="TopK 片段与示例数量")
    args = ap.parse_args()

    det = _load_json(args.detector_output)
    input_paths = [Path(p) for p in det.get("inputs") or []]
    if not input_paths:
        raise ValueError("detector_output.inputs 为空，无法重建 GT 与上下文。")

    # rebuild samples + combined text for context lookup
    all_samples: list[dict[str, Any]] = []
    clean_parts: list[str] = []
    for p in input_paths:
        data = _load_json(p)
        if not isinstance(data, list):
            raise ValueError(f"期望样本数组: {p}")
        all_samples.extend(data)
        clean_parts.extend([str(row.get("clean_text") or "") for row in data])
    combined_text = OCR_BREAK.join(clean_parts)

    # build GT
    ground_truth: list[tuple[PIIAttributeType, str]] = []
    label_unmapped = Counter()
    for row in all_samples:
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            mapped = EVAL_LABEL_TO_ATTR.get(label)
            if mapped is None:
                label_unmapped[label] += 1
                continue
            val = str(item.get("value") or "").strip()
            if val:
                ground_truth.append((mapped, val))

    # candidates
    raw_cands = det.get("all_prompt_candidates") or []
    fp_records: list[FPCandidate] = []
    candidates_for_match: list[tuple[PIIAttributeType, str]] = []
    for row in raw_cands:
        attr = PIIAttributeType(str(row.get("attr_type")))
        text = str(row.get("text") or "")
        candidates_for_match.append((attr, text))
        fp_records.append(
            FPCandidate(
                attr_type=attr.value,
                text=text,
                normalized_text=str(row.get("normalized_text") or ""),
                span_start=row.get("span_start"),
                span_end=row.get("span_end"),
            )
        )

    cand_used, _gt_hit = _greedy_match(ground_truth, candidates_for_match)
    fp_indices = [i for i in range(len(fp_records)) if i not in cand_used]

    fp_by_type = Counter(fp_records[i].attr_type for i in fp_indices)
    name_fp_idx = [i for i in fp_indices if fp_records[i].attr_type == PIIAttributeType.NAME.value]
    addr_fp_idx = [i for i in fp_indices if fp_records[i].attr_type == PIIAttributeType.ADDRESS.value]

    def build_section(indices: list[int], kind: str) -> dict[str, Any]:
        bucket_counter = Counter()
        text_counter = Counter()
        norm_counter = Counter()
        examples: list[dict[str, Any]] = []
        for i in indices:
            c = fp_records[i]
            if kind == "name":
                bucket = _bucket_name(c.text)
            else:
                bucket = _bucket_address(c.text, c.normalized_text)
            bucket_counter[bucket] += 1
            text_counter[_compact(c.text).lower()] += 1
            norm_counter[_compact(c.normalized_text)] += 1

        # examples: pick representative by bucket then fill
        by_bucket: dict[str, list[int]] = defaultdict(list)
        for i in indices:
            c = fp_records[i]
            bucket = _bucket_name(c.text) if kind == "name" else _bucket_address(c.text, c.normalized_text)
            by_bucket[bucket].append(i)

        for bucket, idxs in sorted(by_bucket.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            for i in idxs[: max(1, args.topk // 10)]:
                c = fp_records[i]
                examples.append(
                    {
                        "bucket": bucket,
                        "text": c.text,
                        "normalized_text": c.normalized_text,
                        "span_start": c.span_start,
                        "span_end": c.span_end,
                        "context": _context_window(combined_text, c.span_start, c.span_end),
                    }
                )
                if len(examples) >= args.topk:
                    break
            if len(examples) >= args.topk:
                break

        return {
            "fp_count": len(indices),
            "bucket_counts": dict(bucket_counter.most_common()),
            "top_fp_texts": dict(text_counter.most_common(args.topk)),
            "top_fp_normalized": dict(norm_counter.most_common(args.topk)),
            "examples": examples[: args.topk],
        }

    report = {
        "detector_output": str(args.detector_output.resolve()),
        "inputs": [str(p.resolve()) for p in input_paths],
        "unmapped_inventory_label_counts": dict(label_unmapped.most_common()),
        "fp_total": len(fp_indices),
        "fp_by_attr_type": dict(fp_by_type.most_common()),
        "name_fp": build_section(name_fp_idx, "name"),
        "address_fp": build_section(addr_fp_idx, "address"),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # concise console summary
    print(json.dumps({"fp_total": report["fp_total"], "fp_by_attr_type": report["fp_by_attr_type"]}, ensure_ascii=False, indent=2))
    print(f"\\n已写入: {args.output}")


if __name__ == "__main__":
    main()

