"""多段生成地址 + 随机非地址 PII + OCR_BREAK 分隔，评测 detector 分段与碎片化。"""

from __future__ import annotations

import json
import random
import re
import sys
import time
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils.normalized_pii import same_entity as same_entity_fn

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "outputs" / "analysis"
ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"

# 与 OCR 拼接约定一致：段间硬断点；两侧留白模拟真实 OCR 输出
OCR_BREAK_SEP = "  <OCR_BREAK>    "

SEED = 20260411
CASES_PER_LOCALE = 50
ADDRESSES_PER_CASE_MIN = 2
ADDRESSES_PER_CASE_MAX = 3

TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")

ZH_IDENTITIES = (
    ("林舟", "linzhou"),
    ("苏瑶", "suyao"),
    ("程野", "chengye"),
)
ZH_ORGS = ("星河数据科技有限公司", "云栖智联研发中心", "远帆生活服务集团")
EN_IDENTITIES = (("Emma Lee", "emmalee"), ("Noah Carter", "noahcarter"), ("Ava Brooks", "avabrooks"))
EN_ORGS = ("North Harbor Labs", "Maple Transit Group", "Blue Ridge Systems")


def _normalize_en_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", str(text or "").strip())
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    return normalized.strip()


def _random_phone(locale: str, rng: random.Random) -> str:
    if locale == "zh_cn":
        return f"1{rng.randint(30, 99)}{rng.randint(1000, 9999)}{rng.randint(1000, 9999)}"
    return f"{rng.choice((206, 312, 512, 617, 425))}-555-{rng.randint(1000, 9999)}"


def _build_extra_pii(locale: str, rng: random.Random) -> dict[str, str]:
    if locale == "zh_cn":
        name, stem = rng.choice(ZH_IDENTITIES)
        return {
            "name": name,
            "phone": _random_phone(locale, rng),
            "email": f"{stem}{rng.randint(10, 99)}@mail.cn",
            "organization": rng.choice(ZH_ORGS),
        }
    name, stem = rng.choice(EN_IDENTITIES)
    return {
        "name": name,
        "phone": _random_phone(locale, rng),
        "email": f"{stem}{rng.randint(10, 99)}@example.com",
        "organization": rng.choice(EN_ORGS),
    }


def _compose_prefix(locale: str, extras: dict[str, str]) -> str:
    """前缀仅含非地址 PII，末尾已含分隔符，便于直接拼接第一段地址。"""
    if locale == "zh_cn":
        return "，".join([extras["name"], extras["phone"], extras["email"], extras["organization"]]) + "，"
    return _normalize_en_text(", ".join([extras["name"], extras["phone"], extras["email"], extras["organization"]])) + ", "


def _load_records(locale: str) -> list[dict[str, Any]]:
    jsonl_path = DATA_DIR / ("chinese_addresses.jsonl" if locale == "zh_cn" else "english_addresses.jsonl")
    records: list[dict[str, Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _segment_spans(prefix: str, addresses: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    cursor = len(prefix)
    for index, addr in enumerate(addresses):
        start = cursor
        end = start + len(addr)
        spans.append((start, end))
        cursor = end
        if index < len(addresses) - 1:
            cursor += len(OCR_BREAK_SEP)
    return spans


def _overlap_len(a0: int, a1: int, b0: int, b1: int) -> int:
    left = max(a0, b0)
    right = min(a1, b1)
    return max(0, right - left)


def _assign_candidate_to_segment(
    span_start: int | None, span_end: int | None, seg_spans: list[tuple[int, int]]
) -> int | None:
    if span_start is None or span_end is None:
        return None
    best_i: int | None = None
    best_ov = -1
    for i, (s0, s1) in enumerate(seg_spans):
        ov = _overlap_len(span_start, span_end, s0, s1)
        if ov > best_ov:
            best_ov = ov
            best_i = i
    if best_i is None or best_ov <= 0:
        return None
    return best_i


def _try_andlab() -> Any | None:
    if not (ANDLAB_ROOT / "utils_mobile").is_dir():
        return None
    sys.path.insert(0, str(ANDLAB_ROOT))
    try:
        from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore

        return PrivacyProtectionLayer(enabled=True)
    except Exception:
        return None


def _andlab_address_occurrences(layer: Any, text: str, *, clear: bool) -> list[dict[str, Any]]:
    if clear:
        layer.clear_mappings()
    masked_text, _ = layer.anonymize_prompt(text)
    occurrences: list[dict[str, Any]] = []
    for match in TOKEN_RE.finditer(masked_text):
        token = match.group(1)
        real_value = layer.token_to_real.get(token)
        if not real_value:
            continue
        label = layer.real_to_entity_type.get(real_value, "MISC")
        if label == "ADDRESS" or str(label).startswith("LOCATION_"):
            occurrences.append({"token": token, "label": label, "text": real_value})
    return occurrences


def main() -> None:
    rng = random.Random(SEED)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    andlab = _try_andlab()
    results: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "seed": SEED,
        "ocr_break_sep": OCR_BREAK_SEP,
        "andlab_available": andlab is not None,
        "locales": {},
    }

    for locale in ("zh_cn", "en_us"):
        records = _load_records(locale)
        detector = RuleBasedPIIDetector(locale_profile=locale)
        locale_rows: list[dict[str, Any]] = []
        latencies: list[float] = []
        andlab_latencies: list[float] = []

        stats = {
            "cases": 0,
            "total_address_candidates": 0,
            "expected_segments": 0,
            "segments_with_zero": 0,
            "segments_with_one": 0,
            "segments_with_multi": 0,
            "cross_segment_false_positive_same_entity": 0,
            "cross_segment_pairs_checked": 0,
            "andlab_address_entities": 0,
        }

        for _ in range(CASES_PER_LOCALE):
            k = rng.randint(ADDRESSES_PER_CASE_MIN, min(ADDRESSES_PER_CASE_MAX, len(records)))
            chosen = rng.sample(records, k)
            addresses = [str(r["text"]) for r in chosen]
            ids = [int(r["id"]) for r in chosen]
            extras = _build_extra_pii(locale, rng)
            prefix = _compose_prefix(locale, extras)
            core = OCR_BREAK_SEP.join(addresses)
            full_text = prefix + core
            seg_spans = _segment_spans(prefix, addresses)

            t0 = time.perf_counter()
            all_cands = detector.detect(full_text, [])
            addr_cands = [c for c in all_cands if c.attr_type == PIIAttributeType.ADDRESS]
            elapsed = round((time.perf_counter() - t0) * 1000, 3)
            latencies.append(elapsed)

            per_seg: list[list[Any]] = [[] for _ in range(k)]
            unassigned = 0
            for c in addr_cands:
                si = _assign_candidate_to_segment(c.span_start, c.span_end, seg_spans)
                if si is None:
                    unassigned += 1
                else:
                    per_seg[si].append(c)

            for i in range(k):
                n = len(per_seg[i])
                stats["expected_segments"] += 1
                if n == 0:
                    stats["segments_with_zero"] += 1
                elif n == 1:
                    stats["segments_with_one"] += 1
                else:
                    stats["segments_with_multi"] += 1

            stats["cases"] += 1
            stats["total_address_candidates"] += len(addr_cands)

            # 不同段之间任意两候选不应判为同一地址实体（抽样避免 O(n^2) 过大）
            for i in range(k):
                for j in range(i + 1, k):
                    for a in per_seg[i][:3]:
                        for b in per_seg[j][:3]:
                            stats["cross_segment_pairs_checked"] += 1
                            if same_entity_fn(a.normalized_source, b.normalized_source):
                                stats["cross_segment_false_positive_same_entity"] += 1

            andlab_row: dict[str, Any] | None = None
            if andlab is not None:
                t1 = time.perf_counter()
                occ = _andlab_address_occurrences(andlab, full_text, clear=True)
                andlab_latencies.append(round((time.perf_counter() - t1) * 1000, 3))
                stats["andlab_address_entities"] += len(occ)
                andlab_row = {
                    "count": len(occ),
                    "texts": [o["text"] for o in occ],
                    "tokens": [o["token"] for o in occ],
                }

            locale_rows.append(
                {
                    "locale": locale,
                    "ids": ids,
                    "full_text": full_text,
                    "address_count": k,
                    "address_candidates": len(addr_cands),
                    "unassigned_candidates": unassigned,
                    "per_segment_counts": [len(x) for x in per_seg],
                    "per_segment_candidate_texts": [[c.text for c in seg] for seg in per_seg],
                    "elapsed_ms": elapsed,
                    "andlab": andlab_row,
                }
            )

        def _lat_stats(vals: list[float]) -> dict[str, float]:
            if not vals:
                return {"avg_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}
            ordered = sorted(vals)
            mid = len(ordered) // 2
            median = (ordered[mid - 1] + ordered[mid]) / 2 if len(ordered) % 2 == 0 else ordered[mid]
            p95_i = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
            return {
                "avg_ms": round(sum(ordered) / len(ordered), 3),
                "median_ms": round(median, 3),
                "p95_ms": round(ordered[p95_i], 3),
            }

        summary["locales"][locale] = {
            **stats,
            "detector_latency_ms": _lat_stats(latencies),
            "andlab_latency_ms": _lat_stats(andlab_latencies) if andlab_latencies else None,
            "one_pii_per_segment_rate": round(
                stats["segments_with_one"] / max(1, stats["expected_segments"]), 4
            ),
            "zero_per_segment_rate": round(
                stats["segments_with_zero"] / max(1, stats["expected_segments"]), 4
            ),
            "multi_per_segment_rate": round(
                stats["segments_with_multi"] / max(1, stats["expected_segments"]), 4
            ),
            "avg_address_candidates_per_case": round(
                stats["total_address_candidates"] / max(1, stats["cases"]), 4
            ),
            "avg_addresses_per_case": round(
                stats["expected_segments"] / max(1, stats["cases"]), 4
            ),
        }
        results.extend(locale_rows)

    out_json = OUTPUT_DIR / "generated_address_ocr_break_details.json"
    out_md = OUTPUT_DIR / "generated_address_ocr_break_summary.md"

    out_json.write_text(
        json.dumps({"summary": summary, "cases": results}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# OCR_BREAK 多段地址 + 随机 PII 评测摘要",
        "",
        f"- 随机种子：`{SEED}`，每 locale 用例数：`{CASES_PER_LOCALE}`，每用例地址段数：`{ADDRESSES_PER_CASE_MIN}`–`{ADDRESSES_PER_CASE_MAX}`。",
        f"- 段间分隔：`{repr(OCR_BREAK_SEP)}`。",
        f"- AndLab_protected 可用：`{summary['andlab_available']}`。",
        "",
    ]
    for locale, block in summary["locales"].items():
        label = "中文" if locale == "zh_cn" else "英文"
        lines.append(f"## {label}")
        lines.append("")
        lines.append(f"- 分段总数（各用例地址段之和）：`{block['expected_segments']}`")
        lines.append(f"- 每段恰好 1 个 address 候选占比：`{block['one_pii_per_segment_rate'] * 100:.2f}%`")
        lines.append(f"- 每段 0 个占比：`{block['zero_per_segment_rate'] * 100:.2f}%`")
        lines.append(f"- 每段 >1 个（碎片化）占比：`{block['multi_per_segment_rate'] * 100:.2f}%`")
        lines.append(f"- 每用例平均 address 候选数：`{block['avg_address_candidates_per_case']}`（期望约等于段数）")
        lines.append(
            f"- 跨段误认同实体对数：`{block['cross_segment_false_positive_same_entity']}` / "
            f"抽检对数 `{block['cross_segment_pairs_checked']}`"
        )
        lines.append(
            f"- Detector 耗时 ms：avg `{block['detector_latency_ms']['avg_ms']}`，"
            f"median `{block['detector_latency_ms']['median_ms']}`，"
            f"p95 `{block['detector_latency_ms']['p95_ms']}`"
        )
        if block.get("andlab_latency_ms"):
            al = block["andlab_latency_ms"]
            lines.append(f"- AndLab 耗时 ms：avg `{al['avg_ms']}`，median `{al['median_ms']}`，p95 `{al['p95_ms']}`")
            lines.append(f"- AndLab 识别到的地址类实体总数（累加）：`{block['andlab_address_entities']}`")
        lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(out_json)
    print(out_md)


if __name__ == "__main__":
    main()
