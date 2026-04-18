"""编排：生成地址 → 拼接噪声 PII 与 OCR_BREAK 多段地址 → 评测 detector 组件/碎片化/同址与时间。"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import re
import runpy
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "outputs" / "analysis"

# 用户指定：不同地址段之间分隔符（含两侧空格）
OCR_BREAK = "  <OCR_BREAK>    "

ZH_NOISE_PIIS = [
    "收件人王芳",
    "手机13800138000",
    "订单号PG20250418001",
    "备注加急派送",
    "客户编号CN889921",
]
EN_NOISE_PIIS = [
    "Ship to Alex Rivera",
    "Tel +1 206 555 0142",
    "Order REF-OR-50418",
    "Rush delivery requested",
    "Account ACCT-772031",
]


def _load_script_module(name: str, relative_path: str) -> Any:
    path = ROOT / "scripts" / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载脚本模块: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_generate_data(*, count: int, seed: int) -> None:
    argv_bak = sys.argv[:]
    try:
        sys.argv = ["generate_data.py", "--count", str(count), "--seed", str(seed)]
        runpy.run_path(str(ROOT / "data" / "generate_data.py"), run_name="__main__")
    finally:
        sys.argv = argv_bak


def _normalize_en_outer(text: str) -> str:
    normalized = re.sub(r"\s+", " ", str(text or "").strip())
    return re.sub(r"\s*,\s*", ", ", normalized)


_OCR_PLACEHOLDER = "\ue000PG_OCR_BREAK\ue000"


def _normalize_en_preserving_ocr_break(text: str) -> str:
    """保留 OCR_BREAK 内多空格，其余按英文外层规则压实。"""
    s = str(text or "")
    if OCR_BREAK not in s:
        return _normalize_en_outer(s)
    safe = s.replace(OCR_BREAK, _OCR_PLACEHOLDER)
    return _normalize_en_outer(safe).replace(_OCR_PLACEHOLDER, OCR_BREAK)


def _locate_spans(full: str, left_len: int, segments: list[str], records: list[dict[str, Any]]) -> list[tuple[int, int, dict[str, Any], str]]:
    spans: list[tuple[int, int, dict[str, Any], str]] = []
    cursor = left_len
    for rec, seg in zip(records, segments, strict=True):
        idx = full.find(seg, cursor)
        if idx < 0:
            raise RuntimeError(f"无法在合成文中定位地址片段: {seg[:40]}…")
        spans.append((idx, idx + len(seg), rec, seg))
        cursor = idx + len(seg)
    return spans


def _address_candidates(detector: Any, text: str) -> list[Any]:
    from privacyguard.domain.enums import PIIAttributeType

    return [c for c in detector.detect(text, []) if c.attr_type == PIIAttributeType.ADDRESS]


def _overlap(a0: int, a1: int, b0: int, b1: int) -> int:
    left = max(a0, b0)
    right = min(a1, b1)
    return max(0, right - left)


def _candidates_in_span(
    candidates: list[Any],
    s: int,
    e: int,
) -> list[Any]:
    matched: list[Any] = []
    for c in candidates:
        cs, ce = c.span_start, c.span_end
        if cs is not None and ce is not None:
            if _overlap(int(cs), int(ce), s, e) > 0:
                matched.append(c)
        else:
            # 回退：文本包含关系（弱）
            t = str(c.text or "")
            seg = ""  # 由调用方传入更好；此处跳过无 span 的弱匹配
            if t and s <= 0:
                matched.append(c)
    return matched


def _best_candidate_for_segment(
    se_mod: Any,
    det_mod: Any,
    candidates: list[Any],
    seg_slice: str,
    record: dict[str, Any],
    locale: str,
) -> tuple[Any | None, dict[str, Any]]:
    locale_str = str(locale)
    expected = det_mod._expected_metric_components(record, locale_str)  # noqa: SLF001
    best: Any | None = None
    best_score = (-1, -1, -10**9)
    for c in candidates:
        actual = det_mod._candidate_metric_components(c, locale_str)  # noqa: SLF001
        exact_hits, partial_hits = det_mod._score_candidate(expected, actual)  # noqa: SLF001
        extra = len(actual)
        score = (exact_hits, partial_hits, -extra)
        if score > best_score:
            best_score = score
            best = c
    analysis = (
        se_mod._analyze_detector_candidates(candidates, expected, locale_str)  # noqa: SLF001
        if candidates
        else {
            "count": 0,
            "best_text": "",
            "best_components": {},
            "best_exact_hits": 0,
            "best_partial_hits": 0,
            "union_exact_keys": [],
            "union_partial_keys": [],
            "complete_best_exact": False,
            "complete_union_exact": False,
        }
    )
    return best, analysis


def _compose_zh_multi(records: list[dict[str, Any]], rng: random.Random) -> tuple[str, list[tuple[int, int, dict[str, Any], str]], tuple[str, str]]:
    texts = [str(r["text"]) for r in records]
    block = OCR_BREAK.join(texts)
    k = rng.randint(1, min(3, len(ZH_NOISE_PIIS)))
    frags = rng.sample(ZH_NOISE_PIIS, k=k)
    pos = rng.randint(0, len(frags))
    left = "".join(frags[:pos])
    right = "".join(frags[pos:])
    full = f"{left}{block}{right}"
    segments = texts
    spans = _locate_spans(full, len(left), segments, records)
    return full, spans, (left, right)


def _compose_en_multi(records: list[dict[str, Any]], rng: random.Random) -> tuple[str, list[tuple[int, int, dict[str, Any], str]], tuple[str, str]]:
    texts = [str(r["text"]) for r in records]
    block = OCR_BREAK.join(texts)
    k = rng.randint(1, min(3, len(EN_NOISE_PIIS)))
    frags = rng.sample(EN_NOISE_PIIS, k=k)
    pos = rng.randint(0, len(frags))
    left = (" ".join(frags[:pos]) + " ") if pos else ""
    right = (" " + " ".join(frags[pos:])) if pos < len(frags) else ""
    raw = f"{left}{block}{right}"
    full = _normalize_en_preserving_ocr_break(raw)
    bi = full.find(block)
    if bi < 0:
        raise RuntimeError("英文多段合成失败：找不到 block")
    left_actual = full[:bi]
    segments = texts
    spans = _locate_spans(full, len(left_actual), segments, records)
    return full, spans, (left_actual, full[bi + len(block) :])


def _compose_single_with_template(
    locale: str,
    center_text: str,
    template: tuple[str, str],
    rng: random.Random,
) -> tuple[str, tuple[int, int]]:
    del rng
    left, right = template
    if locale == "zh_cn":
        full = f"{left}{center_text}{right}"
        s = len(left)
        return full, (s, s + len(center_text))
    full = _normalize_en_preserving_ocr_break(f"{left}{center_text}{right}")
    bi = full.find(center_text)
    if bi < 0:
        compact = re.sub(r"\s+", "", center_text)
        for i in range(0, max(1, len(full) - len(center_text) + 1)):
            window = full[i : i + len(center_text)]
            if re.sub(r"\s+", "", window) == compact:
                bi = i
                break
        else:
            raise RuntimeError("单段模板合成失败：无法在英文归一化串中定位地址")
    return full, (bi, bi + len(center_text))


def _pick_multi_records(pool: list[dict[str, Any]], k: int, rng: random.Random) -> list[dict[str, Any]]:
    if len(pool) < k:
        raise ValueError("样本池不足")
    return rng.sample(pool, k=k)


def _latency_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"avg_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}
    ordered = sorted(values)
    mid = len(ordered) // 2
    median = (ordered[mid - 1] + ordered[mid]) / 2 if len(ordered) % 2 == 0 else ordered[mid]
    p95_i = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
    return {
        "avg_ms": round(sum(ordered) / len(ordered), 3),
        "median_ms": round(median, 3),
        "p95_ms": round(ordered[p95_i], 3),
    }


def _write_md(
    path: Path,
    *,
    args: argparse.Namespace,
    multi_stats: dict[str, Any],
    same_stats: dict[str, Any],
    timing: dict[str, Any],
) -> None:
    lines: list[str] = []
    lines.append("# 合成地址 + 噪声 PII + OCR_BREAK 评测摘要")
    lines.append("")
    lines.append("## 设定")
    lines.append("")
    lines.append(f"- 数据：`data/generate_data.py`（count={args.count}, seed={args.seed}）。")
    lines.append(f"- 多段样本/语言：`{args.multi_samples}`；每文 `{args.min_addresses}`–`{args.max_addresses}` 条地址。")
    lines.append(f"- 同址变体样本/语言：`{args.same_samples}`；左右噪声模板与完整句一致。")
    lines.append(f"- 编排随机种子：`{args.compose_seed}`。")
    lines.append(f"- 地址段分隔：`{OCR_BREAK!r}`。")
    lines.append("- 中文：地址与噪声均无空格；逆序样式由生成器随机（含英文逗号 `,` 分段）。")
    lines.append("- 英文：单词间单空格；整句外层 `_normalize_en_outer`。")
    lines.append("- 同址判定：`privacyguard.utils.normalized_pii.same_entity`（重叠段内各候选两两组合）。")
    lines.append("")
    lines.append("## 多段地址（碎片化与组件）")
    lines.append("")
    for loc in ("zh_cn", "en_us"):
        s = multi_stats[loc]
        label = "中文" if loc == "zh_cn" else "英文"
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- 地址段总数：`{s['segments']}`")
        b = s["bucket"]
        lines.append(
            f"- 每段 detector 地址候选数 bucket `0/1/>1`：`{b.get('zero', 0)}` / "
            f"`{b.get('one', 0)}` / `{b.get('multi', 0)}`"
        )
        lines.append(f"- 单段期望组件的「最佳候选」精确覆盖：`{s['seg_complete_best_exact']}` / `{s['segments']}`")
        lines.append(f"- 单段「并集精确」覆盖：`{s['seg_complete_union_exact']}` / `{s['segments']}`")
        lines.append("")
    lines.append("## 同址变体（单段嵌入相同模板）")
    lines.append("")
    for loc in ("zh_cn", "en_us"):
        s = same_stats[loc]
        label = "中文" if loc == "zh_cn" else "英文"
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- 样本数：`{s['cases']}`")
        lines.append(f"- same_entity 命中：`{s['same_entity_hits']}` / `{s['cases']}`")
        lines.append(f"- 双方均有 ≥1 地址候选时 same_entity：`{s['same_when_both']}` / `{s['both_positive']}`")
        fb, vb = s["full_bucket"], s["variant_bucket"]
        lines.append(
            f"- 完整句地址候选数 `0/1/>1`：`{fb.get('zero', 0)}` / "
            f"`{fb.get('one', 0)}` / `{fb.get('multi', 0)}`"
        )
        lines.append(
            f"- 变体句地址候选数 `0/1/>1`：`{vb.get('zero', 0)}` / "
            f"`{vb.get('one', 0)}` / `{vb.get('multi', 0)}`"
        )
        lines.append("")
    lines.append("## 耗时（ms）")
    lines.append("")
    md = timing["multi_detect"]
    sd = timing["same_pair_detect"]
    lines.append(
        f"- 多段（每次整篇 `detect`）：平均 `{md['avg_ms']}`，中位 `{md['median_ms']}`，P95 `{md['p95_ms']}`"
    )
    lines.append(
        f"- 同址成对（每条样本连续两次 `detect` 合计）：平均 `{sd['avg_ms']}`，中位 `{sd['median_ms']}`，P95 `{sd['p95_ms']}`"
    )
    lines.append("")
    lines.append("## 简析")
    lines.append("")
    lines.append(
        "- **碎片化**：`>1` bucket 比例高说明单条真实地址在合成上下文中被切成多个 `ADDRESS` span，后续替换/映射风险上升。"
    )
    lines.append(
        "- **组件**：`最佳`看单 span 内最强解释；`并集`看多 span 是否仍能拼回全部行政/道路要素。"
    )
    lines.append(
        "- **同址**：`same_entity` 不依赖字符串相等；若「双方均有检测」子集上命中率仍低，说明归一化对齐在跨语序/截断场景下偏严或特征不足。"
    )
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="合成地址+PPI 上下文评测")
    parser.add_argument("--skip-generate", action="store_true", help="跳过生成，直接读 data 下 txt/jsonl")
    parser.add_argument("--count", type=int, default=500, help="generate_data 每种语言条数")
    parser.add_argument("--seed", type=int, default=42, help="generate_data 随机种子")
    parser.add_argument("--compose-seed", type=int, default=20260418, help="合成与抽样随机种子")
    parser.add_argument("--multi-samples", type=int, default=60, help="每语言多段合成评测样本数")
    parser.add_argument("--same-samples", type=int, default=60, help="每语言同址变体评测样本数")
    parser.add_argument("--min-addresses", type=int, default=2, help="每篇最少地址条数")
    parser.add_argument("--max-addresses", type=int, default=3, help="每篇最多地址条数")
    args = parser.parse_args()

    if not args.skip_generate:
        _run_generate_data(count=args.count, seed=args.seed)

    rng = random.Random(int(args.compose_seed))
    se_mod = _load_script_module("eval_same_entity_mod", "eval_generated_address_same_entity.py")
    det_mod = _load_script_module("eval_det_mod", "eval_generated_address_detector.py")
    from privacyguard.utils.normalized_pii import same_entity as same_entity_fn

    detectors = {
        "zh_cn": det_mod.RuleBasedPIIDetector(locale_profile="zh_cn"),
        "en_us": det_mod.RuleBasedPIIDetector(locale_profile="en_us"),
    }

    def load_pool(locale: str) -> list[dict[str, Any]]:
        return se_mod._load_records(locale)  # noqa: SLF001

    multi_stats: dict[str, Any] = {}
    same_stats: dict[str, Any] = {}
    multi_lat: list[float] = []
    same_lat: list[float] = []

    multi_cases: list[dict[str, Any]] = []
    same_cases: list[dict[str, Any]] = []

    for locale in ("zh_cn", "en_us"):
        pool = load_pool(locale)
        detector = detectors[locale]
        bucket = Counter()
        seg_complete_best = 0
        seg_complete_union = 0
        segments_total = 0

        for _ in range(args.multi_samples):
            k = rng.randint(args.min_addresses, min(args.max_addresses, len(pool)))
            recs = _pick_multi_records(pool, k, rng)
            if locale == "zh_cn":
                full, spans, _tpl = _compose_zh_multi(recs, rng)
            else:
                full, spans, _tpl = _compose_en_multi(recs, rng)

            t0 = time.perf_counter()
            all_c = _address_candidates(detector, full)
            multi_lat.append((time.perf_counter() - t0) * 1000)

            for s, e, rec, seg_txt in spans:
                segments_total += 1
                seg_cands = [c for c in all_c if c.span_start is not None and _overlap(int(c.span_start), int(c.span_end), s, e) > 0]
                n = len(seg_cands)
                if n <= 0:
                    bucket["zero"] += 1
                elif n == 1:
                    bucket["one"] += 1
                else:
                    bucket["multi"] += 1
                _, analysis = _best_candidate_for_segment(se_mod, det_mod, seg_cands, seg_txt, rec, locale)
                if analysis.get("complete_best_exact"):
                    seg_complete_best += 1
                if analysis.get("complete_union_exact"):
                    seg_complete_union += 1
                multi_cases.append(
                    {
                        "locale": locale,
                        "text": full,
                        "segment": seg_txt,
                        "span": [s, e],
                        "address_hits_in_segment": n,
                        "complete_best_exact": analysis.get("complete_best_exact"),
                        "complete_union_exact": analysis.get("complete_union_exact"),
                        "all_spans": [c.text for c in seg_cands],
                    }
                )

        multi_stats[locale] = {
            "segments": segments_total,
            "bucket": dict(bucket),
            "seg_complete_best_exact": seg_complete_best,
            "seg_complete_union_exact": seg_complete_union,
        }

        sb_full = Counter()
        sb_var = Counter()
        same_hits = 0
        both_pos = 0
        same_when_both = 0

        for _ in range(args.same_samples):
            record = rng.choice(pool)
            variant = se_mod._build_variant_case(record, rng)  # noqa: SLF001
            full_addr = str(record["text"])
            var_addr = str(variant["text"])
            if locale == "zh_cn":
                _, _, tpl = _compose_zh_multi([record], rng)
            else:
                _, _, tpl = _compose_en_multi([record], rng)
            text_full, span_full = _compose_single_with_template(locale, full_addr, tpl, rng)
            text_var, span_var = _compose_single_with_template(locale, var_addr, tpl, rng)

            t0 = time.perf_counter()
            cf = _address_candidates(detector, text_full)
            cv = _address_candidates(detector, text_var)
            same_lat.append((time.perf_counter() - t0) * 1000)

            sf0, sf1 = span_full
            vf0, vf1 = span_var
            cf_seg = [
                c
                for c in cf
                if c.span_start is not None
                and c.span_end is not None
                and _overlap(int(c.span_start), int(c.span_end), sf0, sf1) > 0
            ]
            cv_seg = [
                c
                for c in cv
                if c.span_start is not None
                and c.span_end is not None
                and _overlap(int(c.span_start), int(c.span_end), vf0, vf1) > 0
            ]

            def bkey(n: int) -> str:
                if n <= 0:
                    return "zero"
                if n == 1:
                    return "one"
                return "multi"

            sb_full[bkey(len(cf_seg))] += 1
            sb_var[bkey(len(cv_seg))] += 1

            hit = any(
                same_entity_fn(a.normalized_source, b.normalized_source)
                for a in cf_seg
                for b in cv_seg
                if a.normalized_source is not None and b.normalized_source is not None
            )
            if hit:
                same_hits += 1
            if cf_seg and cv_seg:
                both_pos += 1
                if hit:
                    same_when_both += 1

            same_cases.append(
                {
                    "locale": locale,
                    "full": text_full,
                    "variant": text_var,
                    "same_entity": hit,
                    "full_hits": len(cf_seg),
                    "var_hits": len(cv_seg),
                    "full_spans": [c.text for c in cf_seg],
                    "var_spans": [c.text for c in cv_seg],
                }
            )

        same_stats[locale] = {
            "cases": args.same_samples,
            "same_entity_hits": same_hits,
            "both_positive": both_pos,
            "same_when_both": same_when_both,
            "full_bucket": dict(sb_full),
            "variant_bucket": dict(sb_var),
        }

    timing = {
        "multi_detect": _latency_stats(multi_lat),
        "same_pair_detect": _latency_stats(same_lat),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_DIR / "composed_address_pii_eval.json"
    out_md = OUTPUT_DIR / "composed_address_pii_eval.md"

    payload = {
        "args": vars(args),
        "ocr_break": OCR_BREAK,
        "multi_stats": multi_stats,
        "same_stats": same_stats,
        "timing": timing,
        "multi_cases_sample": multi_cases[:40],
        "same_cases_sample": same_cases[:40],
    }
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_md(out_md, args=args, multi_stats=multi_stats, same_stats=same_stats, timing=timing)

    print(out_md)
    print(out_json)


if __name__ == "__main__":
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    main()
