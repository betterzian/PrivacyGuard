"""编排：生成地址 → 拼接地址派生 PII 与 OCR_BREAK 多段地址 → 评测 detector 组件/碎片化/同址与时间。"""

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
    "订单备注：加急派送",
    "配送前请电话联系",
    "客户状态：已核验",
]
EN_NOISE_PIIS = [
    "Ship to Alex Rivera",
    "Rush delivery requested",
    "Call before arrival",
    "Customer status: verified",
]

ZH_REGION_CODES = {
    "北京市": "BJ",
    "上海市": "SH",
    "广东省": "GD",
    "江苏省": "JS",
    "浙江省": "ZJ",
}
EN_AREA_CODES = ("206", "312", "512", "617", "503", "425")


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


def _normalize_address_text(locale: str, text: str) -> str:
    return str(text or "").strip() if locale == "zh_cn" else _normalize_en_outer(text)


def _join_noise_fragments(locale: str, fragments: list[str]) -> str:
    parts = [str(fragment).strip() for fragment in fragments if str(fragment).strip()]
    if not parts:
        return ""
    return "".join(parts) if locale == "zh_cn" else " ".join(parts)


def _locate_text_spans(full_text: str, texts: list[str], start_cursor: int) -> list[tuple[int, int]]:
    """按出现顺序定位片段 span，避免重复值回跳。"""
    spans: list[tuple[int, int]] = []
    cursor = start_cursor
    for text in texts:
        index = full_text.find(text, cursor)
        if index < 0:
            raise RuntimeError(f"无法在合成文本中定位片段：{text}")
        spans.append((index, index + len(text)))
        cursor = index + len(text)
    return spans


def _address_candidates(detector: Any, text: str) -> list[Any]:
    from privacyguard.domain.enums import PIIAttributeType

    return [candidate for candidate in detector.detect(text, []) if candidate.attr_type == PIIAttributeType.ADDRESS]


def _overlap(a0: int, a1: int, b0: int, b1: int) -> int:
    left = max(a0, b0)
    right = min(a1, b1)
    return max(0, right - left)


def _candidates_in_span(candidates: list[Any], s: int, e: int) -> list[Any]:
    matched: list[Any] = []
    for candidate in candidates:
        if candidate.span_start is None or candidate.span_end is None:
            continue
        if _overlap(int(candidate.span_start), int(candidate.span_end), s, e) > 0:
            matched.append(candidate)
    return matched


def _best_candidate_for_segment(
    se_mod: Any,
    det_mod: Any,
    candidates: list[Any],
    record: dict[str, Any],
    locale: str,
) -> tuple[Any | None, dict[str, Any]]:
    locale_str = str(locale)
    expected = det_mod._expected_metric_components(record, locale_str)  # noqa: SLF001
    best: Any | None = None
    best_score = (-1, -1, -10**9)
    for candidate in candidates:
        actual = det_mod._candidate_metric_components(candidate, locale_str)  # noqa: SLF001
        exact_hits, partial_hits = det_mod._score_candidate(expected, actual)  # noqa: SLF001
        extra = len(actual)
        score = (exact_hits, partial_hits, -extra)
        if score > best_score:
            best_score = score
            best = candidate
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


def _pick_multi_records(pool: list[dict[str, Any]], k: int, rng: random.Random) -> list[dict[str, Any]]:
    if len(pool) < k:
        raise ValueError("样本池不足")
    return rng.sample(pool, k=k)


def _bucket_key(count: int) -> str:
    if count <= 0:
        return "zero"
    if count == 1:
        return "one"
    return "multi"


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


def _extract_digits(text: str) -> list[str]:
    return re.findall(r"\d+", str(text or ""))


def _record_digit_seed(record: dict[str, Any]) -> str:
    components = record.get("components", {})
    digits: list[str] = []
    if isinstance(components, dict):
        for key in ("number", "building", "detail"):
            digits.extend(_extract_digits(str(components.get(key, ""))))
    digits.append(f"{int(record['id']):04d}")
    seed = "".join(digits)
    padded = seed + seed[::-1] + f"{int(record['id']):08d}"
    return padded


def _record_locale_code(record: dict[str, Any], locale: str) -> str:
    components = record.get("components", {})
    if not isinstance(components, dict):
        return "PG"
    if locale == "zh_cn":
        province = str(components.get("province", "")).strip()
        return ZH_REGION_CODES.get(province, "CN")
    province = str(components.get("province", "")).strip().upper()
    city = str(components.get("city", "")).strip()
    city_alpha = "".join(token[0].upper() for token in re.findall(r"[A-Za-z]+", city))
    if len(province) >= 2:
        return province[:2]
    if len(city_alpha) >= 2:
        return city_alpha[:2]
    return (province + city_alpha + "US")[:2]


def _ascii_seed(record: dict[str, Any], locale: str) -> str:
    code = _record_locale_code(record, locale)
    return (code + f"{int(record['id']):04d}").upper()


def _build_derived_pii_specs(record: dict[str, Any], locale: str) -> list[dict[str, Any]]:
    from privacyguard.domain.enums import PIIAttributeType

    seed_digits = _record_digit_seed(record)
    seed_code = _record_locale_code(record, locale)
    ascii_seed = _ascii_seed(record, locale)
    case_id = int(record["id"])

    phone_tail = (seed_digits[-8:]).zfill(8)
    if locale == "zh_cn":
        phone_head = ("139", "138", "137", "136")[case_id % 4]
        phone_full = f"{phone_head}{phone_tail}"
        phone_variant = f"+86 {phone_head} {phone_tail[:4]} {phone_tail[4:]}"
    else:
        area = EN_AREA_CODES[case_id % len(EN_AREA_CODES)]
        local = (seed_digits[-7:]).zfill(7)
        phone_full = f"{area}-{local[:3]}-{local[3:]}"
        phone_variant = f"+1 {area} {local[:3]} {local[3:]}"

    email_local = f"{seed_code.lower()}{case_id:04d}{seed_digits[-4:]}"
    email_full = f"{email_local}@example.com"
    email_variant = f"{email_local.upper()}@EXAMPLE.COM"

    amount_major = 100 + (int(seed_digits[:4]) % 900)
    if locale == "zh_cn":
        amount_full = f"{amount_major}.00元"
        amount_variant = f"￥{amount_major}.00"
    else:
        amount_full = f"${amount_major}.00"
        amount_variant = f"USD {amount_major}.00"

    passport_serial = (seed_digits[:8]).zfill(8)
    passport_full = f"P{ascii_seed[:2]}{passport_serial}"
    passport_variant = f"P-{ascii_seed[:2]}-{passport_serial}"

    member_digits = (seed_digits[-8:]).zfill(8)
    member_full = member_digits
    member_variant = f"{member_digits[:4]}-{member_digits[4:]}"

    if locale == "zh_cn":
        label_prefixes = {
            "phone": "手机：",
            "email": "邮箱：",
            "amount": "金额：",
            "passport_number": "护照号：",
            "member_number": "会员号：",
        }
    else:
        label_prefixes = {
            "phone": "Phone: ",
            "email": "Email: ",
            "amount": "Amount: ",
            "passport_number": "Passport: ",
            "member_number": "Member No.: ",
        }

    return [
        {
            "key": "phone",
            "exact_attr": PIIAttributeType.PHONE,
            "actual_attr": PIIAttributeType.PHONE,
            "full_value": phone_full,
            "variant_value": phone_variant,
            "label_prefix": label_prefixes["phone"],
        },
        {
            "key": "email",
            "exact_attr": PIIAttributeType.EMAIL,
            "actual_attr": PIIAttributeType.EMAIL,
            "full_value": email_full,
            "variant_value": email_variant,
            "label_prefix": label_prefixes["email"],
        },
        {
            "key": "amount",
            "exact_attr": PIIAttributeType.AMOUNT,
            "actual_attr": PIIAttributeType.AMOUNT,
            "full_value": amount_full,
            "variant_value": amount_variant,
            "label_prefix": label_prefixes["amount"],
        },
        {
            "key": "passport_number",
            "exact_attr": PIIAttributeType.PASSPORT_NUMBER,
            "actual_attr": PIIAttributeType.ALNUM,
            "full_value": passport_full,
            "variant_value": passport_variant,
            "label_prefix": label_prefixes["passport_number"],
        },
        {
            "key": "member_number",
            "exact_attr": "member_number",
            "actual_attr": PIIAttributeType.NUM,
            "full_value": member_full,
            "variant_value": member_variant,
            "label_prefix": label_prefixes["member_number"],
        },
    ]


def _materialize_pii_fragment(locale: str, spec: dict[str, Any], *, use_variant: bool) -> dict[str, Any]:
    value = str(spec["variant_value"] if use_variant else spec["full_value"])
    prefix = str(spec["label_prefix"])
    text = f"{prefix}{value}" if locale == "zh_cn" else f"{prefix}{value}"
    return {
        "kind": "pii",
        "key": str(spec["key"]),
        "exact_attr": spec["exact_attr"],
        "actual_attr": spec["actual_attr"],
        "text": text,
        "value": value,
        "value_span": (len(prefix), len(prefix) + len(value)),
    }


def _materialize_static_fragment(text: str) -> dict[str, Any]:
    return {"kind": "static", "text": str(text)}


def _attr_name(attr: Any) -> str:
    value = getattr(attr, "value", None)
    return str(value if value is not None else attr)


def _compose_address_block(
    *,
    locale: str,
    address_texts: list[str],
    left_entries: list[dict[str, Any]],
    right_entries: list[dict[str, Any]],
) -> tuple[str, list[tuple[int, int]], list[dict[str, Any]]]:
    normalized_addresses = [_normalize_address_text(locale, text) for text in address_texts]
    block = OCR_BREAK.join(normalized_addresses)
    left_text = _join_noise_fragments(locale, [entry["text"] for entry in left_entries])
    right_text = _join_noise_fragments(locale, [entry["text"] for entry in right_entries])
    if locale == "zh_cn":
        full_text = f"{left_text}{block}{right_text}"
    else:
        parts = [part for part in (left_text, block, right_text) if part]
        full_text = _normalize_en_preserving_ocr_break(" ".join(parts))
    block_start = full_text.find(block)
    if block_start < 0:
        raise RuntimeError("无法在合成上下文中定位 OCR_BREAK 地址块。")
    address_spans = _locate_text_spans(full_text, normalized_addresses, block_start)
    left_spans = _locate_text_spans(full_text, [entry["text"] for entry in left_entries], 0) if left_entries else []
    right_spans = _locate_text_spans(full_text, [entry["text"] for entry in right_entries], block_start + len(block)) if right_entries else []
    annotated_entries: list[dict[str, Any]] = []
    for entry, span in zip([*left_entries, *right_entries], [*left_spans, *right_spans], strict=True):
        item = dict(entry)
        item["fragment_span"] = [span[0], span[1]]
        if entry.get("kind") == "pii":
            value_start, value_end = entry["value_span"]
            item["value_abs_span"] = [span[0] + value_start, span[0] + value_end]
        annotated_entries.append(item)
    return full_text, address_spans, annotated_entries


def _build_multi_noise_entries(locale: str, records: list[dict[str, Any]], rng: random.Random) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    static_pool = ZH_NOISE_PIIS if locale == "zh_cn" else EN_NOISE_PIIS
    entries: list[dict[str, Any]] = []
    static_count = rng.randint(1, min(2, len(static_pool)))
    entries.extend(_materialize_static_fragment(text) for text in rng.sample(static_pool, k=static_count))

    pii_specs: list[dict[str, Any]] = []
    for record in records:
        specs = _build_derived_pii_specs(record, locale)
        take = rng.randint(1, min(2, len(specs)))
        pii_specs.extend(rng.sample(specs, k=take))
    if pii_specs:
        pick = rng.randint(1, min(4, len(pii_specs)))
        entries.extend(_materialize_pii_fragment(locale, spec, use_variant=False) for spec in rng.sample(pii_specs, k=pick))
    rng.shuffle(entries)
    split = rng.randint(0, len(entries))
    return entries[:split], entries[split:]


def _build_pair_noise_entries(
    locale: str,
    record: dict[str, Any],
    target_spec: dict[str, Any],
    specs: list[dict[str, Any]],
    rng: random.Random,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    static_pool = ZH_NOISE_PIIS if locale == "zh_cn" else EN_NOISE_PIIS
    items: list[dict[str, Any]] = []
    static_count = rng.randint(1, min(2, len(static_pool)))
    items.extend({"kind": "static", "text": text} for text in rng.sample(static_pool, k=static_count))

    del record
    for spec in specs:
        items.append(
            {
                "kind": "pii",
                "key": spec["key"],
                "full": _materialize_pii_fragment(locale, spec, use_variant=False),
                "variant": _materialize_pii_fragment(locale, spec, use_variant=spec["key"] == target_spec["key"]),
            }
        )

    rng.shuffle(items)
    split = rng.randint(0, len(items))
    left_items = items[:split]
    right_items = items[split:]

    def materialize(source: list[dict[str, Any]], which: str) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in source:
            if item["kind"] == "static":
                output.append(_materialize_static_fragment(item["text"]))
                continue
            output.append(dict(item[which]))
        return output

    full_left = materialize(left_items, "full")
    full_right = materialize(right_items, "full")
    variant_left = materialize(left_items, "variant")
    variant_right = materialize(right_items, "variant")
    return full_left, full_right, variant_left, variant_right


def _init_pii_type_summary() -> dict[str, Any]:
    return {
        "mentions": 0,
        "exact_hits": 0,
        "actual_hits": 0,
        "bucket": Counter(),
        "pairs": 0,
        "exact_same_entity_hits": 0,
        "actual_same_entity_hits": 0,
        "both_exact_positive": 0,
        "both_actual_positive": 0,
        "exact_same_when_both": 0,
        "actual_same_when_both": 0,
    }


def _init_pii_summary() -> dict[str, Any]:
    summary = _init_pii_type_summary()
    summary["types"] = defaultdict(_init_pii_type_summary)
    return summary


def _match_expected_candidates(
    candidates: list[Any],
    *,
    attr: Any,
    expected_normalized: Any,
    same_entity_fn: Any,
) -> list[Any]:
    if expected_normalized is None:
        return []
    matched: list[Any] = []
    for candidate in candidates:
        if candidate.attr_type != attr or candidate.normalized_source is None:
            continue
        if same_entity_fn(candidate.normalized_source, expected_normalized):
            matched.append(candidate)
    return matched


def _evaluate_pii_mention(
    candidates: list[Any],
    entry: dict[str, Any],
    *,
    normalize_pii_fn: Any,
    same_entity_fn: Any,
) -> dict[str, Any]:
    value_start, value_end = entry["value_abs_span"]
    span_candidates = _candidates_in_span(candidates, int(value_start), int(value_end))
    exact_attr = entry["exact_attr"]
    actual_attr = entry["actual_attr"]
    exact_normalized = normalize_pii_fn(exact_attr, entry["value"]) if hasattr(exact_attr, "value") else None
    actual_normalized = normalize_pii_fn(actual_attr, entry["value"])
    exact_matches = _match_expected_candidates(span_candidates, attr=exact_attr, expected_normalized=exact_normalized, same_entity_fn=same_entity_fn)
    actual_matches = _match_expected_candidates(span_candidates, attr=actual_attr, expected_normalized=actual_normalized, same_entity_fn=same_entity_fn)
    return {
        "key": entry["key"],
        "exact_attr": _attr_name(exact_attr),
        "actual_attr": _attr_name(actual_attr),
        "count": len(span_candidates),
        "bucket": _bucket_key(len(span_candidates)),
        "exact_hit": bool(exact_matches),
        "actual_hit": bool(actual_matches),
        "all_types": [_attr_name(candidate.attr_type) for candidate in span_candidates],
        "all_texts": [candidate.text for candidate in span_candidates],
        "exact_match_texts": [candidate.text for candidate in exact_matches],
        "actual_match_texts": [candidate.text for candidate in actual_matches],
        "exact_candidates": exact_matches,
        "actual_candidates": actual_matches,
    }


def _update_pii_mention_summary(summary: dict[str, Any], key: str, analysis: dict[str, Any]) -> None:
    summary["mentions"] += 1
    summary["exact_hits"] += int(bool(analysis["exact_hit"]))
    summary["actual_hits"] += int(bool(analysis["actual_hit"]))
    summary["bucket"][analysis["bucket"]] += 1
    type_summary = summary["types"][key]
    type_summary["mentions"] += 1
    type_summary["exact_hits"] += int(bool(analysis["exact_hit"]))
    type_summary["actual_hits"] += int(bool(analysis["actual_hit"]))
    type_summary["bucket"][analysis["bucket"]] += 1


def _same_entity_across(left: list[Any], right: list[Any], same_entity_fn: Any) -> bool:
    return any(
        same_entity_fn(lc.normalized_source, rc.normalized_source)
        for lc in left
        for rc in right
        if lc.normalized_source is not None and rc.normalized_source is not None
    )


def _evaluate_pii_pair(
    full_analysis: dict[str, Any],
    variant_analysis: dict[str, Any],
    *,
    same_entity_fn: Any,
) -> dict[str, Any]:
    full_exact_candidates = list(full_analysis["exact_candidates"])
    variant_exact_candidates = list(variant_analysis["exact_candidates"])
    full_actual_candidates = list(full_analysis["actual_candidates"])
    variant_actual_candidates = list(variant_analysis["actual_candidates"])
    exact_same = _same_entity_across(full_exact_candidates, variant_exact_candidates, same_entity_fn)
    actual_same = _same_entity_across(full_actual_candidates, variant_actual_candidates, same_entity_fn)
    return {
        "full_exact_positive": bool(full_exact_candidates),
        "variant_exact_positive": bool(variant_exact_candidates),
        "full_actual_positive": bool(full_actual_candidates),
        "variant_actual_positive": bool(variant_actual_candidates),
        "exact_same_entity": exact_same,
        "actual_same_entity": actual_same,
    }


def _update_pii_pair_summary(summary: dict[str, Any], key: str, pair_result: dict[str, Any]) -> None:
    summary["pairs"] += 1
    summary["exact_same_entity_hits"] += int(bool(pair_result["exact_same_entity"]))
    summary["actual_same_entity_hits"] += int(bool(pair_result["actual_same_entity"]))
    if pair_result["full_exact_positive"] and pair_result["variant_exact_positive"]:
        summary["both_exact_positive"] += 1
        summary["exact_same_when_both"] += int(bool(pair_result["exact_same_entity"]))
    if pair_result["full_actual_positive"] and pair_result["variant_actual_positive"]:
        summary["both_actual_positive"] += 1
        summary["actual_same_when_both"] += int(bool(pair_result["actual_same_entity"]))

    type_summary = summary["types"][key]
    type_summary["pairs"] += 1
    type_summary["exact_same_entity_hits"] += int(bool(pair_result["exact_same_entity"]))
    type_summary["actual_same_entity_hits"] += int(bool(pair_result["actual_same_entity"]))
    if pair_result["full_exact_positive"] and pair_result["variant_exact_positive"]:
        type_summary["both_exact_positive"] += 1
        type_summary["exact_same_when_both"] += int(bool(pair_result["exact_same_entity"]))
    if pair_result["full_actual_positive"] and pair_result["variant_actual_positive"]:
        type_summary["both_actual_positive"] += 1
        type_summary["actual_same_when_both"] += int(bool(pair_result["actual_same_entity"]))


def _finalize_bucketed_summary(summary: dict[str, Any]) -> dict[str, Any]:
    mentions = max(1, int(summary["mentions"]))
    pairs = max(1, int(summary["pairs"]))
    both_exact_positive = max(1, int(summary["both_exact_positive"]))
    both_actual_positive = max(1, int(summary["both_actual_positive"]))
    finalized = dict(summary)
    finalized["bucket"] = dict(finalized["bucket"])
    finalized["exact_recall_rate"] = round(int(summary["exact_hits"]) / mentions, 3)
    finalized["actual_recall_rate"] = round(int(summary["actual_hits"]) / mentions, 3)
    finalized["exact_same_entity_rate"] = round(int(summary["exact_same_entity_hits"]) / pairs, 3)
    finalized["actual_same_entity_rate"] = round(int(summary["actual_same_entity_hits"]) / pairs, 3)
    finalized["exact_same_when_both_rate"] = round(int(summary["exact_same_when_both"]) / both_exact_positive, 3)
    finalized["actual_same_when_both_rate"] = round(int(summary["actual_same_when_both"]) / both_actual_positive, 3)
    return finalized


def _finalize_pii_summary(summary: dict[str, Any]) -> dict[str, Any]:
    finalized = _finalize_bucketed_summary({key: value for key, value in summary.items() if key != "types"})
    finalized["types"] = {
        key: _finalize_bucketed_summary(type_summary)
        for key, type_summary in sorted(summary["types"].items(), key=lambda item: item[0])
    }
    return finalized


def _rate(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.0%"
    return f"{(numerator / denominator) * 100:.1f}%"


def _write_md(
    path: Path,
    *,
    args: argparse.Namespace,
    multi_stats: dict[str, Any],
    same_stats: dict[str, Any],
    pii_stats: dict[str, Any],
    timing: dict[str, Any],
) -> None:
    lines: list[str] = []
    lines.append("# 合成地址 + 地址派生 PII + OCR_BREAK 评测摘要")
    lines.append("")
    lines.append("## 设定")
    lines.append("")
    lines.append(f"- 数据：`data/generate_data.py`（count={args.count}, seed={args.seed}）。")
    lines.append(f"- 多段样本/语言：`{args.multi_samples}`；每文 `{args.min_addresses}`–`{args.max_addresses}` 条地址。")
    lines.append(f"- 同址变体样本/语言：`{args.same_samples}`；完整地址与地址变体共享同一批干扰地址与 PII 模板。")
    lines.append(f"- 编排随机种子：`{args.compose_seed}`。")
    lines.append(f"- 地址段分隔：`{OCR_BREAK!r}`。")
    lines.append("- 中文：地址与派生 PII 不引入空格；逆序样式由生成器随机（含英文逗号 `,` 分段）。")
    lines.append("- 英文：地址与派生 PII 统一压成单词间单空格，并保留 `OCR_BREAK` 内部空格。")
    lines.append("- 地址组件对比沿用 `eval_generated_address_detector.py` 的 suffix stripping 规则。")
    lines.append("- 地址同址判定与组件评分沿用 `eval_generated_address_same_entity.py`。")
    lines.append("- 派生 PII 精确召回：span 内存在**属性一致**且与目标值 `same_entity` 的候选。")
    lines.append("- 派生 PII 实际召回：仅对 detector 不直接支持的类型放宽到 `alnum/num`；语义类仍要求原属性。")
    lines.append("")
    lines.append("## 多段地址（碎片化与组件）")
    lines.append("")
    for locale in ("zh_cn", "en_us"):
        stats = multi_stats[locale]
        label = "中文" if locale == "zh_cn" else "英文"
        bucket = stats["bucket"]
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- 地址段总数：`{stats['segments']}`")
        lines.append(
            f"- 每段 detector 地址候选数 bucket `0/1/>1`：`{bucket.get('zero', 0)}` / "
            f"`{bucket.get('one', 0)}` / `{bucket.get('multi', 0)}`"
        )
        lines.append(
            f"- 单段期望组件的最佳候选精确覆盖：`{stats['seg_complete_best_exact']}` / `{stats['segments']}` "
            f"（{_rate(int(stats['seg_complete_best_exact']), int(stats['segments']))}）"
        )
        lines.append(
            f"- 单段并集精确覆盖：`{stats['seg_complete_union_exact']}` / `{stats['segments']}` "
            f"（{_rate(int(stats['seg_complete_union_exact']), int(stats['segments']))}）"
        )
        lines.append("")

    lines.append("## 地址同址变体（共享地址块与 PII 模板）")
    lines.append("")
    for locale in ("zh_cn", "en_us"):
        stats = same_stats[locale]
        label = "中文" if locale == "zh_cn" else "英文"
        full_bucket = stats["full_bucket"]
        variant_bucket = stats["variant_bucket"]
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- 样本数：`{stats['cases']}`")
        lines.append(
            f"- same_entity 命中：`{stats['same_entity_hits']}` / `{stats['cases']}` "
            f"（{_rate(int(stats['same_entity_hits']), int(stats['cases']))}）"
        )
        lines.append(
            f"- 双方均有 ≥1 地址候选时 same_entity：`{stats['same_when_both']}` / `{stats['both_positive']}` "
            f"（{_rate(int(stats['same_when_both']), int(stats['both_positive']))}）"
        )
        lines.append(
            f"- 完整句地址候选数 `0/1/>1`：`{full_bucket.get('zero', 0)}` / "
            f"`{full_bucket.get('one', 0)}` / `{full_bucket.get('multi', 0)}`"
        )
        lines.append(
            f"- 变体句地址候选数 `0/1/>1`：`{variant_bucket.get('zero', 0)}` / "
            f"`{variant_bucket.get('one', 0)}` / `{variant_bucket.get('multi', 0)}`"
        )
        lines.append("")

    lines.append("## 地址派生 PII（召回、碎片化与变体）")
    lines.append("")
    for locale in ("zh_cn", "en_us"):
        stats = pii_stats[locale]
        label = "中文" if locale == "zh_cn" else "英文"
        bucket = stats["bucket"]
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- 插入 PII mention：`{stats['mentions']}`")
        lines.append(
            f"- 精确召回：`{stats['exact_hits']}` / `{stats['mentions']}` "
            f"（{_rate(int(stats['exact_hits']), int(stats['mentions']))}）"
        )
        lines.append(
            f"- 实际召回：`{stats['actual_hits']}` / `{stats['mentions']}` "
            f"（{_rate(int(stats['actual_hits']), int(stats['mentions']))}）"
        )
        lines.append(
            f"- 每个 PII span 候选数 `0/1/>1`：`{bucket.get('zero', 0)}` / "
            f"`{bucket.get('one', 0)}` / `{bucket.get('multi', 0)}`"
        )
        lines.append(
            f"- 目标 PII 变体 exact same_entity：`{stats['exact_same_entity_hits']}` / `{stats['pairs']}` "
            f"（{_rate(int(stats['exact_same_entity_hits']), int(stats['pairs']))}）"
        )
        lines.append(
            f"- 目标 PII 变体 actual same_entity：`{stats['actual_same_entity_hits']}` / `{stats['pairs']}` "
            f"（{_rate(int(stats['actual_same_entity_hits']), int(stats['pairs']))}）"
        )
        lines.append(
            f"- 双方均有 exact 命中时 exact same_entity：`{stats['exact_same_when_both']}` / `{stats['both_exact_positive']}` "
            f"（{_rate(int(stats['exact_same_when_both']), int(stats['both_exact_positive']))}）"
        )
        lines.append(
            f"- 双方均有 actual 命中时 actual same_entity：`{stats['actual_same_when_both']}` / `{stats['both_actual_positive']}` "
            f"（{_rate(int(stats['actual_same_when_both']), int(stats['both_actual_positive']))}）"
        )
        lines.append("")
        lines.append("| 类型 | mentions | 精确召回 | 实际召回 | `0/1/>1` | actual same_entity |")
        lines.append("|---|---:|---:|---:|---|---:|")
        for key, type_stats in stats["types"].items():
            bucket_text = (
                f"{type_stats['bucket'].get('zero', 0)} / "
                f"{type_stats['bucket'].get('one', 0)} / "
                f"{type_stats['bucket'].get('multi', 0)}"
            )
            lines.append(
                f"| `{key}` | {type_stats['mentions']} | "
                f"{type_stats['exact_hits']} ({_rate(int(type_stats['exact_hits']), int(type_stats['mentions']))}) | "
                f"{type_stats['actual_hits']} ({_rate(int(type_stats['actual_hits']), int(type_stats['mentions']))}) | "
                f"{bucket_text} | "
                f"{type_stats['actual_same_entity_hits']} / {type_stats['pairs']} "
                f"({_rate(int(type_stats['actual_same_entity_hits']), int(type_stats['pairs']))}) |"
            )
        lines.append("")

    lines.append("## 耗时（ms）")
    lines.append("")
    multi_detect = timing["multi_detect"]
    pair_detect = timing["pair_detect"]
    lines.append(
        f"- 多段整篇 `detect`：平均 `{multi_detect['avg_ms']}`，中位 `{multi_detect['median_ms']}`，P95 `{multi_detect['p95_ms']}`"
    )
    lines.append(
        f"- 地址 + PII 变体成对 `detect`（每样本两次 `detect` 合计）：平均 `{pair_detect['avg_ms']}`，"
        f"中位 `{pair_detect['median_ms']}`，P95 `{pair_detect['p95_ms']}`"
    )
    lines.append("")
    lines.append("## 简析")
    lines.append("")
    lines.append("- **地址组件**：`最佳`反映单个 span 能否完整承载地址；`并集`高于`最佳`时，说明 detector 倾向把一个真实地址拆成多个实体。")
    lines.append("- **地址同址**：若“双方均有检测”子集的 same_entity 仍偏低，问题更多在归一化对齐或组件缺失，而不是单纯漏检。")
    lines.append("- **派生 PII 精确 vs 实际**：两者差值主要来自 detector 未直接支持的类型，被 `alnum/num` 吸收但无法回到原语义标签。")
    lines.append("- **派生 PII 碎片化**：`>1` bucket 偏高说明单个 PII span 被切成多个候选，后续替换和映射时更容易一条值落多实体。")
    lines.append("- **派生 PII same_entity**：actual same_entity 明显高于 exact same_entity，通常说明值本体已经被捕获，但类型被降到了 `alnum/num`。")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="合成地址 + 地址派生 PII 上下文评测")
    parser.add_argument("--skip-generate", action="store_true", help="跳过生成，直接读 data 下 txt/jsonl")
    parser.add_argument("--count", type=int, default=500, help="generate_data 每种语言条数")
    parser.add_argument("--seed", type=int, default=42, help="generate_data 随机种子")
    parser.add_argument("--compose-seed", type=int, default=20260418, help="合成与抽样随机种子")
    parser.add_argument("--multi-samples", type=int, default=60, help="每语言多段合成评测样本数")
    parser.add_argument("--same-samples", type=int, default=60, help="每语言同址与派生 PII 评测样本数")
    parser.add_argument("--min-addresses", type=int, default=2, help="每篇最少地址条数")
    parser.add_argument("--max-addresses", type=int, default=3, help="每篇最多地址条数")
    args = parser.parse_args()

    if not args.skip_generate:
        _run_generate_data(count=args.count, seed=args.seed)

    rng = random.Random(int(args.compose_seed))
    se_mod = _load_script_module("eval_same_entity_mod", "eval_generated_address_same_entity.py")
    det_mod = _load_script_module("eval_det_mod", "eval_generated_address_detector.py")
    from privacyguard.utils.normalized_pii import normalize_pii, same_entity as same_entity_fn

    detectors = {
        "zh_cn": det_mod.RuleBasedPIIDetector(locale_profile="zh_cn"),
        "en_us": det_mod.RuleBasedPIIDetector(locale_profile="en_us"),
    }

    def load_pool(locale: str) -> list[dict[str, Any]]:
        return se_mod._load_records(locale)  # noqa: SLF001

    multi_stats: dict[str, Any] = {}
    same_stats: dict[str, Any] = {}
    pii_stats: dict[str, Any] = {}
    multi_lat: list[float] = []
    pair_lat: list[float] = []

    multi_cases: list[dict[str, Any]] = []
    same_cases: list[dict[str, Any]] = []
    pii_cases: list[dict[str, Any]] = []
    variant_multi_details: list[dict[str, Any]] = []

    for locale in ("zh_cn", "en_us"):
        pool = load_pool(locale)
        detector = detectors[locale]

        bucket = Counter()
        seg_complete_best = 0
        seg_complete_union = 0
        segments_total = 0

        for _ in range(args.multi_samples):
            k = rng.randint(args.min_addresses, min(args.max_addresses, len(pool)))
            records = _pick_multi_records(pool, k, rng)
            left_entries, right_entries = _build_multi_noise_entries(locale, records, rng)
            address_texts = [str(record["text"]) for record in records]
            full_text, address_spans, _ = _compose_address_block(
                locale=locale,
                address_texts=address_texts,
                left_entries=left_entries,
                right_entries=right_entries,
            )

            started = time.perf_counter()
            all_candidates = _address_candidates(detector, full_text)
            multi_lat.append((time.perf_counter() - started) * 1000)

            for (start, end), record, segment_text in zip(address_spans, records, address_texts, strict=True):
                segments_total += 1
                segment_candidates = _candidates_in_span(all_candidates, start, end)
                bucket[_bucket_key(len(segment_candidates))] += 1
                _, analysis = _best_candidate_for_segment(se_mod, det_mod, segment_candidates, record, locale)
                if analysis.get("complete_best_exact"):
                    seg_complete_best += 1
                if analysis.get("complete_union_exact"):
                    seg_complete_union += 1
                multi_cases.append(
                    {
                        "locale": locale,
                        "text": full_text,
                        "segment": segment_text,
                        "span": [start, end],
                        "address_hits_in_segment": len(segment_candidates),
                        "complete_best_exact": analysis.get("complete_best_exact"),
                        "complete_union_exact": analysis.get("complete_union_exact"),
                        "all_spans": [candidate.text for candidate in segment_candidates],
                    }
                )

        multi_stats[locale] = {
            "segments": segments_total,
            "bucket": dict(bucket),
            "seg_complete_best_exact": seg_complete_best,
            "seg_complete_union_exact": seg_complete_union,
        }

        same_bucket_full = Counter()
        same_bucket_variant = Counter()
        same_hits = 0
        same_both_positive = 0
        same_when_both = 0

        pii_summary = _init_pii_summary()

        for _ in range(args.same_samples):
            record = rng.choice(pool)
            variant_record = se_mod._build_variant_case(record, rng)  # noqa: SLF001
            distractor_records = se_mod._sample_distractor_records(pool, record, rng)  # noqa: SLF001
            distractor_texts = [str(item["text"]) for item in distractor_records]
            target_index = rng.randint(0, len(distractor_texts))

            specs = _build_derived_pii_specs(record, locale)
            target_spec = rng.choice(specs)
            full_left, full_right, variant_left, variant_right = _build_pair_noise_entries(locale, record, target_spec, specs, rng)

            full_bundle_text, full_address_spans, full_entries = _compose_address_block(
                locale=locale,
                address_texts=[*distractor_texts[:target_index], str(record["text"]), *distractor_texts[target_index:]],
                left_entries=full_left,
                right_entries=full_right,
            )
            variant_bundle_text, variant_address_spans, variant_entries = _compose_address_block(
                locale=locale,
                address_texts=[*distractor_texts[:target_index], str(variant_record["text"]), *distractor_texts[target_index:]],
                left_entries=variant_left,
                right_entries=variant_right,
            )

            full_address_span = full_address_spans[target_index]
            variant_address_span = variant_address_spans[target_index]

            started = time.perf_counter()
            full_candidates_all = detector.detect(full_bundle_text, [])
            variant_candidates_all = detector.detect(variant_bundle_text, [])
            pair_lat.append((time.perf_counter() - started) * 1000)

            full_address_candidates = [candidate for candidate in full_candidates_all if candidate.attr_type == det_mod.PIIAttributeType.ADDRESS]
            variant_address_candidates = [candidate for candidate in variant_candidates_all if candidate.attr_type == det_mod.PIIAttributeType.ADDRESS]
            full_target_address_candidates = _candidates_in_span(full_address_candidates, *full_address_span)
            variant_target_address_candidates = _candidates_in_span(variant_address_candidates, *variant_address_span)

            same_bucket_full[_bucket_key(len(full_target_address_candidates))] += 1
            same_bucket_variant[_bucket_key(len(variant_target_address_candidates))] += 1

            if len(variant_target_address_candidates) > 1:

                def _norm_dump(candidate: Any) -> dict[str, Any]:
                    normalized = candidate.normalized_source
                    if normalized is None:
                        return {"text": candidate.text, "span": [candidate.span_start, candidate.span_end], "normalized": None}
                    return {
                        "text": candidate.text,
                        "span": [candidate.span_start, candidate.span_end],
                        "canonical": normalized.canonical,
                        "components": dict(normalized.components),
                        "identity": dict(normalized.identity),
                        "numbers": list(normalized.numbers),
                        "keyed_numbers": dict(normalized.keyed_numbers),
                        "ordered_components": [
                            {
                                "type": oc.component_type,
                                "level": list(oc.level),
                                "value": oc.value if not isinstance(oc.value, tuple) else list(oc.value),
                                "key": oc.key if not isinstance(oc.key, tuple) else list(oc.key),
                                "suspected": [
                                    {"levels": list(s.levels), "value": s.value, "key": s.key, "origin": s.origin}
                                    for s in oc.suspected
                                ],
                            }
                            for oc in normalized.ordered_components
                        ],
                    }

                variant_multi_details.append(
                    {
                        "locale": locale,
                        "variant_style": variant_record["style"],
                        "full_address_line": str(record["text"]),
                        "variant_address_line": str(variant_record["text"]),
                        "text_full": full_bundle_text,
                        "text_var": variant_bundle_text,
                        "span_full": list(full_address_span),
                        "span_var": list(variant_address_span),
                        "all_variant_ADDRESS": [_norm_dump(candidate) for candidate in variant_address_candidates],
                        "overlap_variant_ADDRESS": [_norm_dump(candidate) for candidate in variant_target_address_candidates],
                    }
                )

            address_same_hit = any(
                same_entity_fn(left.normalized_source, right.normalized_source)
                for left in full_target_address_candidates
                for right in variant_target_address_candidates
                if left.normalized_source is not None and right.normalized_source is not None
            )
            if address_same_hit:
                same_hits += 1
            if full_target_address_candidates and variant_target_address_candidates:
                same_both_positive += 1
                if address_same_hit:
                    same_when_both += 1

            full_entry_results: list[dict[str, Any]] = []
            variant_entry_results: list[dict[str, Any]] = []
            for entry in full_entries:
                if entry.get("kind") != "pii":
                    continue
                analysis = _evaluate_pii_mention(
                    full_candidates_all,
                    entry,
                    normalize_pii_fn=normalize_pii,
                    same_entity_fn=same_entity_fn,
                )
                full_entry_results.append(analysis)
                _update_pii_mention_summary(pii_summary, entry["key"], analysis)

            for entry in variant_entries:
                if entry.get("kind") != "pii":
                    continue
                analysis = _evaluate_pii_mention(
                    variant_candidates_all,
                    entry,
                    normalize_pii_fn=normalize_pii,
                    same_entity_fn=same_entity_fn,
                )
                variant_entry_results.append(analysis)
                _update_pii_mention_summary(pii_summary, entry["key"], analysis)

            full_target_entry = next(entry for entry in full_entries if entry.get("kind") == "pii" and entry["key"] == target_spec["key"])
            variant_target_entry = next(entry for entry in variant_entries if entry.get("kind") == "pii" and entry["key"] == target_spec["key"])
            full_target_analysis = next(item for item in full_entry_results if item["key"] == target_spec["key"])
            variant_target_analysis = next(item for item in variant_entry_results if item["key"] == target_spec["key"])
            pii_pair_result = _evaluate_pii_pair(full_target_analysis, variant_target_analysis, same_entity_fn=same_entity_fn)
            _update_pii_pair_summary(pii_summary, target_spec["key"], pii_pair_result)

            same_cases.append(
                {
                    "locale": locale,
                    "full": full_bundle_text,
                    "variant": variant_bundle_text,
                    "same_entity": address_same_hit,
                    "full_hits": len(full_target_address_candidates),
                    "var_hits": len(variant_target_address_candidates),
                    "full_spans": [candidate.text for candidate in full_target_address_candidates],
                    "var_spans": [candidate.text for candidate in variant_target_address_candidates],
                }
            )

            pii_cases.append(
                {
                    "locale": locale,
                    "target_type": target_spec["key"],
                    "target_exact_attr": _attr_name(target_spec["exact_attr"]),
                    "target_actual_attr": _attr_name(target_spec["actual_attr"]),
                    "variant_style": variant_record["style"],
                    "distractor_addresses": distractor_texts,
                    "full_context": full_bundle_text,
                    "variant_context": variant_bundle_text,
                    "full_address": str(record["text"]),
                    "variant_address": str(variant_record["text"]),
                    "full_target_fragment": full_target_entry["text"],
                    "variant_target_fragment": variant_target_entry["text"],
                    "full_target_value_span": full_target_entry["value_abs_span"],
                    "variant_target_value_span": variant_target_entry["value_abs_span"],
                    "address_same_entity": address_same_hit,
                    "pii_pair": {
                        "exact_same_entity": pii_pair_result["exact_same_entity"],
                        "actual_same_entity": pii_pair_result["actual_same_entity"],
                        "full_exact_positive": pii_pair_result["full_exact_positive"],
                        "variant_exact_positive": pii_pair_result["variant_exact_positive"],
                        "full_actual_positive": pii_pair_result["full_actual_positive"],
                        "variant_actual_positive": pii_pair_result["variant_actual_positive"],
                    },
                    "full_target_analysis": {
                        key: value
                        for key, value in full_target_analysis.items()
                        if key not in {"exact_candidates", "actual_candidates"}
                    },
                    "variant_target_analysis": {
                        key: value
                        for key, value in variant_target_analysis.items()
                        if key not in {"exact_candidates", "actual_candidates"}
                    },
                }
            )

        same_stats[locale] = {
            "cases": args.same_samples,
            "same_entity_hits": same_hits,
            "both_positive": same_both_positive,
            "same_when_both": same_when_both,
            "full_bucket": dict(same_bucket_full),
            "variant_bucket": dict(same_bucket_variant),
        }
        pii_stats[locale] = _finalize_pii_summary(pii_summary)

    timing = {
        "multi_detect": _latency_stats(multi_lat),
        "pair_detect": _latency_stats(pair_lat),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_DIR / "composed_address_pii_eval.json"
    out_md = OUTPUT_DIR / "composed_address_pii_eval.md"

    payload = {
        "args": vars(args),
        "ocr_break": OCR_BREAK,
        "multi_stats": multi_stats,
        "same_stats": same_stats,
        "pii_stats": pii_stats,
        "timing": timing,
        "multi_cases_sample": multi_cases[:40],
        "same_cases_sample": same_cases[:40],
        "pii_cases_sample": pii_cases[:80],
        "variant_multi_details": variant_multi_details,
    }
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_md(out_md, args=args, multi_stats=multi_stats, same_stats=same_stats, pii_stats=pii_stats, timing=timing)

    print(out_md)
    print(out_json)


if __name__ == "__main__":
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    main()
