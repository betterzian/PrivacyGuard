"""评测 generate_data.py 生成的地址在 PrivacyGuard 中的识别表现。"""

from __future__ import annotations

import csv
import json
import re
import time
from collections import defaultdict
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_keyword_groups,
    load_en_address_suffix_strippers,
    load_zh_address_suffix_strippers,
)
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "outputs" / "analysis"


COMPONENT_KEYS = (
    "province",
    "city",
    "district",
    "subdistrict",
    "road",
    "number",
    "poi",
    "building",
    "detail",
)

ZH_SUFFIX_STRIPPERS = load_zh_address_suffix_strippers()
EN_SUFFIX_STRIPPERS = load_en_address_suffix_strippers()
ALNUM_RE = re.compile(r"[A-Za-z0-9]+")
DIGIT_RE = re.compile(r"\d+")
EN_SUFFIX_KEYWORDS: dict[str, list[str]] = defaultdict(list)
EN_PREFIX_DETAIL_KEYWORDS: list[str] = []

for group in load_en_address_keyword_groups():
    key = group.component_type.value
    keywords = [str(keyword or "").strip().lower() for keyword in group.keywords if str(keyword or "").strip()]
    EN_SUFFIX_KEYWORDS[key].extend(sorted(keywords, key=len, reverse=True))
    if key == "detail":
        EN_PREFIX_DETAIL_KEYWORDS.extend(sorted(keywords, key=len, reverse=True))


def _compact_text(text: str) -> str:
    return re.sub(r"[\s,，。;；:：/\\|()（）【】\[\]#._-]+", "", str(text or "")).strip()


def _normalize_component_value(component_key: str, value: str, locale: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if component_key == "number":
        return "".join(ch for ch in raw if ch.isdigit())
    if locale == "zh_cn" and component_key in {"building", "detail"}:
        alnum = "".join(ALNUM_RE.findall(raw)).upper()
        if any(ch.isalpha() for ch in alnum):
            return alnum
        digits = "".join(DIGIT_RE.findall(raw))
        return digits
    compact = _compact_text(raw)
    if not compact:
        return ""
    if locale == "zh_cn":
        pattern = ZH_SUFFIX_STRIPPERS.get(component_key)
        if pattern is None:
            return compact
        stripped = pattern.sub("", compact).strip()
        return stripped or compact
    lowered = compact.lower()
    if component_key == "province":
        return lowered.upper()
    if component_key == "detail":
        for prefix in EN_PREFIX_DETAIL_KEYWORDS:
            if lowered.startswith(prefix) and len(lowered) > len(prefix):
                tail = compact[len(prefix):]
                normalized_tail = "".join(ALNUM_RE.findall(tail)).upper()
                return normalized_tail or compact.upper()
        return compact.upper()
    if component_key in {"road", "poi", "building"}:
        for suffix in EN_SUFFIX_KEYWORDS.get(component_key, []):
            if lowered.endswith(suffix) and len(lowered) > len(suffix):
                stem = compact[: len(compact) - len(suffix)]
                if component_key == "building":
                    normalized_stem = "".join(ALNUM_RE.findall(stem)).upper()
                    return normalized_stem or compact.upper()
                return _compact_text(stem).upper()
    return compact.upper()


def _component_match(expected: str, actual: str) -> tuple[bool, bool]:
    if not expected or not actual:
        return False, False
    if expected == actual:
        return True, True
    return False, expected in actual or actual in expected


def _load_records(locale: str) -> list[dict[str, object]]:
    txt_path = DATA_DIR / ("chinese_addresses.txt" if locale == "zh_cn" else "english_addresses.txt")
    jsonl_path = DATA_DIR / ("chinese_addresses.jsonl" if locale == "zh_cn" else "english_addresses.jsonl")
    txt_lines = [line.strip() for line in txt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    records: list[dict[str, object]] = []
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            records.append(json.loads(text))
    if len(txt_lines) != len(records):
        raise ValueError(f"{locale} txt/jsonl 行数不一致：{len(txt_lines)} vs {len(records)}")
    for txt, record in zip(txt_lines, records, strict=True):
        if txt != record["text"]:
            raise ValueError(f"{locale} 文本与真值不一致：{txt} != {record['text']}")
    return records


def _candidate_components(candidate, locale: str) -> dict[str, str]:
    normalized = candidate.normalized_source
    if normalized is None:
        return {}
    return {
        key: _normalize_component_value(key, value, locale)
        for key, value in normalized.components.items()
        if key in COMPONENT_KEYS and str(value or "").strip()
    }


def _expected_components(record: dict[str, object], locale: str) -> dict[str, str]:
    source = record.get("components", {})
    if not isinstance(source, dict):
        return {}
    return {
        key: _normalize_component_value(key, value, locale)
        for key, value in source.items()
        if key in COMPONENT_KEYS and str(value or "").strip()
    }


def _score_candidate(expected: dict[str, str], actual: dict[str, str]) -> tuple[int, int]:
    exact_hits = 0
    partial_hits = 0
    for key, exp_value in expected.items():
        is_exact, is_partial = _component_match(exp_value, actual.get(key, ""))
        if is_exact:
            exact_hits += 1
        elif is_partial:
            partial_hits += 1
    return exact_hits, partial_hits


def _evaluate_locale(locale: str, detector: RuleBasedPIIDetector) -> tuple[dict[str, object], list[dict[str, object]]]:
    records = _load_records(locale)
    aggregates: dict[str, object] = {
        "locale": locale,
        "total": len(records),
        "crash": 0,
        "zero_address": 0,
        "single_address": 0,
        "multi_address": 0,
        "avg_address_pii": 0.0,
        "single_full_exact": 0,
        "union_full_exact": 0,
        "single_full_partial": 0,
        "union_full_partial": 0,
        "component_expected_counts": defaultdict(int),
        "component_best_exact_hits": defaultdict(int),
        "component_best_partial_hits": defaultdict(int),
        "component_union_exact_hits": defaultdict(int),
        "component_union_partial_hits": defaultdict(int),
        "elapsed_ms_total": 0.0,
    }
    cases: list[dict[str, object]] = []

    for record in records:
        text = str(record["text"])
        expected = _expected_components(record, locale)
        for key in expected:
            aggregates["component_expected_counts"][key] += 1

        started = time.perf_counter()
        error_text = ""
        detected_addresses = []
        try:
            candidates = detector.detect(text, [])
            detected_addresses = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS]
        except Exception as exc:  # noqa: BLE001
            aggregates["crash"] += 1
            error_text = f"{type(exc).__name__}: {exc}"
            detected_addresses = []
        elapsed_ms = (time.perf_counter() - started) * 1000
        aggregates["elapsed_ms_total"] += elapsed_ms

        if not detected_addresses:
            aggregates["zero_address"] += 1
        elif len(detected_addresses) == 1:
            aggregates["single_address"] += 1
        else:
            aggregates["multi_address"] += 1

        candidate_components = [_candidate_components(candidate, locale) for candidate in detected_addresses]
        best_index = -1
        best_exact = -1
        best_partial = -1
        best_extra = 10**9
        for index, actual in enumerate(candidate_components):
            exact_hits, partial_hits = _score_candidate(expected, actual)
            extra = len(actual)
            if (exact_hits, partial_hits, -extra) > (best_exact, best_partial, -best_extra):
                best_index = index
                best_exact = exact_hits
                best_partial = partial_hits
                best_extra = extra

        if best_index >= 0 and best_index < len(candidate_components):
            best_components = candidate_components[best_index]
            best_text = detected_addresses[best_index].text
        else:
            best_components = {}
            best_text = ""
            best_exact = 0
            best_partial = 0

        union_exact_keys: set[str] = set()
        union_partial_keys: set[str] = set()
        best_exact_keys: set[str] = set()
        best_partial_keys: set[str] = set()
        for key, exp_value in expected.items():
            is_exact, is_partial = _component_match(exp_value, best_components.get(key, ""))
            if is_exact:
                best_exact_keys.add(key)
            elif is_partial:
                best_partial_keys.add(key)

            for actual in candidate_components:
                current_exact, current_partial = _component_match(exp_value, actual.get(key, ""))
                if current_exact:
                    union_exact_keys.add(key)
                    break
                if current_partial:
                    union_partial_keys.add(key)

        for key in best_exact_keys:
            aggregates["component_best_exact_hits"][key] += 1
        for key in best_partial_keys:
            aggregates["component_best_partial_hits"][key] += 1
        for key in union_exact_keys:
            aggregates["component_union_exact_hits"][key] += 1
        for key in union_partial_keys:
            if key not in union_exact_keys:
                aggregates["component_union_partial_hits"][key] += 1

        if expected and len(best_exact_keys) == len(expected) and len(detected_addresses) == 1:
            aggregates["single_full_exact"] += 1
        if expected and len(union_exact_keys) == len(expected):
            aggregates["union_full_exact"] += 1
        if expected and len(best_exact_keys | best_partial_keys) == len(expected) and len(detected_addresses) == 1:
            aggregates["single_full_partial"] += 1
        if expected and len(union_exact_keys | union_partial_keys) == len(expected):
            aggregates["union_full_partial"] += 1

        cases.append(
            {
                "locale": locale,
                "id": record["id"],
                "format": record["format"],
                "text": text,
                "expected_components": expected,
                "address_pii_count": len(detected_addresses),
                "elapsed_ms": round(elapsed_ms, 3),
                "best_text": best_text,
                "best_components": best_components,
                "best_exact_hits": best_exact,
                "best_partial_hits": best_partial,
                "union_exact_keys": sorted(union_exact_keys),
                "union_partial_keys": sorted(union_partial_keys),
                "all_texts": [candidate.text for candidate in detected_addresses],
                "all_components": candidate_components,
                "missing_exact": sorted(key for key in expected if key not in union_exact_keys),
                "missing_partial": sorted(key for key in expected if key not in union_exact_keys | union_partial_keys),
                "error": error_text,
            }
        )

    aggregates["avg_address_pii"] = round(
        sum(case["address_pii_count"] for case in cases) / len(cases),
        3,
    )
    aggregates["avg_elapsed_ms"] = round(float(aggregates["elapsed_ms_total"]) / len(cases), 3)
    return aggregates, cases


def _rate(hit: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(hit / total) * 100:.1f}%"


def _write_summary(path: Path, summaries: list[dict[str, object]], cases: list[dict[str, object]]) -> None:
    lines: list[str] = []
    lines.append("# Generated Address Detector Summary")
    lines.append("")
    lines.append("## 数据口径")
    lines.append("")
    lines.append("- 输入来自 `data/generate_data.py` 生成的 `chinese_addresses.txt` / `english_addresses.txt`。")
    lines.append("- 地址文本不含空格。")
    lines.append("- 中文逆序模板一律带 `,` 或 `，`。")
    lines.append("- 组件正确性按当前 detector 的 `normalized_source.components` 对比生成器真值。")
    lines.append("- 同一输入若返回多个 `address` 候选，既统计“最佳单候选”，也统计“多候选并集”。")
    lines.append("")

    for summary in summaries:
        locale = str(summary["locale"])
        label = "中文" if locale == "zh_cn" else "英文"
        lines.append(f"## {label}")
        lines.append("")
        lines.append(f"- 总样本：`{summary['total']}`")
        lines.append(f"- 崩溃：`{summary['crash']}`")
        lines.append(f"- `0` 个地址 PII：`{summary['zero_address']}`")
        lines.append(f"- `1` 个地址 PII：`{summary['single_address']}`")
        lines.append(f"- `>1` 个地址 PII：`{summary['multi_address']}`")
        lines.append(f"- 平均每条地址产出：`{summary['avg_address_pii']}` 个 `address` PII")
        lines.append(f"- 平均耗时：`{summary['avg_elapsed_ms']}` ms/条")
        lines.append(f"- 单候选完整精确命中：`{summary['single_full_exact']}` / `{summary['total']}`")
        lines.append(f"- 多候选并集完整精确命中：`{summary['union_full_exact']}` / `{summary['total']}`")
        lines.append(f"- 单候选完整宽松命中：`{summary['single_full_partial']}` / `{summary['total']}`")
        lines.append(f"- 多候选并集完整宽松命中：`{summary['union_full_partial']}` / `{summary['total']}`")
        lines.append("")
        lines.append("| 组件 | 真值出现数 | 最佳单候选精确 | 最佳单候选宽松 | 多候选并集精确 | 多候选并集宽松 |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        expected_counts = summary["component_expected_counts"]
        for key in COMPONENT_KEYS:
            total = int(expected_counts.get(key, 0))
            if total <= 0:
                continue
            best_exact = int(summary["component_best_exact_hits"].get(key, 0))
            best_partial = int(summary["component_best_partial_hits"].get(key, 0))
            union_exact = int(summary["component_union_exact_hits"].get(key, 0))
            union_partial = int(summary["component_union_partial_hits"].get(key, 0))
            lines.append(
                f"| `{key}` | {total} | {best_exact} ({_rate(best_exact, total)}) | "
                f"{best_exact + best_partial} ({_rate(best_exact + best_partial, total)}) | "
                f"{union_exact} ({_rate(union_exact, total)}) | "
                f"{union_exact + union_partial} ({_rate(union_exact + union_partial, total)}) |"
            )
        lines.append("")

        lines.append("### 代表性失败样例")
        lines.append("")
        failed_cases = [
            case
            for case in cases
            if case["locale"] == locale
            and (case["address_pii_count"] != 1 or case["missing_exact"] or case["error"])
        ][:8]
        for case in failed_cases:
            lines.append(f"- 输入：`{case['text']}`")
            lines.append(f"  预期：`{case['expected_components']}`")
            lines.append(f"  实际地址 PII 数：`{case['address_pii_count']}`")
            lines.append(f"  最佳 span：`{case['best_text']}`")
            lines.append(f"  最佳组件：`{case['best_components']}`")
            lines.append(f"  所有 span：`{case['all_texts']}`")
            if case["missing_exact"]:
                lines.append(f"  缺失精确组件：`{case['missing_exact']}`")
            if case["error"]:
                lines.append(f"  异常：`{case['error']}`")
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cases_csv(path: Path, cases: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "locale",
                "id",
                "format",
                "text",
                "expected_components",
                "address_pii_count",
                "elapsed_ms",
                "best_text",
                "best_components",
                "best_exact_hits",
                "best_partial_hits",
                "union_exact_keys",
                "union_partial_keys",
                "all_texts",
                "all_components",
                "missing_exact",
                "missing_partial",
                "error",
            ],
        )
        writer.writeheader()
        for case in cases:
            writer.writerow(
                {
                    **case,
                    "expected_components": json.dumps(case["expected_components"], ensure_ascii=False),
                    "best_components": json.dumps(case["best_components"], ensure_ascii=False),
                    "union_exact_keys": json.dumps(case["union_exact_keys"], ensure_ascii=False),
                    "union_partial_keys": json.dumps(case["union_partial_keys"], ensure_ascii=False),
                    "all_texts": json.dumps(case["all_texts"], ensure_ascii=False),
                    "all_components": json.dumps(case["all_components"], ensure_ascii=False),
                    "missing_exact": json.dumps(case["missing_exact"], ensure_ascii=False),
                    "missing_partial": json.dumps(case["missing_partial"], ensure_ascii=False),
                }
            )


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    zh_detector = RuleBasedPIIDetector(locale_profile="zh_cn")
    en_detector = RuleBasedPIIDetector(locale_profile="en_us")

    zh_summary, zh_cases = _evaluate_locale("zh_cn", zh_detector)
    en_summary, en_cases = _evaluate_locale("en_us", en_detector)
    all_cases = [*zh_cases, *en_cases]
    summaries = [zh_summary, en_summary]

    details = {
        "summaries": [
            {
                **summary,
                "component_expected_counts": dict(summary["component_expected_counts"]),
                "component_best_exact_hits": dict(summary["component_best_exact_hits"]),
                "component_best_partial_hits": dict(summary["component_best_partial_hits"]),
                "component_union_exact_hits": dict(summary["component_union_exact_hits"]),
                "component_union_partial_hits": dict(summary["component_union_partial_hits"]),
            }
            for summary in summaries
        ],
        "cases": all_cases,
    }

    summary_path = OUTPUT_DIR / "generated_address_compact_detector_summary.md"
    details_path = OUTPUT_DIR / "generated_address_compact_detector_details.json"
    cases_path = OUTPUT_DIR / "generated_address_compact_detector_cases.csv"

    _write_summary(summary_path, summaries, all_cases)
    details_path.write_text(json.dumps(details, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_cases_csv(cases_path, all_cases)

    print(summary_path)
    print(details_path)
    print(cases_path)


if __name__ == "__main__":
    main()
