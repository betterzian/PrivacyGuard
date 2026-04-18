"""OCR_BREAK 多地址拼接场景评测。"""

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
OCR_BREAK_SEP = "  <OCR_BREAK>    "
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")


def _load(locale: str) -> list[dict[str, Any]]:
    name = "chinese_addresses.jsonl" if locale == "zh_cn" else "english_addresses.jsonl"
    rows: list[dict[str, Any]] = []
    with (DATA_DIR / name).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _prefix(locale: str, rng: random.Random) -> str:
    if locale == "zh_cn":
        return f"林舟，1{rng.randint(30,99)}{rng.randint(1000,9999)}{rng.randint(1000,9999)}，lin{rng.randint(10,99)}@mail.cn，星河数据科技有限公司，"
    return f"Emma Lee, 206-555-{rng.randint(1000,9999)}, emma{rng.randint(10,99)}@example.com, North Harbor Labs, "


def _segment_spans(prefix: str, addrs: list[str]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    cursor = len(prefix)
    for i, addr in enumerate(addrs):
        out.append((cursor, cursor + len(addr)))
        cursor += len(addr)
        if i < len(addrs) - 1:
            cursor += len(OCR_BREAK_SEP)
    return out


def _assign(start: int | None, end: int | None, segs: list[tuple[int, int]]) -> int | None:
    if start is None or end is None:
        return None
    best = None
    best_ov = 0
    for i, (s0, s1) in enumerate(segs):
        ov = max(0, min(end, s1) - max(start, s0))
        if ov > best_ov:
            best_ov = ov
            best = i
    return best


def _andlab() -> Any | None:
    if not (ANDLAB_ROOT / "utils_mobile").is_dir():
        return None
    sys.path.insert(0, str(ANDLAB_ROOT))
    try:
        from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore

        return PrivacyProtectionLayer(enabled=True)
    except Exception:
        return None


def _andlab_addr_count(layer: Any, text: str) -> int:
    layer.clear_mappings()
    masked, _ = layer.anonymize_prompt(text)
    count = 0
    for m in TOKEN_RE.finditer(masked):
        token = m.group(1)
        real = layer.token_to_real.get(token)
        if not real:
            continue
        label = str(layer.real_to_entity_type.get(real, "MISC"))
        if label == "ADDRESS" or label.startswith("LOCATION_"):
            count += 1
    return count


def _lat(vals: list[float]) -> dict[str, float]:
    if not vals:
        return {"avg_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}
    vals = sorted(vals)
    n = len(vals)
    m = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2
    p95 = vals[min(n - 1, max(0, int(0.95 * n) - 1))]
    return {"avg_ms": round(sum(vals) / n, 3), "median_ms": round(m, 3), "p95_ms": round(p95, 3)}


def main() -> None:
    rng = random.Random(20260411)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    andlab = _andlab()
    payload: dict[str, Any] = {"ocr_break_sep": OCR_BREAK_SEP, "andlab_available": andlab is not None, "locales": {}}
    for locale in ("zh_cn", "en_us"):
        rows = _load(locale)
        detector = RuleBasedPIIDetector(locale_profile=locale)
        seg_total = one = zero = multi = 0
        case_addr_total = 0
        pair_checked = pair_false = 0
        d_lat: list[float] = []
        a_lat: list[float] = []
        andlab_entities = 0
        for _ in range(50):
            k = rng.randint(2, 3)
            selected = rng.sample(rows, k)
            addrs = [str(x["text"]) for x in selected]
            text = _prefix(locale, rng) + OCR_BREAK_SEP.join(addrs)
            segs = _segment_spans(_prefix(locale, random.Random(1)), addrs)  # 仅用于对齐长度基准无影响
            # 用真实前缀长度重算
            prefix = text[: len(text) - len(OCR_BREAK_SEP.join(addrs))]
            segs = _segment_spans(prefix, addrs)
            t0 = time.perf_counter()
            cands = [c for c in detector.detect(text, []) if c.attr_type == PIIAttributeType.ADDRESS]
            d_lat.append((time.perf_counter() - t0) * 1000)
            case_addr_total += len(cands)
            per_seg: list[list[Any]] = [[] for _ in range(k)]
            for c in cands:
                idx = _assign(c.span_start, c.span_end, segs)
                if idx is not None:
                    per_seg[idx].append(c)
            for i in range(k):
                seg_total += 1
                n = len(per_seg[i])
                if n == 0:
                    zero += 1
                elif n == 1:
                    one += 1
                else:
                    multi += 1
            for i in range(k):
                for j in range(i + 1, k):
                    for a in per_seg[i][:3]:
                        for b in per_seg[j][:3]:
                            pair_checked += 1
                            if same_entity_fn(a.normalized_source, b.normalized_source):
                                pair_false += 1
            if andlab is not None:
                t1 = time.perf_counter()
                andlab_entities += _andlab_addr_count(andlab, text)
                a_lat.append((time.perf_counter() - t1) * 1000)
        payload["locales"][locale] = {
            "segments": seg_total,
            "one_rate": round(one / max(1, seg_total), 4),
            "zero_rate": round(zero / max(1, seg_total), 4),
            "multi_rate": round(multi / max(1, seg_total), 4),
            "avg_addr_per_case": round(case_addr_total / 50, 4),
            "cross_segment_false_same_entity": pair_false,
            "cross_segment_pairs_checked": pair_checked,
            "detector_latency_ms": _lat(d_lat),
            "andlab_latency_ms": _lat(a_lat) if a_lat else None,
            "andlab_address_entities_total": andlab_entities,
        }
    out_json = OUTPUT_DIR / "generated_address_ocr_break_details.json"
    out_md = OUTPUT_DIR / "generated_address_ocr_break_summary.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# OCR_BREAK 多地址评测",
        f"- 分隔符：`{OCR_BREAK_SEP}`",
        f"- AndLab 可用：`{payload['andlab_available']}`",
        "",
    ]
    for locale, x in payload["locales"].items():
        label = "中文" if locale == "zh_cn" else "英文"
        lines.extend(
            [
                f"## {label}",
                f"- 分段总数：`{x['segments']}`",
                f"- 每段恰好1个地址：`{x['one_rate']*100:.2f}%`",
                f"- 每段0个：`{x['zero_rate']*100:.2f}%`",
                f"- 每段>1个：`{x['multi_rate']*100:.2f}%`",
                f"- 每用例平均地址候选数：`{x['avg_addr_per_case']}`",
                f"- 跨段误判同实体：`{x['cross_segment_false_same_entity']}` / `{x['cross_segment_pairs_checked']}`",
                f"- detector耗时(ms)：avg `{x['detector_latency_ms']['avg_ms']}` / p95 `{x['detector_latency_ms']['p95_ms']}`",
            ]
        )
        if x["andlab_latency_ms"] is not None:
            lines.append(f"- AndLab耗时(ms)：avg `{x['andlab_latency_ms']['avg_ms']}` / p95 `{x['andlab_latency_ms']['p95_ms']}`")
            lines.append(f"- AndLab地址类实体累计：`{x['andlab_address_entities_total']}`")
        lines.append("")
    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(out_md)
    print(out_json)


if __name__ == "__main__":
    main()
