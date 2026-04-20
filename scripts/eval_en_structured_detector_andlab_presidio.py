"""英文 structured 集：去标签 clean_text 后，对比 PrivacyGuard、AndLab、Presidio 的识别结果与 pii_inventory。

- 不写 OCR；PrivacyGuard 仅统计 ``PIISourceType.PROMPT`` 候选。
- AndLab：``PrivacyProtectionLayer.anonymize_prompt``（GLiNER + 正则回退），每条样本前 ``clear_mappings``。
- Presidio：优先从仓库 ``tmp/presidio-main/presidio-analyzer`` 注入 ``sys.path``，再 ``AnalyzerEngine``；``analyze(..., entities=None)`` 使用注册表中的全部实体类型。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

ROOT = Path(__file__).resolve().parents[1]
ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"
PRESIDIO_SRC = ROOT / "tmp" / "presidio-main" / "presidio-analyzer"

TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")
_ATTR_NORMALIZE = {"textual": "alnum", "other": "alnum"}

# 数据集 inventory.type -> 评测用 PIIAttributeType（与 PrivacyGuard 枚举对齐）
EVAL_LABEL_TO_ATTR: dict[str, PIIAttributeType] = {
    "ADDRESS": PIIAttributeType.ADDRESS,
    "NAME": PIIAttributeType.NAME,
    "PHONE": PIIAttributeType.PHONE,
    "EMAIL": PIIAttributeType.EMAIL,
    "BANK_CARD": PIIAttributeType.BANK_NUMBER,
    "ORG": PIIAttributeType.ORGANIZATION,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE,
    "LICENSE_PLATE": PIIAttributeType.LICENSE_PLATE,
    "TIME": PIIAttributeType.TIME,
    "AMOUNT": PIIAttributeType.AMOUNT,
    "ORDER_ID": PIIAttributeType.ALNUM,
    "TRACKING_ID": PIIAttributeType.ALNUM,
    "MEMBER_ID": PIIAttributeType.ALNUM,
    "ACCOUNT_ID": PIIAttributeType.ALNUM,
    "BIRTHDAY": PIIAttributeType.TIME,
}


def _normalize_attr_type(attr: str) -> str:
    normalized = str(attr or "").strip().lower()
    return _ATTR_NORMALIZE.get(normalized, normalized)


def _coerce_attr_type(attr: PIIAttributeType | str | None) -> PIIAttributeType | None:
    if attr is None:
        return None
    normalized = _normalize_attr_type(attr.value if isinstance(attr, PIIAttributeType) else attr)
    if not normalized:
        return None
    try:
        return PIIAttributeType(normalized)
    except Exception:
        return None


def _strip_all_pii_tags(text: str) -> str:
    cleaned = TAG_OPEN_RE.sub("", str(text or ""))
    return TAG_CLOSE_RE.sub("", cleaned)


def _load_structured(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("structured 根节点应为 object。")
    return obj


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
    pred_items: list[tuple[PIIAttributeType, str]],
) -> tuple[list[tuple[int, int]], set[int], set[int]]:
    pairs: list[tuple[int, int]] = []
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (attr, value) in enumerate(ground_truth):
        for ci, (c_attr, c_text) in enumerate(pred_items):
            if ci in cand_used:
                continue
            if c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                pairs.append((gi, ci))
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return pairs, cand_used, gt_hit


def _serialize_inventory_item(item: dict[str, Any], mapped_attr: PIIAttributeType | None) -> dict[str, Any]:
    return {
        "type": str(item.get("type") or "").strip().upper(),
        "value": str(item.get("value") or "").strip(),
        "mapped_attr_type": mapped_attr.value if mapped_attr else None,
    }


def _map_presidio_entity(entity_type: str) -> PIIAttributeType | None:
    et = str(entity_type or "").strip().upper()
    table: dict[str, PIIAttributeType] = {
        "PERSON": PIIAttributeType.NAME,
        "EMAIL_ADDRESS": PIIAttributeType.EMAIL,
        "PHONE_NUMBER": PIIAttributeType.PHONE,
        "CREDIT_CARD": PIIAttributeType.BANK_NUMBER,
        "US_BANK_NUMBER": PIIAttributeType.BANK_NUMBER,
        "IBAN_CODE": PIIAttributeType.BANK_NUMBER,
        "US_DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE,
        "US_PASSPORT": PIIAttributeType.PASSPORT_NUMBER,
        "LICENSE_PLATE": PIIAttributeType.LICENSE_PLATE,
        "LOCATION": PIIAttributeType.ADDRESS,
        "STREET_ADDRESS": PIIAttributeType.ADDRESS,
        "CITY": PIIAttributeType.ADDRESS,
        "STATE": PIIAttributeType.ADDRESS,
        "COUNTRY": PIIAttributeType.ADDRESS,
        "ZIP_CODE": PIIAttributeType.ADDRESS,
        "DATE_TIME": PIIAttributeType.TIME,
        "TIME": PIIAttributeType.TIME,
        "DATE": PIIAttributeType.TIME,
        "NRP": PIIAttributeType.ADDRESS,
        "ORGANIZATION": PIIAttributeType.ORGANIZATION,
        "ORG": PIIAttributeType.ORGANIZATION,
        "US_SSN": PIIAttributeType.ID_NUMBER,
        "US_ITIN": PIIAttributeType.ID_NUMBER,
        "MEDICAL_LICENSE": PIIAttributeType.ALNUM,
        "IP_ADDRESS": PIIAttributeType.ALNUM,
        "URL": PIIAttributeType.ALNUM,
        "CRYPTO": PIIAttributeType.ALNUM,
        "UK_NHS": PIIAttributeType.ID_NUMBER,
        "SG_NRIC_FIN": PIIAttributeType.ID_NUMBER,
        "AU_MEDICARE": PIIAttributeType.ID_NUMBER,
        "AU_PASSPORT": PIIAttributeType.PASSPORT_NUMBER,
        "AU_TFN": PIIAttributeType.ID_NUMBER,
        "AU_ABN": PIIAttributeType.ALNUM,
        "AU_ACN": PIIAttributeType.ALNUM,
        "FIN_NATIONAL_ID": PIIAttributeType.ID_NUMBER,
        "FI_PERSONAL_IDENTITY_CODE": PIIAttributeType.ID_NUMBER,
        "IN_PAN": PIIAttributeType.ID_NUMBER,
        "IN_AADHAAR": PIIAttributeType.ID_NUMBER,
        "IN_VEHICLE_REGISTRATION": PIIAttributeType.LICENSE_PLATE,
        "IN_VOTER": PIIAttributeType.ID_NUMBER,
        "IN_PASSPORT": PIIAttributeType.PASSPORT_NUMBER,
    }
    return table.get(et)


def _map_andlab_label(label: str) -> PIIAttributeType | None:
    u = str(label or "").strip().upper().replace(" ", "_")
    if not u:
        return None
    # 显式关键词优先
    if "CREDIT_CARD" in u or "BANK" in u or "ROUTING" in u or "ACCOUNT_NUMBER" in u:
        return PIIAttributeType.BANK_NUMBER
    if "EMAIL" in u:
        return PIIAttributeType.EMAIL
    if "PHONE" in u:
        return PIIAttributeType.PHONE
    if "DRIVER" in u:
        return PIIAttributeType.DRIVER_LICENSE
    if "PASSPORT" in u:
        return PIIAttributeType.PASSPORT_NUMBER
    if "LICENSE_PLATE" in u or u == "VEHICLE_ID":
        return PIIAttributeType.LICENSE_PLATE
    if "MONEY" in u:
        return PIIAttributeType.AMOUNT
    if "DOB" in u or "DATE" in u or u == "AGE":
        return PIIAttributeType.TIME
    if any(x in u for x in ("ADDRESS", "LOCATION", "ZIP", "STREET", "CITY", "STATE", "COUNTRY")):
        return PIIAttributeType.ADDRESS
    if "ORG" in u or "FACILITY" in u:
        return PIIAttributeType.ORGANIZATION
    if "NAME" in u or u == "PERSON" or "USERNAME" in u:
        return PIIAttributeType.NAME
    if "SSN" in u:
        return PIIAttributeType.ID_NUMBER
    if "IP_ADDRESS" in u or u == "URL" or "PASSWORD" in u:
        return PIIAttributeType.ALNUM
    if "CONDITION" in u or "DRUG" in u or "MEDICAL" in u or "INJURY" in u:
        return PIIAttributeType.ALNUM
    return None


def _privacy_protection_layer_class():  # type: ignore[no-untyped-def]
    if str(ANDLAB_ROOT) not in sys.path:
        sys.path.insert(0, str(ANDLAB_ROOT))
    from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore  # noqa: PLC0415

    return PrivacyProtectionLayer


def _ensure_presidio_path() -> None:
    if PRESIDIO_SRC.is_dir() and str(PRESIDIO_SRC) not in sys.path:
        sys.path.insert(0, str(PRESIDIO_SRC))


def _build_presidio_engine():  # type: ignore[no-untyped-def]
    _ensure_presidio_path()
    from presidio_analyzer import AnalyzerEngine  # type: ignore  # noqa: PLC0415

    return AnalyzerEngine()


def _run_presidio(engine: Any, text: str) -> list[tuple[PIIAttributeType, str, str]]:
    """返回 (映射后的属性, 文本, 原始 presidio entity_type)。"""
    rows: list[tuple[PIIAttributeType, str, str]] = []
    seen: set[tuple[int, int, str]] = set()
    for r in engine.analyze(text=text, language="en", score_threshold=0):
        span = (r.start, r.end, r.entity_type)
        if span in seen:
            continue
        seen.add(span)
        frag = text[r.start : r.end]
        mapped = _map_presidio_entity(r.entity_type)
        if mapped is None:
            continue
        rows.append((mapped, frag, r.entity_type))
    return rows


def _run_andlab(layer: Any, text: str) -> list[tuple[PIIAttributeType, str, str]]:
    """返回 (映射属性, 原文片段, AndLab 标签)。"""
    layer.clear_mappings()
    masked, _err = "", None
    try:
        masked, _ = layer.anonymize_prompt(text)
    except Exception as exc:  # noqa: BLE001
        return []
    out: list[tuple[PIIAttributeType, str, str]] = []
    for m in TOKEN_RE.finditer(masked):
        token = m.group(1)
        real_value = layer.token_to_real.get(token)
        if not real_value:
            continue
        label = layer.real_to_entity_type.get(real_value, "MISC")
        mapped = _map_andlab_label(str(label))
        if mapped is None:
            continue
        out.append((mapped, real_value, str(label)))
    return out


def _aggregate_metrics(
    *,
    name: str,
    comparison_rows: list[dict[str, Any]],
    gt_total: int,
) -> dict[str, Any]:
    tp = sum(r["stats"][name]["tp"] for r in comparison_rows)
    fn = sum(r["stats"][name]["fn"] for r in comparison_rows)
    fp = sum(r["stats"][name]["fp"] for r in comparison_rows)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / gt_total if gt_total else 0.0
    return {
        "label": name,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "precision": prec,
        "recall": rec,
        "f1": (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="EN structured：PG / AndLab / Presidio 三通道对比")
    ap.add_argument(
        "input_json",
        type=Path,
        nargs="?",
        default=Path("data/dataset/privacy_eval_realistic_1200_en_release_structured.json"),
        help="structured JSON 路径",
    )
    ap.add_argument("--max-samples", type=int, default=None, help="仅评测前 N 条（调试用）")
    ap.add_argument(
        "--clean-txt",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_en_1200_full_clean_per_sample.txt"),
    )
    ap.add_argument(
        "--converted-json",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_en_1200_full_clean_samples.json"),
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_en_1200_triple_compare.json"),
    )
    ap.add_argument(
        "--entities-jsonl",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_en_1200_all_detected_entities.jsonl"),
    )
    args = ap.parse_args()

    t0 = time.perf_counter()
    src = _load_structured(args.input_json)
    raw_samples = src.get("samples")
    if not isinstance(raw_samples, list):
        raise ValueError("缺少 samples 数组。")
    if args.max_samples is not None:
        raw_samples = raw_samples[: max(0, args.max_samples)]

    converted: list[dict[str, Any]] = []
    txt_lines: list[str] = []
    for row in raw_samples:
        twt = str(row.get("text_with_tags") or "")
        clean = _strip_all_pii_tags(twt)
        sid = str(row.get("sample_id") or "")
        converted.append(
            {
                "sample_id": sid,
                "category": row.get("category", "unknown"),
                "scene": row.get("scene", ""),
                "text_with_tags": twt,
                "clean_text": clean,
                "pii_inventory": row.get("pii_inventory", []),
            }
        )
        txt_lines.append(f"<<<SAMPLE {sid}>>>")
        txt_lines.append(clean)
        txt_lines.append("<<<END>>>")
        txt_lines.append("")

    args.clean_txt.parent.mkdir(parents=True, exist_ok=True)
    args.clean_txt.write_text("\n".join(txt_lines), encoding="utf-8")
    args.converted_json.write_text(json.dumps(converted, ensure_ascii=False, indent=2), encoding="utf-8")

    detector = RuleBasedPIIDetector(locale_profile="en_us")
    protection_level = ProtectionLevel.STRONG

    andlab_layer = None
    andlab_load_error: str | None = None
    if ANDLAB_ROOT.is_dir():
        try:
            layer_cls = _privacy_protection_layer_class()
            andlab_layer = layer_cls(enabled=True)
        except Exception as exc:  # noqa: BLE001
            andlab_load_error = f"{type(exc).__name__}: {exc}"
    else:
        andlab_load_error = f"路径不存在：{ANDLAB_ROOT}"

    presidio_engine = None
    presidio_load_error: str | None = None
    try:
        presidio_engine = _build_presidio_engine()
    except Exception as exc:  # noqa: BLE001
        presidio_load_error = f"{type(exc).__name__}: {exc}"

    comparison_rows: list[dict[str, Any]] = []
    label_unmapped = Counter()
    gt_total = 0
    inventory_rows_total = 0

    args.entities_jsonl.parent.mkdir(parents=True, exist_ok=True)
    ej = args.entities_jsonl.open("w", encoding="utf-8")

    time_pg = 0.0
    time_andlab = 0.0
    time_presidio = 0.0

    for row in converted:
        sid = str(row.get("sample_id") or "")
        clean = str(row.get("clean_text") or "")
        gt_local: list[tuple[PIIAttributeType, str]] = []
        gt_serializable: list[dict[str, Any]] = []
        unmapped_gt: list[dict[str, Any]] = []
        for item in row.get("pii_inventory") or []:
            inventory_rows_total += 1
            label = str(item.get("type") or "").strip().upper()
            mapped = _coerce_attr_type(EVAL_LABEL_TO_ATTR.get(label))
            serialized_item = _serialize_inventory_item(item, mapped)
            if mapped is None:
                label_unmapped[label] += 1
                unmapped_gt.append(serialized_item)
                continue
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            gt_local.append((mapped, val))
            gt_serializable.append(serialized_item)
            gt_total += 1

        t1 = time.perf_counter()
        raw_cands = detector.detect(
            clean,
            [],
            session_id=None,
            turn_id=None,
            protection_level=protection_level,
            detector_overrides=None,
        )
        time_pg += time.perf_counter() - t1
        pg_items: list[tuple[PIIAttributeType, str]] = []
        pg_detail: list[dict[str, Any]] = []
        for c in raw_cands:
            if c.source != PIISourceType.PROMPT:
                continue
            mapped_attr = _coerce_attr_type(c.attr_type)
            if mapped_attr is None:
                continue
            pg_items.append((mapped_attr, c.text))
            pg_detail.append(
                {"engine": "privacyguard", "attr_type": mapped_attr.value, "text": c.text, "source": c.source.value}
            )
            ej.write(
                json.dumps(
                    {"sample_id": sid, "engine": "privacyguard", "attr_type": mapped_attr.value, "text": c.text},
                    ensure_ascii=False,
                )
                + "\n"
            )

        t2 = time.perf_counter()
        andlab_items: list[tuple[PIIAttributeType, str]] = []
        andlab_detail: list[dict[str, Any]] = []
        if andlab_layer is not None:
            for mapped, frag, raw_label in _run_andlab(andlab_layer, clean):
                normalized_attr = _coerce_attr_type(mapped)
                if normalized_attr is None:
                    continue
                andlab_items.append((normalized_attr, frag))
                andlab_detail.append(
                    {"engine": "andlab", "attr_type": normalized_attr.value, "text": frag, "raw_label": raw_label}
                )
                ej.write(
                    json.dumps(
                        {"sample_id": sid, "engine": "andlab", "attr_type": normalized_attr.value, "text": frag, "raw_label": raw_label},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        time_andlab += time.perf_counter() - t2

        t3 = time.perf_counter()
        presidio_items: list[tuple[PIIAttributeType, str]] = []
        presidio_detail: list[dict[str, Any]] = []
        if presidio_engine is not None:
            for mapped, frag, raw_et in _run_presidio(presidio_engine, clean):
                normalized_attr = _coerce_attr_type(mapped)
                if normalized_attr is None:
                    continue
                presidio_items.append((normalized_attr, frag))
                presidio_detail.append(
                    {"engine": "presidio", "attr_type": normalized_attr.value, "text": frag, "entity_type": raw_et}
                )
                ej.write(
                    json.dumps(
                        {"sample_id": sid, "engine": "presidio", "attr_type": normalized_attr.value, "text": frag, "entity_type": raw_et},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        time_presidio += time.perf_counter() - t3

        def _one_channel(items: list[tuple[PIIAttributeType, str]]) -> dict[str, Any]:
            pairs, cand_used, gt_hit = _greedy_match(gt_local, items)
            tp = len(gt_hit)
            fn = len(gt_local) - tp
            fp = len(items) - len(cand_used)
            matched = [{"gt_index": gi, "pred_index": ci} for gi, ci in pairs]
            return {
                "tp": tp,
                "fn": fn,
                "fp": fp,
                "matched_index_pairs": matched,
                "predictions": items,
            }

        st_pg = _one_channel(pg_items)
        st_al = _one_channel(andlab_items)
        st_pr = _one_channel(presidio_items)

        comparison_rows.append(
            {
                "sample_id": sid,
                "scene": row.get("scene", ""),
                "clean_text": clean,
                "ground_truth_entities": gt_serializable,
                "unmapped_ground_truth_entities": unmapped_gt,
                "privacyguard_prompt": pg_detail,
                "andlab": andlab_detail,
                "presidio": presidio_detail,
                "stats": {
                    "privacyguard": {"tp": st_pg["tp"], "fn": st_pg["fn"], "fp": st_pg["fp"]},
                    "andlab": {"tp": st_al["tp"], "fn": st_al["fn"], "fp": st_al["fp"]},
                    "presidio": {"tp": st_pr["tp"], "fn": st_pr["fn"], "fp": st_pr["fp"]},
                },
            }
        )

    ej.close()

    per_attr: dict[str, dict[str, dict[str, float | int]]] = {
        "privacyguard": defaultdict(lambda: defaultdict(int)),
        "andlab": defaultdict(lambda: defaultdict(int)),
        "presidio": defaultdict(lambda: defaultdict(int)),
    }

    for row in comparison_rows:
        sid = row["sample_id"]
        # 按引擎重算 per-attr（从 matched 不易拆，直接扫 predictions vs gt 简化：用样本内贪心结果需要存 false_negatives — 为省空间在第二遍按样本重跑匹配）
        inv = next((c for c in converted if c["sample_id"] == sid), None)
        if not inv:
            continue
        gt_local = []
        for item in inv.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            mapped = _coerce_attr_type(EVAL_LABEL_TO_ATTR.get(label))
            if mapped is None:
                continue
            val = str(item.get("value") or "").strip()
            if val:
                gt_local.append((mapped, val))

        def _accum(engine: str, items: list[tuple[PIIAttributeType, str]]) -> None:
            pairs, cand_used, gt_hit = _greedy_match(gt_local, items)
            for gi, _ci in pairs:
                ak = gt_local[gi][0].value
                per_attr[engine][ak]["tp"] += 1
            for gi, _ in enumerate(gt_local):
                if gi not in {p[0] for p in pairs}:
                    per_attr[engine][gt_local[gi][0].value]["fn"] += 1
            for ci, _ in enumerate(items):
                if ci not in {p[1] for p in pairs}:
                    per_attr[engine][items[ci][0].value]["fp"] += 1

        pg_items = [(PIIAttributeType(x["attr_type"]), x["text"]) for x in row["privacyguard_prompt"]]
        al_items = [(PIIAttributeType(x["attr_type"]), x["text"]) for x in row["andlab"]]
        pr_items = [(PIIAttributeType(x["attr_type"]), x["text"]) for x in row["presidio"]]
        _accum("privacyguard", pg_items)
        _accum("andlab", al_items)
        _accum("presidio", pr_items)

    def _finalize_per_attr(d: defaultdict) -> dict[str, Any]:
        out = {}
        for k, v in sorted(d.items()):
            tp, fn, fp = int(v["tp"]), int(v["fn"]), int(v["fp"])
            out[k] = {
                "tp": tp,
                "fn": fn,
                "fp": fp,
                "recall": tp / (tp + fn) if (tp + fn) else 0.0,
                "precision": tp / (tp + fp) if (tp + fp) else 0.0,
            }
        return out

    metrics = {
        "privacyguard": _aggregate_metrics(name="privacyguard", comparison_rows=comparison_rows, gt_total=gt_total),
        "andlab": _aggregate_metrics(name="andlab", comparison_rows=comparison_rows, gt_total=gt_total),
        "presidio": _aggregate_metrics(name="presidio", comparison_rows=comparison_rows, gt_total=gt_total),
    }

    major = metrics["privacyguard"]["recall"], metrics["andlab"]["recall"], metrics["presidio"]["recall"]
    analysis_zh = [
        f"样本数 {len(converted)}；可对齐 GT 实体 {gt_total} 条（inventory 总行 {inventory_rows_total}）。",
        f"PrivacyGuard（prompt）：R={metrics['privacyguard']['recall']:.4f} P={metrics['privacyguard']['precision']:.4f}，累计检测耗时约 {time_pg:.1f}s。",
        f"AndLab（GLiNER+regex）：R={metrics['andlab']['recall']:.4f} P={metrics['andlab']['precision']:.4f}，累计耗时约 {time_andlab:.1f}s。"
        + (f" 加载异常：{andlab_load_error}" if andlab_load_error and andlab_layer is None else ""),
        f"Presidio（全实体，映射到 PG 类型空间）：R={metrics['presidio']['recall']:.4f} P={metrics['presidio']['precision']:.4f}，累计耗时约 {time_presidio:.1f}s。"
        + (f" 加载异常：{presidio_load_error}" if presidio_load_error and presidio_engine is None else ""),
        "说明：ORDER_ID/TRACKING_ID/MEMBER_ID/ACCOUNT_ID 在 GT 侧映射为 ALNUM；BIRTHDAY 映射为 TIME；"
        "AndLab/Presidio 的原始标签映射到 PrivacyGuard 的 PIIAttributeType 后再做同类型微对齐；"
        "未映射的预测不计入 TP/FP（Presidio 中已过滤）。",
    ]

    out_obj: dict[str, Any] = {
        "inputs": [str(args.input_json.resolve())],
        "clean_txt_path": str(args.clean_txt.resolve()),
        "converted_json_path": str(args.converted_json.resolve()),
        "entities_jsonl_path": str(args.entities_jsonl.resolve()),
        "sample_count": len(converted),
        "timings_seconds": {
            "privacyguard_detect_sum": round(time_pg, 4),
            "andlab_sum": round(time_andlab, 4),
            "presidio_sum": round(time_presidio, 4),
            "wall_total": round(time.perf_counter() - t0, 4),
        },
        "andlab_available": andlab_layer is not None,
        "andlab_load_error": andlab_load_error,
        "presidio_available": presidio_engine is not None,
        "presidio_load_error": presidio_load_error,
        "presidio_source_path": str(PRESIDIO_SRC.resolve()) if PRESIDIO_SRC.is_dir() else None,
        "ground_truth": {
            "inventory_rows_total": inventory_rows_total,
            "mapped_entity_count": gt_total,
            "unmapped_inventory_labels": dict(label_unmapped.most_common()),
            "eval_label_to_attr": {k: v.value for k, v in EVAL_LABEL_TO_ATTR.items()},
        },
        "micro_match_greedy_global": metrics,
        "per_attr": {
            "privacyguard": _finalize_per_attr(per_attr["privacyguard"]),
            "andlab": _finalize_per_attr(per_attr["andlab"]),
            "presidio": _finalize_per_attr(per_attr["presidio"]),
        },
        "analysis_zh": analysis_zh,
        "per_sample": comparison_rows,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    # 简短控制台摘要
    print("\n".join(analysis_zh))


if __name__ == "__main__":
    main()
