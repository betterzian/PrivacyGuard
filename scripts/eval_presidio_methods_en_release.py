"""对比 Presidio 不同检测方式在 EN release 集上的效果与耗时。"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PRESIDIO_ANALYZER_ROOT = ROOT / "tmp" / "presidio-main" / "presidio-analyzer"
sys.path.insert(0, str(PRESIDIO_ANALYZER_ROOT))

from presidio_analyzer import AnalyzerEngine  # type: ignore  # noqa: E402
from presidio_analyzer.predefined_recognizers import GLiNERRecognizer  # type: ignore  # noqa: E402

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity

INPUT_JSON = ROOT / "data" / "privacy_eval_realistic_1200_en_release_structured.json"
OUT_JSON = ROOT / "outputs" / "analysis" / "privacy_eval_realistic_1200_en_release_presidio_methods_compare.json"

TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")

EVAL_LABEL_TO_ATTR: dict[str, str] = {
    "ADDRESS": PIIAttributeType.ADDRESS.value,
    "NAME": PIIAttributeType.NAME.value,
    "PHONE": PIIAttributeType.PHONE.value,
    "EMAIL": PIIAttributeType.EMAIL.value,
    "ID_CARD": PIIAttributeType.ID_NUMBER.value,
    "BANK_CARD": PIIAttributeType.BANK_NUMBER.value,
    "ORG": PIIAttributeType.ORGANIZATION.value,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE.value,
}

PRESIDIO_LABEL_TO_ATTR: dict[str, str] = {
    "PERSON": PIIAttributeType.NAME.value,
    "PHONE_NUMBER": PIIAttributeType.PHONE.value,
    "EMAIL_ADDRESS": PIIAttributeType.EMAIL.value,
    "US_DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE.value,
    "US_BANK_NUMBER": PIIAttributeType.BANK_NUMBER.value,
    "CREDIT_CARD": PIIAttributeType.BANK_NUMBER.value,
    "IBAN_CODE": PIIAttributeType.BANK_NUMBER.value,
    "LOCATION": PIIAttributeType.ADDRESS.value,
    "US_PASSPORT": PIIAttributeType.ID_NUMBER.value,
    "US_SSN": PIIAttributeType.ID_NUMBER.value,
}

RULE_ONLY_ENTITIES = [
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_PASSPORT",
    "US_SSN",
    "LOCATION",
]


def _clean_text_with_tags(text: str) -> str:
    cleaned = TAG_OPEN_RE.sub("", str(text or ""))
    return TAG_CLOSE_RE.sub("", cleaned)


def _micro_match(attr: str, gt_value: str, cand_text: str) -> bool:
    g = str(gt_value or "").strip()
    c = str(cand_text or "").strip()
    if not g or not c:
        return False
    if attr == PIIAttributeType.ADDRESS.value:
        return g in c or c in g
    attr_enum = PIIAttributeType(attr)
    return same_entity(normalize_pii(attr_enum, g), normalize_pii(attr_enum, c))


def _greedy_match(
    ground_truth: list[tuple[str, str, str]],
    candidates: list[tuple[str, str, str]],
) -> tuple[set[int], set[int]]:
    cand_used: set[int] = set()
    gt_hit: set[int] = set()
    for gi, (sid, attr, value) in enumerate(ground_truth):
        for ci, (csid, c_attr, c_text) in enumerate(candidates):
            if ci in cand_used:
                continue
            if csid != sid or c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return cand_used, gt_hit


def _metrics(
    ground_truth: list[tuple[str, str, str]],
    candidates: list[tuple[str, str, str]],
    hit: set[int],
    used: set[int],
) -> dict[str, float | int]:
    tp = len(hit)
    fn = len(ground_truth) - tp
    fp = len(candidates) - len(used)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(ground_truth) if ground_truth else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "precision": precision, "recall": recall}


def _timing(seconds: float, sample_count: int) -> dict[str, float]:
    return {
        "seconds_total": round(seconds, 4),
        "avg_ms_per_sample": round((seconds / sample_count) * 1000.0 if sample_count else 0.0, 4),
        "samples_per_second": round(sample_count / seconds if seconds > 0 else 0.0, 4),
    }


def _build_default_engine() -> AnalyzerEngine:
    return AnalyzerEngine()


def _build_rule_only_engine() -> AnalyzerEngine:
    # 仍使用 AnalyzerEngine，但实体范围限制在规则类实体，避免 PERSON 等 NER 标签干扰。
    return AnalyzerEngine()


def _build_gliner_engine() -> AnalyzerEngine:
    engine = AnalyzerEngine()
    mapping = {
        "person": "PERSON",
        "name": "PERSON",
        "organization": "ORGANIZATION",
        "phone number": "PHONE_NUMBER",
        "mobile phone number": "PHONE_NUMBER",
        "email": "EMAIL_ADDRESS",
        "email address": "EMAIL_ADDRESS",
        "address": "LOCATION",
        "location": "LOCATION",
        "driver's license number": "US_DRIVER_LICENSE",
        "bank account number": "US_BANK_NUMBER",
        "credit card number": "CREDIT_CARD",
        "passport number": "US_PASSPORT",
        "social security number": "US_SSN",
    }
    gliner = GLiNERRecognizer(
        model_name="urchade/gliner_multi_pii-v1",
        entity_mapping=mapping,
        map_location="cpu",
        threshold=0.3,
        flat_ner=True,
        multi_label=False,
    )
    engine.registry.add_recognizer(gliner)
    engine.registry.remove_recognizer("SpacyRecognizer")
    return engine


def main() -> None:
    t0 = time.perf_counter()
    src = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    samples = src.get("samples") or []
    if not isinstance(samples, list):
        raise ValueError("输入 JSON 缺少 samples。")

    clean_samples: list[dict[str, str]] = []
    ground_truth: list[tuple[str, str, str]] = []
    gt_by_attr: Counter[str] = Counter()

    for row in samples:
        sid = str(row.get("sample_id") or "")
        clean_text = _clean_text_with_tags(str(row.get("text_with_tags") or ""))
        clean_samples.append({"sample_id": sid, "clean_text": clean_text})
        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            value = str(item.get("value") or "").strip()
            attr = EVAL_LABEL_TO_ATTR.get(label)
            if attr and value:
                ground_truth.append((sid, attr, value))
                gt_by_attr[attr] += 1

    modes: list[tuple[str, AnalyzerEngine, list[str] | None]] = [
        ("default_rules_spacy", _build_default_engine(), None),
        ("rule_only_entities", _build_rule_only_engine(), RULE_ONLY_ENTITIES),
        ("rules_plus_gliner", _build_gliner_engine(), None),
    ]

    results: dict[str, Any] = {}

    for mode_name, engine, entities in modes:
        mode_t0 = time.perf_counter()
        all_entities: list[dict[str, Any]] = []
        mapped_candidates: list[tuple[str, str, str]] = []
        label_counter: Counter[str] = Counter()
        attr_counter: Counter[str] = Counter()

        for row in clean_samples:
            sid = row["sample_id"]
            text = row["clean_text"]
            kwargs: dict[str, Any] = {"text": text, "language": "en"}
            if entities is not None:
                kwargs["entities"] = entities
            pres_results = engine.analyze(**kwargs)
            for pr in pres_results:
                raw_label = str(pr.entity_type)
                span_text = text[int(pr.start) : int(pr.end)]
                label_counter[raw_label] += 1
                all_entities.append(
                    {
                        "sample_id": sid,
                        "raw_label": raw_label,
                        "text": span_text,
                        "start": int(pr.start),
                        "end": int(pr.end),
                        "score": float(pr.score),
                    }
                )
                mapped = PRESIDIO_LABEL_TO_ATTR.get(raw_label)
                if mapped:
                    mapped_candidates.append((sid, mapped, span_text))
                    attr_counter[mapped] += 1

        used, hit = _greedy_match(ground_truth, mapped_candidates)
        elapsed = time.perf_counter() - mode_t0
        results[mode_name] = {
            "candidate_total": len(all_entities),
            "candidate_by_label": dict(sorted(label_counter.items())),
            "mapped_candidate_total_for_eval": len(mapped_candidates),
            "mapped_candidate_by_attr": dict(sorted(attr_counter.items())),
            "metrics_vs_ground_truth": _metrics(ground_truth, mapped_candidates, hit, used),
            "runtime": _timing(elapsed, len(clean_samples)),
            "all_entities": all_entities,
        }

    out = {
        "input_json": str(INPUT_JSON.resolve()),
        "sample_count": len(clean_samples),
        "ground_truth_mapped_total": len(ground_truth),
        "ground_truth_mapped_by_attr": dict(sorted(gt_by_attr.items())),
        "presidio_modes": results,
        "analysis_zh": [
            "default_rules_spacy=Presidio 默认 AnalyzerEngine（规则+spaCy NER）。",
            "rule_only_entities=仅请求规则类实体集合（PHONE/EMAIL/证件/卡号/LOCATION）。",
            "rules_plus_gliner=默认规则 + GLiNERRecognizer，并移除 SpacyRecognizer。",
            "指标口径与前序脚本一致：同样本+同属性贪心一对一；地址互含，其余 normalize_pii + same_entity。",
        ],
        "timings": {"end_to_end_total_seconds": round(time.perf_counter() - t0, 4)},
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT_JSON)


if __name__ == "__main__":
    main()
