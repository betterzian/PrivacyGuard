"""逐条 clean_text 评测 detector prompt 路径与 AndLab gliner+regex。"""

from __future__ import annotations

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
INPUT_JSON = ROOT / "data" / "privacy_eval_realistic_1200_en_release_structured.json"
OUT_DIR = ROOT / "outputs" / "analysis"
OUT_JSON = OUT_DIR / "privacy_eval_realistic_1200_en_release_per_sample_detector_andlab_compare.json"
OUT_TXT = OUT_DIR / "privacy_eval_realistic_1200_en_release_clean_texts_per_sample.txt"

ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"
sys.path.insert(0, str(ANDLAB_ROOT))

from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore  # noqa: E402

TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")

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

ANDLAB_LABEL_TO_ATTR: dict[str, str] = {
    "NAME": PIIAttributeType.NAME.value,
    "FIRST_NAME": PIIAttributeType.NAME.value,
    "LAST_NAME": PIIAttributeType.NAME.value,
    "PERSON_NAME": PIIAttributeType.NAME.value,
    "PHONE_NUMBER": PIIAttributeType.PHONE.value,
    "EMAIL": PIIAttributeType.EMAIL.value,
    "EMAIL_ADDRESS": PIIAttributeType.EMAIL.value,
    "ORGANIZATION": PIIAttributeType.ORGANIZATION.value,
    "COMPANY": PIIAttributeType.ORGANIZATION.value,
    "DRIVER_LICENSE": PIIAttributeType.DRIVER_LICENSE.value,
    "CREDIT_CARD": PIIAttributeType.BANK_NUMBER.value,
    "BANK_ACCOUNT": PIIAttributeType.BANK_NUMBER.value,
    "ACCOUNT_NUMBER": PIIAttributeType.BANK_NUMBER.value,
    "ROUTING_NUMBER": PIIAttributeType.BANK_NUMBER.value,
    "ADDRESS": PIIAttributeType.ADDRESS.value,
    "LOCATION": PIIAttributeType.ADDRESS.value,
    "LOCATION_CITY": PIIAttributeType.ADDRESS.value,
    "LOCATION_STATE": PIIAttributeType.ADDRESS.value,
    "LOCATION_COUNTRY": PIIAttributeType.ADDRESS.value,
    "LOCATION_STREET_ADDRESS": PIIAttributeType.ADDRESS.value,
    "LOCATION_ZIP_CODE": PIIAttributeType.ADDRESS.value,
}


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
        _ = sid
        for ci, (_csid, c_attr, c_text) in enumerate(candidates):
            if ci in cand_used or c_attr != attr:
                continue
            if _micro_match(attr, value, c_text):
                cand_used.add(ci)
                gt_hit.add(gi)
                break
    return cand_used, gt_hit


def main() -> None:
    t0 = time.perf_counter()
    raw = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    samples = raw.get("samples") or []
    if not isinstance(samples, list):
        raise ValueError("输入 JSON 缺少 samples。")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    detector = RuleBasedPIIDetector(locale_profile="mixed")
    andlab = PrivacyProtectionLayer(enabled=True)

    clean_texts: list[str] = []
    ground_truth: list[tuple[str, str, str]] = []
    gt_by_attr: Counter[str] = Counter()
    gt_unmapped: Counter[str] = Counter()
    detector_entities: list[dict[str, Any]] = []
    andlab_entities: list[dict[str, Any]] = []
    detector_for_eval: list[tuple[str, str, str]] = []
    andlab_for_eval: list[tuple[str, str, str]] = []
    detector_attr_counter: Counter[str] = Counter()
    andlab_label_counter: Counter[str] = Counter()
    andlab_attr_counter: Counter[str] = Counter()

    for row in samples:
        sample_id = str(row.get("sample_id") or "")
        clean_text = _clean_text_with_tags(str(row.get("text_with_tags") or ""))
        clean_texts.append(clean_text)

        for item in row.get("pii_inventory") or []:
            label = str(item.get("type") or "").strip().upper()
            value = str(item.get("value") or "").strip()
            mapped_attr = EVAL_LABEL_TO_ATTR.get(label)
            if not mapped_attr:
                gt_unmapped[label] += 1
                continue
            if not value:
                continue
            ground_truth.append((sample_id, mapped_attr, value))
            gt_by_attr[mapped_attr] += 1

        # detector: prompt 路径（不传 OCR）
        det_items = detector.detect(
            clean_text,
            [],
            session_id=None,
            turn_id=None,
            protection_level=ProtectionLevel.STRONG,
            detector_overrides=None,
        )
        for c in det_items:
            if c.source != PIISourceType.PROMPT:
                continue
            attr = c.attr_type.value
            detector_attr_counter[attr] += 1
            detector_for_eval.append((sample_id, attr, c.text))
            detector_entities.append(
                {
                    "sample_id": sample_id,
                    "attr": attr,
                    "text": c.text,
                    "normalized_text": c.normalized_text,
                    "span_start": c.span_start,
                    "span_end": c.span_end,
                    "confidence": c.confidence,
                }
            )

        # AndLab: gliner + regex（anonymize_prompt）
        andlab.clear_mappings()
        masked_text, _new_tokens = andlab.anonymize_prompt(clean_text)
        for match in TOKEN_RE.finditer(masked_text):
            token = match.group(1)
            real_value = andlab.token_to_real.get(token)
            if not real_value:
                continue
            raw_label = andlab.real_to_entity_type.get(real_value, "MISC")
            andlab_label_counter[raw_label] += 1
            andlab_entities.append(
                {
                    "sample_id": sample_id,
                    "token": token,
                    "raw_label": raw_label,
                    "text": real_value,
                    "start": match.start(),
                    "end": match.end(),
                }
            )
            mapped_attr = ANDLAB_LABEL_TO_ATTR.get(raw_label)
            if mapped_attr:
                andlab_for_eval.append((sample_id, mapped_attr, real_value))
                andlab_attr_counter[mapped_attr] += 1

    OUT_TXT.write_text("\n\n".join(clean_texts), encoding="utf-8")

    det_used, det_hit = _greedy_match(ground_truth, detector_for_eval)
    and_used, and_hit = _greedy_match(ground_truth, andlab_for_eval)

    def _metrics(hit: set[int], used: set[int], candidates: list[tuple[str, str, str]]) -> dict[str, Any]:
        tp = len(hit)
        fn = len(ground_truth) - tp
        fp = len(candidates) - len(used)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / len(ground_truth) if ground_truth else 0.0
        return {"tp": tp, "fn": fn, "fp": fp, "precision": precision, "recall": recall}

    out = {
        "input_json": str(INPUT_JSON.resolve()),
        "sample_count": len(samples),
        "clean_text_count": len(clean_texts),
        "output_files": {"clean_texts_txt": str(OUT_TXT.resolve())},
        "ground_truth": {
            "mapped_total": len(ground_truth),
            "mapped_by_attr": dict(sorted(gt_by_attr.items())),
            "unmapped_inventory_labels_top": dict(gt_unmapped.most_common(20)),
        },
        "detector_prompt_path": {
            "candidate_total": len(detector_for_eval),
            "candidate_by_attr": dict(sorted(detector_attr_counter.items())),
            "metrics_vs_ground_truth": _metrics(det_hit, det_used, detector_for_eval),
            "all_entities": detector_entities,
        },
        "andlab_gliner_regex_path": {
            "candidate_total": len(andlab_entities),
            "candidate_by_label": dict(sorted(andlab_label_counter.items())),
            "mapped_candidate_total_for_eval": len(andlab_for_eval),
            "mapped_candidate_by_attr": dict(sorted(andlab_attr_counter.items())),
            "metrics_vs_ground_truth": _metrics(and_hit, and_used, andlab_for_eval),
            "all_entities": andlab_entities,
        },
        "analysis_zh": [
            "clean_text 由 text_with_tags 去除标签壳得到，按样本逐条输入 detector 和 AndLab。",
            "detector 仅走 prompt 路径（OCR 传空列表），AndLab 仅走 anonymize_prompt（GLiNER+regex，不使用 openocr）。",
            "GT 与候选比较采用贪心一对一匹配：地址做互为子串，其余类型用 normalize_pii + same_entity。",
        ],
        "timings": {"total_seconds": round(time.perf_counter() - t0, 4)},
    }
    OUT_JSON.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT_TXT)
    print(OUT_JSON)


if __name__ == "__main__":
    main()
