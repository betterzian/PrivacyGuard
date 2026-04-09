"""评测 AndLab_protected 文本 PII 检测能力。

口径尽量对齐上一轮 persona detector 评测：
1. 使用 `people_cn.json` / `people_us.json`。
2. 移除所有 key 中包含 `label` 的字段，并跳过部分元字段。
3. 生成两种输入：
   - `prompt_space`：所有标量值空格拼接。
   - `ocr_break`：所有标量值按行拼接，模拟 OCR block。
4. 额外对地址做两组测试：
   - baseline：直接检测 `ecommerce_full`。
   - variant：从地址组件中随机抽取部分，再拼接同一人的其他 PII。

说明：
- AndLab_protected 的文本入口是 `PrivacyProtectionLayer.anonymize_prompt`
  与 `PrivacyProtectionLayer.identify_and_mask_text`。
- 该实现内部先跑 GLiNER；只有完全无结果时才退回 regex。
- “同地址”这里分成两层：
  1. `exact_full_address`：是否直接识别出完整地址。
  2. `same_token_reuse`：先注册完整地址，再检测变体时是否复用了同一地址 token。
     这更接近 AndLab 自己的同实体复用机制。
"""

from __future__ import annotations

import csv
import json
import random
import re
import sys
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"
sys.path.insert(0, str(ANDLAB_ROOT))

from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore  # noqa: E402


SEED = 20260409
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")
SKIP_EXACT_KEYS = {"alias_type", "template_name", "version", "person_id"}
SKIP_KEY_SUBSTRINGS = ("label",)
CORE_NAME_LABELS = {
    "NAME",
    "FIRST_NAME",
    "LAST_NAME",
    "NAME_MEDICAL_PROFESSIONAL",
    "PERSON_NAME",
}
CORE_PHONE_LABELS = {"PHONE_NUMBER"}
CORE_EMAIL_LABELS = {"EMAIL", "EMAIL_ADDRESS"}
CORE_ORG_LABELS = {"ORGANIZATION_MEDICAL_FACILITY"}
CORE_NUMERIC_LABELS = {
    "ACCOUNT_NUMBER",
    "BANK_ACCOUNT",
    "ROUTING_NUMBER",
    "CREDIT_CARD",
    "CREDIT_CARD_EXPIRATION",
    "CVV",
    "SSN",
    "PASSPORT_NUMBER",
    "DRIVER_LICENSE",
    "HEALTHCARE_NUMBER",
    "MEDICAL_CODE",
    "VEHICLE_ID",
    "DOB",
}


def _norm(text: str) -> str:
    """做宽松归一化，便于跨空格和标点比较。"""
    return "".join(ch.lower() for ch in text if ch.isalnum())


def _string_hit(expected: str, candidates: Iterable[str]) -> bool:
    """判断候选里是否包含目标值。"""
    expected_norm = _norm(expected)
    if not expected_norm:
        return False
    for candidate in candidates:
        candidate_norm = _norm(candidate)
        if not candidate_norm:
            continue
        if expected_norm in candidate_norm or candidate_norm in expected_norm:
            return True
    return False


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and not isinstance(value, bool)


def _iter_scalar_leaves(obj: Any) -> Iterable[str]:
    """按原始 JSON 顺序提取标量叶子。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key in SKIP_EXACT_KEYS or any(part in key_lower for part in SKIP_KEY_SUBSTRINGS):
                continue
            yield from _iter_scalar_leaves(value)
        return
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_scalar_leaves(item)
        return
    if _is_scalar(obj):
        text = str(obj).strip()
        if text:
            yield text


def _extract_primary_fields(person: dict[str, Any], locale: str) -> dict[str, Any]:
    if locale == "cn":
        return {
            "name": person["identity"]["name_zh"],
            "phone": person["contact"]["phone_main"],
            "email": person["contact"]["email_personal"],
            "organization": person["employment"]["company_name_zh"],
        }
    return {
        "name": person["identity"]["full_name"],
        "phone": person["contact"]["phone_main"],
        "email": person["contact"]["email_personal"],
        "organization": person["employment"]["company_name"],
    }


def _extract_numeric_pool(person: dict[str, Any]) -> list[str]:
    """提取主要证件/卡号类数字池，不把日期、门牌和手机号混进去。"""
    values: list[str] = []
    include_markers = {
        "card_number",
        "license_number",
        "id_card",
        "passport_number",
        "account_number",
        "routing_number",
        "ssn",
        "cvv",
    }

    def walk(obj: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = str(key).lower()
                if any(part in key_lower for part in SKIP_KEY_SUBSTRINGS):
                    continue
                walk(value, path + (str(key),))
            return
        if isinstance(obj, list):
            for item in obj:
                walk(item, path)
            return
        if not _is_scalar(obj):
            return

        text = str(obj).strip()
        if not text:
            return
        key_path = ".".join(path).lower()
        digit_count = sum(ch.isdigit() for ch in text)
        if digit_count < 6:
            return
        if "phone" in key_path or "postal" in key_path or "zip" in key_path:
            return
        if "street_number" in key_path:
            return
        if "date" in key_path or "birth_year" in key_path or key_path.endswith(".class"):
            return

        leaf_key = path[-1].lower() if path else ""
        if leaf_key in include_markers or key_path.endswith(".number"):
            values.append(text)

    walk(person)
    return values


@dataclass
class RunResult:
    masked_text: str
    occurrences: list[dict[str, Any]]
    unique_entities: list[dict[str, Any]]
    error: str | None = None


class AndLabEvaluator:
    """复用一个 GLiNER 模型实例，逐案清空 token 映射。"""

    def __init__(self) -> None:
        self.layer = PrivacyProtectionLayer(enabled=True)

    def _run(self, text: str, mode: str, *, clear: bool = True) -> RunResult:
        if clear:
            self.layer.clear_mappings()
        try:
            if mode == "prompt_space":
                masked_text, _ = self.layer.anonymize_prompt(text)
            elif mode == "ocr_break":
                masked_text, _ = self.layer.identify_and_mask_text(text, is_xml=False)
            else:
                raise ValueError(f"unknown mode: {mode}")
        except Exception:
            return RunResult(
                masked_text="",
                occurrences=[],
                unique_entities=[],
                error=traceback.format_exc(),
            )

        occurrences: list[dict[str, Any]] = []
        for match in TOKEN_RE.finditer(masked_text):
            token = match.group(1)
            real_value = self.layer.token_to_real.get(token)
            if not real_value:
                continue
            label = self.layer.real_to_entity_type.get(real_value, "MISC")
            occurrences.append(
                {
                    "token": token,
                    "label": label,
                    "text": real_value,
                    "start": match.start(),
                    "end": match.end(),
                }
            )

        unique_entities = []
        for real_value, token in self.layer.real_to_token.items():
            unique_entities.append(
                {
                    "token": token,
                    "label": self.layer.real_to_entity_type.get(real_value, "MISC"),
                    "text": real_value,
                }
            )

        return RunResult(masked_text=masked_text, occurrences=occurrences, unique_entities=unique_entities)


def _is_address_label(label: str) -> bool:
    return label == "ADDRESS" or label.startswith("LOCATION_")


def _build_flat_text(person: dict[str, Any], mode: str) -> str:
    values = list(_iter_scalar_leaves(person))
    if mode == "prompt_space":
        return " ".join(values)
    return "\n".join(values)


def _collect_address_cases(people: list[dict[str, Any]], locale: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for person_index, person in enumerate(people):
        addresses = person.get("addresses", {})
        for address_key, address_value in addresses.items():
            if not isinstance(address_value, dict):
                continue
            full = str(address_value.get("ecommerce_full", "")).strip()
            if not full:
                continue
            cases.append(
                {
                    "person_index": person_index,
                    "locale": locale,
                    "address_key": address_key,
                    "full_address": full,
                    "address_dict": address_value,
                    "person": person,
                }
            )
    return cases


def _build_variant_case(case: dict[str, Any], rng: random.Random) -> dict[str, str]:
    address_dict = case["address_dict"]
    locale = case["locale"]
    person = case["person"]

    component_order = [
        "country",
        "province",
        "state",
        "city",
        "district",
        "district_or_neighborhood",
        "street",
        "street_number",
        "building_unit_room",
        "apartment_suite_unit",
        "postal_code",
        "zip_code",
    ]
    parts = [str(address_dict.get(key, "")).strip() for key in component_order]
    parts = [part for part in parts if part]
    if len(parts) >= 4:
        start = rng.randint(0, max(0, len(parts) - 3))
        end = rng.randint(start + 3, len(parts))
        parts = parts[start:end]

    address_fragment = "".join(parts) if locale == "cn" else ", ".join(parts)

    primary = _extract_primary_fields(person, locale)
    extras = [
        primary["name"],
        primary["phone"],
        primary["email"],
        primary["organization"],
    ]
    extras = [item for item in extras if item]
    rng.shuffle(extras)
    extras = extras[:3]

    prompt_values = extras + [address_fragment]
    rng.shuffle(prompt_values)
    prompt_text = " ".join(prompt_values)
    ocr_text = "\n".join(prompt_values)

    return {
        "address_fragment": address_fragment,
        "prompt_text": prompt_text,
        "ocr_text": ocr_text,
    }


def evaluate_flattened(
    evaluator: AndLabEvaluator,
    people: list[dict[str, Any]],
    locale: str,
    mode: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary: dict[str, Any] = {
        "cases": 0,
        "crashes": 0,
        "name_hit_rate": 0.0,
        "phone_hit_rate": 0.0,
        "email_hit_rate": 0.0,
        "organization_hit_rate": 0.0,
        "numeric_hit_rate": 0.0,
        "avg_candidate_count": 0.0,
        "candidate_label_counts": {},
        "miss_examples": [],
    }
    details: list[dict[str, Any]] = []
    label_counts: Counter[str] = Counter()
    name_hits = phone_hits = email_hits = org_hits = numeric_hits = 0
    total_candidates = 0

    for person_index, person in enumerate(people):
        summary["cases"] += 1
        text = _build_flat_text(person, mode)
        result = evaluator._run(text, mode, clear=True)
        primary = _extract_primary_fields(person, locale)
        numeric_pool = _extract_numeric_pool(person)

        detail = {
            "person_index": person_index,
            "locale": locale,
            "mode": mode,
            "error": result.error,
            "masked_text": result.masked_text,
            "entities": result.occurrences,
            "expected": {
                **primary,
                "numeric_pool": numeric_pool,
            },
        }

        if result.error:
            summary["crashes"] += 1
            details.append(detail)
            continue

        total_candidates += len(result.occurrences)
        label_counts.update(entity["label"] for entity in result.occurrences)

        names = [e["text"] for e in result.occurrences if e["label"] in CORE_NAME_LABELS]
        phones = [e["text"] for e in result.occurrences if e["label"] in CORE_PHONE_LABELS]
        emails = [e["text"] for e in result.occurrences if e["label"] in CORE_EMAIL_LABELS]
        orgs = [e["text"] for e in result.occurrences if e["label"] in CORE_ORG_LABELS]
        numerics = [e["text"] for e in result.occurrences if e["label"] in CORE_NUMERIC_LABELS]

        misses: list[str] = []
        if _string_hit(primary["name"], names):
            name_hits += 1
        else:
            misses.append("name")
        if _string_hit(primary["phone"], phones):
            phone_hits += 1
        else:
            misses.append("phone")
        if _string_hit(primary["email"], emails):
            email_hits += 1
        else:
            misses.append("email")
        if _string_hit(primary["organization"], orgs):
            org_hits += 1
        else:
            misses.append("organization")
        if not numeric_pool or all(_string_hit(value, numerics) for value in numeric_pool):
            numeric_hits += 1
        else:
            misses.append("numeric_pool")

        detail["misses"] = misses
        details.append(detail)
        if misses and len(summary["miss_examples"]) < 12:
            summary["miss_examples"].append(
                {
                    "person_index": person_index,
                    "misses": misses,
                    **primary,
                }
            )

    effective_cases = max(1, summary["cases"] - summary["crashes"])
    summary["name_hit_rate"] = round(name_hits / effective_cases, 3)
    summary["phone_hit_rate"] = round(phone_hits / effective_cases, 3)
    summary["email_hit_rate"] = round(email_hits / effective_cases, 3)
    summary["organization_hit_rate"] = round(org_hits / effective_cases, 3)
    summary["numeric_hit_rate"] = round(numeric_hits / effective_cases, 3)
    summary["avg_candidate_count"] = round(total_candidates / effective_cases, 2)
    summary["candidate_label_counts"] = dict(label_counts.most_common())
    return summary, details


def evaluate_address_baseline(
    evaluator: AndLabEvaluator,
    cases: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = {
        "cases": len(cases),
        "crashes": 0,
        "any_address_rate": 0.0,
        "partial_hit_rate": 0.0,
        "exact_full_address_rate": 0.0,
    }
    details: list[dict[str, Any]] = []
    any_hits = partial_hits = exact_hits = 0

    for case in cases:
        result = evaluator._run(case["full_address"], "prompt_space", clear=True)
        detail = {
            "locale": case["locale"],
            "person_index": case["person_index"],
            "address_key": case["address_key"],
            "full_address": case["full_address"],
            "error": result.error,
            "entities": result.occurrences,
        }
        if result.error:
            summary["crashes"] += 1
            details.append(detail)
            continue

        address_entities = [e for e in result.occurrences if _is_address_label(e["label"])]
        address_texts = [e["text"] for e in address_entities]
        any_hit = bool(address_entities)
        partial_hit = _string_hit(case["full_address"], address_texts)
        exact_hit = any(_norm(text) == _norm(case["full_address"]) for text in address_texts)

        any_hits += int(any_hit)
        partial_hits += int(partial_hit)
        exact_hits += int(exact_hit)

        detail.update(
            {
                "any_address": any_hit,
                "partial_hit": partial_hit,
                "exact_full_address": exact_hit,
            }
        )
        details.append(detail)

    effective_cases = max(1, summary["cases"] - summary["crashes"])
    summary["any_address_rate"] = round(any_hits / effective_cases, 3)
    summary["partial_hit_rate"] = round(partial_hits / effective_cases, 3)
    summary["exact_full_address_rate"] = round(exact_hits / effective_cases, 3)
    return summary, details


def evaluate_address_variants(
    evaluator: AndLabEvaluator,
    cases: list[dict[str, Any]],
    mode: str,
    rng: random.Random,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = {
        "cases": len(cases),
        "crashes": 0,
        "any_address_rate": 0.0,
        "partial_hit_rate": 0.0,
        "exact_full_address_rate": 0.0,
        "same_token_reuse_rate": 0.0,
    }
    details: list[dict[str, Any]] = []
    any_hits = partial_hits = exact_hits = reuse_hits = 0

    for case in cases:
        variant = _build_variant_case(case, rng)
        variant_text = variant["prompt_text"] if mode == "prompt_space" else variant["ocr_text"]

        evaluator.layer.clear_mappings()
        full_result = evaluator._run(case["full_address"], "prompt_space", clear=False)
        if full_result.error:
            summary["crashes"] += 1
            details.append(
                {
                    "locale": case["locale"],
                    "person_index": case["person_index"],
                    "address_key": case["address_key"],
                    "full_address": case["full_address"],
                    "variant_text": variant_text,
                    "address_fragment": variant["address_fragment"],
                    "error": full_result.error,
                }
            )
            continue

        full_address_tokens = {
            entity["token"]
            for entity in full_result.occurrences
            if _is_address_label(entity["label"])
        }

        variant_result = evaluator._run(variant_text, mode, clear=False)
        detail = {
            "locale": case["locale"],
            "person_index": case["person_index"],
            "address_key": case["address_key"],
            "full_address": case["full_address"],
            "address_fragment": variant["address_fragment"],
            "variant_text": variant_text,
            "full_entities": full_result.occurrences,
            "variant_entities": variant_result.occurrences,
            "error": variant_result.error,
        }
        if variant_result.error:
            summary["crashes"] += 1
            details.append(detail)
            continue

        address_entities = [e for e in variant_result.occurrences if _is_address_label(e["label"])]
        address_texts = [e["text"] for e in address_entities]
        any_hit = bool(address_entities)
        partial_hit = _string_hit(case["full_address"], address_texts)
        exact_hit = any(_norm(text) == _norm(case["full_address"]) for text in address_texts)
        same_token_reuse = any(entity["token"] in full_address_tokens for entity in address_entities)

        any_hits += int(any_hit)
        partial_hits += int(partial_hit)
        exact_hits += int(exact_hit)
        reuse_hits += int(same_token_reuse)

        detail.update(
            {
                "any_address": any_hit,
                "partial_hit": partial_hit,
                "exact_full_address": exact_hit,
                "same_token_reuse": same_token_reuse,
            }
        )
        details.append(detail)

    effective_cases = max(1, summary["cases"] - summary["crashes"])
    summary["any_address_rate"] = round(any_hits / effective_cases, 3)
    summary["partial_hit_rate"] = round(partial_hits / effective_cases, 3)
    summary["exact_full_address_rate"] = round(exact_hits / effective_cases, 3)
    summary["same_token_reuse_rate"] = round(reuse_hits / effective_cases, 3)
    return summary, details


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_flat_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "locale",
                "mode",
                "person_index",
                "error",
                "name_expected",
                "phone_expected",
                "email_expected",
                "organization_expected",
                "misses",
                "entity_count",
                "labels",
            ],
        )
        writer.writeheader()
        for row in rows:
            expected = row.get("expected", {})
            entities = row.get("entities", [])
            writer.writerow(
                {
                    "locale": row.get("locale"),
                    "mode": row.get("mode"),
                    "person_index": row.get("person_index"),
                    "error": row.get("error"),
                    "name_expected": expected.get("name"),
                    "phone_expected": expected.get("phone"),
                    "email_expected": expected.get("email"),
                    "organization_expected": expected.get("organization"),
                    "misses": ",".join(row.get("misses", [])),
                    "entity_count": len(entities),
                    "labels": ",".join(entity["label"] for entity in entities),
                }
            )


def _write_address_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "locale",
                "person_index",
                "address_key",
                "full_address",
                "address_fragment",
                "variant_text",
                "error",
                "any_address",
                "partial_hit",
                "exact_full_address",
                "same_token_reuse",
                "entity_count",
                "labels",
            ],
        )
        writer.writeheader()
        for row in rows:
            entities = row.get("variant_entities") or row.get("entities") or []
            writer.writerow(
                {
                    "locale": row.get("locale"),
                    "person_index": row.get("person_index"),
                    "address_key": row.get("address_key"),
                    "full_address": row.get("full_address"),
                    "address_fragment": row.get("address_fragment"),
                    "variant_text": row.get("variant_text"),
                    "error": row.get("error"),
                    "any_address": row.get("any_address"),
                    "partial_hit": row.get("partial_hit"),
                    "exact_full_address": row.get("exact_full_address"),
                    "same_token_reuse": row.get("same_token_reuse"),
                    "entity_count": len(entities),
                    "labels": ",".join(entity["label"] for entity in entities),
                }
            )


def _build_summary_md(payload: dict[str, Any], output_path: Path) -> None:
    lines = [
        "# AndLab Protected Persona Evaluation",
        "",
        f"- Seed: `{payload['seed']}`",
        f"- CN personas: `{payload['cn_count']}`",
        f"- US personas: `{payload['us_count']}`",
        "- Flattening rule: remove keys containing `label`, plus `alias_type/template_name/version/person_id`; keep other scalar leaves in original order.",
        "- Detector entry: `PrivacyProtectionLayer.anonymize_prompt()` for `prompt_space`, `PrivacyProtectionLayer.identify_and_mask_text()` for `ocr_break`.",
        "- GLiNER model: `knowledgator/gliner-pii-large-v1.0`.",
        "",
        "## Flattened Persona Results",
    ]
    for key, item in payload["flattened"].items():
        lines.append(
            f"- `{key}`: cases={item['cases']}, crashes={item['crashes']}, "
            f"name={item['name_hit_rate']*100:.1f}%, phone={item['phone_hit_rate']*100:.1f}%, "
            f"email={item['email_hit_rate']*100:.1f}%, org={item['organization_hit_rate']*100:.1f}%, "
            f"numeric_pool={item['numeric_hit_rate']*100:.1f}%, avg_entities={item['avg_candidate_count']}"
        )

    lines.extend(["", "## Address Baseline"])
    for key, item in payload["address_baseline"].items():
        lines.append(
            f"- `{key}`: cases={item['cases']}, crashes={item['crashes']}, "
            f"any_address={item['any_address_rate']*100:.1f}%, partial={item['partial_hit_rate']*100:.1f}%, "
            f"exact_full={item['exact_full_address_rate']*100:.1f}%"
        )

    lines.extend(["", "## Address Variants"])
    for key, item in payload["address_variants"].items():
        lines.append(
            f"- `{key}`: cases={item['cases']}, crashes={item['crashes']}, "
            f"any_address={item['any_address_rate']*100:.1f}%, partial={item['partial_hit_rate']*100:.1f}%, "
            f"exact_full={item['exact_full_address_rate']*100:.1f}%, same_token_reuse={item['same_token_reuse_rate']*100:.1f}%"
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rng = random.Random(SEED)
    output_dir = ROOT / "outputs" / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    people_cn = json.loads((ROOT / "data" / "generated_persona" / "people_cn.json").read_text(encoding="utf-8"))
    people_us = json.loads((ROOT / "data" / "generated_persona" / "people_us.json").read_text(encoding="utf-8"))

    evaluator = AndLabEvaluator()
    # 先热启动一次，避免第一次真实样本混入模型初始化耗时。
    evaluator._run("warmup: Michael Chen 206-987-6543 1425 Pine St", "prompt_space", clear=True)

    flattened: dict[str, Any] = {}
    flat_rows: list[dict[str, Any]] = []
    for locale, people in (("cn", people_cn), ("us", people_us)):
        for mode in ("prompt_space", "ocr_break"):
            key = f"{locale}:{mode}"
            summary, rows = evaluate_flattened(evaluator, people, locale, mode)
            flattened[key] = summary
            flat_rows.extend(rows)

    cn_address_cases = _collect_address_cases(people_cn, "cn")
    us_address_cases = _collect_address_cases(people_us, "us")

    address_baseline: dict[str, Any] = {}
    address_variant: dict[str, Any] = {}
    address_rows: list[dict[str, Any]] = []

    for locale, cases in (("cn", cn_address_cases), ("us", us_address_cases)):
        baseline_summary, baseline_rows = evaluate_address_baseline(evaluator, cases)
        address_baseline[f"{locale}:baseline"] = baseline_summary
        address_rows.extend(baseline_rows)

        variant_prompt_summary, variant_prompt_rows = evaluate_address_variants(evaluator, cases, "prompt_space", rng)
        address_variant[f"{locale}:variant_prompt"] = variant_prompt_summary
        address_rows.extend(variant_prompt_rows)

        variant_ocr_summary, variant_ocr_rows = evaluate_address_variants(evaluator, cases, "ocr_break", rng)
        address_variant[f"{locale}:variant_ocr"] = variant_ocr_summary
        address_rows.extend(variant_ocr_rows)

    payload = {
        "seed": SEED,
        "cn_count": len(people_cn),
        "us_count": len(people_us),
        "flattened": flattened,
        "address_baseline": address_baseline,
        "address_variants": address_variant,
        "flat_details": flat_rows,
        "address_details": address_rows,
    }

    _write_json(output_dir / "andlab_persona_eval_details.json", payload)
    _write_flat_csv(output_dir / "andlab_persona_eval_flat_cases.csv", flat_rows)
    _write_address_csv(output_dir / "andlab_persona_eval_address_cases.csv", address_rows)
    _build_summary_md(payload, output_dir / "andlab_persona_eval_summary.md")

    print(output_dir / "andlab_persona_eval_summary.md")
    print(output_dir / "andlab_persona_eval_details.json")
    print(output_dir / "andlab_persona_eval_flat_cases.csv")
    print(output_dir / "andlab_persona_eval_address_cases.csv")


if __name__ == "__main__":
    main()
