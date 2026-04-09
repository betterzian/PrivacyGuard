"""复杂 persona 文本场景下对比 PrivacyGuard 与 AndLab_protected 的检测表现。"""

from __future__ import annotations

import csv
import json
import random
import re
import statistics
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


ROOT = Path(__file__).resolve().parents[1]
ANDLAB_ROOT = ROOT / "tmp" / "gui_privacy_protection" / "AndLab_protected"
sys.path.insert(0, str(ANDLAB_ROOT))

from utils_mobile.privacy.layer import PrivacyProtectionLayer  # type: ignore  # noqa: E402


SEED = 20260409
SKIP_EXACT_KEYS = {"alias_type", "template_name", "version", "person_id"}
SKIP_KEY_SUBSTRINGS = ("label",)
SCENARIOS = ("dense_concat", "punctuation_mix")
CHANNELS = ("prompt", "ocr")
TOKEN_RE = re.compile(r"\[?([A-Z][A-Z0-9_]*#[0-9a-z]{5})\]?")

ANDLAB_NAME_LABELS = {
    "NAME",
    "FIRST_NAME",
    "LAST_NAME",
    "NAME_MEDICAL_PROFESSIONAL",
    "PERSON_NAME",
}
ANDLAB_PHONE_LABELS = {"PHONE_NUMBER"}
ANDLAB_EMAIL_LABELS = {"EMAIL", "EMAIL_ADDRESS"}
ANDLAB_ORG_LABELS = {"ORGANIZATION_MEDICAL_FACILITY"}
ANDLAB_ADDRESS_LABELS = {
    "ADDRESS",
    "LOCATION_ADDRESS",
    "LOCATION_STREET",
    "LOCATION_CITY",
    "LOCATION_STATE",
    "LOCATION_COUNTRY",
    "LOCATION_ZIP",
}
ANDLAB_ID_DOC_LABELS = {"SSN", "PASSPORT_NUMBER", "DRIVER_LICENSE", "HEALTHCARE_NUMBER", "VEHICLE_ID"}
ANDLAB_FINANCIAL_LABELS = {
    "ACCOUNT_NUMBER",
    "BANK_ACCOUNT",
    "ROUTING_NUMBER",
    "CREDIT_CARD",
    "CREDIT_CARD_EXPIRATION",
    "CVV",
}


@dataclass
class EvalInput:
    prompt_text: str
    ocr_lines: list[str]


@dataclass
class RunResult:
    elapsed_ms: float
    entities: list[dict[str, Any]]
    error: str | None = None


def _norm(text: str) -> str:
    return "".join(ch.lower() for ch in text if ch.isalnum())


def _digits(text: str) -> str:
    return "".join(ch for ch in str(text) if ch.isdigit())


def _alnum(text: str) -> str:
    return "".join(ch for ch in str(text) if ch.isalnum())


def _string_hit(expected: str, candidates: Iterable[str]) -> bool:
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


def _string_hit_any(expected_values: Iterable[str], candidates: Iterable[str]) -> bool:
    return any(_string_hit(value, candidates) for value in expected_values if str(value).strip())


def _percent(count: int, total: int) -> float:
    return round((count / total) if total else 0.0, 3)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return round(values[0], 3)
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return round(ordered[lower], 3)
    ratio = pos - lower
    return round(ordered[lower] * (1 - ratio) + ordered[upper] * ratio, 3)


def _runtime_summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "total_ms": 0.0}
    return {
        "avg_ms": round(statistics.mean(values), 3),
        "p50_ms": _percentile(values, 0.5),
        "p95_ms": _percentile(values, 0.95),
        "total_ms": round(sum(values), 3),
    }


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _iter_scalar_items(obj: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    """按 JSON 原始顺序提取标量叶子与路径。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key in SKIP_EXACT_KEYS or any(part in key_lower for part in SKIP_KEY_SUBSTRINGS):
                continue
            yield from _iter_scalar_items(value, path + (str(key),))
        return
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            yield from _iter_scalar_items(item, path + (f"[{index}]",))
        return
    if _is_scalar(obj):
        text = str(obj).strip()
        if text:
            yield path, text


def _path_text(path: tuple[str, ...]) -> str:
    return ".".join(path).lower()


def _extract_primary_fields(person: dict[str, Any], locale: str) -> dict[str, str]:
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


def _extract_other_expectations(person: dict[str, Any], locale: str) -> dict[str, list[str]]:
    if locale == "cn":
        return {
            "id_doc": [person.get("id_card", "")],
            "financial": [card.get("card_number", "") for card in person.get("bank_cards", []) if card.get("card_number")],
        }
    license_number = person.get("drivers_license", {}).get("license_number", "")
    credit_cards = [card.get("number", "") for card in person.get("credit_cards", []) if card.get("number")]
    return {
        "id_doc": [license_number] if license_number else [],
        "financial": credit_cards,
    }


def _extract_numeric_pool(person: dict[str, Any]) -> list[str]:
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
        "number",
    }

    for path, text in _iter_scalar_items(person):
        path_str = _path_text(path)
        leaf = path[-1].lower() if path else ""
        if "phone" in path_str or "postal" in path_str or "zip" in path_str:
            continue
        if "street_number" in path_str or "birth_year" in path_str:
            continue
        if "date" in path_str or path_str.endswith(".class"):
            continue
        digit_count = sum(ch.isdigit() for ch in text)
        if digit_count < 6:
            continue
        if leaf in include_markers or any(marker in path_str for marker in include_markers):
            values.append(text)
    return values


def _classify_value(path: tuple[str, ...], value: str) -> str:
    path_str = _path_text(path)
    leaf = path[-1].lower() if path else ""
    if "phone" in path_str:
        return "phone"
    if "email" in path_str:
        return "email"
    if "company_name" in path_str:
        return "organization"
    if "ecommerce_full" in path_str or "map_search_short" in path_str:
        return "address"
    if any(key in path_str for key in ("id_card", "license_number", "passport_number", "ssn")):
        return "id_doc"
    if any(key in path_str for key in ("card_number", "credit_cards", "account_number", "routing_number", "cvv", "expiry")):
        return "financial"
    if any(key in path_str for key in ("name", "nickname", "alias", "remark")) and "company" not in path_str:
        return "name"
    if leaf == "number":
        return "financial"
    return "general"


def _group_digits(text: str, size: int, sep: str) -> str:
    digits = _digits(text)
    if not digits:
        return text
    return sep.join(digits[index:index + size] for index in range(0, len(digits), size))


def _format_phone(value: str, locale: str, style: int) -> str:
    digits = _digits(value)
    if locale == "cn":
        if len(digits) != 11:
            return digits or value
        if style % 3 == 0:
            return f"{digits[:3]}-{digits[3:7]}-{digits[7:]}"
        if style % 3 == 1:
            return f"({digits[:3]}){digits[3:7]}-{digits[7:]}"
        return f"{digits[:3]} {digits[3:7]} {digits[7:]}"
    local = digits[-10:] if len(digits) >= 10 else digits
    if len(local) != 10:
        return digits or value
    area, prefix, suffix = local[:3], local[3:6], local[6:]
    if style % 3 == 0:
        return f"+1({area}){prefix}-{suffix}"
    if style % 3 == 1:
        return f"{area}.{prefix}.{suffix}"
    return f"({area}){prefix} {suffix}"


def _format_financial(value: str, style: int) -> str:
    digits = _digits(value)
    if not digits:
        return value
    if len(digits) >= 12:
        return _group_digits(digits, 4, "-" if style % 2 == 0 else " ")
    if len(digits) >= 8:
        return _group_digits(digits, 4, "-")
    return digits


def _format_id_doc(value: str, locale: str, style: int) -> str:
    digits = _digits(value)
    if not digits:
        return _alnum(value).upper() or value
    if locale == "cn" and len(digits) == 18:
        if style % 2 == 0:
            return f"{digits[:6]}-{digits[6:14]}-{digits[14:]}"
        return f"{digits[:6]} {digits[6:14]} {digits[14:]}"
    if len(digits) >= 10:
        return _group_digits(digits, 4, "-" if style % 2 == 0 else " ")
    return digits


def _format_address(value: str, locale: str, scenario: str, style: int) -> str:
    text = str(value).strip()
    if scenario == "dense_concat":
        if locale == "us":
            return re.sub(r"[\s,./]+", "", text)
        return re.sub(r"\s+", "", text)
    if locale == "us":
        if style % 3 == 0:
            return text.replace(", ", " ").replace(" Apt ", " Apt-").replace(" WA ", " (WA) ")
        if style % 3 == 1:
            return text.replace(", ", "/").replace(" Apt ", " #")
        return text.replace(", ", " | ")
    if style % 3 == 0:
        return text.replace("号", "号(") + ")" if "号" in text and "(" not in text else text
    if style % 3 == 1:
        return text.replace("中国", "").replace("广东省", "广东").replace("江苏省", "江苏").replace("浙江省", "浙江")
    return text.replace(" ", "").replace("（", "(").replace("）", ")")


def _transform_value(path: tuple[str, ...], value: str, locale: str, scenario: str, style: int) -> str:
    kind = _classify_value(path, value)
    text = str(value).strip()
    if scenario == "dense_concat":
        if kind == "phone":
            return _digits(text)
        if kind == "financial":
            return _digits(text) or _alnum(text).upper()
        if kind == "id_doc":
            return _digits(text) or _alnum(text).upper()
        if kind == "name" and locale == "us":
            return text.replace(" ", "")
        if kind == "address":
            return _format_address(text, locale, scenario, style)
        return text.replace(" ", "")
    if kind == "phone":
        return _format_phone(text, locale, style)
    if kind == "financial":
        return _format_financial(text, style)
    if kind == "id_doc":
        return _format_id_doc(text, locale, style)
    if kind == "address":
        return _format_address(text, locale, scenario, style)
    if kind == "name" and locale == "us" and style % 3 == 1:
        return text.replace(" ", "/")
    return text


def _build_flat_input(person: dict[str, Any], locale: str, scenario: str, rng: random.Random) -> EvalInput:
    transformed: list[str] = []
    for index, (path, value) in enumerate(_iter_scalar_items(person)):
        style = (index + rng.randint(0, 2)) % 3
        transformed.append(_transform_value(path, value, locale, scenario, style))

    if scenario == "dense_concat":
        prompt_text = "".join(transformed)
        ocr_lines = ["".join(transformed[index:index + 6]) for index in range(0, len(transformed), 6)]
        return EvalInput(prompt_text=prompt_text, ocr_lines=[line for line in ocr_lines if line])

    joiners = ["/", "|", ",", ";", " "]
    prompt_parts: list[str] = []
    for index, value in enumerate(transformed):
        if index > 0:
            prompt_parts.append(joiners[index % len(joiners)])
        prompt_parts.append(value)
    prompt_text = "".join(prompt_parts)

    ocr_lines: list[str] = []
    cursor = 0
    chunk_size = 4
    while cursor < len(transformed):
        chunk = transformed[cursor:cursor + chunk_size]
        if chunk:
            inline_joiner = " / " if (cursor // chunk_size) % 2 == 0 else " | "
            ocr_lines.append(inline_joiner.join(chunk))
        cursor += chunk_size
    return EvalInput(prompt_text=prompt_text, ocr_lines=ocr_lines)


def _cn_reference_components(address: dict[str, Any]) -> tuple[dict[str, str], dict[str, list[str]]]:
    components: dict[str, str] = {}
    trace: list[str] = []
    key_trace: list[str] = []
    if address.get("province"):
        components["province"] = address["province"]
        trace.append(f"province:{address['province']}")
    if address.get("city"):
        components["city"] = address["city"]
        trace.append(f"city:{address['city']}")
    if address.get("district"):
        components["district"] = address["district"]
        trace.append(f"district:{address['district']}")
    if address.get("street"):
        components["road"] = address["street"]
        trace.append(f"road:{address['street']}")
    if address.get("map_search_short"):
        components["compound"] = address["map_search_short"]
        trace.append(f"compound:{address['map_search_short']}")
    street_number = str(address.get("street_number", "")).strip()
    if street_number:
        trace.append(f"street_number:{street_number}")
        key_trace.append(f"street_number:{_digits(street_number) or street_number}")
    building = str(address.get("building_unit_room", "")).strip()
    if building:
        components["building"] = building
        trace.append(f"building:{building}")
        token = _digits(building) or _alnum(building).upper() or building
        key_trace.append(f"building:{token}")
    if address.get("postal_code"):
        components["postal_code"] = address["postal_code"]
        trace.append(f"postal_code:{address['postal_code']}")
    return components, {
        "address_component_trace": trace,
        "address_component_key_trace": key_trace,
    }


def _us_reference_components(address: dict[str, Any]) -> tuple[dict[str, str], dict[str, list[str]]]:
    components: dict[str, str] = {}
    trace: list[str] = []
    key_trace: list[str] = []
    if address.get("state"):
        components["province"] = address["state"]
        trace.append(f"province:{address['state']}")
    if address.get("city"):
        components["city"] = address["city"]
        trace.append(f"city:{address['city']}")
    district = str(address.get("district_or_neighborhood", "")).strip()
    if district:
        components["district"] = district
        trace.append(f"district:{district}")
    street = str(address.get("street", "")).strip()
    if street:
        components["road"] = street
        trace.append(f"road:{street}")
    number = str(address.get("street_number", "")).strip()
    if number:
        trace.append(f"street_number:{number}")
        key_trace.append(f"street_number:{_digits(number) or number}")
    unit = str(address.get("apartment_suite_unit", "")).strip()
    if unit:
        components["unit"] = unit
        trace.append(f"unit:{unit}")
        token = _digits(unit) or _alnum(unit).upper() or unit
        key_trace.append(f"unit:{token}")
    if address.get("zip_code"):
        components["postal_code"] = address["zip_code"]
        trace.append(f"postal_code:{address['zip_code']}")
    return components, {
        "address_component_trace": trace,
        "address_component_key_trace": key_trace,
    }


def _reference_normalized_address(address: dict[str, Any], locale: str):
    if locale == "cn":
        components, metadata = _cn_reference_components(address)
    else:
        components, metadata = _us_reference_components(address)
    return normalize_pii(
        PIIAttributeType.ADDRESS,
        str(address.get("ecommerce_full", "")).strip(),
        components=components,
        metadata=metadata,
    )


def _sample_address_cases(people: list[dict[str, Any]], locale: str, rng: random.Random) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    address_keys = ["home_address", "work_address", "backup_shipping_address", "favorite_place"]
    for person_index, person in enumerate(people):
        choices = [key for key in address_keys if person.get("addresses", {}).get(key, {}).get("ecommerce_full")]
        if not choices:
            continue
        selected = choices[rng.randrange(len(choices))]
        address = person["addresses"][selected]
        fields = _extract_primary_fields(person, locale)
        other = _extract_other_expectations(person, locale)
        cases.append(
            {
                "locale": locale,
                "person_index": person_index,
                "address_key": selected,
                "address": address,
                "full_address": address["ecommerce_full"],
                "reference_normalized": _reference_normalized_address(address, locale),
                "name": fields["name"],
                "phone": fields["phone"],
                "email": fields["email"],
                "organization": fields["organization"],
                "financial": (other["financial"][0] if other["financial"] else ""),
            }
        )
    return cases


def _make_address_fragment(case: dict[str, Any], scenario: str) -> str:
    address = case["address"]
    if case["locale"] == "cn":
        candidates = [
            f"{address.get('district', '')}{address.get('street', '')}{address.get('street_number', '')}号{address.get('building_unit_room', '')}",
            f"{address.get('city', '')}{address.get('district', '')}{address.get('street', '')}{address.get('street_number', '')}号{address.get('building_unit_room', '')}",
            f"{address.get('street', '')}{address.get('street_number', '')}号{address.get('building_unit_room', '')}",
        ]
    else:
        unit = str(address.get("apartment_suite_unit", "")).strip()
        unit_part = f" {unit}" if unit else ""
        candidates = [
            f"{address.get('street_number', '')} {address.get('street', '')}{unit_part} {address.get('city', '')} {address.get('state', '')} {address.get('zip_code', '')}",
            f"{address.get('street_number', '')} {address.get('street', '')}{unit_part} {address.get('city', '')} {address.get('zip_code', '')}",
            f"{address.get('street_number', '')} {address.get('street', '')}{unit_part} {address.get('state', '')} {address.get('zip_code', '')}",
        ]
    fragment = next((item.strip() for item in candidates if item.strip()), case["full_address"])
    return _format_address(fragment, case["locale"], scenario, style=1)


def _build_address_variant_input(case: dict[str, Any], scenario: str) -> tuple[EvalInput, str]:
    locale = case["locale"]
    fragment = _make_address_fragment(case, scenario)
    name = _transform_value(("identity", "name"), case["name"], locale, scenario, 1)
    phone = _transform_value(("contact", "phone_main"), case["phone"], locale, scenario, 1)
    email = _transform_value(("contact", "email_personal"), case["email"], locale, scenario, 1)
    organization = _transform_value(("employment", "company_name"), case["organization"], locale, scenario, 1)
    financial = _transform_value(("payment", "number"), case["financial"], locale, scenario, 1) if case["financial"] else ""

    if scenario == "dense_concat":
        values = [name, phone, fragment, email, organization, financial]
        prompt_text = "".join(value for value in values if value)
        ocr_lines = [
            "".join(value for value in values[:3] if value),
            "".join(value for value in values[3:] if value),
        ]
        return EvalInput(prompt_text=prompt_text, ocr_lines=[line for line in ocr_lines if line]), fragment

    prompt_values = [name, f"({phone})", fragment, email, organization, financial]
    prompt_text = " / ".join(value for value in prompt_values if value)
    ocr_lines = [
        " | ".join(value for value in (name, f"({phone})") if value),
        fragment,
        " / ".join(value for value in (email, organization, financial) if value),
    ]
    return EvalInput(prompt_text=prompt_text, ocr_lines=[line for line in ocr_lines if line]), fragment


def _make_ocr_blocks(lines: list[str]) -> list[OCRTextBlock]:
    blocks: list[OCRTextBlock] = []
    for index, line in enumerate(lines):
        text = str(line).strip()
        if not text:
            continue
        blocks.append(
            OCRTextBlock(
                text=text,
                bbox={"x": 0, "y": index * 28, "width": max(20, len(text) * 12), "height": 22},
                block_id=f"line-{index}",
                line_id=index,
            )
        )
    return blocks


class PrivacyGuardEvaluator:
    """包装 PrivacyGuard detector，并记录初始化与运行耗时。"""

    def __init__(self) -> None:
        start = time.perf_counter()
        self.detectors = {
            "cn": RuleBasedPIIDetector(locale_profile="zh_cn"),
            "us": RuleBasedPIIDetector(locale_profile="en_us"),
        }
        self.init_ms = round((time.perf_counter() - start) * 1000, 3)
        warm_start = time.perf_counter()
        self.run(locale="cn", channel="prompt", data=EvalInput(prompt_text="张三13800138000zhangsan@example.com", ocr_lines=[]))
        self.run(
            locale="us",
            channel="ocr",
            data=EvalInput(prompt_text="", ocr_lines=["MichaelChen", "(206)987-6543", "1425PineStApt301SeattleWA98122"]),
        )
        self.warmup_ms = round((time.perf_counter() - warm_start) * 1000, 3)

    def run(self, *, locale: str, channel: str, data: EvalInput) -> RunResult:
        detector = self.detectors[locale]
        start = time.perf_counter()
        try:
            if channel == "prompt":
                candidates = detector.detect(
                    prompt_text=data.prompt_text,
                    ocr_blocks=[],
                    protection_level=ProtectionLevel.STRONG,
                )
            else:
                candidates = detector.detect(
                    prompt_text="",
                    ocr_blocks=_make_ocr_blocks(data.ocr_lines),
                    protection_level=ProtectionLevel.STRONG,
                )
        except Exception:
            return RunResult(
                elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
                entities=[],
                error=traceback.format_exc(),
            )

        entities = [
            {
                "text": candidate.text,
                "label": candidate.attr_type.value,
                "normalized_source": candidate.normalized_source,
            }
            for candidate in candidates
        ]
        return RunResult(
            elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
            entities=entities,
        )


class AndLabEvaluator:
    """包装 AndLab_protected 的文本层接口，并记录初始化与运行耗时。"""

    def __init__(self) -> None:
        start = time.perf_counter()
        self.layer = PrivacyProtectionLayer(enabled=True)
        self.init_ms = round((time.perf_counter() - start) * 1000, 3)
        warm_start = time.perf_counter()
        self.run(locale="us", channel="prompt", data=EvalInput(prompt_text="Michael Chen 2069876543 1425PineSt", ocr_lines=[]), clear=True)
        self.run(locale="cn", channel="ocr", data=EvalInput(prompt_text="", ocr_lines=["李晓明18038637940", "南山区南海大道1001号"]), clear=True)
        self.warmup_ms = round((time.perf_counter() - warm_start) * 1000, 3)

    def run(self, *, locale: str, channel: str, data: EvalInput, clear: bool) -> RunResult:
        del locale
        if clear:
            self.layer.clear_mappings()
        text = data.prompt_text if channel == "prompt" else "\n".join(data.ocr_lines)
        start = time.perf_counter()
        try:
            if channel == "prompt":
                masked_text, _ = self.layer.anonymize_prompt(text)
            else:
                masked_text, _ = self.layer.identify_and_mask_text(text, is_xml=False)
        except Exception:
            return RunResult(
                elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
                entities=[],
                error=traceback.format_exc(),
            )

        # 只统计本轮 masked_text 中真实出现过的 token。
        # 不能直接遍历 layer.real_to_token，否则会把上一轮保留在 mapping 里的地址也算进来，
        # 导致“这次并没识别出地址，却仍被当作命中”的假高。
        entities: list[dict[str, Any]] = []
        for match in TOKEN_RE.finditer(masked_text):
            token = match.group(1)
            real_value = self.layer.token_to_real.get(token)
            if not real_value:
                continue
            entities.append(
                {
                    "text": real_value,
                    "label": self.layer.real_to_entity_type.get(real_value, "MISC"),
                    "token": token,
                }
            )
        return RunResult(
            elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
            entities=entities,
        )


def _texts_for_labels(entities: list[dict[str, Any]], labels: set[str]) -> list[str]:
    return [str(entity["text"]) for entity in entities if str(entity.get("label", "")) in labels]


def _category_texts(detector_name: str, entities: list[dict[str, Any]]) -> dict[str, list[str]]:
    all_texts = [str(entity["text"]) for entity in entities]
    if detector_name == "privacyguard":
        return {
            "all": all_texts,
            "name": _texts_for_labels(entities, {"name"}),
            "phone": _texts_for_labels(entities, {"phone"}),
            "email": _texts_for_labels(entities, {"email"}),
            "organization": _texts_for_labels(entities, {"organization"}),
            "address": _texts_for_labels(entities, {"address"}),
            "id_doc": _texts_for_labels(entities, {"id_number", "driver_license", "passport_number"}),
            "financial": _texts_for_labels(entities, {"bank_number"}),
        }
    return {
        "all": all_texts,
        "name": _texts_for_labels(entities, ANDLAB_NAME_LABELS),
        "phone": _texts_for_labels(entities, ANDLAB_PHONE_LABELS),
        "email": _texts_for_labels(entities, ANDLAB_EMAIL_LABELS),
        "organization": _texts_for_labels(entities, ANDLAB_ORG_LABELS),
        "address": _texts_for_labels(entities, ANDLAB_ADDRESS_LABELS),
        "id_doc": _texts_for_labels(entities, ANDLAB_ID_DOC_LABELS),
        "financial": _texts_for_labels(entities, ANDLAB_FINANCIAL_LABELS),
    }


def evaluate_flat_cases(
    evaluator: PrivacyGuardEvaluator | AndLabEvaluator,
    *,
    detector_name: str,
    people: list[dict[str, Any]],
    locale: str,
    scenario: str,
    channel: str,
    rng: random.Random,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = {
        "cases": len(people),
        "crashes": 0,
        "name_hits": 0,
        "phone_hits": 0,
        "email_hits": 0,
        "organization_hits": 0,
        "id_doc_hits": 0,
        "financial_hits": 0,
        "numeric_pool_hits": 0,
        "runtime_ms": [],
        "entity_counts": [],
    }
    rows: list[dict[str, Any]] = []

    for person_index, person in enumerate(people):
        data = _build_flat_input(person, locale, scenario, rng)
        if detector_name == "andlab":
            result = evaluator.run(locale=locale, channel=channel, data=data, clear=True)
        else:
            result = evaluator.run(locale=locale, channel=channel, data=data)
        summary["runtime_ms"].append(result.elapsed_ms)

        expected = _extract_primary_fields(person, locale)
        other = _extract_other_expectations(person, locale)
        numeric_pool = _extract_numeric_pool(person)

        row = {
            "detector": detector_name,
            "locale": locale,
            "scenario": scenario,
            "channel": channel,
            "person_index": person_index,
            "error": result.error,
            "elapsed_ms": result.elapsed_ms,
            "expected": {**expected, **other, "numeric_pool": numeric_pool},
            "entities": result.entities,
            "input_preview": data.prompt_text[:240] if channel == "prompt" else " | ".join(data.ocr_lines[:3])[:240],
        }
        if result.error:
            summary["crashes"] += 1
            rows.append(row)
            continue

        categorized = _category_texts(detector_name, result.entities)
        name_hit = _string_hit(expected["name"], categorized["name"])
        phone_hit = _string_hit(expected["phone"], categorized["phone"])
        email_hit = _string_hit(expected["email"], categorized["email"])
        organization_hit = _string_hit(expected["organization"], categorized["organization"])
        id_doc_hit = _string_hit_any(other["id_doc"], categorized["id_doc"])
        financial_hit = _string_hit_any(other["financial"], categorized["financial"])
        numeric_hit = _string_hit_any(numeric_pool, categorized["all"])

        summary["name_hits"] += int(name_hit)
        summary["phone_hits"] += int(phone_hit)
        summary["email_hits"] += int(email_hit)
        summary["organization_hits"] += int(organization_hit)
        summary["id_doc_hits"] += int(id_doc_hit)
        summary["financial_hits"] += int(financial_hit)
        summary["numeric_pool_hits"] += int(numeric_hit)
        summary["entity_counts"].append(len(result.entities))

        row.update(
            {
                "name_hit": name_hit,
                "phone_hit": phone_hit,
                "email_hit": email_hit,
                "organization_hit": organization_hit,
                "id_doc_hit": id_doc_hit,
                "financial_hit": financial_hit,
                "numeric_pool_hit": numeric_hit,
            }
        )
        rows.append(row)

    effective = max(1, summary["cases"] - summary["crashes"])
    summary.update(
        {
            "name_hit_rate": _percent(summary["name_hits"], effective),
            "phone_hit_rate": _percent(summary["phone_hits"], effective),
            "email_hit_rate": _percent(summary["email_hits"], effective),
            "organization_hit_rate": _percent(summary["organization_hits"], effective),
            "id_doc_hit_rate": _percent(summary["id_doc_hits"], effective),
            "financial_hit_rate": _percent(summary["financial_hits"], effective),
            "numeric_pool_hit_rate": _percent(summary["numeric_pool_hits"], effective),
            "avg_entity_count": round(statistics.mean(summary["entity_counts"]), 3) if summary["entity_counts"] else 0.0,
            "runtime": _runtime_summary(summary["runtime_ms"]),
        }
    )
    summary.pop("runtime_ms")
    summary.pop("entity_counts")
    return summary, rows


def evaluate_address_cases(
    evaluator: PrivacyGuardEvaluator | AndLabEvaluator,
    *,
    detector_name: str,
    cases: list[dict[str, Any]],
    scenario: str,
    channel: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = {
        "cases": len(cases),
        "crashes": 0,
        "any_address_hits": 0,
        "partial_hits": 0,
        "exact_hits": 0,
        "identity_hits": 0,
        "runtime_ms": [],
    }
    rows: list[dict[str, Any]] = []

    for case in cases:
        data, fragment = _build_address_variant_input(case, scenario)
        if detector_name == "privacyguard":
            result = evaluator.run(locale=case["locale"], channel=channel, data=data)
            total_elapsed = result.elapsed_ms
            full_entities: list[dict[str, Any]] = []
        else:
            full_data = EvalInput(
                prompt_text=case["full_address"],
                ocr_lines=[case["full_address"]],
            )
            full_result = evaluator.run(locale=case["locale"], channel=channel, data=full_data, clear=True)
            result = evaluator.run(locale=case["locale"], channel=channel, data=data, clear=False)
            total_elapsed = round(full_result.elapsed_ms + result.elapsed_ms, 3)
            full_entities = full_result.entities

        summary["runtime_ms"].append(total_elapsed)
        row = {
            "detector": detector_name,
            "locale": case["locale"],
            "scenario": scenario,
            "channel": channel,
            "person_index": case["person_index"],
            "address_key": case["address_key"],
            "full_address": case["full_address"],
            "address_fragment": fragment,
            "variant_input": data.prompt_text if channel == "prompt" else " | ".join(data.ocr_lines),
            "elapsed_ms": total_elapsed,
            "error": result.error,
            "entities": result.entities,
            "full_entities": full_entities,
        }
        if result.error:
            summary["crashes"] += 1
            rows.append(row)
            continue

        if detector_name == "privacyguard":
            address_entities = [entity for entity in result.entities if entity["label"] == "address"]
            address_texts = [entity["text"] for entity in address_entities]
            identity_hit = any(
                entity.get("normalized_source") is not None and same_entity(entity["normalized_source"], case["reference_normalized"])
                for entity in address_entities
            )
        else:
            address_entities = [entity for entity in result.entities if entity["label"] in ANDLAB_ADDRESS_LABELS]
            address_texts = [entity["text"] for entity in address_entities]
            full_address_tokens = {
                entity["token"]
                for entity in full_entities
                if entity["label"] in ANDLAB_ADDRESS_LABELS and entity.get("token")
            }
            identity_hit = any(entity.get("token") in full_address_tokens for entity in address_entities)

        any_hit = bool(address_entities)
        partial_hit = _string_hit(case["full_address"], address_texts)
        exact_hit = any(_norm(text) == _norm(case["full_address"]) for text in address_texts)

        summary["any_address_hits"] += int(any_hit)
        summary["partial_hits"] += int(partial_hit)
        summary["exact_hits"] += int(exact_hit)
        summary["identity_hits"] += int(identity_hit)

        row.update(
            {
                "any_address_hit": any_hit,
                "partial_hit": partial_hit,
                "exact_hit": exact_hit,
                "identity_hit": identity_hit,
            }
        )
        rows.append(row)

    effective = max(1, summary["cases"] - summary["crashes"])
    summary.update(
        {
            "any_address_rate": _percent(summary["any_address_hits"], effective),
            "partial_hit_rate": _percent(summary["partial_hits"], effective),
            "exact_hit_rate": _percent(summary["exact_hits"], effective),
            "identity_hit_rate": _percent(summary["identity_hits"], effective),
            "runtime": _runtime_summary(summary["runtime_ms"]),
        }
    )
    summary.pop("runtime_ms")
    return summary, rows


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _write_flat_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "detector",
                "locale",
                "scenario",
                "channel",
                "person_index",
                "elapsed_ms",
                "error",
                "name_hit",
                "phone_hit",
                "email_hit",
                "organization_hit",
                "id_doc_hit",
                "financial_hit",
                "numeric_pool_hit",
                "input_preview",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "detector": row.get("detector"),
                    "locale": row.get("locale"),
                    "scenario": row.get("scenario"),
                    "channel": row.get("channel"),
                    "person_index": row.get("person_index"),
                    "elapsed_ms": row.get("elapsed_ms"),
                    "error": row.get("error"),
                    "name_hit": row.get("name_hit"),
                    "phone_hit": row.get("phone_hit"),
                    "email_hit": row.get("email_hit"),
                    "organization_hit": row.get("organization_hit"),
                    "id_doc_hit": row.get("id_doc_hit"),
                    "financial_hit": row.get("financial_hit"),
                    "numeric_pool_hit": row.get("numeric_pool_hit"),
                    "input_preview": row.get("input_preview"),
                }
            )


def _write_address_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "detector",
                "locale",
                "scenario",
                "channel",
                "person_index",
                "address_key",
                "elapsed_ms",
                "error",
                "any_address_hit",
                "partial_hit",
                "exact_hit",
                "identity_hit",
                "address_fragment",
                "variant_input",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "detector": row.get("detector"),
                    "locale": row.get("locale"),
                    "scenario": row.get("scenario"),
                    "channel": row.get("channel"),
                    "person_index": row.get("person_index"),
                    "address_key": row.get("address_key"),
                    "elapsed_ms": row.get("elapsed_ms"),
                    "error": row.get("error"),
                    "any_address_hit": row.get("any_address_hit"),
                    "partial_hit": row.get("partial_hit"),
                    "exact_hit": row.get("exact_hit"),
                    "identity_hit": row.get("identity_hit"),
                    "address_fragment": row.get("address_fragment"),
                    "variant_input": row.get("variant_input"),
                }
            )


def _build_summary_md(payload: dict[str, Any], output_path: Path) -> None:
    detectors = payload["detectors"]
    lines = [
        "# Complex Persona Detector Comparison",
        "",
        f"- Seed: `{payload['seed']}`",
        f"- CN personas: `{payload['cn_count']}`",
        f"- US personas: `{payload['us_count']}`",
        "- Complex scenarios: `dense_concat`, `punctuation_mix`。",
        "- Channels: `prompt`, `ocr`。",
        "- Address identity: PrivacyGuard 用 `same_entity()`；AndLab 用地址 token 复用。",
        "",
        "## Initialization",
    ]
    for detector_name, detector_payload in detectors.items():
        lines.append(
            f"- `{detector_name}`: init={detector_payload['init_ms']:.3f}ms, warmup={detector_payload['warmup_ms']:.3f}ms"
        )

    lines.extend(["", "## Flattened Complex Text"])
    for detector_name, detector_payload in detectors.items():
        lines.append(f"### {detector_name}")
        for key, item in detector_payload["flat"].items():
            lines.append(
                f"- `{key}`: crashes={item['crashes']}/{item['cases']}, "
                f"name={item['name_hit_rate']*100:.1f}%, phone={item['phone_hit_rate']*100:.1f}%, "
                f"email={item['email_hit_rate']*100:.1f}%, org={item['organization_hit_rate']*100:.1f}%, "
                f"id_doc={item['id_doc_hit_rate']*100:.1f}%, financial={item['financial_hit_rate']*100:.1f}%, "
                f"numeric_pool={item['numeric_pool_hit_rate']*100:.1f}%, avg_entities={item['avg_entity_count']}, "
                f"avg_ms={item['runtime']['avg_ms']}"
            )

    lines.extend(["", "## Address Variants"])
    for detector_name, detector_payload in detectors.items():
        lines.append(f"### {detector_name}")
        for key, item in detector_payload["address"].items():
            lines.append(
                f"- `{key}`: crashes={item['crashes']}/{item['cases']}, "
                f"any_address={item['any_address_rate']*100:.1f}%, partial={item['partial_hit_rate']*100:.1f}%, "
                f"exact_full={item['exact_hit_rate']*100:.1f}%, identity={item['identity_hit_rate']*100:.1f}%, "
                f"avg_ms={item['runtime']['avg_ms']}"
            )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rng = random.Random(SEED)
    output_dir = ROOT / "outputs" / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    people_cn = json.loads((ROOT / "data" / "generated_persona" / "people_cn.json").read_text(encoding="utf-8"))
    people_us = json.loads((ROOT / "data" / "generated_persona" / "people_us.json").read_text(encoding="utf-8"))

    privacyguard = PrivacyGuardEvaluator()
    andlab = AndLabEvaluator()

    cn_address_cases = _sample_address_cases(people_cn, "cn", rng)
    us_address_cases = _sample_address_cases(people_us, "us", rng)

    payload: dict[str, Any] = {
        "seed": SEED,
        "cn_count": len(people_cn),
        "us_count": len(people_us),
        "detectors": {
            "privacyguard": {
                "init_ms": privacyguard.init_ms,
                "warmup_ms": privacyguard.warmup_ms,
                "flat": {},
                "address": {},
            },
            "andlab": {
                "init_ms": andlab.init_ms,
                "warmup_ms": andlab.warmup_ms,
                "flat": {},
                "address": {},
            },
        },
        "flat_details": [],
        "address_details": [],
    }

    for detector_name, evaluator in (("privacyguard", privacyguard), ("andlab", andlab)):
        for locale, people in (("cn", people_cn), ("us", people_us)):
            for scenario in SCENARIOS:
                for channel in CHANNELS:
                    key = f"{locale}:{scenario}:{channel}"
                    summary, rows = evaluate_flat_cases(
                        evaluator,
                        detector_name=detector_name,
                        people=people,
                        locale=locale,
                        scenario=scenario,
                        channel=channel,
                        rng=random.Random(f"{SEED}:{detector_name}:{locale}:{scenario}:{channel}"),
                    )
                    payload["detectors"][detector_name]["flat"][key] = summary
                    payload["flat_details"].extend(rows)

        for locale, cases in (("cn", cn_address_cases), ("us", us_address_cases)):
            for scenario in SCENARIOS:
                for channel in CHANNELS:
                    key = f"{locale}:{scenario}:{channel}"
                    summary, rows = evaluate_address_cases(
                        evaluator,
                        detector_name=detector_name,
                        cases=cases,
                        scenario=scenario,
                        channel=channel,
                    )
                    payload["detectors"][detector_name]["address"][key] = summary
                    payload["address_details"].extend(rows)

    _write_json(output_dir / "complex_detector_comparison_details.json", payload)
    _write_flat_csv(output_dir / "complex_detector_comparison_flat_cases.csv", payload["flat_details"])
    _write_address_csv(output_dir / "complex_detector_comparison_address_cases.csv", payload["address_details"])
    _build_summary_md(payload, output_dir / "complex_detector_comparison_summary.md")

    print(output_dir / "complex_detector_comparison_summary.md")
    print(output_dir / "complex_detector_comparison_details.json")
    print(output_dir / "complex_detector_comparison_flat_cases.csv")
    print(output_dir / "complex_detector_comparison_address_cases.csv")


if __name__ == "__main__":
    main()
