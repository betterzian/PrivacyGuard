"""结构化数字 validator 的共享实现。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType

# 美国 NANP 非法 NPA（N11 服务号）与 NXX 禁用前缀。
US_NANP_INVALID_NPA = frozenset({
    "211", "311", "411", "511", "611", "711", "811", "911",
})
US_NANP_INVALID_NXX_PREFIX = "555"

# 银行卡 IIN 白名单（prefix, (min_len, max_len)）。
BANK_IIN_WHITELIST: tuple[tuple[str, tuple[int, int]], ...] = (
    ("4", (13, 19)),
    ("51", (16, 16)), ("52", (16, 16)), ("53", (16, 16)),
    ("54", (16, 16)), ("55", (16, 16)),
    *[(str(p), (16, 16)) for p in range(2221, 2721)],
    ("34", (15, 15)), ("37", (15, 15)),
    ("62", (16, 19)),
    ("6011", (16, 16)), ("65", (16, 16)),
    *[(str(p), (16, 16)) for p in range(3528, 3590)],
)

_ID_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CN_CHECK_CODES = "10X98765432"

ValidatorEntry = tuple[PIIAttributeType, str]


def _luhn_valid(digits: str) -> bool:
    """标准 Luhn 校验。"""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for index, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _validate_cn_phone(digits: str) -> bool:
    return len(digits) == 11 and digits[0] == "1" and digits[1] in "3456789"


def _validate_us_phone_strict(digits: str) -> bool:
    """美国 NANP 严格校验：10 位；首位非 0/1；NPA 不在 N11；NXX 不以 555 开头。"""
    if len(digits) != 10 or not digits.isdigit():
        return False
    if digits[0] in "01":
        return False
    npa = digits[:3]
    nxx = digits[3:6]
    if npa in US_NANP_INVALID_NPA:
        return False
    if nxx.startswith(US_NANP_INVALID_NXX_PREFIX):
        return False
    return True


def _match_bank_iin(digits: str) -> bool:
    """按 IIN 白名单匹配银行卡号前缀 + 长度区间。"""
    n = len(digits)
    for prefix, (lo, hi) in BANK_IIN_WHITELIST:
        if lo <= n <= hi and digits.startswith(prefix):
            return True
    return False


def normalize_structured_digits_for_phone(
    digits: str,
    *,
    metadata: dict[str, list[str]] | None = None,
) -> str:
    """结构化片段在进入 validator 前的数字规范化。"""
    metadata = metadata or {}
    phone_region = str((metadata.get("phone_region") or [""])[0]).strip().lower()
    phone_pattern = str((metadata.get("phone_pattern") or [""])[0]).strip().lower()
    if phone_region == "cn" and len(digits) == 13 and digits.startswith("86") and re.fullmatch(r"1[3-9]\d{9}", digits[2:]):
        return digits[2:]
    if phone_region == "us" and phone_pattern in {
        "us_country_code",
        "us_country_code_paren",
        "us_trunk_area_paren",
    } and len(digits) == 11 and digits.startswith("1"):
        return digits[1:]
    # 无显式 region 时仅保留中国国家码兜底，避免把裸 11 位数字误收成美式号码。
    if len(digits) == 13 and digits.startswith("86") and re.fullmatch(r"1[3-9]\d{9}", digits[2:]):
        return digits[2:]
    return digits


def _validate_cn_id_18(text: str) -> bool:
    if len(text) != 18:
        return False
    body = text[:17]
    if not body.isdigit():
        return False
    check = text[17].upper()
    total = sum(int(body[i]) * _ID_CN_WEIGHTS[i] for i in range(17))
    expected = _ID_CN_CHECK_CODES[total % 11]
    if check != expected:
        return False
    month = int(text[10:12])
    day = int(text[12:14])
    return 1 <= month <= 12 and 1 <= day <= 31


def _validate_cn_id_15(digits: str) -> bool:
    if len(digits) != 15 or not digits.isdigit():
        return False
    month = int(digits[8:10])
    day = int(digits[10:12])
    return 1 <= month <= 12 and 1 <= day <= 31


def route_structured_validators(
    *,
    digits: str,
    text: str,
    fragment_type: str,
    phone_region: str | None = None,
) -> ValidatorEntry | None:
    """按数值形态升级为明确的结构化属性。"""
    is_cn_id_alnum = fragment_type == "ALNUM" and bool(re.fullmatch(r"\d{17}[Xx]", text))
    if (fragment_type != "NUM" and not is_cn_id_alnum) or not digits:
        return None

    n = len(digits)
    normalized_region = str(phone_region or "").strip().lower()
    if fragment_type == "NUM" and normalized_region == "cn":
        if _validate_cn_phone(digits):
            return (PIIAttributeType.PHONE, "validated_phone_cn")
        return None
    if fragment_type == "NUM" and normalized_region == "us":
        if _validate_us_phone_strict(digits):
            return (PIIAttributeType.PHONE, "validated_phone_us")
        return None
    if fragment_type == "NUM" and n == 11 and _validate_cn_phone(digits):
        return (PIIAttributeType.PHONE, "validated_phone_cn")
    if fragment_type == "NUM" and n == 10 and _validate_us_phone_strict(digits):
        return (PIIAttributeType.PHONE, "validated_phone_us")
    if n == 18 or is_cn_id_alnum:
        id_text = text if len(text) == 18 else digits
        if _validate_cn_id_18(id_text):
            return (PIIAttributeType.ID_NUMBER, "validated_id_cn_18")
    if fragment_type == "NUM" and n == 15 and _validate_cn_id_15(digits):
        return (PIIAttributeType.ID_NUMBER, "validated_id_cn_15")
    if (
        fragment_type == "NUM"
        and 13 <= n <= 19
        and _luhn_valid(digits)
        and _match_bank_iin(digits)
    ):
        return (PIIAttributeType.BANK_NUMBER, "validated_bank_number_pan")
    return None
