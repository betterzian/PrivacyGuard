"""统一结构化属性 stack。"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, ClueRole, DictionaryEntry
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun, _build_value_candidate

# detector 主路径允许产出的 attr_type 集合；persona 精匹配可额外产出 PASSPORT/DRIVER。
ALLOWED_DETECTOR_OUTPUT_ATTRS = frozenset({
    PIIAttributeType.NAME,
    PIIAttributeType.PHONE,
    PIIAttributeType.BANK_NUMBER,
    PIIAttributeType.ID_NUMBER,
    PIIAttributeType.LICENSE_PLATE,
    PIIAttributeType.EMAIL,
    PIIAttributeType.ADDRESS,
    PIIAttributeType.DETAILS,
    PIIAttributeType.ORGANIZATION,
    PIIAttributeType.TIME,
    PIIAttributeType.AMOUNT,
    PIIAttributeType.NUM,
    PIIAttributeType.ALNUM,
})
PERSONA_ONLY_ATTRS = frozenset({
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
})

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

_LOOKUP_PLACEHOLDER_BY_ATTR = {
    PIIAttributeType.PHONE: "<phone>",
    PIIAttributeType.EMAIL: "<email>",
    PIIAttributeType.ID_NUMBER: "<id>",
    PIIAttributeType.BANK_NUMBER: "<bank>",
    PIIAttributeType.LICENSE_PLATE: "<license_plate>",
    PIIAttributeType.AMOUNT: "<amount>",
}

_ID_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CN_CHECK_CODES = "10X98765432"

_ValidatorEntry = tuple[PIIAttributeType, str]


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


def _normalize_structured_digits_for_phone(digits: str) -> str:
    """结构化片段在进入 validator 前的数字规范化。

    这里假设上游已经用 `re.sub(r"\\D", "", ...)` 去掉了空格、连字符、括号等连接符。
    额外处理常见国家码/前缀：
    - +86XXXXXXXXXXX → 86XXXXXXXXXXX（已去掉 +）→ 去掉 86，得到 11 位中国手机号。
    - 不再盲目把 11 位 `1XXXXXXXXXX` 归一成美式号码，避免中国手机号或普通 11 位数字被误判。
    """
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


def _route_validators(*, digits: str, text: str, fragment_type: str) -> _ValidatorEntry | None:
    """按数值形态升级为明确的结构化属性。

    顺序：CN phone → US phone (严格) → CN ID 18 → CN ID 15 → Luhn + IIN 白名单。
    宽 Luhn 与无 IIN 白名单的命中一律退化为 NUM（由调用方兜底）。
    """
    is_cn_id_alnum = fragment_type == "ALNUM" and bool(re.fullmatch(r"\d{17}[Xx]", text))
    if (fragment_type != "NUM" and not is_cn_id_alnum) or not digits:
        return None

    n = len(digits)
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


def _hard_source_for_entry(entry: DictionaryEntry) -> str:
    if entry.matched_by == "dictionary_session":
        return "session"
    return "local"


class StructuredStack(BaseStack):
    """统一处理 STRUCTURED family 的明确值、通用片段与标签绑定。"""

    def run(self) -> StackRun | None:
        if self.clue.role != ClueRole.VALUE or self.clue.strength != ClaimStrength.HARD:
            return None
        if self.clue.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
            return self._run_fragment()
        return self._build_direct_run()

    def _run_fragment(self) -> StackRun | None:
        candidate = self._resolve_fragment_candidate(self.clue)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
        )

    def _resolve_fragment_candidate(self, clue) -> CandidateDraft:
        metadata = dict(clue.source_metadata)
        fragment_type = self._fragment_type(clue)
        pure_digits = (metadata.get("pure_digits") or [re.sub(r"\D", "", clue.text)])[0]
        pure_digits = _normalize_structured_digits_for_phone(pure_digits)

        candidate = _build_value_candidate(clue, self.context.stream.source)
        entry = self._lookup_dictionary_entry(clue.text, fragment_type, pure_digits)
        if entry is not None:
            candidate.attr_type = entry.attr_type
            candidate.source_kind = entry.matched_by
            # persona/本地词典的精匹配被视为高可信出口，锁定 attr_type，
            # 避免下游 label 或启发式再次改写。
            if entry.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
                candidate.attr_locked = True
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {
                    **{key: list(values) for key, values in entry.metadata.items()},
                    "matched_by": [entry.matched_by],
                    "hard_source": [_hard_source_for_entry(entry)],
                    "placeholder": [_LOOKUP_PLACEHOLDER_BY_ATTR.get(entry.attr_type, f"<{entry.attr_type.value}>")],
                    "original_fragment_type": [fragment_type],
                },
            )
            return candidate

        result = _route_validators(digits=pure_digits, text=clue.text, fragment_type=fragment_type)
        if result is not None:
            attr_type, source_kind = result
            candidate.attr_type = attr_type
            candidate.source_kind = source_kind
            # H 档 validator 命中直接锁定 attr_type。
            candidate.attr_locked = True
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"validated_by": [source_kind], "original_fragment_type": [fragment_type]},
            )
            candidate = self._try_label_bind(candidate, fragment_type=fragment_type)
        return candidate

    def _try_label_bind(self, candidate: CandidateDraft, *, fragment_type: str) -> CandidateDraft:
        """读取 parser 维护的最近结构化锚点，决定绑定还是退化。"""
        anchor = self.context.recent_structured_anchor
        if anchor is None:
            return candidate
        distance = self.clue.unit_start - anchor.unit_end
        if distance < 0 or distance > 5:
            return candidate
        anchor_clue = self.context.clues[anchor.clue_index]
        if anchor_clue.attr_type is None:
            return candidate
        if anchor_clue.attr_type == candidate.attr_type:
            candidate.label_clue_ids.add(anchor_clue.clue_id)
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"bound_label_clue_ids": [anchor_clue.clue_id]},
            )
            return candidate
        candidate.attr_type = PIIAttributeType.ALNUM if fragment_type == "ALNUM" else PIIAttributeType.NUM
        candidate.source_kind = self.clue.source_kind
        candidate.attr_locked = False
        candidate.metadata = merge_metadata(
            candidate.metadata,
            {"label_attr_mismatch": [anchor_clue.attr_type.value]},
        )
        return candidate

    def _lookup_dictionary_entry(self, text: str, fragment_type: str, digits: str) -> DictionaryEntry | None:
        index = self.context.structured_lookup_index
        if fragment_type == "NUM":
            key = digits
            if key:
                return index.numeric_entries.get(key)
            return None
        key = re.sub(r"[^0-9A-Za-z]", "", text or "").upper()
        if key:
            return index.alnum_entries.get(key)
        return None

    def _fragment_type(self, clue) -> str:
        metadata = dict(clue.source_metadata)
        if metadata.get("fragment_type"):
            return str(metadata["fragment_type"][0]).upper()
        if clue.attr_type == PIIAttributeType.ALNUM:
            return "ALNUM"
        return "NUM"
