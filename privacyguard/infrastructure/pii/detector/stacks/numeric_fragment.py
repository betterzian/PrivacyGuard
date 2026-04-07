"""数字/混合片段验证 stack。

scanner 提取的 NUMERIC / OTHER 候选片段在此按位数路由到具体验证器，
验证通过则提升为具体 PII 类型（PHONE / ID_NUMBER / CARD_NUMBER 等），
未通过则保留原始类型，由后续 label 或兜底标签处理。
"""

from __future__ import annotations

import re

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import ClueRole
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun, _build_hard_candidate


# ── 国际区号前缀表 ──

_COUNTRY_CODE_PREFIXES: tuple[tuple[str, int], ...] = (
    ("86", 11),   # 中国：去掉 86 后应为 11 位
    ("1", 10),    # 北美：去掉 1 后应为 10 位
)

# ── 身份证校验权重 ──

_ID_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CN_CHECK_CODES = "10X98765432"


def _luhn_valid(digits: str) -> bool:
    """标准 Luhn 校验（digits 须为纯数字）。"""
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


def _luhn_valid_wide(digits: str) -> bool:
    """宽范围 Luhn 校验，用于银行账号（12-22 位）。"""
    if not digits.isdigit() or not (12 <= len(digits) <= 22):
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
    """中国手机号：11 位，首位 1，第二位 3-9。"""
    return len(digits) == 11 and digits[0] == "1" and digits[1] in "3456789"


def _validate_us_phone(digits: str) -> bool:
    """北美电话号：10 位，区号首位 2-9。"""
    return len(digits) == 10 and digits[0] in "23456789"


def _validate_cn_id_18(text: str) -> bool:
    """中国 18 位身份证：地区码 + 日期合法性 + 校验位。"""
    if len(text) != 18:
        return False
    body = text[:17]
    if not body.isdigit():
        return False
    check = text[17].upper()
    # 校验位验证。
    total = sum(int(body[i]) * _ID_CN_WEIGHTS[i] for i in range(17))
    expected = _ID_CN_CHECK_CODES[total % 11]
    if check != expected:
        return False
    # 月份和日期基本合法性。
    month = int(text[10:12])
    day = int(text[12:14])
    return 1 <= month <= 12 and 1 <= day <= 31


def _validate_cn_id_15(digits: str) -> bool:
    """中国 15 位身份证（旧版）：地区码 + 日期基本合法性。"""
    if len(digits) != 15 or not digits.isdigit():
        return False
    month = int(digits[8:10])
    day = int(digits[10:12])
    return 1 <= month <= 12 and 1 <= day <= 31


def _validate_passport(text: str) -> bool:
    """护照号：首字母白名单 + 8 位数字。"""
    if len(text) != 9:
        return False
    return text[0].upper() in "EGDPHMC" and text[1:].isdigit()


# ── 验证路由：(attr_type, priority, validator) ──

_ValidatorEntry = tuple[PIIAttributeType, int, str]


def _route_validators(digits: str, text: str, fragment_type: str) -> _ValidatorEntry | None:
    """按位数路由到验证器，返回 (attr_type, priority, source_kind) 或 None。"""
    n = len(digits)
    hits: list[_ValidatorEntry] = []

    # 中国手机号：11 位
    if n == 11 and _validate_cn_phone(digits):
        hits.append((PIIAttributeType.PHONE, 118, "validated_phone_cn"))

    # 美国电话：10 位
    if n == 10 and _validate_us_phone(digits):
        hits.append((PIIAttributeType.PHONE, 117, "validated_phone_us"))

    # 中国身份证：18 位（含末位 X）
    if n == 18 or (len(text) == 18 and text[:17].isdigit() and text[17].upper() == "X"):
        id_text = text if len(text) == 18 else digits
        if _validate_cn_id_18(id_text):
            hits.append((PIIAttributeType.ID_NUMBER, 115, "validated_id_cn_18"))

    # 中国身份证：15 位（旧版）
    if n == 15 and _validate_cn_id_15(digits):
        hits.append((PIIAttributeType.ID_NUMBER, 113, "validated_id_cn_15"))

    # 银行卡 PAN：13-19 位 Luhn
    if 13 <= n <= 19 and _luhn_valid(digits):
        hits.append((PIIAttributeType.CARD_NUMBER, 114, "validated_card_pan"))

    # 银行账号：12-22 位 Luhn（宽范围）
    if 12 <= n <= 22 and _luhn_valid_wide(digits):
        hits.append((PIIAttributeType.BANK_ACCOUNT, 110, "validated_bank_account"))

    # 护照号：ALNUM，9 字符，首字母白名单
    if fragment_type == "ALNUM" and _validate_passport(text):
        hits.append((PIIAttributeType.PASSPORT_NUMBER, 108, "validated_passport"))

    # 驾照：12 位纯数字
    if n == 12 and fragment_type == "NUM":
        hits.append((PIIAttributeType.DRIVER_LICENSE, 106, "validated_driver_license_cn"))

    if not hits:
        return None
    # 取最高优先级。
    hits.sort(key=lambda h: -h[1])
    return hits[0]


def _try_phone_candidate(text: str) -> _ValidatorEntry | None:
    """电话候选片段：去格式化后尝试识别国际区号 + 本地号码。"""
    digits = re.sub(r"\D", "", text)
    if not digits:
        return None

    # 先尝试带区号匹配。
    for prefix, local_len in _COUNTRY_CODE_PREFIXES:
        if digits.startswith(prefix):
            local = digits[len(prefix):]
            if len(local) == local_len:
                if prefix == "86" and _validate_cn_phone(local):
                    return (PIIAttributeType.PHONE, 118, "validated_phone_cn")
                if prefix == "1" and _validate_us_phone(local):
                    return (PIIAttributeType.PHONE, 117, "validated_phone_us")

    # 无区号，直接按总位数验证。
    if len(digits) == 11 and _validate_cn_phone(digits):
        return (PIIAttributeType.PHONE, 118, "validated_phone_cn")
    if len(digits) == 10 and _validate_us_phone(digits):
        return (PIIAttributeType.PHONE, 117, "validated_phone_us")

    return None


class NumericFragmentStack(BaseStack):
    """数字/混合片段验证 stack。

    接收 scanner 提取的 NUMERIC / OTHER 候选片段，按位数路由到验证器：
    1. 电话候选优先处理（带 fragment_hint="phone_candidate"）。
    2. 通用位数路由（手机/身份证/银行卡/护照/驾照）。
    3. 验证通过 → 修改 attr_type 为具体类型。
    4. 未通过 → 保留原始 NUMERIC / OTHER 类型，由后续 label 或兜底标签处理。
    """

    def run(self) -> StackRun | None:
        if self.clue.role != ClueRole.HARD:
            # 非 HARD clue 尝试走 label 绑定（与 StructuredBaseStack 一致）。
            if self.clue.role == ClueRole.LABEL:
                return self._try_label_bind()
            return None

        metadata = dict(self.clue.source_metadata)
        fragment_type = (metadata.get("fragment_type") or ["NUM"])[0]
        pure_digits = (metadata.get("pure_digits") or [re.sub(r"\D", "", self.clue.text)])[0]
        fragment_hint = (metadata.get("fragment_hint") or [None])[0]

        result: _ValidatorEntry | None = None

        # 电话候选优先处理。
        if fragment_hint == "phone_candidate":
            result = _try_phone_candidate(self.clue.text)

        # 通用位数路由。
        if result is None:
            result = _route_validators(pure_digits, self.clue.text, fragment_type)

        candidate = _build_hard_candidate(self.clue, self.context.stream.source)

        if result is not None:
            attr_type, priority, source_kind = result
            candidate.attr_type = attr_type
            candidate.source_kind = source_kind
            candidate.metadata = merge_metadata(
                candidate.metadata,
                {"validated_by": [source_kind], "original_fragment_type": [fragment_type]},
            )
            return StackRun(
                attr_type=attr_type,
                candidate=candidate,
                consumed_ids={self.clue.clue_id},
                next_index=self.clue_index + 1,
            )

        # 未通过验证 → 保留原始类型。
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
        )

    def _try_label_bind(self) -> StackRun | None:
        """label 绑定：查找后方的 HARD clue 并绑定。"""
        from privacyguard.infrastructure.pii.detector.stacks.common import is_control_clue
        from privacyguard.infrastructure.pii.rule_based_detector_shared import is_soft_break

        raw_text = self.context.stream.text
        cursor = self.clue.end
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if is_control_clue(clue):
                cursor = max(cursor, clue.end)
                continue
            gap_text = raw_text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return None
            if clue.role == ClueRole.HARD and clue.attr_type == self.clue.attr_type:
                candidate = _build_hard_candidate(clue, self.context.stream.source)
                candidate.label_clue_ids.add(self.clue.clue_id)
                candidate.metadata = merge_metadata(
                    candidate.metadata,
                    {"bound_label_clue_ids": [self.clue.clue_id]},
                )
                return StackRun(
                    attr_type=candidate.attr_type,
                    candidate=candidate,
                    consumed_ids={self.clue.clue_id, clue.clue_id},
                    handled_label_clue_ids={self.clue.clue_id},
                    next_index=index + 1,
                )
            if clue.role in {ClueRole.LABEL, ClueRole.HARD} and clue.attr_type != self.clue.attr_type:
                return None
            cursor = max(cursor, clue.end)
        return None
