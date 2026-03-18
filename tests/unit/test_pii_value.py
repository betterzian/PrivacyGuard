"""PII canonicalization 与 persona 替换辅助测试。"""

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.pii_value import canonicalize_pii_value, persona_slot_replacement


def test_canonicalize_name_removes_inner_spaces() -> None:
    assert canonicalize_pii_value(PIIAttributeType.NAME, "张 三") == "张三"


def test_canonicalize_address_normalizes_missing_province_suffix() -> None:
    left = canonicalize_pii_value(PIIAttributeType.ADDRESS, "四川省成都市")
    right = canonicalize_pii_value(PIIAttributeType.ADDRESS, "四川成都市")

    assert left == right


def test_persona_slot_replacement_truncates_address_to_source_granularity() -> None:
    full_slot = "广东省广州市天河区体育西路100号"

    assert persona_slot_replacement(PIIAttributeType.ADDRESS, "四川省", full_slot) == "广东省"
    assert persona_slot_replacement(PIIAttributeType.ADDRESS, "四川省成都市", full_slot) == "广东省广州市"
    assert persona_slot_replacement(PIIAttributeType.ADDRESS, "四川省成都市武侯区", full_slot) == "广东省广州市天河区"
