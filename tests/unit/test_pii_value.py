"""PII 值规范化与 persona 替换辅助函数的测试。"""

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.pii_value import canonicalize_pii_value, dictionary_match_variants, persona_slot_replacement


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


def test_dictionary_match_variants_keep_useful_road_aliases_without_generating_dirty_address_variants() -> None:
    variants = dictionary_match_variants(PIIAttributeType.ADDRESS, "深圳南山万科云城一期8栋")

    assert "城一期路" not in variants
    assert "城一期街" not in variants


def test_dictionary_match_variants_do_not_duplicate_district_prefix_for_full_road_address() -> None:
    variants = dictionary_match_variants(PIIAttributeType.ADDRESS, "北京市海淀区中关村东路66号")

    assert "海淀区中关村东路" in variants
    assert "海淀区北京市海淀区中关村东路" not in variants
