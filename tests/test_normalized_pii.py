"""NormalizedPII 归一与实体判定测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


def test_phone_canonical_strips_supported_country_codes_only():
    zh = normalize_pii(PIIAttributeType.PHONE, "+86 138-0000-0001")
    us = normalize_pii(PIIAttributeType.PHONE, "+1 (202) 555-0111")
    keep = normalize_pii(PIIAttributeType.PHONE, "+44 20 7946 0958")

    assert zh.raw_text == "+86 138-0000-0001"
    assert zh.canonical == "13800000001"
    assert us.canonical == "2025550111"
    assert keep.canonical == "442079460958"


def test_email_keeps_raw_text_and_only_changes_canonical():
    normalized = normalize_pii(PIIAttributeType.EMAIL, "A.b+c @Example.com")

    assert normalized.raw_text == "A.b+c @Example.com"
    assert normalized.canonical == "a.b+c@example.com"
    assert normalized.match_terms == ("a.b+c@example.com",)


def test_organization_canonical_reuses_company_suffix_lexicon():
    normalized = normalize_pii(PIIAttributeType.ORGANIZATION, "想的美工作室")

    assert normalized.raw_text == "想的美工作室"
    assert normalized.canonical == "想的美"


def test_name_alias_is_independent_component_and_not_part_of_identity():
    normalized = normalize_pii(
        PIIAttributeType.NAME,
        "张三",
        components={"full": "张三", "family": "张", "given": "三", "alias": "阿三"},
    )

    assert normalized.components == {"full": "张三", "family": "张", "given": "三", "alias": "阿三"}
    assert normalized.match_terms == ("张三", "张", "三", "阿三")
    assert normalized.identity == {"family": "张", "given": "三"}


def test_address_normalization_prefers_metadata_components():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "上海市浦东新区阳光国际社区三期10栋一单元102室",
        metadata={
            "address_component_trace": [
                "city:上海",
                "district:浦东",
                "poi:阳光国际",
                "building:10",
                "detail:102",
            ]
        },
    )

    assert normalized.components == {
        "city": "上海",
        "district": "浦东",
        "poi": "阳光国际",
        "building": "10",
        "detail": "102",
    }
    assert normalized.canonical == "city=上海|district=浦东|poi=阳光国际|building=10|detail=102|number=[10,102]"
    assert normalized.match_terms == ("上海", "浦东", "阳光国际")
    assert normalized.identity["address_part"] == "上海|浦东|阳光国际"
    assert normalized.identity["details_part"] == "10-102"
    assert [
        (component.component_type, component.value, component.key, component.suspected)
        for component in normalized.ordered_components
    ] == [
        ("city", "上海", "", {}),
        ("district", "浦东", "", {}),
        ("poi", "阳光国际", "", {}),
        ("building", "10", "", {}),
        ("detail", "102", "", {}),
    ]


def test_address_ordered_components_from_components_follow_fixed_order():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "city": "上海",
            "district": "浦东",
            "road": "中山",
            "number": "1",
            "subdistrict": "花木街道",
            "poi": "阳光国际",
        },
    )

    assert [component.component_type for component in normalized.ordered_components] == [
        "city",
        "district",
        "road",
        "number",
        "subdistrict",
        "poi",
    ]


def test_address_same_entity_accepts_local_admin_cross_field_and_detail_subsequence():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "city": "上海",
            "district": "浦东新区",
            "subdistrict": "唐镇",
            "poi": "阳光国际",
            "building": "10",
            "detail": "102",
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "city": "上海",
            "district": "浦东",
            "subdistrict": "唐镇街道",
            "poi": "阳光",
            "building": "10",
            "detail": "102",
        },
    )

    assert same_entity(left, right) is True


def test_address_same_entity_only_uses_current_component_suspected():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "北京中山路阳光小区",
        metadata={
            "address_component_trace": ["road:中山", "poi:阳光"],
            "address_component_key_trace": ["road:路", "poi:小区"],
            "address_component_suspected": ["city:北京", ""],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "上海中山路阳光小区",
        metadata={
            "address_component_trace": ["city:上海", "road:中山", "poi:阳光"],
            "address_component_key_trace": ["road:路", "poi:小区"],
            "address_component_suspected": ["", "", "city:北京"],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_keeps_number_match_when_building_prefix_is_missing():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "10号楼2楼102室",
        metadata={
            "address_component_trace": ["building:10", "detail:2", "detail:102"],
            "address_component_key_trace": ["building:号楼", "detail:楼", "detail:室"],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "2楼102室",
        metadata={
            "address_component_trace": ["detail:2", "detail:102"],
            "address_component_key_trace": ["detail:楼", "detail:室"],
        },
    )

    assert left.numbers == ("10", "2", "102")
    assert right.numbers == ("2", "102")
    assert same_entity(left, right) is True


def test_bank_number_canonical_keeps_digits_only():
    normalized = normalize_pii(PIIAttributeType.BANK_NUMBER, "6222 0000 1234 5678")

    assert normalized.raw_text == "6222 0000 1234 5678"
    assert normalized.canonical == "6222000012345678"
    assert normalized.match_terms == ("6222000012345678",)


def test_alnum_canonical_keeps_uppercase_letters_and_digits_only():
    normalized = normalize_pii(PIIAttributeType.ALNUM, "ab-12 cd")

    assert normalized.raw_text == "ab-12 cd"
    assert normalized.canonical == "AB12CD"
    assert normalized.match_terms == ("AB12CD",)
