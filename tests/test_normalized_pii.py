"""NormalizedPII 归一与实体判定测试。"""

from __future__ import annotations

import json

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


def _suspected_json(*entries: dict[str, object]) -> str:
    return json.dumps(list(entries), ensure_ascii=False, separators=(",", ":"))


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
        ("city", "上海", "", ()),
        ("district", "浦东", "", ()),
        ("poi", "阳光国际", "", ()),
        ("building", "10", "", ()),
        ("detail", "102", "", ()),
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
            "address_component_suspected": [
                _suspected_json({"levels": ["city"], "value": "北京", "key": "", "origin": "value"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "上海中山路阳光小区",
        metadata={
            "address_component_trace": ["city:上海", "road:中山", "poi:阳光"],
            "address_component_key_trace": ["road:路", "poi:小区"],
            "address_component_suspected": [
                "",
                "",
                _suspected_json({"levels": ["city"], "value": "北京", "key": "", "origin": "value"}),
            ],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_rejects_multi_level_suspect_group_when_earlier_real_level_conflicts():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路",
        metadata={
            "address_component_trace": ["road:中山"],
            "address_component_key_trace": ["road:路"],
            "address_component_suspected": [
                _suspected_json({"levels": ["city", "district"], "value": "朝阳", "key": "", "origin": "value"}),
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "北京市朝阳区中山路",
        metadata={
            "address_component_trace": ["city:北京", "district:朝阳", "road:中山"],
            "address_component_key_trace": ["road:路"],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_accepts_suspect_when_surface_matches_other_component_value():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "南京市中路1号",
        metadata={
            "address_component_trace": ["road:中", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["city"], "value": "南京", "key": "市", "origin": "key"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "南京市中路1号",
        metadata={
            "address_component_trace": ["road:南京市中", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
        },
    )

    assert same_entity(left, right) is True


def test_address_same_entity_accepts_when_same_level_suspect_value_matches():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "朝阳", "key": "", "origin": "value"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "朝阳", "key": "", "origin": "value"}),
                "",
            ],
        },
    )

    assert same_entity(left, right) is True


def test_address_same_entity_rejects_when_same_level_suspect_value_mismatches():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "朝阳", "key": "", "origin": "value"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "海淀中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "海淀", "key": "", "origin": "value"}),
                "",
            ],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_accepts_when_real_same_level_value_matches():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "朝阳", "key": "", "origin": "value"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["district:朝阳", "road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
        },
    )

    assert same_entity(left, right) is True


def test_address_same_entity_rejects_when_real_same_level_value_mismatches():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路1号",
        metadata={
            "address_component_trace": ["road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
            "address_component_suspected": [
                _suspected_json({"levels": ["district"], "value": "朝阳", "key": "", "origin": "value"}),
                "",
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "海淀中山路1号",
        metadata={
            "address_component_trace": ["district:海淀", "road:中山", "number:1"],
            "address_component_key_trace": ["road:路", "number:号"],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_rejects_multi_level_suspect_group_when_all_comparable_levels_fail():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路",
        metadata={
            "address_component_trace": ["road:中山"],
            "address_component_key_trace": ["road:路"],
            "address_component_suspected": [
                _suspected_json({"levels": ["city", "district"], "value": "朝阳", "key": "", "origin": "value"}),
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "北京市海淀区中山路",
        metadata={
            "address_component_trace": ["city:北京", "district:海淀", "road:中山"],
            "address_component_key_trace": ["road:路"],
        },
    )

    assert same_entity(left, right) is False


def test_address_same_entity_skips_multi_level_suspect_group_when_other_side_has_no_levels():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "朝阳中山路",
        metadata={
            "address_component_trace": ["road:中山"],
            "address_component_key_trace": ["road:路"],
            "address_component_suspected": [
                _suspected_json({"levels": ["city", "district"], "value": "朝阳", "key": "", "origin": "value"}),
            ],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "中山路",
        metadata={
            "address_component_trace": ["road:中山"],
            "address_component_key_trace": ["road:路"],
        },
    )

    assert same_entity(left, right) is True


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
    assert same_entity(left, right) is False


def test_address_numbers_normalize_control_value_and_ascii_mix():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "甲1楼",
        metadata={
            "address_component_trace": ["building:甲1"],
            "address_component_key_trace": ["building:楼"],
        },
    )

    assert normalized.numbers == ("甲1",)


def test_address_same_entity_matches_zh_number_and_digit_building():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "一楼",
        metadata={
            "address_component_trace": ["building:1"],
            "address_component_key_trace": ["building:楼"],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "1楼",
        metadata={
            "address_component_trace": ["building:1"],
            "address_component_key_trace": ["building:楼"],
        },
    )

    assert left.numbers == ("1",)
    assert right.numbers == ("1",)


def test_address_same_entity_distinguishes_heavenly_stem_mixed_number():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "甲1楼",
        metadata={
            "address_component_trace": ["building:甲1"],
            "address_component_key_trace": ["building:楼"],
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "乙1楼",
        metadata={
            "address_component_trace": ["building:乙1"],
            "address_component_key_trace": ["building:楼"],
        },
    )

    assert left.numbers == ("甲1",)
    assert right.numbers == ("乙1",)
    assert same_entity(left, right) is False


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
