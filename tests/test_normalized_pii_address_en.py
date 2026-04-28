"""英文地址 NormalizedPII 归一测试。"""

from __future__ import annotations

import pytest

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


def test_english_address_normalization_uses_number_and_precise_components():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "1200 Harbor Ave, North Plaza, Apt 7B, Floor 12, San Diego, CA",
        components={
            "province": "CA",
            "city": "San Diego",
            "road": "Harbor Ave",
            "number": "1200",
            "poi": "North Plaza",
            "unit": "Apt 7B",
            "detail": "Floor 12",
        },
    )

    assert normalized.raw_text == "1200 Harbor Ave, North Plaza, Apt 7B, Floor 12, San Diego, CA"
    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Ave",
        "number": "1200",
        "poi": "North Plaza",
        "unit": "Apt 7B",
        "detail": "Floor 12",
    }
    assert normalized.canonical == (
        "province=CA|city=sandiego|road=harborave|number=1200|poi=northplaza|unit=7b|detail=12"
    )
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Ave", "North Plaza")
    assert normalized.identity["number"] == "1200"
    assert normalized.identity["unit"] == "7b"
    assert normalized.identity["detail"] == "12"
    assert normalized.numbers == ()
    assert "details_part" not in normalized.identity


def test_english_address_same_entity_accepts_state_country_aliases_and_house_number_alias():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "country": "United States",
            "province": "California",
            "city": "San Diego",
            "road": "Harbor Avenue",
            "house_number": "1200",
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "country": "USA",
            "province": "CA",
            "city": "San Diego",
            "road": "Harbor Ave",
            "house_number": "1200",
        },
    )

    assert left.components["number"] == "1200"
    assert "house_number" not in left.components
    assert same_entity(left, right) is True


def test_english_address_same_entity_rejects_number_or_postal_conflict():
    base = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "country": "US",
            "province": "CA",
            "city": "Mountain View",
            "road": "Amphitheatre Parkway",
            "house_number": "1600",
            "postal_code": "94043",
        },
    )
    different_house_number = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "country": "USA",
            "province": "California",
            "city": "Mountain View",
            "road": "Amphitheatre Parkway",
            "house_number": "1601",
            "postal_code": "94043",
        },
    )
    different_postal = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "country": "United States",
            "province": "CA",
            "city": "Mountain View",
            "road": "Amphitheatre Parkway",
            "house_number": "1600",
            "postal_code": "94044",
        },
    )

    assert same_entity(base, different_house_number) is False
    assert same_entity(base, different_postal) is False


@pytest.mark.parametrize(
    ("left_extra", "right_extra", "expected_same"),
    [
        ({"unit": "Apt 205"}, {"unit": "Unit 205"}, True),
        ({"unit": "Apt 205"}, {"unit": "#205"}, True),
        ({"unit": "Apt 205"}, {"room": "Room 205"}, False),
        ({"unit": "Apt 205"}, {"suite": "Suite 205"}, False),
        ({"unit": "Apt 205"}, {"building": "Building 205"}, False),
    ],
)
def test_english_address_same_entity_respects_precise_component_slots(left_extra, right_extra, expected_same):
    base = {
        "province": "WA",
        "city": "Bellevue",
        "road": "Main Street",
        "number": "5176",
        "postal_code": "59060",
    }
    left = normalize_pii(PIIAttributeType.ADDRESS, "", components={**base, **left_extra})
    right = normalize_pii(PIIAttributeType.ADDRESS, "", components={**base, **right_extra})

    assert same_entity(left, right) is expected_same


def test_english_precise_components_do_not_fall_back_to_fuzzy_numbers():
    base = {
        "province": "WA",
        "city": "Bellevue",
        "road": "Main Street",
        "number": "5176",
        "postal_code": "59060",
    }
    suite_300 = normalize_pii(PIIAttributeType.ADDRESS, "", components={**base, "suite": "Suite 300"})
    suite_320 = normalize_pii(PIIAttributeType.ADDRESS, "", components={**base, "suite": "Suite 320"})

    assert suite_300.numbers == ()
    assert suite_320.numbers == ()
    assert same_entity(suite_300, suite_320) is False


def test_ocr_address_component_trace_maps_alias_fields_to_precise_components():
    """旧 trace 中的 state/street/compound/unit/floor/room 应通过别名映射为新类型。"""
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "CA, San Diego, 1200 Harbor Avenue, North Plaza, Apt 7B, Floor 12, Room 1203",
        metadata={
            "address_component_trace": [
                "state:CA",
                "city:San Diego",
                "street:Harbor Ave",
                "road:Harbor Avenue",
                "compound:North",
                "compound:North Plaza",
                "unit:7B",
                "floor:12",
                "room:1203",
                "ignored-entry",
                "unknown:shadow",
            ],
            "address_details_text": ["7B", "12", "1203"],
        },
    )

    # state→province，street/road→road(取最长)，compound→poi，unit/floor/room 各自落到新 schema。
    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Avenue",
        "poi": "North Plaza",
        "unit": "7B",
        "room": "1203",
        "detail": "12",
    }
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Avenue", "North Plaza")
    assert normalized.identity["unit"] == "7b"
    assert normalized.identity["room"] == "1203"
    assert normalized.identity["detail"] == "12"
    assert "details_part" not in normalized.identity


def test_structured_number_matches_detector_number_metadata():
    structured = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "number": "5176",
            "road": "Main Street",
            "city": "Bellevue",
            "province": "WA",
            "postal_code": "59060",
        },
    )
    detected = normalize_pii(
        PIIAttributeType.ADDRESS,
        "5176 Main Street, Bellevue, WA 59060",
        metadata={
            "address_component_trace": [
                "number:5176",
                "road:Main",
                "city:Bellevue",
                "province:WA",
                "postal_code:59060",
            ],
            "address_component_key_trace": ["road:Street"],
        },
    )

    assert same_entity(structured, detected) is True
