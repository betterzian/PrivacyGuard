"""英文地址 NormalizedPII 归一测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


def test_english_address_normalization_keeps_full_hierarchy_components():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "1200 Harbor Ave, North Plaza, Apt 7B, San Diego, CA",
        components={
            "province": "CA",
            "city": "San Diego",
            "road": "Harbor Ave",
            "poi": "North Plaza",
            "detail": "Apt 7B",
        },
    )

    assert normalized.raw_text == "1200 Harbor Ave, North Plaza, Apt 7B, San Diego, CA"
    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Ave",
        "poi": "North Plaza",
        "detail": "Apt 7B",
    }
    assert normalized.canonical == (
        "province=CA|city=sandiego|road=harborave|poi=northplaza|"
        "detail=apt7b|number=[7B]"
    )
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Ave", "North Plaza")
    assert normalized.identity["address_part"] == "CA|sandiego|harborave|northplaza"
    assert normalized.identity["details_part"] == "7"


def test_english_address_same_entity_accepts_state_and_country_aliases():
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

    assert same_entity(left, right) is True


def test_english_address_same_entity_rejects_house_number_or_postal_conflict():
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


def test_ocr_address_component_trace_maps_alias_fields_and_prefers_longest_values():
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

    # state→province, street/road→road(取最长), compound→poi, unit/floor/room→detail(取最长)
    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Avenue",
        "poi": "North Plaza",
        "detail": "1203",
    }
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Avenue", "North Plaza")
