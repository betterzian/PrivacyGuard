"""英文地址 NormalizedPII 归一测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.utils.normalized_pii import normalize_pii, same_entity


def test_english_address_normalization_keeps_full_hierarchy_components():
    normalized = normalize_pii(
        PIIAttributeType.ADDRESS,
        "1200 Harbor Ave, North Plaza, Apt 7B, Floor 12, Room 1203, San Diego, CA 92101",
        components={
            "province": "CA",
            "city": "San Diego",
            "road": "Harbor Ave",
            "compound": "North Plaza",
            "unit": "Apt 7B",
            "floor": "Floor 12",
            "room": "Room 1203",
            "postal_code": "92101",
        },
    )

    assert normalized.raw_text == "1200 Harbor Ave, North Plaza, Apt 7B, Floor 12, Room 1203, San Diego, CA 92101"
    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Ave",
        "compound": "North Plaza",
        "unit": "Apt 7B",
        "floor": "Floor 12",
        "room": "Room 1203",
        "postal_code": "92101",
    }
    assert normalized.canonical == (
        "province=ca|city=sandiego|road=harborave|compound=northplaza|"
        "unit=apt7b|floor=floor12|room=room1203|postal_code=92101|number=[7B,12,1203]"
    )
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Ave", "North Plaza")
    assert normalized.identity["address_part"] == "ca|sandiego|harborave|northplaza"
    assert normalized.identity["details_part"] == "7-12-1203"


def test_english_address_same_entity_accepts_hierarchy_subset_and_detail_subsequence():
    left = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "province": "California",
            "city": "San Diego",
            "road": "Harbor Avenue",
            "compound": "North Plaza",
            "unit": "Apt 7B",
            "floor": "Floor 12",
            "room": "Room 1203",
        },
    )
    right = normalize_pii(
        PIIAttributeType.ADDRESS,
        "",
        components={
            "province": "CA",
            "city": "San Diego",
            "road": "Harbor",
            "compound": "North",
            "floor": "12",
            "room": "1203",
        },
    )

    assert same_entity(left, right) is True


def test_ocr_address_component_trace_maps_alias_fields_and_prefers_longest_values():
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

    assert normalized.components == {
        "province": "CA",
        "city": "San Diego",
        "road": "Harbor Avenue",
        "compound": "North Plaza",
        "unit": "7B",
        "floor": "12",
        "room": "1203",
    }
    assert normalized.canonical == (
        "province=ca|city=sandiego|road=harboravenue|compound=northplaza|"
        "unit=7b|floor=12|room=1203|number=[7B,12,1203]"
    )
    assert normalized.match_terms == ("CA", "San Diego", "Harbor Avenue", "North Plaza")
    assert normalized.identity["details_part"] == "7-12-1203"
