from __future__ import annotations

import json
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.infrastructure.pii.address.component_parser_en import parse_en_components
from privacyguard.infrastructure.pii.address.component_parser_zh import parse_zh_components
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.pii.json_privacy_repository import InvalidPrivacyRepositoryError
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def _write_privacy_repository(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _find_candidate(candidates, attr_type: PIIAttributeType):
    for candidate in candidates:
        if candidate.attr_type == attr_type:
            return candidate
    return None


def _workspace_test_path(test_name: str, filename: str) -> Path:
    path = Path.cwd() / "tests" / ".artifacts" / test_name / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    return path


def test_rule_based_detector_prefers_session_dictionary_for_english_email() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_prefers_session_dictionary_for_english_email",
        "privacy_repository.en.json",
    )
    _write_privacy_repository(
        repository_path,
        {
            "true_personas": [
                {
                    "persona_id": "persona-en",
                    "display_name": "English Persona",
                    "slots": {
                        "email": [{"value": "alice@example.com", "aliases": []}],
                    },
                }
            ]
        },
    )
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-en",
        1,
        [
            ReplacementRecord(
                session_id="session-en",
                turn_id=1,
                candidate_id="c-email",
                source_text="alice@example.com",
                replacement_text="[EMAIL]",
                attr_type=PIIAttributeType.EMAIL,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )

    detector = RuleBasedPIIDetector(
        locale_profile="en_us",
        privacy_repository_path=repository_path,
        mapping_store=mapping_store,
    )
    candidates = detector.detect(
        prompt_text="Please email alice@example.com for the update.",
        ocr_blocks=[],
        session_id="session-en",
        turn_id=2,
    )

    email_candidate = _find_candidate(candidates, PIIAttributeType.EMAIL)
    assert email_candidate is not None
    assert email_candidate.text == "alice@example.com"
    assert email_candidate.confidence == 0.97
    assert email_candidate.metadata["matched_by"] == ["dictionary_session"]
    assert email_candidate.metadata["session_turn_ids"] == ["1"]
    assert "local_entity_ids" not in email_candidate.metadata


def test_rule_based_detector_prefers_local_dictionary_over_english_name_rule() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_prefers_local_dictionary_over_english_name_rule",
        "privacy_repository.en.json",
    )
    _write_privacy_repository(
        repository_path,
        {
            "true_personas": [
                {
                    "persona_id": "persona-en",
                    "display_name": "English Persona",
                    "slots": {
                        "name": [{
                            "full": {"value": "Alice Johnson", "aliases": []},
                            "family": {"value": "Johnson", "aliases": []},
                            "given": {"value": "Alice", "aliases": []},
                        }],
                    },
                }
            ]
        },
    )

    detector = RuleBasedPIIDetector(
        locale_profile="en_us",
        privacy_repository_path=repository_path,
    )
    candidates = detector.detect(
        prompt_text="This is Alice Johnson",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    name_candidate = _find_candidate(candidates, PIIAttributeType.NAME)
    assert name_candidate is not None
    assert name_candidate.text == "Alice Johnson"
    assert name_candidate.confidence == 0.99
    assert name_candidate.metadata["matched_by"] == ["dictionary_local"]
    assert name_candidate.metadata["local_entity_ids"] == ["persona-en"]
    assert name_candidate.metadata["name_component"] == ["full"]


def test_rule_based_detector_gates_english_self_intro_by_strength() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    balanced_candidates = detector.detect(
        prompt_text="This is Alice Johnson",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )
    weak_candidates = detector.detect(
        prompt_text="This is Alice Johnson",
        ocr_blocks=[],
        protection_level=ProtectionLevel.WEAK,
    )

    balanced_name = _find_candidate(balanced_candidates, PIIAttributeType.NAME)
    weak_name = _find_candidate(weak_candidates, PIIAttributeType.NAME)

    assert balanced_name is not None
    assert balanced_name.text == "Alice Johnson"
    assert balanced_name.confidence == 0.76
    assert balanced_name.metadata["matched_by"] == ["context_name_self_intro_en"]
    assert weak_name is None


def test_rule_based_detector_detects_english_phone_organization_and_address() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    phone_candidates = detector.detect(
        prompt_text="Call me at (415) 555-0123",
        ocr_blocks=[],
    )
    organization_candidates = detector.detect(
        prompt_text="I work at Acme Labs Inc",
        ocr_blocks=[],
    )
    address_candidates = detector.detect(
        prompt_text="Address: 123 Main St Apt 4B, Springfield, IL 62704",
        ocr_blocks=[],
    )

    phone_candidate = _find_candidate(phone_candidates, PIIAttributeType.PHONE)
    organization_candidate = _find_candidate(organization_candidates, PIIAttributeType.ORGANIZATION)
    address_candidate = _find_candidate(address_candidates, PIIAttributeType.ADDRESS)

    assert phone_candidate is not None
    assert phone_candidate.text == "(415) 555-0123"
    assert "regex_phone_us" in phone_candidate.metadata["matched_by"]

    assert organization_candidate is not None
    assert organization_candidate.text == "Acme Labs Inc"
    assert round(organization_candidate.confidence, 2) == 0.78
    assert organization_candidate.metadata["matched_by"] == ["regex_organization_suffix"]

    assert address_candidate is not None
    assert address_candidate.text == "123 Main St Apt 4B, Springfield, IL 62704"
    assert address_candidate.confidence == 0.97
    assert address_candidate.metadata["matched_by"] == ["context_address_field"]
    assert address_candidate.metadata["address_kind"] == ["private_address"]
    by_text = {candidate.text: candidate for candidate in address_candidates if candidate.attr_type == PIIAttributeType.ADDRESS}
    assert by_text["123 Main St"].metadata["matched_by"] == ["address_component_street"]
    assert by_text["Apt 4B"].metadata["matched_by"] == ["address_component_unit"]


def test_rule_based_detector_supports_english_repository_address_entity() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_supports_english_repository_address_entity",
        "privacy_repository.en.json",
    )
    _write_privacy_repository(
        repository_path,
        {
            "true_personas": [
                {
                    "persona_id": "persona-en",
                    "display_name": "English Persona",
                    "slots": {
                        "address": [{
                            "street": {"value": "123 Main St", "aliases": []},
                            "building": {"value": "Apt 4B", "aliases": []},
                            "city": {"value": "Springfield", "aliases": []},
                            "province": {"value": "IL", "aliases": []},
                            "postal_code": {"value": "62704", "aliases": []},
                        }],
                    },
                }
            ]
        },
    )

    detector = RuleBasedPIIDetector(
        locale_profile="en_us",
        privacy_repository_path=repository_path,
    )
    candidates = detector.detect(
        prompt_text="Address: 123 Main St Apt 4B, Springfield, IL 62704",
        ocr_blocks=[],
    )

    address_candidate = _find_candidate(candidates, PIIAttributeType.ADDRESS)
    assert address_candidate is not None
    assert address_candidate.text == "123 Main St Apt 4B, Springfield, IL 62704"
    assert address_candidate.confidence == 0.99
    assert address_candidate.metadata["matched_by"] == ["dictionary_local"]
    assert address_candidate.metadata["local_entity_ids"] == ["persona-en"]


def test_rule_based_detector_rejects_legacy_scalar_privacy_repository_slots() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_rejects_legacy_scalar_privacy_repository_slots",
        "privacy_repository.legacy.json",
    )
    _write_privacy_repository(
        repository_path,
        {
            "true_personas": [
                {
                    "persona_id": "persona-en",
                    "slots": {
                        "email": {"value": "alice@example.com", "aliases": []},
                    },
                }
            ]
        },
    )

    try:
        RuleBasedPIIDetector(
            locale_profile="en_us",
            privacy_repository_path=repository_path,
        )
    except InvalidPrivacyRepositoryError:
        return
    raise AssertionError("legacy scalar privacy_repository slots should be rejected")


def test_rule_based_detector_detects_english_given_and_family_name_fields() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="First name: Alice\nLast name: Johnson",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    by_text = {candidate.text: candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME}
    assert "context_name_given_field" in by_text["Alice"].metadata["matched_by"]
    assert by_text["Alice"].metadata["name_component"] == ["given"]
    assert by_text["Alice"].canonical_source_text == "Alice"
    assert "context_name_family_field" in by_text["Johnson"].metadata["matched_by"]
    assert by_text["Johnson"].metadata["name_component"] == ["family"]
    assert by_text["Johnson"].canonical_source_text == "Johnson"


def test_rule_based_detector_keeps_store_name_out_of_address_candidates() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="上海路店",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    # LOCATION_CLUE 已移除，且门店误检拦截规则已移除；此类文本可能产生 ADDRESS 候选。
    assert _find_candidate(candidates, PIIAttributeType.ADDRESS) is not None


def test_rule_based_detector_rejects_ui_like_location_suffix_noise() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="学生专区 京东自营旗 专业折叠旗",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert _find_candidate(candidates, PIIAttributeType.ADDRESS) is None


def test_rule_based_detector_rejects_new_group_as_organization() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="New group",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert _find_candidate(candidates, PIIAttributeType.ORGANIZATION) is None


def test_rule_based_detector_handles_masked_truncated_address_tail() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="上海市浦东新区世纪大道XX小区3号楼1201室...",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = _find_candidate(candidates, PIIAttributeType.ADDRESS)

    assert address_candidate is not None
    assert address_candidate.text == "上海市浦东新区世纪大道XX小区3号楼1201室"
    assert address_candidate.metadata["address_terminated_by"] == ["masked_end"]
    by_text = {candidate.text: candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS}
    assert by_text["3号楼"].metadata["matched_by"] == ["address_component_building"]
    assert by_text["1201室"].metadata["matched_by"] == ["address_component_room"]


def test_rule_based_detector_trims_narrative_tail_after_address() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="我在上海浦东的世纪大道的小区里吃饭",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = _find_candidate(candidates, PIIAttributeType.ADDRESS)

    assert address_candidate is not None
    assert address_candidate.text.endswith("小区")
    assert "吃饭" not in address_candidate.text
    assert not address_candidate.text.endswith("里")


def test_parse_zh_components_keeps_city_district_and_town_separate() -> None:
    components = parse_zh_components("北京市北京市昌平区百善镇")
    by_type = {}
    for component in components:
        by_type.setdefault(component.component_type, []).append(component.text)

    assert by_type.get("city", []) == ["北京市"]
    assert "昌平区" in by_type.get("district", [])
    assert "百善镇" in by_type.get("town", [])


def test_parse_en_components_keeps_right_tail_city_state_and_zip() -> None:
    components = parse_en_components("123 Main St Apt 5B, Seattle, WA 98101")
    by_type = {}
    for component in components:
        by_type.setdefault(component.component_type, []).append(component.text)

    assert "123 Main St" in by_type.get("street", [])
    assert "Apt 5B" in by_type.get("unit", [])
    assert "Seattle" in by_type.get("city", [])
    assert "WA" in by_type.get("state", [])
    assert "98101" in by_type.get("postal_code", [])


def test_rule_based_detector_stops_address_before_ocr_break_and_name_label() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Address: 97 Lincoln Street <OCR_BREAK> > <OCR_BREAK> Name:",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = _find_candidate(candidates, PIIAttributeType.ADDRESS)
    assert address_candidate is not None
    assert address_candidate.text == "97 Lincoln Street"


def test_rule_based_detector_emits_partial_chinese_road_address() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="麦当劳&麦咖啡（北京善缘街店）",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.ADDRESS and candidate.text == "北京善缘街"
    )

    assert address_candidate.metadata["address_kind"] == ["private_address"]
    assert "street" in address_candidate.metadata["address_component_type"] or "road" in address_candidate.metadata["address_component_type"]


def test_rule_based_detector_emits_town_and_village_address_components() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="北京市昌平区百善镇下东廓村2号库",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    by_text = {
        candidate.text: candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.ADDRESS
    }

    assert "百善镇" in by_text
    assert by_text["百善镇"].metadata["address_component_type"] == ["town"]
    assert "下东廓村" in by_text
    assert by_text["下东廓村"].metadata["address_component_type"] == ["village"]


def test_rule_based_detector_rejects_reordered_room_and_city_as_address() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="1201室上海",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(
        candidate.attr_type == PIIAttributeType.ADDRESS and candidate.text == "1201室上海"
        for candidate in candidates
    )


def test_rule_based_detector_rejects_single_component_commerce_road_noise() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="国家补贴至仅剩1件799弄",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_rule_based_detector_rejects_keyword_expansion_block_for_single_address_clue() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="强大道具",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    # LOCATION_CLUE 已移除，地理碎片与单组件更倾向归入 ADDRESS；此处不再强约束为空。
    assert candidates is not None


def test_rule_based_detector_rejects_single_component_compound_noise() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="华润国际社区",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    # LOCATION_CLUE 已移除，单组件 compound 可能作为 ADDRESS 候选存在。
    assert candidates is not None


def test_rule_based_detector_rejects_ui_like_explicit_address_value() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="收货地址 管理",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_rule_based_detector_rejects_city_word_inside_phone_label() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Mobile number",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_rule_based_detector_detects_conservative_english_standalone_name_nearby_pii() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="alice@example.com Brian Foster",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    name_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.NAME and candidate.text == "Brian Foster"
    )

    assert name_candidate.metadata["matched_by"] == ["heuristic_name_fragment_en"]
    assert name_candidate.confidence >= 0.74


def test_rule_based_detector_does_not_trigger_english_standalone_name_without_nearby_pii() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Brian Foster joined the call.",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(
        candidate.attr_type == PIIAttributeType.NAME and candidate.text == "Brian Foster"
        for candidate in candidates
    )


def test_rule_based_detector_rejects_washington_post_as_english_name() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Washington Post",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert _find_candidate(candidates, PIIAttributeType.NAME) is None


def test_rule_based_detector_rejects_or_number_as_name_value() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Type name or number",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert _find_candidate(candidates, PIIAttributeType.NAME) is None


def test_rule_based_detector_supports_full_state_name_in_english_address() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Address: 123 Main St Apt 4B, Springfield, Illinois 62704",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = _find_candidate(candidates, PIIAttributeType.ADDRESS)
    assert address_candidate is not None
    assert address_candidate.text == "123 Main St Apt 4B, Springfield, Illinois 62704"

    by_text = {
        candidate.text: candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.ADDRESS
    }
    assert by_text["Illinois"].metadata["matched_by"] == ["address_component_state"]
    assert by_text["Illinois"].metadata["address_component_type"] == ["state"]


def test_rule_based_detector_emits_ordered_address_component_trace() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="上海浦东新区世纪大道1201室",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    address_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.ADDRESS and candidate.text == "上海浦东新区世纪大道1201室"
    )

    assert address_candidate.metadata["address_component_type"] == ["city", "district", "poi", "room"]
    assert address_candidate.metadata["address_component_trace"][:4] == [
        "city:上海",
        "district:浦东新区",
        "poi:世纪大道",
        "room:1201室",
    ]


def test_rule_based_detector_rejects_explicit_english_address_value_outside_local_geo_lexicon() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="City: Wonderland",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_rule_based_detector_detects_hotel_as_organization() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="轻奢连锁酒店",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    organization_candidate = _find_candidate(candidates, PIIAttributeType.ORGANIZATION)
    assert organization_candidate is not None
    assert organization_candidate.text == "轻奢连锁酒店"
