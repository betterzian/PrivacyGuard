from __future__ import annotations

import json
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord
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
                        "name": [{"value": "Alice Johnson", "aliases": []}],
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
    assert address_candidate.text == "123 Main St Apt 4B"
    assert address_candidate.confidence == 0.9
    assert address_candidate.metadata["matched_by"] == ["context_address_field"]


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
