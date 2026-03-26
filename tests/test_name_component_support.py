from __future__ import annotations

import json
from pathlib import Path

from privacyguard.application.services.replacement_service import ReplacementService
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision import DecisionAction
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer
from privacyguard.utils.pii_value import build_match_text, canonicalize_pii_value


def _workspace_test_path(test_name: str, filename: str) -> Path:
    path = Path.cwd() / "tests" / ".artifacts" / test_name / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    return path


def test_json_persona_repository_replaces_name_components_with_source_order() -> None:
    repository_path = _workspace_test_path(
        "test_json_persona_repository_replaces_name_components_with_source_order",
        "persona_repository.name.json",
    )
    repository = JsonPersonaRepository(path=str(repository_path))
    repository.upsert_persona(
        PersonaProfile(
            persona_id="persona-en",
            display_name="English Persona",
            slots={
                PIIAttributeType.NAME: ["Jordan Demo"],
            },
        )
    )

    payload = json.loads(repository_path.read_text(encoding="utf-8"))
    stored_name = payload["fake_personas"][0]["slots"]["name"][0]
    assert stored_name["full"]["value"] == "Jordan Demo"
    assert stored_name["given"]["value"] == "Jordan"
    assert stored_name["family"]["value"] == "Demo"

    assert repository.get_slot_replacement_text("persona-en", PIIAttributeType.NAME, "Alice Johnson") == "Jordan Demo"
    assert repository.get_slot_replacement_text(
        "persona-en",
        PIIAttributeType.NAME,
        "Alice",
        metadata={"name_component": ["given"]},
    ) == "Jordan"
    assert repository.get_slot_replacement_text(
        "persona-en",
        PIIAttributeType.NAME,
        "Johnson",
        metadata={"name_component": ["family"]},
    ) == "Demo"
    assert repository.get_slot_replacement_text("persona-en", PIIAttributeType.NAME, "Johnson, Alice") == "Demo, Jordan"


def test_english_name_canonicalization_preserves_spaces() -> None:
    assert canonicalize_pii_value(PIIAttributeType.NAME, "Alice Johnson") == "alice johnson"
    assert canonicalize_pii_value(PIIAttributeType.NAME, "张 三") == "张三"

    match_text, index_map = build_match_text(PIIAttributeType.NAME, "Alice   Johnson")
    assert match_text == "alice johnson"
    assert len(index_map) == len(match_text)

    compact_match_text, _ = build_match_text(PIIAttributeType.NAME, "AliceJohnson")
    assert compact_match_text == "alicejohnson"
    assert compact_match_text != match_text


def test_rule_based_detector_matches_name_components_from_structured_dictionary() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_matches_name_components_from_structured_dictionary",
        "privacy_repository.name.json",
    )
    repository_path.write_text(
        json.dumps(
            {
                "true_personas": [
                    {
                        "persona_id": "persona-en",
                        "display_name": "English Persona",
                        "slots": {
                            "name": [
                                {
                                    "full": {"value": "Alice Johnson", "aliases": []},
                                    "family": {"value": "Johnson", "aliases": []},
                                    "given": {"value": "Alice", "aliases": []},
                                }
                            ],
                        },
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(
        locale_profile="en_us",
        privacy_repository_path=repository_path,
    )

    family_candidates = detector.detect(prompt_text="Johnson", ocr_blocks=[])
    given_candidates = detector.detect(prompt_text="Alice", ocr_blocks=[])

    family = next(candidate for candidate in family_candidates if candidate.attr_type == PIIAttributeType.NAME)
    given = next(candidate for candidate in given_candidates if candidate.attr_type == PIIAttributeType.NAME)

    assert family.metadata["matched_by"] == ["dictionary_local"]
    assert family.metadata["name_component"] == ["family"]
    assert family.metadata["local_entity_ids"] == ["persona-en"]
    assert given.metadata["matched_by"] == ["dictionary_local"]
    assert given.metadata["name_component"] == ["given"]
    assert given.metadata["local_entity_ids"] == ["persona-en"]


def test_rule_based_detector_does_not_treat_unspaced_english_full_name_as_dictionary_full_match() -> None:
    repository_path = _workspace_test_path(
        "test_rule_based_detector_does_not_treat_unspaced_english_full_name_as_dictionary_full_match",
        "privacy_repository.name.json",
    )
    repository_path.write_text(
        json.dumps(
            {
                "true_personas": [
                    {
                        "persona_id": "persona-en",
                        "display_name": "English Persona",
                        "slots": {
                            "name": [
                                {
                                    "full": {"value": "Alice Johnson", "aliases": []},
                                    "family": {"value": "Johnson", "aliases": []},
                                    "given": {"value": "Alice", "aliases": []},
                                }
                            ],
                        },
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(
        locale_profile="en_us",
        privacy_repository_path=repository_path,
    )

    candidates = detector.detect(prompt_text="AliceJohnson", ocr_blocks=[])

    assert not any(
        candidate.attr_type == PIIAttributeType.NAME
        and candidate.metadata.get("matched_by") == ["dictionary_local"]
        and candidate.metadata.get("name_component") == ["full"]
        for candidate in candidates
    )


def test_rule_based_detector_preserves_name_component_from_session_dictionary() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-name",
        1,
        [
            ReplacementRecord(
                session_id="session-name",
                turn_id=1,
                candidate_id="c-name",
                source_text="Johnson",
                canonical_source_text="Johnson",
                replacement_text="Demo",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.PERSONA_SLOT,
                persona_id="persona-en",
                metadata={"name_component": "family"},
            )
        ],
    )
    detector = RuleBasedPIIDetector(locale_profile="en_us", mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="Johnson",
        ocr_blocks=[],
        session_id="session-name",
        turn_id=2,
    )
    family = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME)

    assert family.metadata["matched_by"] == ["dictionary_session"]
    assert family.metadata["name_component"] == ["family"]
    assert family.metadata["session_turn_ids"] == ["1"]


def test_replacement_service_persists_name_component_metadata() -> None:
    service = ReplacementService()
    candidate = PIICandidate(
        entity_id="c-name",
        text="Johnson",
        normalized_text="Johnson",
        canonical_source_text="Johnson",
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.PROMPT,
        confidence=0.95,
    )
    action = DecisionAction(
        candidate_id="c-name",
        action_type=ActionType.PERSONA_SLOT,
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.PROMPT,
        source_text="Johnson",
        replacement_text="Demo",
        metadata={"name_component": ["family"]},
    )

    records = service.build_records("session-name", 1, [action], [candidate])

    assert records[0].metadata["name_component"] == "family"


def test_screenshot_renderer_splits_english_name_replacement_across_blocks() -> None:
    renderer = ScreenshotRenderer()
    action = DecisionAction(
        candidate_id="c-name",
        action_type=ActionType.PERSONA_SLOT,
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.OCR,
        source_text="Johnson, Alice",
        replacement_text="Demo, Jordan",
        bbox=BoundingBox(x=0, y=0, width=120, height=20),
        block_id="ocr-1",
    )
    blocks = [
        OCRTextBlock(
            text="Johnson,",
            block_id="ocr-1",
            bbox=BoundingBox(x=0, y=0, width=80, height=20),
        ),
        OCRTextBlock(
            text="Alice",
            block_id="ocr-2",
            bbox=BoundingBox(x=84, y=0, width=40, height=20),
        ),
    ]

    chunks = renderer._split_name_replacement_across_blocks(action, blocks)

    assert chunks == ["Demo,", "Jordan"]


def test_rule_based_detector_detects_name_from_vertical_ocr_label_block() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="住客姓名",
                block_id="ocr-label",
                bbox=BoundingBox(x=18, y=16, width=64, height=14),
            ),
            OCRTextBlock(
                text="STEvEngoodwIN",
                block_id="ocr-name",
                bbox=BoundingBox(x=18, y=42, width=148, height=28),
            ),
        ],
        protection_level=ProtectionLevel.WEAK,
    )

    name_candidate = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME)

    assert name_candidate.text == "STEvEngoodwIN"
    assert name_candidate.block_id == "ocr-name"
    assert name_candidate.metadata["matched_by"] == ["ocr_label_name_field"]
    assert name_candidate.metadata["name_component"] == ["full"]
    assert name_candidate.metadata["ocr_block_ids"] == ["ocr-name"]
    assert name_candidate.confidence >= 0.9


def test_rule_based_detector_detects_family_and_given_name_from_horizontal_ocr_labels() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="姓",
                block_id="ocr-family-label",
                bbox=BoundingBox(x=12, y=12, width=18, height=16),
            ),
            OCRTextBlock(
                text="Foster",
                block_id="ocr-family-value",
                bbox=BoundingBox(x=46, y=10, width=74, height=20),
            ),
            OCRTextBlock(
                text="名",
                block_id="ocr-given-label",
                bbox=BoundingBox(x=12, y=40, width=18, height=16),
            ),
            OCRTextBlock(
                text="Brian",
                block_id="ocr-given-value",
                bbox=BoundingBox(x=46, y=38, width=64, height=20),
            ),
        ],
        protection_level=ProtectionLevel.BALANCED,
    )

    by_text = {
        candidate.text: candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.NAME
    }

    assert by_text["Foster"].metadata["matched_by"] == ["ocr_label_name_family_field"]
    assert by_text["Foster"].metadata["name_component"] == ["family"]
    assert by_text["Brian"].metadata["matched_by"] == ["ocr_label_name_given_field"]
    assert by_text["Brian"].metadata["name_component"] == ["given"]


def test_rule_based_detector_rejects_pronouns_as_name_label_value() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="Name",
                block_id="ocr-name-label",
                bbox=BoundingBox(x=12, y=12, width=54, height=18),
            ),
            OCRTextBlock(
                text="Pronouns",
                block_id="ocr-name-value",
                bbox=BoundingBox(x=12, y=38, width=120, height=26),
            ),
        ],
        protection_level=ProtectionLevel.WEAK,
    )

    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in candidates)
