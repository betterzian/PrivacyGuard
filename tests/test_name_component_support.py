from __future__ import annotations

import json
from pathlib import Path

from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator
from privacyguard.application.services.replacement_service import ReplacementService
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.generic_placeholder import render_generic_replacement_text
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN
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


def test_organization_canonicalization_strips_geo_and_company_suffix() -> None:
    assert canonicalize_pii_value(PIIAttributeType.ORGANIZATION, "上海市浦东新区阳光科技有限公司") == "阳光科技"
    assert canonicalize_pii_value(PIIAttributeType.ORGANIZATION, "88 Main Street Acme Labs Inc") == "acmelabs"

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
        protection_level=ProtectionLevel.STRONG,
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
        protection_level=ProtectionLevel.STRONG,
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
        protection_level=ProtectionLevel.STRONG,
    )

    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in candidates)


def test_rule_based_detector_detects_name_from_inline_ocr_label_block() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="Name Brian Foster",
                block_id="ocr-inline-name",
                bbox=BoundingBox(x=12, y=12, width=160, height=24),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME)

    assert name_candidate.text == "Brian Foster"
    assert name_candidate.block_id == "ocr-inline-name"
    assert "ocr_label_name_field" in name_candidate.metadata["matched_by"]
    assert name_candidate.metadata["name_component"] == ["full"]
    assert name_candidate.metadata["ocr_block_ids"] == ["ocr-inline-name"]
    assert name_candidate.span_start == len("Name ")


def test_rule_based_detector_detects_name_from_large_gap_horizontal_ocr_label() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="Name",
                block_id="ocr-name-label",
                bbox=BoundingBox(x=12, y=12, width=54, height=22),
            ),
            OCRTextBlock(
                text="CaROlIne mCinTyRe",
                block_id="ocr-name-value",
                bbox=BoundingBox(x=216, y=12, width=186, height=24),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME)
    assert name_candidate.text == "CaROlIne mCinTyRe"
    assert name_candidate.metadata["matched_by"] == ["ocr_label_name_field"]


def test_rule_based_detector_joins_inline_ocr_name_label_with_right_continuation() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="Name Brian",
                block_id="ocr-inline-label",
                bbox=BoundingBox(x=12, y=12, width=96, height=22),
            ),
            OCRTextBlock(
                text="Foster",
                block_id="ocr-inline-right",
                bbox=BoundingBox(x=118, y=12, width=72, height=22),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME and candidate.text == "Brian Foster")

    assert "ocr_label_name_field" in name_candidate.metadata["matched_by"]
    assert name_candidate.metadata["name_component"] == ["full"]
    assert name_candidate.metadata["ocr_block_ids"] == ["ocr-inline-label", "ocr-inline-right"]


def test_rule_based_detector_detects_mixed_case_english_ocr_name_with_cross_block_context() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="bRiAn FoSTER",
                block_id="ocr-name",
                bbox=BoundingBox(x=18, y=18, width=132, height=28),
            ),
            OCRTextBlock(
                text="Weixin ID: 0513 499 990",
                block_id="ocr-id",
                bbox=BoundingBox(x=18, y=58, width=188, height=22),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.NAME and candidate.text == "bRiAn FoSTER"
    )

    assert "heuristic_name_fragment_en" in name_candidate.metadata["matched_by"]


def test_rule_based_detector_uses_neighbor_ocr_blocks_for_standalone_name_context() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="bRiAn FoSTER",
                block_id="ocr-name",
                bbox=BoundingBox(x=24, y=24, width=160, height=28),
            ),
            OCRTextBlock(
                text="A very long neutral filler line that should push the plain text context window far away from the id field",
                block_id="ocr-filler",
                bbox=BoundingBox(x=24, y=64, width=720, height=22),
            ),
            OCRTextBlock(
                text="User ID: 12345",
                block_id="ocr-id",
                bbox=BoundingBox(x=24, y=102, width=156, height=22),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.NAME and candidate.text == "bRiAn FoSTER"
    )

    assert "heuristic_name_fragment_en" in name_candidate.metadata["matched_by"]


def test_rule_based_detector_uses_profile_header_neighbors_for_standalone_name_context() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="bRENda fULleR",
                block_id="ocr-name",
                bbox=BoundingBox(x=24, y=24, width=180, height=28),
            ),
            OCRTextBlock(
                text="Following",
                block_id="ocr-following",
                bbox=BoundingBox(x=24, y=92, width=120, height=22),
            ),
            OCRTextBlock(
                text="Followers",
                block_id="ocr-followers",
                bbox=BoundingBox(x=180, y=92, width=120, height=22),
            ),
            OCRTextBlock(
                text="Edit profile",
                block_id="ocr-edit",
                bbox=BoundingBox(x=24, y=128, width=160, height=24),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    name_candidate = next(
        candidate
        for candidate in candidates
        if candidate.attr_type == PIIAttributeType.NAME and candidate.text == "bRENda fULleR"
    )

    assert "heuristic_name_fragment_en" in name_candidate.metadata["matched_by"]


def test_rule_based_detector_rejects_chinese_ui_tokens_as_ocr_names() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="管理",
                block_id="ocr-manage",
                bbox=BoundingBox(x=20, y=20, width=80, height=28),
            ),
            OCRTextBlock(
                text="公司",
                block_id="ocr-company",
                bbox=BoundingBox(x=20, y=60, width=80, height=28),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in candidates)


def test_rule_based_detector_rejects_english_chat_ui_tokens_as_ocr_names() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="New chat",
                block_id="ocr-new-chat",
                bbox=BoundingBox(x=20, y=20, width=160, height=28),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in candidates)


def test_rule_based_detector_rejects_english_profile_banner_ui_tokens_as_ocr_names() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="",
        ocr_blocks=[
            OCRTextBlock(
                text="Show Threadsbanner",
                block_id="ocr-banner",
                bbox=BoundingBox(x=20, y=20, width=220, height=28),
            ),
            OCRTextBlock(
                text="Edit profile",
                block_id="ocr-edit",
                bbox=BoundingBox(x=20, y=60, width=180, height=24),
            ),
        ],
        protection_level=ProtectionLevel.STRONG,
    )

    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in candidates)


def test_rule_based_detector_rejects_english_ui_phrases_as_ocr_names() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    assert detector._is_blacklisted_english_name_phrase("Buy Again")
    assert detector._is_blacklisted_english_name_phrase("Switch Accounts")
    assert detector._is_blacklisted_english_name_phrase("Sign Out")
    assert detector._is_blacklisted_english_name_phrase("Your personal info")
    assert detector._is_blacklisted_english_name_phrase("New community")


def test_render_generic_replacement_text_uses_script_specific_indexed_labels() -> None:
    assert render_generic_replacement_text(PIIAttributeType.NAME, source_text="张三", index=1) == "<姓名1>"
    assert render_generic_replacement_text(PIIAttributeType.NAME, source_text="Alice Johnson", index=2) == "<name2>"
    assert render_generic_replacement_text(PIIAttributeType.ADDRESS, source_text="Seattle", index=3) == "<address3>"
    assert render_generic_replacement_text(PIIAttributeType.ADDRESS, source_text="上海浦东", index=4) == "<地址4>"


def test_session_placeholder_allocator_uses_global_cross_script_indices() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-placeholder",
        1,
        [
            ReplacementRecord(
                session_id="session-placeholder",
                turn_id=1,
                candidate_id="c-existing",
                source_text="张三",
                canonical_source_text="张三",
                replacement_text="<姓名1>",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    allocator = SessionPlaceholderAllocator(mapping_store)
    plan = DecisionPlan(
        session_id="session-placeholder",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="c-zh",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="张三",
            ),
            DecisionAction(
                candidate_id="c-en",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                source_text="Alice Johnson",
            ),
            DecisionAction(
                candidate_id="c-address",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.ADDRESS,
                source_text="上海浦东新区",
                canonical_source_text="province=上海|city=上海|district=浦东",
            ),
        ],
    )

    assigned = allocator.assign(plan)
    by_candidate = {action.candidate_id: action.replacement_text for action in assigned.actions}

    assert by_candidate["c-zh"] == "<姓名1>"
    assert by_candidate["c-en"] == "<name2>"
    assert by_candidate["c-address"] == "<地址3>"


def test_session_placeholder_allocator_reuses_address_placeholder_by_field_prefix_match() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-address-equivalent",
        1,
        [
            ReplacementRecord(
                session_id="session-address-equivalent",
                turn_id=1,
                candidate_id="c-existing-address",
                source_text="上海市浦东新区世纪大道阳光小区",
                    canonical_source_text="province=上海|city=上海|district=浦东|street=世纪大|compound=阳光",
                replacement_text="<地址1>",
                attr_type=PIIAttributeType.ADDRESS,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    allocator = SessionPlaceholderAllocator(mapping_store)
    plan = DecisionPlan(
        session_id="session-address-equivalent",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="c-new-address",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.ADDRESS,
                source_text="上海市浦东新区世纪大道阳光社区一期",
                    canonical_source_text="province=上海|city=上海|district=浦东|street=世纪大|compound=阳光一期",
            )
        ],
    )

    assigned = allocator.assign(plan)
    by_candidate = {action.candidate_id: action.replacement_text for action in assigned.actions}
    assert by_candidate["c-new-address"] == "<地址1>"


def test_session_placeholder_allocator_reuses_address_placeholder_with_extended_keywords() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-address-extended",
        1,
        [
            ReplacementRecord(
                session_id="session-address-extended",
                turn_id=1,
                candidate_id="c-existing-address",
                source_text="上海市浦东新区世纪大道阳光花园",
                canonical_source_text="province=上海市|city=上海市|district=浦东新区|street=世纪大道|compound=阳光花园",
                replacement_text="<地址1>",
                attr_type=PIIAttributeType.ADDRESS,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    allocator = SessionPlaceholderAllocator(mapping_store)
    plan = DecisionPlan(
        session_id="session-address-extended",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="c-new-address",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.ADDRESS,
                source_text="上海市浦东新区世纪大道阳光公寓一期",
                canonical_source_text="province=上海市|city=上海市|district=浦东新区|street=世纪大道|compound=阳光公寓一期",
            )
        ],
    )

    assigned = allocator.assign(plan)
    by_candidate = {action.candidate_id: action.replacement_text for action in assigned.actions}
    # 纯新链路：不再做 mapping 层关键词兼容剥离，因此该组合不复用历史占位符。
    assert by_candidate["c-new-address"] == "<地址2>"


def test_session_placeholder_allocator_reuses_organization_placeholder_by_prefix() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-org-prefix",
        1,
        [
            ReplacementRecord(
                session_id="session-org-prefix",
                turn_id=1,
                candidate_id="c-existing-org",
                source_text="上海市浦东新区阳光科技有限公司",
                canonical_source_text="阳光科技",
                replacement_text="<机构1>",
                attr_type=PIIAttributeType.ORGANIZATION,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    allocator = SessionPlaceholderAllocator(mapping_store)
    plan = DecisionPlan(
        session_id="session-org-prefix",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="c-new-org",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.ORGANIZATION,
                source_text="阳光科技集团",
                canonical_source_text="阳光科技",
            )
        ],
    )
    assigned = allocator.assign(plan)
    by_candidate = {action.candidate_id: action.replacement_text for action in assigned.actions}
    assert by_candidate["c-new-org"] == "<机构1>"


def test_ocr_page_document_uses_space_for_word_gap_between_english_tokens() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")
    scene_index = detector._build_ocr_scene_index(
        (
            OCRTextBlock(
                text="Main",
                block_id="ocr-main",
                bbox=BoundingBox(x=10, y=10, width=40, height=20),
            ),
            OCRTextBlock(
                text="Number",
                block_id="ocr-number",
                bbox=BoundingBox(x=59, y=10, width=72, height=20),
            ),
        )
    )

    document = detector._build_ocr_page_document(scene_index)

    assert document is not None
    assert document.text == "Main Number"


def test_ocr_page_document_uses_break_for_column_gap_between_english_tokens() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")
    scene_index = detector._build_ocr_scene_index(
        (
            OCRTextBlock(
                text="Main",
                block_id="ocr-main",
                bbox=BoundingBox(x=10, y=10, width=40, height=20),
            ),
            OCRTextBlock(
                text="Number",
                block_id="ocr-number",
                bbox=BoundingBox(x=86, y=10, width=72, height=20),
            ),
        )
    )

    document = detector._build_ocr_page_document(scene_index)

    assert document is not None
    assert document.text == f"Main{_OCR_SEMANTIC_BREAK_TOKEN}Number"
