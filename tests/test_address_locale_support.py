from __future__ import annotations

import json
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.persona.json_persona_repository import InvalidPersonaRepositoryError
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer
from privacyguard.utils.pii_value import parse_address_components


def _workspace_test_path(test_name: str, filename: str) -> Path:
    path = Path.cwd() / "tests" / ".artifacts" / test_name / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    return path


def test_parse_address_components_supports_structured_en_us_address() -> None:
    components = parse_address_components("123 Main St Apt 4B, Springfield, IL 62704")

    assert components.locale == "en_us"
    assert components.street_text == "123 Main St"
    assert components.building_text == "Apt 4B"
    assert components.city_text == "Springfield"
    assert components.province_text == "IL"
    assert components.postal_code_text == "62704"
    assert components.detail_text == "123 Main St Apt 4B"


def test_json_persona_repository_round_trips_structured_english_address() -> None:
    repository_path = _workspace_test_path(
        "test_json_persona_repository_round_trips_structured_english_address",
        "persona_repository.en.json",
    )
    repository = JsonPersonaRepository(path=str(repository_path))
    repository.upsert_persona(
        PersonaProfile(
            persona_id="persona-en",
            display_name="English Persona",
            slots={
                PIIAttributeType.NAME: ["Alice Johnson"],
                PIIAttributeType.ADDRESS: ["456 Park Ave Suite 1201, Albany, NY 12207"],
            },
        )
    )

    payload = json.loads(repository_path.read_text(encoding="utf-8"))
    stored = payload["fake_personas"][0]["slots"]["address"][0]
    assert stored["street"]["value"] == "456 Park Ave"
    assert stored["building"]["value"] == "Suite 1201"
    assert stored["city"]["value"] == "Albany"
    assert stored["province"]["value"] == "NY"
    assert stored["postal_code"]["value"] == "12207"

    assert repository.get_slot_value("persona-en", PIIAttributeType.ADDRESS) == "456 Park Ave Suite 1201, Albany, NY 12207"
    assert repository.get_slot_replacement_text("persona-en", PIIAttributeType.ADDRESS, "123 Main St") == "456 Park Ave"
    assert repository.get_slot_replacement_text("persona-en", PIIAttributeType.ADDRESS, "Apt 4B") == "Suite 1201"
    assert repository.get_slot_replacement_text(
        "persona-en",
        PIIAttributeType.ADDRESS,
        "Springfield, IL 62704",
    ) == "Albany, NY 12207"


def test_json_persona_repository_rejects_legacy_scalar_slots() -> None:
    repository_path = _workspace_test_path(
        "test_json_persona_repository_rejects_legacy_scalar_slots",
        "persona_repository.legacy.json",
    )
    repository_path.write_text(
        json.dumps(
            {
                "fake_personas": [
                    {
                        "persona_id": "persona-en",
                        "slots": {
                            "name": {"value": "Alice Johnson", "aliases": []},
                        },
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    try:
        JsonPersonaRepository(path=str(repository_path))
    except InvalidPersonaRepositoryError:
        return
    raise AssertionError("legacy scalar persona_repository slots should be rejected")


def test_screenshot_renderer_splits_english_address_replacement_across_blocks() -> None:
    renderer = ScreenshotRenderer()
    action = DecisionAction(
        candidate_id="c-address",
        action_type=ActionType.PERSONA_SLOT,
        attr_type=PIIAttributeType.ADDRESS,
        source=PIISourceType.OCR,
        source_text="123 Main St Apt 4B, Springfield, IL 62704",
        replacement_text="456 Park Ave Suite 1201, Albany, NY 12207",
        bbox=BoundingBox(x=0, y=0, width=160, height=20),
        block_id="ocr-1",
    )
    blocks = [
        OCRTextBlock(
            text="123 Main St Apt 4B",
            block_id="ocr-1",
            bbox=BoundingBox(x=0, y=0, width=160, height=20),
        ),
        OCRTextBlock(
            text="Springfield, IL 62704",
            block_id="ocr-2",
            bbox=BoundingBox(x=0, y=24, width=180, height=20),
        ),
    ]

    chunks = renderer._split_address_replacement_across_blocks(action, blocks)

    assert chunks == ["456 Park Ave Suite 1201", "Albany, NY 12207"]
