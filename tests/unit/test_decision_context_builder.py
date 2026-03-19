"""de_model 上下文构造测试。"""

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore


class _PersonaRepository:
    def __init__(self, personas: list[PersonaProfile]) -> None:
        self._personas = {item.persona_id: item for item in personas}

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        return persona.slots.get(attr_type)


def test_decision_context_builder_derives_page_candidate_and_persona_features() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-1",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-1",
                turn_id=1,
                candidate_id="old-name",
                source_text="张三",
                replacement_text="李四",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.PERSONA_SLOT,
                source=PIISourceType.PROMPT,
                persona_id="persona-b",
            )
        ],
    )
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-a",
                display_name="角色A",
                slots={PIIAttributeType.EMAIL: "a@example.com"},
                stats={"exposure_count": 5},
            ),
            PersonaProfile(
                persona_id="persona-b",
                display_name="角色B",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.ADDRESS: "北京市朝阳区",
                },
                stats={
                    "exposure_count": 1,
                    "last_exposed_session_id": "session-1",
                    "last_exposed_turn_id": 1,
                },
            ),
        ]
    )
    builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repo)
    ocr_blocks = [
        OCRTextBlock(
            text="北京市海淀区中关村",
            bbox=BoundingBox(x=10, y=20, width=140, height=30),
            block_id="ocr-1",
            score=0.98,
        )
    ]
    candidates = [
        PIICandidate(
            entity_id="cand-name",
            text="张三",
            normalized_text="张三",
            attr_type=PIIAttributeType.NAME,
            source=PIISourceType.PROMPT,
            span_start=3,
            span_end=5,
            confidence=0.93,
        ),
        PIICandidate(
            entity_id="cand-addr",
            text="海淀区",
            normalized_text="海淀区",
            attr_type=PIIAttributeType.ADDRESS,
            source=PIISourceType.OCR,
            bbox=BoundingBox(x=40, y=20, width=60, height=30),
            block_id="ocr-1",
            span_start=3,
            span_end=6,
            confidence=0.88,
        ),
    ]

    context = builder.build(
        session_id="session-1",
        turn_id=2,
        prompt_text="姓名：张三，电话 13800138000",
        protection_level=ProtectionLevel.STRONG,
        ocr_blocks=ocr_blocks,
        candidates=candidates,
        session_binding=SessionBinding(session_id="session-1", active_persona_id="persona-b"),
    )

    assert context.protection_level == ProtectionLevel.STRONG
    assert context.page_features.prompt_length == len("姓名：张三，电话 13800138000")
    assert context.page_features.ocr_block_count == 1
    assert context.page_features.candidate_count == 2
    assert context.page_features.history_record_count == 1
    assert context.page_features.prompt_has_digits is True
    assert context.page_features.active_persona_bound is True
    assert context.page_features.prompt_candidate_count == 1
    assert context.page_features.ocr_candidate_count == 1
    assert context.page_features.average_ocr_block_score == 0.98
    assert context.page_features.min_candidate_confidence == 0.88

    name_feature = next(item for item in context.candidate_features if item.candidate_id == "cand-name")
    assert "姓名：张三" in name_feature.prompt_context
    assert name_feature.history_attr_exposure_count == 1
    assert name_feature.history_exact_match_count == 1
    assert name_feature.same_attr_page_count == 1
    assert name_feature.is_prompt_source is True

    address_feature = next(item for item in context.candidate_features if item.candidate_id == "cand-addr")
    assert "北京市海淀区中关村" in address_feature.ocr_context
    assert address_feature.relative_area > 0.0
    assert address_feature.center_x > 0.0
    assert address_feature.ocr_block_score == 0.98
    assert address_feature.is_low_ocr_confidence is False
    assert address_feature.is_ocr_source is True

    persona_feature = next(item for item in context.persona_features if item.persona_id == "persona-b")
    assert persona_feature.is_active is True
    assert persona_feature.matched_candidate_attr_count == 2
    assert persona_feature.exposure_count == 1
    assert persona_feature.last_exposed_turn_id == 1
