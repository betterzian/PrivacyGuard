"""de_model 特征维度与属性编码测试。"""

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.features import (
    ATTR_FEATURE_ORDER,
    CANDIDATE_FEATURE_DIM,
    PAGE_FEATURE_DIM,
    PERSONA_FEATURE_DIM,
    PROTECTION_LEVEL_ORDER,
    DecisionFeatureExtractor,
)
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


def test_decision_feature_extractor_uses_full_attr_space_and_stable_dims() -> None:
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-all",
                display_name="角色全量",
                slots={
                    PIIAttributeType.BANK_ACCOUNT: "6222020202020202020",
                    PIIAttributeType.DRIVER_LICENSE: "440301199001011234",
                },
                stats={"exposure_count": 0},
            )
        ]
    )
    context = DecisionContextBuilder(
        mapping_store=InMemoryMappingStore(),
        persona_repository=persona_repo,
    ).build(
        session_id="session-feature-dims",
        turn_id=1,
        prompt_text="我的银行账号是 6222020202020202020",
        protection_level=ProtectionLevel.STRONG,
        ocr_blocks=[
            OCRTextBlock(
                text="开户行 6222020202020202020",
                bbox=BoundingBox(x=0, y=0, width=120, height=24),
                block_id="ocr-1",
                score=0.7,
            )
        ],
        candidates=[
            PIICandidate(
                entity_id="cand-bank",
                text="6222020202020202020",
                normalized_text="6222020202020202020",
                attr_type=PIIAttributeType.BANK_ACCOUNT,
                source=PIISourceType.OCR,
                block_id="ocr-1",
                span_start=4,
                span_end=23,
                confidence=0.97,
            )
        ],
    )

    packed = DecisionFeatureExtractor().pack(context)

    assert len(packed.page_vector) == PAGE_FEATURE_DIM
    assert len(packed.candidate_vectors[0]) == CANDIDATE_FEATURE_DIM
    assert len(packed.persona_vectors[0]) == PERSONA_FEATURE_DIM

    attr_slice = packed.candidate_vectors[0][: len(ATTR_FEATURE_ORDER)]
    assert attr_slice[ATTR_FEATURE_ORDER.index(PIIAttributeType.BANK_ACCOUNT.value)] == 1.0
    protection_start = PAGE_FEATURE_DIM - len(PROTECTION_LEVEL_ORDER)
    assert packed.page_vector[protection_start + PROTECTION_LEVEL_ORDER.index(ProtectionLevel.STRONG.value)] == 1.0
    assert packed.page_vector[14] == 0.7

    persona_attr_start = 4
    persona_attr_slice = packed.persona_vectors[0][persona_attr_start : persona_attr_start + len(ATTR_FEATURE_ORDER)]
    assert persona_attr_slice[ATTR_FEATURE_ORDER.index(PIIAttributeType.BANK_ACCOUNT.value)] == 1.0
    assert persona_attr_slice[ATTR_FEATURE_ORDER.index(PIIAttributeType.DRIVER_LICENSE.value)] == 1.0
    assert packed.candidate_vectors[0][23] == 0.7
