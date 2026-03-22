"""de_model 特征提取测试。"""

import pytest

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.features import (
    ATTR_FEATURE_ORDER,
    CANDIDATE_FEATURE_DIM,
    PAGE_FEATURE_DIM,
    PAGE_FEATURE_NAMES,
    PERSONA_FEATURE_DIM,
    PROTECTION_LEVEL_ORDER,
    SOURCE_FEATURE_ORDER,
    DecisionFeatureExtractor,
    build_candidate_dense_features,
    build_page_features,
    build_persona_features,
    build_text_inputs,
)
from privacyguard.infrastructure.decision.policy_context import DerivedDecisionPolicyContext, derive_policy_context
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

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        return self.get_slot_value(persona_id, attr_type)


def test_decision_feature_extractor_maps_candidate_policy_views_to_dense_features() -> None:
    """candidate dense feature 应优先来自新的 candidate_policy_views。"""
    context = _build_policy_context()
    policy = derive_policy_context(context)
    candidate_views = _candidate_views_by_id(policy)
    text_inputs = build_text_inputs(context)
    packed = DecisionFeatureExtractor().pack(context)

    phone_view = candidate_views["cand-phone"]
    assert phone_view["cross_block_flag"] is True
    assert phone_view["history_alias_exposure_bucket"] == "1"

    assert text_inputs["candidates"]["cand-name"]["candidate_text"] == "张三"
    assert "[姓名]" in text_inputs["candidates"]["cand-name"]["prompt_context"]
    assert text_inputs["candidates"]["cand-phone"]["candidate_text"] == "13800138000"
    assert text_inputs["candidates"]["cand-phone"]["ocr_context"] != ""

    phone_vector = build_candidate_dense_features(
        context=context,
        candidate_policy_view=phone_view,
        text_inputs=text_inputs,
    )
    assert len(phone_vector) == CANDIDATE_FEATURE_DIM
    assert len(packed.candidate_vectors[packed.candidate_ids.index("cand-phone")]) == CANDIDATE_FEATURE_DIM

    attr_index = ATTR_FEATURE_ORDER.index(PIIAttributeType.PHONE.value)
    source_start = len(ATTR_FEATURE_ORDER)
    source_index = source_start + SOURCE_FEATURE_ORDER.index(PIISourceType.OCR.value)
    confidence_index = len(ATTR_FEATURE_ORDER) + len(SOURCE_FEATURE_ORDER)
    history_alias_index = confidence_index + 1
    low_ocr_flag_index = len(ATTR_FEATURE_ORDER) + len(SOURCE_FEATURE_ORDER) + 11
    candidate_text_sig_start = len(ATTR_FEATURE_ORDER) + len(SOURCE_FEATURE_ORDER) + 12
    prompt_text_sig_start = candidate_text_sig_start + 5
    ocr_text_sig_start = prompt_text_sig_start + 5

    assert phone_vector[attr_index] == 1.0
    assert phone_vector[source_index] == 1.0
    assert phone_vector[confidence_index] == pytest.approx(0.9)
    assert phone_vector[history_alias_index] > 0.0
    assert phone_vector[low_ocr_flag_index] == 1.0
    assert phone_vector[candidate_text_sig_start] > 0.0
    assert phone_vector[prompt_text_sig_start] > 0.0
    assert phone_vector[ocr_text_sig_start] > 0.0


def test_decision_feature_extractor_builds_page_features_from_page_policy_state() -> None:
    """page feature 应反映 page_policy_state 的质量与保护级别语义。"""
    context = _build_policy_context()
    policy = derive_policy_context(context)
    page_vector = build_page_features(context)

    assert policy.page_policy_state["page_quality_state"] == "poor"
    assert len(page_vector) == PAGE_FEATURE_DIM

    avg_ocr_index = PAGE_FEATURE_NAMES.index("average_ocr_block_score")
    low_ocr_ratio_index = PAGE_FEATURE_NAMES.index("low_confidence_ocr_block_ratio")
    active_persona_index = PAGE_FEATURE_NAMES.index("active_persona_bound")
    prompt_candidate_index = PAGE_FEATURE_NAMES.index("prompt_candidate_count")
    ocr_candidate_index = PAGE_FEATURE_NAMES.index("ocr_candidate_count")
    protection_start = PAGE_FEATURE_DIM - len(PROTECTION_LEVEL_ORDER)
    strong_protection_index = protection_start + PROTECTION_LEVEL_ORDER.index(ProtectionLevel.STRONG.value)

    assert page_vector[avg_ocr_index] == pytest.approx(0.5)
    assert page_vector[low_ocr_ratio_index] == pytest.approx(1.0)
    assert page_vector[active_persona_index] == 1.0
    assert page_vector[prompt_candidate_index] == pytest.approx(1.0 / 32.0)
    assert page_vector[ocr_candidate_index] == pytest.approx(1.0 / 32.0)
    assert page_vector[strong_protection_index] == 1.0


def test_decision_feature_extractor_builds_persona_features_from_persona_policy_states() -> None:
    """persona feature 应反映 available_slot_mask 与 active persona 状态。"""
    context = _build_policy_context()
    text_inputs = build_text_inputs(context)
    policy = derive_policy_context(context)
    persona_states = _persona_states_by_id(policy)
    active_state = persona_states["persona-active"]

    assert active_state["available_slot_mask"][PIIAttributeType.PHONE.value] is True
    assert active_state["available_slot_mask"][PIIAttributeType.ADDRESS.value] is False

    persona_vector = build_persona_features(
        context=context,
        persona_policy_state=active_state,
        text_inputs=text_inputs,
    )
    packed = DecisionFeatureExtractor().pack(context)

    assert len(persona_vector) == PERSONA_FEATURE_DIM
    assert len(packed.persona_vectors[packed.persona_ids.index("persona-active")]) == PERSONA_FEATURE_DIM

    persona_attr_start = 4
    phone_attr_index = persona_attr_start + ATTR_FEATURE_ORDER.index(PIIAttributeType.PHONE.value)
    address_attr_index = persona_attr_start + ATTR_FEATURE_ORDER.index(PIIAttributeType.ADDRESS.value)

    assert persona_vector[2] == 1.0
    assert persona_vector[3] == pytest.approx(2.0 / 8.0)
    assert persona_vector[phone_attr_index] == 1.0
    assert persona_vector[address_attr_index] == 0.0
    assert "角色主" in text_inputs["personas"]["persona-active"]["persona_text"]
    assert "13900001111" in text_inputs["personas"]["persona-active"]["persona_text"]


def _build_policy_context() -> DecisionContext:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-feature-policy",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-feature-policy",
                turn_id=1,
                candidate_id="hist-phone",
                source_text="13800138000",
                replacement_text="<手机号1>",
                attr_type=PIIAttributeType.PHONE,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.OCR,
                block_id="ocr-1",
            )
        ],
    )
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-active",
                display_name="角色主",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.PHONE: "13900001111",
                    PIIAttributeType.ADDRESS: "",
                },
                stats={"exposure_count": 1},
            ),
            PersonaProfile(
                persona_id="persona-other",
                display_name="角色备",
                slots={PIIAttributeType.EMAIL: "other@example.com"},
                stats={"exposure_count": 4},
            ),
        ]
    )
    context = DecisionContextBuilder(
        mapping_store=mapping_store,
        persona_repository=persona_repo,
    ).build(
        session_id="session-feature-policy",
        turn_id=2,
        prompt_text="张三的手机号在图片里",
        protection_level=ProtectionLevel.STRONG,
        ocr_blocks=[
            OCRTextBlock(
                text="138001",
                bbox=BoundingBox(x=0, y=0, width=60, height=20),
                block_id="ocr-1",
                score=0.45,
            ),
            OCRTextBlock(
                text="38000",
                bbox=BoundingBox(x=62, y=0, width=60, height=20),
                block_id="ocr-2",
                score=0.55,
            ),
        ],
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=0,
                span_end=2,
                confidence=0.91,
            ),
            PIICandidate(
                entity_id="cand-phone",
                text="13800138000",
                normalized_text="13800138000",
                attr_type=PIIAttributeType.PHONE,
                source=PIISourceType.OCR,
                bbox=BoundingBox(x=0, y=0, width=122, height=20),
                block_id="ocr-1",
                confidence=0.9,
                metadata={"ocr_block_ids": ["ocr-1", "ocr-2"]},
            ),
        ],
        session_binding=SessionBinding(session_id="session-feature-policy", active_persona_id="persona-active"),
    )
    return context


def _candidate_views_by_id(policy: DerivedDecisionPolicyContext) -> dict[str, dict[str, object]]:
    return {
        str(view["candidate_id"]): view
        for view in policy.candidate_policy_views
    }


def _persona_states_by_id(policy: DerivedDecisionPolicyContext) -> dict[str, dict[str, object]]:
    return {
        str(state["persona_id"]): state
        for state in policy.persona_policy_states
    }
