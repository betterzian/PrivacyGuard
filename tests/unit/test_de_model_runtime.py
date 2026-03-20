"""de_model runtime 输出协议测试。"""

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.de_model_runtime import (
    REWRITE_MODE_NONE,
    TinyPolicyOutputDecoder,
    TinyPolicyRuntime,
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


def test_tiny_policy_output_decoder_emits_keep_protocol_fields_for_low_confidence() -> None:
    torch = __import__("pytest").importorskip("torch")
    from privacyguard.domain.enums import ActionType
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyBatch, TinyPolicyOutput

    decoder = TinyPolicyOutputDecoder(keep_threshold=0.25)
    batch = TinyPolicyBatch(
        page_features=torch.zeros((1, 1), dtype=torch.float32),
        candidate_features=torch.zeros((1, 1, 1), dtype=torch.float32),
        candidate_mask=torch.tensor([[True]], dtype=torch.bool),
        candidate_text_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_text_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_prompt_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_prompt_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_ocr_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_ocr_mask=torch.ones((1, 1, 1), dtype=torch.long),
        persona_features=torch.zeros((1, 2, 1), dtype=torch.float32),
        persona_mask=torch.tensor([[True, True]], dtype=torch.bool),
        persona_text_ids=torch.zeros((1, 2, 1), dtype=torch.long),
        persona_text_mask=torch.ones((1, 2, 1), dtype=torch.long),
        candidate_ids=[["cand-1"]],
        persona_ids=[["persona-a", "persona-b"]],
    )
    output = TinyPolicyOutput(
        persona_logits=torch.tensor([[0.0, 0.0]], dtype=torch.float32),
        action_logits=torch.tensor([[[0.0, 0.0, 5.0]]], dtype=torch.float32),
        confidence_scores=torch.tensor([[0.1]], dtype=torch.float32),
        utility_scores=torch.zeros((1, 1), dtype=torch.float32),
        page_summary=torch.zeros((1, 1), dtype=torch.float32),
        persona_context=torch.zeros((1, 1), dtype=torch.float32),
    )

    runtime_output = decoder.decode(batch=batch, output=output, torch_module=torch)

    decision = runtime_output.candidate_decisions[0]
    assert runtime_output.active_persona_id == "persona-b"
    assert decision.candidate_id == "cand-1"
    assert decision.protect_decision == "KEEP"
    assert decision.rewrite_mode == REWRITE_MODE_NONE
    assert decision.final_action == ActionType.KEEP
    assert decision.confidence == 0.1
    assert decision.fallback_reason is not None
    assert "low_conf_keep" in decision.reason


def test_tiny_policy_output_decoder_emits_genericize_protocol_fields() -> None:
    torch = __import__("pytest").importorskip("torch")
    from privacyguard.domain.enums import ActionType
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyBatch, TinyPolicyOutput

    decoder = TinyPolicyOutputDecoder()
    batch = TinyPolicyBatch(
        page_features=torch.zeros((1, 1), dtype=torch.float32),
        candidate_features=torch.zeros((1, 1, 1), dtype=torch.float32),
        candidate_mask=torch.tensor([[True]], dtype=torch.bool),
        candidate_text_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_text_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_prompt_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_prompt_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_ocr_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_ocr_mask=torch.ones((1, 1, 1), dtype=torch.long),
        persona_features=torch.zeros((1, 1, 1), dtype=torch.float32),
        persona_mask=torch.tensor([[True]], dtype=torch.bool),
        persona_text_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        persona_text_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_ids=[["cand-2"]],
        persona_ids=[["persona-a"]],
    )
    output = TinyPolicyOutput(
        persona_logits=torch.tensor([[0.0]], dtype=torch.float32),
        action_logits=torch.tensor([[[0.0, 2.0, 0.0]]], dtype=torch.float32),
        confidence_scores=torch.tensor([[0.9]], dtype=torch.float32),
        utility_scores=torch.zeros((1, 1), dtype=torch.float32),
        page_summary=torch.zeros((1, 1), dtype=torch.float32),
        persona_context=torch.zeros((1, 1), dtype=torch.float32),
    )

    runtime_output = decoder.decode(batch=batch, output=output, torch_module=torch)

    decision = runtime_output.candidate_decisions[0]
    assert decision.protect_decision == "REWRITE"
    assert decision.rewrite_mode == ActionType.GENERICIZE.value
    assert decision.final_action == ActionType.GENERICIZE
    assert decision.confidence == 0.9
    assert decision.fallback_reason is None


def test_tiny_policy_runtime_emits_persona_slot_protocol_fields() -> None:
    from privacyguard.domain.enums import ActionType
    from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor

    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-main",
                display_name="角色主",
                slots={PIIAttributeType.NAME: "李四"},
                stats={"exposure_count": 0},
            )
        ]
    )
    context = DecisionContextBuilder(
        mapping_store=InMemoryMappingStore(),
        persona_repository=persona_repo,
    ).build(
        session_id="runtime-session",
        turn_id=1,
        prompt_text="请联系张三",
        protection_level=ProtectionLevel.BALANCED,
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=3,
                span_end=5,
                confidence=0.95,
            )
        ],
        session_binding=SessionBinding(session_id="runtime-session", active_persona_id="persona-main"),
    )

    runtime_output = TinyPolicyRuntime().predict(
        context=context,
        packed=DecisionFeatureExtractor().pack(context),
    )

    decision = runtime_output.candidate_decisions[0]
    assert runtime_output.active_persona_id == "persona-main"
    assert decision.protect_decision == "REWRITE"
    assert decision.rewrite_mode == ActionType.PERSONA_SLOT.value
    assert decision.final_action == ActionType.PERSONA_SLOT
    assert decision.persona_id == "persona-main"
    assert decision.confidence == 0.95
    assert decision.fallback_reason is None
