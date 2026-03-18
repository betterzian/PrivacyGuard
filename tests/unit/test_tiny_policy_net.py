"""TinyPolicyNet 原型测试。"""

import pytest

torch = pytest.importorskip("torch")

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from training.torch_batch import TinyPolicyBatchBuilder


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


def test_tiny_policy_net_forward_shapes_and_parameter_budget() -> None:
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-a",
                display_name="角色A",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.ADDRESS: "北京市朝阳区",
                },
                stats={"exposure_count": 1},
            ),
            PersonaProfile(
                persona_id="persona-b",
                display_name="角色B",
                slots={PIIAttributeType.EMAIL: "b@example.com"},
                stats={"exposure_count": 2},
            ),
        ]
    )
    builder = DecisionContextBuilder(mapping_store=InMemoryMappingStore(), persona_repository=persona_repo)
    context = builder.build(
        session_id="session-torch",
        turn_id=1,
        prompt_text="张三住在海淀区，邮箱是 test@example.com",
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=0,
                span_end=2,
                confidence=0.95,
            ),
            PIICandidate(
                entity_id="cand-email",
                text="test@example.com",
                normalized_text="test@example.com",
                attr_type=PIIAttributeType.EMAIL,
                source=PIISourceType.PROMPT,
                span_start=10,
                span_end=26,
                confidence=0.91,
            ),
        ],
    )

    batch = TinyPolicyBatchBuilder(max_candidates=4, max_personas=4, max_text_length=24).build([context])
    model = TinyPolicyNet(TinyPolicyNetConfig(max_text_length=24))

    output = model(batch)

    assert output.persona_logits.shape == (1, 2)
    assert output.action_logits.shape == (1, 2, 3)
    assert output.confidence_scores.shape == (1, 2)
    assert output.utility_scores.shape == (1, 2)
    assert not torch.isnan(output.action_logits).any()
    assert 500_000 <= model.parameter_count() <= 1_200_000
