from __future__ import annotations

import pytest

from privacyguard.application.services.replacement_generation import apply_post_decision_steps
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.decision.de_model_runtime import RuntimeCandidateDecision
from privacyguard.infrastructure.decision.features import CANDIDATE_FEATURE_DIM, PAGE_FEATURE_DIM
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from training.types import SupervisedTurnLabels, TrainingTurnExample, normalize_action_type


class PersonaRepoStub:
    def __init__(self, personas: list[PersonaProfile] | None = None) -> None:
        self._personas = list(personas or [])

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        for persona in self._personas:
            if persona.persona_id == persona_id:
                return persona
        return None

    def list_personas(self) -> list[PersonaProfile]:
        return list(self._personas)

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        values = persona.slots.get(attr_type)
        if not values:
            return None
        return values[0]

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        return self.get_slot_value(persona_id, attr_type)


def _candidate(*, candidate_id: str = "c1") -> PIICandidate:
    return PIICandidate(
        entity_id=candidate_id,
        text="Alice",
        normalized_text="Alice",
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.PROMPT,
        confidence=0.9,
    )


def _context(*, candidates: list[PIICandidate] | None = None, personas: list[PersonaProfile] | None = None) -> DecisionContext:
    return DecisionContext(
        session_id="s1",
        turn_id=1,
        prompt_text="Alice",
        protection_level=ProtectionLevel.BALANCED,
        candidates=list(candidates or []),
        persona_profiles=list(personas or []),
        session_binding=SessionBinding(session_id="s1"),
    )


def _batch_builder(*, max_candidates: int, max_personas: int):
    pytest.importorskip("torch")
    from training.torch_batch import TinyPolicyBatchBuilder

    return TinyPolicyBatchBuilder(max_candidates=max_candidates, max_personas=max_personas)


def test_training_normalize_action_type_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="非法训练动作名"):
        normalize_action_type("BROKEN")


def test_runtime_candidate_decision_rejects_unknown_action() -> None:
    with pytest.raises(ValueError, match="非法 de_model 动作名"):
        RuntimeCandidateDecision(candidate_id="c1", final_action="BROKEN")


def test_constraint_resolver_raises_when_candidate_missing() -> None:
    resolver = ConstraintResolver(PersonaRepoStub())
    action = DecisionAction(
        candidate_id="missing",
        action_type=ActionType.KEEP,
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.PROMPT,
    )

    with pytest.raises(ValueError, match="未找到 candidate"):
        resolver.resolve([action], [], None)


def test_apply_post_decision_steps_raises_when_genericize_has_no_placeholder() -> None:
    candidate = _candidate()
    plan = DecisionPlan(
        session_id="s1",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id=candidate.entity_id,
                action_type=ActionType.GENERICIZE,
                attr_type=candidate.attr_type,
                source=candidate.source,
                source_text=None,
            )
        ],
    )

    with pytest.raises(ValueError, match="GENERICIZE 缺少 replacement_text"):
        apply_post_decision_steps(
            plan,
            _context(candidates=[candidate]),
            InMemoryMappingStore(),
            PersonaRepoStub(),
        )


def test_supervised_turn_labels_reject_inconsistent_action_and_labels() -> None:
    with pytest.raises(ValueError, match="protect_label 与 final_action 不一致"):
        SupervisedTurnLabels(
            target_persona_id=None,
            final_actions={"c1": ActionType.KEEP},
            target_protect_labels={"c1": "REWRITE"},
            target_rewrite_modes={"c1": "NONE"},
        )


def test_tiny_policy_batch_builder_rejects_candidate_overflow() -> None:
    example = TrainingTurnExample(
        session_id="s1",
        turn_id=1,
        prompt_text="x",
        ocr_texts=[],
        candidate_ids=["c1", "c2"],
        candidate_texts=["a", "b"],
        candidate_prompt_contexts=["", ""],
        candidate_ocr_contexts=["", ""],
        candidate_attr_types=[PIIAttributeType.NAME, PIIAttributeType.NAME],
        persona_ids=[],
        persona_texts=[],
        active_persona_id=None,
        page_vector=[0.0] * PAGE_FEATURE_DIM,
        candidate_vectors=[[0.0] * CANDIDATE_FEATURE_DIM, [0.0] * CANDIDATE_FEATURE_DIM],
        persona_vectors=[],
    )

    builder = _batch_builder(max_candidates=1, max_personas=1)

    with pytest.raises(ValueError, match="candidate 数量 2 超过 max_candidates=1"):
        builder.build_examples([example])


def test_tiny_policy_batch_builder_rejects_missing_labeled_candidate() -> None:
    example = TrainingTurnExample(
        session_id="s1",
        turn_id=1,
        prompt_text="x",
        ocr_texts=[],
        candidate_ids=["c1"],
        candidate_texts=["a"],
        candidate_prompt_contexts=[""],
        candidate_ocr_contexts=[""],
        candidate_attr_types=[PIIAttributeType.NAME],
        persona_ids=[],
        persona_texts=[],
        active_persona_id=None,
        page_vector=[0.0] * PAGE_FEATURE_DIM,
        candidate_vectors=[[0.0] * CANDIDATE_FEATURE_DIM],
        persona_vectors=[],
    )
    labels = SupervisedTurnLabels(
        target_persona_id=None,
        final_actions={"c2": ActionType.KEEP},
    )
    builder = _batch_builder(max_candidates=4, max_personas=1)

    with pytest.raises(ValueError, match="candidate label 未出现在 batch 中"):
        builder.build_supervised_examples([example], [labels])


def test_tiny_policy_net_load_state_dict_requires_new_heads() -> None:
    pytest.importorskip("torch")
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet

    model = TinyPolicyNet()
    state_dict = model.state_dict()
    state_dict.pop("protect_head.0.weight")

    with pytest.raises(RuntimeError):
        model.load_state_dict(state_dict)
