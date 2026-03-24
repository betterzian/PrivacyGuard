from __future__ import annotations

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.decision.de_model_runtime import DEModelRuntimeOutput
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor, PackedDecisionFeatures
from privacyguard.infrastructure.decision.policy_context import DerivedDecisionPolicyContext, derive_policy_context
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from training.runtime_bridge import pack_training_turn


def _empty_context() -> DecisionContext:
    return DecisionContext(
        session_id="s1",
        turn_id=1,
        prompt_text="hello",
        protection_level=ProtectionLevel.BALANCED,
    )


def test_decision_feature_extractor_reuses_precomputed_policy(monkeypatch) -> None:
    context = _empty_context()
    policy = derive_policy_context(context)

    def fail_if_called(_context):
        raise AssertionError("derive_policy_context should not be called when policy is provided")

    monkeypatch.setattr("privacyguard.infrastructure.decision.features.derive_policy_context", fail_if_called)

    packed = DecisionFeatureExtractor().pack(context, policy=policy)

    assert packed.page_vector
    assert packed.candidate_ids == []
    assert packed.persona_ids == []


def test_pack_training_turn_reuses_precomputed_policy(monkeypatch) -> None:
    context = _empty_context()
    policy = derive_policy_context(context)

    def fail_if_called(_context):
        raise AssertionError("runtime_bridge should reuse the provided policy")

    monkeypatch.setattr("training.runtime_bridge.derive_policy_context", fail_if_called)

    example, packed = pack_training_turn(context, policy=policy)

    assert example.session_id == "s1"
    assert example.candidate_ids == []
    assert packed.candidate_ids == []


class FeatureExtractorSpy:
    def __init__(self) -> None:
        self.received_policy = None

    def pack(self, context: DecisionContext, *, policy=None) -> PackedDecisionFeatures:
        self.received_policy = policy
        return PackedDecisionFeatures(
            page_vector=[0.0],
            candidate_ids=[],
            candidate_vectors=[],
            persona_ids=[],
            persona_vectors=[],
        )


class RuntimeSpy:
    def __init__(self) -> None:
        self.received_policy = None

    def predict(self, *, context: DecisionContext, packed: PackedDecisionFeatures, policy=None) -> DEModelRuntimeOutput:
        self.received_policy = policy
        return DEModelRuntimeOutput(
            active_persona_id=None,
            persona_scores={},
            candidate_decisions=[],
        )


class PersonaRepoStub:
    def list_personas(self) -> list[object]:
        return []


def test_de_model_engine_derives_policy_once_and_passes_it_down(monkeypatch) -> None:
    fake_policy = DerivedDecisionPolicyContext(
        raw_refs={},
        candidate_policy_views=[],
        page_policy_state={
            "_average_ocr_block_score": 0.0,
            "_average_candidate_confidence": 0.0,
        },
        persona_policy_states=[],
    )
    feature_extractor = FeatureExtractorSpy()
    runtime = RuntimeSpy()
    call_count = {"count": 0}

    def fake_derive_policy_context(context: DecisionContext) -> DerivedDecisionPolicyContext:
        call_count["count"] += 1
        return fake_policy

    monkeypatch.setattr(
        "privacyguard.infrastructure.decision.de_model_engine.derive_policy_context",
        fake_derive_policy_context,
    )

    engine = DEModelEngine(
        persona_repository=PersonaRepoStub(),
        mapping_store=InMemoryMappingStore(),
        feature_extractor=feature_extractor,
        runtime=runtime,
        checkpoint_path="unused.ckpt",
    )

    plan = engine.plan(_empty_context())

    assert plan.metadata["mode"] == "de_model"
    assert call_count["count"] == 1
    assert feature_extractor.received_policy is fake_policy
    assert runtime.received_policy is fake_policy
