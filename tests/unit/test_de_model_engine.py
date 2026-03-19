"""de_model 决策引擎骨架测试。"""

from dataclasses import asdict

import pytest

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore

torch = pytest.importorskip("torch")

from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig


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


def test_de_model_engine_plan_with_context_selects_persona_and_preserves_geometry() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-2",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-2",
                turn_id=1,
                candidate_id="history-name",
                source_text="王五",
                replacement_text="李四",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.PERSONA_SLOT,
                source=PIISourceType.OCR,
                persona_id="persona-b",
            )
        ],
    )
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-a",
                display_name="角色A",
                slots={PIIAttributeType.NAME: "赵六"},
                stats={"exposure_count": 4},
            ),
            PersonaProfile(
                persona_id="persona-b",
                display_name="角色B",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.PHONE: "13900001111",
                    PIIAttributeType.ADDRESS: "上海市浦东新区",
                },
                stats={"exposure_count": 1},
            ),
        ]
    )
    builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repo)
    candidates = [
        PIICandidate(
            entity_id="cand-name",
            text="张三",
            normalized_text="张三",
            attr_type=PIIAttributeType.NAME,
            source=PIISourceType.OCR,
            bbox=BoundingBox(x=5, y=10, width=48, height=18),
            block_id="ocr-9",
            span_start=0,
            span_end=2,
            confidence=0.97,
        ),
        PIICandidate(
            entity_id="cand-other",
            text="某机构",
            normalized_text="某机构",
            attr_type=PIIAttributeType.OTHER,
            source=PIISourceType.PROMPT,
            span_start=0,
            span_end=3,
            confidence=0.91,
        ),
    ]
    context = builder.build(
        session_id="session-2",
        turn_id=2,
        prompt_text="某机构联系人张三",
        candidates=candidates,
        session_binding=None,
    )
    engine = DEModelEngine(persona_repository=persona_repo, mapping_store=mapping_store)

    plan = engine.plan_with_context(context)

    assert plan.active_persona_id == "persona-b"
    assert plan.metadata["mode"] == "de_model"
    assert plan.metadata["engine_type"] == "tiny_policy_skeleton"

    action_map = {item.candidate_id: item for item in plan.actions}
    name_action = action_map["cand-name"]
    assert name_action.action_type == ActionType.PERSONA_SLOT
    assert name_action.persona_id == "persona-b"
    assert name_action.replacement_text == "李四"
    assert name_action.bbox == BoundingBox(x=5, y=10, width=48, height=18)
    assert name_action.block_id == "ocr-9"
    assert name_action.span_start == 0
    assert name_action.span_end == 2

    other_action = action_map["cand-other"]
    assert other_action.action_type == ActionType.GENERICIZE
    assert other_action.replacement_text == "@敏感信息1"


def test_de_model_engine_plan_keeps_legacy_interface_available() -> None:
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-a",
                display_name="角色A",
                slots={PIIAttributeType.NAME: "李四"},
                stats={"exposure_count": 0},
            )
        ]
    )
    engine = DEModelEngine(persona_repository=persona_repo, mapping_store=InMemoryMappingStore())

    plan = engine.plan(
        session_id="session-legacy",
        turn_id=0,
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                confidence=0.9,
            )
        ],
        session_binding=None,
    )

    assert plan.metadata["context_mode"] == "minimal_fallback"
    assert plan.actions[0].candidate_id == "cand-name"


def test_de_model_engine_accepts_explicit_runtime_config() -> None:
    engine = DEModelEngine(
        persona_repository=_PersonaRepository([]),
        mapping_store=InMemoryMappingStore(),
        keep_threshold=0.4,
        persona_score_threshold=0.55,
        action_tie_tolerance=1e-4,
        runtime_type="tiny_policy_heuristic",
        device="mps",
    )

    assert engine.runtime_type == "heuristic"
    assert engine.keep_threshold == 0.4
    assert engine.persona_score_threshold == 0.55
    assert engine.action_tie_tolerance == 1e-4
    assert engine.device == "mps"


def test_de_model_engine_rejects_unknown_runtime_type() -> None:
    try:
        DEModelEngine(
            persona_repository=_PersonaRepository([]),
            mapping_store=InMemoryMappingStore(),
            runtime_type="unknown-runtime",
        )
    except ValueError as exc:
        assert "runtime_type" in str(exc)
    else:
        raise AssertionError("unknown runtime_type 应该报错。")


def test_de_model_engine_torch_runtime_requires_checkpoint() -> None:
    try:
        DEModelEngine(
            persona_repository=_PersonaRepository([]),
            mapping_store=InMemoryMappingStore(),
            runtime_type="torch",
        )
    except ValueError as exc:
        assert "checkpoint_path" in str(exc)
    else:
        raise AssertionError("torch runtime 缺少 checkpoint_path 时应该报错。")


def test_de_model_engine_torch_runtime_runs_checkpoint_inference(tmp_path) -> None:
    checkpoint_path = tmp_path / "tiny_policy.pt"
    model = TinyPolicyNet(TinyPolicyNetConfig(max_text_length=24))
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.zero_()
        model.action_head[-1].bias.copy_(torch.tensor([0.0, 0.2, 1.5], dtype=torch.float32))
    torch.save(
        {
            "state_dict": model.state_dict(),
            "model_config": asdict(model.config),
        },
        checkpoint_path,
    )

    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-torch",
                display_name="角色Torch",
                slots={PIIAttributeType.NAME: "李四"},
                stats={"exposure_count": 0},
            )
        ]
    )
    builder = DecisionContextBuilder(mapping_store=InMemoryMappingStore(), persona_repository=persona_repo)
    context = builder.build(
        session_id="session-torch-runtime",
        turn_id=1,
        prompt_text="请联系张三",
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=3,
                span_end=5,
                confidence=0.98,
            )
        ],
        session_binding=None,
    )

    engine = DEModelEngine(
        persona_repository=persona_repo,
        mapping_store=InMemoryMappingStore(),
        runtime_type="torch",
        checkpoint_path=str(checkpoint_path),
    )

    plan = engine.plan_with_context(context)

    assert plan.active_persona_id == "persona-torch"
    assert plan.metadata["runtime_type"] == "torch_runtime"
    assert plan.metadata["runtime_device"] == "cpu"
    assert len(plan.actions) == 1
    assert plan.actions[0].candidate_id == "cand-name"
    assert plan.actions[0].action_type == ActionType.PERSONA_SLOT
    assert plan.actions[0].persona_id == "persona-torch"
    assert plan.actions[0].replacement_text == "李四"
    assert "torch_tiny_policy" in plan.actions[0].reason
