"""de_model 决策引擎边界测试。"""

from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
import shutil
from uuid import uuid4

import pytest

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.decision.de_model_runtime import DEModelRuntimeOutput, RuntimeCandidateDecision
from privacyguard.infrastructure.decision.features import PROTECTION_LEVEL_ORDER
from privacyguard.infrastructure.decision.policy_context import derive_policy_context
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


class _SpyRuntime:
    def __init__(self, response_factory) -> None:
        self.response_factory = response_factory
        self.calls = 0
        self.last_context = None
        self.last_packed = None

    def predict(self, *, context, packed):
        self.calls += 1
        self.last_context = context
        self.last_packed = packed
        return self.response_factory(context=context, packed=packed)


@contextmanager
def _workspace_temp_dir(prefix: str):
    root = Path("artifacts") / "test_tmp"
    root.mkdir(parents=True, exist_ok=True)
    directory = root / f"{prefix}-{uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_de_model_engine_uses_runtime_and_constraint_resolution_without_building_context() -> None:
    """engine 消费既有上下文，调用 runtime，并让 resolver 收敛最终动作。"""
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-main",
                display_name="角色主",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.PHONE: "13900001111",
                },
                stats={"exposure_count": 0},
            )
        ]
    )
    context = _make_context(
        session_id="session-engine-main",
        protection_level=ProtectionLevel.BALANCED,
        page_quality_state="mixed",
        candidates=[
            PIICandidate(
                entity_id="cand-keep",
                text="普通文本",
                normalized_text="普通文本",
                attr_type=PIIAttributeType.OTHER,
                source=PIISourceType.PROMPT,
                confidence=0.92,
            ),
            PIICandidate(
                entity_id="cand-generic",
                text="13800138000",
                normalized_text="13800138000",
                attr_type=PIIAttributeType.PHONE,
                source=PIISourceType.PROMPT,
                confidence=0.93,
            ),
            PIICandidate(
                entity_id="cand-persona",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                bbox=BoundingBox(x=5, y=10, width=48, height=18),
                block_id="ocr-9",
                span_start=0,
                span_end=2,
                confidence=0.97,
            ),
        ],
        personas=persona_repo.list_personas(),
        session_binding=SessionBinding(session_id="session-engine-main", active_persona_id="persona-main"),
    )
    runtime = _SpyRuntime(
        lambda **_kwargs: DEModelRuntimeOutput(
            active_persona_id="persona-main",
            candidate_decisions=[
                RuntimeCandidateDecision(
                    candidate_id="cand-keep",
                    final_action=ActionType.KEEP,
                    confidence=0.51,
                    reasons=["runtime keep"],
                    fallback_reason="risk_sensitive_keep",
                ),
                RuntimeCandidateDecision(
                    candidate_id="cand-generic",
                    final_action=ActionType.GENERICIZE,
                    confidence=0.88,
                    reasons=["runtime generic"],
                ),
                RuntimeCandidateDecision(
                    candidate_id="cand-persona",
                    final_action=ActionType.PERSONA_SLOT,
                    persona_id="persona-main",
                    confidence=0.95,
                    reasons=["runtime persona"],
                ),
            ],
        )
    )
    engine = DEModelEngine(
        persona_repository=persona_repo,
        mapping_store=InMemoryMappingStore(),
        runtime=runtime,
    )

    plan = engine.plan(context)

    assert runtime.calls == 1
    assert runtime.last_context is context
    assert plan.metadata["mode"] == "de_model"
    assert plan.metadata["engine_type"] == "tiny_policy_skeleton"

    action_map = {item.candidate_id: item for item in plan.actions}
    assert action_map["cand-keep"].action_type == ActionType.KEEP
    assert "risk_sensitive_keep" in action_map["cand-keep"].reason

    assert action_map["cand-generic"].action_type == ActionType.GENERICIZE
    assert action_map["cand-generic"].replacement_text == "<手机号1>"

    assert action_map["cand-persona"].action_type == ActionType.PERSONA_SLOT
    assert action_map["cand-persona"].persona_id == "persona-main"
    assert action_map["cand-persona"].replacement_text == "李四"
    assert action_map["cand-persona"].bbox == BoundingBox(x=5, y=10, width=48, height=18)
    assert action_map["cand-persona"].block_id == "ocr-9"
    assert action_map["cand-persona"].span_start == 0
    assert action_map["cand-persona"].span_end == 2


def test_de_model_engine_falls_back_persona_slot_to_genericize_when_persona_missing() -> None:
    """runtime 给出 PERSONA_SLOT 时，engine 仍应经过约束收敛。"""
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-no-slot",
                display_name="角色空槽位",
                slots={PIIAttributeType.EMAIL: "demo@example.com"},
                stats={"exposure_count": 0},
            )
        ]
    )
    context = _make_context(
        session_id="session-engine-fallback",
        protection_level=ProtectionLevel.BALANCED,
        page_quality_state="mixed",
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                confidence=0.96,
            )
        ],
        personas=persona_repo.list_personas(),
        session_binding=SessionBinding(session_id="session-engine-fallback", active_persona_id="persona-no-slot"),
    )
    runtime = _SpyRuntime(
        lambda **_kwargs: DEModelRuntimeOutput(
            active_persona_id="persona-no-slot",
            candidate_decisions=[
                RuntimeCandidateDecision(
                    candidate_id="cand-name",
                    final_action=ActionType.PERSONA_SLOT,
                    persona_id="persona-no-slot",
                    confidence=0.94,
                    reasons=["runtime persona without slot"],
                )
            ],
        )
    )
    engine = DEModelEngine(
        persona_repository=persona_repo,
        mapping_store=InMemoryMappingStore(),
        runtime=runtime,
    )

    plan = engine.plan(context)

    assert runtime.calls == 1
    assert plan.actions[0].action_type == ActionType.GENERICIZE
    assert plan.actions[0].persona_id is None
    assert plan.actions[0].replacement_text == "<姓名1>"
    assert "已降级为 GENERICIZE" in plan.actions[0].reason


def test_de_model_engine_passes_high_risk_page_signals_to_runtime_for_keep_policy() -> None:
    """高 protection + 差质量页面的 KEEP 策略应由 runtime 决定，engine 负责透传上下文与收敛结果。"""
    persona_repo = _PersonaRepository([])

    def _risk_runtime(*, context, packed):
        protection_start = len(packed.page_vector) - len(PROTECTION_LEVEL_ORDER)
        policy = derive_policy_context(context)
        assert policy.page_policy_state["protection_level"] == ProtectionLevel.STRONG.value
        assert policy.page_policy_state["page_quality_state"] == "poor"
        assert packed.page_vector[protection_start + PROTECTION_LEVEL_ORDER.index(ProtectionLevel.STRONG.value)] == 1.0
        assert packed.page_vector[14] < 0.75
        assert packed.page_vector[16] == 1.0
        return DEModelRuntimeOutput(
            active_persona_id=None,
            candidate_decisions=[
                RuntimeCandidateDecision(
                    candidate_id="cand-risk",
                    final_action=ActionType.KEEP,
                    confidence=0.22,
                    reasons=["runtime conservative keep"],
                    fallback_reason="strong_protection_poor_quality_keep",
                )
            ],
        )

    runtime = _SpyRuntime(_risk_runtime)
    context = _make_context(
        session_id="session-engine-risk",
        protection_level=ProtectionLevel.STRONG,
        page_quality_state="poor",
        candidates=[
            PIICandidate(
                entity_id="cand-risk",
                text="模糊姓名",
                normalized_text="模糊姓名",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.OCR,
                bbox=BoundingBox(x=0, y=0, width=30, height=10),
                block_id="ocr-risk",
                confidence=0.21,
                metadata={"ocr_block_ids": ["ocr-risk"]},
            )
        ],
        personas=[],
        ocr_blocks=[
            {
                "text": "模糊姓名",
                "score": 0.4,
                "block_id": "ocr-risk",
                "bbox": BoundingBox(x=0, y=0, width=30, height=10),
            }
        ],
        session_binding=None,
    )
    engine = DEModelEngine(
        persona_repository=persona_repo,
        mapping_store=InMemoryMappingStore(),
        runtime=runtime,
    )

    plan = engine.plan(context)

    assert runtime.calls == 1
    assert plan.actions[0].action_type == ActionType.KEEP
    assert "strong_protection_poor_quality_keep" in plan.actions[0].reason


def test_de_model_engine_accepts_explicit_runtime_config() -> None:
    engine = DEModelEngine(
        persona_repository=_PersonaRepository([]),
        mapping_store=InMemoryMappingStore(),
        keep_threshold=0.4,
        persona_score_threshold=0.55,
        action_tie_tolerance=1e-4,
        runtime_type="heuristic",
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


def test_de_model_engine_torch_runtime_runs_checkpoint_inference() -> None:
    torch = pytest.importorskip("torch")
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig

    with _workspace_temp_dir("torch-runtime") as temp_dir:
        checkpoint_path = temp_dir / "tiny_policy.pt"
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
        context = _make_context(
            session_id="session-torch-runtime",
            protection_level=ProtectionLevel.BALANCED,
            page_quality_state="mixed",
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
            personas=persona_repo.list_personas(),
            session_binding=None,
        )

        engine = DEModelEngine(
            persona_repository=persona_repo,
            mapping_store=InMemoryMappingStore(),
            runtime_type="torch",
            checkpoint_path=str(checkpoint_path),
        )

        plan = engine.plan(context)

        assert plan.active_persona_id == "persona-torch"
        assert plan.metadata["runtime_type"] == "torch_runtime"
        assert plan.metadata["runtime_device"] == "cpu"
        assert len(plan.actions) == 1
        assert plan.actions[0].candidate_id == "cand-name"
        assert plan.actions[0].action_type == ActionType.PERSONA_SLOT
        assert plan.actions[0].persona_id == "persona-torch"
        assert plan.actions[0].replacement_text == "李四"
        assert "torch_tiny_policy" in plan.actions[0].reason


def _make_context(
    *,
    session_id: str,
    protection_level: ProtectionLevel,
    page_quality_state: str,
    candidates: list[PIICandidate],
    personas: list[PersonaProfile],
    session_binding: SessionBinding | None,
    ocr_blocks: list[dict[str, object]] | None = None,
) -> DecisionContext:
    _ = page_quality_state
    ocr_items = []
    for item in ocr_blocks or []:
        from privacyguard.domain.models.ocr import OCRTextBlock

        ocr_items.append(
            OCRTextBlock(
                text=str(item["text"]),
                bbox=item["bbox"],
                block_id=str(item["block_id"]),
                score=float(item["score"]),
            )
        )
    return DecisionContext(
        session_id=session_id,
        turn_id=1,
        prompt_text="测试输入",
        protection_level=protection_level,
        ocr_blocks=ocr_items,
        candidates=candidates,
        session_binding=session_binding,
        history_records=[],
        persona_profiles=personas,
    )
