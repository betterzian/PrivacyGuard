"""de_model 决策引擎边界测试。"""

from dataclasses import asdict

import pytest

from privacyguard.application.services.decision_context_builder import DecisionModelContext
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.decision.de_model_runtime import DEModelRuntimeOutput, RuntimeCandidateDecision
from privacyguard.infrastructure.decision.features import PROTECTION_LEVEL_ORDER
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
    assert action_map["cand-generic"].replacement_text == "@手机号1"

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
    assert plan.actions[0].replacement_text == "@姓名1"
    assert "已降级为 GENERICIZE" in plan.actions[0].reason


def test_de_model_engine_passes_high_risk_page_signals_to_runtime_for_keep_policy() -> None:
    """高 protection + 差质量页面的 KEEP 策略应由 runtime 决定，engine 负责透传上下文与收敛结果。"""
    persona_repo = _PersonaRepository([])

    def _risk_runtime(*, context, packed):
        protection_start = len(packed.page_vector) - len(PROTECTION_LEVEL_ORDER)
        assert context.page_policy_state["protection_level"] == ProtectionLevel.STRONG.value
        assert context.page_policy_state["page_quality_state"] == "poor"
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
    torch = pytest.importorskip("torch")
    from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyNet, TinyPolicyNetConfig

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
) -> DecisionModelContext:
    candidate_by_id = {candidate.entity_id: candidate for candidate in candidates}
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
    persona_by_id = {persona.persona_id: persona for persona in personas}
    candidate_policy_views = []
    for candidate in candidates:
        is_ocr = candidate.source == PIISourceType.OCR
        covered_block_ids = [str(item) for item in candidate.metadata.get("ocr_block_ids", []) if str(item).strip()]
        if candidate.block_id and candidate.block_id not in covered_block_ids:
            covered_block_ids.append(candidate.block_id)
        candidate_policy_views.append(
            {
                "candidate_id": candidate.entity_id,
                "attr_type": candidate.attr_type,
                "attr_id": candidate.attr_type.value,
                "source": candidate.source,
                "session_alias": f"{candidate.attr_type.value}:{candidate.normalized_text or candidate.text}",
                "same_alias_count_in_turn": 1,
                "cross_source_same_alias_flag": False,
                "history_alias_exposure_bucket": "0",
                "history_exact_match_bucket": "0",
                "det_conf_bucket": "high" if candidate.confidence >= 0.85 else "low",
                "ocr_local_conf_bucket": "low" if is_ocr and page_quality_state == "poor" else "high",
                "low_ocr_flag": bool(is_ocr and page_quality_state == "poor"),
                "cross_block_flag": len(covered_block_ids) > 1,
                "covered_block_count_bucket": "2-3" if len(covered_block_ids) > 1 else ("1" if covered_block_ids else "0"),
                "same_attr_page_bucket": "1",
                "normalized_len_bucket": "3-4",
                "digit_ratio_bucket": "none",
                "mask_char_flag": False,
                "prompt_local_context_labelized": f"[{candidate.attr_type.value}]上下文" if candidate.source == PIISourceType.PROMPT else "",
                "ocr_local_context_labelized": f"[{candidate.attr_type.value}]上下文" if is_ocr else "",
            }
        )
    persona_policy_states = []
    active_persona_id = session_binding.active_persona_id if session_binding else None
    candidate_attr_types = {candidate.attr_type for candidate in candidates}
    for persona in personas:
        supported_attr_mask = {attr.value: attr in persona.slots for attr in PIIAttributeType}
        available_slot_mask = {attr.value: bool(str(persona.slots.get(attr, "")).strip()) for attr in PIIAttributeType}
        persona_policy_states.append(
            {
                "persona_id": persona.persona_id,
                "is_active": persona.persona_id == active_persona_id,
                "supported_attr_mask": supported_attr_mask,
                "available_slot_mask": available_slot_mask,
                "attr_exposure_buckets": {
                    attr.value: ("1" if attr in persona.slots else "0")
                    for attr in PIIAttributeType
                },
                "matched_candidate_attr_count": len(candidate_attr_types.intersection(set(persona.slots.keys()))),
                "_slot_count": len(persona.slots),
                "_display_name": persona.display_name,
                "_exposure_count": int(persona.stats.get("exposure_count", 0) or 0),
                "_supported_attr_types": sorted(persona.slots.keys(), key=lambda item: item.value),
                "_slots": persona.slots,
            }
        )
    page_policy_state = {
        "protection_level": protection_level.value,
        "candidate_count_bucket": "2-3" if len(candidates) >= 2 else "1",
        "unique_attr_count_bucket": "2-3" if len({candidate.attr_type for candidate in candidates}) >= 2 else "1",
        "avg_det_conf_bucket": "high",
        "min_det_conf_bucket": "high",
        "avg_ocr_conf_bucket": "low" if page_quality_state == "poor" else "high",
        "low_ocr_ratio_bucket": "high" if page_quality_state == "poor" else "none",
        "page_quality_state": page_quality_state,
        "_prompt_length": 16,
        "_ocr_block_count": len(ocr_items),
        "_candidate_count": len(candidates),
        "_unique_attr_count": len({candidate.attr_type for candidate in candidates}),
        "_history_record_count": 0,
        "_active_persona_bound": bool(active_persona_id),
        "_prompt_has_digits": False,
        "_prompt_has_address_tokens": False,
        "_average_candidate_confidence": 0.9,
        "_min_candidate_confidence": min((candidate.confidence for candidate in candidates), default=0.0),
        "_high_confidence_candidate_ratio": 1.0,
        "_low_confidence_candidate_ratio": 0.0,
        "_prompt_candidate_count": sum(1 for candidate in candidates if candidate.source == PIISourceType.PROMPT),
        "_ocr_candidate_count": sum(1 for candidate in candidates if candidate.source == PIISourceType.OCR),
        "_average_ocr_block_score": 0.4 if page_quality_state == "poor" else 0.9,
        "_min_ocr_block_score": 0.4 if page_quality_state == "poor" else 0.9,
        "_low_confidence_ocr_block_ratio": 1.0 if page_quality_state == "poor" else 0.0,
    }
    return DecisionModelContext(
        session_id=session_id,
        turn_id=1,
        prompt_text="测试输入",
        protection_level=protection_level,
        ocr_blocks=ocr_items,
        candidates=candidates,
        session_binding=session_binding,
        history_records=[],
        persona_profiles=personas,
        raw_refs={
            "prompt_text": "测试输入",
            "candidate_by_id": candidate_by_id,
            "ocr_block_by_id": {item.block_id: item for item in ocr_items if item.block_id},
            "history_records": [],
            "persona_by_id": persona_by_id,
            "session_binding": session_binding,
        },
        candidate_policy_views=candidate_policy_views,
        page_policy_state=page_policy_state,
        persona_policy_states=persona_policy_states,
    )
