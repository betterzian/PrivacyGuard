"""sanitize pipeline 的 de_model 上下文接线测试。"""

from privacyguard.api.dto import SanitizeRequest
from privacyguard.application.pipelines.sanitize_pipeline import run_sanitize_pipeline
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
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


class _OCR:
    def __init__(self, blocks: list[OCRTextBlock]) -> None:
        self.blocks = blocks

    def extract(self, image):
        return self.blocks


class _Detector:
    def __init__(self, candidates: list[PIICandidate]) -> None:
        self.candidates = candidates

    def detect(self, prompt_text: str, ocr_blocks: list[OCRTextBlock]) -> list[PIICandidate]:
        return self.candidates


class _SpyDecisionEngine:
    def __init__(self) -> None:
        self.received_context = None

    def plan(self, session_id: str, turn_id: int, candidates, session_binding):
        raise AssertionError("sanitize pipeline 应该优先走 plan_with_context。")

    def plan_with_context(self, context):
        self.received_context = context
        return DecisionPlan(
            session_id=context.session_id,
            turn_id=context.turn_id,
            active_persona_id="persona-1",
            actions=[
                DecisionAction(
                    candidate_id=context.candidates[0].entity_id,
                    action_type=ActionType.GENERICIZE,
                    attr_type=context.candidates[0].attr_type,
                    source=context.candidates[0].source,
                    source_text=context.candidates[0].text,
                    replacement_text="@姓名1",
                )
            ],
            metadata={"mode": "de_model"},
        )


class _Renderer:
    def render_text(self, prompt_text: str, plan: DecisionPlan):
        return (prompt_text.replace("张三", "@姓名1"), [])

    def render_image(self, image, plan: DecisionPlan, ocr_blocks=None):
        return image


class _PassthroughRenderer:
    def render_text(self, prompt_text: str, plan: DecisionPlan):
        return (prompt_text, [])

    def render_image(self, image, plan: DecisionPlan, ocr_blocks=None):
        return image


class _PlainDecisionEngine:
    def plan(self, session_id: str, turn_id: int, candidates, session_binding):
        return DecisionPlan(
            session_id=session_id,
            turn_id=turn_id,
            actions=[],
            metadata={"mode": "label_only"},
        )


def test_sanitize_pipeline_prefers_context_aware_decision_engine() -> None:
    blocks = [
        OCRTextBlock(
            text="张三",
            bbox=BoundingBox(x=1, y=1, width=20, height=10),
            block_id="ocr-1",
        )
    ]
    candidates = [
        PIICandidate(
            entity_id="cand-1",
            text="张三",
            normalized_text="张三",
            attr_type=PIIAttributeType.NAME,
            source=PIISourceType.OCR,
            bbox=BoundingBox(x=1, y=1, width=20, height=10),
            block_id="ocr-1",
            span_start=0,
            span_end=2,
            confidence=0.96,
        )
    ]
    mapping_store = InMemoryMappingStore()
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-1",
                display_name="角色1",
                slots={PIIAttributeType.NAME: "李四"},
                stats={"exposure_count": 0},
            )
        ]
    )
    spy_engine = _SpyDecisionEngine()

    response = run_sanitize_pipeline(
        request=SanitizeRequest(
            session_id="session-pipeline",
            turn_id=1,
            prompt_text="张三去吃饭",
            screenshot="fake-image",
        ),
        ocr_engine=_OCR(blocks),
        pii_detector=_Detector(candidates),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=spy_engine,
        rendering_engine=_Renderer(),
    )

    assert spy_engine.received_context is not None
    assert spy_engine.received_context.prompt_text == "张三去吃饭"
    assert spy_engine.received_context.ocr_blocks == blocks
    assert spy_engine.received_context.candidates == candidates
    assert spy_engine.received_context.session_binding.session_id == "session-pipeline"
    assert response.sanitized_prompt_text == "@姓名1去吃饭"
    assert response.active_persona_id == "persona-1"
    assert mapping_store.get_session_binding("session-pipeline").active_persona_id == "persona-1"


def test_sanitize_pipeline_does_not_print_sensitive_trace_by_default(capsys) -> None:
    mapping_store = InMemoryMappingStore()

    response = run_sanitize_pipeline(
        request=SanitizeRequest(
            session_id="session-no-trace",
            turn_id=1,
            prompt_text="张三去吃饭",
            screenshot=None,
        ),
        ocr_engine=_OCR([]),
        pii_detector=_Detector([]),
        persona_repository=_PersonaRepository([]),
        mapping_store=mapping_store,
        decision_engine=_PlainDecisionEngine(),
        rendering_engine=_PassthroughRenderer(),
    )

    captured = capsys.readouterr()

    assert response.sanitized_prompt_text == "张三去吃饭"
    assert captured.out == ""
    assert captured.err == ""
