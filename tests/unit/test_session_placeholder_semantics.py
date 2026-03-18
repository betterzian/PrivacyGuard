"""session 级占位符与恢复语义测试。"""

from pydantic import ValidationError

from privacyguard.api.dto import RestoreRequest, SanitizeRequest
from privacyguard.app.schemas import SanitizeRequestModel
from privacyguard.application.pipelines.restore_pipeline import run_restore_pipeline
from privacyguard.application.pipelines.sanitize_pipeline import run_sanitize_pipeline
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.label_only_engine import LabelOnlyDecisionEngine
from privacyguard.infrastructure.decision.label_persona_mixed_engine import LabelPersonaMixedDecisionEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
from privacyguard.infrastructure.restoration.action_restorer import ActionRestorer


class _EmptyPersonaRepo:
    def get_persona(self, persona_id):
        return None

    def list_personas(self):
        return []

    def get_slot_value(self, persona_id, attr_type):
        return None


class _OCR:
    def extract(self, image):
        return []


class _Detector:
    def __init__(self, candidates):
        self._candidates = candidates

    def detect(self, prompt_text, ocr_blocks):
        return self._candidates


def _name_candidate(entity_id: str, text: str, start: int, end: int) -> PIICandidate:
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        normalized_text=text,
        attr_type=PIIAttributeType.NAME,
        source=PIISourceType.PROMPT,
        span_start=start,
        span_end=end,
        confidence=0.95,
    )


def _address_candidate(entity_id: str, text: str, start: int, end: int) -> PIICandidate:
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        normalized_text=text,
        attr_type=PIIAttributeType.ADDRESS,
        source=PIISourceType.PROMPT,
        span_start=start,
        span_end=end,
        confidence=0.95,
    )


def test_sanitize_pipeline_allocates_session_unique_placeholders_across_turns() -> None:
    mapping_store = InMemoryMappingStore()
    persona_repo = _EmptyPersonaRepo()
    renderer = PromptRenderer()
    engine = LabelOnlyDecisionEngine(persona_repository=persona_repo)

    turn1 = run_sanitize_pipeline(
        request=SanitizeRequest(session_id="session-a", turn_id=1, prompt_text="张三", screenshot=None),
        ocr_engine=_OCR(),
        pii_detector=_Detector([_name_candidate("cand-1", "张三", 0, 2)]),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=engine,
        rendering_engine=renderer,
    )
    turn2 = run_sanitize_pipeline(
        request=SanitizeRequest(session_id="session-a", turn_id=2, prompt_text="李四", screenshot=None),
        ocr_engine=_OCR(),
        pii_detector=_Detector([_name_candidate("cand-2", "李四", 0, 2)]),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=engine,
        rendering_engine=renderer,
    )

    assert turn1.sanitized_prompt_text == "@姓名1"
    assert turn2.sanitized_prompt_text == "@姓名2"

    restored = run_restore_pipeline(
        request=RestoreRequest(
            session_id="session-a",
            turn_id=2,
            cloud_text="当前是@姓名2",
        ),
        mapping_store=mapping_store,
        restoration_module=ActionRestorer(),
    )

    assert restored.restored_text == "当前是李四"


def test_restore_only_uses_current_turn_records() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-a2",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-a2",
                turn_id=1,
                candidate_id="cand-1",
                source_text="张三",
                replacement_text="@姓名1",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    mapping_store.save_replacements(
        session_id="session-a2",
        turn_id=2,
        records=[
            ReplacementRecord(
                session_id="session-a2",
                turn_id=2,
                candidate_id="cand-2",
                source_text="李四",
                replacement_text="@姓名2",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )

    restored = run_restore_pipeline(
        request=RestoreRequest(
            session_id="session-a2",
            turn_id=2,
            cloud_text="上一轮@姓名1，这一轮@姓名2",
        ),
        mapping_store=mapping_store,
        restoration_module=ActionRestorer(),
    )

    assert restored.restored_text == "上一轮@姓名1，这一轮李四"


def test_sanitize_pipeline_reuses_placeholder_for_canonicalized_addresses() -> None:
    mapping_store = InMemoryMappingStore()
    persona_repo = _EmptyPersonaRepo()
    renderer = PromptRenderer()
    engine = LabelOnlyDecisionEngine(persona_repository=persona_repo)

    turn1 = run_sanitize_pipeline(
        request=SanitizeRequest(session_id="session-addr", turn_id=1, prompt_text="四川省成都市", screenshot=None),
        ocr_engine=_OCR(),
        pii_detector=_Detector([_address_candidate("cand-1", "四川省成都市", 0, 6)]),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=engine,
        rendering_engine=renderer,
    )
    turn2 = run_sanitize_pipeline(
        request=SanitizeRequest(session_id="session-addr", turn_id=2, prompt_text="四川成都市", screenshot=None),
        ocr_engine=_OCR(),
        pii_detector=_Detector([_address_candidate("cand-2", "四川成都市", 0, 5)]),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=engine,
        rendering_engine=renderer,
    )

    assert turn1.sanitized_prompt_text == "@地址1"
    assert turn2.sanitized_prompt_text == "@地址1"


def test_label_persona_mixed_replaces_address_by_source_granularity() -> None:
    class _AddressPersonaRepo:
        def get_persona(self, persona_id):
            return PersonaProfile(
                persona_id="persona-1",
                display_name="persona-1",
                slots={PIIAttributeType.ADDRESS: "广东省广州市天河区体育西路100号"},
                stats={},
            )

        def list_personas(self):
            return [self.get_persona("persona-1")]

        def get_slot_value(self, persona_id, attr_type):
            if attr_type == PIIAttributeType.ADDRESS:
                return "广东省广州市天河区体育西路100号"
            return None

    mapping_store = InMemoryMappingStore()

    response = run_sanitize_pipeline(
        request=SanitizeRequest(
            session_id="session-persona-addr",
            turn_id=1,
            prompt_text="收货地址：四川省成都市",
            screenshot=None,
        ),
        ocr_engine=_OCR(),
        pii_detector=_Detector([_address_candidate("cand-addr", "四川省成都市", 5, 11)]),
        persona_repository=_AddressPersonaRepo(),
        mapping_store=mapping_store,
        decision_engine=LabelPersonaMixedDecisionEngine(persona_repository=_AddressPersonaRepo()),
        rendering_engine=PromptRenderer(),
    )

    assert response.sanitized_prompt_text == "收货地址：广东省广州市"


def test_label_persona_mixed_downgrade_still_produces_unique_placeholders() -> None:
    mapping_store = InMemoryMappingStore()
    persona_repo = _EmptyPersonaRepo()

    response = run_sanitize_pipeline(
        request=SanitizeRequest(session_id="session-b", turn_id=1, prompt_text="张三和李四", screenshot=None),
        ocr_engine=_OCR(),
        pii_detector=_Detector(
            [
                _name_candidate("cand-1", "张三", 0, 2),
                _name_candidate("cand-2", "李四", 3, 5),
            ]
        ),
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=LabelPersonaMixedDecisionEngine(persona_repository=persona_repo),
        rendering_engine=PromptRenderer(),
    )

    assert response.sanitized_prompt_text == "@姓名1和@姓名2"

    restored = run_restore_pipeline(
        request=RestoreRequest(
            session_id="session-b",
            turn_id=1,
            cloud_text=response.sanitized_prompt_text,
        ),
        mapping_store=mapping_store,
        restoration_module=ActionRestorer(),
    )

    assert restored.restored_text == "张三和李四"


def test_in_memory_mapping_store_replaces_turn_snapshot() -> None:
    store = InMemoryMappingStore()
    store.save_replacements(
        session_id="session-c",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-c",
                turn_id=1,
                candidate_id="cand-1",
                source_text="张三",
                replacement_text="@姓名1",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    store.save_replacements(
        session_id="session-c",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-c",
                turn_id=1,
                candidate_id="cand-2",
                source_text="13800138000",
                replacement_text="@手机号1",
                attr_type=PIIAttributeType.PHONE,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )

    assert [(record.candidate_id, record.source_text) for record in store.get_replacements("session-c", 1)] == [
        ("cand-2", "13800138000")
    ]

    store.save_replacements(session_id="session-c", turn_id=1, records=[])
    assert store.get_replacements("session-c", 1) == []


def test_sanitize_payload_forbids_extra_fields() -> None:
    try:
        SanitizeRequestModel.from_payload(
            {
                "session_id": "session-d",
                "turn_id": 1,
                "prompt": "张三",
                "image": None,
                "decision_mode": "label_only",
            }
        )
    except ValidationError as exc:
        assert "decision_mode" in str(exc)
    else:
        raise AssertionError("payload 包含额外字段时应直接报错。")
