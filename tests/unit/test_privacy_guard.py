"""PrivacyGuard 顶层装配与外部入口回归测试。"""

from privacyguard import PrivacyGuard
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore


class _StaticOCREngine:
    def extract(self, image) -> list:
        return []


class _StaticDetector:
    def __init__(self, candidates: list[PIICandidate]) -> None:
        self._candidates = list(candidates)

    def detect(self, prompt_text: str, ocr_blocks: list) -> list[PIICandidate]:
        return list(self._candidates)


class _StaticPersonaRepository:
    def __init__(self, personas: list[PersonaProfile]) -> None:
        self._personas = {persona.persona_id: persona for persona in personas}

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        return persona.slots.get(attr_type)


class _StaticDecisionEngine:
    def plan(self, context) -> DecisionPlan:
        actions: list[DecisionAction] = []
        for candidate in context.candidates:
            if candidate.attr_type == PIIAttributeType.NAME:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.PERSONA_SLOT,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        replacement_text="李四",
                        source_text=candidate.text,
                        canonical_source_text=candidate.canonical_source_text,
                        persona_id="persona-main",
                    )
                )
            elif candidate.attr_type == PIIAttributeType.PHONE:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.GENERICIZE,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        replacement_text=None,
                        source_text=candidate.text,
                        canonical_source_text=candidate.canonical_source_text,
                    )
                )
            else:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.KEEP,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        source_text=candidate.text,
                        canonical_source_text=candidate.canonical_source_text,
                    )
                )
        return DecisionPlan(
            session_id=context.session_id,
            turn_id=context.turn_id,
            active_persona_id="persona-main",
            actions=actions,
            metadata={"mode": "de_model"},
        )


class _SimpleRenderer:
    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        rendered = prompt_text
        records: list[ReplacementRecord] = []
        for action in plan.actions:
            if action.action_type == ActionType.KEEP or not action.replacement_text or not action.source_text:
                continue
            rendered = rendered.replace(action.source_text, action.replacement_text)
            records.append(
                ReplacementRecord(
                    session_id=plan.session_id,
                    turn_id=plan.turn_id,
                    candidate_id=action.candidate_id,
                    source_text=action.source_text,
                    canonical_source_text=action.canonical_source_text,
                    replacement_text=action.replacement_text,
                    attr_type=action.attr_type,
                    action_type=action.action_type,
                    persona_id=action.persona_id,
                    source=action.source,
                )
            )
        return (rendered, records)

    def render_image(self, image, plan: DecisionPlan, ocr_blocks=None):
        return image


class _SimpleRestorationModule:
    def restore(self, cloud_text: str, records: list[ReplacementRecord]) -> tuple[str, list[RestoredSlot]]:
        restored_text = cloud_text
        restored_slots: list[RestoredSlot] = []
        for record in records:
            restored_text = restored_text.replace(record.replacement_text, record.source_text)
            restored_slots.append(
                RestoredSlot(
                    attr_type=record.attr_type.value,
                    value=record.source_text,
                    source_placeholder=record.replacement_text,
                )
            )
        return (restored_text, restored_slots)


def test_privacy_guard_passes_decision_config_to_de_model_engine() -> None:
    guard = PrivacyGuard(
        decision_mode="de_model",
        decision_config={
            "runtime_type": "heuristic",
            "keep_threshold": 0.4,
            "device": "cpu",
        },
    )

    assert guard.decision_mode == "de_model"
    assert guard.decision_engine.runtime_type == "heuristic"
    assert guard.decision_engine.keep_threshold == 0.4
    assert guard.decision_engine.device == "cpu"


def test_privacy_guard_sanitize_and_restore_preserve_external_dto_boundary() -> None:
    mapping_store = InMemoryMappingStore()
    persona_repo = _StaticPersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-main",
                display_name="角色主",
                slots={PIIAttributeType.NAME: "李四"},
                stats={"exposure_count": 0},
            )
        ]
    )
    guard = PrivacyGuard(
        detector=_StaticDetector(
            [
                PIICandidate(
                    entity_id="cand-name",
                    text="张三",
                    normalized_text="张三",
                    attr_type=PIIAttributeType.NAME,
                    source=PIISourceType.PROMPT,
                    span_start=0,
                    span_end=2,
                    confidence=0.99,
                ),
                PIICandidate(
                    entity_id="cand-phone",
                    text="13800138000",
                    normalized_text="13800138000",
                    attr_type=PIIAttributeType.PHONE,
                    source=PIISourceType.PROMPT,
                    span_start=6,
                    span_end=17,
                    confidence=0.98,
                ),
                PIICandidate(
                    entity_id="cand-note",
                    text="普通文本",
                    normalized_text="普通文本",
                    attr_type=PIIAttributeType.OTHER,
                    source=PIISourceType.PROMPT,
                    span_start=18,
                    span_end=22,
                    confidence=0.8,
                ),
            ]
        ),
        decision_engine=_StaticDecisionEngine(),
        ocr=_StaticOCREngine(),
        renderer=_SimpleRenderer(),
        restoration=_SimpleRestorationModule(),
        persona_repo=persona_repo,
        mapping_table=mapping_store,
    )

    sanitize_result = guard.sanitize(
        {
            "session_id": "session-facade",
            "turn_id": 1,
            "prompt_text": "张三的电话是13800138000普通文本",
            "screenshot": None,
        }
    )

    assert sanitize_result == {
        "status": "ok",
        "masked_prompt": "李四的电话是@手机号1普通文本",
        "masked_image": None,
        "session_id": "session-facade",
        "turn_id": 1,
        "mapping_count": 2,
        "active_persona_id": "persona-main",
    }
    assert "protect_decision" not in sanitize_result
    assert "rewrite_mode" not in sanitize_result
    assert "final_action" not in sanitize_result

    records = mapping_store.get_replacements("session-facade", 1)
    assert {record.action_type for record in records} == {ActionType.GENERICIZE, ActionType.PERSONA_SLOT}
    assert all(record.action_type != ActionType.KEEP for record in records)

    restore_result = guard.restore(
        {
            "session_id": "session-facade",
            "turn_id": 1,
            "agent_text": sanitize_result["masked_prompt"],
        }
    )

    assert restore_result == {
        "status": "ok",
        "restored_text": "张三的电话是13800138000普通文本",
        "session_id": "session-facade",
    }
