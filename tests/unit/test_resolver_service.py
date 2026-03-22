from privacyguard.application.services import CandidateResolverService
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver


class _TrackingPersonaRepository:
    def __init__(self, *, slot_value: str | None, replacement_text: str | None) -> None:
        self.slot_value = slot_value
        self.replacement_text = replacement_text
        self.calls: list[tuple[str, str, PIIAttributeType, str | None]] = []

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        self.calls.append(("get_slot_value", persona_id, attr_type, None))
        return self.slot_value

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        self.calls.append(("get_slot_replacement_text", persona_id, attr_type, source_text))
        return self.replacement_text


def _candidate(*, entity_id: str, text: str, attr_type: PIIAttributeType) -> PIICandidate:
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        normalized_text=text,
        attr_type=attr_type,
        source=PIISourceType.PROMPT,
        confidence=0.99,
    )


def _persona_slot_action(candidate: PIICandidate) -> DecisionAction:
    return DecisionAction(
        candidate_id=candidate.entity_id,
        action_type=ActionType.PERSONA_SLOT,
        attr_type=candidate.attr_type,
        source=candidate.source,
        source_text=candidate.text,
    )


def _decision_context(candidate: PIICandidate, *, persona_id: str) -> DecisionContext:
    return DecisionContext(
        session_id="session-1",
        turn_id=1,
        prompt_text=f"输入：{candidate.text}",
        candidates=[candidate],
        session_binding=SessionBinding(session_id="session-1", active_persona_id=persona_id),
    )


def test_candidate_resolver_service_prefers_repository_render_text_for_persona_slot() -> None:
    repository = _TrackingPersonaRepository(
        slot_value="广东省广州市天河区体育西路100号",
        replacement_text="广州天河",
    )
    candidate = _candidate(
        entity_id="cand-addr",
        text="四川省成都市",
        attr_type=PIIAttributeType.ADDRESS,
    )
    service = CandidateResolverService(persona_repository=repository)
    plan = DecisionPlan(
        session_id="session-1",
        turn_id=1,
        active_persona_id="persona-1",
        actions=[_persona_slot_action(candidate)],
    )

    resolved = service.resolve_plan(plan, _decision_context(candidate, persona_id="persona-1")).actions[0]

    assert resolved.action_type == ActionType.PERSONA_SLOT
    assert resolved.persona_id == "persona-1"
    assert resolved.replacement_text == "广州天河"
    assert repository.calls == [
        ("get_slot_value", "persona-1", PIIAttributeType.ADDRESS, None),
        ("get_slot_replacement_text", "persona-1", PIIAttributeType.ADDRESS, "四川省成都市"),
    ]


def test_candidate_resolver_service_falls_back_to_slot_value_when_render_text_empty() -> None:
    repository = _TrackingPersonaRepository(slot_value="李四", replacement_text="")
    candidate = _candidate(
        entity_id="cand-name",
        text="张三",
        attr_type=PIIAttributeType.NAME,
    )
    service = CandidateResolverService(persona_repository=repository)
    plan = DecisionPlan(
        session_id="session-1",
        turn_id=1,
        active_persona_id="persona-1",
        actions=[_persona_slot_action(candidate)],
    )

    resolved = service.resolve_plan(plan, _decision_context(candidate, persona_id="persona-1")).actions[0]

    assert resolved.replacement_text == "李四"
    assert resolved.reason == "PERSONA_SLOT 通过槽位校验，但 persona repository 未提供渲染值，已回退为原始 persona 槽位值。"
    assert repository.calls == [
        ("get_slot_value", "persona-1", PIIAttributeType.NAME, None),
        ("get_slot_replacement_text", "persona-1", PIIAttributeType.NAME, "张三"),
    ]


def test_constraint_resolver_prefers_repository_render_text_for_persona_slot() -> None:
    repository = _TrackingPersonaRepository(slot_value="李四", replacement_text="李岚")
    candidate = _candidate(
        entity_id="cand-name",
        text="张三",
        attr_type=PIIAttributeType.NAME,
    )
    resolver = ConstraintResolver(repository)

    resolved = resolver.resolve(
        [_persona_slot_action(candidate)],
        [candidate],
        SessionBinding(session_id="session-1", active_persona_id="persona-1"),
    )[0]

    assert resolved.action_type == ActionType.PERSONA_SLOT
    assert resolved.persona_id == "persona-1"
    assert resolved.replacement_text == "李岚"
    assert repository.calls == [
        ("get_slot_value", "persona-1", PIIAttributeType.NAME, None),
        ("get_slot_replacement_text", "persona-1", PIIAttributeType.NAME, "张三"),
    ]


def test_constraint_resolver_falls_back_to_slot_value_when_render_text_empty() -> None:
    repository = _TrackingPersonaRepository(slot_value="李四", replacement_text="")
    candidate = _candidate(
        entity_id="cand-name",
        text="张三",
        attr_type=PIIAttributeType.NAME,
    )
    resolver = ConstraintResolver(repository)

    resolved = resolver.resolve(
        [_persona_slot_action(candidate)],
        [candidate],
        SessionBinding(session_id="session-1", active_persona_id="persona-1"),
    )[0]

    assert resolved.replacement_text == "李四"
    assert resolved.reason == "persona repository 未提供渲染值，已回退为原始 persona 槽位值。"
    assert repository.calls == [
        ("get_slot_value", "persona-1", PIIAttributeType.NAME, None),
        ("get_slot_replacement_text", "persona-1", PIIAttributeType.NAME, "张三"),
    ]
