"""NormalizedPII 链路测试。"""

from __future__ import annotations

import json
from pathlib import Path

from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils.normalized_pii import normalize_pii


class InMemoryMappingStore:
    def __init__(self) -> None:
        self._records: dict[str, list[ReplacementRecord]] = {}
        self._bindings: dict[str, SessionBinding] = {}

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        self._records.setdefault(session_id, []).extend(records)

    def get_replacements(self, session_id: str, turn_id: int | None = None) -> list[ReplacementRecord]:
        records = list(self._records.get(session_id, []))
        if turn_id is None:
            return records
        return [record for record in records if record.turn_id == turn_id]

    def get_session_binding(self, session_id: str) -> SessionBinding | None:
        return self._bindings.get(session_id)

    def set_session_binding(self, binding: SessionBinding) -> None:
        self._bindings[binding.session_id] = binding


class StubPersonaRepository:
    def get_persona(self, persona_id: str):
        return None

    def list_personas(self):
        return []

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType):
        return None

    def get_slot_replacement_text(self, persona_id: str, attr_type: PIIAttributeType, source_text: str, metadata=None):
        return None


def test_rule_based_local_dictionary_uses_address_part_terms_and_alias_component():
    payload = {
        "true_personas": [
            {
                "persona_id": "persona-1",
                "slots": {
                    "name": [
                        {
                            "full": {"value": "张三", "aliases": []},
                            "family": {"value": "张", "aliases": []},
                            "given": {"value": "三", "aliases": []},
                            "alias": {"value": "阿三", "aliases": []},
                        }
                    ],
                    "address": [
                        {
                            "city": {"value": "上海", "aliases": []},
                            "district": {"value": "浦东", "aliases": []},
                            "poi": {"value": "阳光国际", "aliases": []},
                            "building": {"value": "10", "aliases": []},
                            "detail": {"value": "102", "aliases": []},
                        }
                    ],
                },
            }
        ]
    }
    repo_path = Path("tests/_privacy_rule_based_fixture.json")
    repo_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        detector = RuleBasedPIIDetector(privacy_repository_path=repo_path)

        address_entries = [entry for entry in detector.local_entries if entry.attr_type == PIIAttributeType.ADDRESS]
        alias_entries = [
            entry
            for entry in detector.local_entries
            if entry.attr_type == PIIAttributeType.NAME and entry.metadata.get("name_component") == ["alias"]
        ]

        assert len(address_entries) == 1
        assert address_entries[0].match_terms == ("上海", "浦东", "阳光国际")
        assert len(alias_entries) == 1
        assert alias_entries[0].match_terms == ("阿三",)
    finally:
        if repo_path.exists():
            repo_path.unlink()



def test_session_service_reuses_organization_alias_by_same_entity():
    store = InMemoryMappingStore()
    service = SessionService(store, StubPersonaRepository())

    first = service.resolve_session_alias(
        "session-1",
        PIIAttributeType.ORGANIZATION,
        "想的美工作室",
        confidence=0.95,
    )
    second = service.resolve_session_alias(
        "session-1",
        PIIAttributeType.ORGANIZATION,
        "想的美国际",
        confidence=0.95,
    )

    assert first == second



def test_placeholder_allocator_reuses_address_placeholder_by_same_entity():
    store = InMemoryMappingStore()
    store.save_replacements(
        session_id="session-1",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-1",
                turn_id=1,
                candidate_id="candidate-1",
                source_text="上海浦东阳光国际10-1-102",
                normalized_source=normalize_pii(
                    PIIAttributeType.ADDRESS,
                    "",
                    components={
                        "city": "上海",
                        "district": "浦东新区",
                        "poi": "阳光国际",
                        "building": "10",
                        "detail": "102",
                    },
                ),
                canonical_source_text=None,
                replacement_text="⟨ADDR#1.CITY-DIST-DTL⟩",
                attr_type=PIIAttributeType.ADDRESS,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
                entity_id=1,
            )
        ],
    )

    plan = DecisionPlan(
        session_id="session-1",
        turn_id=2,
        actions=[
            DecisionAction(
                candidate_id="candidate-2",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.ADDRESS,
                source_text="上海浦东阳光10-102",
                normalized_source=normalize_pii(
                    PIIAttributeType.ADDRESS,
                    "",
                    components={
                        "city": "上海",
                        "district": "浦东",
                        "poi": "阳光",
                        "building": "10",
                        "detail": "102",
                    },
                ),
            )
        ],
    )

    assigned = SessionPlaceholderAllocator(store).assign(plan)

    # 同实体复用 #1，本次 PII 自身组件投射出 CITY-DIST-DTL（无 ROAD）。
    assert assigned.actions[0].replacement_text == "⟨ADDR#1.CITY-DIST-DTL⟩"
    assert assigned.actions[0].entity_id == 1
