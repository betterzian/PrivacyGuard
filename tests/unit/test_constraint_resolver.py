"""约束解析器测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.decision import DecisionAction
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


def _write_personas(tmp_path: Path) -> Path:
    """写入测试 persona 文件。"""
    path = tmp_path / "personas.sample.json"
    path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "p1",
                    "profile": {"name": "张三", "phone": "13900001111"},
                    "stats": {"exposure_count": 0, "last_exposed_session_id": None, "last_exposed_turn_id": None},
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def _candidate(entity_id: str, attr_type: PIIAttributeType) -> PIICandidate:
    """创建测试候选实体。"""
    return PIICandidate(
        entity_id=entity_id,
        text="demo",
        normalized_text="demo",
        attr_type=attr_type,
        source=PIISourceType.PROMPT,
        bbox=BoundingBox(x=0, y=0, width=10, height=10),
        confidence=0.9,
    )


def test_constraint_resolver_blocks_cross_slot_replace(tmp_path: Path) -> None:
    """验证可阻止跨槽位替换。"""
    resolver = ConstraintResolver(JsonPersonaRepository(path=str(_write_personas(tmp_path))))
    candidate = _candidate("c1", PIIAttributeType.ADDRESS)
    action = DecisionAction(
        candidate_id="c1",
        action_type=ActionType.PERSONA_SLOT,
        attr_type=PIIAttributeType.PHONE,
        persona_id="p1",
    )

    resolved = resolver.resolve([action], [candidate], SessionBinding(session_id="s1", active_persona_id="p1"))

    assert resolved[0].action_type == ActionType.GENERICIZE
    assert resolved[0].attr_type == PIIAttributeType.ADDRESS


def test_constraint_resolver_downgrades_when_persona_slot_missing(tmp_path: Path) -> None:
    """验证 persona 缺槽位时可合理降级。"""
    resolver = ConstraintResolver(JsonPersonaRepository(path=str(_write_personas(tmp_path))))
    candidate = _candidate("c2", PIIAttributeType.EMAIL)
    action = DecisionAction(
        candidate_id="c2",
        action_type=ActionType.PERSONA_SLOT,
        attr_type=PIIAttributeType.EMAIL,
        persona_id="p1",
    )
    resolved = resolver.resolve([action], [candidate], SessionBinding(session_id="s1", active_persona_id="p1"))

    assert resolved[0].action_type == ActionType.GENERICIZE
    assert resolved[0].replacement_text == "<EMAIL>"


def test_constraint_resolver_fixes_illegal_action() -> None:
    """验证非法动作会被修正而非透传。"""
    resolver = ConstraintResolver(JsonPersonaRepository(path="not_found.json"))
    candidate = _candidate("c3", PIIAttributeType.NAME)
    action = DecisionAction(candidate_id="missing", action_type=ActionType.GENERICIZE, attr_type=PIIAttributeType.NAME)
    resolved = resolver.resolve([action], [candidate], None)

    assert resolved[0].action_type == ActionType.KEEP

