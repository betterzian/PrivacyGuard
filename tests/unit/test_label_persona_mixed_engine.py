"""LabelPersonaMixed 决策引擎测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.label_persona_mixed_engine import LabelPersonaMixedDecisionEngine
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


def _write_personas(tmp_path: Path) -> Path:
    """写入测试 persona 数据。"""
    path = tmp_path / "personas.sample.json"
    path.write_text(
        json.dumps(
            [
                {
                    "persona_id": "p_low",
                    "profile": {"name": "张三", "phone": "13900001111", "address": "上海市XX路", "email": "a@example.com"},
                    "stats": {"exposure_count": 0, "last_exposed_session_id": None, "last_exposed_turn_id": None},
                },
                {
                    "persona_id": "p_high",
                    "profile": {"name": "李四", "phone": "13600002222", "address": "北京市YY路", "email": "b@example.com"},
                    "stats": {"exposure_count": 5, "last_exposed_session_id": "s2", "last_exposed_turn_id": 3},
                },
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def _candidate(entity_id: str, attr_type: PIIAttributeType, text: str) -> PIICandidate:
    """创建测试候选实体。"""
    return PIICandidate(
        entity_id=entity_id,
        text=text,
        normalized_text=text.lower(),
        attr_type=attr_type,
        source=PIISourceType.PROMPT,
        bbox=BoundingBox(x=0, y=0, width=10, height=10),
        confidence=0.95,
    )


def test_label_persona_mixed_selects_persona_when_unbound(tmp_path: Path) -> None:
    """验证未绑定会话时可选出 persona。"""
    repo = JsonPersonaRepository(path=str(_write_personas(tmp_path)))
    engine = LabelPersonaMixedDecisionEngine(persona_repository=repo)
    candidates = [_candidate("c1", PIIAttributeType.NAME, "王五")]

    plan = engine.plan(session_id="s1", turn_id=1, candidates=candidates, session_binding=None)

    assert plan.active_persona_id == "p_low"
    assert plan.actions[0].replacement_text == "张三"


def test_label_persona_mixed_reuses_existing_binding(tmp_path: Path) -> None:
    """验证已绑定会话时沿用既有 persona。"""
    repo = JsonPersonaRepository(path=str(_write_personas(tmp_path)))
    engine = LabelPersonaMixedDecisionEngine(persona_repository=repo)
    candidates = [_candidate("c2", PIIAttributeType.PHONE, "13800138000")]
    binding = SessionBinding(session_id="s1", active_persona_id="p_high")

    plan = engine.plan(session_id="s1", turn_id=2, candidates=candidates, session_binding=binding)

    assert plan.active_persona_id == "p_high"
    assert plan.actions[0].replacement_text == "13600002222"

