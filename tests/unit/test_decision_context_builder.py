"""de_model 上下文构造测试。"""

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder, DecisionModelContext
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
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


def test_decision_context_builder_builds_new_policy_views_for_prompt_and_single_block_ocr() -> None:
    """builder 负责收敛策略上下文，不负责 detector 本身。"""
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-1",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-1",
                turn_id=1,
                candidate_id="old-name",
                source_text="张三",
                replacement_text="李四",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.PERSONA_SLOT,
                source=PIISourceType.PROMPT,
                persona_id="persona-b",
            )
        ],
    )
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-a",
                display_name="角色A",
                slots={PIIAttributeType.EMAIL: "a@example.com"},
                stats={"exposure_count": 5},
            ),
            PersonaProfile(
                persona_id="persona-b",
                display_name="角色B",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.ADDRESS: "北京市朝阳区",
                },
                stats={
                    "exposure_count": 1,
                    "last_exposed_session_id": "session-1",
                    "last_exposed_turn_id": 1,
                },
            ),
        ]
    )
    builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repo)

    context = builder.build(
        session_id="session-1",
        turn_id=2,
        prompt_text="姓名：张三，电话 13800138000",
        protection_level=ProtectionLevel.STRONG,
        ocr_blocks=[
            OCRTextBlock(
                text="北京市海淀区中关村",
                bbox=BoundingBox(x=10, y=20, width=140, height=30),
                block_id="ocr-1",
                score=0.98,
            )
        ],
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=3,
                span_end=5,
                confidence=0.93,
            ),
            PIICandidate(
                entity_id="cand-addr",
                text="海淀区",
                normalized_text="海淀区",
                attr_type=PIIAttributeType.ADDRESS,
                source=PIISourceType.OCR,
                bbox=BoundingBox(x=40, y=20, width=60, height=30),
                block_id="ocr-1",
                span_start=3,
                span_end=6,
                confidence=0.88,
            ),
        ],
        session_binding=SessionBinding(session_id="session-1", active_persona_id="persona-b"),
    )

    assert isinstance(context, DecisionModelContext)
    assert len(context.candidate_policy_views) == 2
    assert len(context.persona_policy_states) == 2

    # raw_refs: 只重排索引现有对象，不引入新的 detector/linking 真值对象。
    assert context.raw_refs["prompt_text"] == "姓名：张三，电话 13800138000"
    assert context.raw_refs["candidate_by_id"]["cand-name"].text == "张三"
    assert context.raw_refs["ocr_block_by_id"]["ocr-1"].text == "北京市海淀区中关村"
    assert context.raw_refs["persona_by_id"]["persona-b"].display_name == "角色B"
    assert context.raw_refs["history_records"][0].candidate_id == "old-name"
    assert context.raw_refs["session_binding"].active_persona_id == "persona-b"

    candidate_views = _candidate_views_by_id(context)
    name_view = candidate_views["cand-name"]
    assert name_view["source"] == PIISourceType.PROMPT
    assert name_view["session_alias"].startswith(f"{PIIAttributeType.NAME.value}:")
    assert name_view["same_alias_count_in_turn"] == 1
    assert name_view["history_alias_exposure_bucket"] == "1"
    assert name_view["history_exact_match_bucket"] == "1"
    assert name_view["det_conf_bucket"] == "high"
    assert name_view["cross_block_flag"] is False
    assert "[姓名]" in name_view["prompt_local_context_labelized"]

    address_view = candidate_views["cand-addr"]
    assert address_view["source"] == PIISourceType.OCR
    assert address_view["cross_block_flag"] is False
    assert address_view["covered_block_count_bucket"] == "1"
    assert address_view["ocr_local_conf_bucket"] == "high"
    assert address_view["low_ocr_flag"] is False
    assert address_view["same_attr_page_bucket"] == "1"
    assert "[地址]" in address_view["ocr_local_context_labelized"]

    # page_policy_state: 页面级策略状态直接服务 runtime / 训练，不再以旧 page_features 为主断言对象。
    assert context.page_policy_state["protection_level"] == ProtectionLevel.STRONG.value
    assert context.page_policy_state["candidate_count_bucket"] == "2-3"
    assert context.page_policy_state["unique_attr_count_bucket"] == "2-3"
    assert context.page_policy_state["avg_det_conf_bucket"] == "high"
    assert context.page_policy_state["avg_ocr_conf_bucket"] == "high"
    assert context.page_policy_state["page_quality_state"] == "good"

    persona_states = _persona_states_by_id(context)
    assert persona_states["persona-b"]["is_active"] is True
    assert persona_states["persona-b"]["matched_candidate_attr_count"] == 2
    assert persona_states["persona-b"]["supported_attr_mask"][PIIAttributeType.NAME.value] is True
    assert persona_states["persona-b"]["available_slot_mask"][PIIAttributeType.ADDRESS.value] is True
    assert persona_states["persona-a"]["is_active"] is False


def test_decision_context_builder_marks_cross_block_and_low_ocr_quality_candidates() -> None:
    """builder 需要收敛 OCR 跨 block 与低质量信号，供后续策略层消费。"""
    builder = DecisionContextBuilder(
        mapping_store=InMemoryMappingStore(),
        persona_repository=_PersonaRepository(
            [
                PersonaProfile(
                    persona_id="persona-phone",
                    display_name="角色手机号",
                    slots={PIIAttributeType.PHONE: "13900001111"},
                    stats={"exposure_count": 0},
                )
            ]
        ),
    )

    context = builder.build(
        session_id="session-cross-block",
        turn_id=1,
        prompt_text="请联系对方",
        protection_level=ProtectionLevel.BALANCED,
        ocr_blocks=[
            OCRTextBlock(
                text="138001",
                bbox=BoundingBox(x=0, y=0, width=60, height=20),
                block_id="ocr-1",
                score=0.45,
            ),
            OCRTextBlock(
                text="38000",
                bbox=BoundingBox(x=62, y=0, width=60, height=20),
                block_id="ocr-2",
                score=0.55,
            ),
        ],
        candidates=[
            PIICandidate(
                entity_id="cand-phone",
                text="13800138000",
                normalized_text="13800138000",
                attr_type=PIIAttributeType.PHONE,
                source=PIISourceType.OCR,
                bbox=BoundingBox(x=0, y=0, width=122, height=20),
                block_id="ocr-1",
                confidence=0.92,
                metadata={"ocr_block_ids": ["ocr-1", "ocr-2"]},
            )
        ],
    )

    assert isinstance(context, DecisionModelContext)
    assert context.raw_refs["session_binding"] is None
    assert set(context.raw_refs["ocr_block_by_id"]) == {"ocr-1", "ocr-2"}

    phone_view = _candidate_views_by_id(context)["cand-phone"]
    assert phone_view["source"] == PIISourceType.OCR
    assert phone_view["cross_block_flag"] is True
    assert phone_view["covered_block_count_bucket"] == "2-3"
    assert phone_view["low_ocr_flag"] is True
    assert phone_view["ocr_local_conf_bucket"] == "medium"
    assert phone_view["digit_ratio_bucket"] == "high"

    assert context.page_policy_state["protection_level"] == ProtectionLevel.BALANCED.value
    assert context.page_policy_state["candidate_count_bucket"] == "1"
    assert context.page_policy_state["avg_ocr_conf_bucket"] == "medium"
    assert context.page_policy_state["low_ocr_ratio_bucket"] == "high"
    assert context.page_policy_state["page_quality_state"] == "poor"

    persona_states = _persona_states_by_id(context)
    assert persona_states["persona-phone"]["is_active"] is False
    assert persona_states["persona-phone"]["matched_candidate_attr_count"] == 1


def test_decision_context_builder_handles_active_persona_absence_without_mutating_persona_state() -> None:
    """没有 active persona 时，builder 只反映当前 session 状态，不自行决定 persona。"""
    builder = DecisionContextBuilder(
        mapping_store=InMemoryMappingStore(),
        persona_repository=_PersonaRepository(
            [
                PersonaProfile(
                    persona_id="persona-a",
                    display_name="角色A",
                    slots={PIIAttributeType.NAME: "李四"},
                    stats={"exposure_count": 0},
                ),
                PersonaProfile(
                    persona_id="persona-b",
                    display_name="角色B",
                    slots={PIIAttributeType.EMAIL: "b@example.com"},
                    stats={"exposure_count": 3},
                ),
            ]
        ),
    )

    context = builder.build(
        session_id="session-no-active-persona",
        turn_id=3,
        prompt_text="张三在这里",
        protection_level=ProtectionLevel.WEAK,
        candidates=[
            PIICandidate(
                entity_id="cand-name",
                text="张三",
                normalized_text="张三",
                attr_type=PIIAttributeType.NAME,
                source=PIISourceType.PROMPT,
                span_start=0,
                span_end=2,
                confidence=0.91,
            )
        ],
        session_binding=SessionBinding(session_id="session-no-active-persona", active_persona_id=None),
    )

    assert context.raw_refs["session_binding"] is not None
    assert context.raw_refs["session_binding"].active_persona_id is None
    persona_states = _persona_states_by_id(context)
    assert persona_states["persona-a"]["is_active"] is False
    assert persona_states["persona-b"]["is_active"] is False
    assert persona_states["persona-a"]["matched_candidate_attr_count"] == 1
    assert persona_states["persona-b"]["matched_candidate_attr_count"] == 0
    assert context.page_policy_state["protection_level"] == ProtectionLevel.WEAK.value


def _candidate_views_by_id(context: DecisionModelContext) -> dict[str, dict[str, object]]:
    return {
        str(view["candidate_id"]): view
        for view in context.candidate_policy_views
    }


def _persona_states_by_id(context: DecisionModelContext) -> dict[str, dict[str, object]]:
    return {
        str(state["persona_id"]): state
        for state in context.persona_policy_states
    }
