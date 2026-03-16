"""DEModel 规则评分占位决策引擎。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class DEModelEngine:
    """使用启发式评分模拟 DEmodel 的可运行占位实现。"""

    def __init__(
        self,
        persona_repository: PersonaRepository | None = None,
        mapping_store: MappingStore | None = None,
        keep_threshold: float = 0.25,
    ) -> None:
        """初始化依赖与评分阈值。"""
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.mapping_store = mapping_store
        self.keep_threshold = keep_threshold
        self.constraint_resolver = ConstraintResolver(self.persona_repository)
        self.persona_attr_types = {
            PIIAttributeType.NAME,
            PIIAttributeType.PHONE,
            PIIAttributeType.ADDRESS,
            PIIAttributeType.EMAIL,
        }

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """根据规则评分生成 DEmodel 占位计划。"""
        active_persona_id = self._select_persona_id(session_binding)
        existing = self.mapping_store.get_replacements(session_id=session_id) if self.mapping_store else []
        history_keys = {(item.attr_type, item.replacement_text) for item in existing}
        actions: list[DecisionAction] = []
        for candidate in candidates:
            decided = self._decide_action(candidate=candidate, active_persona_id=active_persona_id, history_keys=history_keys)
            actions.append(decided)
        binding = session_binding or SessionBinding(session_id=session_id, active_persona_id=active_persona_id)
        if binding.active_persona_id is None:
            binding.active_persona_id = active_persona_id
        resolved = self.constraint_resolver.resolve(actions=actions, candidates=candidates, session_binding=binding)
        return DecisionPlan(
            session_id=session_id,
            turn_id=turn_id,
            active_persona_id=binding.active_persona_id,
            actions=resolved,
            summary=f"de_model_engine 占位评分生成 {len(resolved)} 条动作。",
            metadata={"mode": "de_model_engine", "engine_type": "rule_scorer_placeholder"},
        )

    def _decide_action(
        self,
        candidate: PIICandidate,
        active_persona_id: str | None,
        history_keys: set[tuple[PIIAttributeType, str]],
    ) -> DecisionAction:
        """对单个候选执行规则评分并选取动作。"""
        has_history = any(item[0] == candidate.attr_type for item in history_keys)
        score_keep = 0.7 if candidate.confidence <= self.keep_threshold else 0.1
        score_generic = 0.4 + candidate.confidence * 0.4 + (0.1 if has_history else 0.0)
        score_persona = 0.0
        if candidate.attr_type in self.persona_attr_types:
            score_persona += 0.5
        if active_persona_id:
            score_persona += 0.2
        if has_history:
            score_persona += 0.2
        score_persona += min(candidate.confidence, 1.0) * 0.2

        scores = {
            ActionType.KEEP: score_keep,
            ActionType.GENERICIZE: score_generic,
            ActionType.PERSONA_SLOT: score_persona,
        }
        action_type = max(scores, key=scores.get)
        if action_type == ActionType.KEEP:
            return DecisionAction(
                candidate_id=candidate.entity_id,
                action_type=ActionType.KEEP,
                attr_type=candidate.attr_type,
                source_text=candidate.text,
                bbox=candidate.bbox,
                reason="规则评分选择 KEEP。",
            )
        if action_type == ActionType.PERSONA_SLOT:
            return DecisionAction(
                candidate_id=candidate.entity_id,
                action_type=ActionType.PERSONA_SLOT,
                attr_type=candidate.attr_type,
                persona_id=active_persona_id,
                replacement_text=None,
                source_text=candidate.text,
                bbox=candidate.bbox,
                reason="规则评分选择 PERSONA_SLOT。",
            )
        return DecisionAction(
            candidate_id=candidate.entity_id,
            action_type=ActionType.GENERICIZE,
            attr_type=candidate.attr_type,
            replacement_text=self._label_for_attr(candidate.attr_type),
            source_text=candidate.text,
            bbox=candidate.bbox,
            reason="规则评分选择 GENERICIZE。",
        )

    def _select_persona_id(self, session_binding: SessionBinding | None) -> str | None:
        """从会话绑定或仓库中选择 persona。"""
        if session_binding and session_binding.active_persona_id:
            return session_binding.active_persona_id
        personas = self.persona_repository.list_personas()
        if not personas:
            return None
        sorted_personas = sorted(personas, key=lambda item: int(item.stats.get("exposure_count", 0)))
        return sorted_personas[0].persona_id

    def _label_for_attr(self, attr_type: PIIAttributeType) -> str:
        """将属性类型转换为标准标签。"""
        mapping = {
            PIIAttributeType.NAME: "<NAME>",
            PIIAttributeType.PHONE: "<PHONE>",
            PIIAttributeType.EMAIL: "<EMAIL>",
            PIIAttributeType.ADDRESS: "<ADDRESS>",
            PIIAttributeType.ID_NUMBER: "<ID_NUMBER>",
            PIIAttributeType.ORGANIZATION: "<ORGANIZATION>",
            PIIAttributeType.OTHER: "<PII>",
        }
        return mapping.get(attr_type, "<PII>")
