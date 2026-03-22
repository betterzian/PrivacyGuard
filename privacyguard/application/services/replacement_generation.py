"""替换文案生成：决策之后、渲染之前。

将 ``ConstraintResolver`` 结构约束后的计划（``GENERICIZE`` / ``PERSONA_SLOT`` 的
``replacement_text`` 仍为空）补全为可执行计划：

- ``PERSONA_SLOT``：从 persona 仓库解析槽位展示文案；
- ``GENERICIZE``：``SessionPlaceholderAllocator`` 分配会话级 ``<标签n>``，无 ``source_text`` 时回退为 ``<标签1>``。
"""

from __future__ import annotations

from privacyguard.domain.enums import ActionType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.domain.policies.generic_placeholder import render_generic_replacement_text

from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator


class ReplacementGenerationService:
    """决策计划 → 带完整 ``replacement_text`` 的执行计划。"""

    def __init__(self, mapping_store: MappingStore, persona_repository: PersonaRepository) -> None:
        self._mapping_store = mapping_store
        self._persona_repository = persona_repository

    def apply(self, plan: DecisionPlan, context: DecisionContext) -> DecisionPlan:
        """补全 persona 文案与会话级 generic 占位符。"""
        candidate_map: dict[str, PIICandidate] = {c.entity_id: c for c in context.candidates}
        after_persona: list[DecisionAction] = []
        for action in plan.actions:
            if action.action_type != ActionType.PERSONA_SLOT:
                after_persona.append(action.model_copy(deep=True))
                continue
            updated = self._fill_persona_slot(action, candidate_map)
            after_persona.append(updated)

        plan = plan.model_copy(update={"actions": after_persona}, deep=True)
        plan = SessionPlaceholderAllocator(self._mapping_store).assign(plan)

        final_actions: list[DecisionAction] = []
        for action in plan.actions:
            if action.action_type != ActionType.GENERICIZE:
                final_actions.append(action.model_copy(deep=True))
                continue
            if action.replacement_text:
                final_actions.append(action.model_copy(deep=True))
                continue
            candidate = candidate_map.get(action.candidate_id)
            attr = candidate.attr_type if candidate else action.attr_type
            final_actions.append(
                action.model_copy(
                    update={"replacement_text": render_generic_replacement_text(attr, 1)},
                    deep=True,
                )
            )
        return plan.model_copy(update={"actions": final_actions}, deep=True)

    def _fill_persona_slot(self, action: DecisionAction, candidate_map: dict[str, PIICandidate]) -> DecisionAction:
        """为 ``PERSONA_SLOT`` 写入 persona 渲染文案（结构合法性由 ConstraintResolver 保证）。"""
        candidate = candidate_map.get(action.candidate_id)
        if candidate is None:
            return action.model_copy(deep=True)
        persona_id = action.persona_id
        if not persona_id:
            return action.model_copy(deep=True)
        slot_value = self._persona_repository.get_slot_value(persona_id, candidate.attr_type)
        if not slot_value:
            return action.model_copy(deep=True)
        replacement_text = self._persona_repository.get_slot_replacement_text(
            persona_id,
            candidate.attr_type,
            candidate.text,
        )
        text = replacement_text or slot_value
        return action.model_copy(update={"replacement_text": text}, deep=True)


def apply_post_decision_steps(
    plan: DecisionPlan,
    context: DecisionContext,
    mapping_store: MappingStore,
    persona_repository: PersonaRepository,
) -> DecisionPlan:
    """决策引擎产出抽象计划后：结构约束 → 替换文案与会话占位生成。"""
    resolver = ConstraintResolver(persona_repository)
    actions = resolver.resolve(plan.actions, context.candidates, context.session_binding)
    bound = plan.model_copy(update={"actions": actions}, deep=True)
    return ReplacementGenerationService(mapping_store, persona_repository).apply(bound, context)
