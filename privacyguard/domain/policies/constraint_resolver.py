"""决策动作结构约束解析器。

仅修正动作类型与属性一致性，不生成 ``replacement_text``（由 ``ReplacementGenerationService`` 负责）。
"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, clone_action_metadata
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate


class ConstraintResolver:
    """对决策动作做结构级校正与降级；不填充替换文案。"""

    def __init__(self, persona_repository: PersonaRepository) -> None:
        """注入 persona 仓库以支持槽位存在性校验。"""
        self.persona_repository = persona_repository

    def resolve(
        self,
        actions: list[DecisionAction],
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> list[DecisionAction]:
        """按统一规则修正动作类型；``replacement_text`` 保持为 None，交由生成阶段填写。"""
        candidate_map = {candidate.entity_id: candidate for candidate in candidates}
        resolved: list[DecisionAction] = []
        for action in actions:
            candidate = candidate_map.get(action.candidate_id)
            if candidate is None:
                raise ValueError(f"ConstraintResolver 未找到 candidate: {action.candidate_id}")
            resolved.append(self._resolve_single(action, candidate, session_binding))
        return resolved

    def _resolve_single(
        self,
        action: DecisionAction,
        candidate: PIICandidate,
        session_binding: SessionBinding | None,
    ) -> DecisionAction:
        """修正单条动作；不写入 ``replacement_text``。"""
        if action.action_type == ActionType.KEEP:
            action.replacement_text = None
            action.persona_id = None
            action.reason = action.reason or "按策略保留原文。"
            return action

        if action.attr_type != candidate.attr_type:
            raise ValueError(
                f"DecisionAction.attr_type 与 candidate 不一致: "
                f"candidate_id={action.candidate_id}, action={action.attr_type}, candidate={candidate.attr_type}"
            )

        if action.action_type == ActionType.PERSONA_SLOT:
            active_persona_id = session_binding.active_persona_id if session_binding else None
            persona_id = active_persona_id or action.persona_id
            if not persona_id:
                raise ValueError(f"PERSONA_SLOT 缺少 persona_id: candidate_id={action.candidate_id}")
            slot_value = self.persona_repository.get_slot_value(persona_id, candidate.attr_type)
            if not slot_value:
                raise ValueError(
                    f"PERSONA_SLOT 缺少可用槽位: persona_id={persona_id}, attr_type={candidate.attr_type}"
                )
            action.persona_id = persona_id
            action.replacement_text = None
            action.reason = action.reason or "PERSONA_SLOT 已校验，替换文案由生成阶段写入。"
            return action

        if action.action_type == ActionType.GENERICIZE:
            action.replacement_text = None
            action.persona_id = None
            action.reason = action.reason or "使用标准标签替换。"
            return action

        raise ValueError(f"ConstraintResolver 收到非法动作类型: {action.action_type!r}")
