"""决策动作约束解析器。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate


class ConstraintResolver:
    """对决策动作进行合法性校正与降级。"""

    def __init__(self, persona_repository: PersonaRepository) -> None:
        """注入 persona 仓库以支持槽位校验。"""
        self.persona_repository = persona_repository

    def resolve(
        self,
        actions: list[DecisionAction],
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> list[DecisionAction]:
        """按统一规则修正动作，确保可恢复与可解释。"""
        candidate_map = {candidate.entity_id: candidate for candidate in candidates}
        resolved: list[DecisionAction] = []
        for action in actions:
            candidate = candidate_map.get(action.candidate_id)
            if candidate is None:
                resolved.append(
                    DecisionAction(
                        candidate_id=action.candidate_id,
                        action_type=ActionType.KEEP,
                        attr_type=action.attr_type,
                        replacement_text=None,
                        persona_id=None,
                        reason="候选不存在，动作降级为 KEEP。",
                    )
                )
                continue
            resolved.append(self._resolve_single(action, candidate, session_binding))
        return resolved

    def _resolve_single(
        self,
        action: DecisionAction,
        candidate: PIICandidate,
        session_binding: SessionBinding | None,
    ) -> DecisionAction:
        """修正单条动作并补充 reason。"""
        if action.action_type == ActionType.KEEP:
            action.replacement_text = None
            action.persona_id = None
            action.reason = action.reason or "按策略保留原文。"
            return action

        if action.attr_type != candidate.attr_type:
            action.attr_type = candidate.attr_type
            action.action_type = ActionType.GENERICIZE
            action.replacement_text = self._label_for_attr(candidate.attr_type)
            action.persona_id = None
            action.reason = "检测到跨槽位替换，已改为同槽位 GENERICIZE。"
            return action

        if action.action_type == ActionType.PERSONA_SLOT:
            active_persona_id = session_binding.active_persona_id if session_binding else None
            persona_id = active_persona_id or action.persona_id
            if not persona_id:
                action.action_type = ActionType.GENERICIZE
                action.replacement_text = self._label_for_attr(candidate.attr_type)
                action.persona_id = None
                action.reason = "未绑定 persona，已降级为 GENERICIZE。"
                return action
            slot_value = self.persona_repository.get_slot_value(persona_id, candidate.attr_type)
            if not slot_value:
                action.action_type = ActionType.GENERICIZE
                action.replacement_text = self._label_for_attr(candidate.attr_type)
                action.persona_id = None
                action.reason = "persona 缺少槽位值，已降级为 GENERICIZE。"
                return action
            action.persona_id = persona_id
            action.replacement_text = slot_value
            action.reason = action.reason or "使用 persona 槽位值替换。"
            return action

        if action.action_type == ActionType.GENERICIZE:
            if not action.replacement_text:
                action.replacement_text = self._label_for_attr(candidate.attr_type)
            action.persona_id = None
            action.reason = action.reason or "使用标准标签替换。"
            return action

        action.action_type = ActionType.KEEP
        action.replacement_text = None
        action.persona_id = None
        action.reason = "动作类型非法，已降级为 KEEP。"
        return action

    def _label_for_attr(self, attr_type: PIIAttributeType) -> str:
        """将属性类型映射为统一标签文本。"""
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

