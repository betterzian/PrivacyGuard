"""决策动作约束解析器。"""

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, clone_action_metadata
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.utils.pii_value import persona_slot_replacement


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
                        source=action.source,
                        replacement_text=None,
                        persona_id=None,
                        bbox=action.bbox,
                        block_id=action.block_id,
                        span_start=action.span_start,
                        span_end=action.span_end,
                        reason="候选不存在，动作降级为 KEEP。",
                        source_text=action.source_text,
                        canonical_source_text=action.canonical_source_text,
                        metadata=clone_action_metadata(action.metadata),
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
            action.replacement_text = persona_slot_replacement(candidate.attr_type, candidate.text, slot_value)
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

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        """将属性类型映射为中文标签，格式为 @姓名1、@手机号1 等（无尖括号）。"""
        mapping = {
            PIIAttributeType.NAME: "姓名",
            PIIAttributeType.PHONE: "手机号",
            PIIAttributeType.CARD_NUMBER: "卡号",
            PIIAttributeType.BANK_ACCOUNT: "银行账号",
            PIIAttributeType.PASSPORT_NUMBER: "护照号",
            PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
            PIIAttributeType.EMAIL: "邮箱",
            PIIAttributeType.ADDRESS: "地址",
            PIIAttributeType.ID_NUMBER: "身份证号",
            PIIAttributeType.ORGANIZATION: "机构",
            PIIAttributeType.OTHER: "敏感信息",
        }
        name = mapping.get(attr_type, "敏感信息")
        return f"@{name}{index}"
