"""应用层 resolve 服务。

本文件当前收敛两类 resolve 能力：

- 候选去重与稳定 ID 生成
- de_model 动作的约束与回退解析

这里不是模型推理器：

- 不负责 detector
- 不负责 runtime 打分
- 不负责最终策略推理

它只对已有候选或已有动作执行应用层的收敛、校正与回退。
"""

from __future__ import annotations

import re
from hashlib import md5

from privacyguard.domain.enums import ActionType, PIISourceType, PIIAttributeType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan, clone_action_metadata
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.policy_context import derive_policy_context
from privacyguard.utils.pii_value import canonicalize_pii_value, persona_slot_replacement

_LOW_CANDIDATE_CONFIDENCE = 0.5
_HIGH_CANDIDATE_CONFIDENCE = 0.85
_LOW_OCR_BLOCK_SCORE = 0.75
_PLACEHOLDER_PREFIX = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.LOCATION_CLUE: "位置",
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
_PLACEHOLDER_PATTERN = re.compile(r"^@(?P<label>.+?)(?P<index>\d+)$")


class CandidateResolverService:
    """应用层约束与回退服务，并保留候选去重兼容能力。

    正式职责是“约束与回退”：

    - 对 `DecisionPlan` / `DecisionAction` 应用硬约束
    - 对非法或高风险动作做回退
    - 把 `fallback_reason` / `resolution_reason` 写回输出，供 debug 与训练导出

    兼容职责是“候选去重”：

    - `build_candidate_id(...)`
    - `resolve_candidates(...)`

    这样既不破坏现有 detector 侧导入，也为 de_model 动作约束提供统一入口。
    """

    def __init__(
        self,
        persona_repository: PersonaRepository | None = None,
        mapping_store: MappingStore | None = None,
    ) -> None:
        self.persona_repository = persona_repository
        self.mapping_store = mapping_store

    def build_candidate_id(
        self,
        detector_mode: str,
        source: str,
        normalized_text: str,
        attr_type: str,
        block_id: str | None = None,
        span_start: int | None = None,
        span_end: int | None = None,
    ) -> str:
        """根据关键字段生成稳定候选 ID。"""
        raw = f"{detector_mode}|{source}|{normalized_text}|{attr_type}|{block_id or ''}|{span_start}|{span_end}"
        return md5(raw.encode("utf-8")).hexdigest()

    def resolve_candidates(self, candidates: list[PIICandidate]) -> list[PIICandidate]:
        """按来源、属性与位置去重；同文不同 bbox 保留为多个候选（屏幕多处同一 PII 都会打码）。"""
        deduped: dict[tuple, PIICandidate] = {}
        for candidate in candidates:
            bbox_key = self._bbox_dedup_key(candidate.bbox)
            span_key = (candidate.block_id, candidate.span_start, candidate.span_end)
            key = (candidate.source.value, candidate.normalized_text, candidate.attr_type.value, bbox_key, span_key)
            previous = deduped.get(key)
            if previous is None:
                deduped[key] = candidate
                continue
            if candidate.confidence > previous.confidence:
                merged = candidate.model_copy(deep=True)
                if merged.canonical_source_text is None:
                    merged.canonical_source_text = previous.canonical_source_text
                merged.metadata = self._merge_metadata(previous, candidate)
                deduped[key] = merged
            else:
                if previous.canonical_source_text is None and candidate.canonical_source_text is not None:
                    previous.canonical_source_text = candidate.canonical_source_text
                previous.metadata = self._merge_metadata(previous, candidate)
        return list(deduped.values())

    def resolve_plan(self, plan: DecisionPlan, context: DecisionContext) -> DecisionPlan:
        """对 de_model 产出的动作计划施加应用层硬约束与回退。

        这里不重新做模型推理，只做约束收敛：

        - PERSONA_SLOT 的 persona 可用性校验
        - GENERICIZE 的 alias / placeholder 补建
        - 高风险场景下对 KEEP 的保守回退
        - 旧动作别名 `LABEL -> GENERICIZE` 的兼容归一化
        """
        candidate_map = {candidate.entity_id: candidate for candidate in context.candidates}
        candidate_view_map = self._candidate_view_map(context)
        page_policy_state = self._page_policy_state(context)
        active_persona_id = plan.active_persona_id or (
            context.session_binding.active_persona_id if context.session_binding else None
        )

        resolved_actions: list[DecisionAction] = []
        for action in plan.actions:
            resolved_actions.append(
                self.resolve_action(
                    plan_session_id=plan.session_id,
                    action=action,
                    candidate=candidate_map.get(action.candidate_id),
                    page_policy_state=page_policy_state,
                    candidate_policy_view=candidate_view_map.get(action.candidate_id, {}),
                    active_persona_id=active_persona_id,
                )
            )

        metadata = dict(plan.metadata)
        metadata.setdefault("resolver_service", "constraint_fallback")
        return plan.model_copy(update={"actions": resolved_actions, "metadata": metadata}, deep=True)

    def resolve_action(
        self,
        *,
        plan_session_id: str,
        action: DecisionAction,
        candidate: PIICandidate | None,
        page_policy_state: dict[str, object],
        candidate_policy_view: dict[str, object],
        active_persona_id: str | None,
    ) -> DecisionAction:
        """对单条动作施加硬约束与回退，不做模型打分。"""
        normalized_action_type, normalization_reason = self._normalized_action_type(action.action_type)
        resolved = action.model_copy(deep=True)
        resolved.metadata = clone_action_metadata(action.metadata)
        if normalized_action_type is None:
            return self._fallback_to_keep(
                resolved,
                fallback_reason="动作类型非法，已回退为 KEEP。",
                resolution_reason=normalization_reason or "动作类型非法。",
            )
        resolved.action_type = normalized_action_type
        if normalization_reason:
            resolved = self._annotate_action(resolved, resolution_reason=normalization_reason)

        if candidate is None:
            return self._fallback_to_keep(
                resolved,
                fallback_reason="候选不存在，已回退为 KEEP。",
                resolution_reason="约束服务未找到对应 candidate。",
            )

        if resolved.attr_type != candidate.attr_type:
            resolved.attr_type = candidate.attr_type
            resolved.source = candidate.source
            resolved.source_text = candidate.text
            resolved.canonical_source_text = candidate.canonical_source_text
            return self._fallback_to_genericize(
                plan_session_id=plan_session_id,
                action=resolved,
                fallback_reason="动作 attr_type 与候选不一致，已回退为 GENERICIZE。",
                resolution_reason="检测到跨槽位动作，统一改写为同 attr_type 的 GENERICIZE。",
            )

        if resolved.action_type == ActionType.PERSONA_SLOT:
            return self._resolve_persona_slot(
                plan_session_id=plan_session_id,
                action=resolved,
                candidate=candidate,
                active_persona_id=active_persona_id,
            )

        if resolved.action_type == ActionType.KEEP:
            if self._should_fallback_keep(
                action=resolved,
                page_policy_state=page_policy_state,
                candidate_policy_view=candidate_policy_view,
            ):
                return self._fallback_to_genericize(
                    plan_session_id=plan_session_id,
                    action=resolved,
                    fallback_reason="当前页面/局部质量风险较高，KEEP 已回退为 GENERICIZE。",
                    resolution_reason="约束服务在高风险条件下收紧 KEEP。",
                )
            resolved.replacement_text = None
            resolved.persona_id = None
            return self._annotate_action(
                resolved,
                resolution_reason="KEEP 通过约束校验，保留原文。",
            )

        if resolved.action_type == ActionType.GENERICIZE:
            return self._resolve_genericize(
                plan_session_id=plan_session_id,
                action=resolved,
            )

        return self._fallback_to_keep(
            resolved,
            fallback_reason="未知动作类型，已回退为 KEEP。",
            resolution_reason="约束服务无法识别该动作类型。",
        )

    def _resolve_persona_slot(
        self,
        *,
        plan_session_id: str,
        action: DecisionAction,
        candidate: PIICandidate,
        active_persona_id: str | None,
    ) -> DecisionAction:
        """校验 PERSONA_SLOT 的 persona 可用性，并在必要时回退。"""
        persona_id = active_persona_id or action.persona_id
        if not persona_id:
            return self._fallback_to_genericize(
                plan_session_id=plan_session_id,
                action=action,
                fallback_reason="PERSONA_SLOT 缺少 active persona，已回退为 GENERICIZE。",
                resolution_reason="约束服务要求 PERSONA_SLOT 必须绑定 active persona。",
            )
        if self.persona_repository is None:
            return self._fallback_to_genericize(
                plan_session_id=plan_session_id,
                action=action,
                fallback_reason="PERSONA_SLOT 无法校验 persona 槽位，已回退为 GENERICIZE。",
                resolution_reason="未注入 persona_repository，无法确认 persona slot 可用性。",
            )
        slot_value = self.persona_repository.get_slot_value(persona_id, candidate.attr_type)
        if not slot_value:
            return self._fallback_to_genericize(
                plan_session_id=plan_session_id,
                action=action,
                fallback_reason="PERSONA_SLOT 缺少对应 persona slot，已回退为 GENERICIZE。",
                resolution_reason="当前 persona 不支持该 attr_type 或槽位值为空。",
            )
        action.persona_id = persona_id
        action.replacement_text = persona_slot_replacement(candidate.attr_type, candidate.text, slot_value)
        return self._annotate_action(
            action,
            resolution_reason="PERSONA_SLOT 通过槽位校验，使用 active persona 槽位值。",
        )

    def _resolve_genericize(self, *, plan_session_id: str, action: DecisionAction) -> DecisionAction:
        """确保 GENERICIZE 具有可执行 alias / placeholder。"""
        action.persona_id = None
        replacement_text, fallback_reason, resolution_reason = self._ensure_genericize_alias(
            plan_session_id=plan_session_id,
            action=action,
        )
        action.replacement_text = replacement_text
        return self._annotate_action(
            action,
            resolution_reason=resolution_reason,
            fallback_reason=fallback_reason,
        )

    def _should_fallback_keep(
        self,
        *,
        action: DecisionAction,
        page_policy_state: dict[str, object],
        candidate_policy_view: dict[str, object],
    ) -> bool:
        """判定 KEEP 是否应被硬约束拦下。

        当前支持两类保守回退：

        - 高 protection + 低质量页面：KEEP 更保守
        - OCR 跨 block + 低 OCR local conf：KEEP 更保守
        """
        protection_level = str(page_policy_state.get("protection_level", "")).strip().lower()
        page_quality_state = str(page_policy_state.get("page_quality_state", "")).strip().lower()
        if protection_level == ProtectionLevel.STRONG.value and page_quality_state == "poor":
            return True

        if action.source == PIISourceType.OCR:
            cross_block_flag = bool(candidate_policy_view.get("cross_block_flag", False))
            ocr_local_conf_bucket = str(candidate_policy_view.get("ocr_local_conf_bucket", "")).strip().lower()
            low_ocr_flag = bool(candidate_policy_view.get("low_ocr_flag", False))
            if cross_block_flag and (low_ocr_flag or ocr_local_conf_bucket in {"low", "none"}):
                return True
        return False

    def _fallback_to_genericize(
        self,
        *,
        plan_session_id: str,
        action: DecisionAction,
        fallback_reason: str,
        resolution_reason: str,
    ) -> DecisionAction:
        """把动作收敛为 GENERICIZE，并确保 replacement_text 可执行。"""
        action.action_type = ActionType.GENERICIZE
        action.persona_id = None
        replacement_text, alias_fallback_reason, alias_resolution_reason = self._ensure_genericize_alias(
            plan_session_id=plan_session_id,
            action=action,
        )
        action.replacement_text = replacement_text
        combined_resolution_reason = resolution_reason
        if alias_resolution_reason:
            combined_resolution_reason = f"{combined_resolution_reason} {alias_resolution_reason}".strip()
        combined_fallback_reason = fallback_reason
        if alias_fallback_reason:
            combined_fallback_reason = f"{combined_fallback_reason} {alias_fallback_reason}".strip()
        return self._annotate_action(
            action,
            resolution_reason=combined_resolution_reason,
            fallback_reason=combined_fallback_reason,
        )

    def _fallback_to_keep(
        self,
        action: DecisionAction,
        *,
        fallback_reason: str,
        resolution_reason: str,
    ) -> DecisionAction:
        """把动作收敛为 KEEP。"""
        action.action_type = ActionType.KEEP
        action.replacement_text = None
        action.persona_id = None
        return self._annotate_action(
            action,
            resolution_reason=resolution_reason,
            fallback_reason=fallback_reason,
        )

    def _ensure_genericize_alias(
        self,
        *,
        plan_session_id: str,
        action: DecisionAction,
    ) -> tuple[str, str | None, str]:
        """保证 GENERICIZE 带有 alias；缺失时先补建，再失败则回退到安全 placeholder。"""
        if action.replacement_text:
            return (action.replacement_text, None, "GENERICIZE 已携带 alias，直接通过约束。")

        if self.mapping_store is not None and action.source_text:
            existing_alias = self._find_existing_generic_alias(
                session_id=plan_session_id,
                attr_type=action.attr_type,
                source_text=action.canonical_source_text or action.source_text,
            )
            if existing_alias:
                return (existing_alias, None, "GENERICIZE 缺少 alias，已复用 session 历史 alias。")

            allocated_alias = self._allocate_new_generic_alias(
                session_id=plan_session_id,
                attr_type=action.attr_type,
            )
            if allocated_alias:
                return (allocated_alias, None, "GENERICIZE 缺少 alias，已补建新的 session placeholder。")

        safe_placeholder = self._safe_placeholder(action.attr_type)
        return (
            safe_placeholder,
            "GENERICIZE 缺少可复用 alias，已回退到安全 placeholder。",
            "约束服务未能从 session alias 状态补建可执行 alias。",
        )

    def _find_existing_generic_alias(
        self,
        *,
        session_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        """从已有 replacement 记录中复用同源 GENERICIZE alias。"""
        if self.mapping_store is None:
            return None
        source_key = self._source_key(attr_type, source_text)
        for record in sorted(
            self.mapping_store.get_replacements(session_id=session_id),
            key=lambda item: (item.turn_id, item.replacement_id),
            reverse=True,
        ):
            if self._normalized_action_name(record.action_type) != ActionType.GENERICIZE.value:
                continue
            if not record.replacement_text:
                continue
            record_source_text = record.canonical_source_text or record.source_text
            if self._source_key(record.attr_type, record_source_text) != source_key:
                continue
            return record.replacement_text
        return None

    def _allocate_new_generic_alias(self, *, session_id: str, attr_type: PIIAttributeType) -> str | None:
        """按 session 历史补建新的 GENERICIZE alias。"""
        if self.mapping_store is None:
            return None
        max_index = 0
        expected_label = _PLACEHOLDER_PREFIX.get(attr_type, "敏感信息")
        for record in self.mapping_store.get_replacements(session_id=session_id):
            if self._normalized_action_name(record.action_type) != ActionType.GENERICIZE.value:
                continue
            if not record.replacement_text:
                continue
            matched = _PLACEHOLDER_PATTERN.match(record.replacement_text)
            if matched is None:
                continue
            if matched.group("label") != expected_label:
                continue
            max_index = max(max_index, int(matched.group("index")))
        return self._label_for_attr(attr_type, max_index + 1)

    def _safe_placeholder(self, attr_type: PIIAttributeType) -> str:
        """生成不依赖 session 历史的安全 placeholder。"""
        return self._label_for_attr(attr_type, 1)

    def _candidate_view_map(self, context: DecisionContext) -> dict[str, dict[str, object]]:
        views = derive_policy_context(context).candidate_policy_views
        return {
            str(view.get("candidate_id")): view
            for view in views
            if isinstance(view, dict) and view.get("candidate_id")
        }

    def _page_policy_state(self, context: DecisionContext) -> dict[str, object]:
        return derive_policy_context(context).page_policy_state

    def _legacy_page_quality_state(
        self,
        *,
        avg_det_conf: float,
        avg_ocr_conf: float,
        low_ocr_ratio: float,
        has_ocr: bool,
    ) -> str:
        if avg_det_conf < _LOW_CANDIDATE_CONFIDENCE:
            return "poor"
        if has_ocr and (avg_ocr_conf < _LOW_OCR_BLOCK_SCORE or low_ocr_ratio > 0.5):
            return "poor"
        if avg_det_conf >= _HIGH_CANDIDATE_CONFIDENCE and (not has_ocr or avg_ocr_conf >= _HIGH_CANDIDATE_CONFIDENCE):
            return "good"
        return "mixed"

    def _normalized_action_type(self, action_type: object) -> tuple[ActionType | None, str | None]:
        """只识别工程动作名；未知值交由回退（KEEP）。"""
        raw = action_type.value if isinstance(action_type, ActionType) else str(action_type).strip()
        normalized_name = self._normalized_action_name(action_type)
        if normalized_name is None:
            return (None, "动作类型缺失。")
        if normalized_name == ActionType.KEEP.value:
            return (ActionType.KEEP, None)
        if normalized_name == ActionType.GENERICIZE.value:
            return (ActionType.GENERICIZE, None)
        if normalized_name == ActionType.PERSONA_SLOT.value:
            return (ActionType.PERSONA_SLOT, None)
        return (None, f"无法识别的动作类型: {action_type}")

    def _normalized_action_name(self, action_type: object) -> str | None:
        if action_type is None:
            return None
        raw = action_type.value if isinstance(action_type, ActionType) else str(action_type).strip()
        if not raw:
            return None
        normalized = raw.upper()
        allowed = {ActionType.KEEP.value, ActionType.GENERICIZE.value, ActionType.PERSONA_SLOT.value}
        return normalized if normalized in allowed else None

    def _annotate_action(
        self,
        action: DecisionAction,
        *,
        resolution_reason: str | None = None,
        fallback_reason: str | None = None,
    ) -> DecisionAction:
        metadata = clone_action_metadata(action.metadata)
        if resolution_reason:
            metadata.setdefault("resolution_reason", []).append(resolution_reason)
        if fallback_reason:
            metadata.setdefault("fallback_reason", []).append(fallback_reason)
        action.metadata = metadata

        parts: list[str] = []
        if action.reason:
            parts.append(action.reason)
        if fallback_reason:
            parts.append(fallback_reason)
        elif resolution_reason:
            parts.append(resolution_reason)
        deduped_parts: list[str] = []
        for item in parts:
            if item and item not in deduped_parts:
                deduped_parts.append(item)
        action.reason = " ".join(deduped_parts)
        return action

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        return f"@{_PLACEHOLDER_PREFIX.get(attr_type, '敏感信息')}{index}"

    def _source_key(self, attr_type: PIIAttributeType, source_text: str) -> tuple[PIIAttributeType, str]:
        return (attr_type, canonicalize_pii_value(attr_type, source_text))

    def _bucket_count(self, value: int) -> str:
        if value <= 0:
            return "0"
        if value == 1:
            return "1"
        if value <= 3:
            return "2-3"
        if value <= 7:
            return "4-7"
        return "8+"

    def _bucket_confidence(self, value: float) -> str:
        if value <= 0.0:
            return "none"
        if value < _LOW_CANDIDATE_CONFIDENCE:
            return "low"
        if value < _HIGH_CANDIDATE_CONFIDENCE:
            return "medium"
        return "high"

    def _bucket_ratio(self, value: float) -> str:
        if value <= 0.0:
            return "none"
        if value < 0.34:
            return "low"
        if value < 0.67:
            return "medium"
        return "high"

    def _bbox_dedup_key(self, bbox) -> tuple:
        """生成用于去重的 bbox 键：同位置视为同一候选，不同位置保留多个。"""
        if bbox is None:
            return (None,)
        return (bbox.x, bbox.y, bbox.width, bbox.height)

    def _merge_metadata(self, left: PIICandidate, right: PIICandidate) -> dict[str, list[str]]:
        """合并候选元信息并记录命中来源。"""
        merged: dict[str, list[str]] = {}
        for source in (left.metadata, right.metadata):
            for key, values in source.items():
                merged[key] = sorted(set(merged.get(key, [])) | set(values))
        return merged
