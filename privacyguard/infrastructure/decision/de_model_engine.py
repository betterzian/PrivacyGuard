"""DEModel 上下文感知占位决策引擎。"""

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.decision_context import DecisionModelContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.decision.de_model_runtime import DEModelRuntimeOutput, TinyPolicyRuntime
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository


class DEModelEngine:
    """使用 context/features/runtime 骨架模拟 de_model 的可运行占位实现。"""

    def __init__(
        self,
        persona_repository: PersonaRepository | None = None,
        mapping_store: MappingStore | None = None,
        keep_threshold: float = 0.25,
        feature_extractor: DecisionFeatureExtractor | None = None,
        runtime: TinyPolicyRuntime | None = None,
    ) -> None:
        """初始化依赖、特征提取器与占位运行时。"""
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.mapping_store = mapping_store or InMemoryMappingStore()
        self.keep_threshold = keep_threshold
        self.constraint_resolver = ConstraintResolver(self.persona_repository)
        self.context_builder = DecisionContextBuilder(
            mapping_store=self.mapping_store,
            persona_repository=self.persona_repository,
        )
        self.feature_extractor = feature_extractor or DecisionFeatureExtractor()
        self.runtime = runtime or TinyPolicyRuntime(keep_threshold=keep_threshold)

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[PIICandidate],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """兼容旧接口，使用最小上下文构建 de_model 计划。"""
        context = self.context_builder.build(
            session_id=session_id,
            turn_id=turn_id,
            prompt_text="",
            ocr_blocks=[],
            candidates=candidates,
            session_binding=session_binding,
        )
        plan = self.plan_with_context(context)
        plan.metadata["context_mode"] = "minimal_fallback"
        return plan

    def plan_with_context(self, context: DecisionModelContext) -> DecisionPlan:
        """使用完整上下文生成 de_model 占位计划。"""
        packed = self.feature_extractor.pack(context)
        runtime_output = self.runtime.predict(context=context, packed=packed)
        binding = context.session_binding or SessionBinding(
            session_id=context.session_id,
            active_persona_id=runtime_output.active_persona_id,
        )
        if binding.active_persona_id is None:
            binding.active_persona_id = runtime_output.active_persona_id
        actions = self._build_actions(
            context=context,
            active_persona_id=binding.active_persona_id,
            runtime_output=runtime_output,
        )
        resolved = self.constraint_resolver.resolve(
            actions=actions,
            candidates=context.candidates,
            session_binding=binding,
        )
        return DecisionPlan(
            session_id=context.session_id,
            turn_id=context.turn_id,
            active_persona_id=binding.active_persona_id,
            actions=resolved,
            summary=f"de_model 占位评分生成 {len(resolved)} 条动作。",
            metadata={
                "mode": "de_model",
                "engine_type": "tiny_policy_skeleton",
                "runtime_type": "context_runtime",
                "selected_persona_id": binding.active_persona_id or "",
                "candidate_count": str(len(context.candidates)),
                "persona_count": str(len(context.persona_profiles)),
                "page_vector_dim": str(len(packed.page_vector)),
            },
        )

    def _build_actions(
        self,
        *,
        context: DecisionModelContext,
        active_persona_id: str | None,
        runtime_output: DEModelRuntimeOutput,
    ) -> list[DecisionAction]:
        """将运行时输出转换为可解析的动作列表。"""
        candidate_map = {candidate.entity_id: candidate for candidate in context.candidates}
        attr_counts: dict[PIIAttributeType, int] = {}
        actions: list[DecisionAction] = []
        for item in runtime_output.candidate_decisions:
            candidate = candidate_map.get(item.candidate_id)
            if candidate is None:
                continue
            if item.preferred_action == ActionType.KEEP:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.KEEP,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        source_text=candidate.text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason=item.reason,
                    )
                )
                continue
            if item.preferred_action == ActionType.PERSONA_SLOT:
                actions.append(
                    DecisionAction(
                        candidate_id=candidate.entity_id,
                        action_type=ActionType.PERSONA_SLOT,
                        attr_type=candidate.attr_type,
                        source=candidate.source,
                        persona_id=active_persona_id,
                        replacement_text=None,
                        source_text=candidate.text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason=item.reason,
                    )
                )
                continue
            attr_counts[candidate.attr_type] = attr_counts.get(candidate.attr_type, 0) + 1
            actions.append(
                DecisionAction(
                    candidate_id=candidate.entity_id,
                    action_type=ActionType.GENERICIZE,
                    attr_type=candidate.attr_type,
                    source=candidate.source,
                    replacement_text=self._label_for_attr(candidate.attr_type, attr_counts[candidate.attr_type]),
                    source_text=candidate.text,
                    bbox=candidate.bbox,
                    block_id=candidate.block_id,
                    span_start=candidate.span_start,
                    span_end=candidate.span_end,
                    reason=item.reason,
                )
            )
        return actions

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        """将属性类型转换为中文标签，格式为 @姓名1、@手机号1 等（无尖括号）。"""
        mapping = {
            PIIAttributeType.NAME: "姓名",
            PIIAttributeType.PHONE: "手机号",
            PIIAttributeType.EMAIL: "邮箱",
            PIIAttributeType.ADDRESS: "地址",
            PIIAttributeType.ID_NUMBER: "身份证号",
            PIIAttributeType.ORGANIZATION: "机构",
            PIIAttributeType.OTHER: "敏感信息",
        }
        name = mapping.get(attr_type, "敏感信息")
        return f"@{name}{index}"
