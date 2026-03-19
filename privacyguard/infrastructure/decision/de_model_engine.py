"""DEModel 上下文感知占位决策引擎。"""

from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan, clone_action_metadata
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.policies.constraint_resolver import ConstraintResolver
from privacyguard.infrastructure.decision.de_model_runtime import (
    DEModelRuntimeOutput,
    DecisionPolicyRuntime,
    TinyPolicyRuntime,
    TorchTinyPolicyRuntime,
)
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
        persona_score_threshold: float = 0.0,
        action_tie_tolerance: float = 1e-6,
        runtime_type: str = "heuristic",
        checkpoint_path: str | None = None,
        bundle_path: str | None = None,
        device: str = "cpu",
        feature_extractor: DecisionFeatureExtractor | None = None,
        runtime: DecisionPolicyRuntime | None = None,
    ) -> None:
        """初始化依赖、特征提取器与占位运行时。"""
        self.persona_repository = persona_repository or JsonPersonaRepository()
        self.mapping_store = mapping_store or InMemoryMappingStore()
        self.keep_threshold = keep_threshold
        self.persona_score_threshold = persona_score_threshold
        self.action_tie_tolerance = action_tie_tolerance
        self.runtime_type = self._normalize_runtime_type(runtime_type)
        self.checkpoint_path = str(Path(checkpoint_path)) if checkpoint_path else None
        self.bundle_path = str(Path(bundle_path)) if bundle_path else None
        self.device = str(device).strip() or "cpu"
        self.constraint_resolver = ConstraintResolver(self.persona_repository)
        self.feature_extractor = feature_extractor or DecisionFeatureExtractor()
        self.runtime = runtime or self._build_runtime()

    def _normalize_runtime_type(self, runtime_type: str) -> str:
        """将 de_model runtime 类型归一化为内部标准键。"""
        normalized = str(runtime_type).strip().lower()
        aliases = {
            "heuristic": "heuristic",
            "tiny_policy_heuristic": "heuristic",
            "torch": "torch",
            "bundle": "bundle",
            "onnx": "bundle",
        }
        if normalized not in aliases:
            raise ValueError(f"不支持的 de_model runtime_type: {runtime_type}")
        return aliases[normalized]

    def _build_runtime(self) -> DecisionPolicyRuntime:
        """按 runtime_type 构建运行时。"""
        if self.runtime_type == "heuristic":
            return TinyPolicyRuntime(keep_threshold=self.keep_threshold)
        if self.runtime_type == "torch":
            if not self.checkpoint_path:
                raise ValueError("de_model runtime_type='torch' 时必须提供 checkpoint_path。")
            return TorchTinyPolicyRuntime(
                checkpoint_path=self.checkpoint_path,
                device=self.device,
                keep_threshold=self.keep_threshold,
                persona_score_threshold=self.persona_score_threshold,
                action_tie_tolerance=self.action_tie_tolerance,
            )
        if self.runtime_type == "bundle":
            if not self.bundle_path:
                raise ValueError("de_model runtime_type='bundle' 时必须提供 bundle_path。")
            raise NotImplementedError("de_model bundle runtime 尚未实现；当前请使用 runtime_type='heuristic'。")
        raise ValueError(f"不支持的 de_model runtime_type: {self.runtime_type}")

    def plan(self, context: DecisionContext) -> DecisionPlan:
        """使用统一上下文生成 de_model 占位计划。"""
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
                "runtime_type": f"{self.runtime_type}_runtime",
                "runtime_device": self.device,
                "selected_persona_id": binding.active_persona_id or "",
                "protection_level": context.protection_level.value,
                "candidate_count": str(len(context.candidates)),
                "persona_count": str(len(context.persona_profiles)),
                "page_vector_dim": str(len(packed.page_vector)),
                "average_ocr_block_score": f"{context.page_features.average_ocr_block_score:.4f}",
                "average_candidate_confidence": f"{context.page_features.average_candidate_confidence:.4f}",
            },
        )

    def _build_actions(
        self,
        *,
        context: DecisionContext,
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
                        canonical_source_text=candidate.canonical_source_text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason=item.reason,
                        metadata=clone_action_metadata(candidate.metadata),
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
                        canonical_source_text=candidate.canonical_source_text,
                        bbox=candidate.bbox,
                        block_id=candidate.block_id,
                        span_start=candidate.span_start,
                        span_end=candidate.span_end,
                        reason=item.reason,
                        metadata=clone_action_metadata(candidate.metadata),
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
                    canonical_source_text=candidate.canonical_source_text,
                    bbox=candidate.bbox,
                    block_id=candidate.block_id,
                    span_start=candidate.span_start,
                    span_end=candidate.span_end,
                    reason=item.reason,
                    metadata=clone_action_metadata(candidate.metadata),
                )
            )
        return actions

    def _label_for_attr(self, attr_type: PIIAttributeType, index: int = 1) -> str:
        """将属性类型转换为中文标签，格式为 @姓名1、@手机号1 等（无尖括号）。"""
        mapping = {
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
        name = mapping.get(attr_type, "敏感信息")
        return f"@{name}{index}"
