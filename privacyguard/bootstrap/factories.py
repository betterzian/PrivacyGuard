"""配置读取与对象装配工厂。"""

import inspect
from typing import Any

from privacyguard.api.errors import ComponentNotRegisteredError
from privacyguard.bootstrap.registry import ComponentRegistry, create_default_registry
from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.decision.label_only_engine import LabelOnlyDecisionEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.mapping.json_mapping_store import JsonMappingStore
from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.rendering.fill_strategies import (
    CVFillStrategy,
    GradientFillStrategy,
    MixFillStrategy,
    RingFillStrategy,
)
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
from privacyguard.infrastructure.restoration.action_restorer import ActionRestorer


class PlaceholderOCREngine:
    """OCR 占位实现。"""

    def extract(self, image: Any) -> list[OCRTextBlock]:
        raise NotImplementedError("placeholder OCR 组件未实现 extract。")


class PlaceholderPIIDetector:
    """PII 检测占位实现。"""

    def detect(
        self,
        prompt_text: str,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_id: str | None = None,
        turn_id: int | None = None,
        protection_level: ProtectionLevel | str = ProtectionLevel.STRONG,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> list[Any]:
        _ = (
            prompt_text,
            ocr_blocks,
            session_id,
            turn_id,
            protection_level,
            detector_overrides,
        )
        raise NotImplementedError("placeholder PII 检测组件未实现 detect。")


class PlaceholderPersonaRepository:
    """Persona 仓库占位实现。"""

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        return None

    def list_personas(self) -> list[PersonaProfile]:
        return []

    def get_slot_value(self, persona_id: str, attr_type: Any) -> str | None:
        return None

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: Any,
        source_text: str,
        metadata: dict[str, list[str]] | None = None,
    ) -> str | None:
        _ = metadata
        return self.get_slot_value(persona_id, attr_type)


class PlaceholderMappingStore:
    """Mapping 存储占位实现。"""

    def __init__(self) -> None:
        self._records: dict[tuple[str, int], list[ReplacementRecord]] = {}
        self._bindings: dict[str, SessionBinding] = {}

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        self._records[(session_id, turn_id)] = records

    def get_replacements(self, session_id: str, turn_id: int | None = None) -> list[ReplacementRecord]:
        if turn_id is not None:
            return self._records.get((session_id, turn_id), [])
        collected: list[ReplacementRecord] = []
        for (sid, _tid), records in self._records.items():
            if sid == session_id:
                collected.extend(records)
        return collected

    def get_session_binding(self, session_id: str) -> SessionBinding | None:
        return self._bindings.get(session_id)

    def set_session_binding(self, binding: SessionBinding) -> None:
        self._bindings[binding.session_id] = binding


class PlaceholderRenderingEngine:
    """渲染引擎占位实现。"""

    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        raise NotImplementedError("placeholder 渲染组件未实现 render_text。")

    def render_image(self, image: Any, plan: DecisionPlan, ocr_blocks: list[OCRTextBlock] | None = None) -> Any:
        raise NotImplementedError("placeholder 渲染组件未实现 render_image。")


class PlaceholderRestorationModule:
    """还原模块占位实现。"""

    def restore(self, cloud_text: str, records: list[ReplacementRecord]) -> tuple[str, list[RestoredSlot]]:
        raise NotImplementedError("placeholder 还原组件未实现 restore。")


def register_default_components(registry: ComponentRegistry) -> None:
    """注册默认组件与可用占位组件。"""
    registry.register_ocr_provider("placeholder", PlaceholderOCREngine)
    registry.register_ocr_provider("ppocr_v5", PPOCREngineAdapter)
    registry.register_detector_mode("placeholder", PlaceholderPIIDetector)
    registry.register_detector_mode("rule_based", RuleBasedPIIDetector)
    registry.register_decision_mode("label_only", LabelOnlyDecisionEngine)
    registry.register_mapping_store_type("placeholder", PlaceholderMappingStore)
    registry.register_mapping_store_type("in_memory", InMemoryMappingStore)
    registry.register_mapping_store_type("json", JsonMappingStore)
    registry.register_persona_repository_type("placeholder", PlaceholderPersonaRepository)
    registry.register_persona_repository_type("in_memory", PlaceholderPersonaRepository)
    registry.register_persona_repository_type("json", JsonPersonaRepository)
    registry.register_rendering_mode("placeholder", PlaceholderRenderingEngine)
    registry.register_rendering_mode("prompt_renderer", PromptRenderer)
    registry.register_restoration_mode("placeholder", PlaceholderRestorationModule)
    registry.register_restoration_mode("action_restorer", ActionRestorer)
    registry.register_screenshot_fill_mode("ring", RingFillStrategy)
    registry.register_screenshot_fill_mode("gradient", GradientFillStrategy)
    registry.register_screenshot_fill_mode("cv", CVFillStrategy)
    registry.register_screenshot_fill_mode("mix", MixFillStrategy)


def _build_component(
    mapping: dict[str, type[Any]],
    key: str,
    category: str,
    component_config: dict[str, Any] | None = None,
    injected_dependencies: dict[str, Any] | None = None,
) -> Any:
    """按标签构建组件实例并注入可识别配置。"""
    impl_cls = mapping.get(key)
    if impl_cls is None:
        raise ComponentNotRegisteredError(f"{category} 未注册: {key}")
    config = component_config or {}
    signature = inspect.signature(impl_cls.__init__)
    accepted = {name for name in signature.parameters if name != "self"}
    kwargs = {name: value for name, value in config.items() if name in accepted}
    if injected_dependencies:
        for name, value in injected_dependencies.items():
            if name in accepted:
                kwargs[name] = value
    return impl_cls(**kwargs)
