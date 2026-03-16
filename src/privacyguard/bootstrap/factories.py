"""配置读取与对象装配工厂。"""

import inspect
from pathlib import Path
from typing import Any

import yaml

from privacyguard.api.dto import RestoreResponse, SanitizeResponse
from privacyguard.api.errors import ComponentNotRegisteredError, InvalidConfigurationError
from privacyguard.api.facade import PrivacyGuardFacade
from privacyguard.bootstrap.registry import ComponentRegistry, create_default_registry
from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.decision.label_only_engine import LabelOnlyDecisionEngine
from privacyguard.infrastructure.decision.label_persona_mixed_engine import LabelPersonaMixedDecisionEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.mapping.json_mapping_store import JsonMappingStore
from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.rule_ner_based_detector import RuleNerBasedPIIDetector
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
from privacyguard.infrastructure.restoration.action_restorer import ActionRestorer


class PlaceholderOCREngine:
    """OCR 占位实现。"""

    def extract(self, image: Any) -> list[OCRTextBlock]:
        """占位提取函数。"""
        raise NotImplementedError("第 1 轮不实现 OCR 业务逻辑。")


class PlaceholderPIIDetector:
    """PII 检测占位实现。"""

    def detect(self, prompt_text: str, ocr_blocks: list[OCRTextBlock]) -> list[Any]:
        """占位检测函数。"""
        raise NotImplementedError("第 1 轮不实现 PII 检测逻辑。")


class PlaceholderPersonaRepository:
    """Persona 仓库占位实现。"""

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        """占位读取 persona。"""
        return None

    def list_personas(self) -> list[PersonaProfile]:
        """占位列出 persona。"""
        return []

    def get_slot_value(self, persona_id: str, attr_type: Any) -> str | None:
        """占位读取槽位。"""
        return None


class PlaceholderMappingStore:
    """Mapping 存储占位实现。"""

    def __init__(self) -> None:
        """初始化内存占位容器。"""
        self._records: dict[tuple[str, int], list[ReplacementRecord]] = {}
        self._bindings: dict[str, SessionBinding] = {}

    def save_replacements(self, session_id: str, turn_id: int, records: list[ReplacementRecord]) -> None:
        """保存替换记录。"""
        self._records[(session_id, turn_id)] = records

    def get_replacements(self, session_id: str, turn_id: int | None = None) -> list[ReplacementRecord]:
        """按会话或轮次读取替换记录。"""
        if turn_id is not None:
            return self._records.get((session_id, turn_id), [])
        collected: list[ReplacementRecord] = []
        for (sid, _tid), records in self._records.items():
            if sid == session_id:
                collected.extend(records)
        return collected

    def get_session_binding(self, session_id: str) -> SessionBinding | None:
        """读取会话绑定。"""
        return self._bindings.get(session_id)

    def set_session_binding(self, binding: SessionBinding) -> None:
        """写入会话绑定。"""
        self._bindings[binding.session_id] = binding


class PlaceholderDecisionEngine:
    """Decision 引擎占位实现。"""

    def plan(
        self,
        session_id: str,
        turn_id: int,
        candidates: list[Any],
        session_binding: SessionBinding | None,
    ) -> DecisionPlan:
        """占位生成决策计划。"""
        raise NotImplementedError("第 1 轮不实现 Decision 业务逻辑。")


class PlaceholderRenderingEngine:
    """渲染引擎占位实现。"""

    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        """占位渲染文本。"""
        raise NotImplementedError("第 1 轮不实现文本渲染逻辑。")

    def render_image(self, image: Any, plan: DecisionPlan) -> Any:
        """占位渲染图片。"""
        raise NotImplementedError("第 1 轮不实现图像渲染逻辑。")


class PlaceholderRestorationModule:
    """还原模块占位实现。"""

    def restore(self, cloud_text: str, records: list[ReplacementRecord]) -> tuple[str, list[RestoredSlot]]:
        """占位恢复文本。"""
        raise NotImplementedError("第 1 轮不实现还原业务逻辑。")


def load_config(config_path: str | Path) -> dict[str, Any]:
    """读取 YAML 配置并返回字典。"""
    path = Path(config_path)
    if not path.exists():
        raise InvalidConfigurationError(f"配置文件不存在: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise InvalidConfigurationError("配置根节点必须是映射类型。")
    return data


def register_default_components(registry: ComponentRegistry) -> None:
    """注册默认组件与可用占位组件。"""
    registry.register_ocr_provider("placeholder", PlaceholderOCREngine)
    registry.register_ocr_provider("ppocr_v5", PPOCREngineAdapter)
    registry.register_detector_mode("placeholder", PlaceholderPIIDetector)
    registry.register_detector_mode("rule_based", RuleBasedPIIDetector)
    registry.register_detector_mode("rule_ner_based", RuleNerBasedPIIDetector)
    registry.register_decision_mode("placeholder", PlaceholderDecisionEngine)
    registry.register_decision_mode("label_only", LabelOnlyDecisionEngine)
    registry.register_decision_mode("label_persona_mixed", LabelPersonaMixedDecisionEngine)
    registry.register_decision_mode("de_model_engine", DEModelEngine)
    registry.register_decision_mode("de_model", DEModelEngine)
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


def create_facade(config: dict[str, Any], registry: ComponentRegistry | None = None) -> PrivacyGuardFacade:
    """按配置创建可实例化的门面对象。"""
    work_registry = registry or create_default_registry()
    if not work_registry.ocr_providers:
        register_default_components(work_registry)

    ocr_provider = config.get("ocr", {}).get("provider", "ppocr_v5")
    detector_mode = config.get("pii_detector", {}).get("mode", "rule_based")
    decision_mode = config.get("decision_engine", {}).get("mode", "label_only")
    mapping_type = config.get("mapping_store", {}).get("type", "in_memory")
    persona_type = config.get("persona_repository", {}).get("type", "json")
    rendering_mode = config.get("rendering_engine", {}).get("mode", "prompt_renderer")
    restoration_mode = config.get("restoration_module", {}).get("mode", "action_restorer")

    ocr_config = config.get("ocr", {})
    detector_config = config.get("pii_detector", {})
    mapping_config = config.get("mapping_store", {})
    persona_config = config.get("persona_repository", {})
    decision_config = config.get("decision_engine", {})
    rendering_config = config.get("rendering_engine", {})
    restoration_config = config.get("restoration_module", {})

    ocr_engine = _build_component(work_registry.ocr_providers, ocr_provider, "ocr provider", ocr_config)
    pii_detector = _build_component(work_registry.detector_modes, detector_mode, "detector mode", detector_config)
    persona_repository = _build_component(
        work_registry.persona_repository_types,
        persona_type,
        "persona repository",
        persona_config,
    )
    mapping_store = _build_component(work_registry.mapping_store_types, mapping_type, "mapping store", mapping_config)
    decision_engine = _build_component(
        work_registry.decision_modes,
        decision_mode,
        "decision mode",
        decision_config,
        injected_dependencies={
            "persona_repository": persona_repository,
            "mapping_store": mapping_store,
        },
    )
    rendering_engine = _build_component(work_registry.rendering_modes, rendering_mode, "rendering mode", rendering_config)
    restoration_module = _build_component(work_registry.restoration_modes, restoration_mode, "restoration mode", restoration_config)

    return PrivacyGuardFacade(
        ocr_engine=ocr_engine,
        pii_detector=pii_detector,
        persona_repository=persona_repository,
        mapping_store=mapping_store,
        decision_engine=decision_engine,
        rendering_engine=rendering_engine,
        restoration_module=restoration_module,
        registry=work_registry,
        detector_mode=detector_mode,
        decision_mode=decision_mode,
        detector_config=detector_config,
        decision_config=decision_config,
    )


def create_facade_from_file(config_path: str | Path, registry: ComponentRegistry | None = None) -> PrivacyGuardFacade:
    """从配置文件创建门面对象。"""
    config = load_config(config_path)
    return create_facade(config=config, registry=registry)


def create_placeholder_sanitize_response() -> SanitizeResponse:
    """返回最小可实例化的脱敏响应对象。"""
    return SanitizeResponse(sanitized_prompt_text="")


def create_placeholder_restore_response() -> RestoreResponse:
    """返回最小可实例化的还原响应对象。"""
    return RestoreResponse(restored_text="")
