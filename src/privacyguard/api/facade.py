"""统一外部调用入口。"""

import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Any

from privacyguard.api.dto import RestoreRequest, RestoreResponse, SanitizeRequest, SanitizeResponse
from privacyguard.api.errors import ComponentNotRegisteredError
from privacyguard.application.pipelines.restore_pipeline import run_restore_pipeline
from privacyguard.application.pipelines.sanitize_pipeline import run_sanitize_pipeline
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine
from privacyguard.domain.interfaces.restoration_module import RestorationModule

if TYPE_CHECKING:
    from privacyguard.bootstrap.registry import ComponentRegistry


class PrivacyGuardFacade:
    """PrivacyGuard 对外统一门面类。"""

    def __init__(
        self,
        ocr_engine: OCREngine,
        pii_detector: PIIDetector,
        persona_repository: PersonaRepository,
        mapping_store: MappingStore,
        decision_engine: DecisionEngine,
        rendering_engine: RenderingEngine,
        restoration_module: RestorationModule,
        registry: "ComponentRegistry | None" = None,
        detector_mode: str = "rule_based",
        decision_mode: str = "label_only",
        detector_config: dict[str, Any] | None = None,
        decision_config: dict[str, Any] | None = None,
    ) -> None:
        """注入各模块依赖以完成装配。"""
        self.ocr_engine = ocr_engine
        self.pii_detector = pii_detector
        self.persona_repository = persona_repository
        self.mapping_store = mapping_store
        self.decision_engine = decision_engine
        self.rendering_engine = rendering_engine
        self.restoration_module = restoration_module
        self.registry = registry
        self.detector_mode = detector_mode
        self.decision_mode = decision_mode
        self.detector_config = detector_config or {}
        self.decision_config = decision_config or {}

    def sanitize(self, request: SanitizeRequest) -> SanitizeResponse:
        """执行 API_1 脱敏流程编排。"""
        runtime_detector = self._resolve_detector_for_request(request.detector_mode)
        runtime_decision = self._resolve_decision_for_request(request.decision_mode)
        return run_sanitize_pipeline(
            request=request,
            ocr_engine=self.ocr_engine,
            pii_detector=runtime_detector,
            persona_repository=self.persona_repository,
            mapping_store=self.mapping_store,
            decision_engine=runtime_decision,
            rendering_engine=self.rendering_engine,
        )

    def restore(self, request: RestoreRequest) -> RestoreResponse:
        """执行 API_2 还原流程编排。"""
        return run_restore_pipeline(
            request=request,
            mapping_store=self.mapping_store,
            restoration_module=self.restoration_module,
        )

    @classmethod
    def from_config(cls, config: dict) -> "PrivacyGuardFacade":
        """从配置字典装配并创建 facade。"""
        from privacyguard.bootstrap.factories import create_facade

        return create_facade(config=config)

    @classmethod
    def from_config_file(cls, config_path: str | Path) -> "PrivacyGuardFacade":
        """从配置文件装配并创建 facade。"""
        from privacyguard.bootstrap.factories import create_facade_from_file

        return create_facade_from_file(config_path=config_path)

    def _resolve_detector_for_request(self, detector_mode: str) -> PIIDetector:
        """根据请求中的 detector_mode 获取运行时检测器。"""
        if detector_mode == self.detector_mode or self.registry is None:
            return self.pii_detector
        return self._build_runtime_component(
            mapping=self.registry.detector_modes,
            mode=detector_mode,
            category="detector mode",
            component_config=self.detector_config,
        )

    def _resolve_decision_for_request(self, decision_mode: str) -> DecisionEngine:
        """根据请求中的 decision_mode 获取运行时决策引擎。"""
        if decision_mode == self.decision_mode or self.registry is None:
            return self.decision_engine
        return self._build_runtime_component(
            mapping=self.registry.decision_modes,
            mode=decision_mode,
            category="decision mode",
            component_config=self.decision_config,
            injected_dependencies={
                "persona_repository": self.persona_repository,
                "mapping_store": self.mapping_store,
            },
        )

    def _build_runtime_component(
        self,
        mapping: dict[str, type[Any]],
        mode: str,
        category: str,
        component_config: dict[str, Any] | None = None,
        injected_dependencies: dict[str, Any] | None = None,
    ) -> Any:
        """按模式构造运行时组件并注入可识别参数。"""
        impl_cls = mapping.get(mode)
        if impl_cls is None:
            raise ComponentNotRegisteredError(f"{category} 未注册: {mode}")
        config = component_config or {}
        signature = inspect.signature(impl_cls.__init__)
        accepted = {name for name in signature.parameters if name != "self"}
        kwargs = {name: value for name, value in config.items() if name in accepted}
        if injected_dependencies:
            for name, value in injected_dependencies.items():
                if name in accepted:
                    kwargs[name] = value
        return impl_cls(**kwargs)
