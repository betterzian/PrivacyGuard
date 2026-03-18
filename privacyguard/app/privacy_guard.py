from typing import Any

from privacyguard.bootstrap.factories import _build_component
from privacyguard.bootstrap.registry import ComponentRegistry
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine
from privacyguard.domain.interfaces.restoration_module import RestorationModule

from privacyguard.app.factories import (
    DEFAULT_DECISION_MODE,
    DEFAULT_DETECTOR_MODE,
    build_decision,
    build_detector,
    build_screenshot_fill_strategy,
    get_or_create_registry,
    normalize_decision_mode,
    normalize_detector_mode,
    normalize_fill_mode,
)
from privacyguard.app.pipelines import RestorePipeline, SanitizePipeline
from privacyguard.app.schemas import RestoreRequestModel, SanitizeRequestModel


class PrivacyGuard:
    """项目顶层入口，负责依赖装配、模式选择与对外 API 暴露。"""

    def __init__(
        self,
        detector_mode: str = DEFAULT_DETECTOR_MODE,
        decision_mode: str = DEFAULT_DECISION_MODE,
        *,
        detector: PIIDetector | None = None,
        decision_engine: DecisionEngine | None = None,
        ocr: OCREngine | None = None,
        renderer: RenderingEngine | None = None,
        restoration: RestorationModule | None = None,
        persona_repo: PersonaRepository | None = None,
        mapping_table: MappingStore | None = None,
        registry: ComponentRegistry | None = None,
        screenshot_fill_mode: str | None = None,
    ) -> None:
        """初始化核心依赖并构建 sanitize/restore 两条流水线。screenshot_fill_mode: ring（纯色）、gradient（渐变）、cv（OpenCV inpaint）、mix（三段式自动选择，默认）。"""
        self.registry = get_or_create_registry(registry)
        self.detector_mode = normalize_detector_mode(detector_mode)
        self.decision_mode = normalize_decision_mode(decision_mode)

        self.persona_repo = persona_repo or _build_component(
            self.registry.persona_repository_types,
            "json",
            "persona repository",
        )
        self.mapping_table = mapping_table or _build_component(
            self.registry.mapping_store_types,
            "in_memory",
            "mapping store",
        )
        self.ocr = ocr or _build_component(self.registry.ocr_providers, "ppocr_v5", "ocr provider")
        if renderer is not None:
            self.renderer = renderer
        elif screenshot_fill_mode and str(screenshot_fill_mode).strip():
            from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
            from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer
            fill_mode = normalize_fill_mode(str(screenshot_fill_mode).strip())
            fill_strategy = build_screenshot_fill_strategy(fill_mode, self.registry)
            self.renderer = PromptRenderer(screenshot_renderer=ScreenshotRenderer(fill_strategy=fill_strategy))
        else:
            self.renderer = _build_component(self.registry.rendering_modes, "prompt_renderer", "rendering mode")
        self.restoration = restoration or _build_component(
            self.registry.restoration_modes,
            "action_restorer",
            "restoration mode",
        )
        self.detector = detector or build_detector(self.detector_mode, self.registry)
        self.decision_engine = decision_engine or build_decision(
            self.decision_mode,
            self.registry,
            self.persona_repo,
            self.mapping_table,
        )
        self.sanitize_pipeline = SanitizePipeline(
            ocr=self.ocr,
            detector=self.detector,
            persona_repo=self.persona_repo,
            mapping_table=self.mapping_table,
            decision_engine=self.decision_engine,
            renderer=self.renderer,
        )
        self.restore_pipeline = RestorePipeline(mapping_table=self.mapping_table, restoration=self.restoration)

    def sanitize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """接收脱敏请求字典并返回脱敏结果字典。"""
        request = SanitizeRequestModel.from_payload(payload)
        return self.sanitize_pipeline.run(request=request).to_dict()

    def restore(self, payload: dict[str, Any]) -> dict[str, Any]:
        """接收还原请求字典并返回还原结果字典。"""
        request = RestoreRequestModel.from_payload(payload)
        return self.restore_pipeline.run(request).to_dict()
