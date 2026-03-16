from privacyguard.application.pipelines.restore_pipeline import run_restore_pipeline
from privacyguard.application.pipelines.sanitize_pipeline import run_sanitize_pipeline
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine
from privacyguard.domain.interfaces.restoration_module import RestorationModule

from privacyguard.app.schemas import (
    RestoreRequestModel,
    RestoreResponseModel,
    SanitizeRequestModel,
    SanitizeResponseModel,
)


class SanitizePipeline:
    """封装脱敏主链路，负责调用 application 层 sanitize 编排。"""

    def __init__(
        self,
        ocr: OCREngine,
        detector: PIIDetector,
        persona_repo: PersonaRepository,
        mapping_table: MappingStore,
        decision_engine: DecisionEngine,
        renderer: RenderingEngine,
    ) -> None:
        """初始化脱敏流程依赖。"""
        self.ocr = ocr
        self.detector = detector
        self.persona_repo = persona_repo
        self.mapping_table = mapping_table
        self.decision_engine = decision_engine
        self.renderer = renderer

    def run(
        self,
        request: SanitizeRequestModel,
        detector: PIIDetector | None = None,
        decision_engine: DecisionEngine | None = None,
    ) -> SanitizeResponseModel:
        """执行脱敏流程并返回边界层响应模型。"""
        response = run_sanitize_pipeline(
            request=request.to_dto(),
            ocr_engine=self.ocr,
            pii_detector=detector or self.detector,
            persona_repository=self.persona_repo,
            mapping_store=self.mapping_table,
            decision_engine=decision_engine or self.decision_engine,
            rendering_engine=self.renderer,
        )
        return SanitizeResponseModel.from_pipeline_result(request, response)


class RestorePipeline:
    """封装还原主链路，负责调用 application 层 restore 编排。"""

    def __init__(
        self,
        mapping_table: MappingStore,
        restoration: RestorationModule,
    ) -> None:
        """初始化还原流程依赖。"""
        self.mapping_table = mapping_table
        self.restoration = restoration

    def run(self, request: RestoreRequestModel) -> RestoreResponseModel:
        """执行还原流程并返回边界层响应模型。"""
        response = run_restore_pipeline(
            request=request.to_dto(),
            mapping_store=self.mapping_table,
            restoration_module=self.restoration,
        )
        return RestoreResponseModel.from_pipeline_result(request, response)
