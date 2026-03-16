"""统一外部调用入口。"""

from pathlib import Path

from privacyguard.api.dto import RestoreRequest, RestoreResponse, SanitizeRequest, SanitizeResponse
from privacyguard.application.pipelines.restore_pipeline import run_restore_pipeline
from privacyguard.application.pipelines.sanitize_pipeline import run_sanitize_pipeline
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine
from privacyguard.domain.interfaces.restoration_module import RestorationModule


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
    ) -> None:
        """注入各模块依赖以完成装配。"""
        self.ocr_engine = ocr_engine
        self.pii_detector = pii_detector
        self.persona_repository = persona_repository
        self.mapping_store = mapping_store
        self.decision_engine = decision_engine
        self.rendering_engine = rendering_engine
        self.restoration_module = restoration_module

    def sanitize(self, request: SanitizeRequest) -> SanitizeResponse:
        """执行 API_1 脱敏流程编排。"""
        return run_sanitize_pipeline(
            request=request,
            ocr_engine=self.ocr_engine,
            pii_detector=self.pii_detector,
            persona_repository=self.persona_repository,
            mapping_store=self.mapping_store,
            decision_engine=self.decision_engine,
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
