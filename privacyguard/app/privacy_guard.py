"""PrivacyGuard 应用层门面（facade）。

`PrivacyGuard` 是对外应用层入口，职责边界保持收敛：

- 接收外部 payload
- 转换为边界层 request model / DTO
- 调用 sanitize / restore pipeline
- 返回外部响应字典
- `write_privacy_repository`：合并写入 `rule_based` 本地词库并刷新检测器（实现细节仍在 infrastructure）

sanitize / restore 与 OCR、`de_model` runtime、restore 规则的具体策略仍由 pipeline 与下层模块承担；
app facade 不展开 `protect_decision` / `rewrite_mode` 等内部字段。
"""

from pathlib import Path
from typing import Any

from privacyguard.api.errors import InvalidConfigurationError
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
from privacyguard.app.schemas import (
    PrivacyRepositoryWritePayloadModel,
    PrivacyRepositoryWriteResponseModel,
    RestoreRequestModel,
    SanitizeRequestModel,
)
from privacyguard.infrastructure.pii.json_privacy_repository import DEFAULT_PRIVACY_REPOSITORY_PATH, JsonPrivacyRepository
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def _build_ocr_component_config(ocr_config: dict[str, Any] | None) -> dict[str, Any]:
    """构建 OCR 组件配置，允许外部覆盖并保留默认 backend_kwargs。"""
    config: dict[str, Any] = {
        "use_doc_orientation_classify": False,
        "use_doc_unwarping": False,
        "use_textline_orientation": False,
        "backend_kwargs": {},
    }
    if not ocr_config:
        return config
    merged = dict(config)
    merged.update(ocr_config)
    default_backend_kwargs = dict(config["backend_kwargs"])
    incoming_backend_kwargs = ocr_config.get("backend_kwargs")
    if isinstance(incoming_backend_kwargs, dict):
        default_backend_kwargs.update(incoming_backend_kwargs)
    merged["backend_kwargs"] = default_backend_kwargs
    return merged


class PrivacyGuard:
    """项目顶层 facade，负责依赖装配并暴露稳定的 app 层入口。

    该类本身不直接执行 detector、OCR、de_model 决策或 restore 规则；这些职责都
    由下层 pipeline 与其依赖组件承担。app 层只负责接入外部请求并返回外部响应。
    """

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
        ocr_config: dict[str, Any] | None = None,
        detector_config: dict[str, Any] | None = None,
        decision_config: dict[str, Any] | None = None,
    ) -> None:
        """初始化核心依赖并装配 sanitize / restore 两条流水线。

        `screenshot_fill_mode`:
        `ring`（纯色）、`gradient`（渐变）、`cv`（OpenCV inpaint）、`mix`（三段式自动选择，默认）。

        这里仅做组件装配与 pipeline 组装，不在 app 层展开具体策略逻辑。
        """
        self.detector_mode = normalize_detector_mode(detector_mode)
        self.decision_mode = normalize_decision_mode(decision_mode)
        self.registry = get_or_create_registry(registry)

        # 基础依赖由 registry 或显式注入提供；app 层不关心其内部实现细节。
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
        ocr_component_config = _build_ocr_component_config(ocr_config)
        self.ocr = ocr or _build_component(
            self.registry.ocr_providers,
            "ppocr_v5",
            "ocr provider",
            ocr_component_config,
        )
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
        # detector / decision_engine 在 app 层只以统一接口接入。
        # de_model 若发生内部重构，也应被封装在 decision_engine 之后。
        self.detector = detector or build_detector(
            self.detector_mode,
            self.registry,
            mapping_table=self.mapping_table,
            detector_config=detector_config,
        )
        self.decision_engine = decision_engine or build_decision(
            self.decision_mode,
            self.registry,
            self.persona_repo,
            self.mapping_table,
            decision_config=decision_config,
        )
        # app facade 仅委托 pipeline 执行主链，不直接介入 sanitize / restore 内部步骤。
        self.sanitize_pipeline = SanitizePipeline(
            ocr=self.ocr,
            detector=self.detector,
            persona_repo=self.persona_repo,
            mapping_table=self.mapping_table,
            decision_engine=self.decision_engine,
            renderer=self.renderer,
        )
        self.restore_pipeline = RestorePipeline(mapping_table=self.mapping_table, restoration=self.restoration)

    def write_privacy_repository(self, payload: dict[str, Any]) -> dict[str, Any]:
        """合并写入 rule_based 本地隐私词库 JSON，并刷新当前 detector 词典。

        若构造时未设置 `detector_config["privacy_repository_path"]`，则写入默认路径
        `data/privacy_repository.json` 并令检测器从该路径加载。
        仅支持 `rule_based` 检测器（`RuleBasedPIIDetector`）。
        """
        if not isinstance(self.detector, RuleBasedPIIDetector):
            raise InvalidConfigurationError("write_privacy_repository 仅适用于 rule_based 检测器")

        if self.detector.privacy_repository_path is None:
            self.detector.privacy_repository_path = Path(DEFAULT_PRIVACY_REPOSITORY_PATH)
        target_path = Path(self.detector.privacy_repository_path)

        request = PrivacyRepositoryWritePayloadModel.model_validate(payload)
        patch = request.model_dump(exclude_none=True)
        JsonPrivacyRepository(path=str(target_path)).merge_and_write(patch)
        self.detector.reload_privacy_dictionary()
        return PrivacyRepositoryWriteResponseModel(
            status="ok",
            repository_path=str(target_path),
        ).to_dict()

    def sanitize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """接收外部脱敏 payload，委托 sanitize pipeline，并返回外部响应字典。

        该入口保持公开行为稳定，不暴露内部 `de_model` 的 context、分层决策字段或
        其他 pipeline 内部状态。
        """
        request = SanitizeRequestModel.from_payload(payload)
        response = self.sanitize_pipeline.run(request=request)
        return response.to_dict()

    def restore(self, payload: dict[str, Any]) -> dict[str, Any]:
        """接收外部还原 payload，委托 restore pipeline，并返回外部响应字典。

        restore 的执行细节停留在 pipeline / restoration module 内部，不由 app facade
        直接承担。
        """
        request = RestoreRequestModel.from_payload(payload)
        response = self.restore_pipeline.run(request=request)
        return response.to_dict()
