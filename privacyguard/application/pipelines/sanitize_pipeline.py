"""sanitize 主链编排。

当前 sanitize 主链的阶段边界保持为：

OCR / prompt parse
-> detector
-> alias / session context preparation
-> local context / quality / persona state preparation
-> DecisionContextBuilder
-> DecisionFeatureExtractor
-> DEModelEngine / runtime
-> ConstraintResolver
-> placeholder allocation / replacement planning
-> render
-> mapping store

说明：

- 本文件只负责 application 层编排，不直接堆叠 de_model 内部细节
- `DecisionFeatureExtractor`、runtime 与 `ConstraintResolver` 由 `decision_engine.plan(...)`
  封装承担
- 后续若抽出 `AliasLinker`、`LocalContextBuilder`、`QualityAggregator`、
  `PersonaStateBuilder`，应接入本文件预留的准备阶段，而不是继续把细节写进主函数
"""

from __future__ import annotations

import inspect
import logging

from privacyguard.api.dto import SanitizeRequest, SanitizeResponse
from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine

LOGGER = logging.getLogger(__name__)


def _trace_ocr_blocks(session_id: str, turn_id: int, ocr_blocks: list) -> None:
    """追踪 PP-OCRv5 输出：默认仅在 debug 打印非明文摘要。"""
    if not LOGGER.isEnabledFor(logging.DEBUG):
        return
    n = len(ocr_blocks)
    sample = []
    for i, b in enumerate(ocr_blocks[:5]):
        text = getattr(b, "text", str(b))
        bbox = getattr(b, "bbox", None)
        sample.append({"text_len": len(text), "bbox": str(bbox) if bbox else None, "index": i})
    LOGGER.debug(
        "PP-OCRv5 output session=%s turn=%s blocks=%s sample=%s",
        session_id[:8],
        turn_id,
        n,
        sample,
    )


def _trace_detector_input(session_id: str, turn_id: int, prompt_text: str, ocr_blocks: list) -> None:
    """追踪 Detector 输入：默认仅在 debug 打印长度级摘要。"""
    if not LOGGER.isEnabledFor(logging.DEBUG):
        return
    ocr_lengths = [len(getattr(b, "text", str(b))) for b in ocr_blocks[:3]]
    LOGGER.debug(
        "Detector input session=%s turn=%s prompt_len=%s ocr_blocks=%s ocr_text_lens=%s",
        session_id[:8],
        turn_id,
        len(prompt_text),
        len(ocr_blocks),
        ocr_lengths,
    )


def _detect_candidates(request: SanitizeRequest, pii_detector: PIIDetector, ocr_blocks: list) -> list:
    """向后兼容地调用 detector；支持带会话上下文与保护度的实现。"""
    detect_method = pii_detector.detect
    parameters = inspect.signature(detect_method).parameters
    kwargs = {
        "prompt_text": request.prompt_text,
        "ocr_blocks": ocr_blocks,
    }
    if "session_id" in parameters:
        kwargs["session_id"] = request.session_id
    if "turn_id" in parameters:
        kwargs["turn_id"] = request.turn_id
    if "protection_level" in parameters:
        kwargs["protection_level"] = request.protection_level
    if "detector_overrides" in parameters:
        kwargs["detector_overrides"] = request.detector_overrides
    return detect_method(**kwargs)


def _trace_detector_output(session_id: str, turn_id: int, candidates: list) -> None:
    """追踪 Detector 输出：默认仅在 debug 打印非明文摘要。"""
    if not LOGGER.isEnabledFor(logging.DEBUG):
        return
    cand_sample = []
    for c in candidates[:5]:
        attr = getattr(c, "attr_type", None)
        src = getattr(c, "source", None)
        text = getattr(c, "text", str(c))
        cand_sample.append(
            {
                "text_len": len(text),
                "attr_type": str(attr),
                "source": str(src),
                "confidence": getattr(c, "confidence", None),
            }
        )
    LOGGER.debug(
        "Detector output session=%s turn=%s candidates=%s sample=%s",
        session_id[:8],
        turn_id,
        len(candidates),
        cand_sample,
    )


def _extract_ocr_blocks(request: SanitizeRequest, ocr_engine: OCREngine) -> list:
    """阶段 1：执行 OCR；prompt 侧输入直接来自请求 DTO。"""
    if request.screenshot is None:
        return []
    return ocr_engine.extract(request.screenshot)


def _prepare_session_context(
    *,
    session_id: str,
    mapping_store: MappingStore,
    persona_repository: PersonaRepository,
) -> tuple[SessionService, object]:
    """阶段 3：准备会话级上下文。

    当前阶段只显式处理 session binding。后续若引入 AliasLinker，应优先在这里或紧随其后的
    决策前准备阶段接入，而不是把 alias 逻辑塞进 renderer 或 app facade。
    """
    session_service = SessionService(mapping_store=mapping_store, persona_repository=persona_repository)
    session_binding = session_service.get_or_create_binding(session_id)
    return (session_service, session_binding)


def _build_decision_context(
    *,
    request: SanitizeRequest,
    ocr_blocks: list,
    detected_candidates: list,
    session_binding,
    mapping_store: MappingStore,
    persona_repository: PersonaRepository,
):
    """阶段 4-5：准备决策上下文并交给 DecisionContextBuilder 组装。

    当前仓库里，局部上下文、质量聚合与 persona 摘要仍主要由 `DecisionContextBuilder`
    内部承接。后续若拆出 `LocalContextBuilder`、`QualityAggregator`、
    `PersonaStateBuilder`，应在这里先完成准备，再统一汇入 `DecisionContextBuilder`。
    """
    context_builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repository)
    return context_builder.build(
        session_id=request.session_id,
        turn_id=request.turn_id,
        prompt_text=request.prompt_text,
        protection_level=request.protection_level,
        detector_overrides=request.detector_overrides,
        ocr_blocks=ocr_blocks,
        candidates=detected_candidates,
        session_binding=session_binding,
    )


def _plan_replacements(
    *,
    decision_context,
    decision_engine: DecisionEngine,
    mapping_store: MappingStore,
):
    """阶段 6-9：生成动作计划并完成 placeholder 级替换规划。

    `decision_engine.plan(...)` 是 de_model 内部边界：其内部可继续封装
    `DecisionFeatureExtractor`、runtime 执行与 `ConstraintResolver`，但这些细节不在
    sanitize pipeline 中展开。
    """
    decision_plan = decision_engine.plan(decision_context)
    return SessionPlaceholderAllocator(mapping_store=mapping_store).assign(decision_plan)


def _render_sanitize_result(
    *,
    request: SanitizeRequest,
    rendering_engine: RenderingEngine,
    replacement_plan,
    ocr_blocks: list,
) -> tuple[str, object | None, list]:
    """阶段 10：执行文本与截图渲染。"""
    sanitized_prompt_text, applied_replacements = rendering_engine.render_text(request.prompt_text, replacement_plan)
    sanitized_screenshot = (
        rendering_engine.render_image(request.screenshot, replacement_plan, ocr_blocks=ocr_blocks)
        if request.screenshot is not None
        else None
    )
    return (sanitized_prompt_text, sanitized_screenshot, applied_replacements)


def _persist_sanitize_result(
    *,
    request: SanitizeRequest,
    session_service: SessionService,
    replacement_plan,
    applied_replacements: list,
) -> None:
    """阶段 11：写入 mapping store，并更新 session 绑定。"""
    session_service.append_turn_replacements(request.session_id, request.turn_id, applied_replacements)
    if replacement_plan.active_persona_id:
        session_service.bind_active_persona(request.session_id, replacement_plan.active_persona_id, request.turn_id)


def run_sanitize_pipeline(
    request: SanitizeRequest,
    ocr_engine: OCREngine,
    pii_detector: PIIDetector,
    persona_repository: PersonaRepository,
    mapping_store: MappingStore,
    decision_engine: DecisionEngine,
    rendering_engine: RenderingEngine,
) -> SanitizeResponse:
    """按固定顺序执行 sanitize 编排并返回响应。"""
    # 1. OCR / prompt parse
    # prompt 侧输入直接使用 request.prompt_text；截图存在时才执行 OCR。
    ocr_blocks = _extract_ocr_blocks(request=request, ocr_engine=ocr_engine)
    _trace_ocr_blocks(request.session_id, request.turn_id, ocr_blocks)

    # 2. detector
    _trace_detector_input(request.session_id, request.turn_id, request.prompt_text, ocr_blocks)
    detected_candidates = _detect_candidates(request=request, pii_detector=pii_detector, ocr_blocks=ocr_blocks)
    _trace_detector_output(request.session_id, request.turn_id, detected_candidates)

    # 3. alias / session context preparation
    session_service, session_binding = _prepare_session_context(
        session_id=request.session_id,
        mapping_store=mapping_store,
        persona_repository=persona_repository,
    )

    # 4. local context / quality / persona state preparation
    # 5. DecisionContextBuilder
    decision_context = _build_decision_context(
        request=request,
        ocr_blocks=ocr_blocks,
        detected_candidates=detected_candidates,
        session_binding=session_binding,
        mapping_store=mapping_store,
        persona_repository=persona_repository,
    )

    # 6. DecisionFeatureExtractor
    # 7. DEModelEngine / runtime
    # 8. ConstraintResolver
    # 9. placeholder allocation / replacement planning
    replacement_plan = _plan_replacements(
        decision_context=decision_context,
        decision_engine=decision_engine,
        mapping_store=mapping_store,
    )

    # 10. render
    sanitized_prompt_text, sanitized_screenshot, applied_replacements = _render_sanitize_result(
        request=request,
        rendering_engine=rendering_engine,
        replacement_plan=replacement_plan,
        ocr_blocks=ocr_blocks,
    )

    # 11. mapping store
    _persist_sanitize_result(
        request=request,
        session_service=session_service,
        replacement_plan=replacement_plan,
        applied_replacements=applied_replacements,
    )

    return SanitizeResponse(
        sanitized_prompt_text=sanitized_prompt_text,
        sanitized_screenshot=sanitized_screenshot,
        active_persona_id=replacement_plan.active_persona_id,
        replacements=applied_replacements,
        metadata={
            "mode": replacement_plan.metadata.get("mode", ""),
            "protection_level": request.protection_level.value,
            "candidate_count": str(len(detected_candidates)),
            "applied_count": str(len(applied_replacements)),
        },
    )
