"""脱敏流程编排。"""

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
    context_builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repository)
    ocr_blocks = ocr_engine.extract(request.screenshot) if request.screenshot is not None else []
    _trace_ocr_blocks(request.session_id, request.turn_id, ocr_blocks)
    _trace_detector_input(request.session_id, request.turn_id, request.prompt_text, ocr_blocks)
    candidates = _detect_candidates(request=request, pii_detector=pii_detector, ocr_blocks=ocr_blocks)
    _trace_detector_output(request.session_id, request.turn_id, candidates)
    session_service = SessionService(mapping_store=mapping_store, persona_repository=persona_repository)
    session_binding = session_service.get_or_create_binding(request.session_id)
    decision_context = context_builder.build(
        session_id=request.session_id,
        turn_id=request.turn_id,
        prompt_text=request.prompt_text,
        protection_level=request.protection_level,
        detector_overrides=request.detector_overrides,
        ocr_blocks=ocr_blocks,
        candidates=candidates,
        session_binding=session_binding,
    )
    plan = decision_engine.plan(decision_context)
    plan = SessionPlaceholderAllocator(mapping_store=mapping_store).assign(plan)
    sanitized_prompt_text, applied_records = rendering_engine.render_text(request.prompt_text, plan)
    sanitized_screenshot = (
        rendering_engine.render_image(request.screenshot, plan, ocr_blocks=ocr_blocks)
        if request.screenshot is not None
        else None
    )
    session_service.append_turn_replacements(request.session_id, request.turn_id, applied_records)
    if plan.active_persona_id:
        session_service.bind_active_persona(request.session_id, plan.active_persona_id, request.turn_id)
    return SanitizeResponse(
        sanitized_prompt_text=sanitized_prompt_text,
        sanitized_screenshot=sanitized_screenshot,
        active_persona_id=plan.active_persona_id,
        replacements=applied_records,
        metadata={
            "mode": plan.metadata.get("mode", ""),
            "protection_level": request.protection_level.value,
            "candidate_count": str(len(candidates)),
            "applied_count": str(len(applied_records)),
        },
    )
