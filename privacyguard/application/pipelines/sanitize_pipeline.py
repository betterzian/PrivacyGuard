"""脱敏流程编排。"""

from privacyguard.api.dto import SanitizeRequest, SanitizeResponse
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine


def _trace_ocr_blocks(session_id: str, turn_id: int, ocr_blocks: list) -> None:
    """追踪 PP-OCRv5 输出：块数量与样本。"""
    n = len(ocr_blocks)
    sample = []
    for i, b in enumerate(ocr_blocks[:5]):
        text = getattr(b, "text", str(b))[:30]
        bbox = getattr(b, "bbox", None)
        sample.append({"text": text, "bbox": str(bbox) if bbox else None})
    print(f"[PrivacyGuard] PP-OCRv5 output (session={session_id[:8]}, turn={turn_id}): blocks={n}, sample={sample}")


def _trace_detector_input(session_id: str, turn_id: int, prompt_text: str, ocr_blocks: list) -> None:
    """追踪 Detector 输入：prompt 与 ocr_blocks。"""
    prompt_preview = (prompt_text[:60] + "…") if len(prompt_text) > 60 else prompt_text
    ocr_sample = [getattr(b, "text", str(b))[:20] for b in ocr_blocks[:3]]
    print(f"[PrivacyGuard] Detector input (session={session_id[:8]}, turn={turn_id}): prompt_len={len(prompt_text)}, prompt_preview={prompt_preview!r}, ocr_blocks={len(ocr_blocks)}, ocr_sample={ocr_sample}")


def _trace_detector_output(session_id: str, turn_id: int, candidates: list) -> None:
    """追踪 Detector 输出：candidates。"""
    cand_sample = []
    for c in candidates[:5]:
        text = getattr(c, "text", str(c))[:20]
        attr = getattr(c, "attr_type", None)
        src = getattr(c, "source", None)
        cand_sample.append({"text": text, "attr_type": str(attr), "source": str(src)})
    print(f"[PrivacyGuard] Detector output (session={session_id[:8]}, turn={turn_id}): candidates={len(candidates)}, sample={cand_sample}")


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
    ocr_blocks = ocr_engine.extract(request.screenshot) if request.screenshot is not None else []
    _trace_ocr_blocks(request.session_id, request.turn_id, ocr_blocks)
    _trace_detector_input(request.session_id, request.turn_id, request.prompt_text, ocr_blocks)
    candidates = pii_detector.detect(prompt_text=request.prompt_text, ocr_blocks=ocr_blocks)
    _trace_detector_output(request.session_id, request.turn_id, candidates)
    session_service = SessionService(mapping_store=mapping_store, persona_repository=persona_repository)
    session_binding = session_service.get_or_create_binding(request.session_id)
    plan = decision_engine.plan(
        session_id=request.session_id,
        turn_id=request.turn_id,
        candidates=candidates,
        session_binding=session_binding,
    )
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
            "candidate_count": str(len(candidates)),
            "applied_count": str(len(applied_records)),
        },
    )
