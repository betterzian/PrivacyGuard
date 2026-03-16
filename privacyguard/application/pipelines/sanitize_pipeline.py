"""脱敏流程编排。"""

from privacyguard.api.dto import SanitizeRequest, SanitizeResponse
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine


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
    candidates = pii_detector.detect(prompt_text=request.prompt_text, ocr_blocks=ocr_blocks)
    session_service = SessionService(mapping_store=mapping_store, persona_repository=persona_repository)
    session_binding = session_service.get_or_create_binding(request.session_id)
    plan = decision_engine.plan(
        session_id=request.session_id,
        turn_id=request.turn_id,
        candidates=candidates,
        session_binding=session_binding,
    )
    sanitized_prompt_text, applied_records = rendering_engine.render_text(request.prompt_text, plan)
    sanitized_screenshot = rendering_engine.render_image(request.screenshot, plan) if request.screenshot is not None else None
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

