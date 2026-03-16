"""sanitize -> restore 闭环集成测试。"""

from privacyguard.api.dto import RestoreRequest, SanitizeRequest
from privacyguard.api.facade import PrivacyGuardFacade
from privacyguard.infrastructure.decision.label_persona_mixed_engine import LabelPersonaMixedDecisionEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
from privacyguard.infrastructure.restoration.action_restorer import ActionRestorer


class FakeOCRBackend:
    """测试用 OCR 后端。"""

    def infer(self, image):
        """返回包含地址的 OCR 结果。"""
        _ = image
        return [
            {
                "text": "北京市海淀区XX路",
                "bbox": {"x": 10, "y": 10, "width": 80, "height": 18},
                "score": 0.95,
                "line_id": 0,
            }
        ]


def test_sanitize_restore_roundtrip_with_label_persona_mixed(tmp_path) -> None:
    """验证使用 label_persona_mixed 的闭环可还原真实文本。"""
    image_path = tmp_path / "input.png"
    image_path.write_bytes(b"fake-image")
    mapping_store = InMemoryMappingStore()
    persona_repo = JsonPersonaRepository(path="data/personas.sample.json")
    ocr_engine = PPOCREngineAdapter(backend=FakeOCRBackend())
    detector = RuleBasedPIIDetector(dictionary_path="data/pii_dictionary.sample.json")
    decision_engine = LabelPersonaMixedDecisionEngine(persona_repository=persona_repo, confidence_threshold=0.0)
    rendering_engine = PromptRenderer()
    restoration_module = ActionRestorer()
    facade = PrivacyGuardFacade(
        ocr_engine=ocr_engine,
        pii_detector=detector,
        persona_repository=persona_repo,
        mapping_store=mapping_store,
        decision_engine=decision_engine,
        rendering_engine=rendering_engine,
        restoration_module=restoration_module,
    )

    sanitize_request = SanitizeRequest(
        session_id="s-roundtrip",
        turn_id=1,
        prompt_text="我叫张三，电话是13800138000。",
        screenshot=str(image_path),
        detector_mode="rule_based",
        decision_mode="label_persona_mixed",
    )
    sanitize_response = facade.sanitize(sanitize_request)

    assert sanitize_response.sanitized_prompt_text != sanitize_request.prompt_text
    assert len(sanitize_response.replacements) > 0

    restore_request = RestoreRequest(
        session_id="s-roundtrip",
        turn_id=1,
        cloud_text=sanitize_response.sanitized_prompt_text,
    )
    restore_response = facade.restore(restore_request)

    assert "张三" in restore_response.restored_text
    assert "13800138000" in restore_response.restored_text
