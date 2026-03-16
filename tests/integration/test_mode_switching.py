"""模式切换装配集成测试。"""

from privacyguard.api.facade import PrivacyGuardFacade
from privacyguard.bootstrap.factories import create_facade


def test_mode_switching_detector_and_decision_can_be_assembled() -> None:
    """验证 detector/decision 多模式切换不破坏装配。"""
    config_rule = {
        "ocr": {"provider": "ppocr_v5"},
        "pii_detector": {"mode": "rule_based"},
        "decision_engine": {"mode": "label_only"},
        "mapping_store": {"type": "in_memory"},
        "persona_repository": {"type": "json", "path": "data/personas.sample.json"},
        "rendering_engine": {"mode": "prompt_renderer"},
        "restoration_module": {"mode": "action_restorer"},
    }
    config_ner = {
        "ocr": {"provider": "ppocr_v5"},
        "pii_detector": {"mode": "rule_ner_based"},
        "decision_engine": {"mode": "label_persona_mixed"},
        "mapping_store": {"type": "json", "path": "data/test.mapping.json"},
        "persona_repository": {"type": "json", "path": "data/personas.sample.json"},
        "rendering_engine": {"mode": "prompt_renderer"},
        "restoration_module": {"mode": "action_restorer"},
    }
    config_de = {
        "ocr": {"provider": "ppocr_v5"},
        "pii_detector": {"mode": "rule_based"},
        "decision_engine": {"mode": "de_model"},
        "mapping_store": {"type": "in_memory"},
        "persona_repository": {"type": "json", "path": "data/personas.sample.json"},
        "rendering_engine": {"mode": "prompt_renderer"},
        "restoration_module": {"mode": "action_restorer"},
    }

    facade_rule = create_facade(config_rule)
    facade_ner = create_facade(config_ner)
    facade_de = create_facade(config_de)

    assert isinstance(facade_rule, PrivacyGuardFacade)
    assert isinstance(facade_ner, PrivacyGuardFacade)
    assert isinstance(facade_de, PrivacyGuardFacade)

