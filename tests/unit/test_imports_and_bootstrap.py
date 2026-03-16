"""第 1 轮导入与装配测试。"""

from importlib import import_module
from pathlib import Path

from privacyguard.api.dto import RestoreRequest, SanitizeRequest
from privacyguard.api.facade import PrivacyGuardFacade
from privacyguard.bootstrap.factories import create_facade, create_facade_from_file, load_config


def test_dto_can_be_instantiated() -> None:
    """验证核心 DTO 可实例化。"""
    sanitize_request = SanitizeRequest(session_id="s1", turn_id=1, prompt_text="hello")
    restore_request = RestoreRequest(session_id="s1", turn_id=1, cloud_text="world")

    assert sanitize_request.session_id == "s1"
    assert restore_request.cloud_text == "world"


def test_imports_and_facade_are_available() -> None:
    """验证抽象接口与门面可导入。"""
    modules = [
        "privacyguard.domain.interfaces.ocr_engine",
        "privacyguard.domain.interfaces.pii_detector",
        "privacyguard.domain.interfaces.persona_repository",
        "privacyguard.domain.interfaces.mapping_store",
        "privacyguard.domain.interfaces.decision_engine",
        "privacyguard.domain.interfaces.rendering_engine",
        "privacyguard.domain.interfaces.restoration_module",
        "privacyguard.api.facade",
    ]
    for module in modules:
        assert import_module(module) is not None

    assert PrivacyGuardFacade is not None


def test_default_config_can_be_loaded() -> None:
    """验证默认配置可被解析。"""
    project_root = Path(__file__).resolve().parents[2]
    config_path = project_root / "configs" / "default.yaml"

    config = load_config(config_path)
    assert config["ocr"]["provider"] == "ppocr_v5"
    assert config["pii_detector"]["mode"] == "rule_based"


def test_factory_can_create_facade() -> None:
    """验证工厂可创建 facade。"""
    project_root = Path(__file__).resolve().parents[2]
    config_path = project_root / "configs" / "default.yaml"

    facade_from_file = create_facade_from_file(config_path)
    facade_from_dict = create_facade(load_config(config_path))

    assert isinstance(facade_from_file, PrivacyGuardFacade)
    assert isinstance(facade_from_dict, PrivacyGuardFacade)


def test_key_modules_import_without_cycles() -> None:
    """验证关键模块无明显循环导入导致的失败。"""
    key_modules = [
        "privacyguard.api.dto",
        "privacyguard.api.facade",
        "privacyguard.bootstrap.registry",
        "privacyguard.bootstrap.factories",
        "privacyguard.domain.enums",
        "privacyguard.domain.models.ocr",
        "privacyguard.domain.models.pii",
        "privacyguard.domain.models.persona",
        "privacyguard.domain.models.mapping",
        "privacyguard.domain.models.decision",
        "privacyguard.domain.models.action",
    ]
    imported = [import_module(module_name) for module_name in key_modules]
    assert all(module is not None for module in imported)
