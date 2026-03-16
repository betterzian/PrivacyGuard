"""Facade sanitize 集成测试。"""

from privacyguard.api.dto import SanitizeRequest, SanitizeResponse
from privacyguard.api.facade import PrivacyGuardFacade


def test_facade_sanitize_can_start_from_default_config() -> None:
    """验证可从默认配置启动并返回结构化响应。"""
    facade = PrivacyGuardFacade.from_config_file("configs/default.yaml")
    request = SanitizeRequest(
        session_id="s-facade-sanitize",
        turn_id=1,
        prompt_text="测试文本",
        screenshot=None,
    )

    response = facade.sanitize(request)

    assert isinstance(response, SanitizeResponse)
    assert isinstance(response.sanitized_prompt_text, str)
    assert isinstance(response.replacements, list)
    assert isinstance(response.metadata, dict)

