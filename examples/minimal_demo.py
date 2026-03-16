"""最小可运行示例。"""

from privacyguard.api import RestoreRequest, SanitizeRequest
from privacyguard.api.facade import PrivacyGuardFacade


def main() -> None:
    """演示 sanitize -> restore 的最小调用链。"""
    facade = PrivacyGuardFacade.from_config_file("configs/default.yaml")
    sanitize_response = facade.sanitize(
        SanitizeRequest(
            session_id="demo-session",
            turn_id=1,
            prompt_text="我叫张三，电话是13800138000。",
            screenshot=None,
            detector_mode="rule_based",
            decision_mode="label_only",
        )
    )
    print("Sanitized:", sanitize_response.sanitized_prompt_text)

    restore_response = facade.restore(
        RestoreRequest(
            session_id="demo-session",
            turn_id=1,
            cloud_text=sanitize_response.sanitized_prompt_text,
        )
    )
    print("Restored:", restore_response.restored_text)


if __name__ == "__main__":
    main()

