"""最小可运行示例。"""

from privacyguard import PrivacyGuard


def main() -> None:
    """演示 sanitize -> restore 的最小调用链。"""
    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
    sanitize_response = guard.sanitize(
        {
            "session_id": "demo-session",
            "turn_id": 1,
            "prompt": "我叫张三，电话是13800138000。",
            "image": None,
        }
    )
    print("Sanitized:", sanitize_response["masked_prompt"])

    restore_response = guard.restore(
        {
            "session_id": "demo-session",
            "turn_id": 1,
            "agent_text": sanitize_response["masked_prompt"],
        }
    )
    print("Restored:", restore_response["restored_text"])


if __name__ == "__main__":
    main()
