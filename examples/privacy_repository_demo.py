"""本地隐私仓库写入示例。"""

from privacyguard import PrivacyGuard, PrivacyRepository


def main() -> None:
    """先写本地隐私仓库，再让 PrivacyGuard 直接读取。"""
    repository = PrivacyRepository()
    repository.write(
        {
            "personas": [
                {
                    "persona_id": "owner",
                    "display_name": "主身份",
                    "slots": {
                        "name": "张三",
                        "phone": "13800138000",
                        "email": "zhangsan@example.com",
                        "address": "上海市浦东新区世纪大道100号",
                    },
                    "metadata": {
                        "source": "manual_import",
                    },
                    "stats": {
                        "exposure_count": 0,
                    },
                }
            ]
        }
    )

    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_persona_mixed")
    persona = guard.persona_repo.get_persona("owner")
    print("Loaded persona:", persona.display_name if persona else "missing")


if __name__ == "__main__":
    main()
