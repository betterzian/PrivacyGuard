"""Privacy 词库（rule_based 本地词典）写入示例。"""

from privacyguard import PrivacyGuard


def main() -> None:
    """通过 PrivacyGuard.write_privacy_repository 合并写入并自动刷新检测器词典。"""
    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
    summary = guard.write_privacy_repository(
        {
            "version": 2,
            "true_personas": [
                {
                    "persona_id": "demo_user",
                    "display_name": "演示用户",
                    "slots": {
                        "name": {"value": "张三", "aliases": ["李四"]},
                        "phone": {"value": "13800138000", "aliases": []},
                        "email": {"value": "zhangsan@example.com", "aliases": []},
                        "address": {
                            "street": {
                                "value": "上海市浦东新区世纪大道100号",
                                "aliases": [],
                            }
                        },
                    },
                }
            ],
        }
    )
    print("Written:", summary["repository_path"])


if __name__ == "__main__":
    main()
