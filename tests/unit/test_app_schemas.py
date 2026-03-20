"""app schema 请求映射测试。"""

from privacyguard.app.schemas import PrivacyRepositoryWriteRequestModel, SanitizeRequestModel
from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel


def test_sanitize_request_model_maps_detector_overrides_from_payload() -> None:
    request = SanitizeRequestModel.from_payload(
        {
            "session_id": "session-schema",
            "turn_id": 2,
            "prompt_text": "腾讯科技",
            "protection_level": "balanced",
            "detector_overrides": {
                "organization": 0.61,
                "address": 0.52,
            },
        }
    )

    assert request.protection_level == ProtectionLevel.BALANCED
    assert request.detector_overrides == {
        PIIAttributeType.ORGANIZATION: 0.61,
        PIIAttributeType.ADDRESS: 0.52,
    }
    dto = request.to_dto()
    assert dto.detector_overrides == {
        PIIAttributeType.ORGANIZATION: 0.61,
        PIIAttributeType.ADDRESS: 0.52,
    }


def test_privacy_repository_write_request_model_maps_profile_and_slots() -> None:
    request = PrivacyRepositoryWriteRequestModel.from_payload(
        {
            "personas": [
                {
                    "persona_id": "persona-owner",
                    "display_name": "主身份",
                    "slots": {
                        "name": "张三",
                        "phone": "13800138000",
                        "email": "zhangsan@example.com",
                    },
                    "metadata": {
                        "source": "crm",
                    },
                    "stats": {
                        "exposure_count": 2,
                        "last_exposed_turn_id": 5,
                    },
                }
            ]
        }
    )

    item = request.personas[0]
    assert item.display_name == "主身份"
    assert item.slot_updates == {
        PIIAttributeType.NAME: "张三",
        PIIAttributeType.PHONE: "13800138000",
        PIIAttributeType.EMAIL: "zhangsan@example.com",
    }
    assert item.metadata_updates == {"source": "crm"}
    assert item.stats_updates == {
        "exposure_count": 2,
        "last_exposed_turn_id": 5,
    }
