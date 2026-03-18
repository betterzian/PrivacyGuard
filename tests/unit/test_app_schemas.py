"""app schema 请求映射测试。"""

from privacyguard.app.schemas import SanitizeRequestModel
from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel


def test_sanitize_request_model_maps_detector_overrides_from_payload() -> None:
    request = SanitizeRequestModel.from_payload(
        {
            "session_id": "session-schema",
            "turn_id": 2,
            "prompt": "腾讯科技",
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
