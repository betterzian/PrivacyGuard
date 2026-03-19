"""PrivacyGuard 顶层装配测试。"""

from privacyguard import PrivacyGuard


def test_privacy_guard_passes_decision_config_to_de_model_engine() -> None:
    guard = PrivacyGuard(
        decision_mode="de_model",
        decision_config={
            "runtime_type": "heuristic",
            "keep_threshold": 0.4,
            "device": "cpu",
        },
    )

    assert guard.decision_mode == "de_model"
    assert guard.decision_engine.runtime_type == "heuristic"
    assert guard.decision_engine.keep_threshold == 0.4
    assert guard.decision_engine.device == "cpu"
