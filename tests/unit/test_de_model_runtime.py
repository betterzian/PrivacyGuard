"""de_model runtime 解码测试。"""

import pytest

from privacyguard.domain.enums import ActionType
from privacyguard.infrastructure.decision.de_model_runtime import TinyPolicyOutputDecoder

torch = pytest.importorskip("torch")

from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyBatch, TinyPolicyOutput


def test_tiny_policy_output_decoder_uses_keep_fallback_for_low_confidence() -> None:
    decoder = TinyPolicyOutputDecoder(keep_threshold=0.25)
    batch = _build_batch()
    output = _build_output(
        persona_logits=[[0.0, 0.0]],
        action_logits=[[[0.0, 0.0, 5.0]]],
        confidence_scores=[[0.1]],
    )

    runtime_output = decoder.decode(batch=batch, output=output, torch_module=torch)

    assert runtime_output.active_persona_id == "persona-b"
    assert runtime_output.candidate_decisions[0].preferred_action == ActionType.KEEP
    assert "decode=low_conf_keep" in runtime_output.candidate_decisions[0].reason


def test_tiny_policy_output_decoder_applies_tie_break_priority() -> None:
    decoder = TinyPolicyOutputDecoder(action_tie_tolerance=1e-6)
    batch = _build_batch()
    output = _build_output(
        persona_logits=[[0.0, 0.0]],
        action_logits=[[[0.0, 0.0, 0.0]]],
        confidence_scores=[[0.9]],
    )

    runtime_output = decoder.decode(batch=batch, output=output, torch_module=torch)

    assert runtime_output.candidate_decisions[0].preferred_action == ActionType.PERSONA_SLOT
    assert "decode=tie_break:PERSONA_SLOT" in runtime_output.candidate_decisions[0].reason


def test_tiny_policy_output_decoder_respects_persona_score_threshold() -> None:
    decoder = TinyPolicyOutputDecoder(persona_score_threshold=0.6)
    batch = _build_batch()
    output = _build_output(
        persona_logits=[[0.0, 0.0]],
        action_logits=[[[0.0, 1.0, 0.0]]],
        confidence_scores=[[0.9]],
    )

    runtime_output = decoder.decode(batch=batch, output=output, torch_module=torch)

    assert runtime_output.active_persona_id is None
    assert runtime_output.persona_scores["persona-a"] == pytest.approx(0.5, abs=1e-6)
    assert runtime_output.persona_scores["persona-b"] == pytest.approx(0.5, abs=1e-6)
    assert runtime_output.candidate_decisions[0].preferred_action == ActionType.GENERICIZE


def _build_batch() -> TinyPolicyBatch:
    return TinyPolicyBatch(
        page_features=torch.zeros((1, 1), dtype=torch.float32),
        candidate_features=torch.zeros((1, 1, 1), dtype=torch.float32),
        candidate_mask=torch.tensor([[True]], dtype=torch.bool),
        candidate_text_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_text_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_prompt_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_prompt_mask=torch.ones((1, 1, 1), dtype=torch.long),
        candidate_ocr_ids=torch.zeros((1, 1, 1), dtype=torch.long),
        candidate_ocr_mask=torch.ones((1, 1, 1), dtype=torch.long),
        persona_features=torch.zeros((1, 2, 1), dtype=torch.float32),
        persona_mask=torch.tensor([[True, True]], dtype=torch.bool),
        persona_text_ids=torch.zeros((1, 2, 1), dtype=torch.long),
        persona_text_mask=torch.ones((1, 2, 1), dtype=torch.long),
        candidate_ids=[["cand-1"]],
        persona_ids=[["persona-a", "persona-b"]],
    )


def _build_output(*, persona_logits, action_logits, confidence_scores) -> TinyPolicyOutput:
    return TinyPolicyOutput(
        persona_logits=torch.tensor(persona_logits, dtype=torch.float32),
        action_logits=torch.tensor(action_logits, dtype=torch.float32),
        confidence_scores=torch.tensor(confidence_scores, dtype=torch.float32),
        utility_scores=torch.zeros((1, 1), dtype=torch.float32),
        page_summary=torch.zeros((1, 1), dtype=torch.float32),
        persona_context=torch.zeros((1, 1), dtype=torch.float32),
    )
