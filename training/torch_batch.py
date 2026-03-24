"""PyTorch 训练 batch 构造工具。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

import torch

from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.policies.action_labels import (
    ACTION_ORDER,
    PROTECT_LABEL_REWRITE,
    PROTECT_ORDER,
    REWRITE_MODE_NONE,
    REWRITE_MODE_ORDER,
)
from privacyguard.infrastructure.decision.features import (
    CANDIDATE_FEATURE_DIM,
    PAGE_FEATURE_DIM,
    PERSONA_FEATURE_DIM,
    DecisionFeatureExtractor,
)
from privacyguard.infrastructure.decision.policy_context import (
    candidate_by_id as derived_candidate_by_id,
    derive_policy_context,
)
from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyBatch
from privacyguard.infrastructure.decision.tokenizer import CharacterHashTokenizer
from training.types import (
    SupervisedTurnLabels,
    TrainingTurnExample,
    hierarchical_labels_to_action,
    normalize_action_type,
    normalize_rewrite_mode,
)

IGNORE_INDEX = -100


@dataclass(slots=True)
class SupervisedTinyPolicyBatch(TinyPolicyBatch):
    """在 `TinyPolicyBatch` 基础上附带层级监督标签。

    结构化特征与文本辅助特征沿用 `TinyPolicyBatch`：

    - `page_features`
    - `candidate_features`
    - `persona_features`
    - `candidate_text_ids`
    - `candidate_prompt_ids`
    - `candidate_ocr_ids`
    - `persona_text_ids`

    新增监督标签：

    - `target_protect_labels`: candidate 级 `KEEP / REWRITE`
    - `target_rewrite_modes`: candidate 级 `GENERICIZE / PERSONA_SLOT`
      `KEEP` 情况使用 `IGNORE_INDEX`
    - `target_persona_indices`: turn 级 persona 目标；无目标为 `IGNORE_INDEX`
    - `final_action_targets`: candidate 级 final_action 兼容/调试标签
    """

    target_protect_labels: torch.Tensor
    target_rewrite_modes: torch.Tensor
    target_persona_indices: torch.Tensor
    final_action_targets: torch.Tensor

    def to(self, device: torch.device | str) -> "SupervisedTinyPolicyBatch":
        return replace(
            self,
            page_features=self.page_features.to(device),
            candidate_features=self.candidate_features.to(device),
            candidate_mask=self.candidate_mask.to(device),
            candidate_text_ids=self.candidate_text_ids.to(device),
            candidate_text_mask=self.candidate_text_mask.to(device),
            candidate_prompt_ids=self.candidate_prompt_ids.to(device),
            candidate_prompt_mask=self.candidate_prompt_mask.to(device),
            candidate_ocr_ids=self.candidate_ocr_ids.to(device),
            candidate_ocr_mask=self.candidate_ocr_mask.to(device),
            persona_features=self.persona_features.to(device),
            persona_mask=self.persona_mask.to(device),
            persona_text_ids=self.persona_text_ids.to(device),
            persona_text_mask=self.persona_text_mask.to(device),
            target_protect_labels=self.target_protect_labels.to(device),
            target_rewrite_modes=self.target_rewrite_modes.to(device),
            target_persona_indices=self.target_persona_indices.to(device),
            final_action_targets=self.final_action_targets.to(device),
        )


@dataclass(slots=True)
class TinyPolicyBatchBuilder:
    """把 DecisionContext 打包为 TinyPolicyNet 可消费的 batch。"""

    max_candidates: int = 32
    max_personas: int = 8
    max_text_length: int = 48
    vocab_size: int = 2048
    tokenizer: CharacterHashTokenizer = field(init=False)
    feature_extractor: DecisionFeatureExtractor = field(init=False)

    def __post_init__(self) -> None:
        self.tokenizer = CharacterHashTokenizer(vocab_size=self.vocab_size)
        self.feature_extractor = DecisionFeatureExtractor()

    def build(self, contexts: list[DecisionContext]) -> TinyPolicyBatch:
        """将多个上下文转换为一个张量 batch。"""
        if not contexts:
            raise ValueError("contexts 不能为空。")
        batch_size = len(contexts)
        policies = [derive_policy_context(context) for context in contexts]
        packed_features = [
            self.feature_extractor.pack(context, policy=policy)
            for context, policy in zip(contexts, policies, strict=False)
        ]
        for context, packed in zip(contexts, packed_features):
            self._validate_capacity(
                candidate_count=len(packed.candidate_ids),
                persona_count=len(packed.persona_ids),
                subject=f"session_id={context.session_id}, turn_id={context.turn_id}",
            )
        max_candidates = max(1, max(len(packed.candidate_ids) for packed in packed_features))
        max_personas = max(1, max(len(packed.persona_ids) for packed in packed_features))

        page_features = torch.zeros((batch_size, PAGE_FEATURE_DIM), dtype=torch.float32)
        candidate_features = torch.zeros((batch_size, max_candidates, CANDIDATE_FEATURE_DIM), dtype=torch.float32)
        candidate_mask = torch.zeros((batch_size, max_candidates), dtype=torch.bool)
        candidate_text_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_text_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_prompt_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_prompt_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_ocr_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_ocr_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        persona_features = torch.zeros((batch_size, max_personas, PERSONA_FEATURE_DIM), dtype=torch.float32)
        persona_mask = torch.zeros((batch_size, max_personas), dtype=torch.bool)
        persona_text_ids = torch.zeros((batch_size, max_personas, self.max_text_length), dtype=torch.long)
        persona_text_mask = torch.zeros((batch_size, max_personas, self.max_text_length), dtype=torch.long)

        candidate_ids = [["" for _ in range(max_candidates)] for _ in range(batch_size)]
        persona_ids = [["" for _ in range(max_personas)] for _ in range(batch_size)]

        for batch_index, context in enumerate(contexts):
            policy = policies[batch_index]
            packed = packed_features[batch_index]
            candidate_views = policy.candidate_policy_views
            candidate_view_by_id = {
                str(view.get("candidate_id", "")).strip(): view
                for view in candidate_views
                if str(view.get("candidate_id", "")).strip()
            }
            persona_states = policy.persona_policy_states
            persona_state_by_id = {
                str(state.get("persona_id", "")).strip(): state
                for state in persona_states
                if str(state.get("persona_id", "")).strip()
            }
            page_features[batch_index, : len(packed.page_vector)] = torch.tensor(packed.page_vector, dtype=torch.float32)

            for candidate_index, candidate_id in enumerate(packed.candidate_ids[:max_candidates]):
                candidate_vector = packed.candidate_vectors[candidate_index]
                candidate_features[batch_index, candidate_index, : len(candidate_vector)] = torch.tensor(candidate_vector, dtype=torch.float32)
                candidate_mask[batch_index, candidate_index] = True
                candidate_ids[batch_index][candidate_index] = candidate_id
                candidate_view = candidate_view_by_id.get(candidate_id, {})

                encoded_text = self.tokenizer.encode(self._candidate_text(context, candidate_id), max_length=self.max_text_length)
                encoded_prompt = self.tokenizer.encode(str(candidate_view.get("_prompt_context", "")), max_length=self.max_text_length)
                encoded_ocr = self.tokenizer.encode(str(candidate_view.get("_ocr_context", "")), max_length=self.max_text_length)
                candidate_text_ids[batch_index, candidate_index] = torch.tensor(encoded_text.input_ids, dtype=torch.long)
                candidate_text_mask[batch_index, candidate_index] = torch.tensor(encoded_text.attention_mask, dtype=torch.long)
                candidate_prompt_ids[batch_index, candidate_index] = torch.tensor(encoded_prompt.input_ids, dtype=torch.long)
                candidate_prompt_mask[batch_index, candidate_index] = torch.tensor(encoded_prompt.attention_mask, dtype=torch.long)
                candidate_ocr_ids[batch_index, candidate_index] = torch.tensor(encoded_ocr.input_ids, dtype=torch.long)
                candidate_ocr_mask[batch_index, candidate_index] = torch.tensor(encoded_ocr.attention_mask, dtype=torch.long)

            for persona_index, persona_id in enumerate(packed.persona_ids[:max_personas]):
                persona_vector = packed.persona_vectors[persona_index]
                persona_features[batch_index, persona_index, : len(persona_vector)] = torch.tensor(persona_vector, dtype=torch.float32)
                persona_mask[batch_index, persona_index] = True
                persona_ids[batch_index][persona_index] = persona_id
                persona_state = persona_state_by_id.get(persona_id, {})

                encoded_persona = self.tokenizer.encode(self._persona_text(context, persona_state), max_length=self.max_text_length)
                persona_text_ids[batch_index, persona_index] = torch.tensor(encoded_persona.input_ids, dtype=torch.long)
                persona_text_mask[batch_index, persona_index] = torch.tensor(encoded_persona.attention_mask, dtype=torch.long)

        return TinyPolicyBatch(
            page_features=page_features,
            candidate_features=candidate_features,
            candidate_mask=candidate_mask,
            candidate_text_ids=candidate_text_ids,
            candidate_text_mask=candidate_text_mask,
            candidate_prompt_ids=candidate_prompt_ids,
            candidate_prompt_mask=candidate_prompt_mask,
            candidate_ocr_ids=candidate_ocr_ids,
            candidate_ocr_mask=candidate_ocr_mask,
            persona_features=persona_features,
            persona_mask=persona_mask,
            persona_text_ids=persona_text_ids,
            persona_text_mask=persona_text_mask,
            candidate_ids=candidate_ids,
            persona_ids=persona_ids,
        )

    def build_examples(self, examples: list[TrainingTurnExample]) -> TinyPolicyBatch:
        """将序列化后的训练样本转换为 TinyPolicyBatch。"""
        return self._build_example_batch(examples)

    def build_supervised_examples(
        self,
        examples: list[TrainingTurnExample],
        labels: list[SupervisedTurnLabels],
    ) -> SupervisedTinyPolicyBatch:
        """将训练样本与层级标签一起打包为 supervised batch。"""
        base_batch = self._build_example_batch(examples)
        return self._attach_supervised_targets(base_batch=base_batch, labels=labels)

    def _build_example_batch(self, examples: list[TrainingTurnExample]) -> TinyPolicyBatch:
        """将序列化后的训练样本转换为 TinyPolicyBatch。"""
        if not examples:
            raise ValueError("examples 不能为空。")
        batch_size = len(examples)
        for example in examples:
            self._validate_capacity(
                candidate_count=len(example.candidate_ids),
                persona_count=len(example.persona_ids),
                subject=f"session_id={example.session_id}, turn_id={example.turn_id}",
            )
        max_candidates = max(1, max(len(example.candidate_ids) for example in examples))
        max_personas = max(1, max(len(example.persona_ids) for example in examples))

        page_features = torch.zeros((batch_size, PAGE_FEATURE_DIM), dtype=torch.float32)
        candidate_features = torch.zeros((batch_size, max_candidates, CANDIDATE_FEATURE_DIM), dtype=torch.float32)
        candidate_mask = torch.zeros((batch_size, max_candidates), dtype=torch.bool)
        candidate_text_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_text_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_prompt_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_prompt_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_ocr_ids = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        candidate_ocr_mask = torch.zeros((batch_size, max_candidates, self.max_text_length), dtype=torch.long)
        persona_features = torch.zeros((batch_size, max_personas, PERSONA_FEATURE_DIM), dtype=torch.float32)
        persona_mask = torch.zeros((batch_size, max_personas), dtype=torch.bool)
        persona_text_ids = torch.zeros((batch_size, max_personas, self.max_text_length), dtype=torch.long)
        persona_text_mask = torch.zeros((batch_size, max_personas, self.max_text_length), dtype=torch.long)

        candidate_ids = [["" for _ in range(max_candidates)] for _ in range(batch_size)]
        persona_ids = [["" for _ in range(max_personas)] for _ in range(batch_size)]

        for batch_index, example in enumerate(examples):
            page_features[batch_index, : len(example.page_vector)] = torch.tensor(example.page_vector, dtype=torch.float32)

            for candidate_index, candidate_id in enumerate(example.candidate_ids[:max_candidates]):
                candidate_vector = example.candidate_vectors[candidate_index]
                candidate_features[batch_index, candidate_index, : len(candidate_vector)] = torch.tensor(candidate_vector, dtype=torch.float32)
                candidate_mask[batch_index, candidate_index] = True
                candidate_ids[batch_index][candidate_index] = candidate_id

                encoded_text = self.tokenizer.encode(example.candidate_texts[candidate_index], max_length=self.max_text_length)
                encoded_prompt = self.tokenizer.encode(
                    example.candidate_prompt_contexts[candidate_index],
                    max_length=self.max_text_length,
                )
                encoded_ocr = self.tokenizer.encode(example.candidate_ocr_contexts[candidate_index], max_length=self.max_text_length)
                candidate_text_ids[batch_index, candidate_index] = torch.tensor(encoded_text.input_ids, dtype=torch.long)
                candidate_text_mask[batch_index, candidate_index] = torch.tensor(encoded_text.attention_mask, dtype=torch.long)
                candidate_prompt_ids[batch_index, candidate_index] = torch.tensor(encoded_prompt.input_ids, dtype=torch.long)
                candidate_prompt_mask[batch_index, candidate_index] = torch.tensor(encoded_prompt.attention_mask, dtype=torch.long)
                candidate_ocr_ids[batch_index, candidate_index] = torch.tensor(encoded_ocr.input_ids, dtype=torch.long)
                candidate_ocr_mask[batch_index, candidate_index] = torch.tensor(encoded_ocr.attention_mask, dtype=torch.long)

            for persona_index, persona_id in enumerate(example.persona_ids[:max_personas]):
                persona_vector = example.persona_vectors[persona_index]
                persona_features[batch_index, persona_index, : len(persona_vector)] = torch.tensor(persona_vector, dtype=torch.float32)
                persona_mask[batch_index, persona_index] = True
                persona_ids[batch_index][persona_index] = persona_id

                encoded_persona = self.tokenizer.encode(example.persona_texts[persona_index], max_length=self.max_text_length)
                persona_text_ids[batch_index, persona_index] = torch.tensor(encoded_persona.input_ids, dtype=torch.long)
                persona_text_mask[batch_index, persona_index] = torch.tensor(encoded_persona.attention_mask, dtype=torch.long)

        return TinyPolicyBatch(
            page_features=page_features,
            candidate_features=candidate_features,
            candidate_mask=candidate_mask,
            candidate_text_ids=candidate_text_ids,
            candidate_text_mask=candidate_text_mask,
            candidate_prompt_ids=candidate_prompt_ids,
            candidate_prompt_mask=candidate_prompt_mask,
            candidate_ocr_ids=candidate_ocr_ids,
            candidate_ocr_mask=candidate_ocr_mask,
            persona_features=persona_features,
            persona_mask=persona_mask,
            persona_text_ids=persona_text_ids,
            persona_text_mask=persona_text_mask,
            candidate_ids=candidate_ids,
            persona_ids=persona_ids,
        )

    def _attach_supervised_targets(
        self,
        *,
        base_batch: TinyPolicyBatch,
        labels: list[SupervisedTurnLabels],
    ) -> SupervisedTinyPolicyBatch:
        """把层级监督标签附着到训练 batch。"""
        if len(labels) != len(base_batch.candidate_ids):
            raise ValueError("labels 数量必须与 batch examples 数量一致。")

        batch_size = len(base_batch.candidate_ids)
        max_candidates = len(base_batch.candidate_ids[0]) if base_batch.candidate_ids else 1

        target_protect_labels = torch.full((batch_size, max_candidates), IGNORE_INDEX, dtype=torch.long)
        target_rewrite_modes = torch.full((batch_size, max_candidates), IGNORE_INDEX, dtype=torch.long)
        final_action_targets = torch.full((batch_size, max_candidates), IGNORE_INDEX, dtype=torch.long)
        target_persona_indices = torch.full((batch_size,), IGNORE_INDEX, dtype=torch.long)

        for batch_index, label in enumerate(labels):
            candidate_lookup = {
                candidate_id: candidate_index
                for candidate_index, candidate_id in enumerate(base_batch.candidate_ids[batch_index])
                if candidate_id
            }
            persona_lookup = {
                persona_id: persona_index
                for persona_index, persona_id in enumerate(base_batch.persona_ids[batch_index])
                if persona_id
            }

            if label.target_persona_id:
                persona_index = persona_lookup.get(label.target_persona_id)
                if persona_index is None:
                    raise ValueError(
                        f"target_persona_id 未出现在 batch 中: {label.target_persona_id}"
                    )
                target_persona_indices[batch_index] = persona_index

            labeled_candidate_ids = (
                set(label.final_actions)
                | set(label.target_protect_labels)
                | set(label.target_rewrite_modes)
            )
            missing_candidate_ids = sorted(candidate_id for candidate_id in labeled_candidate_ids if candidate_id not in candidate_lookup)
            if missing_candidate_ids:
                raise ValueError(
                    f"以下 candidate label 未出现在 batch 中: {missing_candidate_ids}"
                )

            for candidate_id, candidate_index in candidate_lookup.items():
                if (
                    candidate_id not in label.final_actions
                    and candidate_id not in label.target_protect_labels
                    and candidate_id not in label.target_rewrite_modes
                ):
                    continue
                if candidate_id in label.final_actions:
                    final_action = normalize_action_type(label.final_actions[candidate_id])
                else:
                    final_action = hierarchical_labels_to_action(
                        label.target_protect_labels.get(candidate_id),
                        label.target_rewrite_modes.get(candidate_id),
                    )
                protect_label = str(label.target_protect_labels.get(candidate_id, "KEEP")).strip().upper()
                rewrite_mode = normalize_rewrite_mode(label.target_rewrite_modes.get(candidate_id)) or REWRITE_MODE_NONE

                target_protect_labels[batch_index, candidate_index] = PROTECT_ORDER.index(protect_label)
                final_action_targets[batch_index, candidate_index] = ACTION_ORDER.index(final_action)

                if protect_label == PROTECT_LABEL_REWRITE and rewrite_mode != REWRITE_MODE_NONE:
                    target_rewrite_modes[batch_index, candidate_index] = REWRITE_MODE_ORDER.index(rewrite_mode)

        return SupervisedTinyPolicyBatch(
            page_features=base_batch.page_features,
            candidate_features=base_batch.candidate_features,
            candidate_mask=base_batch.candidate_mask,
            candidate_text_ids=base_batch.candidate_text_ids,
            candidate_text_mask=base_batch.candidate_text_mask,
            candidate_prompt_ids=base_batch.candidate_prompt_ids,
            candidate_prompt_mask=base_batch.candidate_prompt_mask,
            candidate_ocr_ids=base_batch.candidate_ocr_ids,
            candidate_ocr_mask=base_batch.candidate_ocr_mask,
            persona_features=base_batch.persona_features,
            persona_mask=base_batch.persona_mask,
            persona_text_ids=base_batch.persona_text_ids,
            persona_text_mask=base_batch.persona_text_mask,
            candidate_ids=base_batch.candidate_ids,
            persona_ids=base_batch.persona_ids,
            target_protect_labels=target_protect_labels,
            target_rewrite_modes=target_rewrite_modes,
            target_persona_indices=target_persona_indices,
            final_action_targets=final_action_targets,
        )

    def _candidate_text(self, context: DecisionContext, candidate_id: str) -> str:
        candidate = derived_candidate_by_id(context).get(candidate_id)
        if candidate is not None:
            return str(getattr(candidate, "text", "") or "")
        for candidate in context.candidates:
            if candidate.entity_id == candidate_id:
                return candidate.text
        return ""

    def _persona_text(self, context: DecisionContext, state: dict[str, object]) -> str:
        display_name = str(state.get("_display_name", "") or "")
        slots = state.get("_slots", {})
        if not isinstance(slots, dict):
            slots = {}
        slot_text = " ".join(str(value) for value in slots.values())
        if not display_name:
            persona_id = str(state.get("persona_id", "")).strip()
            for persona in context.persona_profiles:
                if persona.persona_id == persona_id:
                    display_name = persona.display_name
                    slot_text = " ".join(str(value) for value in persona.slots.values())
                    break
        return f"{display_name} {slot_text}".strip()

    def _validate_capacity(self, *, candidate_count: int, persona_count: int, subject: str) -> None:
        if candidate_count > self.max_candidates:
            raise ValueError(
                f"{subject} 的 candidate 数量 {candidate_count} 超过 max_candidates={self.max_candidates}"
            )
        if persona_count > self.max_personas:
            raise ValueError(
                f"{subject} 的 persona 数量 {persona_count} 超过 max_personas={self.max_personas}"
            )

