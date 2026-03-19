"""PyTorch 训练 batch 构造工具。"""

from __future__ import annotations

from dataclasses import dataclass, field

import torch

from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.features import (
    CANDIDATE_FEATURE_DIM,
    PAGE_FEATURE_DIM,
    PERSONA_FEATURE_DIM,
    DecisionFeatureExtractor,
)
from privacyguard.infrastructure.decision.tiny_policy_net import TinyPolicyBatch
from privacyguard.infrastructure.decision.tokenizer import CharacterHashTokenizer
from training.types import TrainingTurnExample


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
        max_candidates = max(1, min(self.max_candidates, max(len(context.candidate_features) for context in contexts)))
        max_personas = max(1, min(self.max_personas, max(len(context.persona_features) for context in contexts)))

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
            packed = self.feature_extractor.pack(context)
            page_features[batch_index, : len(packed.page_vector)] = torch.tensor(packed.page_vector, dtype=torch.float32)

            for candidate_index, feature in enumerate(context.candidate_features[:max_candidates]):
                candidate_vector = packed.candidate_vectors[candidate_index]
                candidate_features[batch_index, candidate_index, : len(candidate_vector)] = torch.tensor(candidate_vector, dtype=torch.float32)
                candidate_mask[batch_index, candidate_index] = True
                candidate_ids[batch_index][candidate_index] = feature.candidate_id

                encoded_text = self.tokenizer.encode(feature.text, max_length=self.max_text_length)
                encoded_prompt = self.tokenizer.encode(feature.prompt_context, max_length=self.max_text_length)
                encoded_ocr = self.tokenizer.encode(feature.ocr_context, max_length=self.max_text_length)
                candidate_text_ids[batch_index, candidate_index] = torch.tensor(encoded_text.input_ids, dtype=torch.long)
                candidate_text_mask[batch_index, candidate_index] = torch.tensor(encoded_text.attention_mask, dtype=torch.long)
                candidate_prompt_ids[batch_index, candidate_index] = torch.tensor(encoded_prompt.input_ids, dtype=torch.long)
                candidate_prompt_mask[batch_index, candidate_index] = torch.tensor(encoded_prompt.attention_mask, dtype=torch.long)
                candidate_ocr_ids[batch_index, candidate_index] = torch.tensor(encoded_ocr.input_ids, dtype=torch.long)
                candidate_ocr_mask[batch_index, candidate_index] = torch.tensor(encoded_ocr.attention_mask, dtype=torch.long)

            for persona_index, feature in enumerate(context.persona_features[:max_personas]):
                persona_vector = packed.persona_vectors[persona_index]
                persona_features[batch_index, persona_index, : len(persona_vector)] = torch.tensor(persona_vector, dtype=torch.float32)
                persona_mask[batch_index, persona_index] = True
                persona_ids[batch_index][persona_index] = feature.persona_id

                encoded_persona = self.tokenizer.encode(self._persona_text(feature), max_length=self.max_text_length)
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
        if not examples:
            raise ValueError("examples 不能为空。")
        batch_size = len(examples)
        max_candidates = max(1, min(self.max_candidates, max(len(example.candidate_ids) for example in examples)))
        max_personas = max(1, min(self.max_personas, max(len(example.persona_ids) for example in examples)))

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

    def _persona_text(self, feature) -> str:
        slot_text = " ".join(str(value) for _key, value in sorted(feature.slots.items(), key=lambda item: item[0].value))
        return f"{feature.display_name} {slot_text}".strip()
