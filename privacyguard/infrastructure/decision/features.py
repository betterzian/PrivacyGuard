"""de_model 特征提取与张量打包骨架。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.models.decision_context import DecisionModelContext


@dataclass(slots=True)
class PackedDecisionFeatures:
    """供运行时使用的定长数值特征。"""

    page_vector: list[float]
    candidate_ids: list[str]
    candidate_vectors: list[list[float]]
    persona_ids: list[str]
    persona_vectors: list[list[float]]


class DecisionFeatureExtractor:
    """将 DecisionModelContext 压缩为轻量数值特征。"""

    def pack(self, context: DecisionModelContext) -> PackedDecisionFeatures:
        page_vector = self._page_vector(context)
        candidate_ids: list[str] = []
        candidate_vectors: list[list[float]] = []
        for item in context.candidate_features:
            candidate_ids.append(item.candidate_id)
            candidate_vectors.append(self._candidate_vector(item))
        persona_ids: list[str] = []
        persona_vectors: list[list[float]] = []
        for item in context.persona_features:
            persona_ids.append(item.persona_id)
            persona_vectors.append(self._persona_vector(item))
        return PackedDecisionFeatures(
            page_vector=page_vector,
            candidate_ids=candidate_ids,
            candidate_vectors=candidate_vectors,
            persona_ids=persona_ids,
            persona_vectors=persona_vectors,
        )

    def _page_vector(self, context: DecisionModelContext) -> list[float]:
        item = context.page_features
        return [
            min(1.0, item.prompt_length / 256.0),
            min(1.0, item.ocr_block_count / 64.0),
            min(1.0, item.candidate_count / 32.0),
            min(1.0, item.unique_attr_count / 8.0),
            min(1.0, item.history_record_count / 64.0),
            1.0 if item.active_persona_bound else 0.0,
            1.0 if item.prompt_has_digits else 0.0,
            1.0 if item.prompt_has_address_tokens else 0.0,
            item.average_candidate_confidence,
        ]

    def _candidate_vector(self, item) -> list[float]:
        attr_one_hot = self._attr_one_hot(item.attr_type.value)
        source_one_hot = [1.0, 0.0] if item.is_prompt_source else [0.0, 1.0 if item.is_ocr_source else 0.0]
        text_stats = self._text_signature(item.text)
        prompt_stats = self._text_signature(item.prompt_context)
        ocr_stats = self._text_signature(item.ocr_context)
        return [
            *attr_one_hot,
            *source_one_hot,
            item.confidence,
            min(1.0, item.history_attr_exposure_count / 16.0),
            min(1.0, item.history_exact_match_count / 8.0),
            min(1.0, item.same_attr_page_count / 8.0),
            min(1.0, item.same_text_page_count / 8.0),
            item.relative_area,
            min(1.0, item.aspect_ratio / 6.0),
            item.center_x,
            item.center_y,
            *text_stats,
            *prompt_stats,
            *ocr_stats,
        ]

    def _persona_vector(self, item) -> list[float]:
        attr_coverage = self._attr_one_hot(*(attr.value for attr in item.supported_attr_types))
        display_stats = self._text_signature(item.display_name)
        slot_stats = self._text_signature(" ".join(item.slots.values()))
        return [
            min(1.0, item.slot_count / 8.0),
            min(1.0, item.exposure_count / 32.0),
            1.0 if item.is_active else 0.0,
            min(1.0, item.matched_candidate_attr_count / 8.0),
            *attr_coverage,
            *display_stats,
            *slot_stats,
        ]

    def _attr_one_hot(self, *names: str) -> list[float]:
        order = ["name", "phone", "email", "address", "id_number", "organization", "other"]
        values = set(names)
        return [1.0 if name in values else 0.0 for name in order]

    def _text_signature(self, text: str) -> list[float]:
        if not text:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        total = max(1, len(text))
        digit_count = sum(char.isdigit() for char in text)
        ascii_count = sum(char.isascii() for char in text)
        alpha_count = sum(char.isalpha() for char in text)
        punctuation_count = sum(not char.isalnum() and not self._is_cjk(char) for char in text)
        cjk_count = sum(self._is_cjk(char) for char in text)
        return [
            min(1.0, total / 32.0),
            digit_count / total,
            ascii_count / total,
            alpha_count / total,
            max(punctuation_count, cjk_count) / total,
        ]

    def _is_cjk(self, char: str) -> bool:
        code = ord(char)
        return 0x4E00 <= code <= 0x9FFF
