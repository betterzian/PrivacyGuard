"""训练数据集构建入口骨架。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from privacyguard.domain.models.decision_context import DecisionModelContext
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor
from training.runtime_bridge import pack_training_turn


def build_jsonl_dataset(
    contexts: Iterable[DecisionModelContext],
    output_path: str | Path,
    extractor: DecisionFeatureExtractor | None = None,
) -> Path:
    """把上下文样本导出为简单 JSONL，便于训练侧继续处理。"""
    feature_extractor = extractor or DecisionFeatureExtractor()
    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as handle:
        for context in contexts:
            example, _packed = pack_training_turn(context, extractor=feature_extractor)
            handle.write(
                json.dumps(
                    {
                        "session_id": example.session_id,
                        "turn_id": example.turn_id,
                        "prompt_text": example.prompt_text,
                        "ocr_texts": example.ocr_texts,
                        "candidate_ids": example.candidate_ids,
                        "candidate_attr_types": [item.value for item in example.candidate_attr_types],
                        "active_persona_id": example.active_persona_id,
                        "page_vector": example.page_vector,
                        "candidate_vectors": example.candidate_vectors,
                        "persona_vectors": example.persona_vectors,
                        "metadata": example.metadata,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return target_path
