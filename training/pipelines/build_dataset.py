"""训练数据集构建入口骨架。

导出边界保持收敛：

- 保留旧 `labels.candidate_actions`，兼容当前读取链路
- 增加层级标签导出：
  - `target_protect_label`
  - `target_rewrite_mode`
  - `target_persona_id`
  - `final_action`
- 增加策略上下文导出：
  - `candidate_policy_view`
  - `page_policy_state`
  - `persona_policy_states`

说明：

- 不新增 EntityTruth 等独立大对象
- 若上游仍只提供旧式平面 action，这里在导出阶段做兼容拆解
- JSONL 继续保持“旧字段可读 + 新字段可训练”的双轨格式
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Iterable

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.features import DecisionFeatureExtractor
from training.runtime_bridge import pack_training_turn, plan_to_supervision
from training.types import (
    SupervisedTurnLabels,
    action_to_hierarchical_labels,
    normalize_action_type,
)


def build_jsonl_dataset(
    contexts: Iterable[DecisionContext],
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
                json.dumps(_example_payload(example, context=context), ensure_ascii=False) + "\n"
            )
    return target_path


def build_supervised_jsonl_dataset(
    samples: Iterable[tuple[DecisionContext, DecisionPlan]],
    output_path: str | Path,
    extractor: DecisionFeatureExtractor | None = None,
) -> Path:
    """把上下文与目标 plan 导出为带 supervision 的 JSONL。"""
    feature_extractor = extractor or DecisionFeatureExtractor()
    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as handle:
        for context, plan in samples:
            example, _packed = pack_training_turn(context, extractor=feature_extractor)
            labels = plan_to_supervision(plan)
            payload = _example_payload(example, context=context)
            payload["labels"] = _labels_payload(labels)
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return target_path


def _example_payload(example, *, context: DecisionContext) -> dict[str, object]:
    """构造训练样本 payload。

    关键新增字段：

    - `candidate_policy_view`:
      以 `candidate_id -> policy_view` 的形式导出，便于训练侧直接按 candidate 对齐
    - `page_policy_state`:
      页面级策略状态
    - `persona_policy_states`:
      persona 级策略状态列表
    """
    return {
        "session_id": example.session_id,
        "turn_id": example.turn_id,
        "prompt_text": example.prompt_text,
        "ocr_texts": example.ocr_texts,
        "candidate_ids": example.candidate_ids,
        "candidate_texts": example.candidate_texts,
        "candidate_prompt_contexts": example.candidate_prompt_contexts,
        "candidate_ocr_contexts": example.candidate_ocr_contexts,
        "candidate_attr_types": [item.value for item in example.candidate_attr_types],
        "persona_ids": example.persona_ids,
        "persona_texts": example.persona_texts,
        "active_persona_id": example.active_persona_id,
        "page_vector": example.page_vector,
        "candidate_vectors": example.candidate_vectors,
        "persona_vectors": example.persona_vectors,
        "candidate_policy_view": _candidate_policy_view_payload(context),
        "page_policy_state": _page_policy_state_payload(context),
        "persona_policy_states": _persona_policy_states_payload(context),
        "metadata": example.metadata,
    }


def _labels_payload(labels: SupervisedTurnLabels) -> dict[str, object]:
    """构造监督标签 payload。

    关键新增字段：

    - `target_protect_label`: candidate 级 `KEEP / REWRITE`
    - `target_rewrite_mode`: candidate 级 `GENERICIZE / PERSONA_SLOT / NONE`
    - `final_action`: candidate 级最终动作

    同时保留：

    - `candidate_actions`: 旧平面动作标签，兼容当前 supervised finetune 读取链路
    """
    final_actions = _final_action_payload(labels)
    target_protect_labels, target_rewrite_modes = _hierarchical_label_payloads(labels, final_actions)
    return {
        "target_persona_id": labels.target_persona_id,
        "target_protect_label": target_protect_labels,
        "target_rewrite_mode": target_rewrite_modes,
        "final_action": final_actions,
        "candidate_actions": dict(final_actions),
        "metadata": labels.metadata,
    }


def _candidate_policy_view_payload(context: DecisionContext) -> dict[str, dict[str, object]]:
    views = getattr(context, "candidate_policy_views", None)
    if isinstance(views, list) and views:
        payload: dict[str, dict[str, object]] = {}
        for view in views:
            if not isinstance(view, dict):
                continue
            candidate_id = str(view.get("candidate_id", "")).strip()
            if not candidate_id:
                continue
            payload[candidate_id] = _json_ready(view)
        if payload:
            return payload

    # 兼容旧上下文：当尚未切到 `candidate_policy_views` 时，导出可读的简化策略视图。
    fallback: dict[str, dict[str, object]] = {}
    for feature in getattr(context, "candidate_features", []):
        fallback[feature.candidate_id] = {
            "candidate_id": feature.candidate_id,
            "attr_type": _json_ready(feature.attr_type),
            "source": _json_ready(feature.source),
            "det_conf_bucket": _bucket_confidence(float(getattr(feature, "confidence", 0.0) or 0.0)),
            "ocr_local_conf_bucket": _bucket_confidence(float(getattr(feature, "ocr_block_score", 0.0) or 0.0)),
            "low_ocr_flag": bool(getattr(feature, "is_low_ocr_confidence", False)),
            "history_exact_match_bucket": _bucket_count(int(getattr(feature, "history_exact_match_count", 0) or 0)),
            "same_attr_page_bucket": _bucket_count(int(getattr(feature, "same_attr_page_count", 0) or 0)),
            "prompt_local_context_labelized": getattr(feature, "prompt_context", ""),
            "ocr_local_context_labelized": getattr(feature, "ocr_context", ""),
        }
    return fallback


def _page_policy_state_payload(context: DecisionContext) -> dict[str, object]:
    state = getattr(context, "page_policy_state", None)
    if isinstance(state, dict) and state:
        return _json_ready(state)

    feature = getattr(context, "page_features", None)
    if feature is None:
        return {
            "protection_level": _json_ready(getattr(context, "protection_level", "")),
        }
    return {
        "protection_level": _json_ready(getattr(context, "protection_level", "")),
        "candidate_count_bucket": _bucket_count(int(getattr(feature, "candidate_count", 0) or 0)),
        "unique_attr_count_bucket": _bucket_count(int(getattr(feature, "unique_attr_count", 0) or 0)),
        "avg_det_conf_bucket": _bucket_confidence(float(getattr(feature, "average_candidate_confidence", 0.0) or 0.0)),
        "min_det_conf_bucket": _bucket_confidence(float(getattr(feature, "min_candidate_confidence", 0.0) or 0.0)),
        "avg_ocr_conf_bucket": _bucket_confidence(float(getattr(feature, "average_ocr_block_score", 0.0) or 0.0)),
        "low_ocr_ratio_bucket": _bucket_ratio(float(getattr(feature, "low_confidence_ocr_block_ratio", 0.0) or 0.0)),
        "page_quality_state": _legacy_page_quality_state(feature),
    }


def _persona_policy_states_payload(context: DecisionContext) -> list[dict[str, object]]:
    states = getattr(context, "persona_policy_states", None)
    if isinstance(states, list) and states:
        return _json_ready(states)

    fallback: list[dict[str, object]] = []
    for feature in getattr(context, "persona_features", []):
        supported_attr_mask = {str(item.value): True for item in getattr(feature, "supported_attr_types", [])}
        available_slot_mask = {
            str(attr.value): bool(str(value).strip())
            for attr, value in (getattr(feature, "slots", {}) or {}).items()
        }
        fallback.append(
            {
                "persona_id": feature.persona_id,
                "is_active": bool(getattr(feature, "is_active", False)),
                "supported_attr_mask": supported_attr_mask,
                "available_slot_mask": available_slot_mask,
                "attr_exposure_buckets": {
                    attr_name: _bucket_count(int(getattr(feature, "exposure_count", 0) or 0))
                    for attr_name in set(supported_attr_mask) | set(available_slot_mask)
                },
                "matched_candidate_attr_count": int(getattr(feature, "matched_candidate_attr_count", 0) or 0),
            }
        )
    return fallback


def _final_action_payload(labels: SupervisedTurnLabels) -> dict[str, str]:
    final_actions = dict(labels.final_actions) if labels.final_actions else dict(labels.candidate_actions)
    payload: dict[str, str] = {}
    for candidate_id, action in final_actions.items():
        payload[str(candidate_id)] = normalize_action_type(action).value
    return payload


def _hierarchical_label_payloads(
    labels: SupervisedTurnLabels,
    final_actions: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    protect_payload: dict[str, str] = {}
    rewrite_payload: dict[str, str] = {}

    for candidate_id, action_name in final_actions.items():
        protect_label = str(labels.target_protect_labels.get(candidate_id, "")).strip().upper()
        rewrite_mode = str(labels.target_rewrite_modes.get(candidate_id, "")).strip().upper()
        if not protect_label or not rewrite_mode:
            derived_protect, derived_rewrite = action_to_hierarchical_labels(action_name)
            protect_label = protect_label or derived_protect
            rewrite_mode = rewrite_mode or derived_rewrite
        protect_payload[candidate_id] = protect_label
        rewrite_payload[candidate_id] = rewrite_mode

    return (protect_payload, rewrite_payload)


def _json_ready(value):
    """把 Enum / Pydantic model / 嵌套容器收敛为 JSON 可序列化对象。"""
    if hasattr(value, "model_dump"):
        return _json_ready(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _bucket_count(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 7:
        return "4-7"
    return "8+"


def _bucket_confidence(value: float) -> str:
    if value <= 0.0:
        return "none"
    if value < 0.5:
        return "low"
    if value < 0.85:
        return "medium"
    return "high"


def _bucket_ratio(value: float) -> str:
    if value <= 0.0:
        return "none"
    if value < 0.34:
        return "low"
    if value < 0.67:
        return "medium"
    return "high"


def _legacy_page_quality_state(feature) -> str:
    avg_det_conf = float(getattr(feature, "average_candidate_confidence", 0.0) or 0.0)
    avg_ocr_conf = float(getattr(feature, "average_ocr_block_score", 0.0) or 0.0)
    low_ocr_ratio = float(getattr(feature, "low_confidence_ocr_block_ratio", 0.0) or 0.0)
    has_ocr = int(getattr(feature, "ocr_block_count", 0) or 0) > 0
    if avg_det_conf < 0.5:
        return "poor"
    if has_ocr and (avg_ocr_conf < 0.75 or low_ocr_ratio > 0.5):
        return "poor"
    if avg_det_conf >= 0.85 and (not has_ocr or avg_ocr_conf >= 0.85):
        return "good"
    return "mixed"
