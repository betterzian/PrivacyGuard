"""de_model 特征提取与张量打包。

本模块已对齐当前 `DecisionContext -> policy_context` 的组织方式：

- `candidate_policy_views -> candidate dense features`
- `page_policy_state -> page features`
- `persona_policy_states -> persona features`

当前仅读取从 `DecisionContext` 内部派生出的策略视图结构：

- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

注意：

- 文本通道只保留为辅助信号；dense vector 中仅编码轻量 text signature
- 真正的文本序列仍由上游/训练侧按现有链路消费
- 本模块不做策略推理
"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.policy_context import (
    DerivedDecisionPolicyContext,
    candidate_by_id as derived_candidate_by_id,
    derive_policy_context,
    persona_by_id as derived_persona_by_id,
)

PAGE_FEATURE_NAMES: tuple[str, ...] = (
    "prompt_length",
    "ocr_block_count",
    "candidate_count",
    "unique_attr_count",
    "history_record_count",
    "active_persona_bound",
    "prompt_has_digits",
    "prompt_has_address_tokens",
    "average_candidate_confidence",
    "min_candidate_confidence",
    "high_confidence_candidate_ratio",
    "low_confidence_candidate_ratio",
    "prompt_candidate_count",
    "ocr_candidate_count",
    "average_ocr_block_score",
    "min_ocr_block_score",
    "low_confidence_ocr_block_ratio",
    "protection_level_weak",
    "protection_level_balanced",
    "protection_level_strong",
)
ATTR_FEATURE_ORDER: tuple[str, ...] = tuple(attr.value for attr in PIIAttributeType)
SOURCE_FEATURE_ORDER: tuple[str, ...] = ("prompt", "ocr")
PROTECTION_LEVEL_ORDER: tuple[str, ...] = tuple(level.value for level in ProtectionLevel)
TEXT_SIGNATURE_DIM = 5
PAGE_FEATURE_DIM = len(PAGE_FEATURE_NAMES)
ATTR_ONE_HOT_DIM = len(ATTR_FEATURE_ORDER)
SOURCE_ONE_HOT_DIM = len(SOURCE_FEATURE_ORDER)
# 维度保持兼容，避免影响当前 TinyPolicyNet / runtime / 训练 batch。
CANDIDATE_FEATURE_DIM = ATTR_ONE_HOT_DIM + SOURCE_ONE_HOT_DIM + 1 + 4 + 4 + 3 + TEXT_SIGNATURE_DIM * 3
PERSONA_FEATURE_DIM = 4 + ATTR_ONE_HOT_DIM + TEXT_SIGNATURE_DIM * 2

_ADDRESS_HINT_TOKENS = ("省", "市", "区", "县", "路", "街", "道", "号", "小区", "公寓")
_LOW_CANDIDATE_CONFIDENCE = 0.5
_HIGH_CANDIDATE_CONFIDENCE = 0.85
_LOW_OCR_BLOCK_SCORE = 0.75
_MASK_CHARS = set("*＊xX×#＃•●○◦◯_＿?？")


@dataclass(slots=True)
class PackedDecisionFeatures:
    """供运行时使用的定长数值特征。"""

    page_vector: list[float]
    candidate_ids: list[str]
    candidate_vectors: list[list[float]]
    persona_ids: list[str]
    persona_vectors: list[list[float]]


def pack_decision_features(
    context: DecisionContext,
    *,
    policy: DerivedDecisionPolicyContext | None = None,
) -> PackedDecisionFeatures:
    """把上下文打包为当前 runtime 可消费的定长特征。

    优先从 `DecisionContext` 派生策略视图；若上下文已预构建同名字段则兼容读取。
    """
    resolved_policy = policy or derive_policy_context(context)
    page_vector = build_page_features(context, policy=resolved_policy)
    text_inputs = build_text_inputs(context, policy=resolved_policy)

    candidate_ids: list[str] = []
    candidate_vectors: list[list[float]] = []
    for candidate_policy_view in resolved_policy.candidate_policy_views:
        candidate_id = str(candidate_policy_view.get("candidate_id", "")).strip()
        if not candidate_id:
            continue
        candidate_ids.append(candidate_id)
        candidate_vectors.append(
            build_candidate_dense_features(
                context=context,
                candidate_policy_view=candidate_policy_view,
                text_inputs=text_inputs,
            )
        )

    persona_ids: list[str] = []
    persona_vectors: list[list[float]] = []
    for persona_policy_state in resolved_policy.persona_policy_states:
        persona_id = str(persona_policy_state.get("persona_id", "")).strip()
        if not persona_id:
            continue
        persona_ids.append(persona_id)
        persona_vectors.append(
            build_persona_features(
                context=context,
                persona_policy_state=persona_policy_state,
                text_inputs=text_inputs,
            )
        )

    return PackedDecisionFeatures(
        page_vector=page_vector,
        candidate_ids=candidate_ids,
        candidate_vectors=candidate_vectors,
        persona_ids=persona_ids,
        persona_vectors=persona_vectors,
    )


def build_page_features(
    context: DecisionContext,
    *,
    policy: DerivedDecisionPolicyContext | None = None,
) -> list[float]:
    """从 `page_policy_state` 构造 page vector。

    向量布局保持兼容旧模型，但取值来源优先来自新页面状态。

    页面向量中的 protection one-hot 继续保持在尾部，避免影响 runtime / TinyPolicyNet。
    """
    resolved_policy = policy or derive_policy_context(context)
    state = resolved_policy.page_policy_state
    candidate_views = resolved_policy.candidate_policy_views
    prompt_text = getattr(context, "prompt_text", "") or ""
    ocr_blocks = list(getattr(context, "ocr_blocks", []) or [])

    protection_level = str(
        state.get("protection_level")
        or getattr(getattr(context, "protection_level", None), "value", getattr(context, "protection_level", ""))
    ).strip().lower()

    prompt_length = _safe_float(state.get("_prompt_length"), len(prompt_text))
    ocr_block_count = _safe_float(state.get("_ocr_block_count"), len(ocr_blocks))
    candidate_count = _safe_float(state.get("_candidate_count"), len(candidate_views))
    unique_attr_count = _safe_float(
        state.get("_unique_attr_count"),
        len({str(view.get("attr_id") or _attr_name(view)) for view in candidate_views if (view.get("attr_id") or _attr_name(view))}),
    )
    history_record_count = _safe_float(state.get("_history_record_count"), len(getattr(context, "history_records", []) or []))
    active_persona_bound = _safe_bool(
        state.get("_active_persona_bound"),
        bool(getattr(getattr(context, "session_binding", None), "active_persona_id", None)),
    )
    prompt_has_digits = _safe_bool(state.get("_prompt_has_digits"), any(char.isdigit() for char in prompt_text))
    prompt_has_address_tokens = _safe_bool(
        state.get("_prompt_has_address_tokens"),
        any(token in prompt_text for token in _ADDRESS_HINT_TOKENS),
    )

    average_candidate_confidence = _safe_float(
        state.get("_average_candidate_confidence"),
        _average(
            [_confidence_from_candidate_view(view) for view in candidate_views],
            default=_confidence_from_bucket(state.get("avg_det_conf_bucket")),
        ),
    )
    min_candidate_confidence = _safe_float(
        state.get("_min_candidate_confidence"),
        _minimum(
            [_confidence_from_candidate_view(view) for view in candidate_views],
            default=_confidence_from_bucket(state.get("min_det_conf_bucket")),
        ),
    )
    high_confidence_candidate_ratio = _safe_float(
        state.get("_high_confidence_candidate_ratio"),
        _ratio_of(
            candidate_views,
            lambda view: str(view.get("det_conf_bucket", "")).strip().lower() == "high",
        ),
    )
    low_confidence_candidate_ratio = _safe_float(
        state.get("_low_confidence_candidate_ratio"),
        _ratio_of(
            candidate_views,
            lambda view: str(view.get("det_conf_bucket", "")).strip().lower() in {"low", "none"},
        ),
    )
    prompt_candidate_count = _safe_float(
        state.get("_prompt_candidate_count"),
        sum(1 for view in candidate_views if _source_name(view) == PIISourceType.PROMPT.value),
    )
    ocr_candidate_count = _safe_float(
        state.get("_ocr_candidate_count"),
        sum(1 for view in candidate_views if _source_name(view) == PIISourceType.OCR.value),
    )
    average_ocr_block_score = _safe_float(
        state.get("_average_ocr_block_score"),
        _average(
            [float(getattr(block, "score", 0.0) or 0.0) for block in ocr_blocks],
            default=_confidence_from_bucket(state.get("avg_ocr_conf_bucket")),
        ),
    )
    min_ocr_block_score = _safe_float(
        state.get("_min_ocr_block_score"),
        _minimum(
            [float(getattr(block, "score", 0.0) or 0.0) for block in ocr_blocks],
            default=_confidence_from_bucket(state.get("min_ocr_conf_bucket")),
        ),
    )
    low_confidence_ocr_block_ratio = _safe_float(
        state.get("_low_confidence_ocr_block_ratio"),
        _ratio_of(
            ocr_blocks,
            lambda block: float(getattr(block, "score", 0.0) or 0.0) < _LOW_OCR_BLOCK_SCORE,
            default=_ratio_from_bucket(state.get("low_ocr_ratio_bucket")),
        ),
    )

    return [
        min(1.0, prompt_length / 256.0),
        min(1.0, ocr_block_count / 64.0),
        min(1.0, candidate_count / 32.0),
        min(1.0, unique_attr_count / 8.0),
        min(1.0, history_record_count / 64.0),
        1.0 if active_persona_bound else 0.0,
        1.0 if prompt_has_digits else 0.0,
        1.0 if prompt_has_address_tokens else 0.0,
        average_candidate_confidence,
        min_candidate_confidence,
        high_confidence_candidate_ratio,
        low_confidence_candidate_ratio,
        min(1.0, prompt_candidate_count / 32.0),
        min(1.0, ocr_candidate_count / 32.0),
        average_ocr_block_score,
        min_ocr_block_score,
        low_confidence_ocr_block_ratio,
        *_one_hot(protection_level, ordered_values=PROTECTION_LEVEL_ORDER),
    ]


def build_candidate_dense_features(
    *,
    context: DecisionContext,
    candidate_policy_view: dict[str, object],
    text_inputs: dict[str, dict[str, dict[str, str]]],
) -> list[float]:
    """从 `candidate_policy_views` 构造 candidate dense feature。

    结构化信号是主通道；文本只编码为轻量 signature，避免压过 alias/history/quality。

    映射顺序仍沿用旧 candidate vector 版式：

    - attr/source/confidence
    - history / page-level count
    - geometry / OCR quality
    - candidate_text / prompt_context / ocr_context 的轻量 text signature
    """
    candidate_id = str(candidate_policy_view.get("candidate_id", "")).strip()
    candidate_by_id = _candidate_by_id(context)
    candidate = candidate_by_id.get(candidate_id)

    attr_name = str(candidate_policy_view.get("attr_id") or _attr_name(candidate_policy_view) or _candidate_attr_name(candidate)).strip()
    source_name = str(_source_name(candidate_policy_view) or _candidate_source_name(candidate)).strip().lower()

    candidate_text_inputs = text_inputs["candidates"].get(candidate_id, {})
    candidate_text = candidate_text_inputs.get("candidate_text", "")
    prompt_context = candidate_text_inputs.get("prompt_context", "")
    ocr_context = candidate_text_inputs.get("ocr_context", "")

    confidence = _safe_float(
        candidate_policy_view.get("_confidence"),
        float(getattr(candidate, "confidence", 0.0) if candidate is not None else _confidence_from_bucket(candidate_policy_view.get("det_conf_bucket"))),
    )
    history_attr_exposure_count = _safe_float(
        candidate_policy_view.get("_history_attr_exposure_count"),
        max(
            _count_from_bucket(candidate_policy_view.get("history_alias_exposure_bucket")),
            _safe_float(candidate_policy_view.get("_history_alias_exposure_count"), 0.0),
        ),
    )
    history_exact_match_count = _safe_float(
        candidate_policy_view.get("_history_exact_match_count"),
        _count_from_bucket(candidate_policy_view.get("history_exact_match_bucket")),
    )
    same_attr_page_count = _safe_float(
        candidate_policy_view.get("_same_attr_page_count"),
        _count_from_bucket(candidate_policy_view.get("same_attr_page_bucket")),
    )
    same_text_page_or_alias_count = max(
        _safe_float(candidate_policy_view.get("_same_text_page_count"), 0.0),
        _safe_float(candidate_policy_view.get("same_alias_count_in_turn"), 0.0),
    )

    relative_area, aspect_ratio, center_x, center_y = _geometry_features(
        context=context,
        candidate_id=candidate_id,
        candidate_policy_view=candidate_policy_view,
    )
    ocr_block_score = _safe_float(
        candidate_policy_view.get("_ocr_block_score"),
        _confidence_from_bucket(candidate_policy_view.get("ocr_local_conf_bucket")),
    )
    ocr_block_rotation_degrees = _safe_float(candidate_policy_view.get("_ocr_block_rotation_degrees"), 0.0)
    low_ocr_flag = bool(candidate_policy_view.get("low_ocr_flag", False))

    return [
        *_attr_one_hot(attr_name),
        *_source_one_hot(source_name),
        confidence,
        min(1.0, history_attr_exposure_count / 16.0),
        min(1.0, history_exact_match_count / 8.0),
        min(1.0, same_attr_page_count / 8.0),
        min(1.0, same_text_page_or_alias_count / 8.0),
        relative_area,
        min(1.0, aspect_ratio / 6.0),
        center_x,
        center_y,
        ocr_block_score,
        min(1.0, abs(ocr_block_rotation_degrees) / 180.0),
        1.0 if low_ocr_flag else 0.0,
        *_text_signature(candidate_text),
        *_text_signature(prompt_context),
        *_text_signature(ocr_context),
    ]


def build_persona_features(
    *,
    context: DecisionContext,
    persona_policy_state: dict[str, object],
    text_inputs: dict[str, dict[str, dict[str, str]]],
) -> list[float]:
    """从 `persona_policy_states` 构造 persona dense feature。

    persona vector 继续维持旧布局：

    - slot_count / exposure_count / is_active / matched_candidate_attr_count
    - supported attr one-hot
    - display_name 与 slot text 的辅助 text signature
    """
    persona_id = str(persona_policy_state.get("persona_id", "")).strip()
    persona_text = text_inputs["personas"].get(persona_id, {}).get("persona_text", "")
    supported_attr_mask = persona_policy_state.get("supported_attr_mask", {})
    available_slot_mask = persona_policy_state.get("available_slot_mask", {})

    supported_attr_names = [
        attr_name
        for attr_name in ATTR_FEATURE_ORDER
        if bool(available_slot_mask.get(attr_name, supported_attr_mask.get(attr_name, False)))
    ]
    slot_count = _safe_float(
        persona_policy_state.get("_slot_count"),
        sum(1 for attr_name in ATTR_FEATURE_ORDER if bool(available_slot_mask.get(attr_name, False))),
    )
    exposure_count = _safe_float(
        persona_policy_state.get("_exposure_count"),
        _max_bucket_count(persona_policy_state.get("attr_exposure_buckets", {})),
    )
    is_active = bool(persona_policy_state.get("is_active", False))
    matched_candidate_attr_count = _safe_float(persona_policy_state.get("matched_candidate_attr_count"), 0.0)
    display_name = str(persona_policy_state.get("_display_name", "")).strip()
    slot_text = " ".join(str(value) for value in _persona_slots(persona_policy_state, context).values())

    return [
        min(1.0, slot_count / 8.0),
        min(1.0, exposure_count / 32.0),
        1.0 if is_active else 0.0,
        min(1.0, matched_candidate_attr_count / 8.0),
        *_attr_one_hot(*supported_attr_names),
        *_text_signature(display_name),
        *_text_signature(slot_text or persona_text),
    ]


def build_text_inputs(
    context: DecisionContext,
    *,
    policy: DerivedDecisionPolicyContext | None = None,
) -> dict[str, dict[str, dict[str, str]]]:
    """构建辅助文本通道输入。
    """
    resolved_policy = policy or derive_policy_context(context)
    candidate_inputs: dict[str, dict[str, str]] = {}
    candidate_by_id = _candidate_by_id(context)
    for view in resolved_policy.candidate_policy_views:
        candidate_id = str(view.get("candidate_id", "")).strip()
        if not candidate_id:
            continue
        candidate = candidate_by_id.get(candidate_id)
        candidate_inputs[candidate_id] = {
            "candidate_text": str(
                getattr(candidate, "text", "")
                or ""
            ),
            "prompt_context": str(
                view.get("prompt_local_context_labelized")
                or view.get("_prompt_context")
                or ""
            ),
            "ocr_context": str(
                view.get("ocr_local_context_labelized")
                or view.get("_ocr_context")
                or ""
            ),
        }

    persona_inputs: dict[str, dict[str, str]] = {}
    for state in resolved_policy.persona_policy_states:
        persona_id = str(state.get("persona_id", "")).strip()
        if not persona_id:
            continue
        display_name = str(
            state.get("_display_name")
            or _persona_display_name(context, persona_id)
            or ""
        ).strip()
        slot_text = " ".join(str(value) for value in _persona_slots(state, context).values())
        persona_inputs[persona_id] = {
            "persona_text": f"{display_name} {slot_text}".strip(),
        }

    return {
        "candidates": candidate_inputs,
        "personas": persona_inputs,
    }


class DecisionFeatureExtractor:
    """将 DecisionContext 压缩为轻量数值特征。"""

    def pack(
        self,
        context: DecisionContext,
        *,
        policy: DerivedDecisionPolicyContext | None = None,
    ) -> PackedDecisionFeatures:
        return pack_decision_features(context, policy=policy)


def _candidate_by_id(context: DecisionContext) -> dict[str, object]:
    return derived_candidate_by_id(context)


def _persona_by_id(context: DecisionContext) -> dict[str, object]:
    return derived_persona_by_id(context)


def _persona_display_name(context: DecisionContext, persona_id: str) -> str:
    persona = _persona_by_id(context).get(persona_id)
    return str(getattr(persona, "display_name", "") or "")


def _persona_slots(persona_policy_state: dict[str, object], context: DecisionContext) -> dict[object, object]:
    slots = persona_policy_state.get("_slots")
    if isinstance(slots, dict):
        return slots
    persona = _persona_by_id(context).get(str(persona_policy_state.get("persona_id", "")).strip())
    return dict(getattr(persona, "slots", {}) or {})


def _geometry_features(
    *,
    context: DecisionContext,
    candidate_id: str,
    candidate_policy_view: dict[str, object],
) -> tuple[float, float, float, float]:
    if all(key in candidate_policy_view for key in ("_relative_area", "_aspect_ratio", "_center_x", "_center_y")):
        return (
            _safe_float(candidate_policy_view.get("_relative_area"), 0.0),
            _safe_float(candidate_policy_view.get("_aspect_ratio"), 0.0),
            _safe_float(candidate_policy_view.get("_center_x"), 0.0),
            _safe_float(candidate_policy_view.get("_center_y"), 0.0),
        )
    candidate = _candidate_by_id(context).get(candidate_id)
    bbox = getattr(candidate, "bbox", None)
    if bbox is None:
        return (0.0, 0.0, 0.0, 0.0)
    max_right = 1
    max_bottom = 1
    for block in getattr(context, "ocr_blocks", []) or []:
        block_bbox = getattr(block, "bbox", None)
        if block_bbox is None:
            continue
        max_right = max(max_right, block_bbox.x + block_bbox.width)
        max_bottom = max(max_bottom, block_bbox.y + block_bbox.height)
    for item in getattr(context, "candidates", []) or []:
        item_bbox = getattr(item, "bbox", None)
        if item_bbox is None:
            continue
        max_right = max(max_right, item_bbox.x + item_bbox.width)
        max_bottom = max(max_bottom, item_bbox.y + item_bbox.height)
    page_area = max(1, max_right * max_bottom)
    relative_area = min(1.0, (bbox.width * bbox.height) / page_area)
    aspect_ratio = bbox.width / max(1, bbox.height)
    center_x = min(1.0, max(0.0, (bbox.x + bbox.width / 2) / max_right))
    center_y = min(1.0, max(0.0, (bbox.y + bbox.height / 2) / max_bottom))
    return (relative_area, aspect_ratio, center_x, center_y)


def _confidence_from_candidate_view(view: dict[str, object]) -> float:
    return _safe_float(view.get("_confidence"), _confidence_from_bucket(view.get("det_conf_bucket")))


def _candidate_attr_name(candidate) -> str:
    return str(getattr(getattr(candidate, "attr_type", None), "value", "")).strip()


def _candidate_source_name(candidate) -> str:
    return str(getattr(getattr(candidate, "source", None), "value", "")).strip().lower()


def _attr_name(view: dict[str, object]) -> str:
    attr_type = view.get("attr_type")
    return str(getattr(attr_type, "value", attr_type or "")).strip()


def _source_name(view: dict[str, object]) -> str:
    source = view.get("source")
    return str(getattr(source, "value", source or "")).strip().lower()


def _attr_one_hot(*names: str) -> list[float]:
    return _one_hot(*names, ordered_values=ATTR_FEATURE_ORDER)


def _source_one_hot(source_name: str) -> list[float]:
    return _one_hot(source_name, ordered_values=SOURCE_FEATURE_ORDER)


def _one_hot(*names: str, ordered_values: tuple[str, ...]) -> list[float]:
    values = {str(name).strip() for name in names if str(name).strip()}
    return [1.0 if name in values else 0.0 for name in ordered_values]


def _text_signature(text: str) -> list[float]:
    if not text:
        return [0.0, 0.0, 0.0, 0.0, 0.0]
    total = max(1, len(text))
    digit_count = sum(char.isdigit() for char in text)
    ascii_count = sum(char.isascii() for char in text)
    alpha_count = sum(char.isalpha() for char in text)
    punctuation_count = sum(not char.isalnum() and not _is_cjk(char) for char in text)
    cjk_count = sum(_is_cjk(char) for char in text)
    return [
        min(1.0, total / 32.0),
        digit_count / total,
        ascii_count / total,
        alpha_count / total,
        max(punctuation_count, cjk_count) / total,
    ]


def _is_cjk(char: str) -> bool:
    code = ord(char)
    return 0x4E00 <= code <= 0x9FFF


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(char.isdigit() for char in text) / max(1, len(text))


def _contains_mask_char(text: str) -> bool:
    return any(char in _MASK_CHARS for char in text)


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


def _bucket_text_length(value: int) -> str:
    if value <= 0:
        return "0"
    if value <= 2:
        return "1-2"
    if value <= 4:
        return "3-4"
    if value <= 8:
        return "5-8"
    return "9+"


def _bucket_confidence(value: float) -> str:
    if value <= 0.0:
        return "none"
    if value < _LOW_CANDIDATE_CONFIDENCE:
        return "low"
    if value < _HIGH_CANDIDATE_CONFIDENCE:
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


def _count_from_bucket(bucket: object) -> float:
    name = str(bucket or "").strip()
    mapping = {
        "0": 0.0,
        "1": 1.0,
        "2-3": 3.0,
        "4-7": 6.0,
        "8+": 8.0,
        "1-2": 2.0,
        "3-4": 4.0,
        "5-8": 8.0,
        "9+": 9.0,
    }
    return mapping.get(name, 0.0)


def _max_bucket_count(bucket_map: object) -> float:
    if not isinstance(bucket_map, dict):
        return 0.0
    return max((_count_from_bucket(value) for value in bucket_map.values()), default=0.0)


def _confidence_from_bucket(bucket: object) -> float:
    name = str(bucket or "").strip().lower()
    return {
        "none": 0.0,
        "low": 0.25,
        "medium": 0.675,
        "high": 0.925,
    }.get(name, 0.0)


def _ratio_from_bucket(bucket: object) -> float:
    name = str(bucket or "").strip().lower()
    return {
        "none": 0.0,
        "low": 0.17,
        "medium": 0.5,
        "high": 0.84,
    }.get(name, 0.0)


def _ratio_of(items, predicate, *, default: float = 0.0) -> float:
    items = list(items)
    if not items:
        return default
    return sum(1 for item in items if predicate(item)) / len(items)


def _average(values: list[float], default: float = 0.0) -> float:
    values = [float(value) for value in values if value is not None]
    if not values:
        return default
    return sum(values) / len(values)


def _minimum(values: list[float], default: float = 0.0) -> float:
    values = [float(value) for value in values if value is not None]
    if not values:
        return default
    return min(values)


def _safe_float(value: object, default: float = 0.0) -> float:
    if value is None:
        return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return bool(default)
