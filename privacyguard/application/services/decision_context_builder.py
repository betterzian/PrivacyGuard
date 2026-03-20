"""de_model 正式策略上下文组装器。

本 builder 的职责是把 sanitize 主链已有信息收敛为统一的策略上下文，不负责：

- detector 候选发现
- 最终策略决策
- restore
- 最终 placeholder 分配

当前正式上下文在运行时收敛为 `DecisionModelContext`，内部组织为四块：

- `raw_refs`
- `candidate_policy_views`
- `page_policy_state`
- `persona_policy_states`

该 builder 直接输出正式策略字段（`raw_refs` / `candidate_policy_views` /
`page_policy_state` / `persona_policy_states`）。
"""

from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import Field

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.utils.pii_value import canonicalize_pii_value

_ADDRESS_HINT_TOKENS = ("省", "市", "区", "县", "路", "街", "道", "号", "小区", "公寓")
_HIGH_CANDIDATE_CONFIDENCE = 0.85
_LOW_CANDIDATE_CONFIDENCE = 0.5
_LOW_OCR_BLOCK_SCORE = 0.75
_MASK_CHARS = set("*＊xX×#＃•●○◦◯_＿?？")
_ATTR_LABELS = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.LOCATION_CLUE: "位置",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.CARD_NUMBER: "卡号",
    PIIAttributeType.BANK_ACCOUNT: "银行账号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.OTHER: "敏感信息",
}


class DecisionModelContext(DecisionContext):
    """正式策略上下文。

    这是对 `DecisionContext` 的收敛扩展：新增四块正式策略视图。
    """

    # 原始工程对象引用层。
    # 用途：给 runtime / debug / render 回查真实对象，不作为轻量策略特征直接消费。
    # 若只是想拿旧链路已有对象，通常可以直接使用旧顶层字段：
    # - `prompt_text`
    # - `ocr_blocks`
    # - `candidates`
    # - `history_records`
    # - `persona_profiles`
    # - `session_binding`
    raw_refs: dict[str, object] = Field(default_factory=dict)
    # 候选级轻量策略视图。
    # 用途：提供 de_model 真正应消费的 candidate 级策略字段。
    # 不能整体被旧顶层字段直接替代，但其中一部分字段可以从旧顶层直接读取：
    # - `candidate_id` ~= `candidates[*].entity_id`
    # - `attr_type` / `source` ~= `candidates[*].attr_type` / `candidates[*].source`
    # - `prompt_local_context_labelized` / `ocr_local_context_labelized` 由 context/candidate 重建
    # - `low_ocr_flag` 由 OCR block 质量重建
    candidate_policy_views: list[dict[str, object]] = Field(default_factory=list)
    # 页面级策略状态。
    # 用途：把 protection level、检测质量、OCR 质量等收敛为页面级输入。
    # 这里的大多数字段都能从基础上下文字段推导：
    # - `protection_level` 可直接用旧顶层 `protection_level`
    # - 其余 bucket 字段由 candidates / OCR / history 统计离散化得到
    page_policy_state: dict[str, object] = Field(default_factory=dict)
    # persona 级策略状态。
    # 用途：表达 persona 是否激活、支持哪些属性、槽位是否可用、暴露统计等。
    # 其中部分字段可由旧顶层直接取得：
    # - `persona_id` 可直接用 `persona_profiles[*].persona_id`
    # - `is_active` 可直接用 `session_binding.active_persona_id`
    # - `matched_candidate_attr_count` 可由 persona slots 与当前 candidates 重建
    persona_policy_states: list[dict[str, object]] = Field(default_factory=list)


class DecisionContextBuilder:
    """从 sanitize 主链已有信息构建统一策略上下文。"""

    def __init__(self, mapping_store: MappingStore, persona_repository: PersonaRepository) -> None:
        self.mapping_store = mapping_store
        self.persona_repository = persona_repository

    def build(
        self,
        *,
        session_id: str,
        turn_id: int,
        prompt_text: str = "",
        protection_level: ProtectionLevel | str = ProtectionLevel.BALANCED,
        detector_overrides: dict[object, float] | None = None,
        ocr_blocks: list[OCRTextBlock] | None = None,
        candidates: list[PIICandidate] | None = None,
        session_binding: SessionBinding | None = None,
    ) -> DecisionModelContext:
        """构建正式策略上下文。"""
        ocr_items = list(ocr_blocks or [])
        candidate_items = list(candidates or [])
        normalized_protection_level = self._normalize_protection_level(protection_level)
        normalized_detector_overrides = self._normalize_detector_overrides(detector_overrides)
        history_records = self._history_records(session_id=session_id)
        persona_profiles = self._persona_profiles()
        block_map = {block.block_id: block for block in ocr_items if block.block_id}
        geometry_bounds = self._page_geometry_bounds(ocr_items=ocr_items, candidates=candidate_items)

        attr_counter = Counter(candidate.attr_type for candidate in candidate_items)
        text_counter = Counter((candidate.normalized_text or candidate.text) for candidate in candidate_items)
        source_counter = Counter(candidate.source for candidate in candidate_items)
        alias_by_candidate = {candidate.entity_id: self._alias_value(candidate) for candidate in candidate_items}
        alias_counter = Counter(alias_by_candidate.values())
        alias_sources: defaultdict[str, set[PIISourceType]] = defaultdict(set)
        for candidate in candidate_items:
            alias_sources[alias_by_candidate[candidate.entity_id]].add(candidate.source)
        history_alias_counter = Counter(
            alias_value
            for alias_value in (self._record_alias_value(record) for record in history_records)
            if alias_value
        )
        history_attr_counter = Counter(record.attr_type for record in history_records)

        candidate_policy_views: list[dict[str, object]] = []
        for candidate in candidate_items:
            policy_view = self._build_candidate_policy_view(
                candidate=candidate,
                prompt_text=prompt_text,
                block_map=block_map,
                history_records=history_records,
                history_alias_counter=history_alias_counter,
                history_attr_counter=history_attr_counter,
                attr_counter=attr_counter,
                text_counter=text_counter,
                geometry_bounds=geometry_bounds,
                alias_value=alias_by_candidate[candidate.entity_id],
                alias_counter=alias_counter,
                alias_sources=alias_sources,
            )
            candidate_policy_views.append(policy_view)

        page_policy_state = self._build_page_policy_state(
            prompt_text=prompt_text,
            protection_level=normalized_protection_level,
            ocr_items=ocr_items,
            candidate_items=candidate_items,
            history_records=history_records,
            session_binding=session_binding,
            source_counter=source_counter,
        )
        persona_policy_states: list[dict[str, object]] = []
        for persona in persona_profiles:
            persona_view = self._build_persona_view(
                persona=persona,
                candidates=candidate_items,
                active_persona_id=session_binding.active_persona_id if session_binding else None,
            )
            persona_policy_states.append(persona_view)

        return DecisionModelContext(
            session_id=session_id,
            turn_id=turn_id,
            prompt_text=prompt_text,
            protection_level=normalized_protection_level,
            detector_overrides=normalized_detector_overrides,
            ocr_blocks=ocr_items,
            candidates=candidate_items,
            session_binding=session_binding,
            history_records=history_records,
            persona_profiles=persona_profiles,
            raw_refs=self._build_raw_refs(
                prompt_text=prompt_text,
                ocr_items=ocr_items,
                candidate_items=candidate_items,
                history_records=history_records,
                persona_profiles=persona_profiles,
                session_binding=session_binding,
            ),
            candidate_policy_views=candidate_policy_views,
            page_policy_state=page_policy_state,
            persona_policy_states=persona_policy_states,
        )

    def _build_raw_refs(
        self,
        *,
        prompt_text: str,
        ocr_items: list[OCRTextBlock],
        candidate_items: list[PIICandidate],
        history_records: list[ReplacementRecord],
        persona_profiles: list[PersonaProfile],
        session_binding: SessionBinding | None,
    ) -> dict[str, object]:
        """构建 raw_refs。

        字段含义：

        - `prompt_text`：当前轮 prompt 原文引用
        - `candidate_by_id`：`candidate_id -> PIICandidate`
        - `ocr_block_by_id`：`block_id -> OCRTextBlock`
        - `history_records`：当前 session 的历史替换记录
        - `persona_by_id`：`persona_id -> PersonaProfile`
        - `session_binding`：当前 session 的 persona 绑定状态

        哪些可以直接用旧顶层字段代替：

        - `prompt_text` 可直接用旧顶层 `prompt_text`
        - `history_records` 可直接用旧顶层 `history_records`
        - `session_binding` 可直接用旧顶层 `session_binding`
        - `candidate_by_id` / `ocr_block_by_id` / `persona_by_id` 只是把旧顶层列表重排成索引结构，
          方便查找，不是新的真值对象类型
        """
        return {
            "prompt_text": prompt_text,
            "candidate_by_id": {candidate.entity_id: candidate for candidate in candidate_items},
            "ocr_block_by_id": {block.block_id: block for block in ocr_items if block.block_id},
            "history_records": history_records,
            "persona_by_id": {persona.persona_id: persona for persona in persona_profiles},
            "session_binding": session_binding,
        }

    def _build_alias_view(
        self,
        *,
        candidate: PIICandidate,
        alias_value: str,
        alias_counter: Counter,
        alias_sources: dict[str, set[PIISourceType]],
        history_alias_counter: Counter,
    ) -> dict[str, object]:
        """构建 alias 相关轻量视图。

        字段含义：

        - `session_alias`：当前 candidate 在 session 内的稳定别名键
        - `same_alias_count_in_turn`：当前轮中同 alias 出现次数
        - `cross_source_same_alias_flag`：同 alias 是否同时出现在 prompt / OCR 两种来源
        - `history_alias_exposure_bucket`：该 alias 在历史记录中的暴露桶

        哪些可以直接用旧顶层字段代替：

        - 这一组字段在旧顶层里没有等价正式字段
        - 只能用旧 `history_records` + `candidates` 重新推导，不能直接读取现成值
        """
        return {
            "session_alias": alias_value,
            "same_alias_count_in_turn": alias_counter[alias_value],
            "cross_source_same_alias_flag": len(alias_sources.get(alias_value, set())) > 1,
            "history_alias_exposure_bucket": self._bucket_count(history_alias_counter[alias_value]),
            "_history_alias_exposure_count": history_alias_counter[alias_value],
            "_alias_attr_type": candidate.attr_type,
        }

    def _build_local_context_view(
        self,
        *,
        candidate: PIICandidate,
        prompt_text: str,
        block_map: dict[str, OCRTextBlock],
    ) -> dict[str, object]:
        """构建局部上下文视图。

        字段含义：

        - `cross_block_flag`：OCR candidate 是否跨多个 block
        - `covered_block_count_bucket`：覆盖 block 数量桶
        - `prompt_local_context_labelized`：prompt 局部上下文，并把命中实体替换成类型标签
        - `ocr_local_context_labelized`：OCR 局部上下文，并把命中实体替换成类型标签

        哪些可以直接用旧顶层字段代替：

        - `prompt_local_context_labelized` / `ocr_local_context_labelized` 没有旧顶层同名字段
        - 但可退回使用旧兼容层 `candidate_features[*].prompt_context` /
          `candidate_features[*].ocr_context` 作为未 labelize 版本
        - `cross_block_flag` / `covered_block_count_bucket` 在旧顶层没有直接字段，只能由
          `candidate.metadata["ocr_block_ids"]`、`candidate.block_id` 重新推导
        """
        covered_block_ids = self._covered_block_ids(candidate)
        cross_block_flag = len(covered_block_ids) > 1
        prompt_context = self._text_window(
            text=prompt_text,
            source_text=candidate.text,
            start=candidate.span_start if candidate.source == PIISourceType.PROMPT else None,
            end=candidate.span_end if candidate.source == PIISourceType.PROMPT else None,
        )
        ocr_source_text = self._merged_ocr_context_text(covered_block_ids=covered_block_ids, block_map=block_map)
        if not ocr_source_text and candidate.block_id and candidate.block_id in block_map:
            ocr_source_text = block_map[candidate.block_id].text
        ocr_context = self._text_window(
            text=ocr_source_text,
            source_text=candidate.text,
            start=candidate.span_start if candidate.source == PIISourceType.OCR and not cross_block_flag else None,
            end=candidate.span_end if candidate.source == PIISourceType.OCR and not cross_block_flag else None,
        )
        label_token = self._context_label(candidate.attr_type)
        return {
            "cross_block_flag": cross_block_flag,
            "covered_block_count_bucket": self._bucket_count(len(covered_block_ids)),
            "prompt_local_context_labelized": self._labelize_context(prompt_context, candidate.text, label_token),
            "ocr_local_context_labelized": self._labelize_context(ocr_context, candidate.text, label_token),
            "_covered_block_ids": covered_block_ids,
            "_prompt_context": prompt_context,
            "_ocr_context": ocr_context,
        }

    def _build_quality_view(
        self,
        *,
        candidate: PIICandidate,
        block_map: dict[str, OCRTextBlock],
        local_context_view: dict[str, object],
    ) -> dict[str, object]:
        """构建 candidate 级质量视图。

        字段含义：

        - `det_conf_bucket`：detector 置信度桶
        - `ocr_local_conf_bucket`：OCR 局部质量桶
        - `low_ocr_flag`：OCR 局部质量是否偏低

        哪些可以直接用旧顶层字段代替：

        - `det_conf_bucket` 可由旧 `candidates[*].confidence` 或
          `candidate_features[*].confidence` 再离散化得到
        - `ocr_local_conf_bucket` 可由旧 `candidate_features[*].ocr_block_score`
          近似离散化得到
        - `low_ocr_flag` 可直接退回使用旧 `candidate_features[*].is_low_ocr_confidence`
        """
        covered_block_ids = [str(item) for item in local_context_view.get("_covered_block_ids", [])]
        covered_blocks = [block_map[block_id] for block_id in covered_block_ids if block_id in block_map]
        primary_block = block_map.get(candidate.block_id) if candidate.block_id else (covered_blocks[0] if covered_blocks else None)
        if covered_blocks:
            ocr_local_conf = sum(block.score for block in covered_blocks) / len(covered_blocks)
        elif primary_block is not None:
            ocr_local_conf = primary_block.score
        else:
            ocr_local_conf = 0.0
        return {
            "det_conf_bucket": self._bucket_confidence(candidate.confidence),
            "ocr_local_conf_bucket": self._bucket_confidence(ocr_local_conf),
            "low_ocr_flag": bool(covered_blocks or primary_block) and ocr_local_conf < _LOW_OCR_BLOCK_SCORE,
            "_ocr_block_score": primary_block.score if primary_block is not None else 0.0,
            "_ocr_block_rotation_degrees": primary_block.rotation_degrees if primary_block is not None else 0.0,
            "_ocr_local_conf": ocr_local_conf,
        }

    def _build_persona_view(
        self,
        *,
        persona: PersonaProfile,
        candidates: list[PIICandidate],
        active_persona_id: str | None,
    ) -> dict[str, object]:
        """构建 persona 级策略状态。

        字段含义：

        - `persona_id`：persona 标识
        - `is_active`：是否为当前 session 的 active persona
        - `supported_attr_mask`：该 persona 是否支持各 attr_type
        - `available_slot_mask`：对应槽位当前是否有可用值
        - `attr_exposure_buckets`：各 attr_type 的暴露桶摘要
        - `matched_candidate_attr_count`：当前页面 candidate 中，有多少 attr_type 能被该 persona 覆盖

        哪些可以直接用旧顶层字段代替：

        - `persona_id` 可直接用旧 `persona_profiles[*].persona_id`
        - `is_active` 可直接用旧 `session_binding.active_persona_id` 或
          `persona_features[*].is_active`
        - `matched_candidate_attr_count` 可直接用旧
          `persona_features[*].matched_candidate_attr_count`
        - `supported_attr_mask` / `available_slot_mask` 可由旧 `persona_profiles[*].slots` 或
          `persona_features[*].supported_attr_types` / `slots` 重建
        - `attr_exposure_buckets` 没有旧同名字段，但可由旧 `persona_features[*].exposure_count`
          或 `persona_profiles[*].stats` 再离散化得到
        """
        candidate_attrs = {candidate.attr_type for candidate in candidates}
        supported_attrs = set(persona.slots.keys())
        exposure_count = int(persona.stats.get("exposure_count", 0) or 0)
        exposure_bucket = self._bucket_count(exposure_count)
        supported_attr_mask = {attr.value: attr in supported_attrs for attr in PIIAttributeType}
        available_slot_mask = {
            attr.value: bool(str(persona.slots.get(attr, "")).strip()) if attr in supported_attrs else False
            for attr in PIIAttributeType
        }
        attr_exposure_buckets = {
            attr.value: exposure_bucket if attr in supported_attrs else "0"
            for attr in PIIAttributeType
        }
        return {
            "persona_id": persona.persona_id,
            "is_active": persona.persona_id == active_persona_id,
            "supported_attr_mask": supported_attr_mask,
            "available_slot_mask": available_slot_mask,
            "attr_exposure_buckets": attr_exposure_buckets,
            "matched_candidate_attr_count": len(candidate_attrs.intersection(supported_attrs)),
            "_slot_count": len(persona.slots),
            "_display_name": persona.display_name,
            "_exposure_count": exposure_count,
            "_last_exposed_session_id": self._stats_value_as_str(persona.stats.get("last_exposed_session_id")),
            "_last_exposed_turn_id": self._stats_value_as_int(persona.stats.get("last_exposed_turn_id")),
            "_supported_attr_types": sorted(supported_attrs, key=lambda item: item.value),
            "_slots": persona.slots,
        }

    def _build_candidate_policy_view(
        self,
        *,
        candidate: PIICandidate,
        prompt_text: str,
        block_map: dict[str, OCRTextBlock],
        history_records: list[ReplacementRecord],
        history_alias_counter: Counter,
        history_attr_counter: Counter,
        attr_counter: Counter,
        text_counter: Counter,
        geometry_bounds: tuple[int, int],
        alias_value: str,
        alias_counter: Counter,
        alias_sources: dict[str, set[PIISourceType]],
    ) -> dict[str, object]:
        """构建 candidate 级正式策略视图。

        字段含义：

        - `candidate_id`：候选唯一标识
        - `attr_type` / `attr_id`：属性类型对象 / 属性类型字符串
        - `source`：来源，prompt 或 OCR
        - `session_alias`：session 内稳定别名键
        - `same_alias_count_in_turn`：本轮同 alias 次数
        - `cross_source_same_alias_flag`：同 alias 是否跨 prompt/OCR 来源
        - `history_alias_exposure_bucket`：alias 历史暴露桶
        - `history_exact_match_bucket`：同真实值历史命中桶
        - `det_conf_bucket`：detector 置信度桶
        - `ocr_local_conf_bucket`：OCR 局部置信桶
        - `low_ocr_flag`：OCR 局部质量偏低标记
        - `cross_block_flag`：是否跨多个 OCR block
        - `covered_block_count_bucket`：覆盖 block 数量桶
        - `same_attr_page_bucket`：当前页同 attr_type 数量桶
        - `normalized_len_bucket`：标准化文本长度桶
        - `digit_ratio_bucket`：数字占比桶
        - `mask_char_flag`：是否包含掩码字符
        - `prompt_local_context_labelized`：prompt 局部上下文标签化结果
        - `ocr_local_context_labelized`：OCR 局部上下文标签化结果

        哪些可以直接用旧顶层字段代替：

        - `candidate_id` / `attr_type` / `source` 可直接用旧 `candidates[*]`
        - `history_exact_match_bucket` 可由旧 `candidate_features[*].history_exact_match_count`
          再离散化得到
        - `low_ocr_flag` 可直接参考旧 `candidate_features[*].is_low_ocr_confidence`
        - `same_attr_page_bucket` 可由旧 `candidate_features[*].same_attr_page_count`
          再离散化得到
        - `prompt_local_context_labelized` / `ocr_local_context_labelized` 可退回参考旧
          `candidate_features[*].prompt_context` / `ocr_context`
        - alias、cross-block、digit/mask、桶化质量字段在旧顶层没有同名正式字段，
          只能由旧对象重新推导，不能直接等值替换
        """
        alias_view = self._build_alias_view(
            candidate=candidate,
            alias_value=alias_value,
            alias_counter=alias_counter,
            alias_sources=alias_sources,
            history_alias_counter=history_alias_counter,
        )
        local_context_view = self._build_local_context_view(
            candidate=candidate,
            prompt_text=prompt_text,
            block_map=block_map,
        )
        quality_view = self._build_quality_view(
            candidate=candidate,
            block_map=block_map,
            local_context_view=local_context_view,
        )

        history_exact_match_count = self._history_exact_match_count(candidate, history_records)
        same_attr_page_count = attr_counter[candidate.attr_type]
        key_text = candidate.normalized_text or candidate.text
        same_text_page_count = text_counter[key_text]
        relative_area, aspect_ratio, center_x, center_y = self._geometry_features(candidate.bbox, geometry_bounds)
        normalized_text = candidate.normalized_text or candidate.text
        digit_ratio = self._digit_ratio(normalized_text)
        return {
            "candidate_id": candidate.entity_id,
            "attr_type": candidate.attr_type,
            "attr_id": candidate.attr_type.value,
            "source": candidate.source,
            **alias_view,
            "history_exact_match_bucket": self._bucket_count(history_exact_match_count),
            "det_conf_bucket": quality_view["det_conf_bucket"],
            "ocr_local_conf_bucket": quality_view["ocr_local_conf_bucket"],
            "low_ocr_flag": quality_view["low_ocr_flag"],
            "cross_block_flag": local_context_view["cross_block_flag"],
            "covered_block_count_bucket": local_context_view["covered_block_count_bucket"],
            "same_attr_page_bucket": self._bucket_count(same_attr_page_count),
            "normalized_len_bucket": self._bucket_text_length(len(normalized_text)),
            "digit_ratio_bucket": self._bucket_ratio(digit_ratio),
            "mask_char_flag": self._contains_mask_char(candidate.text),
            "prompt_local_context_labelized": local_context_view["prompt_local_context_labelized"],
            "ocr_local_context_labelized": local_context_view["ocr_local_context_labelized"],
            "_prompt_context": local_context_view["_prompt_context"],
            "_ocr_context": local_context_view["_ocr_context"],
            "_history_attr_exposure_count": history_attr_counter[candidate.attr_type],
            "_history_exact_match_count": history_exact_match_count,
            "_same_attr_page_count": same_attr_page_count,
            "_same_text_page_count": same_text_page_count,
            "_relative_area": relative_area,
            "_aspect_ratio": aspect_ratio,
            "_center_x": center_x,
            "_center_y": center_y,
            "_confidence": candidate.confidence,
            "_ocr_block_score": quality_view["_ocr_block_score"],
            "_ocr_block_rotation_degrees": quality_view["_ocr_block_rotation_degrees"],
            "_ocr_local_conf": quality_view["_ocr_local_conf"],
        }

    def _build_page_policy_state(
        self,
        *,
        prompt_text: str,
        protection_level: ProtectionLevel,
        ocr_items: list[OCRTextBlock],
        candidate_items: list[PIICandidate],
        history_records: list[ReplacementRecord],
        session_binding: SessionBinding | None,
        source_counter: Counter,
    ) -> dict[str, object]:
        """构建页面级正式策略状态。

        字段含义：

        - `protection_level`：页面当前保护强度
        - `candidate_count_bucket`：候选数量桶
        - `unique_attr_count_bucket`：页面内不同属性类型数量桶
        - `avg_det_conf_bucket`：平均 detector 质量桶
        - `min_det_conf_bucket`：最弱 detector 质量桶
        - `avg_ocr_conf_bucket`：平均 OCR 质量桶
        - `low_ocr_ratio_bucket`：低质量 OCR block 比例桶
        - `page_quality_state`：页面总体质量状态

        哪些可以直接用旧顶层字段代替：

        - `protection_level` 可直接用旧顶层 `protection_level`
        - `candidate_count_bucket` 可由旧 `page_features.candidate_count` 再离散化
        - `unique_attr_count_bucket` 可由旧 `page_features.unique_attr_count` 再离散化
        - `avg_det_conf_bucket` 可由旧 `page_features.average_candidate_confidence` 再离散化
        - `min_det_conf_bucket` 可由旧 `page_features.min_candidate_confidence` 再离散化
        - `avg_ocr_conf_bucket` 可由旧 `page_features.average_ocr_block_score` 再离散化
        - `low_ocr_ratio_bucket` 可由旧 `page_features.low_confidence_ocr_block_ratio` 再离散化
        - `page_quality_state` 在旧顶层没有直接字段，只能由上述质量信号重新归纳
        """
        candidate_confidences = [candidate.confidence for candidate in candidate_items]
        ocr_scores = [block.score for block in ocr_items]
        candidate_count = len(candidate_items)
        unique_attr_count = len({candidate.attr_type for candidate in candidate_items})
        avg_det_conf = sum(candidate_confidences) / len(candidate_confidences) if candidate_confidences else 0.0
        min_det_conf = min(candidate_confidences) if candidate_confidences else 0.0
        avg_ocr_conf = sum(ocr_scores) / len(ocr_scores) if ocr_scores else 0.0
        min_ocr_conf = min(ocr_scores) if ocr_scores else 0.0
        low_ocr_ratio = (
            sum(score < _LOW_OCR_BLOCK_SCORE for score in ocr_scores) / len(ocr_scores)
            if ocr_scores
            else 0.0
        )
        return {
            "protection_level": protection_level.value,
            "candidate_count_bucket": self._bucket_count(candidate_count),
            "unique_attr_count_bucket": self._bucket_count(unique_attr_count),
            "avg_det_conf_bucket": self._bucket_confidence(avg_det_conf),
            "min_det_conf_bucket": self._bucket_confidence(min_det_conf),
            "avg_ocr_conf_bucket": self._bucket_confidence(avg_ocr_conf),
            "low_ocr_ratio_bucket": self._bucket_ratio(low_ocr_ratio),
            "page_quality_state": self._page_quality_state(
                avg_det_conf=avg_det_conf,
                avg_ocr_conf=avg_ocr_conf,
                low_ocr_ratio=low_ocr_ratio,
                has_ocr=bool(ocr_scores),
            ),
            "_prompt_length": len(prompt_text),
            "_ocr_block_count": len(ocr_items),
            "_candidate_count": candidate_count,
            "_unique_attr_count": unique_attr_count,
            "_history_record_count": len(history_records),
            "_active_persona_bound": bool(session_binding and session_binding.active_persona_id),
            "_prompt_has_digits": any(char.isdigit() for char in prompt_text),
            "_prompt_has_address_tokens": any(token in prompt_text for token in _ADDRESS_HINT_TOKENS),
            "_average_candidate_confidence": avg_det_conf,
            "_min_candidate_confidence": min_det_conf,
            "_high_confidence_candidate_ratio": (
                sum(score >= _HIGH_CANDIDATE_CONFIDENCE for score in candidate_confidences) / len(candidate_confidences)
                if candidate_confidences
                else 0.0
            ),
            "_low_confidence_candidate_ratio": (
                sum(score < _LOW_CANDIDATE_CONFIDENCE for score in candidate_confidences) / len(candidate_confidences)
                if candidate_confidences
                else 0.0
            ),
            "_prompt_candidate_count": source_counter[PIISourceType.PROMPT],
            "_ocr_candidate_count": source_counter[PIISourceType.OCR],
            "_average_ocr_block_score": avg_ocr_conf,
            "_min_ocr_block_score": min_ocr_conf,
            "_low_confidence_ocr_block_ratio": low_ocr_ratio,
        }

    def _history_records(self, session_id: str) -> list[ReplacementRecord]:
        records = self.mapping_store.get_replacements(session_id=session_id)
        return sorted(records, key=lambda item: (item.turn_id, len(item.replacement_text)), reverse=True)

    def _persona_profiles(self) -> list[PersonaProfile]:
        personas = self.persona_repository.list_personas()
        return sorted(personas, key=lambda item: int(item.stats.get("exposure_count", 0) or 0))

    def _record_alias_value(self, record: ReplacementRecord) -> str | None:
        source_text = record.canonical_source_text or record.source_text
        if not source_text:
            return None
        try:
            canonical = canonicalize_pii_value(record.attr_type, source_text)
        except Exception:
            canonical = source_text.strip()
        return f"{record.attr_type.value}:{canonical or source_text.strip()}"

    def _alias_value(self, candidate: PIICandidate) -> str:
        source_text = candidate.canonical_source_text or candidate.normalized_text or candidate.text
        try:
            canonical = canonicalize_pii_value(candidate.attr_type, source_text)
        except Exception:
            canonical = source_text.strip()
        stable_value = canonical or source_text.strip() or candidate.entity_id
        return f"{candidate.attr_type.value}:{stable_value}"

    def _history_exact_match_count(self, candidate: PIICandidate, history_records: list[ReplacementRecord]) -> int:
        candidate_source_texts = {
            candidate.text,
            candidate.normalized_text,
            candidate.canonical_source_text or "",
        }
        return sum(
            1
            for record in history_records
            if (record.canonical_source_text or record.source_text) in candidate_source_texts
            or record.source_text in candidate_source_texts
        )

    def _covered_block_ids(self, candidate: PIICandidate) -> list[str]:
        metadata_ids = candidate.metadata.get("ocr_block_ids", [])
        ordered: list[str] = []
        for item in metadata_ids:
            text = str(item).strip()
            if text and text not in ordered:
                ordered.append(text)
        if candidate.block_id and candidate.block_id not in ordered:
            ordered.append(candidate.block_id)
        return ordered

    def _merged_ocr_context_text(self, *, covered_block_ids: list[str], block_map: dict[str, OCRTextBlock]) -> str:
        parts = [block_map[block_id].text for block_id in covered_block_ids if block_id in block_map]
        return " ".join(part for part in parts if part)

    def _page_geometry_bounds(
        self,
        *,
        ocr_items: list[OCRTextBlock],
        candidates: list[PIICandidate],
    ) -> tuple[int, int]:
        max_right = 1
        max_bottom = 1
        for item in list(ocr_items) + [candidate for candidate in candidates if candidate.bbox is not None]:
            bbox = item.bbox
            if bbox is None:
                continue
            max_right = max(max_right, bbox.x + bbox.width)
            max_bottom = max(max_bottom, bbox.y + bbox.height)
        return (max_right, max_bottom)

    def _geometry_features(
        self,
        bbox: BoundingBox | None,
        geometry_bounds: tuple[int, int],
    ) -> tuple[float, float, float, float]:
        if bbox is None:
            return (0.0, 0.0, 0.0, 0.0)
        max_right, max_bottom = geometry_bounds
        page_area = max(1, max_right * max_bottom)
        relative_area = min(1.0, (bbox.width * bbox.height) / page_area)
        aspect_ratio = bbox.width / max(1, bbox.height)
        center_x = min(1.0, max(0.0, (bbox.x + bbox.width / 2) / max_right))
        center_y = min(1.0, max(0.0, (bbox.y + bbox.height / 2) / max_bottom))
        return (relative_area, aspect_ratio, center_x, center_y)

    def _text_window(
        self,
        *,
        text: str,
        source_text: str,
        start: int | None,
        end: int | None,
        radius: int = 10,
    ) -> str:
        if not text:
            return ""
        if start is not None and end is not None and 0 <= start < end <= len(text):
            left = max(0, start - radius)
            right = min(len(text), end + radius)
            return text[left:right]
        if source_text:
            index = text.find(source_text)
            if index >= 0:
                left = max(0, index - radius)
                right = min(len(text), index + len(source_text) + radius)
                return text[left:right]
        return text[: radius * 2]

    def _labelize_context(self, context_text: str, source_text: str, label_token: str) -> str:
        if not context_text:
            return ""
        if source_text and source_text in context_text:
            return context_text.replace(source_text, label_token, 1)
        return context_text

    def _context_label(self, attr_type: PIIAttributeType) -> str:
        return f"[{_ATTR_LABELS.get(attr_type, '敏感信息')}]"

    def _contains_mask_char(self, text: str) -> bool:
        return any(char in _MASK_CHARS for char in text)

    def _digit_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        return sum(char.isdigit() for char in text) / max(1, len(text))

    def _bucket_count(self, value: int) -> str:
        if value <= 0:
            return "0"
        if value == 1:
            return "1"
        if value <= 3:
            return "2-3"
        if value <= 7:
            return "4-7"
        return "8+"

    def _bucket_text_length(self, value: int) -> str:
        if value <= 0:
            return "0"
        if value <= 2:
            return "1-2"
        if value <= 4:
            return "3-4"
        if value <= 8:
            return "5-8"
        return "9+"

    def _bucket_confidence(self, value: float) -> str:
        if value <= 0.0:
            return "none"
        if value < _LOW_CANDIDATE_CONFIDENCE:
            return "low"
        if value < _HIGH_CANDIDATE_CONFIDENCE:
            return "medium"
        return "high"

    def _bucket_ratio(self, value: float) -> str:
        if value <= 0.0:
            return "none"
        if value < 0.34:
            return "low"
        if value < 0.67:
            return "medium"
        return "high"

    def _page_quality_state(
        self,
        *,
        avg_det_conf: float,
        avg_ocr_conf: float,
        low_ocr_ratio: float,
        has_ocr: bool,
    ) -> str:
        if avg_det_conf < _LOW_CANDIDATE_CONFIDENCE:
            return "poor"
        if has_ocr and (avg_ocr_conf < _LOW_OCR_BLOCK_SCORE or low_ocr_ratio > 0.5):
            return "poor"
        if avg_det_conf >= _HIGH_CANDIDATE_CONFIDENCE and (not has_ocr or avg_ocr_conf >= _HIGH_CANDIDATE_CONFIDENCE):
            return "good"
        return "mixed"

    def _stats_value_as_str(self, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _stats_value_as_int(self, value: object) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _normalize_protection_level(self, protection_level: ProtectionLevel | str) -> ProtectionLevel:
        if isinstance(protection_level, ProtectionLevel):
            return protection_level
        normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
        return ProtectionLevel(normalized)

    def _normalize_detector_overrides(
        self,
        detector_overrides: dict[object, float] | None,
    ) -> dict[object, float]:
        normalized: dict[object, float] = {}
        for key, value in (detector_overrides or {}).items():
            normalized[key] = value
        return normalized
