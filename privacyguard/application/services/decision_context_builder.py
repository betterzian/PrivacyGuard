"""de_model 决策上下文构造服务。"""

from __future__ import annotations

from collections import Counter

from privacyguard.domain.models.decision_context import (
    CandidateDecisionFeatures,
    DecisionModelContext,
    PageDecisionFeatures,
    PersonaDecisionFeatures,
)
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository

_ADDRESS_HINT_TOKENS = ("省", "市", "区", "县", "路", "街", "道", "号", "小区", "公寓")


class DecisionContextBuilder:
    """从 sanitize 主链路已有信息构建 de_model 上下文。"""

    def __init__(self, mapping_store: MappingStore, persona_repository: PersonaRepository) -> None:
        self.mapping_store = mapping_store
        self.persona_repository = persona_repository

    def build(
        self,
        *,
        session_id: str,
        turn_id: int,
        prompt_text: str = "",
        ocr_blocks: list[OCRTextBlock] | None = None,
        candidates: list[PIICandidate] | None = None,
        session_binding: SessionBinding | None = None,
    ) -> DecisionModelContext:
        """构建供 de_model 使用的完整上下文。"""
        ocr_items = list(ocr_blocks or [])
        candidate_items = list(candidates or [])
        history_records = self._history_records(session_id=session_id)
        persona_profiles = self._persona_profiles()
        block_map = {block.block_id: block for block in ocr_items if block.block_id}
        geometry_bounds = self._page_geometry_bounds(ocr_items=ocr_items, candidates=candidate_items)
        attr_counter = Counter(candidate.attr_type for candidate in candidate_items)
        text_counter = Counter((candidate.normalized_text or candidate.text) for candidate in candidate_items)
        candidate_features = [
            self._candidate_features(
                candidate=candidate,
                prompt_text=prompt_text,
                block_map=block_map,
                history_records=history_records,
                attr_counter=attr_counter,
                text_counter=text_counter,
                geometry_bounds=geometry_bounds,
            )
            for candidate in candidate_items
        ]
        persona_features = [
            self._persona_features(
                persona=persona,
                candidates=candidate_items,
                active_persona_id=session_binding.active_persona_id if session_binding else None,
            )
            for persona in persona_profiles
        ]
        page_features = PageDecisionFeatures(
            prompt_length=len(prompt_text),
            ocr_block_count=len(ocr_items),
            candidate_count=len(candidate_items),
            unique_attr_count=len({candidate.attr_type for candidate in candidate_items}),
            history_record_count=len(history_records),
            active_persona_bound=bool(session_binding and session_binding.active_persona_id),
            prompt_has_digits=any(char.isdigit() for char in prompt_text),
            prompt_has_address_tokens=any(token in prompt_text for token in _ADDRESS_HINT_TOKENS),
            average_candidate_confidence=(
                sum(candidate.confidence for candidate in candidate_items) / len(candidate_items)
                if candidate_items
                else 0.0
            ),
        )
        return DecisionModelContext(
            session_id=session_id,
            turn_id=turn_id,
            prompt_text=prompt_text,
            ocr_blocks=ocr_items,
            candidates=candidate_items,
            session_binding=session_binding,
            history_records=history_records,
            persona_profiles=persona_profiles,
            page_features=page_features,
            candidate_features=candidate_features,
            persona_features=persona_features,
        )

    def _history_records(self, session_id: str) -> list[ReplacementRecord]:
        records = self.mapping_store.get_replacements(session_id=session_id)
        return sorted(records, key=lambda item: (item.turn_id, len(item.replacement_text)), reverse=True)

    def _persona_profiles(self) -> list[PersonaProfile]:
        personas = self.persona_repository.list_personas()
        return sorted(personas, key=lambda item: int(item.stats.get("exposure_count", 0) or 0))

    def _candidate_features(
        self,
        *,
        candidate: PIICandidate,
        prompt_text: str,
        block_map: dict[str, OCRTextBlock],
        history_records: list[ReplacementRecord],
        attr_counter: Counter,
        text_counter: Counter,
        geometry_bounds: tuple[int, int],
    ) -> CandidateDecisionFeatures:
        history_attr_exposure_count = sum(1 for record in history_records if record.attr_type == candidate.attr_type)
        history_exact_match_count = sum(
            1
            for record in history_records
            if record.source_text == candidate.text or record.source_text == candidate.normalized_text
        )
        block_text = ""
        if candidate.block_id and candidate.block_id in block_map:
            block_text = block_map[candidate.block_id].text
        prompt_context = self._text_window(
            text=prompt_text,
            source_text=candidate.text,
            start=candidate.span_start if candidate.source.value == "prompt" else None,
            end=candidate.span_end if candidate.source.value == "prompt" else None,
        )
        ocr_context = self._text_window(
            text=block_text,
            source_text=candidate.text,
            start=candidate.span_start if candidate.source.value == "ocr" else None,
            end=candidate.span_end if candidate.source.value == "ocr" else None,
        )
        relative_area, aspect_ratio, center_x, center_y = self._geometry_features(candidate.bbox, geometry_bounds)
        key_text = candidate.normalized_text or candidate.text
        return CandidateDecisionFeatures(
            candidate_id=candidate.entity_id,
            text=candidate.text,
            normalized_text=candidate.normalized_text,
            attr_type=candidate.attr_type,
            source=candidate.source,
            confidence=candidate.confidence,
            bbox=candidate.bbox,
            block_id=candidate.block_id,
            span_start=candidate.span_start,
            span_end=candidate.span_end,
            prompt_context=prompt_context,
            ocr_context=ocr_context,
            history_attr_exposure_count=history_attr_exposure_count,
            history_exact_match_count=history_exact_match_count,
            same_attr_page_count=attr_counter[candidate.attr_type],
            same_text_page_count=text_counter[key_text],
            relative_area=relative_area,
            aspect_ratio=aspect_ratio,
            center_x=center_x,
            center_y=center_y,
            is_prompt_source=candidate.source.value == "prompt",
            is_ocr_source=candidate.source.value == "ocr",
        )

    def _persona_features(
        self,
        *,
        persona: PersonaProfile,
        candidates: list[PIICandidate],
        active_persona_id: str | None,
    ) -> PersonaDecisionFeatures:
        candidate_attrs = {candidate.attr_type for candidate in candidates}
        supported_attrs = sorted(persona.slots.keys(), key=lambda item: item.value)
        return PersonaDecisionFeatures(
            persona_id=persona.persona_id,
            display_name=persona.display_name,
            slot_count=len(persona.slots),
            exposure_count=int(persona.stats.get("exposure_count", 0) or 0),
            last_exposed_session_id=self._stats_value_as_str(persona.stats.get("last_exposed_session_id")),
            last_exposed_turn_id=self._stats_value_as_int(persona.stats.get("last_exposed_turn_id")),
            is_active=persona.persona_id == active_persona_id,
            supported_attr_types=supported_attrs,
            matched_candidate_attr_count=len(candidate_attrs.intersection(set(persona.slots.keys()))),
            slots=persona.slots,
        )

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

    def _geometry_features(self, bbox: BoundingBox | None, geometry_bounds: tuple[int, int]) -> tuple[float, float, float, float]:
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
