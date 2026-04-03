"""候选去重与稳定 ID 生成服务。

当前主链的动作约束只保留一套实现：

- `ConstraintResolver`
- `ReplacementGenerationService`

本服务不再承担 `DecisionPlan` / `DecisionAction` 的约束、回退或 placeholder 补建，
只保留 detector 侧实际使用的两项能力：

- `build_candidate_id(...)`
- `resolve_candidates(...)`
"""

from __future__ import annotations

from hashlib import md5

from privacyguard.domain.models.pii import PIICandidate


class CandidateResolverService:
    """为 detector 提供稳定 candidate_id 与候选去重能力。"""

    def build_candidate_id(
        self,
        detector_mode: str,
        source: str,
        normalized_text: str,
        attr_type: str,
        block_id: str | None = None,
        span_start: int | None = None,
        span_end: int | None = None,
    ) -> str:
        """根据关键字段生成稳定候选 ID。"""
        raw = f"{detector_mode}|{source}|{normalized_text}|{attr_type}|{block_id or ''}|{span_start}|{span_end}"
        return md5(raw.encode("utf-8")).hexdigest()

    def resolve_candidates(self, candidates: list[PIICandidate]) -> list[PIICandidate]:
        """按来源、属性与位置去重；同文不同 bbox 保留为多个候选。"""
        deduped: dict[tuple[object, ...], PIICandidate] = {}
        for candidate in candidates:
            bbox_key = self._bbox_dedup_key(candidate.bbox)
            span_key = (candidate.block_id, candidate.span_start, candidate.span_end)
            stable_text = candidate.normalized_source.canonical if candidate.normalized_source else candidate.normalized_text
            key = (candidate.source.value, stable_text, candidate.attr_type.value, bbox_key, span_key)
            previous = deduped.get(key)
            if previous is None:
                deduped[key] = candidate
                continue
            if previous.normalized_source is None and candidate.normalized_source is not None:
                previous.normalized_source = candidate.normalized_source
            if previous.canonical_source_text is None and candidate.canonical_source_text is not None:
                previous.canonical_source_text = candidate.canonical_source_text
            if not previous.normalized_text and candidate.normalized_text:
                previous.normalized_text = candidate.normalized_text
            previous.metadata = self._merge_metadata(previous, candidate)
        return list(deduped.values())

    def _bbox_dedup_key(self, bbox) -> tuple[object, ...]:
        """生成用于去重的 bbox 键。"""
        if bbox is None:
            return (None,)
        return (bbox.x, bbox.y, bbox.width, bbox.height)

    def _merge_metadata(self, left: PIICandidate, right: PIICandidate) -> dict[str, list[str]]:
        """合并候选元信息。"""
        merged: dict[str, list[str]] = {}
        for source in (left.metadata, right.metadata):
            for key, values in source.items():
                merged[key] = sorted(set(merged.get(key, [])) | set(values))
        return merged
