"""PII 候选归一化与去重服务。"""

from hashlib import md5

from privacyguard.domain.models.pii import PIICandidate


class CandidateResolverService:
    """负责候选实体去重、冲突合并与稳定 ID 生成。"""

    def build_candidate_id(self, detector_mode: str, source: str, normalized_text: str, attr_type: str) -> str:
        """根据关键字段生成稳定候选 ID。"""
        raw = f"{detector_mode}|{source}|{normalized_text}|{attr_type}"
        return md5(raw.encode("utf-8")).hexdigest()

    def resolve_candidates(self, candidates: list[PIICandidate]) -> list[PIICandidate]:
        """按来源、属性与位置去重；同文不同 bbox 保留为多个候选（屏幕多处同一 PII 都会打码）。"""
        deduped: dict[tuple, PIICandidate] = {}
        for candidate in candidates:
            bbox_key = self._bbox_dedup_key(candidate.bbox)
            key = (candidate.source.value, candidate.normalized_text, candidate.attr_type.value, bbox_key)
            previous = deduped.get(key)
            if previous is None:
                deduped[key] = candidate
                continue
            if candidate.confidence > previous.confidence:
                merged = candidate.model_copy(deep=True)
                merged.metadata = self._merge_metadata(previous, candidate)
                deduped[key] = merged
            else:
                previous.metadata = self._merge_metadata(previous, candidate)
        return list(deduped.values())

    def _bbox_dedup_key(self, bbox) -> tuple:
        """生成用于去重的 bbox 键：同位置视为同一候选，不同位置保留多个。"""
        if bbox is None:
            return (None,)
        return (bbox.x, bbox.y, bbox.width, bbox.height)

    def _merge_metadata(self, left: PIICandidate, right: PIICandidate) -> dict[str, list[str]]:
        """合并候选元信息并记录命中来源。"""
        left_keys = left.metadata.get("matched_by", [])
        right_keys = right.metadata.get("matched_by", [])
        merged = sorted(set(left_keys) | set(right_keys))
        return {"matched_by": merged}

