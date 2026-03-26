"""决策动作到映射记录的拼装服务。"""

from privacyguard.domain.enums import ActionType
from privacyguard.domain.models.decision import DecisionAction
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.pii import PIICandidate


def _record_metadata_from_action(action: DecisionAction) -> dict[str, str]:
    metadata = {"reason": action.reason}
    normalized = [
        str(value).strip().lower()
        for value in action.metadata.get("name_component", [])
        if str(value).strip()
    ]
    for preferred in ("family", "given", "middle", "full"):
        if preferred in normalized:
            metadata["name_component"] = preferred
            break
    return metadata


class ReplacementService:
    """将 DecisionAction 与候选实体转换为 ReplacementRecord。"""

    def build_records(
        self,
        session_id: str,
        turn_id: int,
        actions: list[DecisionAction],
        candidates: list[PIICandidate],
    ) -> list[ReplacementRecord]:
        """生成可写入 mapping store 的替换记录列表。"""
        candidate_map = {candidate.entity_id: candidate for candidate in candidates}
        records: list[ReplacementRecord] = []
        for action in actions:
            if action.action_type == ActionType.KEEP:
                continue
            candidate = candidate_map.get(action.candidate_id)
            if candidate is None:
                continue
            records.append(
                ReplacementRecord(
                    session_id=session_id,
                    turn_id=turn_id,
                    candidate_id=action.candidate_id,
                    source_text=action.source_text or candidate.text,
                    canonical_source_text=action.canonical_source_text or candidate.canonical_source_text,
                    replacement_text=action.replacement_text or "",
                    attr_type=action.attr_type,
                    action_type=action.action_type,
                    bbox=action.bbox or candidate.bbox,
                    block_id=action.block_id or candidate.block_id,
                    span_start=action.span_start if action.span_start is not None else candidate.span_start,
                    span_end=action.span_end if action.span_end is not None else candidate.span_end,
                    persona_id=action.persona_id,
                    source=action.source,
                    metadata=_record_metadata_from_action(action),
                )
            )
        return records
