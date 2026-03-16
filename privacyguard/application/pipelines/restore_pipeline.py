"""还原流程编排。"""

from privacyguard.api.dto import RestoreRequest, RestoreResponse
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.restoration_module import RestorationModule


def run_restore_pipeline(
    request: RestoreRequest,
    mapping_store: MappingStore,
    restoration_module: RestorationModule,
) -> RestoreResponse:
    """按 turn 优先、session 回溯策略执行还原。"""
    current_turn_records = mapping_store.get_replacements(request.session_id, request.turn_id)
    session_records = mapping_store.get_replacements(request.session_id)
    combined_records = _merge_records(current_turn_records=current_turn_records, session_records=session_records)
    restored_text, restored_slots = restoration_module.restore(request.cloud_text, combined_records)
    return RestoreResponse(
        restored_text=restored_text,
        restored_slots=restored_slots,
        metadata={
            "turn_records": str(len(current_turn_records)),
            "session_records": str(len(session_records)),
            "resolved_records": str(len(combined_records)),
        },
    )


def _merge_records(current_turn_records, session_records):
    """合并当前轮与会话级记录并保证当前轮优先。"""
    by_key = {}
    for record in current_turn_records:
        by_key[(record.turn_id, record.candidate_id)] = record
    ordered_session = sorted(session_records, key=lambda item: item.turn_id, reverse=True)
    for record in ordered_session:
        key = (record.turn_id, record.candidate_id)
        if key not in by_key:
            by_key[key] = record
    merged = list(by_key.values())
    merged.sort(key=lambda item: (item.turn_id, len(item.replacement_text)), reverse=True)
    return merged

