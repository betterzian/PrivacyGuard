"""还原流程编排。"""

from privacyguard.api.dto import RestoreRequest, RestoreResponse
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.restoration_module import RestorationModule


def run_restore_pipeline(
    request: RestoreRequest,
    mapping_store: MappingStore,
    restoration_module: RestorationModule,
) -> RestoreResponse:
    """仅按当前 turn 的映射执行还原。"""
    current_turn_records = mapping_store.get_replacements(request.session_id, request.turn_id)
    combined_records = _merge_records(current_turn_records=current_turn_records)
    restored_text, restored_slots = restoration_module.restore(request.cloud_text, combined_records)
    return RestoreResponse(
        restored_text=restored_text,
        restored_slots=restored_slots,
        metadata={
            "turn_records": str(len(current_turn_records)),
            "resolved_records": str(len(combined_records)),
        },
    )


def _merge_records(current_turn_records):
    """对当前 turn 记录按 placeholder 去重。"""
    by_placeholder = {}
    ordered_current = sorted(current_turn_records, key=lambda item: len(item.replacement_text), reverse=True)
    for record in ordered_current:
        if record.replacement_text:
            by_placeholder[record.replacement_text] = record
    merged = list(by_placeholder.values())
    merged.sort(key=lambda item: (item.turn_id, len(item.replacement_text)), reverse=True)
    return merged
