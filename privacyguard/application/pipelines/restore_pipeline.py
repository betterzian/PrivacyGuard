"""restore 主链编排。

restore 的边界保持收敛：

- 仅基于当前 turn 的 `ReplacementRecord` 恢复文本
- 不扩展为全会话 restore
- 不承担 DSL restore 或对 `de_model` 决策的反向推理

与当前动作语义的兼容约定：

- `KEEP` 不产生替换文本，因此不要求特殊恢复逻辑
- `GENERICIZE` 继续通过 `replacement record` 恢复
- `PERSONA_SLOT` 继续通过 `replacement record` 恢复
- 旧数据若仍使用 `LABEL` 作为动作名别名，则按 `GENERICIZE` 兼容处理
"""

from __future__ import annotations

from privacyguard.api.dto import RestoreRequest, RestoreResponse
from privacyguard.domain.enums import ActionType
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.restoration_module import RestorationModule
from privacyguard.domain.models.mapping import ReplacementRecord


def run_restore_pipeline(
    request: RestoreRequest,
    mapping_store: MappingStore,
    restoration_module: RestorationModule,
) -> RestoreResponse:
    """仅按当前 turn 的替换记录执行还原。"""
    current_turn_records = mapping_store.get_replacements(request.session_id, request.turn_id)
    restorable_records = _merge_records(current_turn_records=current_turn_records)
    restored_text, restored_slots = restoration_module.restore(request.cloud_text, restorable_records)
    return RestoreResponse(
        restored_text=restored_text,
        restored_slots=restored_slots,
        metadata={
            "turn_records": str(len(current_turn_records)),
            "resolved_records": str(len(restorable_records)),
        },
    )


def _merge_records(current_turn_records: list[ReplacementRecord]) -> list[ReplacementRecord]:
    """对当前 turn 的可恢复记录按 placeholder 去重。

    restore 是 replacement-record 驱动的：

    - `KEEP` 记录不进入恢复集合
    - `GENERICIZE` / `PERSONA_SLOT` 记录进入恢复集合
    - 旧别名 `LABEL` 视作 `GENERICIZE`
    """
    by_placeholder: dict[str, ReplacementRecord] = {}
    ordered_current = sorted(
        current_turn_records,
        key=lambda item: len(getattr(item, "replacement_text", "") or ""),
        reverse=True,
    )
    for record in ordered_current:
        if not _is_restorable_record(record):
            continue
        replacement_text = getattr(record, "replacement_text", "") or ""
        by_placeholder[replacement_text] = record
    merged = list(by_placeholder.values())
    merged.sort(
        key=lambda item: (item.turn_id, len(getattr(item, "replacement_text", "") or "")),
        reverse=True,
    )
    return merged


def _is_restorable_record(record: ReplacementRecord) -> bool:
    """判断记录是否应参与当前 turn restore。"""
    replacement_text = getattr(record, "replacement_text", "") or ""
    if not replacement_text:
        return False
    action_name = _normalized_action_name(getattr(record, "action_type", None))
    if action_name == ActionType.KEEP.value:
        return False
    if action_name in {ActionType.GENERICIZE.value, ActionType.PERSONA_SLOT.value}:
        return True
    # restore 以 replacement record 为主；未知旧动作值若携带 replacement_text，仍保守兼容。
    return True


def _normalized_action_name(action_type: object | None) -> str | None:
    """将动作名归一化为当前工程枚举名，并兼容旧别名。"""
    if action_type is None:
        return None
    raw = action_type.value if isinstance(action_type, ActionType) else str(action_type).strip()
    if not raw:
        return None
    normalized = raw.upper()
    if normalized == "LABEL":
        return ActionType.GENERICIZE.value
    return normalized
