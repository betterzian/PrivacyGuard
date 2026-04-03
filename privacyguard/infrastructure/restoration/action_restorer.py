"""动作文本还原模块实现。"""

from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.mapping import ReplacementRecord


class ActionRestorer:
    """根据替换记录将云端文本恢复为真实值。"""

    def restore(self, cloud_text: str, records: list[ReplacementRecord]) -> tuple[str, list[RestoredSlot]]:
        """按优先级应用映射并返回恢复后的槽位命中。"""
        ordered = sorted(
            records,
            key=lambda item: (item.turn_id, len(item.replacement_text)),
            reverse=True,
        )
        restored_text = cloud_text
        restored_slots: list[RestoredSlot] = []
        seen_placeholders: set[str] = set()
        for record in ordered:
            if not record.replacement_text:
                continue
            if record.replacement_text in seen_placeholders:
                continue
            if record.replacement_text not in restored_text:
                continue
            source_value = record.normalized_source.raw_text if record.normalized_source else record.source_text
            restored_text = restored_text.replace(record.replacement_text, source_value)
            seen_placeholders.add(record.replacement_text)
            restored_slots.append(
                RestoredSlot(
                    attr_type=record.attr_type.value,
                    value=source_value,
                    source_placeholder=record.replacement_text,
                )
            )
        return restored_text, restored_slots
