"""Prompt 渲染器实现。"""

from privacyguard.domain.enums import ActionType, PIISourceType
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import ImageLike, OCRTextBlock
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


def _record_metadata_from_action(action) -> dict[str, str]:
    metadata = {"reason": action.reason}
    normalized = [
        str(value).strip().lower()
        for value in action.metadata.get("name_component", [])
        if str(value).strip()
    ]
    for preferred in ("full", "family", "given", "alias", "middle"):
        if preferred in normalized:
            metadata["name_component"] = preferred
            break
    return metadata


class PromptRenderer:
    """应用决策计划到 prompt 与 screenshot 的统一渲染器。"""

    def __init__(self, screenshot_renderer: ScreenshotRenderer | None = None) -> None:
        """初始化文本渲染器并注入截图渲染器。"""
        self.screenshot_renderer = screenshot_renderer or ScreenshotRenderer()

    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        """优先按 span 渲染 prompt 文本，并产出替换记录。"""
        applied_records = self._build_records_from_plan(plan)
        prompt_records = [record for record in applied_records if record.source == PIISourceType.PROMPT]
        sanitized = self._render_prompt_text(prompt_text, prompt_records)
        return sanitized, applied_records

    def render_image(
        self,
        image: ImageLike,
        plan: DecisionPlan,
        ocr_blocks: list[OCRTextBlock] | None = None,
    ) -> ImageLike:
        """按决策计划渲染截图。"""
        return self.screenshot_renderer.render(image=image, plan=plan, ocr_blocks=ocr_blocks)

    def _build_records_from_plan(self, plan: DecisionPlan) -> list[ReplacementRecord]:
        """把决策动作转换为共享替换记录。"""
        records: list[ReplacementRecord] = []
        for action in plan.actions:
            if action.action_type == ActionType.KEEP:
                continue
            source_text = action.source_text or ""
            canonical_source_text = action.canonical_source_text or None
            replacement_text = action.replacement_text or ""
            if not source_text or not replacement_text:
                continue
            records.append(
                ReplacementRecord(
                    session_id=plan.session_id,
                    turn_id=plan.turn_id,
                    candidate_id=action.candidate_id,
                    source_text=source_text,
                    normalized_source=action.normalized_source,
                    canonical_source_text=canonical_source_text,
                    replacement_text=replacement_text,
                    attr_type=action.attr_type,
                    action_type=action.action_type,
                    bbox=action.bbox,
                    block_id=action.block_id,
                    span_start=action.span_start,
                    span_end=action.span_end,
                    persona_id=action.persona_id,
                    source=action.source,
                    entity_id=action.entity_id,
                    metadata=_record_metadata_from_action(action),
                )
            )
        return records

    def _render_prompt_text(self, prompt_text: str, records: list[ReplacementRecord]) -> str:
        """严格按 decision span 切替；缺 span 的记录视为数据问题直接断言失败。"""
        # 缺 span 的记录在新管线里属于配置错误（detector 主路径已稳定输出 span）；
        # 直接抛错，避免兜底正则路径再次复活。
        for record in records:
            if record.source_text and record.replacement_text and (
                record.span_start is None or record.span_end is None
            ):
                raise AssertionError(
                    f"PromptRenderer requires span for record candidate_id={record.candidate_id!r}; "
                    "fallback regex path has been removed."
                )

        valid_records = [
            record for record in records if self._is_valid_span_record(prompt_text, record)
        ]
        span_records = self._select_non_overlapping_records(prompt_text, valid_records)
        sanitized = prompt_text
        for record in sorted(span_records, key=lambda item: item.span_start or 0, reverse=True):
            start = record.span_start or 0
            end = record.span_end or start
            sanitized = sanitized[:start] + record.replacement_text + sanitized[end:]
        return sanitized

    def _select_non_overlapping_records(
        self,
        prompt_text: str,
        records: list[ReplacementRecord],
    ) -> list[ReplacementRecord]:
        """优先保留更长的 prompt span，避免重复替换同一区间。"""
        ranked = sorted(
            records,
            key=lambda item: (-(item.span_end - item.span_start), item.span_start),
        )
        selected: list[ReplacementRecord] = []
        occupied: list[tuple[int, int]] = []
        for record in ranked:
            start = record.span_start or 0
            end = record.span_end or start
            if any(not (end <= used_start or start >= used_end) for used_start, used_end in occupied):
                continue
            if not self._is_valid_span_record(prompt_text, record):
                continue
            selected.append(record)
            occupied.append((start, end))
        return selected

    def _is_valid_span_record(self, prompt_text: str, record: ReplacementRecord) -> bool:
        """校验 span 是否能安全应用到 prompt 原文。"""
        if record.span_start is None or record.span_end is None:
            return False
        start = record.span_start
        end = record.span_end
        if start < 0 or end <= start or end > len(prompt_text):
            return False
        if not record.source_text or not record.replacement_text:
            return False
        return prompt_text[start:end] == record.source_text
