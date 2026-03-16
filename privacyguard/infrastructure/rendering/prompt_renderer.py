"""Prompt 渲染器实现。"""

import re

from privacyguard.domain.enums import ActionType, PIISourceType
from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import ImageLike
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


class PromptRenderer:
    """应用决策计划到 prompt 与 screenshot 的统一渲染器。"""

    def __init__(self, screenshot_renderer: ScreenshotRenderer | None = None) -> None:
        """初始化文本渲染器并注入截图渲染器。"""
        self.screenshot_renderer = screenshot_renderer or ScreenshotRenderer()

    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        """按长度倒序策略渲染文本并产出替换记录。"""
        applied_records = self._build_records_from_plan(plan)
        sanitized = prompt_text
        sorted_records = sorted(
            [record for record in applied_records if record.source_text and record.replacement_text],
            key=lambda item: len(item.source_text),
            reverse=True,
        )
        for record in sorted_records:
            pattern = self._build_boundary_pattern(record.source_text)
            sanitized = re.sub(pattern, record.replacement_text, sanitized)
        return sanitized, applied_records

    def render_image(self, image: ImageLike, plan: DecisionPlan) -> ImageLike:
        """按决策计划渲染截图。"""
        return self.screenshot_renderer.render(image=image, plan=plan)

    def _build_records_from_plan(self, plan: DecisionPlan) -> list[ReplacementRecord]:
        """把决策动作转换为共享替换记录。"""
        records: list[ReplacementRecord] = []
        for action in plan.actions:
            if action.action_type == ActionType.KEEP:
                continue
            source_text = action.source_text or ""
            replacement_text = action.replacement_text or ""
            if not source_text or not replacement_text:
                continue
            records.append(
                ReplacementRecord(
                    session_id=plan.session_id,
                    turn_id=plan.turn_id,
                    candidate_id=action.candidate_id,
                    source_text=source_text,
                    replacement_text=replacement_text,
                    attr_type=action.attr_type,
                    action_type=action.action_type,
                    bbox=action.bbox,
                    persona_id=action.persona_id,
                    source=PIISourceType.PROMPT,
                    metadata={"reason": action.reason},
                )
            )
        return records

    def _build_boundary_pattern(self, source_text: str) -> str:
        """构建兼顾中英文的保守替换模式。"""
        escaped = re.escape(source_text)
        if source_text.isascii() and source_text.replace("_", "").isalnum():
            return rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"
        return escaped

