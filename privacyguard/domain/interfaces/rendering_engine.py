"""渲染引擎抽象接口。"""

from typing import Protocol

from privacyguard.domain.models.decision import DecisionPlan
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import ImageLike


class RenderingEngine(Protocol):
    """定义渲染模块最小职责接口。"""

    def render_text(self, prompt_text: str, plan: DecisionPlan) -> tuple[str, list[ReplacementRecord]]:
        """根据决策计划渲染脱敏文本。"""

    def render_image(self, image: ImageLike, plan: DecisionPlan) -> ImageLike:
        """根据决策计划渲染脱敏截图。"""
