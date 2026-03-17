"""截图填充策略抽象接口（与 decision 解耦方式一致：按模式注册实现类）。"""

from typing import Any, Protocol

from privacyguard.domain.models.decision import DecisionPlan


class ScreenshotFillStrategy(Protocol):
    """定义截图 PII 区域填充策略：对图像做填充并返回每格是否已填充（跳过矩形绘制）。"""

    def apply(
        self,
        image: Any,
        plan: DecisionPlan,
        actions_list: list[Any],
    ) -> tuple[Any, list[bool]]:
        """
        对图像应用填充逻辑。
        :param image: 原始截图（PIL 或可转为 PIL 的输入）
        :param plan: 决策计划
        :param actions_list: 本帧要绘制的 action 列表（与 plan.actions 子集、顺序一致）
        :return: (填充后的图像, skip_fill_per_action)，skip_fill[i]=True 表示第 i 格已由策略填充，无需再画矩形
        """
        ...
