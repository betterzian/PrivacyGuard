"""截图渲染器实现。填充逻辑由注入的 ScreenshotFillStrategy 提供（与 decision 一致：按模式注册、工厂构建）。"""

from dataclasses import dataclass
import logging
import math
from pathlib import Path
from typing import Any

from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.interfaces.screenshot_fill_strategy import ScreenshotFillStrategy
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint
from privacyguard.infrastructure.rendering.fill_strategies import MixFillStrategy
from privacyguard.utils.pii_value import (
    address_display_units,
    name_component_order,
    name_display_units,
    parse_address_components,
    parse_name_components,
)

# 常见系统字体路径。优先贴近 Android 默认无衬线风格；本机缺少 Android 字体时回退到 macOS 的中文黑体。
_CJK_FONT_PATHS = [
    "/system/fonts/NotoSansCJK-Regular.ttc",
    "/system/fonts/NotoSansSC-Regular.otf",
    "/system/fonts/NotoSansCJKsc-Regular.otf",
    "/system/fonts/DroidSansFallback.ttf",
    "/system/fonts/SourceHanSansSC-Regular.otf",
    "C:/Windows/Fonts/msyh.ttc",   # Windows 微软雅黑
    "C:/Windows/Fonts/msyhbd.ttc",
    "C:/Windows/Fonts/simhei.ttf",
    "/Library/Fonts/Roboto-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/System/Library/Fonts/STHeiti Medium.ttc",
    "/System/Library/Fonts/STHeiti Light.ttc",
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    "/System/Library/Fonts/PingFang.ttc",
    "/System/Library/Fonts/Supplemental/Songti.ttc",
]
_LATIN_FONT_PATHS = [
    "/system/fonts/Roboto-Regular.ttf",
    "/system/fonts/RobotoFlex-Regular.ttf",
    "/Library/Fonts/Roboto-Regular.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
LOGGER = logging.getLogger(__name__)


def _contains_cjk_text(text: str | None) -> bool:
    if not text:
        return False
    return any(
        "\u3400" <= char <= "\u4dbf"
        or "\u4e00" <= char <= "\u9fff"
        or "\uf900" <= char <= "\ufaff"
        for char in text
    )


def _font_path_candidates(sample_text: str | None = None) -> tuple[str, ...]:
    ordered: list[str] = []
    if _contains_cjk_text(sample_text):
        ordered.extend(_CJK_FONT_PATHS)
        ordered.extend(_LATIN_FONT_PATHS)
    else:
        ordered.extend(_LATIN_FONT_PATHS)
        ordered.extend(_CJK_FONT_PATHS)
    return tuple(dict.fromkeys(ordered))


def _get_font_path(sample_text: str | None = None) -> Path | None:
    """获取可用的 TrueType 字体路径。"""
    for p in _font_path_candidates(sample_text):
        path = Path(p)
        if path.exists():
            return path
    return None


@dataclass
class _DrawItem:
    """截图渲染阶段的实际绘制单元。"""

    bbox: BoundingBox
    text: str
    block_id: str | None = None
    original_text: str | None = None
    polygon: list[PolygonPoint] | None = None
    rotation_degrees: float = 0.0


@dataclass
class _ResolvedAction:
    """可安全应用到 OCR 原文的替换动作。"""

    action: DecisionAction
    start: int
    end: int


@dataclass
class _TextLayout:
    """文本布局结果。"""

    mask: Any
    rendered_text: str
    font_size: int
    char_spacing: float = 0.0
    scale_x: float = 1.0
    scale_y: float = 1.0

__all__ = [name for name in globals() if not name.startswith("__")]
