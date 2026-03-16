"""OCR 引擎抽象接口。"""

from typing import Protocol

from privacyguard.domain.models.ocr import ImageLike, OCRTextBlock


class OCREngine(Protocol):
    """定义 OCR 模块最小职责接口。"""

    def extract(self, image: ImageLike) -> list[OCRTextBlock]:
        """从截图中提取结构化文本块。"""
