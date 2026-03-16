"""OCR 领域模型定义。"""

from typing import Any

from pydantic import BaseModel, Field

ImageLike = Any


class BoundingBox(BaseModel):
    """表示截图中的矩形区域。"""

    x: int = Field(ge=0)
    y: int = Field(ge=0)
    width: int = Field(gt=0)
    height: int = Field(gt=0)


class OCRTextBlock(BaseModel):
    """表示 OCR 输出的结构化文本块。"""

    text: str
    bbox: BoundingBox
    score: float = Field(ge=0.0, le=1.0, default=1.0)
    line_id: int = Field(ge=0, default=0)
    source: str = "screenshot"

