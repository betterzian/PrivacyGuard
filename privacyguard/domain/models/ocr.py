"""OCR 领域模型定义。"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, Field, model_validator

ImageLike = Any


class PolygonPoint(BaseModel):
    """表示 OCR 多边形框上的一个顶点。"""

    x: float
    y: float


class BoundingBox(BaseModel):
    """表示截图中的矩形区域。"""

    x: int = Field(ge=0)
    y: int = Field(ge=0)
    width: int = Field(gt=0)
    height: int = Field(gt=0)

    @classmethod
    def from_polygon(cls, polygon: list[PolygonPoint] | list[dict[str, float]] | None) -> "BoundingBox" | None:
        """从 polygon 推导一个兼容旧链路使用的轴对齐 bbox。"""
        if not polygon:
            return None
        xs: list[float] = []
        ys: list[float] = []
        for point in polygon:
            if isinstance(point, PolygonPoint):
                xs.append(point.x)
                ys.append(point.y)
                continue
            if isinstance(point, dict) and "x" in point and "y" in point:
                xs.append(float(point["x"]))
                ys.append(float(point["y"]))
        if not xs or not ys:
            return None
        min_x = math.floor(min(xs))
        min_y = math.floor(min(ys))
        max_x = math.ceil(max(xs))
        max_y = math.ceil(max(ys))
        return cls(
            x=max(0, int(min_x)),
            y=max(0, int(min_y)),
            width=max(1, int(max_x - min_x)),
            height=max(1, int(max_y - min_y)),
        )


class OCRTextBlock(BaseModel):
    """表示 OCR 输出的结构化文本块。"""

    text: str
    bbox: BoundingBox | None = None
    block_id: str | None = None
    polygon: list[PolygonPoint] | None = None
    rotation_degrees: float = 0.0
    score: float = Field(ge=0.0, le=1.0, default=1.0)
    line_id: int = Field(ge=0, default=0)
    source: str = "screenshot"

    @model_validator(mode="after")
    def _normalize_geometry(self) -> "OCRTextBlock":
        """优先以 polygon 作为真相源，并同步生成兼容字段 bbox。"""
        derived_bbox = BoundingBox.from_polygon(self.polygon)
        if derived_bbox is not None:
            self.bbox = derived_bbox
            return self
        if self.bbox is None:
            raise ValueError("OCRTextBlock requires either polygon or bbox.")
        return self
