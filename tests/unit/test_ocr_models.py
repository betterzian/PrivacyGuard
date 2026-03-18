"""OCR 领域模型的几何归一化测试。"""

import pytest
from pydantic import ValidationError

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint


def test_ocr_text_block_derives_bbox_from_polygon_when_bbox_omitted() -> None:
    block = OCRTextBlock(
        text="张三",
        polygon=[
            PolygonPoint(x=10.2, y=10.0),
            PolygonPoint(x=50.0, y=20.1),
            PolygonPoint(x=48.3, y=32.0),
            PolygonPoint(x=8.0, y=22.2),
        ],
    )

    assert block.bbox == BoundingBox(x=8, y=10, width=42, height=22)


def test_ocr_text_block_prefers_polygon_over_conflicting_bbox() -> None:
    block = OCRTextBlock(
        text="张三",
        bbox=BoundingBox(x=0, y=0, width=10, height=10),
        polygon=[
            PolygonPoint(x=10.0, y=10.0),
            PolygonPoint(x=50.0, y=20.0),
            PolygonPoint(x=48.0, y=32.0),
            PolygonPoint(x=8.0, y=22.0),
        ],
    )

    assert block.bbox == BoundingBox(x=8, y=10, width=42, height=22)


def test_ocr_text_block_requires_bbox_or_polygon() -> None:
    with pytest.raises(ValidationError, match="bbox"):
        OCRTextBlock(text="张三")
