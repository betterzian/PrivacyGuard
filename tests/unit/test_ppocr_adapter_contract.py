"""PP-OCR 适配器契约测试。"""

from pathlib import Path

import pytest

from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter


class FakeOCRBackend:
    """测试用 OCR 后端桩。"""

    def infer(self, image: object) -> list[dict[str, object]]:
        """返回固定格式的 OCR 结果。"""
        _ = image
        return [
            {
                "text": "张三",
                "bbox": {"x": 1, "y": 2, "width": 30, "height": 12},
                "score": 0.93,
                "line_id": 7,
            }
        ]


def test_ppocr_adapter_returns_ocr_text_blocks(tmp_path: Path) -> None:
    """验证适配器输出符合 OCRTextBlock 契约。"""
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(b"fake-image")
    adapter = PPOCREngineAdapter(backend=FakeOCRBackend())

    blocks = adapter.extract(str(image_path))

    assert len(blocks) == 1
    assert blocks[0].text == "张三"
    assert blocks[0].bbox.width == 30
    assert blocks[0].source == "screenshot"


def test_ppocr_adapter_raises_clear_error_for_invalid_input() -> None:
    """验证非法图像输入时抛出清晰异常。"""
    adapter = PPOCREngineAdapter(backend=FakeOCRBackend())
    with pytest.raises(ValueError):
        adapter.extract(12345)

