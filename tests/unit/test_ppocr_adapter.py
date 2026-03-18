"""PP-OCRv5 适配层测试。"""

import pytest

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint
from privacyguard.infrastructure.ocr.ppocr_adapter import (
    MissingDependencyOCRBackend,
    PPOCREngineAdapter,
    _parse_paddle_result,
)
from privacyguard.utils.image import ensure_supported_image_input


class _FakeBackend:
    def __init__(self, infer_result=None, predict_result=None) -> None:
        self.infer_result = infer_result if infer_result is not None else []
        self.predict_result = predict_result if predict_result is not None else []
        self.predict_inputs = []
        self.infer_inputs = []

    def predict(self, input):
        self.predict_inputs.append(input)
        return self.predict_result

    def infer(self, image):
        self.infer_inputs.append(image)
        return self.infer_result


class _FakeResult:
    def __init__(self, payload) -> None:
        self._payload = payload

    def json(self):
        return self._payload


def test_ensure_supported_image_input_accepts_remote_url() -> None:
    url = "https://paddle-model-ecology.bj.bcebos.com/paddlex/imgs/demo_image/general_ocr_002.png"

    assert ensure_supported_image_input(url) == url


def test_adapter_predict_delegates_to_backend() -> None:
    backend = _FakeBackend(predict_result=["ok"])
    adapter = PPOCREngineAdapter(backend=backend)

    result = adapter.predict(input="https://example.com/demo.png")

    assert result == ["ok"]
    assert backend.predict_inputs == ["https://example.com/demo.png"]


def test_adapter_extract_keeps_predict_input_and_maps_blocks() -> None:
    backend = _FakeBackend(
        infer_result=[
            {"text": "张三", "bbox": {"x": 10, "y": 20, "width": 30, "height": 40}, "score": 0.98, "line_id": 3}
        ]
    )
    adapter = PPOCREngineAdapter(backend=backend)

    blocks = adapter.extract("https://example.com/demo.png")

    assert backend.infer_inputs == ["https://example.com/demo.png"]
    assert blocks == [
        OCRTextBlock(
            text="张三",
            bbox=BoundingBox(x=10, y=20, width=30, height=40),
            block_id="ocr-3-0-10-20-30-40",
            score=0.98,
            line_id=3,
            source="screenshot",
        )
    ]


def test_parse_paddle_result_supports_json_method_payload() -> None:
    result = _FakeResult(
        {
            "rec_texts": ["海淀区"],
            "rec_scores": [0.9],
            "rec_boxes": [[[0, 0], [10, 0], [10, 10], [0, 10]]],
        }
    )

    parsed = _parse_paddle_result(result)

    assert parsed == [
        {
            "text": "海淀区",
            "bbox": {"x": 0, "y": 0, "width": 10, "height": 10},
            "polygon": [
                {"x": 0.0, "y": 0.0},
                {"x": 10.0, "y": 0.0},
                {"x": 10.0, "y": 10.0},
                {"x": 0.0, "y": 10.0},
            ],
            "rotation_degrees": 0.0,
            "score": 0.9,
            "line_id": 0,
        }
    ]


def test_adapter_extract_maps_polygon_and_rotation() -> None:
    backend = _FakeBackend(
        infer_result=[
            {
                "text": "张三",
                "polygon": [
                    {"x": 10.0, "y": 10.0},
                    {"x": 50.0, "y": 20.0},
                    {"x": 48.0, "y": 32.0},
                    {"x": 8.0, "y": 22.0},
                ],
                "rotation_degrees": 14.036243467926479,
                "score": 0.96,
                "line_id": 1,
            }
        ]
    )
    adapter = PPOCREngineAdapter(backend=backend)

    blocks = adapter.extract("https://example.com/rotated.png")

    assert len(blocks) == 1
    assert blocks[0].text == "张三"
    assert blocks[0].bbox == BoundingBox(x=8, y=10, width=42, height=22)
    assert blocks[0].block_id == "ocr-1-0-8-10-42-22"
    assert blocks[0].polygon == [
        PolygonPoint(x=10.0, y=10.0),
        PolygonPoint(x=50.0, y=20.0),
        PolygonPoint(x=48.0, y=32.0),
        PolygonPoint(x=8.0, y=22.0),
    ]
    assert blocks[0].rotation_degrees == pytest.approx(14.036243467926479)
    assert blocks[0].score == 0.96
    assert blocks[0].line_id == 1
    assert blocks[0].source == "screenshot"


def test_missing_dependency_backend_fails_fast_with_install_hint() -> None:
    adapter = PPOCREngineAdapter(backend=MissingDependencyOCRBackend())

    with pytest.raises(RuntimeError, match="paddleocr"):
        adapter.extract("https://example.com/demo.png")
