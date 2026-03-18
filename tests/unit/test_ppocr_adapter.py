"""PP-OCRv5 适配层测试。"""

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter, _parse_paddle_result
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
            "score": 0.9,
            "line_id": 0,
        }
    ]
