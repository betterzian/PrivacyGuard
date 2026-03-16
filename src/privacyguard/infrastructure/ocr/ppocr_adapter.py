"""PP-OCR 适配层实现。"""

from pathlib import Path
from typing import Any, Protocol

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.utils.image import ensure_supported_image_input


class OCRBackendProtocol(Protocol):
    """定义 OCR 后端最小推理协议。"""

    def infer(self, image: Any) -> list[dict[str, Any]]:
        """执行 OCR 推理并返回中间结果。"""


class MockOCRBackend:
    """无真实模型时的回退 OCR 后端。"""

    def infer(self, image: Any) -> list[dict[str, Any]]:
        """在回退模式下返回空结果。"""
        return []


class PPOCREngineAdapter:
    """统一 OCR 接口适配器，兼容真实与回退后端。"""

    def __init__(self, backend: OCRBackendProtocol | None = None) -> None:
        """初始化适配器并注入后端实现。"""
        self.backend = backend or MockOCRBackend()

    def extract(self, image: Any) -> list[OCRTextBlock]:
        """将输入图像转换为标准 OCRTextBlock 列表。"""
        normalized_image = ensure_supported_image_input(image)
        backend_output = self.backend.infer(normalized_image)
        return self._to_ocr_blocks(backend_output)

    def _to_ocr_blocks(self, backend_output: list[dict[str, Any]]) -> list[OCRTextBlock]:
        """将后端结果映射为领域模型。"""
        blocks: list[OCRTextBlock] = []
        for index, item in enumerate(backend_output):
            text = str(item.get("text", "")).strip()
            if not text:
                continue
            bbox_data = item.get("bbox", {})
            bbox = self._to_bbox(bbox_data)
            score = float(item.get("score", 1.0))
            line_id = int(item.get("line_id", index))
            blocks.append(
                OCRTextBlock(
                    text=text,
                    bbox=bbox,
                    score=max(0.0, min(1.0, score)),
                    line_id=max(0, line_id),
                    source="screenshot",
                )
            )
        return blocks

    def _to_bbox(self, bbox_data: Any) -> BoundingBox:
        """将后端 bbox 数据转换为统一 BoundingBox。"""
        if isinstance(bbox_data, dict):
            return BoundingBox(
                x=int(bbox_data.get("x", 0)),
                y=int(bbox_data.get("y", 0)),
                width=max(1, int(bbox_data.get("width", 1))),
                height=max(1, int(bbox_data.get("height", 1))),
            )
        if isinstance(bbox_data, (list, tuple)) and len(bbox_data) == 4:
            x, y, width, height = bbox_data
            return BoundingBox(
                x=max(0, int(x)),
                y=max(0, int(y)),
                width=max(1, int(width)),
                height=max(1, int(height)),
            )
        return BoundingBox(x=0, y=0, width=1, height=1)


def load_ppocr_backend(model_name: str = "ppocr_v5") -> OCRBackendProtocol:
    """加载 OCR 后端，当前默认返回回退后端。"""
    _ = model_name
    return MockOCRBackend()


def normalize_image_path(path: str | Path) -> Path:
    """将路径标准化为绝对路径。"""
    return Path(path).resolve()

