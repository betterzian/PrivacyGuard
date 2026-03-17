"""PP-OCR 适配层实现。"""

from pathlib import Path
from typing import Any, Protocol

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.utils.image import ensure_supported_image_input


def _image_to_predict_input(image: Any) -> Any:
    """将领域支持的图像输入转换为 PaddleOCR predict 可接受的输入。PaddleX 检测器期望 RGB 三通道，RGBA 会触发 Normalize 的 IndexError。"""
    if isinstance(image, Path):
        return str(image)
    try:
        from PIL import Image
        import numpy as np
        if isinstance(image, Image.Image):
            img = image.convert("RGB") if image.mode != "RGB" else image
            return np.array(img)
    except Exception:
        pass
    return image


def _parse_paddle_result(res: Any) -> list[dict[str, Any]]:
    """将 PaddleOCR 单条 predict 结果（Result 对象或 dict）解析为适配层中间格式。兼容 rec_* 与 dt_polys 等格式。"""
    raw = getattr(res, "json", res)
    if callable(raw):
        raw = raw()
    if isinstance(raw, str):
        import json
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        return []
    data = raw.get("res", raw)
    if not isinstance(data, dict):
        data = raw
    rec_texts = data.get("rec_texts") or []
    rec_scores = data.get("rec_scores")
    rec_boxes = data.get("rec_boxes")
    rec_polys = data.get("rec_polys")
    dt_polys = data.get("dt_polys")  # PaddleX / 新 PP-OCR 可能使用 dt_polys
    if rec_scores is not None and hasattr(rec_scores, "tolist"):
        rec_scores = rec_scores.tolist()
    if rec_boxes is not None and hasattr(rec_boxes, "tolist"):
        rec_boxes = rec_boxes.tolist()
    if rec_polys is not None and hasattr(rec_polys, "tolist"):
        rec_polys = rec_polys.tolist()
    if dt_polys is not None and hasattr(dt_polys, "tolist"):
        dt_polys = dt_polys.tolist()
    n = len(rec_texts)
    if n == 0:
        return []

    def box_to_xywh(box: Any) -> dict[str, int]:
        try:
            if isinstance(box, (list, tuple)) and len(box) >= 2:
                if isinstance(box[0], (list, tuple)):
                    xs = [p[0] for p in box if isinstance(p, (list, tuple)) and len(p) >= 2]
                    ys = [p[1] for p in box if isinstance(p, (list, tuple)) and len(p) >= 2]
                    if not xs or not ys:
                        return {"x": 0, "y": 0, "width": 1, "height": 1}
                    x1, x2 = min(xs), max(xs)
                    y1, y2 = min(ys), max(ys)
                    return {"x": max(0, int(x1)), "y": max(0, int(y1)), "width": max(1, int(x2 - x1)), "height": max(1, int(y2 - y1))}
                if len(box) == 4:
                    x1, y1, x2, y2 = int(box[0]), int(box[1]), int(box[2]), int(box[3])
                    return {"x": max(0, min(x1, x2)), "y": max(0, min(y1, y2)), "width": max(1, abs(x2 - x1)), "height": max(1, abs(y2 - y1))}
        except (IndexError, TypeError, ValueError):
            pass
        return {"x": 0, "y": 0, "width": 1, "height": 1}

    out: list[dict[str, Any]] = []
    scores = rec_scores if isinstance(rec_scores, list) else ([float(rec_scores)] * n if rec_scores is not None else [1.0] * n)
    boxes = rec_boxes or rec_polys or dt_polys
    if not boxes or not isinstance(boxes, (list, tuple)):
        boxes = [[0, 0, 1, 1]] * n
    else:
        boxes = list(boxes)
    if len(boxes) < n:
        boxes = boxes + [[0, 0, 1, 1]] * (n - len(boxes))
    for i in range(n):
        text = (rec_texts[i] if i < len(rec_texts) else "").strip() or ""
        score = float(scores[i]) if i < len(scores) else 1.0
        bbox = box_to_xywh(boxes[i]) if i < len(boxes) else {"x": 0, "y": 0, "width": 1, "height": 1}
        out.append({"text": text, "bbox": bbox, "score": score, "line_id": i})
    return out


class OCRBackendProtocol(Protocol):
    """定义 OCR 后端最小推理协议。"""

    def infer(self, image: Any) -> list[dict[str, Any]]:
        """执行 OCR 推理并返回中间结果。"""


class MockOCRBackend:
    """无真实模型时的回退 OCR 后端。"""

    def infer(self, image: Any) -> list[dict[str, Any]]:
        """在回退模式下返回空结果。"""
        return []


class PaddleOCRBackend:
    """基于 PaddleOCR PP-OCRv5 的真实推理后端。"""

    def __init__(
        self,
        use_doc_orientation_classify: bool = False,
        use_doc_unwarping: bool = False,
        use_textline_orientation: bool = False,
        **kwargs: Any,
    ) -> None:
        from paddleocr import PaddleOCR
        self._ocr = PaddleOCR(
            use_doc_orientation_classify=use_doc_orientation_classify,
            use_doc_unwarping=use_doc_unwarping,
            use_textline_orientation=use_textline_orientation,
            **kwargs,
        )

    def infer(self, image: Any) -> list[dict[str, Any]]:
        """执行 PP-OCRv5 推理，返回适配层中间结果。"""
        predict_input = _image_to_predict_input(image)
        result = self._ocr.predict(input=predict_input)
        items: list[dict[str, Any]] = []
        if result is None:
            return items
        if isinstance(result, dict):
            result = [result]
        for res in result:
            try:
                items.extend(_parse_paddle_result(res))
            except (IndexError, TypeError, KeyError, ValueError) as e:
                import warnings
                warnings.warn(f"PP-OCR result parse skip one item: {e}", UserWarning)
        return items


class PPOCREngineAdapter:
    """统一 OCR 接口适配器，兼容真实与回退后端。"""

    def __init__(self, backend: OCRBackendProtocol | None = None) -> None:
        """初始化适配器并注入后端实现；未注入时自动尝试加载 PP-OCRv5 后端。"""
        self.backend = backend if backend is not None else load_ppocr_backend()

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


def load_ppocr_backend(
    model_name: str = "ppocr_v5",
    use_doc_orientation_classify: bool = False,
    use_doc_unwarping: bool = False,
    use_textline_orientation: bool = False,
    **kwargs: Any,
) -> OCRBackendProtocol:
    """加载 OCR 后端：若已安装 paddleocr 则返回 PP-OCRv5 真实后端，否则返回回退后端。"""
    _ = model_name
    try:
        from paddleocr import PaddleOCR  # noqa: F401
        print("[PrivacyGuard] OCR backend: PP-OCRv5 (paddleocr loaded, screenshot PII masking enabled)")
        return PaddleOCRBackend(
            use_doc_orientation_classify=use_doc_orientation_classify,
            use_doc_unwarping=use_doc_unwarping,
            use_textline_orientation=use_textline_orientation,
            **kwargs,
        )
    except ImportError:
        print("[PrivacyGuard] OCR backend: Mock (paddleocr not installed, screenshot PII masking disabled)")
        return MockOCRBackend()


def normalize_image_path(path: str | Path) -> Path:
    """将路径标准化为绝对路径。"""
    return Path(path).resolve()

