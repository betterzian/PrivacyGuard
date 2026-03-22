"""使用 _server_test_output.json 中的 OCR 结果重放 detector → label_persona_mixed → render。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from privacyguard.app.privacy_guard import PrivacyGuard
from privacyguard.app.schemas import SanitizeRequestModel
from privacyguard.application.pipelines.sanitize_pipeline import _detect_candidates
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock

ROOT = Path(__file__).resolve().parents[1]


def _load_ocr_blocks(ocr_json: list[dict]) -> list[OCRTextBlock]:
    blocks: list[OCRTextBlock] = []
    for i, item in enumerate(ocr_json):
        bb = item.get("bbox") or {}
        bbox = BoundingBox(
            x=int(bb.get("x", 0)),
            y=int(bb.get("y", 0)),
            width=max(1, int(bb.get("width", 1))),
            height=max(1, int(bb.get("height", 1))),
        )
        blocks.append(
            OCRTextBlock(
                text=str(item.get("text", "")),
                bbox=bbox,
                block_id=item.get("block_id"),
                score=float(item.get("score", 1.0)),
                line_id=int(item.get("line_id", i)),
            )
        )
    return blocks


class StaticOCREngine:
    """返回预置 OCR 块，不调用真实 OCR。"""

    def __init__(self, blocks: list[OCRTextBlock]) -> None:
        self._blocks = blocks

    def extract(self, image):  # noqa: ANN001
        return list(self._blocks)


def main() -> int:
    json_path = ROOT / "_server_test_output.json"
    if not json_path.is_file():
        print(f"未找到 {json_path}", file=sys.stderr)
        return 1
    with json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    ocr_blocks = _load_ocr_blocks(data.get("ocr", []))
    cfg = data.get("config") or {}
    # JSON 无 prompt 字段：用 OCR 文本拼接，便于 prompt 侧替换与检测对齐
    prompt_text = "\n".join(b["text"] for b in data.get("ocr", []))

    image_path = ROOT / "test.PNG"
    if not image_path.is_file():
        print(f"未找到截图 {image_path}，仅跑文本链（无 render）", file=sys.stderr)
        screenshot = None
    else:
        screenshot = str(image_path)

    guard = PrivacyGuard(
        detector_mode=cfg.get("detector_mode", "rule_based"),
        decision_mode="label_persona_mixed",
        ocr=StaticOCREngine(ocr_blocks),
    )

    payload = {
        "session_id": "replay-server-ocr-json",
        "turn_id": 0,
        "prompt_text": prompt_text,
        "screenshot": screenshot,
    }
    request_model = SanitizeRequestModel.from_payload(payload)
    request_dto = request_model.to_dto()
    # 与 sanitize 主链 detector 阶段一致（见 sanitize_pipeline._detect_candidates）
    detected = _detect_candidates(request=request_dto, pii_detector=guard.detector, ocr_blocks=ocr_blocks)
    detector_export = {
        "detector_mode": cfg.get("detector_mode", "rule_based"),
        "session_id": request_dto.session_id,
        "turn_id": request_dto.turn_id,
        "candidate_count": len(detected),
        "candidates": [c.model_dump(mode="json") for c in detected],
    }
    detector_path = ROOT / "_server_detector_output.json"
    with detector_path.open("w", encoding="utf-8") as df:
        json.dump(detector_export, df, ensure_ascii=False, indent=2)
    print(f"已导出 detector 结果: {detector_path}")

    out = guard.sanitize(payload)

    masked = out.get("masked_prompt", "")
    print("--- masked_prompt (前 2000 字符) ---")
    print(masked[:2000] + ("..." if len(masked) > 2000 else ""))
    print("--- 元 ---")
    print(
        json.dumps(
            {k: v for k, v in out.items() if k != "masked_image"},
            ensure_ascii=False,
            indent=2,
        )
    )

    img = out.get("masked_image")
    if img is not None and hasattr(img, "save"):
        out_png = ROOT / "_sanitized_label_persona_mixed.png"
        img.save(out_png)
        print(f"已保存脱敏图: {out_png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
