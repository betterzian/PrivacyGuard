"""批量运行 OCR 并导出当前拼接结果报告。"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from PIL import Image

from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter
from privacyguard.infrastructure.pii.detector.preprocess import (
    _build_recursive_ocr_chunks,
    _join_clean_blocks_ocr_inline,
    _prepare_ocr_block_text,
    build_ocr_stream,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    OCR_BREAK,
    _OCR_INLINE_GAP_TOKEN,
)

IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".bmp", ".webp"})
TOKEN_DISPLAY = {
    _OCR_INLINE_GAP_TOKEN: "[INLINE_GAP]",
    OCR_BREAK: "[OCR_BREAK]",
}


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(
        description="对 data/test 下的图片批量运行 OCR，并导出当前 OCR 拼接报告。",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data/test"),
        help="待处理图片目录，默认 data/test。",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("output"),
        help="输出根目录，默认 output。",
    )
    parser.add_argument(
        "--run-name",
        type=str,
        default=None,
        help="可选输出目录名；未提供时自动生成时间戳目录。",
    )
    return parser.parse_args()


def iter_image_paths(data_root: Path) -> list[Path]:
    """列出目录下所有受支持图片，按文件名排序。"""
    if not data_root.exists():
        raise FileNotFoundError(f"图片目录不存在：{data_root}")
    if not data_root.is_dir():
        raise NotADirectoryError(f"图片目录不是文件夹：{data_root}")
    return sorted(
        [
            path
            for path in data_root.iterdir()
            if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES
        ],
        key=lambda path: path.name.lower(),
    )


def display_tokens(text: str) -> str:
    """将私有分隔符替换为可读占位符。"""
    shown = text
    for token, display in TOKEN_DISPLAY.items():
        shown = shown.replace(token, display)
    return shown


def serialize_bbox(bbox: Any) -> dict[str, Any] | None:
    """序列化 bbox，便于写入 JSON。"""
    if bbox is None:
        return None
    if hasattr(bbox, "model_dump"):
        return bbox.model_dump(mode="python")
    return {
        "x": getattr(bbox, "x", None),
        "y": getattr(bbox, "y", None),
        "width": getattr(bbox, "width", None),
        "height": getattr(bbox, "height", None),
    }


def serialize_block(
    block: Any,
    *,
    clean_text: str | None = None,
    clean_raw_indices: tuple[int | None, ...] | None = None,
) -> dict[str, Any]:
    """序列化 OCR block。"""
    return {
        "block_id": getattr(block, "block_id", None),
        "text": getattr(block, "text", None),
        "score": getattr(block, "score", None),
        "bbox": serialize_bbox(getattr(block, "bbox", None)),
        "clean_text": clean_text,
        "clean_raw_indices": list(clean_raw_indices) if clean_raw_indices is not None else None,
    }


def build_chunk_raw_text(chunk: list[Any]) -> str:
    """按当前拼接逻辑生成 chunk 的 raw 文本。"""
    return _OCR_INLINE_GAP_TOKEN.join((getattr(block, "text", "") or "") for block in chunk)


def build_chunk_clean_text(chunk: list[Any]) -> str:
    """按当前拼接逻辑生成 chunk 的 clean 文本。"""
    pieces: list[str] = []
    previous_clean_text: str | None = None
    for block in chunk:
        clean_text, _clean_raw_indices = _prepare_ocr_block_text(getattr(block, "text", "") or "")
        if not clean_text:
            continue
        if previous_clean_text is not None:
            join_text = _join_clean_blocks_ocr_inline(previous_clean_text, clean_text)
            if join_text:
                pieces.append(join_text)
        pieces.append(clean_text)
        previous_clean_text = clean_text
    return "".join(pieces)


def write_json(path: Path, payload: Any) -> None:
    """写 UTF-8 JSON 文件。"""
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_logic_lines() -> list[str]:
    """生成报告中的拼接逻辑说明。"""
    return [
        "## 当前 OCR 拼接逻辑",
        "",
        "1. `build_ocr_stream` 先过滤空文本或无 `bbox` 的 OCR block。",
        "2. `_build_recursive_ocr_chunks` 为每个 block 预计算两类候选：",
        "   - 链 A：严格位于当前块右边界右侧的候选，只看排序后的第一个。",
        "   - 链 B：位于当前块下方，且左缘与当前块左缘在容差内的候选。",
        "3. 用“链 A 首候选 + 链 B 候选”建图并统计入度；每轮从入度为 `0` 的块里选阅读序最小的块作为新 chunk 起点。",
        "4. chunk 扩展时先沿链 A 做同行相邻合并，再把整条语义链的链 B 并集拿出来递归向下扩展。",
        "5. 同行合并要求：y 区间有正重叠、高度差相对误差 `< 10%`、水平间距 `<= 0.5 * 更高块高度`。",
        "6. 跨行合并要求：垂距不超过上行高度且不超过更高行高度的一半，行高差在阈值内，且两行左缘差 `<= 行高`。",
        "7. chunk 内部 block 之间插 `_OCR_INLINE_GAP_TOKEN`；chunk 与 chunk 之间插 `OCR_BREAK`。",
        "8. `_prepare_ocr_block_text` 会做 Unicode 归一、空白改写、边缘噪声裁剪、歧义字符修正；clean 文本按同样 chunk 顺序重新拼接。",
        "",
        "报告里将分隔符显示为：`[INLINE_GAP]` 和 `[OCR_BREAK]`。",
        "",
    ]


def process_image(
    engine: PPOCREngineAdapter,
    image_path: Path,
    ocr_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], list[str], float]:
    """处理单张图片并返回汇总、调试与报告片段。"""
    with Image.open(image_path) as image:
        image_width, image_height = image.size

    start = time.perf_counter()
    blocks = engine.extract(image_path)
    elapsed = time.perf_counter() - start

    materialized = [
        block
        for block in blocks
        if (getattr(block, "text", "") or "").strip() and getattr(block, "bbox", None) is not None
    ]
    chunks = _build_recursive_ocr_chunks(materialized) if materialized else []
    prepared = build_ocr_stream(blocks)

    ocr_json_path = ocr_root / f"{image_path.stem}.ocr.json"
    write_json(
        ocr_json_path,
        {
            "image_name": image_path.name,
            "image_path": str(image_path),
            "image_size": {"width": image_width, "height": image_height},
            "elapsed_seconds": elapsed,
            "block_count": len(blocks),
            "materialized_block_count": len(materialized),
            "blocks": [serialize_block(block) for block in blocks],
        },
    )

    block_debug: list[dict[str, Any]] = []
    for index, block in enumerate(blocks):
        clean_text, clean_raw_indices = _prepare_ocr_block_text(getattr(block, "text", "") or "")
        block_debug.append(
            {
                "index": index,
                **serialize_block(
                    block,
                    clean_text=clean_text,
                    clean_raw_indices=clean_raw_indices,
                ),
            }
        )

    chunk_payload: list[dict[str, Any]] = []
    report_lines = [
        f"## {image_path.name}",
        "",
        f"- OCR 用时：`{elapsed:.6f}s`",
        f"- OCR blocks：`{len(blocks)}`",
        f"- 参与拼接的 materialized blocks：`{len(materialized)}`",
        f"- Chunk 数：`{len(chunks)}`",
    ]
    for chunk_index, chunk in enumerate(chunks, start=1):
        raw_chunk = build_chunk_raw_text(chunk)
        clean_chunk = build_chunk_clean_text(chunk)
        report_lines.append(
            f"- Chunk {chunk_index}: blocks=`{len(chunk)}` | raw=`{display_tokens(raw_chunk) or '∅'}` | clean=`{display_tokens(clean_chunk) or '∅'}`"
        )
        chunk_payload.append(
            {
                "chunk_index": chunk_index,
                "block_count": len(chunk),
                "raw_text": raw_chunk,
                "clean_text": clean_chunk,
                "blocks": [serialize_block(block) for block in chunk],
            }
        )

    report_lines.extend(
        [
            "",
            "### Clean 之后的文本",
            "",
            "```text",
            display_tokens(prepared.stream.text),
            "```",
            "",
            "### 拼接之后的文本（raw block 顺序）",
            "",
            "```text",
            display_tokens(prepared.raw_text),
            "```",
            "",
            "### Block 级 raw_text -> clean_text",
            "",
        ]
    )
    for block in block_debug:
        raw_text = display_tokens(block["text"] or "") or "∅"
        clean_text = display_tokens(block["clean_text"] or "") or "∅"
        report_lines.append(
            f"- Block {block['index']}: raw=`{raw_text}` -> clean=`{clean_text}`"
        )
    report_lines.append("")

    summary_payload = {
        "image_name": image_path.name,
        "ocr_elapsed_seconds": elapsed,
        "ocr_block_count": len(blocks),
        "materialized_block_count": len(materialized),
        "chunk_count": len(chunks),
        "clean_text": display_tokens(prepared.stream.text),
        "raw_text": display_tokens(prepared.raw_text),
        "ocr_json": str(ocr_json_path),
    }
    debug_payload = {
        "image_name": image_path.name,
        "image_path": str(image_path),
        "image_width": image_width,
        "image_height": image_height,
        "ocr_elapsed_seconds": elapsed,
        "ocr_block_count": len(blocks),
        "materialized_block_count": len(materialized),
        "chunk_count": len(chunks),
        "clean_text": prepared.stream.text,
        "raw_text": prepared.raw_text,
        "chunks": chunk_payload,
        "blocks": block_debug,
    }
    return summary_payload, debug_payload, report_lines, elapsed


def main() -> None:
    """批量运行并写出 OCR 拼接报告。"""
    args = parse_args()
    data_root = args.data_root.resolve()
    output_root = args.output_root.resolve()
    image_paths = iter_image_paths(data_root)
    if not image_paths:
        raise RuntimeError(f"目录下未找到图片：{data_root}")

    run_name = args.run_name or f"ocr_stitch_all_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_root = output_root / run_name
    ocr_root = run_root / "ocr"
    run_root.mkdir(parents=True, exist_ok=True)
    ocr_root.mkdir(parents=True, exist_ok=True)

    engine = PPOCREngineAdapter()

    report_lines = [
        "# OCR 拼接总报告（data/test 全量图片）",
        "",
        f"- 图片数量：`{len(image_paths)}`",
        "",
        *build_logic_lines(),
    ]
    summary_images: list[dict[str, Any]] = []
    debug_images: list[dict[str, Any]] = []
    total_ocr_seconds = 0.0

    for image_path in image_paths:
        summary_payload, debug_payload, image_report_lines, elapsed = process_image(
            engine=engine,
            image_path=image_path,
            ocr_root=ocr_root,
        )
        summary_images.append(summary_payload)
        debug_images.append(debug_payload)
        report_lines.extend(image_report_lines)
        total_ocr_seconds += elapsed

    report_path = run_root / "ocr_stitching_report.md"
    debug_path = run_root / "ocr_stitching_debug.json"
    summary_path = run_root / "summary.json"

    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    write_json(
        debug_path,
        {
            "output_root": str(run_root),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "image_count": len(image_paths),
            "total_ocr_seconds": total_ocr_seconds,
            "images": debug_images,
        },
    )
    write_json(
        summary_path,
        {
            "output_root": str(run_root),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "image_count": len(image_paths),
            "total_ocr_seconds": total_ocr_seconds,
            "images": summary_images,
        },
    )

    print(
        json.dumps(
            {
                "output_root": str(run_root),
                "report": str(report_path),
                "debug": str(debug_path),
                "summary": str(summary_path),
                "image_count": len(image_paths),
                "total_ocr_seconds": total_ocr_seconds,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
