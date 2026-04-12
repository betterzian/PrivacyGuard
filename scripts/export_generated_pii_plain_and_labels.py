"""
从 generated_text.json 导出「去标签原文 + 字符级标注表」。

标注由 text_with_tags 解析，并与官方 clean_text 对齐；PII 段前允许跳过空白，
以兼容 clean_text 相对标签串多插入空格等情况（如 split_phone）。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Literal

OPEN = "【PII:"
CLOSE_OPEN = "】"
CLOSE_BLOCK = "【/PII】"

SegPlain = tuple[Literal["plain"], str]
SegPii = tuple[Literal["pii"], str, str, str]
Segment = SegPlain | SegPii


def parse_segments(text_with_tags: str) -> list[Segment]:
    """将带标签文本拆成顺序的 plain / pii 段。"""
    segs: list[Segment] = []
    i = 0
    while i < len(text_with_tags):
        j = text_with_tags.find(OPEN, i)
        if j < 0:
            if i < len(text_with_tags):
                segs.append(("plain", text_with_tags[i:]))
            break
        if j > i:
            segs.append(("plain", text_with_tags[i:j]))
        k = text_with_tags.find(CLOSE_OPEN, j + len(OPEN))
        if k < 0:
            raise ValueError("未闭合的开标签")
        header = text_with_tags[j + len(OPEN) : k]
        typ, pii_id = header.rsplit(":", 1)
        m = text_with_tags.find(CLOSE_BLOCK, k + 1)
        if m < 0:
            raise ValueError("未闭合的 PII 块")
        content = text_with_tags[k + 1 : m]
        segs.append(("pii", typ, pii_id, content))
        i = m + len(CLOSE_BLOCK)
    return segs


def align_annotations(clean_text: str, segs: list[Segment]) -> list[dict[str, Any]]:
    """在 clean_text 上计算各 PII 的 [start, end) 字符偏移（与 Python 字符串索引一致）。"""
    cursor = 0
    anns: list[dict[str, Any]] = []
    for seg in segs:
        if seg[0] == "plain":
            _, p = seg
            if not p:
                continue
            if clean_text[cursor : cursor + len(p)] != p:
                raise ValueError(
                    f"plain 与 clean_text 不一致：cursor={cursor}, plain={p!r}, "
                    f"实际={clean_text[cursor : cursor + len(p) + 16]!r}"
                )
            cursor += len(p)
        else:
            _, typ, pii_id, content = seg
            while cursor < len(clean_text) and clean_text[cursor].isspace():
                cursor += 1
            if clean_text[cursor : cursor + len(content)] != content:
                raise ValueError(
                    f"PII 与 clean_text 不一致：type={typ}, cursor={cursor}, "
                    f"content={content!r}, 实际={clean_text[cursor : cursor + len(content) + 16]!r}"
                )
            anns.append(
                {
                    "pii_id": pii_id,
                    "type": typ,
                    "start": cursor,
                    "end": cursor + len(content),
                    "text": content,
                }
            )
            cursor += len(content)
    while cursor < len(clean_text) and clean_text[cursor].isspace():
        cursor += 1
    if cursor != len(clean_text):
        raise ValueError(f"clean_text 尾部未消费完：cursor={cursor}, len={len(clean_text)}")
    return anns


def main() -> None:
    parser = argparse.ArgumentParser(description="导出去标签原文与字符级标注表")
    parser.add_argument(
        "--src",
        type=Path,
        default=Path("data/generated_pii_chat/generated_text.json"),
        help="输入 generated_text.json 路径",
    )
    parser.add_argument(
        "--dst",
        type=Path,
        default=Path("data/generated_pii_chat/generated_text_plain_and_labels.json"),
        help="输出 JSON 路径",
    )
    args = parser.parse_args()
    src = args.src if args.src.is_absolute() else Path(__file__).resolve().parents[1] / args.src
    dst = args.dst if args.dst.is_absolute() else Path(__file__).resolve().parents[1] / args.dst

    rows = json.loads(src.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for row in rows:
        segs = parse_segments(row["text_with_tags"])
        annotations = align_annotations(row["clean_text"], segs)
        out.append(
            {
                "sample_id": row["sample_id"],
                "shard_id": row.get("shard_id"),
                "category": row.get("category"),
                "scene": row.get("scene"),
                "difficulty": row.get("difficulty"),
                "text": row["clean_text"],
                "annotations": annotations,
            }
        )

    dst.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format": "plain_text_and_char_spans",
        "span_unit": "unicode_codepoints",
        "source": str(src.as_posix()),
        "count": len(out),
        "items": out,
    }
    dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(out)} items -> {dst}")


if __name__ == "__main__":
    main()
