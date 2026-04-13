"""将 structured 数据集的 text_with_tags 清洗为 clean_text，拼接后评测 detector prompt 路径。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK

TAG_OPEN_RE = re.compile(r"【PII:[^】]+】")
TAG_CLOSE_RE = re.compile(r"【/PII】")


def _load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("structured 文件根节点应为 object。")
    return obj


def _clean_text_with_tags(text: str) -> str:
    cleaned = TAG_OPEN_RE.sub("", str(text or ""))
    cleaned = TAG_CLOSE_RE.sub("", cleaned)
    return cleaned


def main() -> None:
    parser = argparse.ArgumentParser(description="评测 privacy_eval_realistic_1200_zh_release_structured 的 prompt detector")
    parser.add_argument("input_json", type=Path, help="structured 数据集 JSON 路径")
    parser.add_argument(
        "--clean-txt",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_zh_clean_text_concat.txt"),
        help="清洗并拼接后的长文本 txt",
    )
    parser.add_argument(
        "--converted-json",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_zh_clean_samples.json"),
        help="转换后的样本 JSON（含 clean_text + pii_inventory）",
    )
    parser.add_argument(
        "--eval-output",
        type=Path,
        default=Path("outputs/analysis/privacy_eval_realistic_1200_zh_prompt_detector.json"),
        help="评测输出 JSON",
    )
    args = parser.parse_args()

    src = _load_json(args.input_json)
    raw_samples = src.get("samples")
    if not isinstance(raw_samples, list):
        raise ValueError("structured 文件缺少 samples 数组。")

    converted: list[dict[str, Any]] = []
    clean_texts: list[str] = []
    for row in raw_samples:
        text_with_tags = str(row.get("text_with_tags") or "")
        clean_text = _clean_text_with_tags(text_with_tags)
        clean_texts.append(clean_text)
        converted.append(
            {
                "sample_id": row.get("sample_id"),
                "category": row.get("category", "unknown"),
                "scene": row.get("scene", ""),
                "clean_text": clean_text,
                "pii_inventory": row.get("pii_inventory", []),
            }
        )

    concat_text = OCR_BREAK.join(clean_texts)
    args.clean_txt.parent.mkdir(parents=True, exist_ok=True)
    args.clean_txt.write_text(concat_text, encoding="utf-8")

    args.converted_json.parent.mkdir(parents=True, exist_ok=True)
    args.converted_json.write_text(json.dumps(converted, ensure_ascii=False, indent=2), encoding="utf-8")

    # 复用既有评测脚本，确保口径一致。
    from scripts.eval_privacy_realistic_prompt_concat import main as eval_main  # type: ignore
    import sys

    argv_backup = sys.argv[:]
    try:
        sys.argv = [
            "eval_privacy_realistic_prompt_concat.py",
            str(args.converted_json),
            "-o",
            str(args.eval_output),
            "--locale-profile",
            "mixed",
        ]
        eval_main()
    finally:
        sys.argv = argv_backup

    print(f"clean_text 拼接 txt: {args.clean_txt}")
    print(f"转换样本 json: {args.converted_json}")
    print(f"评测输出 json: {args.eval_output}")


if __name__ == "__main__":
    main()

