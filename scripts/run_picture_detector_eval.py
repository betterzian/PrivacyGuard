from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from privacyguard.application.services.replacement_generation import apply_post_decision_steps
from privacyguard.domain.enums import ProtectionLevel
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.infrastructure.decision.label_only_engine import LabelOnlyDecisionEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.ocr.ppocr_adapter import PPOCREngineAdapter
from privacyguard.infrastructure.persona.json_persona_repository import JsonPersonaRepository
from privacyguard.infrastructure.pii.detector.label_layout import LabelLayoutManager
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
DEFAULT_LEVELS = ("strong", "balanced", "weak")
LABEL_LAYOUT_CAPTURE: list[dict[str, Any]] = []
CURRENT_CAPTURE_CONTEXT: dict[str, str] = {}


def _patch_label_layout_capture() -> None:
    """记录每次 OCR label layout 的 trusted/drop 结果。"""
    original_evaluate = LabelLayoutManager.evaluate

    def _wrapped_evaluate(self: LabelLayoutManager):  # type: ignore[no-untyped-def]
        decisions = original_evaluate(self)
        image = CURRENT_CAPTURE_CONTEXT.get("image")
        level = CURRENT_CAPTURE_CONTEXT.get("level")
        if not image or not level:
            return decisions
        labels: list[dict[str, Any]] = []
        label_clues = getattr(self, "_label_clues", ())
        label_blocks = getattr(self, "_label_blocks", {})
        bindings = getattr(self, "_bindings", {})
        for clue in label_clues:
            block = label_blocks.get(clue.clue_id)
            decision = decisions.get(clue.clue_id)
            binding = bindings.get(clue.clue_id)
            bbox = block.block.bbox.model_dump(mode="json") if block and block.block.bbox else None
            labels.append(
                {
                    "clue_id": clue.clue_id,
                    "attr_type": str(clue.attr_type.value),
                    "role": str(clue.role.value),
                    "text": clue.text,
                    "source_kind": clue.source_kind,
                    "source_metadata": clue.source_metadata,
                    "block_id": block.block_id if block else None,
                    "block_text": block.clean_text if block else None,
                    "bbox": bbox,
                    "trusted": bool(decision.trusted) if decision else False,
                    "layout_score": float(decision.layout_score) if decision else 0.0,
                    "drop_reason": decision.drop_reason if decision else "not_evaluated",
                    "already_bound": binding is not None,
                    "binding_relation": binding.relation if binding else None,
                }
            )
        LABEL_LAYOUT_CAPTURE.append(
            {
                "image": image,
                "level": level,
                "labels": labels,
            }
        )
        return decisions

    LabelLayoutManager.evaluate = _wrapped_evaluate  # type: ignore[method-assign]


def _json_dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _safe_stem(path: Path) -> str:
    return path.stem.replace(" ", "_")


def _iter_images(data_root: Path, *, exclude_pixpin: bool) -> list[Path]:
    images = [
        path
        for path in sorted(data_root.iterdir(), key=lambda item: item.name.lower())
        if path.is_file() and path.suffix.lower() in IMAGE_EXTS
    ]
    if exclude_pixpin:
        images = [path for path in images if not path.name.lower().startswith("pixpin")]
    return images


def _to_candidate_summary(candidates: list[Any]) -> str:
    if not candidates:
        return "(none)"
    return "; ".join(f"{candidate.attr_type.value}:{candidate.text}" for candidate in candidates)


def _load_font(size: int) -> ImageFont.ImageFont:
    for candidate in (
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/simhei.ttf",
    ):
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size=size)
    return ImageFont.load_default()


def _save_compare_image(original: Image.Image, rendered: Image.Image, output_path: Path) -> None:
    """保存原图和渲染图的横向对比。"""
    original_rgb = original.convert("RGB")
    rendered_rgb = rendered.convert("RGB")
    if rendered_rgb.size != original_rgb.size:
        rendered_rgb = rendered_rgb.resize(original_rgb.size)
    title_h = 48
    gutter = 12
    canvas = Image.new(
        "RGB",
        (original_rgb.width * 2 + gutter, original_rgb.height + title_h),
        "white",
    )
    canvas.paste(original_rgb, (0, title_h))
    canvas.paste(rendered_rgb, (original_rgb.width + gutter, title_h))
    draw = ImageDraw.Draw(canvas)
    font = _load_font(26)
    draw.text((12, 8), "原图", fill=(20, 20, 20), font=font)
    draw.text((original_rgb.width + gutter + 12, 8), "渲染结果", fill=(20, 20, 20), font=font)
    draw.rectangle(
        [original_rgb.width, title_h, original_rgb.width + gutter - 1, original_rgb.height + title_h],
        fill=(235, 235, 235),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(output_path)


def _write_report(
    *,
    output_dir: Path,
    rows: list[dict[str, Any]],
    image_count: int,
    ocr_init_s: float,
    detector_init_s: float,
    exclude_pixpin: bool,
) -> None:
    levels = tuple(dict.fromkeys(str(row["level"]) for row in rows))
    lines: list[str] = [
        "# 图片 Detector 评测报告",
        "",
        f"- 输出目录：`{output_dir}`",
        f"- 图片：{image_count} 张，{'已排除 PixPin 两张' if exclude_pixpin else '包含 PixPin 图片'}。",
        f"- OCR 初始化耗时：`{ocr_init_s:.4f}s`；Detector 初始化耗时：`{detector_init_s:.6f}s`。",
        "- OCR：PP-OCRv5 单例复用；Detector：RuleBased 单例复用；Decision：label_only；Render：ScreenshotRenderer。",
        "",
        "## 模块平均耗时",
        "",
        "| level | images | OCR(s) | detector(s) | decision(s) | render(s) | total no init(s) | candidates | actions |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for level in levels:
        level_rows = [row for row in rows if row["level"] == level]
        n = max(len(level_rows), 1)
        lines.append(
            "| {level} | {images} | {ocr:.4f} | {det:.4f} | {dec:.4f} | {ren:.4f} | {total:.4f} | {cand} | {actions} |".format(
                level=level,
                images=len(level_rows),
                ocr=sum(float(row["ocr_time_s"]) for row in level_rows) / n,
                det=sum(float(row["detector_time_s"]) for row in level_rows) / n,
                dec=sum(float(row["decision_time_s"]) for row in level_rows) / n,
                ren=sum(float(row["render_time_s"]) for row in level_rows) / n,
                total=sum(float(row["total_no_init_s"]) for row in level_rows) / n,
                cand=sum(int(row["candidate_count"]) for row in level_rows),
                actions=sum(int(row["action_count"]) for row in level_rows),
            )
        )
    lines.extend(["", "## PII 实体结果", ""])
    for level in levels:
        lines.extend([f"### {level}", "", "| image | candidates |", "|---|---|"])
        for row in [item for item in rows if item["level"] == level]:
            lines.append(f"| {row['image']} | {row['candidate_summary']} |")
        lines.append("")
    lines.extend(["## Label Layout 结果", ""])
    for level in levels:
        lines.append(f"- {level}: `label_layout/{level}`")
    lines.extend(
        [
            "",
            "## 渲染与对比图",
            "",
        ]
    )
    for level in levels:
        lines.append(f"- {level} render: `{output_dir / 'render' / level}`")
        lines.append(f"- {level} compare: `{output_dir / 'compare' / level}`")
    (output_dir / "analysis_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run(args: argparse.Namespace) -> None:
    data_root = Path(args.data_root)
    run_name = args.run_name or f"picture_detector_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_dir = Path(args.output_root) / run_name
    images = _iter_images(data_root, exclude_pixpin=args.exclude_pixpin)
    output_dir.mkdir(parents=True, exist_ok=True)

    _patch_label_layout_capture()

    ocr_init_start = perf_counter()
    ocr_engine = PPOCREngineAdapter(
        use_doc_orientation_classify=False,
        use_doc_unwarping=False,
        use_textline_orientation=False,
        backend_kwargs={},
    )
    ocr_init_s = perf_counter() - ocr_init_start

    detector_init_start = perf_counter()
    detector = RuleBasedPIIDetector(locale_profile=args.detector_locale_profile)
    detector_init_s = perf_counter() - detector_init_start

    decision_engine = LabelOnlyDecisionEngine()
    persona_repo = JsonPersonaRepository()
    renderer = ScreenshotRenderer()
    rows: list[dict[str, Any]] = []
    ocr_by_image: dict[str, tuple[list[Any], float]] = {}

    for image_path in images:
        image = Image.open(image_path).convert("RGB")
        start = perf_counter()
        ocr_blocks = ocr_engine.extract(image)
        ocr_time_s = perf_counter() - start
        ocr_by_image[image_path.name] = (ocr_blocks, ocr_time_s)
        _json_dump(
            output_dir / "ocr" / f"{_safe_stem(image_path)}.json",
            {
                "image": image_path.name,
                "ocr_time_s": ocr_time_s,
                "blocks": [block.model_dump(mode="json") for block in ocr_blocks],
            },
        )

    for level in args.levels:
        protection_level = ProtectionLevel(level)
        for turn_id, image_path in enumerate(images):
            image = Image.open(image_path).convert("RGB")
            ocr_blocks, ocr_time_s = ocr_by_image[image_path.name]
            CURRENT_CAPTURE_CONTEXT.clear()
            CURRENT_CAPTURE_CONTEXT.update({"image": image_path.name, "level": level})
            before_capture = len(LABEL_LAYOUT_CAPTURE)

            detector_start = perf_counter()
            candidates = detector.detect(
                "",
                ocr_blocks,
                session_id=f"eval-{level}-{_safe_stem(image_path)}",
                turn_id=turn_id,
                protection_level=protection_level,
            )
            detector_time_s = perf_counter() - detector_start
            CURRENT_CAPTURE_CONTEXT.clear()

            label_payload = (
                LABEL_LAYOUT_CAPTURE[-1]
                if len(LABEL_LAYOUT_CAPTURE) > before_capture
                else {"image": image_path.name, "level": level, "labels": []}
            )
            _json_dump(output_dir / "label_layout" / level / f"{_safe_stem(image_path)}.json", label_payload)

            context = DecisionContext(
                session_id=f"eval-{level}-{_safe_stem(image_path)}",
                turn_id=turn_id,
                prompt_text="",
                protection_level=protection_level,
                ocr_blocks=ocr_blocks,
                candidates=candidates,
            )
            decision_start = perf_counter()
            abstract_plan = decision_engine.plan(context)
            plan = apply_post_decision_steps(
                abstract_plan,
                context,
                InMemoryMappingStore(),
                persona_repo,
            )
            decision_time_s = perf_counter() - decision_start

            render_start = perf_counter()
            rendered = renderer.render(image=image.copy(), plan=plan, ocr_blocks=ocr_blocks)
            render_time_s = perf_counter() - render_start

            render_path = output_dir / "render" / level / f"{_safe_stem(image_path)}_render.png"
            compare_path = output_dir / "compare" / level / f"{_safe_stem(image_path)}_compare.png"
            render_path.parent.mkdir(parents=True, exist_ok=True)
            rendered.save(render_path)
            _save_compare_image(image, rendered, compare_path)

            _json_dump(
                output_dir / "detector" / level / f"{_safe_stem(image_path)}.json",
                {
                    "image": image_path.name,
                    "level": level,
                    "detector_time_s": detector_time_s,
                    "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
                },
            )
            _json_dump(
                output_dir / "decision" / level / f"{_safe_stem(image_path)}.json",
                {
                    "image": image_path.name,
                    "level": level,
                    "decision_time_s": decision_time_s,
                    "summary": plan.summary,
                    "actions": [action.model_dump(mode="json") for action in plan.actions],
                },
            )

            row = {
                "image": image_path.name,
                "level": level,
                "ocr_time_s": ocr_time_s,
                "detector_time_s": detector_time_s,
                "decision_time_s": decision_time_s,
                "render_time_s": render_time_s,
                "total_no_init_s": ocr_time_s + detector_time_s + decision_time_s + render_time_s,
                "candidate_count": len(candidates),
                "action_count": len(plan.actions),
                "candidate_summary": _to_candidate_summary(candidates),
                "render_path": str(render_path),
                "compare_path": str(compare_path),
            }
            rows.append(row)

    with (output_dir / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)

    _json_dump(
        output_dir / "run_meta.json",
        {
            "run_name": run_name,
            "data_root": str(data_root),
            "image_count": len(images),
            "exclude_pixpin": bool(args.exclude_pixpin),
            "levels": list(args.levels),
            "ocr_init_time_s": ocr_init_s,
            "detector_init_time_s": detector_init_s,
            "pid": os.getpid(),
        },
    )
    _write_report(
        output_dir=output_dir,
        rows=rows,
        image_count=len(images),
        ocr_init_s=ocr_init_s,
        detector_init_s=detector_init_s,
        exclude_pixpin=bool(args.exclude_pixpin),
    )
    print(str(output_dir))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="图片集 detector 三档评测脚本。")
    parser.add_argument("--data-root", default="data/test/picture")
    parser.add_argument("--output-root", default="outputs")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--levels", nargs="+", default=list(DEFAULT_LEVELS), choices=list(DEFAULT_LEVELS))
    parser.add_argument("--detector-locale-profile", default="mixed")
    parser.add_argument("--exclude-pixpin", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args()


if __name__ == "__main__":
    _run(_parse_args())
