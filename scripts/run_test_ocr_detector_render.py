"""Run OCR -> detector -> label_only -> render for screenshots under data/test.

This script is intentionally evaluation-oriented:

- OCR runs once per image and is saved to disk.
- The same OCR blocks are reused for detector runs under weak/balanced/strong.
- Detector outputs, decision/replacement plans, applied records, and rendered images
  are all persisted locally for inspection.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from privacyguard.app.privacy_guard import PrivacyGuard
from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.application.services.replacement_generation import apply_post_decision_steps
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.enums import ProtectionLevel


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_ROOT = REPO_ROOT / "data" / "test"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "outputs" / "test_ocr_detector_render"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _iter_images(data_root: Path) -> list[Path]:
    return sorted(
        path
        for path in data_root.iterdir()
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
    )


def _json_dump(path: Path, payload: Any) -> None:
    _ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _save_pil_image(image: Any, output_path: Path) -> None:
    try:
        from PIL import Image

        if isinstance(image, Image.Image):
            _ensure_dir(output_path.parent)
            image.save(output_path)
            return
    except Exception as exc:  # pragma: no cover - image saving should work in evaluation env
        raise RuntimeError(f"保存渲染图片失败: {output_path}") from exc
    raise RuntimeError(f"render 输出不是 PIL.Image: {type(image)!r}")


def _ocr_blocks_to_jsonable(blocks: list[Any]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for block in blocks:
        bbox = getattr(block, "bbox", None)
        polygon = getattr(block, "polygon", None)
        payload.append(
            {
                "text": getattr(block, "text", ""),
                "score": getattr(block, "score", None),
                "line_id": getattr(block, "line_id", None),
                "block_id": getattr(block, "block_id", None),
                "rotation_degrees": getattr(block, "rotation_degrees", None),
                "bbox": None
                if bbox is None
                else {
                    "x": getattr(bbox, "x", None),
                    "y": getattr(bbox, "y", None),
                    "width": getattr(bbox, "width", None),
                    "height": getattr(bbox, "height", None),
                },
                "polygon": None
                if not polygon
                else [{"x": getattr(point, "x", None), "y": getattr(point, "y", None)} for point in polygon],
            }
        )
    return payload


def _model_list_to_jsonable(items: list[Any]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for item in items:
        if hasattr(item, "model_dump"):
            payload.append(item.model_dump(mode="json", exclude_none=True))
            continue
        payload.append({"repr": repr(item)})
    return payload


def _collect_name_findings(candidates: list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for candidate in candidates:
        attr_type = getattr(getattr(candidate, "attr_type", None), "value", getattr(candidate, "attr_type", ""))
        if attr_type != "name":
            continue
        metadata = getattr(candidate, "metadata", {}) or {}
        findings.append(
            {
                "text": getattr(candidate, "text", ""),
                "canonical_source_text": getattr(candidate, "canonical_source_text", None),
                "source": getattr(getattr(candidate, "source", None), "value", getattr(candidate, "source", "")),
                "confidence": getattr(candidate, "confidence", None),
                "block_id": getattr(candidate, "block_id", None),
                "metadata": metadata,
            }
        )
    return findings


def run_for_image(
    *,
    guard: PrivacyGuard,
    image_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    image_output_root = output_root / image_path.stem
    _ensure_dir(image_output_root)

    ocr_blocks = guard.ocr.extract(image_path)
    _json_dump(
        image_output_root / "ocr.json",
        {
            "image_path": str(image_path),
            "ocr_block_count": len(ocr_blocks),
            "ocr_blocks": _ocr_blocks_to_jsonable(ocr_blocks),
        },
    )

    level_summaries: dict[str, Any] = {}
    for protection_level in (ProtectionLevel.WEAK, ProtectionLevel.BALANCED, ProtectionLevel.STRONG):
        level_name = protection_level.value
        session_id = f"{image_path.stem}-{level_name}"
        turn_id = 0

        candidates = guard.detector.detect(
            prompt_text="",
            ocr_blocks=ocr_blocks,
            session_id=session_id,
            turn_id=turn_id,
            protection_level=protection_level,
            detector_overrides={},
        )
        _json_dump(
            image_output_root / level_name / "detector.json",
            {
                "image_path": str(image_path),
                "protection_level": level_name,
                "candidate_count": len(candidates),
                "candidates": _model_list_to_jsonable(candidates),
                "name_findings": _collect_name_findings(candidates),
            },
        )

        session_service = SessionService(mapping_store=guard.mapping_table, persona_repository=guard.persona_repo)
        session_binding = session_service.get_or_create_binding(session_id)
        context = DecisionContextBuilder(
            mapping_store=guard.mapping_table,
            persona_repository=guard.persona_repo,
        ).build(
            session_id=session_id,
            turn_id=turn_id,
            prompt_text="",
            protection_level=protection_level,
            detector_overrides={},
            ocr_blocks=ocr_blocks,
            candidates=candidates,
            session_binding=session_binding,
        )
        abstract_plan = guard.decision_engine.plan(context)
        replacement_plan = apply_post_decision_steps(
            abstract_plan,
            context,
            guard.mapping_table,
            guard.persona_repo,
        )
        sanitized_prompt_text, applied_replacements = guard.renderer.render_text("", replacement_plan)
        rendered_image = guard.renderer.render_image(image_path, replacement_plan, ocr_blocks=ocr_blocks)
        session_service.append_turn_replacements(session_id, turn_id, applied_replacements)
        if replacement_plan.active_persona_id:
            session_service.bind_active_persona(session_id, replacement_plan.active_persona_id, turn_id)

        _json_dump(
            image_output_root / level_name / "plan.json",
            {
                "image_path": str(image_path),
                "protection_level": level_name,
                "sanitized_prompt_text": sanitized_prompt_text,
                "abstract_plan": abstract_plan.model_dump(mode="json", exclude_none=True),
                "replacement_plan": replacement_plan.model_dump(mode="json", exclude_none=True),
                "applied_replacements": _model_list_to_jsonable(applied_replacements),
            },
        )
        _save_pil_image(rendered_image, image_output_root / level_name / "render.png")

        name_findings = _collect_name_findings(candidates)
        level_summaries[level_name] = {
            "candidate_count": len(candidates),
            "name_candidate_count": len(name_findings),
            "name_findings": name_findings,
            "render_path": str((image_output_root / level_name / "render.png").resolve()),
            "ocr_path": str((image_output_root / "ocr.json").resolve()),
            "detector_path": str((image_output_root / level_name / "detector.json").resolve()),
            "plan_path": str((image_output_root / level_name / "plan.json").resolve()),
        }

    return {
        "image_path": str(image_path.resolve()),
        "image_name": image_path.name,
        "levels": level_summaries,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=str, default=str(DEFAULT_DATA_ROOT))
    parser.add_argument("--output-root", type=str, default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument(
        "--detector-locale-profile",
        type=str,
        default="mixed",
        choices=["zh_cn", "en_us", "mixed"],
    )
    args = parser.parse_args()

    data_root = Path(args.data_root).resolve()
    output_root = Path(args.output_root).resolve()
    _ensure_dir(output_root)

    images = _iter_images(data_root)
    if not images:
        raise RuntimeError(f"未在 {data_root} 找到图片")

    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"locale_profile": str(args.detector_locale_profile)},
    )

    image_summaries = [run_for_image(guard=guard, image_path=image_path, output_root=output_root) for image_path in images]
    _json_dump(
        output_root / "summary.json",
        {
            "data_root": str(data_root),
            "image_count": len(images),
            "images": image_summaries,
        },
    )
    print(f"Saved outputs under: {output_root}")


if __name__ == "__main__":
    main()
