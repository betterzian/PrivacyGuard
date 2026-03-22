"""使用 _server_test_output.json 中的 OCR 结果对 sanitize 两种决策模式做阶段级重放与耗时分析。"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from privacyguard.app.privacy_guard import PrivacyGuard
from privacyguard.app.schemas import SanitizeRequestModel
from privacyguard.application.pipelines.sanitize_pipeline import (
    _build_decision_context,
    _detect_candidates,
    _extract_ocr_blocks,
    _persist_sanitize_result,
    _prepare_session_context,
)
from privacyguard.application.services.replacement_generation import apply_post_decision_steps
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON_PATH = ROOT / "_server_test_output.json"
DEFAULT_IMAGE_PATH = ROOT / "test.PNG"
DEFAULT_OUTPUT_PATH = ROOT / "_sanitize_mode_profile.json"
MODES = ("label_persona_mixed", "label_only")


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
        self._blocks = list(blocks)

    def extract(self, image):  # noqa: ANN001
        return list(self._blocks)


def _summarize_candidates(candidates: list, *, sample_limit: int) -> dict[str, object]:
    attr_counts = Counter(candidate.attr_type.value for candidate in candidates)
    source_counts = Counter(candidate.source.value for candidate in candidates)
    sample = [
        {
            "text": candidate.text,
            "attr_type": candidate.attr_type.value,
            "source": candidate.source.value,
            "confidence": round(candidate.confidence, 3),
            "matched_by": candidate.metadata.get("matched_by", []),
        }
        for candidate in candidates[:sample_limit]
    ]
    return {
        "candidate_count": len(candidates),
        "attr_counts": dict(sorted(attr_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "sample": sample,
    }


def _summarize_plan(plan, *, sample_limit: int) -> dict[str, object]:
    action_counts = Counter(action.action_type.value for action in plan.actions)
    attr_counts = Counter(action.attr_type.value for action in plan.actions)
    sample = [
        {
            "source_text": action.source_text,
            "attr_type": action.attr_type.value,
            "action_type": action.action_type.value,
            "persona_id": action.persona_id,
            "replacement_text": action.replacement_text,
        }
        for action in plan.actions[:sample_limit]
    ]
    return {
        "active_persona_id": plan.active_persona_id,
        "summary": plan.summary,
        "action_counts": dict(sorted(action_counts.items())),
        "attr_counts": dict(sorted(attr_counts.items())),
        "sample": sample,
    }


def _summarize_replacements(records: list, *, sample_limit: int) -> dict[str, object]:
    action_counts = Counter(record.action_type.value for record in records)
    attr_counts = Counter(record.attr_type.value for record in records)
    sample = [
        {
            "source_text": record.source_text,
            "attr_type": record.attr_type.value,
            "action_type": record.action_type.value,
            "replacement_text": record.replacement_text,
            "persona_id": record.persona_id,
            "source": record.source.value,
        }
        for record in records[:sample_limit]
    ]
    return {
        "count": len(records),
        "action_counts": dict(sorted(action_counts.items())),
        "attr_counts": dict(sorted(attr_counts.items())),
        "sample": sample,
    }


def _build_guard(mode: str, *, detector_mode: str, ocr_blocks: list[OCRTextBlock]) -> PrivacyGuard:
    return PrivacyGuard(
        detector_mode=detector_mode,
        decision_mode=mode,
        ocr=StaticOCREngine(ocr_blocks),
    )


def _run_manual_once(
    *,
    mode: str,
    run_idx: int,
    detector_mode: str,
    ocr_blocks_source: list[OCRTextBlock],
    prompt_text: str,
    screenshot: str | None,
    sample_limit: int,
) -> dict[str, object]:
    guard = _build_guard(mode, detector_mode=detector_mode, ocr_blocks=ocr_blocks_source)
    payload = {
        "session_id": f"profile-{mode}-{run_idx}",
        "turn_id": 0,
        "prompt_text": prompt_text,
        "screenshot": screenshot,
    }

    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    t0 = time.perf_counter()
    request_model = SanitizeRequestModel.from_payload(payload)
    request_dto = request_model.to_dto()
    timings["request_parse"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    ocr_blocks = _extract_ocr_blocks(request=request_dto, ocr_engine=guard.ocr)
    timings["ocr_extract"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    detected = _detect_candidates(request=request_dto, pii_detector=guard.detector, ocr_blocks=ocr_blocks)
    timings["detector"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    session_service, session_binding = _prepare_session_context(
        session_id=request_dto.session_id,
        mapping_store=guard.mapping_table,
        persona_repository=guard.persona_repo,
    )
    timings["session_context"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    decision_context = _build_decision_context(
        request=request_dto,
        ocr_blocks=ocr_blocks,
        detected_candidates=detected,
        session_binding=session_binding,
        mapping_store=guard.mapping_table,
        persona_repository=guard.persona_repo,
    )
    timings["decision_context_build"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    raw_plan = guard.decision_engine.plan(decision_context)
    timings["decision_plan"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    replacement_plan = apply_post_decision_steps(
        raw_plan,
        decision_context,
        guard.mapping_table,
        guard.persona_repo,
    )
    timings["post_decision"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    sanitized_prompt_text, applied_replacements = guard.renderer.render_text(request_dto.prompt_text, replacement_plan)
    timings["render_text"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    sanitized_screenshot = (
        guard.renderer.render_image(request_dto.screenshot, replacement_plan, ocr_blocks=ocr_blocks)
        if request_dto.screenshot is not None
        else None
    )
    timings["render_image"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    _persist_sanitize_result(
        request=request_dto,
        session_service=session_service,
        replacement_plan=replacement_plan,
        applied_replacements=applied_replacements,
    )
    timings["persist_mapping"] = (time.perf_counter() - t0) * 1000
    timings["manual_total"] = (time.perf_counter() - total_start) * 1000

    session_binding_after = guard.mapping_table.get_session_binding(request_dto.session_id)
    return {
        "timings_ms": timings,
        "ocr": {
            "block_count": len(ocr_blocks),
            "sample": [block.text for block in ocr_blocks[:sample_limit]],
        },
        "detector": _summarize_candidates(detected, sample_limit=sample_limit),
        "decision_raw": _summarize_plan(raw_plan, sample_limit=sample_limit),
        "decision_resolved": _summarize_plan(replacement_plan, sample_limit=sample_limit),
        "render": {
            "masked_prompt_preview": sanitized_prompt_text[:1200],
            "masked_prompt_length": len(sanitized_prompt_text),
            "applied_replacements": _summarize_replacements(applied_replacements, sample_limit=sample_limit),
            "has_masked_image": sanitized_screenshot is not None,
        },
        "persist": {
            "stored_replacement_count": len(guard.mapping_table.get_replacements(request_dto.session_id)),
            "active_persona_id_after_persist": session_binding_after.active_persona_id if session_binding_after else None,
        },
    }


def _run_public_once(
    *,
    mode: str,
    run_idx: int,
    detector_mode: str,
    ocr_blocks_source: list[OCRTextBlock],
    prompt_text: str,
    screenshot: str | None,
) -> tuple[float, dict[str, object]]:
    guard = _build_guard(mode, detector_mode=detector_mode, ocr_blocks=ocr_blocks_source)
    payload = {
        "session_id": f"public-{mode}-{run_idx}",
        "turn_id": 0,
        "prompt_text": prompt_text,
        "screenshot": screenshot,
    }
    t0 = time.perf_counter()
    out = guard.sanitize(payload)
    return ((time.perf_counter() - t0) * 1000, out)


def _aggregate_timings(runs: list[dict[str, object]]) -> tuple[dict[str, float], dict[str, float], dict[str, float]]:
    stage_names = list(runs[0]["timings_ms"].keys())
    median = {
        stage: round(statistics.median(run["timings_ms"][stage] for run in runs), 3)
        for stage in stage_names
    }
    mean = {
        stage: round(statistics.mean(run["timings_ms"][stage] for run in runs), 3)
        for stage in stage_names
    }
    total = max(median.get("manual_total", 0.0), 1e-9)
    share = {stage: round(value / total * 100.0, 2) for stage, value in median.items() if stage != "manual_total"}
    return (median, mean, share)


def _build_profile(
    *,
    mode: str,
    detector_mode: str,
    ocr_blocks_source: list[OCRTextBlock],
    prompt_text: str,
    screenshot: str | None,
    repeats: int,
    sample_limit: int,
) -> dict[str, object]:
    _run_manual_once(
        mode=mode,
        run_idx=-1,
        detector_mode=detector_mode,
        ocr_blocks_source=ocr_blocks_source,
        prompt_text=prompt_text,
        screenshot=screenshot,
        sample_limit=sample_limit,
    )
    manual_runs = [
        _run_manual_once(
            mode=mode,
            run_idx=index,
            detector_mode=detector_mode,
            ocr_blocks_source=ocr_blocks_source,
            prompt_text=prompt_text,
            screenshot=screenshot,
            sample_limit=sample_limit,
        )
        for index in range(repeats)
    ]
    public_runs = [
        _run_public_once(
            mode=mode,
            run_idx=index,
            detector_mode=detector_mode,
            ocr_blocks_source=ocr_blocks_source,
            prompt_text=prompt_text,
            screenshot=screenshot,
        )
        for index in range(repeats)
    ]
    timings_median, timings_mean, timing_share = _aggregate_timings(manual_runs)
    representative = dict(manual_runs[0])
    representative["timings_ms_median"] = timings_median
    representative["timings_ms_mean"] = timings_mean
    representative["timing_share_percent_median"] = timing_share
    representative["public_sanitize_total_ms_median"] = round(
        statistics.median(item[0] for item in public_runs),
        3,
    )
    representative["public_sanitize_output_preview"] = {
        "status": public_runs[0][1]["status"],
        "session_id": public_runs[0][1]["session_id"],
        "turn_id": public_runs[0][1]["turn_id"],
        "mapping_count": public_runs[0][1]["mapping_count"],
        "active_persona_id": public_runs[0][1]["active_persona_id"],
        "masked_prompt_preview": public_runs[0][1]["masked_prompt"][:1200],
    }
    return representative


def _build_comparison(result_by_mode: dict[str, dict[str, object]]) -> dict[str, object]:
    mixed = result_by_mode["label_persona_mixed"]
    label_only = result_by_mode["label_only"]
    mixed_total = mixed["timings_ms_median"]["manual_total"]
    label_only_total = label_only["timings_ms_median"]["manual_total"]
    return {
        "manual_total_ms_delta": round(mixed_total - label_only_total, 3),
        "public_total_ms_delta": round(
            mixed["public_sanitize_total_ms_median"] - label_only["public_sanitize_total_ms_median"],
            3,
        ),
        "detector_candidate_count_equal": mixed["detector"]["candidate_count"] == label_only["detector"]["candidate_count"],
        "detector_attr_counts_equal": mixed["detector"]["attr_counts"] == label_only["detector"]["attr_counts"],
        "decision_action_counts": {
            "label_persona_mixed": mixed["decision_resolved"]["action_counts"],
            "label_only": label_only["decision_resolved"]["action_counts"],
        },
        "active_persona_id": {
            "label_persona_mixed": mixed["decision_resolved"]["active_persona_id"],
            "label_only": label_only["decision_resolved"]["active_persona_id"],
        },
    }


def _print_brief_summary(result_by_mode: dict[str, dict[str, object]]) -> None:
    for mode in MODES:
        item = result_by_mode[mode]
        print(f"=== {mode} ===")
        print(f"detector candidates: {item['detector']['candidate_count']}")
        print(f"detector attr counts: {json.dumps(item['detector']['attr_counts'], ensure_ascii=False)}")
        print(f"decision action counts: {json.dumps(item['decision_resolved']['action_counts'], ensure_ascii=False)}")
        print(f"active persona: {item['decision_resolved']['active_persona_id']}")
        print(f"manual total median(ms): {item['timings_ms_median']['manual_total']}")
        print(f"public sanitize median(ms): {item['public_sanitize_total_ms_median']}")
        print(f"top timing shares: render_image={item['timing_share_percent_median'].get('render_image', 0)}%, detector={item['timing_share_percent_median'].get('detector', 0)}%")
        print(item["render"]["masked_prompt_preview"][:240] + ("..." if len(item["render"]["masked_prompt_preview"]) > 240 else ""))
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-path", type=Path, default=DEFAULT_JSON_PATH, help="OCR 回放 JSON 路径")
    parser.add_argument("--image-path", type=Path, default=DEFAULT_IMAGE_PATH, help="截图路径；不存在则仅分析文本链")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH, help="输出 JSON 报告路径")
    parser.add_argument("--repeats", type=int, default=5, help="每种模式的 fresh run 次数（默认 5）")
    parser.add_argument("--sample-limit", type=int, default=12, help="各阶段 sample 条数（默认 12）")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats <= 0:
        print("--repeats 必须大于 0", file=sys.stderr)
        return 2
    if not args.json_path.is_file():
        print(f"未找到 OCR JSON: {args.json_path}", file=sys.stderr)
        return 1

    with args.json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    ocr_blocks = _load_ocr_blocks(data.get("ocr", []))
    prompt_text = "\n".join(item.get("text", "") for item in data.get("ocr", []))
    cfg = data.get("config") or {}
    screenshot = str(args.image_path) if args.image_path.is_file() else None
    if screenshot is None:
        print(f"未找到截图 {args.image_path}，仅分析文本链（render_image 将跳过）。", file=sys.stderr)

    result_by_mode = {
        mode: _build_profile(
            mode=mode,
            detector_mode=cfg.get("detector_mode", "rule_based"),
            ocr_blocks_source=ocr_blocks,
            prompt_text=prompt_text,
            screenshot=screenshot,
            repeats=args.repeats,
            sample_limit=args.sample_limit,
        )
        for mode in MODES
    }

    report = {
        "input": {
            "json_path": str(args.json_path.resolve()),
            "image_path": str(args.image_path.resolve()),
            "screenshot_used": screenshot is not None,
            "detector_mode": cfg.get("detector_mode", "rule_based"),
            "repeats": args.repeats,
            "ocr_block_count": len(ocr_blocks),
            "prompt_length": len(prompt_text),
        },
        "notes": [
            "ocr_extract 为静态 OCR 回放时间，不代表真实 OCR 模型推理耗时。",
            "label_persona_mixed 的 persona 渲染文本可能因 render aliases 随机选择而在不同 run 间略有变化。",
        ],
        "modes": result_by_mode,
        "comparison": _build_comparison(result_by_mode),
    }

    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_brief_summary(result_by_mode)
    print(f"已写出分析报告: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
