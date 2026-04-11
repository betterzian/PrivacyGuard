"""Detector 全链路分阶段基准测试脚本。

默认测量以下阶段的稳态耗时：
1. session dictionary 读取 + structured lookup 构建；
2. prompt preprocess / scanner / parser；
3. OCR preprocess / scanner / parser / geometry；
4. draft -> PIICandidate -> resolver。

脚本目标是帮助比较重构或数据结构改造前后的收益，因此刻意：
- 复用真实 detector 内部阶段；
- 使用稳定的合成 prompt / OCR blocks；
- 输出每个阶段的离散统计值，而不是只给一个总耗时。
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.ocr import apply_ocr_geometry
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_ocr_stream, build_prompt_stream
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle

_BASE_PARAGRAPH = (
    "请帮我核对订单收货信息，联系人张明，联系电话13800138000，备用邮箱zhangming@example.com，"
    "收货地址是上海市闵行区申长路88号A座1203，发票抬头为星云科技有限公司。"
    "若系统提示请优先使用最近一次记录，并同步更新历史备注中的备用联系人与收货地址。"
)

_OCR_BLOCK_TEMPLATES = (
    "联系人 张明",
    "联系电话 13800138000",
    "备用邮箱 zhangming@example.com",
    "收货地址 上海市闵行区",
    "申长路88号 A座1203",
    "发票抬头 星云科技有限公司",
    "历史联系人 会话用户0001",
    "备用号码 13912341234",
    "地址变更 请先更新备注",
    "收件人 Alice Zhang",
    "Address 88 Shenchang Rd",
    "Invoice Nebula Tech Co Ltd",
)

_STAGE_ORDER = (
    "dictionary_prepare",
    "prompt_preprocess",
    "prompt_scanner",
    "prompt_parser",
    "ocr_preprocess",
    "ocr_scanner",
    "ocr_parser",
    "ocr_geometry",
    "draft_finalize",
    "total_pipeline",
)


@dataclass(slots=True)
class StageStats:
    mean_ms: float
    p50_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float


@dataclass(slots=True)
class ScenarioStats:
    scenario: str
    prompt_length: int
    ocr_block_count: int
    session_entry_count: int
    local_entry_count: int
    samples: int
    loops_per_sample: int
    prompt_clue_count: int
    ocr_clue_count: int
    prompt_draft_count: int
    ocr_draft_count: int
    final_candidate_count: int
    stage_stats: dict[str, StageStats]


def _make_text(length: int) -> str:
    """生成固定内容测试文本，并裁到目标字符数。"""
    if length <= 0:
        return ""
    repeat = length // len(_BASE_PARAGRAPH) + 2
    text = (_BASE_PARAGRAPH * repeat)[:length]
    if len(text) != length:
        raise ValueError(f"文本长度生成失败: expect={length}, actual={len(text)}")
    return text


def _make_ocr_blocks(count: int) -> list[OCRTextBlock]:
    """生成稳定布局的 OCR block，覆盖中英混合、结构化片段和地址片段。"""
    if count <= 0:
        return []
    blocks: list[OCRTextBlock] = []
    row_height = 28
    block_height = 20
    blocks_per_row = 4
    for index in range(count):
        row = index // blocks_per_row
        col = index % blocks_per_row
        template = _OCR_BLOCK_TEMPLATES[index % len(_OCR_BLOCK_TEMPLATES)]
        text = template.replace("0001", f"{index % 10000:04d}")
        width = max(60, len(text) * 11)
        x = 24 + col * 220
        y = 18 + row * row_height
        blocks.append(
            OCRTextBlock(
                text=text,
                block_id=f"block-{index:04d}",
                line_id=row,
                bbox=BoundingBox(x=x, y=y, width=width, height=block_height),
            )
        )
    return blocks


def _make_detector_with_session_entries(entry_count: int) -> tuple[RuleBasedPIIDetector, str | None]:
    """构造带指定 session dictionary 规模的 detector。"""
    if entry_count <= 0:
        return RuleBasedPIIDetector(), None

    session_id = "benchmark-session"
    store = InMemoryMappingStore()
    records = [
        ReplacementRecord(
            session_id=session_id,
            turn_id=0,
            candidate_id=f"candidate-{index:04d}",
            source_text=f"会话用户{index:04d}",
            canonical_source_text=f"会话用户{index:04d}",
            replacement_text=f"<name_{index:04d}>",
            attr_type=PIIAttributeType.NAME,
            action_type=ActionType.GENERICIZE,
            source=PIISourceType.PROMPT,
            metadata={},
        )
        for index in range(entry_count)
    ]
    store.save_replacements(session_id=session_id, turn_id=0, records=records)
    return RuleBasedPIIDetector(mapping_store=store), session_id


def _percentile(sorted_values: list[float], ratio: float) -> float:
    """返回离散分位点。"""
    if not sorted_values:
        return 0.0
    index = max(0, math.ceil(len(sorted_values) * ratio) - 1)
    return sorted_values[index]


def _summarize_stage(values_ms: list[float]) -> StageStats:
    ordered = sorted(values_ms)
    mean_ms = statistics.fmean(values_ms)
    p50_ms = statistics.median(ordered)
    p95_ms = _percentile(ordered, 0.95)
    min_ms = ordered[0]
    max_ms = ordered[-1]
    stdev_ms = statistics.stdev(values_ms) if len(values_ms) > 1 else 0.0
    return StageStats(
        mean_ms=round(mean_ms, 3),
        p50_ms=round(p50_ms, 3),
        p95_ms=round(p95_ms, 3),
        min_ms=round(min_ms, 3),
        max_ms=round(max_ms, 3),
        stdev_ms=round(stdev_ms, 3),
    )


def _run_pipeline_once(
    detector: RuleBasedPIIDetector,
    *,
    prompt_text: str,
    ocr_blocks: list[OCRTextBlock],
    session_id: str | None,
    turn_id: int,
) -> tuple[dict[str, float], dict[str, int]]:
    """运行一次 detector 内部主链，并返回分阶段耗时与计数。"""
    stage_costs_ms: dict[str, float] = {}
    counts = {
        "prompt_clues": 0,
        "ocr_clues": 0,
        "prompt_drafts": 0,
        "ocr_drafts": 0,
        "final_candidates": 0,
    }

    total_start_ns = time.perf_counter_ns()

    ctx = DetectContext(
        protection_level=ProtectionLevel.STRONG,
        session_id=session_id,
        turn_id=turn_id,
    )

    stage_start_ns = time.perf_counter_ns()
    session_entries = detector._load_session_dictionary(session_id=session_id, turn_id=turn_id)
    structured_lookup_index = detector._build_structured_lookup_index(
        session_entries=session_entries,
        local_entries=detector.local_entries,
    )
    parser = StreamParser(locale_profile=detector.locale_profile, ctx=ctx)
    stage_costs_ms["dictionary_prepare"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    prompt_stream = build_prompt_stream(prompt_text)
    stage_costs_ms["prompt_preprocess"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    prompt_bundle = build_clue_bundle(
        prompt_stream,
        ctx=ctx,
        session_entries=session_entries,
        local_entries=detector.local_entries,
        locale_profile=detector.locale_profile,
    )
    counts["prompt_clues"] = len(prompt_bundle.all_clues)
    stage_costs_ms["prompt_scanner"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    prompt_result = parser.parse(
        prompt_stream,
        prompt_bundle,
        structured_lookup_index=structured_lookup_index,
    )
    counts["prompt_drafts"] = len(prompt_result.candidates)
    stage_costs_ms["prompt_parser"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    prepared_ocr = build_ocr_stream(ocr_blocks)
    stage_costs_ms["ocr_preprocess"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    ocr_bundle = build_clue_bundle(
        prepared_ocr.stream,
        ctx=ctx,
        session_entries=session_entries,
        local_entries=detector.local_entries,
        locale_profile=detector.locale_profile,
    )
    counts["ocr_clues"] = len(ocr_bundle.all_clues)
    stage_costs_ms["ocr_scanner"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    ocr_result = parser.parse(
        prepared_ocr.stream,
        ocr_bundle,
        structured_lookup_index=structured_lookup_index,
    )
    stage_costs_ms["ocr_parser"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    ocr_drafts = apply_ocr_geometry(
        prepared=prepared_ocr,
        bundle=ocr_bundle,
        parsed=ocr_result,
    )
    counts["ocr_drafts"] = len(ocr_drafts)
    stage_costs_ms["ocr_geometry"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_start_ns = time.perf_counter_ns()
    candidates = detector._to_pii_candidates(prompt_result.candidates)
    candidates.extend(detector._to_pii_candidates(ocr_drafts))
    resolved = detector.resolver.resolve_candidates(candidates)
    counts["final_candidates"] = len(resolved)
    stage_costs_ms["draft_finalize"] = (time.perf_counter_ns() - stage_start_ns) / 1_000_000

    stage_costs_ms["total_pipeline"] = (time.perf_counter_ns() - total_start_ns) / 1_000_000
    return stage_costs_ms, counts


def _measure_scenario(
    *,
    scenario: str,
    prompt_length: int,
    ocr_block_count: int,
    session_entry_count: int,
    samples: int,
    loops_per_sample: int,
    warmup: int,
) -> ScenarioStats:
    detector, session_id = _make_detector_with_session_entries(session_entry_count)
    prompt_text = _make_text(prompt_length)
    ocr_blocks = _make_ocr_blocks(ocr_block_count)

    for warmup_index in range(max(0, warmup)):
        _run_pipeline_once(
            detector,
            prompt_text=prompt_text,
            ocr_blocks=ocr_blocks,
            session_id=session_id,
            turn_id=warmup_index + 1,
        )

    stage_samples_ms: dict[str, list[float]] = {name: [] for name in _STAGE_ORDER}
    final_counts = {
        "prompt_clues": 0,
        "ocr_clues": 0,
        "prompt_drafts": 0,
        "ocr_drafts": 0,
        "final_candidates": 0,
    }

    gc_enabled = gc.isenabled()
    if gc_enabled:
        gc.disable()
    try:
        for sample_index in range(samples):
            aggregated_ms = {name: 0.0 for name in _STAGE_ORDER}
            counts = dict(final_counts)
            for loop_index in range(loops_per_sample):
                stage_costs_ms, counts = _run_pipeline_once(
                    detector,
                    prompt_text=prompt_text,
                    ocr_blocks=ocr_blocks,
                    session_id=session_id,
                    turn_id=sample_index * loops_per_sample + loop_index + 1,
                )
                for stage_name in _STAGE_ORDER:
                    aggregated_ms[stage_name] += stage_costs_ms[stage_name]
            for stage_name in _STAGE_ORDER:
                stage_samples_ms[stage_name].append(aggregated_ms[stage_name] / loops_per_sample)
            final_counts = counts
    finally:
        if gc_enabled:
            gc.enable()

    return ScenarioStats(
        scenario=scenario,
        prompt_length=prompt_length,
        ocr_block_count=ocr_block_count,
        session_entry_count=session_entry_count,
        local_entry_count=len(detector.local_entries),
        samples=samples,
        loops_per_sample=loops_per_sample,
        prompt_clue_count=final_counts["prompt_clues"],
        ocr_clue_count=final_counts["ocr_clues"],
        prompt_draft_count=final_counts["prompt_drafts"],
        ocr_draft_count=final_counts["ocr_drafts"],
        final_candidate_count=final_counts["final_candidates"],
        stage_stats={
            stage_name: _summarize_stage(stage_samples_ms[stage_name])
            for stage_name in _STAGE_ORDER
        },
    )


def _build_results(
    *,
    samples: int,
    loops_per_sample: int,
    warmup: int,
    prompt_curve_lengths: tuple[int, ...],
    ocr_curve_blocks: tuple[int, ...],
    session_curve_counts: tuple[int, ...],
    anchor_prompt_length: int,
    anchor_ocr_blocks: int,
) -> dict[str, object]:
    prompt_curve = [
        asdict(
            _measure_scenario(
                scenario=f"prompt_curve_{prompt_length}_chars",
                prompt_length=prompt_length,
                ocr_block_count=0,
                session_entry_count=0,
                samples=samples,
                loops_per_sample=loops_per_sample,
                warmup=warmup,
            )
        )
        for prompt_length in prompt_curve_lengths
    ]

    ocr_curve = [
        asdict(
            _measure_scenario(
                scenario=f"ocr_curve_{ocr_blocks}_blocks",
                prompt_length=anchor_prompt_length,
                ocr_block_count=ocr_blocks,
                session_entry_count=0,
                samples=samples,
                loops_per_sample=loops_per_sample,
                warmup=warmup,
            )
        )
        for ocr_blocks in ocr_curve_blocks
    ]

    session_curve = [
        asdict(
            _measure_scenario(
                scenario=f"session_curve_{entry_count}_entries",
                prompt_length=anchor_prompt_length,
                ocr_block_count=anchor_ocr_blocks,
                session_entry_count=entry_count,
                samples=samples,
                loops_per_sample=loops_per_sample,
                warmup=warmup,
            )
        )
        for entry_count in session_curve_counts
    ]

    return {
        "assumptions": {
            "measured_unit": "detector staged warm-path without OCR engine inference",
            "text_length_unit": "Python len(prompt_text) characters",
            "ocr_block_shape": "synthetic OCRTextBlock grid with stable bbox layout",
            "local_dictionary_load_included": False,
            "session_dictionary_prepare_included": True,
            "ocr_engine_inference_included": False,
            "public_detect_wrapper_included": False,
        },
        "environment": {
            "python": sys.version.splitlines()[0],
            "platform": platform.platform(),
            "samples": samples,
            "loops_per_sample": loops_per_sample,
            "warmup": warmup,
            "stage_order": list(_STAGE_ORDER),
        },
        "prompt_length_curve": prompt_curve,
        "ocr_block_curve": ocr_curve,
        "session_entry_curve": session_curve,
    }


def _parse_csv_ints(raw_value: str) -> tuple[int, ...]:
    values = []
    for chunk in str(raw_value or "").split(","):
        text = chunk.strip()
        if not text:
            continue
        values.append(max(0, int(text)))
    if not values:
        raise ValueError("至少需要一个整数参数。")
    return tuple(values)


def main() -> None:
    parser = argparse.ArgumentParser(description="测量 PrivacyGuard detector 的分阶段稳态耗时。")
    parser.add_argument("--samples", type=int, default=12, help="采样次数。")
    parser.add_argument("--loops", type=int, default=5, help="每个采样内重复调用次数。")
    parser.add_argument("--warmup", type=int, default=3, help="每个场景正式计时前的预热次数。")
    parser.add_argument("--prompt-curve", type=str, default="300,1000,3000", help="prompt 长度曲线。")
    parser.add_argument("--ocr-curve", type=str, default="0,40,120", help="OCR block 数量曲线。")
    parser.add_argument("--session-curve", type=str, default="0,100,500", help="session dictionary 条目数曲线。")
    parser.add_argument("--anchor-prompt", type=int, default=1000, help="OCR/session 曲线使用的固定 prompt 长度。")
    parser.add_argument("--anchor-ocr-blocks", type=int, default=40, help="session 曲线使用的固定 OCR block 数量。")
    args = parser.parse_args()

    results = _build_results(
        samples=max(1, args.samples),
        loops_per_sample=max(1, args.loops),
        warmup=max(0, args.warmup),
        prompt_curve_lengths=_parse_csv_ints(args.prompt_curve),
        ocr_curve_blocks=_parse_csv_ints(args.ocr_curve),
        session_curve_counts=_parse_csv_ints(args.session_curve),
        anchor_prompt_length=max(0, args.anchor_prompt),
        anchor_ocr_blocks=max(0, args.anchor_ocr_blocks),
    )
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
