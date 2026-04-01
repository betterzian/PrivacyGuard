"""scanner 基准测试脚本。

默认测量 `build_clue_bundle(...)` 的稳态耗时，不包含：
1. prompt 预处理 `build_prompt_stream(...)`；
2. parser / resolver / OCR 后续阶段；
3. 从 mapping_store 读取并构造 session dictionary 的准备时间。

这样可以把结果收敛到 scanner 本体，便于观察文本长度和 session dictionary
规模对扫描耗时的影响。
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
from pathlib import Path

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.json_privacy_repository import DEFAULT_PRIVACY_REPOSITORY_PATH


_BASE_PARAGRAPH = (
    "请帮我核对订单收货信息，联系人张明，会话用户0000曾在上一轮确认备用电话。"
    "联系电话13800138000，备用邮箱zhangming@example.com，"
    "收货地址是上海市闵行区申长路88号A座1203，"
    "历史会话中还出现过会话用户0001和会话用户0002，如系统提示请以最近一次记录为准，"
    "发票抬头为星云科技有限公司，若地址变更请先更新备注再重新提交。"
)


@dataclass(slots=True)
class ScenarioStats:
    scenario: str
    text_length: int
    session_entry_count: int
    local_entry_count: int
    samples: int
    loops_per_sample: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float
    clue_count: int


def _make_text(length: int) -> str:
    """生成固定内容的测试文本，并裁到目标字符数。"""
    if length <= 0:
        return ""
    repeat = length // len(_BASE_PARAGRAPH) + 2
    text = (_BASE_PARAGRAPH * repeat)[:length]
    if len(text) != length:
        raise ValueError(f"文本长度生成失败: expect={length}, actual={len(text)}")
    return text


def _make_session_entries(count: int) -> tuple:
    """通过真实 mapping_store 路径构造 session dictionary。"""
    if count <= 0:
        return ()
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
        for index in range(count)
    ]
    store.save_replacements(session_id=session_id, turn_id=0, records=records)
    detector = RuleBasedPIIDetector(mapping_store=store)
    return detector._load_session_dictionary(session_id=session_id, turn_id=1)


def _warm_builtin_matchers(local_entries: tuple) -> None:
    """预热内建 lexicon / matcher，避免把冷启动算进稳态结果。"""
    stream = build_prompt_stream(_make_text(300))
    build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=local_entries,
        locale_profile="mixed",
    )


def _percentile(sorted_values: list[float], ratio: float) -> float:
    """返回离散分位点，便于在小样本下保持可解释性。"""
    if not sorted_values:
        return 0.0
    index = max(0, math.ceil(len(sorted_values) * ratio) - 1)
    return sorted_values[index]


def _run_scanner_once(stream, local_entries: tuple, session_entries: tuple) -> int:
    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=session_entries,
        local_entries=local_entries,
        locale_profile="mixed",
    )
    return len(bundle.all_clues)


def _measure_scenario(
    *,
    scenario: str,
    text: str,
    local_entries: tuple,
    session_entries: tuple,
    samples: int,
    loops_per_sample: int,
    warmup: int,
) -> ScenarioStats:
    """多轮采样，输出每次 scanner 调用的平均耗时。"""
    stream = build_prompt_stream(text)

    for _ in range(max(0, warmup)):
        _run_scanner_once(stream, local_entries, session_entries)

    sample_costs_ms: list[float] = []
    clue_count = 0
    gc_enabled = gc.isenabled()
    if gc_enabled:
        gc.disable()
    try:
        for _ in range(samples):
            start_ns = time.perf_counter_ns()
            for _ in range(loops_per_sample):
                clue_count = _run_scanner_once(stream, local_entries, session_entries)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000 / loops_per_sample
            sample_costs_ms.append(elapsed_ms)
    finally:
        if gc_enabled:
            gc.enable()

    ordered = sorted(sample_costs_ms)
    mean_ms = statistics.fmean(sample_costs_ms)
    p50_ms = statistics.median(ordered)
    p95_ms = _percentile(ordered, 0.95)
    min_ms = ordered[0]
    max_ms = ordered[-1]
    stdev_ms = statistics.stdev(sample_costs_ms) if len(sample_costs_ms) > 1 else 0.0
    return ScenarioStats(
        scenario=scenario,
        text_length=len(text),
        session_entry_count=len(session_entries),
        local_entry_count=len(local_entries),
        samples=samples,
        loops_per_sample=loops_per_sample,
        mean_ms=round(mean_ms, 3),
        p50_ms=round(p50_ms, 3),
        p95_ms=round(p95_ms, 3),
        min_ms=round(min_ms, 3),
        max_ms=round(max_ms, 3),
        stdev_ms=round(stdev_ms, 3),
        clue_count=clue_count,
    )


def _build_results(samples: int, loops_per_sample: int, warmup: int) -> dict[str, object]:
    detector = RuleBasedPIIDetector()
    local_entries = detector.local_entries
    current_repo_path = Path(DEFAULT_PRIVACY_REPOSITORY_PATH).resolve()

    _warm_builtin_matchers(local_entries)

    length_curve = [
        _measure_scenario(
            scenario=f"current_dictionary_{text_length}_chars",
            text=_make_text(text_length),
            local_entries=local_entries,
            session_entries=(),
            samples=samples,
            loops_per_sample=loops_per_sample,
            warmup=warmup,
        )
        for text_length in (300, 1000, 3000)
    ]

    session_curve = [
        _measure_scenario(
            scenario=f"session_dictionary_{entry_count}_entries",
            text=_make_text(300),
            local_entries=local_entries,
            session_entries=_make_session_entries(entry_count),
            samples=samples,
            loops_per_sample=loops_per_sample,
            warmup=warmup,
        )
        for entry_count in (100, 500, 1000)
    ]

    return {
        "assumptions": {
            "measured_unit": "scanner build_clue_bundle warm-path only",
            "text_length_unit": "Python len(text) characters",
            "current_local_dictionary_path": str(current_repo_path),
            "current_local_dictionary_exists": current_repo_path.exists(),
            "current_local_dictionary_entries": len(local_entries),
            "session_dictionary_build_time_included": False,
            "prompt_preprocess_included": False,
            "parser_resolver_ocr_included": False,
        },
        "environment": {
            "python": sys.version.splitlines()[0],
            "platform": platform.platform(),
            "samples": samples,
            "loops_per_sample": loops_per_sample,
            "warmup": warmup,
        },
        "baseline_300_chars_current_dictionary": asdict(length_curve[0]),
        "length_curve": [asdict(item) for item in length_curve],
        "session_dictionary_curve": [asdict(item) for item in session_curve],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="测量 PrivacyGuard scanner 的稳态耗时。")
    parser.add_argument("--samples", type=int, default=20, help="采样次数。")
    parser.add_argument("--loops", type=int, default=10, help="每个采样内重复调用次数。")
    parser.add_argument("--warmup", type=int, default=5, help="每个场景正式计时前的预热次数。")
    args = parser.parse_args()

    results = _build_results(
        samples=max(1, args.samples),
        loops_per_sample=max(1, args.loops),
        warmup=max(0, args.warmup),
    )
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
