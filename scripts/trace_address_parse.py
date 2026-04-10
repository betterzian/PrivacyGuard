"""对单段文本跑真实 StreamParser，打印 clue 列表与每次 stack run（含 AddressStack 的 next_index）。

用法：
  python scripts/trace_address_parse.py "广东省广州市…"
  python scripts/trace_address_parse.py   # 使用内置示例
"""

from __future__ import annotations

import sys
from dataclasses import asdict

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClueFamily, PIIAttributeType
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser, _is_control_clue
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
def _clue_line(i: int, c) -> str:
    fam = c.family.value if hasattr(c.family, "value") else c.family
    role = c.role.value if hasattr(c.role, "value") else c.role
    at = "None" if c.attr_type is None else c.attr_type.value
    ct = "" if c.component_type is None else c.component_type.value
    return (
        f"[{i:03d}] fam={fam} role={role} attr={at} comp={ct} "
        f"char[{c.start}:{c.end}) text={c.text!r}"
    )


def trace_text(text: str, *, locale_profile: str = "zh_cn") -> None:
    print("=" * 80)
    print("TEXT:", text)
    print("len:", len(text))

    ctx = DetectContext()
    ctx.protection_level = ProtectionLevel.STRONG
    stream = build_prompt_stream(text)
    bundle = build_clue_bundle(
        stream,
        ctx=ctx,
        session_entries=(),
        local_entries=(),
        locale_profile=locale_profile,
    )
    clues = bundle.all_clues

    print("\n--- 全部 clues（节选 ADDRESS / NAME / ORG / NUMERIC） ---")
    interest = {
        PIIAttributeType.ADDRESS,
        PIIAttributeType.NAME,
        PIIAttributeType.ORGANIZATION,
        PIIAttributeType.NUMERIC,
        PIIAttributeType.ALNUM,
    }
    for i, c in enumerate(clues):
        if c.attr_type in interest or c.family == ClueFamily.ADDRESS:
            print(_clue_line(i, c))

    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    context = StackContext(
        stream=stream,
        locale_profile=locale_profile,
        protection_level=ctx.protection_level,
        clues=clues,
    )
    consumed_ids: set[str] = set()
    index = 0
    step = 0

    orig_try = StreamParser._try_run_stack

    def traced_try(self, context: StackContext, idx: int):
        run, stack = orig_try(self, context, idx)
        if run is not None:
            nonlocal step
            step += 1
            sn = type(stack).__name__ if stack is not None else "?"
            seed = context.clues[idx]
            print(
                f"\n>>> run#{step} seed[{idx}] stack={sn} "
                f"seed_fam={seed.family.value} seed_text={seed.text!r}"
            )
            print(f"    candidate: {run.candidate.text!r} char[{run.candidate.start}:{run.candidate.end})")
            print(f"    next_index={run.next_index} consumed_ids_count={len(run.consumed_ids)}")
            if run.pending_challenge is not None:
                print("    pending_challenge: digit tail 待 StructuredStack 裁决")
        return run, stack

    StreamParser._try_run_stack = traced_try  # type: ignore[method-assign]

    try:
        result = parser.parse(stream, bundle)
    finally:
        StreamParser._try_run_stack = orig_try  # type: ignore[method-assign]

    print("\n--- parse 最终 candidates ---")
    for j, cand in enumerate(result.candidates):
        d = asdict(cand)
        d["attr_type"] = cand.attr_type.value
        d["source"] = cand.source.value
        print(f"[{j}] {cand.attr_type.value}: {cand.text!r} [{cand.start}:{cand.end})")
        meta = cand.metadata or {}
        if meta:
            brief = {k: v for k, v in meta.items() if k in ("address_components", "matched_by", "hard_source")}
            if brief:
                print("    meta:", brief)


def main() -> None:
    if len(sys.argv) >= 2:
        trace_text(sys.argv[1])
        return
    examples = [
        "广东省广州市天河区石牌街道文一西路105号星河中心2栋1203室",
        "科苑路715号阳光花园C幢502室,南山区深圳市广东省",
    ]
    for t in examples:
        trace_text(t)
        print()


if __name__ == "__main__":
    main()
