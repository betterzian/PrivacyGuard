from __future__ import annotations

import json
from dataclasses import asdict

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.detector.stacks.address import (
    _build_cross_tier_value_key_component,
    _label_seed_address_index,
    _pop_components_overlapping_negative,
)
from privacyguard.infrastructure.pii.detector.stacks.common import _skip_separators, _unit_index_at_or_after, is_break_clue, is_negative_clue


def _clue_brief(c: Clue) -> str:
    at = "None" if c.attr_type is None else c.attr_type.value
    ct = "" if c.component_type is None else c.component_type.value
    return (
        f"role={c.role.value} attr={at} comp={ct} "
        f"char=[{c.start},{c.end}) unit=[{c.unit_start},{c.unit_end}) "
        f"text={c.text!r} src={c.source_kind}"
    )


def _print_clues(clues: tuple[Clue, ...]) -> None:
    for i, c in enumerate(clues):
        print(f"[{i:03d}] {_clue_brief(c)}")


def trace_address_stack(text: str, *, locale_profile: str = "zh_cn") -> None:
    print("=".ljust(80, "="))
    print("TEXT:", text)
    ctx = DetectContext()
    stream = build_prompt_stream(text)
    bundle = build_clue_bundle(
        stream,
        ctx=ctx,
        session_entries=(),
        local_entries=(),
        locale_profile=locale_profile,
    )

    print("\n--- scanner: final ordered clues ---")
    clues = bundle.all_clues
    _print_clues(clues)

    print("\n--- parser: committed candidates ---")
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    result = parser.parse(stream, bundle)
    for cand in result.candidates:
        d = asdict(cand)
        d["attr_type"] = cand.attr_type.value
        d["source"] = cand.source.value
        print(json.dumps(d, ensure_ascii=False, sort_keys=True, default=str))

    print("\n--- addressstack: step-by-step (replica run with prints) ---")
    # 找到第一个 ADDRESS clue（LABEL/VALUE/KEY）作为起栈点来展示细节；若没有则退出。
    seed_index = next(
        (
            i
            for i, c in enumerate(clues)
            if c.attr_type == PIIAttributeType.ADDRESS and c.role in {ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY}
        ),
        None,
    )
    if seed_index is None:
        print("No ADDRESS seed clue found.")
        return

    seed = clues[seed_index]
    raw_text = stream.text
    is_label_seed = seed.role == ClueRole.LABEL
    print("Seed index:", seed_index, _clue_brief(seed))

    if seed.strength == ClaimStrength.HARD:
        print("Seed is HARD, would direct-commit candidate (not expanded).")
        return

    if is_label_seed:
        address_start = _skip_separators(raw_text, seed.end)
        start_unit = _unit_index_at_or_after(stream, address_start)
        seed_index2 = _label_seed_address_index(clues, start_unit, max_units=6)
        print(f"Label seed: address_start={address_start}, start_unit={start_unit}, first_scan_index={seed_index2}")
        if seed_index2 is None:
            print("Label seed failed: no VALUE covering start_unit and no KEY within 6 units.")
            return
        scan_index = seed_index2
        consumed_ids = {seed.clue_id}
        evidence_count = 1
    else:
        address_start = seed.start if seed.role in {ClueRole.VALUE, ClueRole.KEY} else None
        scan_index = seed_index
        consumed_ids = set()
        evidence_count = 0

    if address_start is None:
        print("Seed has no address_start, abort.")
        return

    components: list[dict[str, object]] = []
    pending_value: dict[AddressComponentType, Clue] = {}
    negative_spans: list[tuple[int, int]] = []
    last_consumed_address_clue: Clue | None = None
    last_value_clue: Clue | None = None

    i = scan_index
    while i < len(clues):
        c = clues[i]
        print(f"\n@i={i:03d} {_clue_brief(c)}")

        if is_break_clue(c):
            print("STOP: break clue")
            break
        if is_negative_clue(c):
            print("NEGATIVE: record span and continue")
            negative_spans.append((c.start, c.end))
            i += 1
            continue
        if c.attr_type is None:
            print("CONTROL: skip")
            i += 1
            continue
        if c.attr_type != PIIAttributeType.ADDRESS:
            print("STOP: other attr_type")
            break
        if c.role == ClueRole.LABEL:
            print("SKIP: label inside scan")
            i += 1
            continue
        if c.start < address_start:
            print("SKIP: before address_start")
            i += 1
            continue

        if last_consumed_address_clue is not None and c.unit_start - last_consumed_address_clue.unit_end > 6:
            print("STOP: >6 units since last consumed address clue")
            break

        comp_type = c.component_type
        if comp_type is None:
            print("SKIP: address clue without component_type")
            i += 1
            continue

        consumed_ids.add(c.clue_id)
        last_consumed_address_clue = c

        if c.role == ClueRole.VALUE:
            if comp_type in pending_value:
                print("STOP: duplicate pending value for same component_type")
                break
            pending_value[comp_type] = c
            last_value_clue = c
            print(f"VALUE: pending_value[{comp_type.value}] = {c.text!r}")
            i += 1
            continue

        # KEY
        same_tier_value = pending_value.pop(comp_type, None)
        if same_tier_value is not None:
            # 这里不复刻旧的 value-key gap 校验细节，只展示同层级合并发生。
            merged = _build_cross_tier_value_key_component(raw_text, same_tier_value, c, comp_type)
            if merged is not None:
                components.append(merged)
                evidence_count += 1
                print(f"KEY: merged same-type value+key into component={comp_type.value}")
            else:
                print("KEY: same-type merge failed (value normalized empty)")
            i += 1
            continue

        # cross-tier attach
        if last_value_clue is not None and c.unit_start - last_value_clue.unit_end <= 1:
            merged = _build_cross_tier_value_key_component(raw_text, last_value_clue, c, comp_type)
            if merged is not None:
                components.append(merged)
                evidence_count += 1
                print(f"KEY: cross-tier attached last_value ({last_value_clue.component_type}) to key ({comp_type.value})")
                i += 1
                continue

        print("KEY: no merge, (note) real AddressStack would try _build_key_component here")
        i += 1

    # flush pending values as standalone components (replica: just list them)
    if pending_value:
        for t, v in pending_value.items():
            components.append(
                {
                    "component_type": t,
                    "start": v.start,
                    "end": v.end,
                    "value": v.text,
                    "key": "",
                    "is_detail": t in {AddressComponentType.BUILDING, AddressComponentType.DETAIL},
                }
            )
            evidence_count += 1
        pending_value.clear()

    print("\n--- post-process ---")
    print("components_count(before_negative):", len(components), "evidence_count:", evidence_count)
    if negative_spans:
        print("negative_spans:", negative_spans)
        components = _pop_components_overlapping_negative(components, negative_spans)
        print("components_count(after_negative):", len(components))

    print("components(final):")
    for comp in components:
        ct = comp["component_type"].value if hasattr(comp["component_type"], "value") else str(comp["component_type"])
        print(" -", ct, "span", (comp["start"], comp["end"]), "value", comp.get("value"), "key", comp.get("key"))


if __name__ == "__main__":
    trace_address_stack("上海浦东新区南京东路100号10栋102", locale_profile="zh_cn")
    trace_address_stack("上海市浦东新区南京东路阳光小区10-2-102", locale_profile="zh_cn")

