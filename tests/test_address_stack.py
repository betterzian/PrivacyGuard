from __future__ import annotations

from dataclasses import replace

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
)
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks.common import _char_span_to_unit_span


def _with_units(stream, clue: Clue) -> Clue:
    us, ue = _char_span_to_unit_span(stream, clue.start, clue.end)
    return replace(clue, unit_start=us, unit_end=ue)


def _clue(
    clue_id: str,
    *,
    role: ClueRole,
    attr_type: PIIAttributeType | None,
    start: int,
    end: int,
    text: str,
    component_type: AddressComponentType | None = None,
    family: ClueFamily | None = None,
) -> Clue:
    if family is None:
        family = ClueFamily.ADDRESS if attr_type == PIIAttributeType.ADDRESS else ClueFamily.CONTROL
    return Clue(
        clue_id=clue_id,
        family=family,
        role=role,
        attr_type=attr_type,
        strength=ClaimStrength.SOFT,
        start=start,
        end=end,
        text=text,
        priority=300,
        source_kind="test",
        component_type=component_type,
        unit_start=0,
        unit_end=0,
    )


def _detect_candidates(text: str, clues: tuple[Clue, ...], *, locale_profile: str = "zh"):
    ctx = DetectContext()
    stream = build_prompt_stream(text)
    fixed = tuple(_with_units(stream, c) for c in clues)
    bundle = ClueBundle(all_clues=fixed)
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    result = parser.parse(stream, bundle)
    return result.candidates


def test_label_seed_returns_none_when_no_value_and_no_key_within_6_units():
    # “收货地址”应被识别为 label，但后续 6 个 unit 内没有 address key/value，则不应起栈。
    text = "收货地址：你好世界"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
    )
    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


def test_cross_tier_merge_city_plus_road_key():
    # “上海”(CITY value) + “路”(ROAD key) → 吸附合并为 road 组件，候选文本应包含“上海路”。
    text = "收货地址：上海路"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=7, text="上海", component_type=AddressComponentType.CITY),
        _clue("k1", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=7, end=8, text="路", component_type=AddressComponentType.ROAD),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "上海路" in addr.text


def test_negative_overlap_pops_rightmost_component():
    # “路由”是 negative_address_word，和“上海路”在“路”处交叉，需回吐右侧 road 组件。
    text = "收货地址：上海路由"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=7, text="上海", component_type=AddressComponentType.CITY),
        _clue("k1", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=7, end=8, text="路", component_type=AddressComponentType.ROAD),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="路由", family=ClueFamily.CONTROL),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "路" not in addr.text


def test_digit_tail_extends_after_last_component():
    # digit_run 紧邻在 “上海路” 后方，应被吸收并扩展候选。
    text = "收货地址：上海路79"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=7, text="上海", component_type=AddressComponentType.CITY),
        _clue("k1", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=7, end=8, text="路", component_type=AddressComponentType.ROAD),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "79" in addr.text
