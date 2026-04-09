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


def test_rightmost_negative_drops_single_component_address():
    # “路由”命中最右组件本身时，应整段放弃。
    text = "收货地址：朝阳路由用户反馈"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="朝阳路", component_type=AddressComponentType.ROAD),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="路由", family=ClueFamily.CONTROL),
    )
    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


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


def test_same_tier_value_replaces_pending_and_flushes_previous():
    # 连续出现同层级 VALUE 时，旧 VALUE 应立即落成 component（自动补 key），然后新 VALUE 进入 pending。
    # 例：上海(CITY value) + 南京(CITY value) + 路(ROAD key) → 候选应包含“上海南京路”。
    text = "收货地址：上海南京路"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=7, text="上海", component_type=AddressComponentType.CITY),
        _clue("v2", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=7, end=9, text="南京", component_type=AddressComponentType.CITY),
        _clue("k1", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=9, end=10, text="路", component_type=AddressComponentType.ROAD),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "上海南京路" in addr.text


def test_middle_negative_keeps_address_when_rightmost_component_is_clean_city_center_case():
    text = "收货地址：上海市中心路109号"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="上海市", component_type=AddressComponentType.CITY),
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=10, end=11, text="路", component_type=AddressComponentType.ROAD),
        _clue("street_number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=14, end=15, text="号", component_type=AddressComponentType.STREET_NUMBER),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=10, text="市中心", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)

    assert addr is not None
    assert addr.text == "上海市中心路109号"


def test_middle_negative_keeps_address_when_rightmost_component_is_clean_road_case():
    text = "收货地址：北京市朝阳区建国路88号"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="北京市", component_type=AddressComponentType.CITY),
        _clue("district", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=8, end=11, text="朝阳区", component_type=AddressComponentType.DISTRICT),
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=13, end=14, text="路", component_type=AddressComponentType.ROAD),
        _clue("street_number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=16, end=17, text="号", component_type=AddressComponentType.STREET_NUMBER),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=11, end=13, text="建国", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)

    assert addr is not None
    assert addr.text == "北京市朝阳区建国路88号"


def test_middle_negative_keeps_open_road_name_when_rightmost_component_is_clean():
    text = "收货地址：上海市浦东新区域名路23号"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="上海市", component_type=AddressComponentType.CITY),
        _clue("district", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=8, end=11, text="浦东新", component_type=AddressComponentType.DISTRICT),
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=14, end=15, text="路", component_type=AddressComponentType.ROAD),
        _clue("street_number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=17, end=18, text="号", component_type=AddressComponentType.STREET_NUMBER),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=11, end=13, text="区域", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)

    assert addr is not None
    assert addr.text == "上海市浦东新区域名路23号"


def test_rightmost_negative_drops_street_admin_candidate():
    text = "收货地址：长安街道办事处"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("value", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=9, text="长安街道", component_type=AddressComponentType.STREET_ADMIN),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="街道", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)
