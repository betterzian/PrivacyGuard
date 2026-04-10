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
    text = "收货地址：你好世界"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
    )
    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


def test_cross_tier_merge_city_plus_road_key():
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
    text = "收货地址：朝阳路由用户反馈"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="朝阳路", component_type=AddressComponentType.ROAD),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="路由", family=ClueFamily.CONTROL),
    )
    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


def test_digit_tail_extends_after_last_component():
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
    # 连续出现同层级 VALUE 时，旧 VALUE 应立即落成 component（自动补 key），新 VALUE 进入 pending。
    # DISTRICT→DISTRICT 在新后继图中允许自环（通过 SUBDISTRICT 路径），但 DISTRICT 不含自身后继，
    # 所以改为用 SUBDISTRICT（允许 SUBDISTRICT→SUBDISTRICT）来验证。
    text = "收货地址：长安镇南山镇路"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("v1", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="长安镇", component_type=AddressComponentType.SUBDISTRICT),
        _clue("v2", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=8, end=11, text="南山镇", component_type=AddressComponentType.SUBDISTRICT),
        _clue("k1", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=11, end=12, text="路", component_type=AddressComponentType.ROAD),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "长安镇" in addr.text
    assert "路" in addr.text


def test_middle_negative_keeps_address_when_rightmost_component_is_clean_city_center_case():
    text = "收货地址：上海市中心路109号"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="上海市", component_type=AddressComponentType.CITY),
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=10, end=11, text="路", component_type=AddressComponentType.ROAD),
        _clue("number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=14, end=15, text="号", component_type=AddressComponentType.NUMBER),
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
        _clue("number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=16, end=17, text="号", component_type=AddressComponentType.NUMBER),
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
        _clue("number", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=17, end=18, text="号", component_type=AddressComponentType.NUMBER),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=11, end=13, text="区域", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)

    assert addr is not None
    assert addr.text == "上海市浦东新区域名路23号"


def test_rightmost_negative_drops_subdistrict_candidate():
    text = "收货地址：长安街道办事处"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("value", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=9, text="长安街道", component_type=AddressComponentType.SUBDISTRICT),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="街道", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


# ---- POI 延迟提交测试 ----


def test_poi_deferred_combined_with_road():
    # "科技园路10号" → 科技园(POI) 延迟 + 路(ROAD) 吞噬 → ROAD(科技园, 路)
    text = "收货地址：科技园路10号"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("poi", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=5, end=8, text="科技园", component_type=AddressComponentType.POI),
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=8, end=9, text="路", component_type=AddressComponentType.ROAD),
        _clue("num", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=11, end=12, text="号", component_type=AddressComponentType.NUMBER),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "科技园路" in addr.text


def test_poi_independent_when_not_adjacent():
    # "科苑花园C栋" → 花园(POI) 与 栋(BUILDING) 不紧邻（中间有 "C"）→ POI 独立提交。
    # "C" 非中文字符，BUILDING 的 _left_expand_zh_chars 无法扩展取值，故仅 POI 落成。
    text = "收货地址：科苑花园C栋"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("poi", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=7, end=9, text="花园", component_type=AddressComponentType.POI),
        _clue("bld", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=10, end=11, text="栋", component_type=AddressComponentType.BUILDING),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    trace = addr.metadata.get("address_component_type", [])
    assert "poi" in trace


# ---- 逆序逗号检查测试 ----


def test_trailing_admin_allowed_with_comma():
    # "金钟路968号,上海市" → 逆序有逗号 → 允许追加上海市。
    text = "金钟路968号,上海市"
    clues = (
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=2, end=3, text="路", component_type=AddressComponentType.ROAD),
        _clue("num", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=6, end=7, text="号", component_type=AddressComponentType.NUMBER),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=8, end=11, text="上海市", component_type=AddressComponentType.CITY),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert "上海市" in addr.text


def test_trailing_admin_blocked_without_comma():
    # "金钟路968号上海市" → 逆序无逗号 → 截断，不追加上海市。
    text = "金钟路968号上海市"
    clues = (
        _clue("road", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=2, end=3, text="路", component_type=AddressComponentType.ROAD),
        _clue("num", role=ClueRole.KEY, attr_type=PIIAttributeType.ADDRESS, start=6, end=7, text="号", component_type=AddressComponentType.NUMBER),
        _clue("city", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=7, end=10, text="上海市", component_type=AddressComponentType.CITY),
    )
    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    if addr is not None:
        assert "上海市" not in addr.text
