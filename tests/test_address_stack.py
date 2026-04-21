"""AddressStack 行为回归：从 `StreamParser` 间接驱动 `privacyguard/.../stacks/address.py`。

与实现文件的对应关系（便于单测跳转阅读）：
- **起栈与种子**：`test_label_seed_*` → `AddressStack.run` 中 `_label_seed_start_char`、`_label_seed_address_index`。
- **VALUE+KEY 合并 / 跨层**：`test_cross_tier_merge_*`、`test_digit_tail_extends_*` → `_handle_value_clue`、`_flush_chain`、`_analyze_digit_tail`。
- **同层 VALUE 冲洗**：`test_same_tier_value_replaces_pending_*` → `_segment_admit` 失败时 `_flush_chain` 再 `_append_deferred`。
- **负向与尾修复**：`test_middle_negative_*`、`test_rightmost_negative_trims_*` → `_scan_components` 收集 span，
  `_repair_negative_tail_components` / `_replay_component_clue_prefix`。
- **POI 延迟与路名**：`test_poi_deferred_*`、`test_poi_independent_*` → `_routed_key_clue`、`_handle_key_clue`、`_commit_poi`。
- **逆序行政与逗号**：`test_trailing_admin_*` → `_comma_tail_prehandle`、`_segment_admit` 逗号尾方向。
"""

from __future__ import annotations

import pytest

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
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.detector.stacks.address_policy_common import (
    _key_key_chain_gap_allowed,
    _label_seed_address_index,
)
from privacyguard.infrastructure.pii.detector.stacks.address import AddressStack
from tests._detector_negative_index import split_negative_clues


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
    unit_start: int = 0,
    unit_last: int = 0,
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
        unit_start=unit_start,
        unit_last=unit_last,
    )


def _split_negative_clues(
    stream,
    clues: tuple[Clue, ...],
) -> tuple[tuple[Clue, ...], tuple[Clue, ...], tuple]:
    fixed, negative_clues, _index_by_id, unit_index = split_negative_clues(stream, clues)
    return fixed, negative_clues, unit_index


def _detect_candidates(text: str, clues: tuple[Clue, ...], *, locale_profile: str = "zh"):
    ctx = DetectContext()
    stream = build_prompt_stream(text)
    fixed, negative_clues, unit_index = _split_negative_clues(stream, clues)
    bundle = ClueBundle(
        all_clues=fixed,
        unit_index=unit_index,
        negative_clues=negative_clues,
    )
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    result = parser.parse(stream, bundle)
    return result.candidates


def _build_address_context(text: str, clues: tuple[Clue, ...], *, locale_profile: str = "zh"):
    stream = build_prompt_stream(text)
    fixed, negative_clues, unit_index = _split_negative_clues(stream, clues)
    stack_context = StackContext(
        stream=stream,
        locale_profile=locale_profile,
        clues=fixed,
        negative_clues=negative_clues,
        unit_index=unit_index,
    )
    return stream, fixed, stack_context


def _detect_candidates_from_scanner(text: str, *, locale_profile: str = "zh_cn"):
    ctx = DetectContext()
    stream = build_prompt_stream(text)
    bundle = build_clue_bundle(
        stream,
        ctx=ctx,
        session_entries=(),
        local_entries=(),
        locale_profile=locale_profile,
    )
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    return parser.parse(stream, bundle).candidates


def test_label_seed_returns_none_when_no_value_and_no_key_within_6_units():
    text = "收货地址：你好世界"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
    )
    candidates = _detect_candidates(text, clues)
    assert not any(c.attr_type.value == "address" for c in candidates)


def test_value_seed_before_address_value_floor_is_rejected():
    text = "上海路"
    stream, fixed, context = _build_address_context(
        text,
        (
            _clue(
                "value",
                role=ClueRole.VALUE,
                attr_type=PIIAttributeType.ADDRESS,
                start=0,
                end=2,
                text="上海",
                component_type=AddressComponentType.CITY,
            ),
            _clue(
                "key",
                role=ClueRole.KEY,
                attr_type=PIIAttributeType.ADDRESS,
                start=2,
                end=3,
                text="路",
                component_type=AddressComponentType.ROAD,
            ),
        ),
    )
    context.raise_stack_value_floor(ClueFamily.ADDRESS, fixed[0].unit_start)

    run = AddressStack(clue=fixed[0], clue_index=0, context=context).run()

    assert stream.text == text
    assert run is None


def test_label_seed_value_hit_includes_value_last_unit():
    stream = build_prompt_stream("上海")
    clues = (
        _clue(
            "value",
            role=ClueRole.VALUE,
            attr_type=PIIAttributeType.ADDRESS,
            start=0,
            end=2,
            text="上海",
            component_type=AddressComponentType.CITY,
            unit_start=0,
            unit_last=1,
        ),
    )
    assert _label_seed_address_index(clues, stream, 0, 1, max_units=6) == 0


def test_key_key_chain_gap_allows_single_cjk_unit_under_closed_interval():
    stream = build_prompt_stream("市名路")
    left = _clue(
        "city-key",
        role=ClueRole.KEY,
        attr_type=PIIAttributeType.ADDRESS,
        start=0,
        end=1,
        text="市",
        component_type=AddressComponentType.CITY,
        unit_start=0,
        unit_last=0,
    )
    right = _clue(
        "road-key",
        role=ClueRole.KEY,
        attr_type=PIIAttributeType.ADDRESS,
        start=2,
        end=3,
        text="路",
        component_type=AddressComponentType.ROAD,
        unit_start=2,
        unit_last=2,
    )
    assert _key_key_chain_gap_allowed(left, right, stream) is True


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


def test_rightmost_negative_trims_subdistrict_tail_leaves_prefix():
    """负向「街道」与 subdistrict 尾相交时，尾修复后仍可能提交与负向不相交的前缀「长安街道」。"""
    text = "收货地址：长安街道办事处"
    clues = (
        _clue("label", role=ClueRole.LABEL, attr_type=PIIAttributeType.ADDRESS, start=0, end=4, text="收货地址"),
        _clue("value", role=ClueRole.VALUE, attr_type=PIIAttributeType.ADDRESS, start=5, end=9, text="长安街道", component_type=AddressComponentType.SUBDISTRICT),
        _clue("neg", role=ClueRole.NEGATIVE, attr_type=None, start=7, end=9, text="街道", family=ClueFamily.CONTROL),
    )

    candidates = _detect_candidates(text, clues)
    addr = next((c for c in candidates if c.attr_type.value == "address"), None)
    assert addr is not None
    assert addr.text == "长安街道"


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


def test_name_label_and_start_no_longer_emit_label_text_as_name_candidate():
    candidates = _detect_candidates_from_scanner("家属姓名：罗嘉羽。")

    names = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME]

    assert [candidate.text for candidate in names] == ["罗嘉羽"]


def test_regular_name_label_path_remains_unchanged():
    candidates = _detect_candidates_from_scanner("姓名：罗嘉羽。")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["罗嘉羽"]
    assert candidates[0].claim_strength == ClaimStrength.HARD


def test_same_start_name_address_conflict_prefers_full_name_when_name_contains_city():
    candidates = _detect_candidates_from_scanner("登记的姓名是陈南宁。")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["陈南宁"]
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == []


@pytest.mark.parametrize(
    ("text", "expected_address"),
    [
        ("景明路187号", "景明路187号"),
        ("住址道路：景明路187号。", "景明路187号"),
        ("南京市鼓楼区景明路46号", "南京市鼓楼区景明路46号"),
        ("苏州市工业园区青年路323号国际广场1号楼5层1581室", "苏州市工业园区青年路323号国际广场1号楼5层1581室"),
    ],
)
def test_road_and_hao_chain_commit_full_address(text: str, expected_address: str):
    candidates = _detect_candidates_from_scanner(text)

    addresses = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS]

    assert [candidate.text for candidate in addresses] == [expected_address]
    assert addresses[0].claim_strength == ClaimStrength.HARD


def test_partial_overlap_keeps_trimmed_multi_unit_name_and_full_address():
    candidates = _detect_candidates_from_scanner("欧阳南京路88号")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["欧阳"]
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == ["南京路88号"]


def test_partial_overlap_with_single_unit_residual_falls_back_to_strength_compare():
    candidates = _detect_candidates_from_scanner("陈南宁路88号")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == []
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == ["南宁路88号"]


def test_plain_hao_fragment_is_not_promoted_without_context():
    candidates = _detect_candidates_from_scanner("187号")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == []
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NUM] == ["187"]


@pytest.mark.parametrize("text", ["国际广场1号楼", "10号楼"])
def test_existing_building_shapes_still_parse_as_address(text: str):
    candidates = _detect_candidates_from_scanner(text)

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == [text]

