"""dictionary matcher 的 scanner 回归测试。"""

from __future__ import annotations

import pytest

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector import scanner as scanner_module
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, ClueRole, DictionaryEntry
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_ocr_stream, build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK, _OCR_INLINE_GAP_TOKEN


@pytest.fixture(autouse=True)
def _clear_dictionary_matcher_caches():
    scanner_module._local_dictionary_matcher.cache_clear()
    scanner_module._session_dictionary_matcher.cache_clear()
    yield
    scanner_module._local_dictionary_matcher.cache_clear()
    scanner_module._session_dictionary_matcher.cache_clear()


def _entry(
    *,
    attr_type: PIIAttributeType = PIIAttributeType.NAME,
    text: str,
    match_terms: tuple[str, ...] | None = None,
    matched_by: str,
    metadata: dict[str, list[str]] | None = None,
) -> DictionaryEntry:
    return DictionaryEntry(
        attr_type=attr_type,
        match_terms=match_terms or (text,),
        matched_by=matched_by,
        metadata=metadata or {},
    )


def _ocr_block(text: str, *, block_id: str, line_id: int, x: int = 0, y: int = 0) -> OCRTextBlock:
    return OCRTextBlock(
        text=text,
        block_id=block_id,
        line_id=line_id,
        bbox=BoundingBox(x=x, y=y, width=max(10, len(text) * 10), height=20),
    )


def _first_segment(text: str):
    stream = build_prompt_stream(text)
    segments = scanner_module._build_soft_scan_segments(
        stream,
        (),
        inline_gap_spans=scanner_module._find_inline_gap_spans(stream),
    )
    return stream, segments[0]


def test_local_dictionary_hard_clue_fields_match_legacy_contract():
    entry = _entry(
        attr_type=PIIAttributeType.EMAIL,
        text="Jordan Demo",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"]},
    )

    clues = scanner_module._scan_dictionary_hard_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "Please contact Jordan Demo today.",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.role == ClueRole.VALUE
    assert clue.strength == ClaimStrength.HARD
    assert clue.attr_type == PIIAttributeType.EMAIL
    assert clue.text == "Jordan Demo"
    assert clue.source_kind == "dictionary_local"
    assert clue.source_metadata["hard_source"] == ["local"]
    assert clue.source_metadata["local_entity_ids"] == ["persona-1"]


def test_session_dictionary_hard_clue_fields_match_legacy_contract():
    entry = _entry(
        attr_type=PIIAttributeType.EMAIL,
        text="demo@example.com",
        matched_by="dictionary_session",
        metadata={"session_turn_ids": ["3"], "local_entity_ids": ["persona-7"]},
    )

    clues = scanner_module._scan_dictionary_hard_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "上一轮已经记录 demo@example.com，请直接沿用。",
        (entry,),
        source_kind="session",
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.attr_type == PIIAttributeType.EMAIL
    assert clue.text == "demo@example.com"
    assert clue.source_kind == "dictionary_session"
    assert clue.source_metadata["hard_source"] == ["session"]
    assert clue.source_metadata["session_turn_ids"] == ["3"]
    assert clue.source_metadata["local_entity_ids"] == ["persona-7"]


def test_ascii_literal_keeps_word_boundary_behavior_for_name_dictionary_clues():
    entry = _entry(text="Ann", matched_by="dictionary_local", metadata={"name_component": ["full"]})

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "Annie met Ann and ann yesterday.",
        (entry,),
        source_kind="local",
    )

    assert all(clue.role == ClueRole.FULL_NAME for clue in clues)
    assert [clue.text for clue in clues] == ["Ann", "ann"]


def test_prompt_stream_builds_single_layer_units_for_ascii_digit_cjk_and_tokens():
    stream = build_prompt_stream(f"12345678 apples h123 12345678a 张三 {_OCR_INLINE_GAP_TOKEN} {OCR_BREAK}")

    assert len(stream.char_to_unit) == len(stream.text)
    assert [unit.text for unit in stream.units if unit.kind == "digit_run"] == ["12345678"]
    assert [unit.text for unit in stream.units if unit.kind == "ascii_word"] == ["apples"]
    assert [unit.text for unit in stream.units if unit.kind == "alnum_run"] == ["h123", "12345678a"]
    assert [unit.text for unit in stream.units if unit.kind == "cjk_char"] == ["张", "三"]
    assert [unit.text for unit in stream.units if unit.kind == "inline_gap"] == [_OCR_INLINE_GAP_TOKEN]
    assert [unit.text for unit in stream.units if unit.kind == "ocr_break"] == [OCR_BREAK]

    inline_start = stream.text.index(_OCR_INLINE_GAP_TOKEN)
    ocr_break_start = stream.text.index(OCR_BREAK)
    assert len(set(stream.char_to_unit[inline_start : inline_start + len(_OCR_INLINE_GAP_TOKEN)])) == 1
    assert len(set(stream.char_to_unit[ocr_break_start : ocr_break_start + len(OCR_BREAK)])) == 1


def test_prompt_stream_normalizes_fullwidth_parentheses_only():
    stream = build_prompt_stream("备注【测试】（+86）13812345678")

    assert stream.text == "备注【测试】(+86)13812345678"


def test_hard_pattern_scan_prefers_alnum_fragment_over_nested_digit_fragment():
    stream = build_prompt_stream("h123 12345678a")

    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    assert [(clue.source_kind, clue.text, clue.attr_type) for clue in clues] == [
        ("extract_alnum_fragment", "h123", PIIAttributeType.ALNUM),
        ("extract_alnum_fragment", "12345678a", PIIAttributeType.ALNUM),
    ]


def test_hard_pattern_scan_matches_email_when_preceded_by_chinese_text():
    stream = build_prompt_stream("备用邮箱填kctfqcb33@163.com")

    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    assert [(clue.source_kind, clue.text, clue.attr_type) for clue in clues] == [
        ("regex_email", "kctfqcb33@163.com", PIIAttributeType.EMAIL),
    ]


def test_hard_pattern_scan_keeps_plain_email_boundary_behavior():
    stream = build_prompt_stream("邮箱是 kctfqcb33@163.com")

    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    assert [(clue.source_kind, clue.text, clue.attr_type) for clue in clues] == [
        ("regex_email", "kctfqcb33@163.com", PIIAttributeType.EMAIL),
    ]



def test_non_ascii_literal_still_matches_substring():
    entry = _entry(text="张三", matched_by="dictionary_local", metadata={"name_component": ["full"]})

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "王张三李",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    assert clues[0].text == "张三"
    assert clues[0].start == 1
    assert clues[0].end == 3


@pytest.mark.parametrize(
    ("raw_text", "expected_text"),
    [
        ("张 三 宝", "张 三 宝"),
        ("张 三  宝", "张 三 宝"),
        ("张 三   宝", "张 三 宝"),
        ("张三 宝，", "张三 宝，"),
        ("张三   宝，", "张三 宝，"),
    ],
)
def test_build_ocr_stream_rewrites_cjk_whitespace(raw_text: str, expected_text: str):
    prepared = build_ocr_stream([_ocr_block(raw_text, block_id="b1", line_id=0)])

    assert prepared.stream.text == expected_text


def test_build_ocr_stream_normalizes_fullwidth_parentheses_only():
    prepared = build_ocr_stream([_ocr_block("备注【测试】（+86）13812345678", block_id="b1", line_id=0)])

    assert prepared.stream.text == "备注【测试】(+86)13812345678"


def test_ignored_spans_still_filter_dictionary_matches():
    entry = _entry(text="Jordan", matched_by="dictionary_local", metadata={"name_component": ["full"]})

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "Jordan Jordan",
        (entry,),
        source_kind="local",
        ignored_spans=((0, 6),),
    )

    assert len(clues) == 1
    assert clues[0].text == "Jordan"
    assert clues[0].start == 7
    assert clues[0].end == 13


def test_ascii_dictionary_match_only_accepts_exact_s_and_es_word_units():
    entry = _entry(attr_type=PIIAttributeType.ORGANIZATION, text="apple", matched_by="dictionary_local")
    stream = build_prompt_stream("apple apples applees pineapple applex appel applies")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(entry,),
        locale_profile="mixed",
    )

    dictionary_clues = [
        clue
        for clue in bundle.all_clues
        if clue.strength == ClaimStrength.HARD and clue.source_kind == "dictionary_local"
    ]
    assert [clue.text for clue in dictionary_clues] == ["apple", "apples", "applees"]
    assert [clue.unit_last - clue.unit_start + 1 for clue in dictionary_clues] == [1, 1, 1]
    assert [stream.units[clue.unit_start].text for clue in dictionary_clues] == ["apple", "apples", "applees"]


def test_find_ocr_break_spans_reads_from_synthetic_units():
    prepared = build_ocr_stream(
        [
            _ocr_block("张 三   宝", block_id="b1", line_id=0, y=0),
            # y=41：垂距 21 > 上行 block 高 20，跨行不拼接，保留段间 semantic break。
            _ocr_block("第二行", block_id="b2", line_id=1, y=41),
        ]
    )

    spans = scanner_module._find_ocr_break_spans(prepared.stream)

    assert [prepared.stream.text[start:end] for start, end in spans] == [OCR_BREAK]
    assert [
        prepared.stream.units[prepared.stream.char_to_unit[start]].kind
        for start, _end in spans
    ] == ["ocr_break"]


def test_build_clue_bundle_still_resolves_multi_variant_overlap_to_longer_match():
    entry = _entry(
        text="Jordan Demo",
        match_terms=("Jordan Demo", "Jordan"),
        matched_by="dictionary_local",
        metadata={"name_component": ["full"]},
    )
    stream = build_prompt_stream("Jordan Demo")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(entry,),
        locale_profile="mixed",
    )

    dictionary_clues = [
        clue for clue in bundle.all_clues
        if clue.source_kind == "dictionary_local"
    ]
    assert len(dictionary_clues) == 1
    assert dictionary_clues[0].text == "Jordan Demo"
    assert dictionary_clues[0].role == ClueRole.FULL_NAME


def test_name_full_match_still_wins_over_family_and_given_overlap():
    entries = (
        _entry(
            text="Jordan Demo",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["full"]},
        ),
        _entry(
            text="Jordan",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["given"]},
        ),
        _entry(
            text="Demo",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["family"]},
        ),
    )
    stream = build_prompt_stream("Jordan Demo")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=entries,
        locale_profile="mixed",
    )

    dictionary_clues = [
        clue for clue in bundle.all_clues
        if clue.source_kind == "dictionary_local"
    ]
    assert len(dictionary_clues) == 1
    assert dictionary_clues[0].text == "Jordan Demo"
    assert dictionary_clues[0].source_metadata["name_component"] == ["full"]
    assert dictionary_clues[0].role == ClueRole.FULL_NAME


def test_name_full_match_still_wins_over_alias_overlap():
    entries = (
        _entry(
            text="Jordan Demo",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["full"]},
        ),
        _entry(
            text="Jordan",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["alias"]},
        ),
        _entry(
            text="Jordan",
            matched_by="dictionary_local",
            metadata={"local_entity_ids": ["persona-1"], "name_component": ["given"]},
        ),
    )
    stream = build_prompt_stream("Jordan Demo")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=entries,
        locale_profile="mixed",
    )

    dictionary_clues = [
        clue for clue in bundle.all_clues
        if clue.source_kind == "dictionary_local"
    ]
    assert len(dictionary_clues) == 1
    assert dictionary_clues[0].text == "Jordan Demo"
    assert dictionary_clues[0].role == ClueRole.FULL_NAME


def test_name_alias_entry_is_exposed_as_independent_component():
    entry = _entry(
        text="阿宝",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"], "name_component": ["alias"]},
    )

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "联系人阿宝今天会到。",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    assert clues[0].text == "阿宝"
    assert clues[0].source_metadata["name_component"] == ["alias"]
    assert clues[0].role == ClueRole.ALIAS


def test_name_middle_entry_is_mapped_to_given_name_role():
    entry = _entry(
        text="Marie",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"], "name_component": ["middle"]},
    )

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "Ann Marie Demo",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    assert clues[0].text == "Marie"
    assert clues[0].source_metadata["name_component"] == ["middle"]
    assert clues[0].role == ClueRole.GIVEN_NAME


def test_chinese_dictionary_family_entry_is_downgraded_to_soft_surname_clue():
    entry = _entry(
        text="王",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"], "name_component": ["family"]},
    )

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "王伟来了",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.role == ClueRole.FAMILY_NAME
    # "王"在 scanner weak claim_strength 词表中，词典姓氏与 scanner 词库重合时以 scanner 词表为准。
    assert clue.strength == ClaimStrength.WEAK
    assert "hard_source" not in clue.source_metadata
    assert clue.source_metadata["surname_claim_strength"] == ["weak"]
    assert clue.source_metadata["surname_match_kind"] == ["single"]
    assert clue.source_metadata["surname_from_dictionary"] == ["1"]


def test_chinese_dictionary_custom_family_entry_keeps_soft_custom_tier():
    entry = _entry(
        text="第五",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"], "name_component": ["family"]},
    )

    clues = scanner_module._scan_name_dictionary_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "第五明提交了申请",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.role == ClueRole.FAMILY_NAME
    assert clue.strength == ClaimStrength.SOFT
    assert clue.source_metadata["surname_claim_strength"] == ["soft"]
    assert clue.source_metadata["surname_match_kind"] == ["compound"]
    assert clue.source_metadata["surname_from_dictionary"] == ["1"]


def test_label_seed_metadata_keeps_boundary_signals():
    ctx = DetectContext(protection_level=ProtectionLevel.STRONG)
    _stream_a, segment_a = _first_segment("姓名: 张三")
    _stream_b, segment_b = _first_segment("这里的姓名 张三")

    label_a = scanner_module._scan_label_clues(ctx, segment_a)[0]
    label_b = scanner_module._scan_label_clues(ctx, segment_b)[0]

    assert label_a.source_metadata["seed_has_connector_after"] == ["1"]
    assert label_a.source_metadata["seed_is_left_edge"] == ["1"]
    assert label_b.source_metadata["seed_has_connector_after"] == ["0"]
    assert label_b.source_metadata["seed_is_left_edge"] == ["0"]


def test_non_boundary_structured_label_is_dropped_instead_of_becoming_hint():
    ctx = DetectContext(protection_level=ProtectionLevel.STRONG)
    stream = build_prompt_stream("这里的手机1234")
    bundle = build_clue_bundle(
        stream,
        ctx=ctx,
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )
    parsed = StreamParser(locale_profile="mixed", ctx=ctx).parse(stream, bundle)

    assert not any(clue.role == ClueRole.LABEL and clue.text == "手机" for clue in bundle.all_clues)
    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].attr_type == PIIAttributeType.NUM
    assert "label_hint_attr" not in parsed.candidates[0].metadata


def test_start_seed_metadata_marks_start_kind():
    ctx = DetectContext(protection_level=ProtectionLevel.STRONG)
    _stream, segment = _first_segment("我叫张三")

    start = scanner_module._scan_name_start_clues(ctx, segment)[0]

    assert start.source_metadata["seed_kind"] == ["start"]


def test_family_name_scanner_keeps_compound_surname_before_address_terms():
    ctx = DetectContext(protection_level=ProtectionLevel.STRONG)
    _stream, segment = _first_segment("司马名区中山路")

    clues = scanner_module._scan_family_name_clues(ctx, segment)

    assert any(
        clue.role == ClueRole.FAMILY_NAME
        and clue.text == "司马"
        and clue.strength == ClaimStrength.HARD
        for clue in clues
    )


def test_name_component_coverage_drops_contained_family_name_clue():
    stream = build_prompt_stream("司马名区中山路")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )

    family_name_clues = sorted(
        (
            clue.text,
            clue.start,
            clue.end,
            clue.strength,
        )
        for clue in bundle.all_clues
        if clue.role == ClueRole.FAMILY_NAME and clue.start == 0
    )

    assert family_name_clues == [("司马", 0, 2, ClaimStrength.HARD)]



def test_scanner_no_longer_emits_generic_zh_given_name_clues():
    stream = build_prompt_stream("可欣今天到了")

    bundle = build_clue_bundle(
        stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )

    assert not any(
        clue.role == ClueRole.GIVEN_NAME and clue.source_kind == "zh_given_name"
        for clue in bundle.all_clues
    )


def test_parser_keeps_char_span_and_unit_span_for_dictionary_name_candidate():
    ctx = DetectContext(protection_level=ProtectionLevel.STRONG)
    entry = _entry(text="Jordan Demo", matched_by="dictionary_local", metadata={"name_component": ["full"]})
    stream = build_prompt_stream("Please contact Jordan Demo today.")
    bundle = build_clue_bundle(
        stream,
        ctx=ctx,
        session_entries=(),
        local_entries=(entry,),
        locale_profile="mixed",
    )

    parsed = StreamParser(locale_profile="mixed", ctx=ctx).parse(stream, bundle)
    dictionary_candidates = [candidate for candidate in parsed.candidates if candidate.source_kind == "dictionary_local"]

    assert len(dictionary_candidates) == 1
    candidate = dictionary_candidates[0]
    assert stream.text[candidate.start : candidate.end] == "Jordan Demo"
    assert [unit.text for unit in stream.units[candidate.unit_start : candidate.unit_last + 1]] == ["Jordan", " ", "Demo"]


def test_session_dictionary_matcher_cache_reuses_same_content_signature():
    sig1 = scanner_module._dictionary_matcher_signature(
        (_entry(text="会话用户0001", matched_by="dictionary_session"),)
    )
    sig2 = scanner_module._dictionary_matcher_signature(
        (_entry(text="会话用户0001", matched_by="dictionary_session"),)
    )

    matcher1 = scanner_module._session_dictionary_matcher(sig1)
    info_after_first = scanner_module._session_dictionary_matcher.cache_info()
    matcher2 = scanner_module._session_dictionary_matcher(sig2)
    info_after_second = scanner_module._session_dictionary_matcher.cache_info()

    assert matcher1 is matcher2
    assert info_after_first.misses == 1
    assert info_after_second.misses == 1
    assert info_after_second.hits == 1


def test_session_dictionary_matcher_cache_rebuilds_when_content_changes():
    sig1 = scanner_module._dictionary_matcher_signature(
        (_entry(text="会话用户0001", matched_by="dictionary_session"),)
    )
    sig2 = scanner_module._dictionary_matcher_signature(
        (_entry(text="会话用户0002", matched_by="dictionary_session"),)
    )

    matcher1 = scanner_module._session_dictionary_matcher(sig1)
    matcher2 = scanner_module._session_dictionary_matcher(sig2)
    info = scanner_module._session_dictionary_matcher.cache_info()

    assert matcher1 is not matcher2
    assert info.misses == 2
    assert info.hits == 0


def test_local_dictionary_matcher_cache_rebuilds_when_content_changes():
    sig1 = scanner_module._dictionary_matcher_signature(
        (_entry(text="Jordan Demo", matched_by="dictionary_local"),)
    )
    sig2 = scanner_module._dictionary_matcher_signature(
        (_entry(text="Jordan Demo", matched_by="dictionary_local", metadata={"local_entity_ids": ["persona-2"]}),)
    )

    matcher1 = scanner_module._local_dictionary_matcher(sig1)
    matcher2 = scanner_module._local_dictionary_matcher(sig2)
    info = scanner_module._local_dictionary_matcher.cache_info()

    assert matcher1 is not matcher2
    assert info.misses == 2
    assert info.hits == 0


def test_session_name_dictionary_clues_stay_within_ocr_segment_bounds():
    session_entry = _entry(
        text="张明",
        matched_by="dictionary_session",
        metadata={"name_component": ["full"]},
    )
    prepared = build_ocr_stream(
        [
            _ocr_block("联系人 张明", block_id="b1", line_id=0, x=24, y=18),
            _ocr_block("联系电话 13800138000", block_id="b2", line_id=0, x=244, y=18),
            _ocr_block("备用邮箱 zhangming@example.com", block_id="b3", line_id=0, x=464, y=18),
            _ocr_block("收货地址 上海市闵行区", block_id="b4", line_id=0, x=684, y=18),
            _ocr_block("申长路88号 A座1203", block_id="b5", line_id=1, x=24, y=46),
            _ocr_block("发票抬头 星云科技有限公司", block_id="b6", line_id=1, x=244, y=46),
            _ocr_block("历史联系人 张明", block_id="b7", line_id=1, x=464, y=46),
            _ocr_block("备用号码 13912341234", block_id="b8", line_id=1, x=684, y=46),
        ]
    )

    bundle = build_clue_bundle(
        prepared.stream,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(session_entry,),
        local_entries=(),
        locale_profile="mixed",
    )

    session_name_clues = [
        clue
        for clue in bundle.all_clues
        if clue.source_kind == "dictionary_session"
        and clue.attr_type == PIIAttributeType.NAME
    ]
    assert [clue.text for clue in session_name_clues] == ["张明", "张明"]
    for clue in session_name_clues:
        assert clue.start >= 0
        assert clue.end <= len(prepared.stream.text)
        assert prepared.stream.text[clue.start : clue.end] == "张明"


def test_build_clue_bundle_emits_control_value_number_clues_for_zh_address_tokens():
    prepared = build_prompt_stream("甲2楼 一百室 子单元")

    bundle = build_clue_bundle(
        prepared,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(),
        locale_profile="zh_cn",
    )

    control_values = [
        clue
        for clue in bundle.all_clues
        if clue.source_kind == "control_value_zh"
    ]

    payloads = {(clue.text, tuple(clue.source_metadata.get("normalized_number", []))) for clue in control_values}

    assert ("甲", ("甲",)) in payloads
    assert ("一百", ("100",)) in payloads
    assert ("子", ("子",)) in payloads


def test_scan_control_value_clues_emits_en_copula_words_before_conflict_resolution():
    _stream, segment = _first_segment("This is Liam, they are James, and I am Noah")

    control_values = scanner_module._scan_control_value_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        segment,
        locale_profile="en_us",
    )

    assert [clue.text.lower() for clue in control_values] == ["is", "are", "am"]
    assert all(clue.source_metadata.get("control_kind") == ["copula_en"] for clue in control_values)

@pytest.mark.parametrize(
    ("text", "expected_value"),
    [
        ("登记时间3月13日16:50", "3月13日16:50"),
        ("到达时间是 2026年3月13日16:50", "2026年3月13日16:50"),
        ("出发时间 2026-03-13 16:50:22", "2026-03-13 16:50:22"),
        ("记录在2026.03.13 16:50", "2026.03.13 16:50"),
    ],
)
def test_hard_pattern_scan_matches_expanded_time_formats(text: str, expected_value: str):
    stream = build_prompt_stream(text)
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    time_values = [clue.text for clue in clues if clue.attr_type == PIIAttributeType.TIME]
    assert expected_value in time_values


def test_hard_pattern_scan_matches_md_clock_without_inner_clock_duplicate():
    stream = build_prompt_stream("arrival 03/13 16:50 update")
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    time_clues = [clue for clue in clues if clue.attr_type == PIIAttributeType.TIME]

    assert [clue.text for clue in time_clues] == ["03/13 16:50"]
    assert not any(clue.source_kind == "time_clock" for clue in time_clues)


def test_hard_pattern_scan_does_not_match_standalone_md():
    stream = build_prompt_stream("arrival 03/13 only")
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    assert not any(
        clue.attr_type == PIIAttributeType.TIME and clue.text == "03/13"
        for clue in clues
    )


def test_hard_pattern_scan_matches_amount_before_generic_fragments():
    stream = build_prompt_stream("金额填¥88、532.00元、USD 12和181.00 dollars")
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    amount_values = [clue.text for clue in clues if clue.attr_type == PIIAttributeType.AMOUNT]
    assert amount_values == ["¥88", "532.00元", "USD 12", "181.00 dollars"]
    assert not any(
        clue.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}
        and clue.text in {"88", "532.00", "12", "181.00"}
        for clue in clues
    )


@pytest.mark.parametrize(
    ("text", "expected_text", "expected_region", "expected_pattern"),
    [
        ("（+86）13812345678", "(+86)13812345678", "cn", "cn_country_code_paren"),
        ("+86 138-1234-5678", "+86 138-1234-5678", "cn", "cn_country_code"),
        ("8613812345678", "8613812345678", "cn", "cn_country_code"),
        ("（+1）4152671234", "(+1)4152671234", "us", "us_country_code_paren"),
        ("+1 4152671234", "+1 4152671234", "us", "us_country_code"),
        ("1（415）2671234", "1(415)2671234", "us", "us_trunk_area_paren"),
    ],
)
def test_hard_pattern_scan_keeps_phone_structure_as_single_fragment(
    text: str,
    expected_text: str,
    expected_region: str,
    expected_pattern: str,
):
    stream = build_prompt_stream(text)
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.attr_type == PIIAttributeType.NUM
    assert clue.text == expected_text
    assert clue.source_metadata["phone_region"] == [expected_region]
    assert clue.source_metadata["phone_pattern"] == [expected_pattern]


def test_hard_pattern_scan_matches_alnum_with_underscore_and_hyphen():
    stream = build_prompt_stream("abc_123 A1-B2 abc-def 123_456")
    clues = scanner_module._scan_hard_patterns(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        stream,
    )

    alnum_values = [clue.text for clue in clues if clue.attr_type == PIIAttributeType.ALNUM]
    assert alnum_values == ["abc_123", "A1-B2"]


def test_build_clue_bundle_emits_license_plate_prefix_family_value_clue():
    prepared = build_prompt_stream("登记车牌是粤A12345，地址是甲2楼")

    bundle = build_clue_bundle(
        prepared,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(),
        locale_profile="zh_cn",
    )

    plate_clues = [
        clue
        for clue in bundle.all_clues
        if clue.source_kind == "lexicon_license_plate_prefix_zh"
    ]
    assert len(plate_clues) == 1
    assert plate_clues[0].text == "粤"
    assert plate_clues[0].attr_type == PIIAttributeType.LICENSE_PLATE
    assert plate_clues[0].family == scanner_module.ClueFamily.LICENSE_PLATE

    control_values = [
        clue
        for clue in bundle.all_clues
        if clue.source_kind == "control_value_zh"
    ]
    assert not any(clue.text == "粤" for clue in control_values)
    assert any(clue.text == "甲" for clue in control_values)


def test_license_plate_start_seed_covers_contained_name_clue():
    prepared = build_prompt_stream("车牌是粤A12345")

    bundle = build_clue_bundle(
        prepared,
        ctx=DetectContext(protection_level=ProtectionLevel.STRONG),
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )

    assert any(
        clue.family == scanner_module.ClueFamily.LICENSE_PLATE
        and clue.role == ClueRole.START
        and clue.text == "车牌是"
        for clue in bundle.all_clues
    )
    assert not any(
        clue.role == ClueRole.FAMILY_NAME and clue.text == "车"
        for clue in bundle.all_clues
    )


