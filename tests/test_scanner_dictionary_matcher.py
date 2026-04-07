"""dictionary matcher 的 scanner 回归测试。"""

from __future__ import annotations

import pytest

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector import scanner as scanner_module
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClueRole, DictionaryEntry
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
    assert clue.role == ClueRole.HARD
    assert clue.attr_type == PIIAttributeType.EMAIL
    assert clue.text == "Jordan Demo"
    assert clue.priority == 290
    assert clue.source_kind == "dictionary_local"
    assert clue.hard_source == "local"
    assert clue.source_metadata == {"local_entity_ids": ["persona-1"]}


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
    assert clue.priority == 300
    assert clue.source_kind == "dictionary_session"
    assert clue.hard_source == "session"
    assert clue.source_metadata == {"session_turn_ids": ["3"], "local_entity_ids": ["persona-7"]}


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
    stream = build_prompt_stream(f"12345678 apples 张三 {_OCR_INLINE_GAP_TOKEN} {OCR_BREAK}")

    assert len(stream.char_to_unit) == len(stream.text)
    assert [unit.text for unit in stream.units if unit.kind == "digit_char"] == list("12345678")
    assert [unit.text for unit in stream.units if unit.kind == "ascii_word"] == ["apples"]
    assert [unit.text for unit in stream.units if unit.kind == "cjk_char"] == ["张", "三"]
    assert [unit.text for unit in stream.units if unit.kind == "inline_gap"] == [_OCR_INLINE_GAP_TOKEN]
    assert [unit.text for unit in stream.units if unit.kind == "ocr_break"] == [OCR_BREAK]

    inline_start = stream.text.index(_OCR_INLINE_GAP_TOKEN)
    ocr_break_start = stream.text.index(OCR_BREAK)
    assert len(set(stream.char_to_unit[inline_start : inline_start + len(_OCR_INLINE_GAP_TOKEN)])) == 1
    assert len(set(stream.char_to_unit[ocr_break_start : ocr_break_start + len(OCR_BREAK)])) == 1


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
        if clue.role == ClueRole.HARD and clue.source_kind == "dictionary_local"
    ]
    assert [clue.text for clue in dictionary_clues] == ["apple", "apples", "applees"]
    assert [clue.unit_end - clue.unit_start for clue in dictionary_clues] == [1, 1, 1]
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
    assert [unit.text for unit in stream.units[candidate.unit_start : candidate.unit_end]] == ["Jordan", " ", "Demo"]


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
