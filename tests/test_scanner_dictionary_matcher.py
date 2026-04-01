"""dictionary matcher 的 scanner 回归测试。"""

from __future__ import annotations

import pytest

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector import scanner as scanner_module
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClueRole, DictionaryEntry
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle


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
    variants: tuple[str, ...] | None = None,
    matched_by: str,
    metadata: dict[str, list[str]] | None = None,
) -> DictionaryEntry:
    return DictionaryEntry(
        attr_type=attr_type,
        text=text,
        variants=variants or (text,),
        matched_by=matched_by,
        metadata=metadata or {},
    )


def test_local_dictionary_hard_clue_fields_match_legacy_contract():
    entry = _entry(
        text="Jordan Demo",
        matched_by="dictionary_local",
        metadata={"local_entity_ids": ["persona-1"], "name_component": ["full"]},
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
    assert clue.attr_type == PIIAttributeType.NAME
    assert clue.text == "Jordan Demo"
    assert clue.priority == 290
    assert clue.source_kind == "dictionary_local"
    assert clue.hard_source == "local"
    assert clue.source_metadata == {"local_entity_ids": ["persona-1"], "name_component": ["full"]}


def test_session_dictionary_hard_clue_fields_match_legacy_contract():
    entry = _entry(
        text="会话用户0001",
        matched_by="dictionary_session",
        metadata={"session_turn_ids": ["3"], "local_entity_ids": ["persona-7"]},
    )

    clues = scanner_module._scan_dictionary_hard_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "上一轮已经记录会话用户0001，请直接沿用。",
        (entry,),
        source_kind="session",
    )

    assert len(clues) == 1
    clue = clues[0]
    assert clue.attr_type == PIIAttributeType.NAME
    assert clue.text == "会话用户0001"
    assert clue.priority == 300
    assert clue.source_kind == "dictionary_session"
    assert clue.hard_source == "session"
    assert clue.source_metadata == {"session_turn_ids": ["3"], "local_entity_ids": ["persona-7"]}


def test_ascii_literal_keeps_word_boundary_behavior():
    entry = _entry(text="Ann", matched_by="dictionary_local")

    clues = scanner_module._scan_dictionary_hard_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "Annie met Ann and ann yesterday.",
        (entry,),
        source_kind="local",
    )

    assert [clue.text for clue in clues] == ["Ann", "ann"]


def test_non_ascii_literal_still_matches_substring():
    entry = _entry(text="张三", matched_by="dictionary_local")

    clues = scanner_module._scan_dictionary_hard_clues(
        DetectContext(protection_level=ProtectionLevel.STRONG),
        "王张三李",
        (entry,),
        source_kind="local",
    )

    assert len(clues) == 1
    assert clues[0].text == "张三"
    assert clues[0].start == 1
    assert clues[0].end == 3


def test_ignored_spans_still_filter_dictionary_matches():
    entry = _entry(text="Jordan", matched_by="dictionary_local")

    clues = scanner_module._scan_dictionary_hard_clues(
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


def test_build_clue_bundle_still_resolves_multi_variant_overlap_to_longer_match():
    entry = _entry(
        text="Jordan Demo",
        variants=("Jordan Demo", "Jordan"),
        matched_by="dictionary_local",
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
        if clue.role == ClueRole.HARD and clue.source_kind == "dictionary_local"
    ]
    assert len(dictionary_clues) == 1
    assert dictionary_clues[0].text == "Jordan Demo"


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
