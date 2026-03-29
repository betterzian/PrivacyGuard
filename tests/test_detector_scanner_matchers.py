from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.matcher import AhoMatcher, AhoPattern
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def test_aho_matcher_respects_ascii_boundaries_and_exact_unicode_terms() -> None:
    matcher = AhoMatcher.from_patterns(
        (
            AhoPattern(text="street", payload="street", ascii_boundary=True),
            AhoPattern(text="上海", payload="上海", ascii_boundary=False),
        )
    )

    matches = matcher.find_matches("上海 streetX street", folded_text="上海 streetx street")

    assert [(match.matched_text, match.payload) for match in matches] == [
        ("上海", "上海"),
        ("street", "street"),
    ]


def test_build_clue_bundle_does_not_leak_soft_clues_from_email_hard_span() -> None:
    stream = build_prompt_stream("foo@co.com")

    bundle = build_clue_bundle(
        stream,
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )

    assert any(clue.role == ClueRole.HARD and clue.attr_type == PIIAttributeType.EMAIL for clue in bundle.all_clues)
    assert not any(clue.family == ClueFamily.ORGANIZATION and clue.role == ClueRole.SUFFIX for clue in bundle.all_clues)
    assert not any(
        clue.family == ClueFamily.ADDRESS
        and clue.role == ClueRole.VALUE
        and clue.component_type == AddressComponentType.STATE
        for clue in bundle.all_clues
    )


def test_build_clue_bundle_keeps_real_address_keyword_without_bank_placeholder_leak() -> None:
    stream = build_prompt_stream("123456789012 Main Street")

    bundle = build_clue_bundle(
        stream,
        session_entries=(),
        local_entries=(),
        locale_profile="mixed",
    )

    assert any(
        clue.family == ClueFamily.ADDRESS
        and clue.role == ClueRole.KEY
        and clue.component_type == AddressComponentType.STREET
        for clue in bundle.all_clues
    )
    assert not any(clue.family == ClueFamily.ORGANIZATION and clue.role == ClueRole.SUFFIX for clue in bundle.all_clues)


def test_rule_based_detector_still_binds_label_to_hard_phone_after_segment_scanning() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="手机号码：13800138000",
        ocr_blocks=[],
    )

    phone = next(candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.PHONE)

    assert phone.text == "13800138000"
