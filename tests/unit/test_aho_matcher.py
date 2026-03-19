from privacyguard.utils.aho_matcher import AhoCorasickMatcher


def test_aho_matcher_returns_overlapping_matches_in_stream_order() -> None:
    matcher = AhoCorasickMatcher(["哈尔滨", "哈尔滨市", "江宁区"])

    matches = list(matcher.finditer("哈尔滨市江宁区"))

    assert matches == [
        (0, 3, "哈尔滨"),
        (0, 4, "哈尔滨市"),
        (4, 7, "江宁区"),
    ]


def test_aho_matcher_deduplicates_patterns_and_prefers_deterministic_output_order() -> None:
    matcher = AhoCorasickMatcher(["江宁区", "江宁区", "江宁"])

    matches = list(matcher.finditer("江宁区"))

    assert matches == [
        (0, 2, "江宁"),
        (0, 3, "江宁区"),
    ]
