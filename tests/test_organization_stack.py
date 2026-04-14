"""组织名栈行为测试。"""

from __future__ import annotations

from dataclasses import replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueBundle, ClueFamily, ClueRole, build_clue_index, build_negative_unit_index
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks.common import _char_span_to_unit_span
from privacyguard.infrastructure.pii.detector.stacks import OrganizationStack


def _clue(
    clue_id: str,
    role: ClueRole,
    start: int,
    end: int,
    text: str,
    *,
    source_kind: str,
    attr_type: PIIAttributeType | None = PIIAttributeType.ORGANIZATION,
    hard_source: str | None = None,
    strength: ClaimStrength = ClaimStrength.SOFT,
) -> Clue:
    md: dict[str, list[str]] = {}
    if hard_source:
        md["hard_source"] = [hard_source]
    return Clue(
        clue_id=clue_id,
        family=ClueFamily.CONTROL if role == ClueRole.NEGATIVE or attr_type is None else ClueFamily.ORGANIZATION,
        role=role,
        attr_type=attr_type,
        strength=strength,
        start=start,
        end=end,
        text=text,
        source_kind=source_kind,
        source_metadata=md,
    )


def _run_organization_stack(
    text: str,
    clue_index: int,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
) -> OrganizationStack:
    stream = build_prompt_stream(text)
    fixed, index_by_id, negative_unit_marks, negative_prefix_sum, negative_start_weight = _split_negative_clues(stream, clues)
    target = clues[clue_index]
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=protection_level,
        clues=fixed,
        negative_unit_marks=negative_unit_marks,
        negative_prefix_sum=negative_prefix_sum,
        negative_start_weight=negative_start_weight,
        clue_index=build_clue_index(len(stream.units), fixed),
    )
    fixed_index = index_by_id[target.clue_id]
    return OrganizationStack(clue=fixed[fixed_index], clue_index=fixed_index, context=context)


def _parse_organization_texts(
    text: str,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
) -> list[str]:
    stream = build_prompt_stream(text)
    fixed, _, negative_unit_marks, negative_prefix_sum, negative_start_weight = _split_negative_clues(stream, clues)
    parser = StreamParser(
        locale_profile="mixed",
        ctx=DetectContext(protection_level=protection_level),
    )
    result = parser.parse(
        stream,
        ClueBundle(
            all_clues=fixed,
            negative_unit_marks=negative_unit_marks,
            negative_prefix_sum=negative_prefix_sum,
            negative_start_weight=negative_start_weight,
            clue_index=build_clue_index(len(stream.units), fixed),
        ),
    )
    return [candidate.text for candidate in result.candidates if candidate.attr_type == PIIAttributeType.ORGANIZATION]


def _with_units(stream, clue: Clue) -> Clue:
    unit_start, unit_end = _char_span_to_unit_span(stream, clue.start, clue.end)
    return replace(clue, unit_start=unit_start, unit_end=unit_end)


def _split_negative_clues(
    stream,
    clues: tuple[Clue, ...],
) -> tuple[tuple[Clue, ...], dict[str, int], list[int], list[int], int]:
    fixed_clues: list[Clue] = []
    index_by_id: dict[str, int] = {}
    negative_spans: list[tuple[int, int]] = []
    for clue in clues:
        fixed = _with_units(stream, clue)
        if fixed.role == ClueRole.NEGATIVE:
            negative_spans.append((fixed.unit_start, fixed.unit_end))
            continue
        index_by_id[fixed.clue_id] = len(fixed_clues)
        fixed_clues.append(fixed)
    negative_unit_marks, negative_prefix_sum, negative_start_weight = build_negative_unit_index(
        len(stream.units),
        negative_spans,
    )
    return tuple(fixed_clues), index_by_id, negative_unit_marks, negative_prefix_sum, negative_start_weight


def test_label_seed_skips_separators_and_starts_from_first_value_char():
    text = "公司名称： 星河科技"
    label = "公司名称"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            len(label),
            label,
            source_kind="context_organization_field",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == "星河科技"


def test_suffix_seed_can_start_under_weak():
    text = "星河科技公司"
    suffix = "公司"
    start = text.index(suffix)
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            start,
            start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == "星河科技公司"


def test_label_seed_prefers_suffix_within_ten_non_space_units():
    text = "company name: Blue River Labs Ltd"
    label = "company name"
    suffix = "Ltd"
    label_start = text.index(label)
    suffix_start = text.index(suffix)
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            label_start,
            label_start + len(label),
            label,
            source_kind="context_organization_field",
        ),
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            suffix_start,
            suffix_start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Blue River Labs Ltd"


def test_label_seed_caps_zh_length_without_suffix():
    text = "公司名称：甲乙丙丁戊己庚"
    label = "公司名称"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            len(label),
            label,
            source_kind="context_organization_field",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "甲乙丙丁戊己"


def test_label_seed_caps_en_length_without_suffix():
    text = "company name: Alpha Beta Gamma Delta Echo"
    label = "company name"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            len(label),
            label,
            source_kind="context_organization_field",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Alpha Beta Gamma Delta"


def test_suffix_seed_caps_zh_left_expansion():
    text = "甲乙丙丁戊己庚公司"
    suffix = "公司"
    start = text.index(suffix)
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            start,
            start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "乙丙丁戊己庚公司"


def test_suffix_seed_caps_en_left_expansion():
    text = "Alpha Beta Gamma Delta Echo Ltd"
    suffix = "Ltd"
    start = text.index(suffix)
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            start,
            start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Beta Gamma Delta Echo Ltd"


def test_suffix_seed_left_expansion_stops_at_negative_boundary():
    text = "路由科技公司"
    suffix = "公司"
    start = text.index(suffix)
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            start,
            start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
        _clue(
            "neg-1",
            ClueRole.NEGATIVE,
            0,
            2,
            "路由",
            source_kind="negative_org_word",
            attr_type=None,
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "科技公司"


def test_suffix_only_candidate_is_rejected():
    text = "有限公司"
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            0,
            len(text),
            text,
            source_kind="company_suffix",
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is None


def test_hard_seed_submits_directly():
    text = "Acme LLC"
    clues = (
        _clue(
            "hard-1",
            ClueRole.VALUE,
            0,
            len(text),
            text,
            source_kind="dictionary_local",
            hard_source="local",
            strength=ClaimStrength.HARD,
        ),
    )

    run = _run_organization_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == text
    assert run.candidate.claim_strength.value == "hard"


def test_parser_label_path_matches_between_weak_and_strong():
    text = "company name: Blue River Labs Ltd"
    label = "company name"
    suffix = "Ltd"
    label_start = text.index(label)
    suffix_start = text.index(suffix)
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            label_start,
            label_start + len(label),
            label,
            source_kind="context_organization_field",
        ),
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            suffix_start,
            suffix_start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    weak = _parse_organization_texts(text, clues, protection_level=ProtectionLevel.WEAK)
    strong = _parse_organization_texts(text, clues, protection_level=ProtectionLevel.STRONG)

    assert weak == ["Blue River Labs Ltd"]
    assert strong == weak


def test_parser_suffix_path_matches_between_weak_and_strong():
    text = "星河科技公司"
    suffix = "公司"
    start = text.index(suffix)
    clues = (
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            start,
            start + len(suffix),
            suffix,
            source_kind="company_suffix",
        ),
    )

    weak = _parse_organization_texts(text, clues, protection_level=ProtectionLevel.WEAK)
    strong = _parse_organization_texts(text, clues, protection_level=ProtectionLevel.STRONG)

    assert weak == ["星河科技公司"]
    assert strong == weak
