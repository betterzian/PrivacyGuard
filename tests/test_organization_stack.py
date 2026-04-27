"""组织名栈行为测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueBundle, ClueFamily, ClueRole, InspireEntry
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks import OrganizationStack
from privacyguard.infrastructure.pii.detector.stacks.organization_en import EnOrganizationStack
from tests._detector_negative_index import build_test_bundle_with_inspire, split_negative_clues


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
    fixed, negative_clues, index_by_id, unit_index = _split_negative_clues(stream, clues)
    target = clues[clue_index]
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=protection_level,
        clues=fixed,
        negative_clues=negative_clues,
        unit_index=unit_index,
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
    fixed, negative_clues, _index_by_id, unit_index = _split_negative_clues(stream, clues)
    parser = StreamParser(
        locale_profile="mixed",
        ctx=DetectContext(protection_level=protection_level),
    )
    result = parser.parse(
        stream,
        ClueBundle(
            all_clues=fixed,
            negative_clues=negative_clues,
            unit_index=unit_index,
        ),
    )
    return [candidate.text for candidate in result.candidates if candidate.attr_type == PIIAttributeType.ORGANIZATION]


def _build_organization_context(
    text: str,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
) -> tuple[object, tuple[Clue, ...], dict[str, int], StackContext]:
    stream = build_prompt_stream(text)
    fixed, negative_clues, index_by_id, unit_index = _split_negative_clues(stream, clues)
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=protection_level,
        clues=fixed,
        negative_clues=negative_clues,
        unit_index=unit_index,
    )
    return stream, fixed, index_by_id, context

def _split_negative_clues(
    stream,
    clues: tuple[Clue, ...],
) -> tuple[tuple[Clue, ...], tuple[Clue, ...], dict[str, int], tuple]:
    return split_negative_clues(stream, clues)


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


def test_label_seed_respects_organization_value_floor_start():
    text = "公司名称：蓝河科技有限公司"
    label = "公司名称"
    stream, fixed, index_by_id, context = _build_organization_context(
        text,
        (
            _clue(
                "label-1",
                ClueRole.LABEL,
                0,
                len(label),
                label,
                source_kind="context_organization_field",
            ),
        ),
        protection_level=ProtectionLevel.STRONG,
    )
    locked_unit = stream.char_to_unit[text.index("蓝")]
    context.raise_stack_value_floor(ClueFamily.ORGANIZATION, locked_unit)

    run = OrganizationStack(clue=fixed[index_by_id["label-1"]], clue_index=index_by_id["label-1"], context=context).run()

    assert run is not None
    assert run.candidate.text.startswith("河科技")
    assert not run.candidate.text.startswith("蓝")


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

    assert run is None


def test_value_seed_before_organization_value_floor_is_rejected():
    text = "星河科技有限公司"
    stream, fixed, index_by_id, context = _build_organization_context(
        text,
        (
            _clue(
                "value-1",
                ClueRole.VALUE,
                0,
                4,
                "星河科技",
                source_kind="dictionary_local",
            ),
            _clue(
                "suffix-1",
                ClueRole.SUFFIX,
                4,
                len(text),
                "有限公司",
                source_kind="company_suffix",
            ),
        ),
        protection_level=ProtectionLevel.WEAK,
    )
    context.raise_stack_value_floor(ClueFamily.ORGANIZATION, fixed[index_by_id["value-1"]].unit_start)

    run = OrganizationStack(clue=fixed[index_by_id["value-1"]], clue_index=index_by_id["value-1"], context=context).run()

    assert stream.text == text
    assert run is None


def test_suffix_seed_left_expansion_respects_organization_value_floor():
    text = "蓝河科技有限公司"
    stream, fixed, index_by_id, context = _build_organization_context(
        text,
        (
            _clue(
                "suffix-1",
                ClueRole.SUFFIX,
                text.index("有限公司"),
                len(text),
                "有限公司",
                source_kind="company_suffix",
            ),
        ),
        protection_level=ProtectionLevel.WEAK,
    )
    context.raise_stack_value_floor(ClueFamily.ORGANIZATION, stream.char_to_unit[text.index("蓝")])

    stack = OrganizationStack(clue=fixed[index_by_id["suffix-1"]], clue_index=index_by_id["suffix-1"], context=context)
    localized_stack = stack._delegate()

    assert localized_stack._resolve_suffix_start(locale=localized_stack.STACK_LOCALE) == text.index("河")


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


def test_suffix_seed_soft_negative_no_longer_hard_trims_prefix():
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
    assert run.candidate.text == "路由科技公司"


def test_en_label_seed_without_value_suffix_or_two_capitalized_tokens_is_rejected():
    text = "company name: alpha"
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

    assert run is None


def test_en_label_seed_with_two_capitalized_tokens_commits_without_suffix():
    text = "company name: Blue River"
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
    assert run.candidate.text == "Blue River"


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

    assert strong == ["星河科技公司"]
    assert weak == []


def test_organization_negative_cover_includes_label_start_but_not_inspire():
    text = "Label Blue River Ltd Hint"
    label_start = text.index("Label")
    value_start = text.index("Blue")
    suffix_start = text.index("Ltd")
    hint_start = text.index("Hint")
    stream = build_prompt_stream(text)
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            label_start,
            label_start + len("Label"),
            "Label",
            source_kind="context_name_field",
            attr_type=PIIAttributeType.NAME,
        ),
        _clue(
            "value-1",
            ClueRole.VALUE,
            value_start,
            value_start + len("Blue River"),
            "Blue River",
            source_kind="dictionary_local",
            attr_type=PIIAttributeType.ORGANIZATION,
        ),
        _clue(
            "suffix-1",
            ClueRole.SUFFIX,
            suffix_start,
            suffix_start + len("Ltd"),
            "Ltd",
            source_kind="company_suffix",
            attr_type=PIIAttributeType.ORGANIZATION,
        ),
    )
    fixed, negative_clues, index_by_id, unit_index = _split_negative_clues(stream, clues)
    context = StackContext(
        stream=stream,
        locale_profile="en_us",
        protection_level=ProtectionLevel.STRONG,
        clues=fixed,
        negative_clues=negative_clues,
        unit_index=unit_index,
    )
    stack = EnOrganizationStack(clue=fixed[index_by_id["value-1"]], clue_index=index_by_id["value-1"], context=context)

    assert stack._has_organization_negative_cover(fixed[index_by_id["label-1"]].unit_start, fixed[index_by_id["label-1"]].unit_last) is True

    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=hint_start,
        end=hint_start + len("Hint"),
        unit_start=stream.char_to_unit[hint_start],
        unit_last=stream.char_to_unit[hint_start + len("Hint") - 1],
        clue_id="hint-1",
    )
    inspire_bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    inspire_index_by_id = {clue.clue_id: idx for idx, clue in enumerate(inspire_bundle.all_clues)}
    inspire_context = StackContext(
        stream=stream,
        locale_profile="en_us",
        protection_level=ProtectionLevel.STRONG,
        clues=inspire_bundle.all_clues,
        negative_clues=inspire_bundle.negative_clues,
        unit_index=inspire_bundle.unit_index,
        inspire_entries=inspire_bundle.inspire_entries,
    )
    inspire_stack = EnOrganizationStack(
        clue=inspire_bundle.all_clues[inspire_index_by_id["value-1"]],
        clue_index=inspire_index_by_id["value-1"],
        context=inspire_context,
    )

    assert inspire_stack._has_organization_negative_cover(inspire.unit_start, inspire.unit_last) is False

