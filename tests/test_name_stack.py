"""中文姓名栈行为测试。"""

from __future__ import annotations

from scripts.eval_detector_en_structured import merge_entities_with_inventory, strip_pii_tags

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
    InspireEntry,
)
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.infrastructure.pii.detector.stacks import NameStack
from privacyguard.infrastructure.pii.detector.stacks.name_en import EnNameStack
from privacyguard.infrastructure.pii.detector.zh_name_rules import (
    NegativeOverlap,
    NegativeOverlapKind,
    apply_negative_overlap_strength,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import OCR_BREAK
from tests._detector_negative_index import build_test_bundle_with_inspire, split_negative_clues


def _family_for_attr(attr_type: PIIAttributeType | None) -> ClueFamily:
    if attr_type == PIIAttributeType.NAME:
        return ClueFamily.NAME
    if attr_type == PIIAttributeType.ADDRESS:
        return ClueFamily.ADDRESS
    if attr_type == PIIAttributeType.ORGANIZATION:
        return ClueFamily.ORGANIZATION
    return ClueFamily.CONTROL


def _clue(
    clue_id: str,
    role: ClueRole,
    start: int,
    end: int,
    text: str,
    *,
    source_kind: str,
    attr_type: PIIAttributeType | None = PIIAttributeType.NAME,
    strength: ClaimStrength = ClaimStrength.SOFT,
    family: ClueFamily | None = None,
    source_metadata: dict[str, list[str]] | None = None,
    component_type: AddressComponentType | None = None,
) -> Clue:
    return Clue(
        clue_id=clue_id,
        family=family or _family_for_attr(attr_type),
        role=role,
        attr_type=attr_type,
        strength=strength,
        start=start,
        end=end,
        text=text,
        source_kind=source_kind,
        source_metadata=dict(source_metadata or {}),
        component_type=component_type,
    )

def _split_negative_clues(
    stream,
    clues: tuple[Clue, ...],
) -> tuple[tuple[Clue, ...], tuple[Clue, ...], dict[str, int], tuple]:
    return split_negative_clues(stream, clues)


def _run_name_stack(
    text: str,
    clue_index: int,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
    locale_profile: str = "mixed",
) -> NameStack:
    stream = build_prompt_stream(text)
    fixed, negative_clues, index_by_id, unit_index = _split_negative_clues(
        stream,
        clues,
    )
    target = clues[clue_index]
    context = StackContext(
        stream=stream,
        locale_profile=locale_profile,
        protection_level=protection_level,
        clues=fixed,
        negative_clues=negative_clues,
        unit_index=unit_index,
    )
    fixed_index = index_by_id[target.clue_id]
    return NameStack(clue=fixed[fixed_index], clue_index=fixed_index, context=context)


def _parse_candidates(
    text: str,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
    locale_profile: str = "mixed",
):
    ctx = DetectContext(protection_level=protection_level)
    stream = build_prompt_stream(text)
    fixed, negative_clues, _index_by_id, unit_index = _split_negative_clues(
        stream,
        clues,
    )
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    result = parser.parse(
        stream,
        ClueBundle(
            all_clues=fixed,
            unit_index=unit_index,
            negative_clues=negative_clues,
        ),
    )
    return result.candidates


def _build_context_with_bundle(
    text: str,
    clues: tuple[Clue, ...],
    *,
    inspire_entries: tuple[InspireEntry, ...] = (),
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
    locale_profile: str = "mixed",
) -> tuple[object, ClueBundle, StackContext]:
    stream = build_prompt_stream(text)
    if inspire_entries:
        bundle = build_test_bundle_with_inspire(stream, clues, inspire_entries)
    else:
        fixed, negative_clues, _index_by_id, unit_index = _split_negative_clues(stream, clues)
        bundle = ClueBundle(
            all_clues=fixed,
            unit_index=unit_index,
            negative_clues=negative_clues,
        )
    context = StackContext(
        stream=stream,
        locale_profile=locale_profile,
        protection_level=protection_level,
        clues=bundle.all_clues,
        unit_index=bundle.unit_index,
        negative_clues=bundle.negative_clues,
        inspire_entries=bundle.inspire_entries,
    )
    return stream, bundle, context


def test_stack_context_value_locks_default_to_minus_one_and_commit_syncs_all_floors():
    stream = build_prompt_stream("张三")
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=ProtectionLevel.STRONG,
    )
    parser = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG))

    assert context.commit_frontier_last_unit == -1
    assert context.all_candidate_value_cannot_get_this_unit == -1
    assert context.stack_value_cannot_get_this_unit == {
        ClueFamily.NAME: -1,
        ClueFamily.ORGANIZATION: -1,
        ClueFamily.ADDRESS: -1,
    }

    parser._commit_candidate(
        context,
        CandidateDraft(
            attr_type=PIIAttributeType.NAME,
            start=0,
            end=2,
            text="张三",
            source=stream.source,
            source_kind="test",
            unit_start=0,
            unit_last=1,
            claim_strength=ClaimStrength.HARD,
        ),
    )

    assert context.commit_frontier_last_unit == 1
    assert context.all_candidate_value_cannot_get_this_unit == 1
    assert context.stack_value_cannot_get_this_unit == {
        ClueFamily.NAME: 1,
        ClueFamily.ORGANIZATION: 1,
        ClueFamily.ADDRESS: 1,
    }


def test_parser_advances_name_value_floor_for_label_only():
    _stream, bundle, context = _build_context_with_bundle(
        "姓名张三",
        (
            _clue("label-1", ClueRole.LABEL, 0, 2, "姓名", source_kind="context_name_field"),
        ),
    )
    parser = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG))

    parser._advance_semantic_value_locks_at_unit(context, 0)

    assert context.stack_value_cannot_get_this_unit[ClueFamily.NAME] == bundle.all_clues[0].unit_last
    assert context.stack_value_cannot_get_this_unit[ClueFamily.ORGANIZATION] == -1
    assert context.stack_value_cannot_get_this_unit[ClueFamily.ADDRESS] == -1


def test_parser_prefers_name_within_same_start_group_before_other_families():
    text = "Clark"
    clues = (
        _clue(
            "name-1",
            ClueRole.FULL_NAME,
            0,
            5,
            "Clark",
            source_kind="full_name",
            attr_type=PIIAttributeType.NAME,
            family=ClueFamily.NAME,
            strength=ClaimStrength.HARD,
        ),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            0,
            5,
            "Clark",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.HARD,
        ),
        _clue(
            "org-1",
            ClueRole.VALUE,
            0,
            5,
            "Clark",
            source_kind="company_value",
            attr_type=PIIAttributeType.ORGANIZATION,
            family=ClueFamily.ORGANIZATION,
            strength=ClaimStrength.HARD,
        ),
    )

    candidates = _parse_candidates(text, clues, locale_profile="en_us")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["Clark"]
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == []
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ORGANIZATION] == []


def test_english_name_address_overlap_uses_name_address_conflict_resolution():
    text = "Lucas Clark"
    clues = (
        _clue(
            "name-1",
            ClueRole.FULL_NAME,
            0,
            11,
            "Lucas Clark",
            source_kind="full_name",
            attr_type=PIIAttributeType.NAME,
            family=ClueFamily.NAME,
            strength=ClaimStrength.HARD,
        ),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            6,
            11,
            "Clark",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.WEAK,
        ),
    )

    candidates = _parse_candidates(text, clues, locale_profile="en_us")

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["Lucas Clark"]
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == []


def test_detector_keeps_full_english_name_when_surname_overlaps_address():
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect("name: Lucas Clark;", [])

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["Lucas Clark"]
    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS] == []


def test_name_commit_negative_sources_include_seed_and_inspire_but_not_value():
    text = "Lucas Clark Name Addr Hint"
    stream = build_prompt_stream(text)
    clues = (
        _clue(
            "name-1",
            ClueRole.FULL_NAME,
            0,
            len("Lucas Clark"),
            "Lucas Clark",
            source_kind="full_name",
            attr_type=PIIAttributeType.NAME,
            family=ClueFamily.NAME,
            strength=ClaimStrength.SOFT,
        ),
        _clue(
            "label-1",
            ClueRole.LABEL,
            text.index("Name"),
            text.index("Name") + len("Name"),
            "Name",
            source_kind="context_address_field",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.SOFT,
        ),
        _clue(
            "value-1",
            ClueRole.VALUE,
            text.index("Addr"),
            text.index("Addr") + len("Addr"),
            "Addr",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.SOFT,
        ),
        _clue(
            "start-1",
            ClueRole.START,
            text.index("Hint"),
            text.index("Hint") + len("Hint"),
            "Hint",
            source_kind="context_org_start",
            attr_type=PIIAttributeType.ORGANIZATION,
            family=ClueFamily.ORGANIZATION,
            strength=ClaimStrength.SOFT,
        ),
    )
    inspire_start = text.index("Hint")
    inspire_end = inspire_start + len("Hint")
    inspire = InspireEntry(
        attr_type=PIIAttributeType.ADDRESS,
        family=ClueFamily.ADDRESS,
        start=inspire_start,
        end=inspire_end,
        unit_start=stream.char_to_unit[inspire_start],
        unit_last=stream.char_to_unit[inspire_end - 1],
        clue_id="hint-inspire",
    )
    _stream, bundle, context = _build_context_with_bundle(
        text,
        clues,
        inspire_entries=(inspire,),
        locale_profile="en_us",
    )
    stack = EnNameStack(clue=bundle.all_clues[0], clue_index=0, context=context)

    negative_ids = {clue.clue_id for clue in stack._commit_negative_clues()}

    assert "label-1" in negative_ids
    assert "start-1" in negative_ids
    assert "value-1" not in negative_ids
    assert "hint-inspire:inspire-negative" in negative_ids


def test_parser_advances_name_value_floor_for_inspire_and_keeps_it_after_failed_run():
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 2, 3, "王", source_kind="family_name", strength=ClaimStrength.SOFT),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    _stream, bundle, context = _build_context_with_bundle(
        "姓名王",
        clues,
        inspire_entries=(inspire,),
    )
    parser = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG))

    parser._advance_semantic_value_locks_at_unit(context, 0)
    run, _stack = parser._try_run_stack_at_unit(context, bundle.all_clues[0].unit_start, ClueFamily.NAME)

    assert run is None
    assert context.stack_value_cannot_get_this_unit[ClueFamily.NAME] == inspire.unit_last


def test_name_non_seed_starter_before_value_floor_is_rejected():
    text = "张三"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "张", source_kind="family_name", strength=ClaimStrength.HARD),
    )
    stream, bundle, context = _build_context_with_bundle(text, clues)
    context.raise_stack_value_floor(ClueFamily.NAME, bundle.all_clues[0].unit_last)

    run = NameStack(clue=bundle.all_clues[0], clue_index=0, context=context).run()

    assert stream.text == text
    assert run is None


def test_parser_inspire_boosts_weak_name_clue_by_two_levels_within_three_units():
    stream = build_prompt_stream("姓名张三")
    clues = (
        _clue(
            "full-1",
            ClueRole.FULL_NAME,
            2,
            4,
            "张三",
            source_kind="dictionary_local",
            strength=ClaimStrength.WEAK,
        ),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    parsed = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG)).parse(
        stream,
        bundle,
    )

    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].attr_type == PIIAttributeType.NAME
    assert parsed.candidates[0].claim_strength == ClaimStrength.HARD


def test_parser_inspire_boosts_weak_name_clue_by_one_level_within_six_units():
    stream = build_prompt_stream("姓名 这里 张三")
    clues = (
        _clue(
            "full-1",
            ClueRole.FULL_NAME,
            6,
            8,
            "张三",
            source_kind="dictionary_local",
            strength=ClaimStrength.WEAK,
        ),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    parsed = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG)).parse(
        stream,
        bundle,
    )

    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].claim_strength == ClaimStrength.SOFT


def test_parser_inspire_window_is_based_on_unit_index_difference():
    stream = build_prompt_stream("姓名 这里 真 张三")
    clues = (
        _clue("full-1", ClueRole.FULL_NAME, 8, 10, "张三", source_kind="dictionary_local"),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    parsed = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG)).parse(
        stream,
        bundle,
    )

    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].claim_strength == ClaimStrength.SOFT


def test_parser_inspire_writes_back_boosted_strength_to_original_clue():
    stream = build_prompt_stream("姓名张三")
    clues = (
        _clue(
            "full-1",
            ClueRole.FULL_NAME,
            2,
            4,
            "张三",
            source_kind="dictionary_local",
            strength=ClaimStrength.WEAK,
        ),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    parser = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG))
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=ProtectionLevel.STRONG,
        clues=bundle.all_clues,
        unit_index=bundle.unit_index,
        negative_clues=bundle.negative_clues,
        inspire_entries=bundle.inspire_entries,
    )

    run, _stack = parser._try_run_stack_at_unit(
        context,
        bundle.all_clues[0].unit_start,
        ClueFamily.NAME,
    )

    assert run is not None
    assert context.clues[0].strength == ClaimStrength.HARD


def test_parser_inspire_is_reset_by_ocr_break():
    text = f"姓名{OCR_BREAK}张三"
    stream = build_prompt_stream(text)
    clues = (
        _clue("full-1", ClueRole.FULL_NAME, len(f"姓名{OCR_BREAK}"), len(text), "张三", source_kind="dictionary_local"),
    )
    inspire = InspireEntry(
        attr_type=PIIAttributeType.NAME,
        family=ClueFamily.NAME,
        start=0,
        end=2,
        unit_start=0,
        unit_last=1,
        clue_id="label-1",
    )
    bundle = build_test_bundle_with_inspire(stream, clues, (inspire,))
    parsed = StreamParser(locale_profile="mixed", ctx=DetectContext(protection_level=ProtectionLevel.STRONG)).parse(
        stream,
        bundle,
    )

    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].claim_strength == ClaimStrength.SOFT


def _name_texts(
    text: str,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
    locale_profile: str = "mixed",
) -> list[str]:
    return [
        candidate.text
        for candidate in _parse_candidates(
            text,
            clues,
            protection_level=protection_level,
            locale_profile=locale_profile,
        )
        if candidate.attr_type == PIIAttributeType.NAME
    ]


def test_full_name_single_stage_accepts_none_exact_and_negative_fully_inside():
    assert _name_texts(
        "张三",
        (
            _clue("full-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.HARD),
        ),
    ) == ["张三"]
    assert _name_texts(
        "张三",
        (
            _clue("full-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "张三", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["张三"]
    assert _name_texts(
        "张三丰",
        (
            _clue("full-1", ClueRole.FULL_NAME, 0, 3, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "三", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["张三丰"]


def test_full_name_single_stage_allows_local_vault_name_containing_negative_subspan():
    """本地 FULL_NAME 可包含 blacklist 子串（如「三丰」嵌在「张三丰」内），仍允许直接提交。"""
    assert _name_texts(
        "张三丰",
        (
            _clue("full-1", ClueRole.FULL_NAME, 0, 3, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 3, "三丰", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["张三丰"]


def test_full_name_parser_drops_name_when_address_span_strictly_contains():
    """NAME 与更长地址重叠时，parser 按 unit 区间严格包含规则只保留地址，不再输出 NAME。"""
    assert _name_texts(
        "张三丰路",
        (
            _clue("full-1", ClueRole.FULL_NAME, 0, 3, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue(
                "addr-1",
                ClueRole.VALUE,
                0,
                4,
                "张三丰路",
                source_kind="geo_db",
                attr_type=PIIAttributeType.ADDRESS,
                family=ClueFamily.ADDRESS,
                strength=ClaimStrength.HARD,
                component_type=AddressComponentType.ROAD,
            ),
        ),
    ) == []


def test_alias_single_stage_allows_negative_fully_inside():
    assert _name_texts(
        "阿宝",
        (
            _clue("alias-1", ClueRole.ALIAS, 0, 2, "阿宝", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "宝", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["阿宝"]


def test_given_name_single_stage_rejects_negative_fully_inside_when_soft():
    assert _name_texts(
        "可欣",
        (
            _clue("given-1", ClueRole.GIVEN_NAME, 0, 2, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "欣", source_kind="negative_name_word", attr_type=None),
        ),
    ) == []


def test_given_name_single_stage_allows_negative_fully_inside_when_hard():
    assert _name_texts(
        "可欣",
        (
            _clue("given-1", ClueRole.GIVEN_NAME, 0, 2, "可欣", source_kind="zh_given_name", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "欣", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["可欣"]


def test_given_name_single_stage_treats_exact_equal_as_negative_fully_inside():
    assert _name_texts(
        "可欣",
        (
            _clue("given-1", ClueRole.GIVEN_NAME, 0, 2, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
            _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "可欣", source_kind="negative_name_word", attr_type=None),
        ),
    ) == []


def test_given_name_single_stage_still_respects_protection_gate():
    assert _name_texts(
        "可欣",
        (
            _clue("given-1", ClueRole.GIVEN_NAME, 0, 2, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
        ),
        protection_level=ProtectionLevel.WEAK,
    ) == []


def test_compound_surname_path_allows_four_chars():
    text = "欧阳娜娜"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 2, "欧阳", source_kind="family_name", strength=ClaimStrength.HARD),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "欧阳娜娜"


def test_single_family_standalone_no_longer_extends_to_four_chars_without_explicit_given():
    text = "王小明明,"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "王", source_kind="family_name", strength=ClaimStrength.SOFT),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "王小明"


def test_family_path_fully_covered_drops_weak_family_component():
    text = "王国庆"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "王", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "王国", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_family_path_other_attr_value_overlap_no_longer_counts_as_negative():
    text = "王国庆"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "王", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            0,
            2,
            "王国",
            source_kind="dictionary_local",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.SOFT,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "王国庆"
    assert run.pending_challenge is not None
    assert run.pending_challenge.challenge_kind == "name_address_conflict"


def test_label_seed_dropped_when_given_or_standalone_hits_strong_negative():
    """名片段与 blacklist 部分重叠 → 整段取消；standalone 内命中 negative 亦不再提交。"""
    text = "用户许可欣同学"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 2, "用户", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 2, 3, "许", source_kind="family_name", strength=ClaimStrength.SOFT),
        _clue("given-1", ClueRole.GIVEN_NAME, 3, 5, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "许可", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_label_seed_treats_negative_fully_inside_as_hard_override():
    text = "姓名: 张三丰"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 2, "姓名", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 4, 5, "张", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue("neg-1", ClueRole.NEGATIVE, 5, 6, "三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_start_seed_treats_negative_fully_inside_as_hard_override():
    text = "姓名是张三丰"
    clues = (
        _clue("start-1", ClueRole.START, 0, 3, "姓名是", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 3, 4, "张", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 5, "三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_standalone_double_boundary_with_negative_is_dropped():
    text = "收件人：孟子轩"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 3, "收件人", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 4, 5, "孟", source_kind="family_name", strength=ClaimStrength.SOFT),
        _clue("given-1", ClueRole.GIVEN_NAME, 5, 7, "子轩", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "孟子", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_single_boundary_standalone_upgrades_claim_strength():
    text = "他说张三,"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 2, 3, "张", source_kind="family_name", strength=ClaimStrength.SOFT),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"
    assert run.candidate.claim_strength == ClaimStrength.SOFT


def test_boundary_upgrade_uses_adjacent_units_instead_of_skipping_to_outer_punct():
    text = "；运单号："
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 2, 3, "单", source_kind="family_name", strength=ClaimStrength.WEAK),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_label_seed_outputs_hard_candidate():
    text = "姓名: 张三"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 2, "姓名", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 4, 5, "张", source_kind="family_name", strength=ClaimStrength.WEAK),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_label_seed_without_explicit_family_uses_full_name_clue_span():
    text = "姓名: 张三丰"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 2, "姓名", source_kind="context_name_field"),
        _clue("full-1", ClueRole.FULL_NAME, 4, 7, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.HARD),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_label_seed_with_explicit_family_prefers_full_name_clue_for_second_stage():
    text = "姓名: 张三丰"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 2, "姓名", source_kind="context_name_field"),
        _clue("family-1", ClueRole.FAMILY_NAME, 4, 5, "张", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue("full-1", ClueRole.FULL_NAME, 4, 7, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.HARD),
        _clue("neg-1", ClueRole.NEGATIVE, 5, 6, "三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_family_route_hard_allows_negative_fully_inside():
    text = "张三丰"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "张", source_kind="family_name", strength=ClaimStrength.HARD),
        _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.HARD


def test_family_route_soft_negative_fully_inside_can_be_rescued_by_boundary_upgrade():
    text = "张三丰"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "张", source_kind="family_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三丰"
    assert run.candidate.claim_strength == ClaimStrength.SOFT


def test_negative_helper_partial_overlap_has_higher_priority_than_inside():
    overlaps = (
        NegativeOverlap(
            kind=NegativeOverlapKind.NEGATIVE_FULLY_INSIDE,
            clue_id="neg-inside",
            start=1,
            end=2,
            text="三",
        ),
        NegativeOverlap(
            kind=NegativeOverlapKind.PARTIAL_OVERLAP,
            clue_id="neg-partial",
            start=0,
            end=2,
            text="张三",
        ),
    )

    assert apply_negative_overlap_strength(overlaps, effective_strength=ClaimStrength.HARD) == ClaimStrength.SOFT


def test_negative_helper_non_hard_inside_downgrades_to_failure_from_weak():
    overlaps = (
        NegativeOverlap(
            kind=NegativeOverlapKind.NEGATIVE_FULLY_INSIDE,
            clue_id="neg-inside",
            start=1,
            end=2,
            text="三",
        ),
    )

    assert apply_negative_overlap_strength(overlaps, effective_strength=ClaimStrength.WEAK) is None


def test_negative_helper_fully_covered_cancels_immediately():
    overlaps = (
        NegativeOverlap(
            kind=NegativeOverlapKind.FULLY_COVERED,
            clue_id="neg-covered",
            start=0,
            end=2,
            text="张三",
        ),
        NegativeOverlap(
            kind=NegativeOverlapKind.NEGATIVE_FULLY_INSIDE,
            clue_id="neg-inside",
            start=1,
            end=2,
            text="三",
        ),
    )

    assert apply_negative_overlap_strength(overlaps, effective_strength=ClaimStrength.HARD) is None


def test_guobu_non_regression_still_dropped_by_fully_covered_family():
    text = "国补"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "国", source_kind="family_name", strength=ClaimStrength.HARD),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "国补", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_heng_wuliu_regression_no_longer_commits_name():
    text = "单位填远衡物流服务有限公司"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 3, 4, "衡", source_kind="family_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "物流", source_kind="negative_name_word", attr_type=None),
    )

    assert "衡物流" not in _name_texts(text, clues)


def test_ning_xinxi_regression_no_longer_commits_name():
    text = "单位填川宁信息技术有限公司"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 3, 4, "宁", source_kind="family_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "信息", source_kind="negative_name_word", attr_type=None),
    )

    assert "宁信息" not in _name_texts(text, clues)


def test_parser_span_containment_address_wins_over_name_prefix():
    """ADDRESS 的 unit 区间严格包含 NAME 时，包含方胜出（不比较 strength）。"""
    text = "张三路"
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.HARD),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            0,
            3,
            "张三路",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.HARD,
            component_type=AddressComponentType.ROAD,
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.ADDRESS, "张三路"),
    ]


def test_parser_span_containment_email_wins_over_name_inside():
    """EMAIL 的 unit 区间严格包含 NAME 时，包含方胜出。"""
    text = "张三@example.com"
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.HARD),
        _clue(
            "email-1",
            ClueRole.VALUE,
            0,
            len(text),
            text,
            source_kind="regex_email",
            attr_type=PIIAttributeType.EMAIL,
            family=ClueFamily.STRUCTURED,
            strength=ClaimStrength.HARD,
            source_metadata={"hard_source": ["regex"], "placeholder": ["<email>"]},
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.EMAIL, text),
    ]


def test_parser_address_wins_name_then_independent_email_commits():
    """NAME 被更长 ADDRESS 包含则只保留地址；右侧与地址不重叠的 EMAIL 照常提交。"""
    text = "张三路 demo@example.com"
    email_text = "demo@example.com"
    email_start = text.index(email_text)
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.HARD),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            0,
            3,
            "张三路",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.HARD,
            component_type=AddressComponentType.ROAD,
        ),
        _clue(
            "email-1",
            ClueRole.VALUE,
            email_start,
            len(text),
            email_text,
            source_kind="regex_email",
            attr_type=PIIAttributeType.EMAIL,
            family=ClueFamily.STRUCTURED,
            strength=ClaimStrength.HARD,
            source_metadata={"hard_source": ["regex"], "placeholder": ["<email>"]},
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.ADDRESS, "张三路"),
        (PIIAttributeType.EMAIL, email_text),
    ]


def test_parser_commits_winner_when_name_loses_strength_conflict():
    text = "张三@example.com"
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 2, "张三", source_kind="dictionary_local", strength=ClaimStrength.SOFT),
        _clue(
            "email-1",
            ClueRole.VALUE,
            0,
            len(text),
            text,
            source_kind="regex_email",
            attr_type=PIIAttributeType.EMAIL,
            family=ClueFamily.STRUCTURED,
            strength=ClaimStrength.HARD,
            source_metadata={"hard_source": ["regex"], "placeholder": ["<email>"]},
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.EMAIL, text),
    ]


def test_parser_keeps_trimmed_name_when_other_attr_value_overlap_is_not_negative():
    """其他类型 VALUE 片段不再直接充当 negative，后续交给 parser 常规裁剪。"""
    text = "张三丰路"
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 3, "张三丰", source_kind="dictionary_local", strength=ClaimStrength.SOFT),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            2,
            4,
            "丰路",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.HARD,
            component_type=AddressComponentType.ROAD,
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.NAME, "张三"),
        (PIIAttributeType.ADDRESS, "丰路"),
    ]


def test_parser_drops_trimmed_name_when_only_family_name_remains():
    """中文姓名输给地址后，若裁剪结果只剩 family name，则不单独提交。"""
    text = "欧阳娜娜路"
    clues = (
        _clue("name-1", ClueRole.FULL_NAME, 0, 4, "欧阳娜娜", source_kind="dictionary_local", strength=ClaimStrength.SOFT),
        _clue(
            "addr-1",
            ClueRole.VALUE,
            2,
            5,
            "娜娜路",
            source_kind="geo_db",
            attr_type=PIIAttributeType.ADDRESS,
            family=ClueFamily.ADDRESS,
            strength=ClaimStrength.HARD,
            component_type=AddressComponentType.ROAD,
        ),
    )

    candidates = _parse_candidates(text, clues)

    assert [(candidate.attr_type, candidate.text) for candidate in candidates] == [
        (PIIAttributeType.ADDRESS, "娜娜路"),
    ]


def test_family_strong_negative_exits_stack_before_given_expansion():
    """姓片段被 FULLY_COVERED / PARTIAL 强阻断时本栈立即结束（不吞后续名）。"""
    text = "左张右可欣"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 1, 2, "张", source_kind="family_name", strength=ClaimStrength.HARD),
        _clue("given-1", ClueRole.GIVEN_NAME, 3, 5, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 3, "左张右", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_implicit_tail_partial_negative_cancels_boundary_name():
    """无显式 given 时，姓右扩尾部与 blacklist 部分重叠 → 取消整段提交。"""
    text = "张三丰"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "张", source_kind="family_name", strength=ClaimStrength.HARD),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "张三", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_parser_family_stack_exits_then_given_name_direct_still_parsed():
    """姓 clue 因强阻断不产生 run 时，parser 继续扫描，后续 given 仍可独立提交。"""
    text = "左张右可欣"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 1, 2, "张", source_kind="family_name", strength=ClaimStrength.HARD),
        _clue("given-1", ClueRole.GIVEN_NAME, 3, 5, "可欣", source_kind="zh_given_name", strength=ClaimStrength.HARD),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 3, "左张右", source_kind="negative_name_word", attr_type=None),
    )

    assert _name_texts(text, clues, protection_level=ProtectionLevel.STRONG) == ["可欣"]


def test_en_given_path_blocks_copula_and_absorbs_family_name():
    """英文 given path 左侧遇到 copula 时应截断，并继续向右吸收 family name。"""
    text = "the name on file is Wyatt Bell"
    is_start = text.index(" is ") + 1
    wyatt_start = text.index("Wyatt")
    bell_start = text.index("Bell")
    clues = (
        _clue(
            "control-1",
            ClueRole.VALUE,
            is_start,
            is_start + 2,
            "is",
            source_kind="control_value_en",
            attr_type=None,
            family=ClueFamily.CONTROL,
            source_metadata={"control_kind": ["copula_en"]},
        ),
        _clue("given-1", ClueRole.GIVEN_NAME, wyatt_start, wyatt_start + 5, "Wyatt", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, bell_start, bell_start + 4, "Bell", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )

    run = _run_name_stack(
        text,
        1,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ).run()

    assert run is not None
    assert run.candidate.text == "Wyatt Bell"


def test_en_given_path_does_not_absorb_lowercase_plain_unit():
    """英文 plain unit 只有首字母大写时才能并入姓名。"""
    text = "the name on file is little Wyatt Bell"
    is_start = text.index(" is ") + 1
    wyatt_start = text.index("Wyatt")
    bell_start = text.index("Bell")
    clues = (
        _clue(
            "control-1",
            ClueRole.VALUE,
            is_start,
            is_start + 2,
            "is",
            source_kind="control_value_en",
            attr_type=None,
            family=ClueFamily.CONTROL,
            source_metadata={"control_kind": ["copula_en"]},
        ),
        _clue("given-1", ClueRole.GIVEN_NAME, wyatt_start, wyatt_start + 5, "Wyatt", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, bell_start, bell_start + 4, "Bell", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )

    assert _name_texts(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ) == ["Wyatt Bell"]


def test_detector_merges_adjacent_english_name_clues_even_with_weird_ocr_casing():
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect("keVIN dANiEl", [])

    assert [candidate.text for candidate in candidates if candidate.attr_type == PIIAttributeType.NAME] == ["keVIN dANiEl"]


def test_en_label_seed_keeps_joiner_name_parts():
    """英文 label seed 右扩时应保留连字符姓名片段。"""
    text = "Name: Mary-Jane Watson"
    mary_start = text.index("Mary")
    watson_start = text.index("Watson")
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 4, "Name", source_kind="context_name_field"),
        _clue("given-1", ClueRole.GIVEN_NAME, mary_start, mary_start + 4, "Mary", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, watson_start, watson_start + 6, "Watson", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )

    assert _name_texts(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ) == ["Mary-Jane Watson"]


def test_en_given_name_respects_same_protection_gate_as_zh():
    """英文单 given 的提交门槛与中文 protection gate 对齐。"""
    clues = (
        _clue("given-1", ClueRole.GIVEN_NAME, 0, 4, "Liam", source_kind="en_given_name", strength=ClaimStrength.SOFT),
    )

    assert _name_texts(
        "Liam",
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ) == ["Liam"]
    assert _name_texts(
        "Liam",
        clues,
        protection_level=ProtectionLevel.BALANCED,
        locale_profile="en_us",
    ) == []


def test_en_name_non_seed_starter_before_value_floor_is_rejected():
    text = "Wyatt Bell"
    clues = (
        _clue("given-1", ClueRole.GIVEN_NAME, 0, 5, "Wyatt", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, 6, 10, "Bell", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )
    _stream, bundle, context = _build_context_with_bundle(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    )
    context.raise_stack_value_floor(ClueFamily.NAME, bundle.all_clues[0].unit_last)

    run = NameStack(clue=bundle.all_clues[0], clue_index=0, context=context).run()

    assert run is None


def test_en_label_seed_start_respects_name_value_floor():
    text = "Name: Wyatt Bell"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 4, "Name", source_kind="context_name_field"),
        _clue("given-1", ClueRole.GIVEN_NAME, 6, 11, "Wyatt", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, 12, 16, "Bell", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )
    _stream, bundle, context = _build_context_with_bundle(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    )
    context.raise_stack_value_floor(ClueFamily.NAME, bundle.all_clues[1].unit_last)

    run = NameStack(clue=bundle.all_clues[0], clue_index=0, context=context).run()

    assert run is not None
    assert run.candidate.text == "Bell"
    assert run.candidate.start >= context.effective_value_floor_char(ClueFamily.NAME)


def test_en_given_left_expansion_respects_name_value_floor():
    text = "Wyatt James Bell"
    clues = (
        _clue("given-1", ClueRole.GIVEN_NAME, 6, 11, "James", source_kind="en_given_name", strength=ClaimStrength.SOFT),
        _clue("family-1", ClueRole.FAMILY_NAME, 12, 16, "Bell", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )
    _stream, bundle, context = _build_context_with_bundle(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    )
    context.raise_stack_value_floor(ClueFamily.NAME, context.stream.char_to_unit[text.index("t")])

    run = NameStack(clue=bundle.all_clues[0], clue_index=0, context=context).run()

    assert run is not None
    assert run.candidate.text == "James Bell"
    assert run.candidate.start == text.index("James")


def test_en_family_path_absorbs_left_capitalized_token_symmetrically():
    text = "Harper Collins"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 7, 14, "Collins", source_kind="en_surname", strength=ClaimStrength.SOFT),
    )

    run = _run_name_stack(
        text,
        0,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ).run()

    assert run is not None
    assert run.candidate.text == "Harper Collins"


def test_en_label_seed_single_capitalized_token_without_name_clue_is_rejected():
    text = "Name: Avery"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, 4, "Name", source_kind="context_name_field"),
    )

    assert _name_texts(
        text,
        clues,
        protection_level=ProtectionLevel.STRONG,
        locale_profile="en_us",
    ) == []


def test_structured_eval_maps_birthday_to_time_for_eval():
    text, parsed_entities = strip_pii_tags("生日【PII:BIRTHDAY:1】1992年6月6日 【/PII】")
    merged, mismatches = merge_entities_with_inventory(
        "sample-1",
        parsed_entities,
        [
            {
                "type": "BIRTHDAY",
                "value": "1992年6月6日",
            }
        ],
    )

    assert text == "生日1992年6月6日"
    assert mismatches == []
    assert len(merged) == 1
    assert merged[0].raw_entity_type == "BIRTHDAY"
    assert merged[0].entity_type == "TIME"
    assert merged[0].exact_detector_type == "time"

