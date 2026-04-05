"""地址栈行为测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.parser import StackContext
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks import AddressStack


def _clue(
    clue_id: str,
    role: ClueRole,
    start: int,
    end: int,
    text: str,
    *,
    source_kind: str,
    component_type: AddressComponentType | None = None,
    priority: int = 230,
    attr_type: PIIAttributeType | None = PIIAttributeType.ADDRESS,
) -> Clue:
    return Clue(
        clue_id=clue_id,
        role=role,
        attr_type=attr_type,
        start=start,
        end=end,
        text=text,
        priority=priority,
        source_kind=source_kind,
        component_type=component_type,
    )


def _run_address_stack(
    text: str,
    clue_index: int,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
) -> AddressStack:
    stream = build_prompt_stream(text)
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=protection_level,
        clues=clues,
    )
    return AddressStack(clue=clues[clue_index], clue_index=clue_index, context=context)


def test_label_seed_finds_first_address_clue():
    text = "地址：上海市"
    label = "地址"
    city = "上海市"
    clues = (
        _clue("label-1", ClueRole.LABEL, 0, len(label), label, source_kind="context_address_field"),
        _clue(
            "value-1",
            ClueRole.VALUE,
            text.index(city),
            text.index(city) + len(city),
            city,
            source_kind="zh_address_city",
            component_type=AddressComponentType.CITY,
        ),
    )

    run = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == city


def test_same_tier_value_and_key_merge_into_one_component():
    text = "Main St"
    clues = (
        _clue(
            "value-1",
            ClueRole.VALUE,
            0,
            4,
            "Main",
            source_kind="en_address_road",
            component_type=AddressComponentType.ROAD,
        ),
        _clue(
            "key-1",
            ClueRole.KEY,
            5,
            7,
            "St",
            source_kind="en_address_road_keyword",
            component_type=AddressComponentType.ROAD,
        ),
    )

    run = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == text
    assert run.candidate.metadata["address_component_trace"] == ["road:Main"]
    assert run.candidate.metadata["address_component_key_trace"] == ["road:St"]


def test_non_tight_value_and_key_split_into_two_evidences():
    text = "Main\tSt"
    clues = (
        _clue(
            "value-1",
            ClueRole.VALUE,
            0,
            4,
            "Main",
            source_kind="en_address_road",
            component_type=AddressComponentType.ROAD,
        ),
        _clue(
            "key-1",
            ClueRole.KEY,
            5,
            7,
            "St",
            source_kind="en_address_road_keyword",
            component_type=AddressComponentType.ROAD,
        ),
    )

    run = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Main St"
    assert len(run.candidate.metadata["address_component_trace"]) == 2
    assert run.candidate.metadata["address_component_key_trace"] == ["road:St"]


def test_en_key_seed_expands_left_one_word():
    text = "Main St"
    start = text.index("St")
    clues = (
        _clue(
            "key-1",
            ClueRole.KEY,
            start,
            start + 2,
            "St",
            source_kind="en_address_road_keyword",
            component_type=AddressComponentType.ROAD,
        ),
    )

    run = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == text


def test_zh_key_seed_expands_left_two_chars():
    text = "人民路"
    start = text.index("路")
    clues = (
        _clue(
            "key-1",
            ClueRole.KEY,
            start,
            start + 1,
            "路",
            source_kind="zh_address_road_keyword",
            component_type=AddressComponentType.ROAD,
        ),
    )

    run = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == text


def test_shrink_returns_none_when_trimmed_text_loses_address_signal():
    text = "人民路"
    clues = (
        _clue(
            "value-1",
            ClueRole.VALUE,
            0,
            len(text),
            text,
            source_kind="zh_address_road",
            component_type=AddressComponentType.ROAD,
        ),
    )
    stack = _run_address_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG)
    run = stack.run()

    assert run is not None
    assert stack.shrink(run, run.candidate.unit_end - 1, run.candidate.unit_end) is None
