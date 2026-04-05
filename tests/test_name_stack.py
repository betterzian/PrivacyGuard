"""姓名栈行为测试。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole, NameComponentHint
from privacyguard.infrastructure.pii.detector.parser import StackContext
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks import NameStack


def _clue(
    clue_id: str,
    role: ClueRole,
    start: int,
    end: int,
    text: str,
    *,
    source_kind: str,
    priority: int = 220,
    component_hint: NameComponentHint | None = None,
    attr_type: PIIAttributeType | None = PIIAttributeType.NAME,
    hard_source: str | None = None,
    source_metadata: dict[str, list[str]] | None = None,
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
        component_hint=component_hint,
        hard_source=hard_source,
        source_metadata=source_metadata or {},
    )


def _run_name_stack(text: str, clue_index: int, clues: tuple[Clue, ...], *, protection_level: ProtectionLevel) -> NameStack:
    stream = build_prompt_stream(text)
    context = StackContext(
        stream=stream,
        locale_profile="mixed",
        protection_level=protection_level,
        clues=clues,
    )
    return NameStack(clue=clues[clue_index], clue_index=clue_index, context=context)


def test_label_seed_skips_separators_and_captures_value_chars():
    text = "姓名: 张三"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            2,
            "姓名",
            source_kind="context_name_field",
            priority=247,
            component_hint=NameComponentHint.FULL,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"


def test_start_seed_uses_first_character_after_separator():
    text = "我是：张三"
    clues = (
        _clue(
            "start-1",
            ClueRole.START,
            0,
            2,
            "我是",
            source_kind="name_start",
            priority=230,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"


def test_given_name_seed_expands_left_then_right():
    text = "Ann Demo"
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            0,
            3,
            "Ann",
            source_kind="en_given_name",
            priority=215,
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            4,
            8,
            "Demo",
            source_kind="en_surname",
            priority=218,
            component_hint=NameComponentHint.FAMILY,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == "Ann Demo"


def test_full_name_and_alias_submit_directly_under_weak():
    full_clues = (
        _clue(
            "full-1",
            ClueRole.FULL_NAME,
            0,
            11,
            "Jordan Demo",
            source_kind="dictionary_local",
            priority=290,
            component_hint=NameComponentHint.FULL,
            hard_source="local",
            source_metadata={"name_component": ["full"]},
        ),
    )
    alias_clues = (
        _clue(
            "alias-1",
            ClueRole.ALIAS,
            0,
            2,
            "阿宝",
            source_kind="dictionary_local",
            priority=290,
            component_hint=NameComponentHint.ALIAS,
            hard_source="local",
            source_metadata={"name_component": ["alias"]},
        ),
    )

    full_run = _run_name_stack("Jordan Demo", 0, full_clues, protection_level=ProtectionLevel.WEAK).run()
    alias_run = _run_name_stack("阿宝", 0, alias_clues, protection_level=ProtectionLevel.WEAK).run()

    assert full_run is not None
    assert full_run.candidate.text == "Jordan Demo"
    assert alias_run is not None
    assert alias_run.candidate.text == "阿宝"


def test_balanced_accepts_single_dictionary_given_name_longer_than_one_char():
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            0,
            2,
            "汉文",
            source_kind="dictionary_local",
            priority=290,
            component_hint=NameComponentHint.GIVEN,
            hard_source="local",
            source_metadata={"name_component": ["given"]},
        ),
    )

    run = _run_name_stack("汉文", 0, clues, protection_level=ProtectionLevel.BALANCED).run()

    assert run is not None
    assert run.candidate.text == "汉文"


def test_weak_rejects_single_non_privileged_name_clue():
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            0,
            3,
            "Ann",
            source_kind="en_given_name",
            priority=215,
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack("Ann", 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is None


def test_negative_overlap_blocks_non_privileged_submit_when_not_fully_exited():
    text = "杨汉文档"
    clues = (
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            0,
            1,
            "杨",
            source_kind="family_name",
            priority=220,
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            1,
            3,
            "汉文",
            source_kind="zh_given_name",
            priority=210,
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "neg-1",
            ClueRole.NEGATIVE,
            2,
            4,
            "文档",
            source_kind="negative_ui_word",
            priority=600,
            attr_type=None,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None
