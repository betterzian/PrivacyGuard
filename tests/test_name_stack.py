"""姓名栈行为测试。"""

from __future__ import annotations

from dataclasses import replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import NameComponentHint
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, Clue, ClueBundle, ClueFamily, ClueRole
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks.common import _char_span_to_unit_span
from privacyguard.infrastructure.pii.detector.stacks import NameStack


def _clue(
    clue_id: str,
    role: ClueRole,
    start: int,
    end: int,
    text: str,
    *,
    source_kind: str,
    component_hint: NameComponentHint | None = None,
    attr_type: PIIAttributeType | None = PIIAttributeType.NAME,
    hard_source: str | None = None,
    source_metadata: dict[str, list[str]] | None = None,
    strength: ClaimStrength = ClaimStrength.SOFT,
) -> Clue:
    md = dict(source_metadata) if source_metadata else {}
    if hard_source:
        md.setdefault("hard_source", [hard_source])
    if component_hint is not None:
        md.setdefault("name_component_hint", [component_hint.value])
    return Clue(
        clue_id=clue_id,
        family=ClueFamily.NAME if attr_type in (PIIAttributeType.NAME, None) else ClueFamily.CONTROL,
        role=role,
        attr_type=attr_type,
        strength=strength,
        start=start,
        end=end,
        text=text,
        source_kind=source_kind,
        source_metadata=md,
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


def _with_units(stream, clue: Clue) -> Clue:
    unit_start, unit_end = _char_span_to_unit_span(stream, clue.start, clue.end)
    return replace(clue, unit_start=unit_start, unit_end=unit_end)


def _parse_name_texts(
    text: str,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
) -> list[str]:
    ctx = DetectContext(protection_level=protection_level)
    stream = build_prompt_stream(text)
    fixed = tuple(_with_units(stream, clue) for clue in clues)
    parser = StreamParser(locale_profile="mixed", ctx=ctx)
    result = parser.parse(stream, ClueBundle(all_clues=fixed))
    return [candidate.text for candidate in result.candidates if candidate.attr_type == PIIAttributeType.NAME]


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
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"


def test_zh_given_name_seed_does_not_submit_without_surname_anchor():
    text = "杨汉文"
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            1,
            3,
            "汉文",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_en_given_name_seed_can_expand_left_one_plain_word():
    text = "John Marie"
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            5,
            10,
            "Marie",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "John Marie"


def test_en_given_name_seed_can_chain_right_given_names():
    text = "Ann de Marie Claire"
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            0,
            3,
            "Ann",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "given-2",
            ClueRole.GIVEN_NAME,
            7,
            12,
            "Marie",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "given-3",
            ClueRole.GIVEN_NAME,
            13,
            19,
            "Claire",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Ann de Marie Claire"


def test_en_given_name_seed_stops_when_gap_has_two_words():
    text = "Ann de la Marie"
    clues = (
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            0,
            3,
            "Ann",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "given-2",
            ClueRole.GIVEN_NAME,
            10,
            15,
            "Marie",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "Ann"


def test_en_family_name_seed_switches_to_given_chain():
    text = "Doe John Paul"
    clues = (
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            0,
            3,
            "Doe",
            source_kind="en_family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            4,
            8,
            "John",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "given-2",
            ClueRole.GIVEN_NAME,
            9,
            13,
            "Paul",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == "Doe John Paul"


def test_label_seed_switches_to_given_chain_in_english():
    text = "name: John Paul"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            4,
            "name",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            6,
            10,
            "John",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "given-2",
            ClueRole.GIVEN_NAME,
            11,
            15,
            "Paul",
            source_kind="en_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is not None
    assert run.candidate.text == "John Paul"


def test_full_name_and_alias_submit_directly_under_weak():
    full_clues = (
        _clue(
            "full-1",
            ClueRole.FULL_NAME,
            0,
            11,
            "Jordan Demo",
            source_kind="dictionary_local",
            component_hint=NameComponentHint.FULL,
            hard_source="local",
            strength=ClaimStrength.HARD,
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
            component_hint=NameComponentHint.ALIAS,
            hard_source="local",
            strength=ClaimStrength.HARD,
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
            component_hint=NameComponentHint.GIVEN,
            hard_source="local",
            strength=ClaimStrength.HARD,
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
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack("Ann", 0, clues, protection_level=ProtectionLevel.WEAK).run()

    assert run is None


def test_same_role_clues_only_count_once_under_weak():
    text = "van Helsing"
    clues = (
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            0,
            3,
            "van",
            source_kind="en_family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "family-2",
            ClueRole.FAMILY_NAME,
            4,
            11,
            "Helsing",
            source_kind="en_family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.WEAK).run()

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
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            1,
            3,
            "汉文",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue(
            "neg-1",
            ClueRole.NEGATIVE,
            2,
            4,
            "文档",
            source_kind="negative_ui_word",
            attr_type=None,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_start_seed_rejects_blacklisted_exact_negative_name():
    text = "我叫张力"
    clues = (
        _clue("start-1", ClueRole.START, 0, 2, "我叫", source_kind="name_start"),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            2,
            3,
            "张",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "张力", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_start_seed_keeps_two_char_negative_word_name_under_strong():
    text = "我叫高兴"
    clues = (
        _clue("start-1", ClueRole.START, 0, 2, "我叫", source_kind="name_start"),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            2,
            3,
            "高",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "高兴", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "高兴"


def test_start_seed_keeps_three_char_name_when_prefix_is_negative():
    text = "我叫王国庆"
    clues = (
        _clue("start-1", ClueRole.START, 0, 2, "我叫", source_kind="name_start"),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            2,
            3,
            "王",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "王国", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "王国庆"


def test_label_seed_keeps_three_char_name_when_prefix_is_negative():
    text = "收件人：孟子轩"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            3,
            "收件人",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            4,
            5,
            "孟",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            5,
            7,
            "子轩",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "孟子", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "孟子轩"


def test_label_seed_rejects_exact_negative_word_name():
    text = "收件人：高兴"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            3,
            "收件人",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            4,
            5,
            "高",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "高兴", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_label_seed_keeps_name_when_prefix_is_negative_and_given_name_exists():
    text = "用户许可欣"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            2,
            "用户",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            2,
            3,
            "许",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            3,
            5,
            "可欣",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "许可", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "许可欣"


def test_parser_rejects_blacklisted_start_seed_name():
    text = "我叫张力"
    clues = (
        _clue("start-1", ClueRole.START, 0, 2, "我叫", source_kind="name_start"),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            2,
            3,
            "张",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 2, 4, "张力", source_kind="negative_name_word", attr_type=None),
    )

    assert _parse_name_texts(text, clues) == []


def test_parser_keeps_label_seed_name_despite_negative():
    text = "收件人：孟子轩"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            3,
            "收件人",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            4,
            5,
            "孟",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            5,
            7,
            "子轩",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "孟子", source_kind="negative_name_word", attr_type=None),
    )

    assert _parse_name_texts(text, clues) == ["孟子轩"]


def test_parser_rejects_exact_negative_word_from_label_seed():
    text = "收件人：高兴"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            3,
            "收件人",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
        ),
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            4,
            5,
            "高",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 4, 6, "高兴", source_kind="negative_name_word", attr_type=None),
    )

    assert _parse_name_texts(text, clues) == []


def test_label_seed_accepts_short_common_name():
    text = "姓名: 张三"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            2,
            "姓名",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
            source_metadata={"seed_context_score": ["4"]},
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "张三"


def test_label_seed_accepts_weak_surname_with_given_name_evidence():
    text = "用户姓名：李娜"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            4,
            "用户姓名",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
            source_metadata={"seed_context_score": ["4"]},
        ),
        _clue(
            "given-1",
            ClueRole.GIVEN_NAME,
            6,
            7,
            "娜",
            source_kind="zh_given_name",
            component_hint=NameComponentHint.GIVEN,
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "李娜"


def test_start_seed_accepts_compound_surname_name():
    text = "姓名是 欧阳娜娜"
    clues = (
        _clue(
            "start-1",
            ClueRole.START,
            0,
            3,
            "姓名是",
            source_kind="name_start",
            source_metadata={"seed_context_score": ["4"], "seed_kind": ["start"]},
        ),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is not None
    assert run.candidate.text == "欧阳娜娜"


def test_label_seed_rejects_direction_phrase():
    text = "姓名：方向"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            2,
            "姓名",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
            source_metadata={"seed_context_score": ["4"]},
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 3, 5, "方向", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_label_seed_rejects_title_font_phrase():
    text = "用户姓名：宋体"
    clues = (
        _clue(
            "label-1",
            ClueRole.LABEL,
            0,
            4,
            "用户姓名",
            source_kind="context_name_field",
            component_hint=NameComponentHint.FULL,
            source_metadata={"seed_context_score": ["4"]},
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 5, 7, "宋体", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_parser_still_blocks_non_seed_negative_phrase():
    text = "高兴地说"
    clues = (
        _clue(
            "family-1",
            ClueRole.FAMILY_NAME,
            0,
            1,
            "高",
            source_kind="family_name",
            component_hint=NameComponentHint.FAMILY,
        ),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "高兴", source_kind="negative_name_word", attr_type=None),
    )

    assert _parse_name_texts(text, clues) == []
