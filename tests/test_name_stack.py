"""中文姓名栈行为测试。"""

from __future__ import annotations

from dataclasses import replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
    build_clue_index,
    build_negative_unit_index,
)
from privacyguard.infrastructure.pii.detector.parser import StackContext, StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_prompt_stream
from privacyguard.infrastructure.pii.detector.stacks import NameStack
from privacyguard.infrastructure.pii.detector.stacks.common import _char_span_to_unit_span


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


def _with_units(stream, clue: Clue) -> Clue:
    unit_start, unit_end = _char_span_to_unit_span(stream, clue.start, clue.end)
    return replace(clue, unit_start=unit_start, unit_end=unit_end)


def _split_negative_clues(
    stream,
    clues: tuple[Clue, ...],
) -> tuple[tuple[Clue, ...], tuple[Clue, ...], dict[str, int], list[int], list[int], int]:
    fixed_clues: list[Clue] = []
    negative_clues: list[Clue] = []
    index_by_id: dict[str, int] = {}
    negative_spans: list[tuple[int, int]] = []

    for clue in clues:
        fixed = _with_units(stream, clue)
        if fixed.role == ClueRole.NEGATIVE:
            negative_clues.append(fixed)
            negative_spans.append((fixed.unit_start, fixed.unit_end))
            continue
        index_by_id[fixed.clue_id] = len(fixed_clues)
        fixed_clues.append(fixed)

    negative_unit_marks, negative_prefix_sum, negative_start_weight = build_negative_unit_index(
        len(stream.units),
        negative_spans,
    )
    return (
        tuple(fixed_clues),
        tuple(negative_clues),
        index_by_id,
        negative_unit_marks,
        negative_prefix_sum,
        negative_start_weight,
    )


def _run_name_stack(
    text: str,
    clue_index: int,
    clues: tuple[Clue, ...],
    *,
    protection_level: ProtectionLevel,
    locale_profile: str = "mixed",
) -> NameStack:
    stream = build_prompt_stream(text)
    fixed, negative_clues, index_by_id, negative_unit_marks, negative_prefix_sum, negative_start_weight = _split_negative_clues(
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
        negative_unit_marks=negative_unit_marks,
        negative_prefix_sum=negative_prefix_sum,
        negative_start_weight=negative_start_weight,
        clue_index=build_clue_index(len(stream.units), fixed),
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
    fixed, negative_clues, _index_by_id, negative_unit_marks, negative_prefix_sum, negative_start_weight = _split_negative_clues(
        stream,
        clues,
    )
    parser = StreamParser(locale_profile=locale_profile, ctx=ctx)
    result = parser.parse(
        stream,
        ClueBundle(
            all_clues=fixed,
            negative_clues=negative_clues,
            negative_unit_marks=negative_unit_marks,
            negative_prefix_sum=negative_prefix_sum,
            negative_start_weight=negative_start_weight,
            clue_index=build_clue_index(len(stream.units), fixed),
        ),
    )
    return result.candidates


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


def test_full_name_direct_submit_accepts_none_exact_and_negative_fully_inside():
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


def test_full_name_direct_submit_allows_local_vault_name_containing_negative_subspan():
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


def test_alias_and_given_name_share_direct_submit_rules():
    assert _name_texts(
        "阿宝",
        (
            _clue("alias-1", ClueRole.ALIAS, 0, 2, "阿宝", source_kind="dictionary_local", strength=ClaimStrength.HARD),
            _clue("neg-1", ClueRole.NEGATIVE, 1, 2, "宝", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["阿宝"]
    assert _name_texts(
        "可欣",
        (
            _clue("given-1", ClueRole.GIVEN_NAME, 0, 2, "可欣", source_kind="zh_given_name", strength=ClaimStrength.SOFT),
            _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "可欣", source_kind="negative_name_word", attr_type=None),
        ),
    ) == ["可欣"]


def test_given_name_direct_submit_still_respects_protection_gate():
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


def test_family_path_same_start_cover_can_drop_weak_family_component():
    text = "王国庆"
    clues = (
        _clue("family-1", ClueRole.FAMILY_NAME, 0, 1, "王", source_kind="family_name", strength=ClaimStrength.WEAK),
        _clue("neg-1", ClueRole.NEGATIVE, 0, 2, "王国", source_kind="negative_name_word", attr_type=None),
    )

    run = _run_name_stack(text, 0, clues, protection_level=ProtectionLevel.STRONG).run()

    assert run is None


def test_family_path_other_attr_overlap_demotes_like_negative():
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

    assert run is None


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


def test_parser_keeps_trimmed_name_when_loss_still_leaves_non_family_text():
    """NAME 输给地址后，裁掉冲突区若仍保留“姓+其余内容”，则允许按门槛提交裁剪结果。"""
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
