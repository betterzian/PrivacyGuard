"""rule_based 检测器的高召回规则测试。"""

import json

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def _make_detector(tmp_path) -> RuleBasedPIIDetector:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({}, ensure_ascii=False), encoding="utf-8")
    return RuleBasedPIIDetector(dictionary_path=dictionary_path)


def _candidate_texts(candidates, attr_type: PIIAttributeType) -> set[str]:
    return {candidate.text for candidate in candidates if candidate.attr_type == attr_type}


def test_rule_based_detects_name_fields_with_symbol_prefix(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="{name: 张三}", ocr_blocks=[])

    assert "张三" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_default_detector_does_not_load_sample_dictionary() -> None:
    detector = RuleBasedPIIDetector()

    candidates = detector.detect(prompt_text="请联系李四", ocr_blocks=[])

    assert candidates == []


def test_rule_based_protection_level_weak_disables_secondary_name_rules(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    strong_candidates = detector.detect(
        prompt_text="我叫王老师",
        ocr_blocks=[],
        protection_level=ProtectionLevel.STRONG,
    )
    weak_candidates = detector.detect(
        prompt_text="我叫王老师",
        ocr_blocks=[],
        protection_level=ProtectionLevel.WEAK,
    )

    assert "王老师" in _candidate_texts(strong_candidates, PIIAttributeType.NAME)
    assert _candidate_texts(weak_candidates, PIIAttributeType.NAME) == set()


def test_rule_based_protection_level_weak_still_keeps_local_dictionary_priority(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(
        prompt_text="请联系张 三",
        ocr_blocks=[],
        protection_level=ProtectionLevel.WEAK,
    )

    assert any(
        candidate.text == "张 三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_uses_session_mapping_as_primary_dictionary_source(tmp_path) -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-history",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-history",
                turn_id=1,
                candidate_id="cand-1",
                source_text="张三",
                replacement_text="@姓名1",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    detector = RuleBasedPIIDetector(mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="请联系张 三",
        ocr_blocks=[],
        session_id="session-history",
        turn_id=2,
        protection_level=ProtectionLevel.WEAK,
    )

    assert any(
        candidate.text == "张 三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_session" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_prefers_session_history_over_duplicate_local_dictionary(tmp_path) -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-priority",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-priority",
                turn_id=1,
                candidate_id="cand-1",
                source_text="张三",
                replacement_text="@姓名1",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path, mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="请联系张 三",
        ocr_blocks=[],
        session_id="session-priority",
        turn_id=2,
        protection_level=ProtectionLevel.WEAK,
    )

    assert any(
        candidate.text == "张 三"
        and candidate.attr_type == PIIAttributeType.NAME
        and candidate.metadata.get("matched_by", []) == ["dictionary_session"]
        for candidate in candidates
    )


def test_rule_based_detects_name_fields_with_chinese_keywords(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="患者姓名：李雷", ocr_blocks=[])

    assert "李雷" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_trims_following_field_label_from_name_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="姓名：张三 电话：13800138000", ocr_blocks=[])

    assert "张三" in _candidate_texts(candidates, PIIAttributeType.NAME)
    assert "张三 电话" not in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_detects_self_introduced_name(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="你好，我叫韩梅梅，今天来咨询。", ocr_blocks=[])

    assert "韩梅梅" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_detects_self_introduced_name_with_inner_space(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="你好，我叫张 三，今天来咨询。", ocr_blocks=[])

    assert "张 三" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_avoids_false_positive_self_intro_common_noun(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="我是前端", ocr_blocks=[])

    assert candidates == []


def test_rule_based_detects_single_surname_with_honorific(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="请联系王老师", ocr_blocks=[])

    assert "王老师" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_avoids_false_positive_role_with_honorific(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="项目经理", ocr_blocks=[])

    assert candidates == []


def test_rule_based_detects_address_from_context_field(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="收货地址：上海市浦东新区世纪大道100号", ocr_blocks=[])

    assert "上海市浦东新区世纪大道100号" in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


def test_rule_based_trims_following_field_label_from_address_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="地址：广东省广州市天河区 电话：13800138000", ocr_blocks=[])

    assert "广东省广州市天河区" in _candidate_texts(candidates, PIIAttributeType.ADDRESS)
    assert "广东省广州市天河区 电话" not in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


def test_rule_based_detects_organization_from_context_field(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="公司：腾讯科技", ocr_blocks=[])

    assert "腾讯科技" in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_trims_following_field_label_from_organization_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="公司：腾讯科技 地址：北京市海淀区", ocr_blocks=[])

    assert "腾讯科技" in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)
    assert "腾讯科技 地址" not in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_detects_organization_from_employment_phrase(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="我在腾讯科技工作", ocr_blocks=[])

    assert "腾讯科技" in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_detects_school_from_sentence(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="她毕业于北京大学", ocr_blocks=[])

    assert "北京大学" in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_avoids_false_positive_generic_technology_word(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="这个方案很高科技", ocr_blocks=[])

    assert _candidate_texts(candidates, PIIAttributeType.ORGANIZATION) == set()


def test_rule_based_detects_short_ocr_address_fragments(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(text="海淀区", bbox=BoundingBox(x=0, y=0, width=40, height=20)),
        OCRTextBlock(text="知春路", bbox=BoundingBox(x=50, y=0, width=50, height=20)),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)
    address_texts = _candidate_texts(candidates, PIIAttributeType.ADDRESS)

    assert "海淀区" in address_texts
    assert "知春路" in address_texts


def test_rule_based_does_not_collect_full_sentence_as_address_when_multiple_fields_present(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="公司：腾讯科技 地址：北京市海淀区", ocr_blocks=[])

    assert "公司：腾讯科技 地址：北京市海淀区" not in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


def test_rule_based_detects_phone_across_adjacent_ocr_blocks(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(text="1380013", bbox=BoundingBox(x=0, y=0, width=42, height=18), block_id="ocr-phone-1"),
        OCRTextBlock(text="8000", bbox=BoundingBox(x=44, y=0, width=24, height=18), block_id="ocr-phone-2"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.attr_type == PIIAttributeType.PHONE
        and candidate.text == "13800138000"
        and (candidate.block_id or "").startswith("ocr-merge-")
        and "cross_block_window" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_detects_context_value_across_adjacent_ocr_blocks(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(text="公司：", bbox=BoundingBox(x=0, y=0, width=30, height=18), block_id="ocr-org-1"),
        OCRTextBlock(text="腾讯科技", bbox=BoundingBox(x=32, y=0, width=48, height=18), block_id="ocr-org-2"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.attr_type == PIIAttributeType.ORGANIZATION
        and candidate.text == "腾讯科技"
        and candidate.block_id == "ocr-org-2"
        and "cross_block_window" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_detects_address_across_adjacent_ocr_blocks(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(text="海淀区", bbox=BoundingBox(x=0, y=0, width=40, height=18), block_id="ocr-addr-x1"),
        OCRTextBlock(text="知春路", bbox=BoundingBox(x=42, y=0, width=48, height=18), block_id="ocr-addr-x2"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.attr_type == PIIAttributeType.ADDRESS
        and candidate.text == "海淀区知春路"
        and (candidate.block_id or "").startswith("ocr-merge-")
        for candidate in candidates
    )


def test_rule_based_detects_room_and_building_address_fragments(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(text="3栋2单元1202室", bbox=BoundingBox(x=0, y=0, width=90, height=20), block_id="ocr-box-1"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert "3栋2单元1202室" in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


def test_rule_based_detects_masked_phone_and_id_from_context_fields(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = "手机号：138****8000，身份证号：110101********1234"

    candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[])

    assert "138****8000" in _candidate_texts(candidates, PIIAttributeType.PHONE)
    assert "110101********1234" in _candidate_texts(candidates, PIIAttributeType.ID_NUMBER)


def test_rule_based_detects_spaced_id_and_email_from_ocr_like_text(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    id_candidates = detector.detect(prompt_text="身份证：110101 19900101 1234", ocr_blocks=[])
    email_candidates = detector.detect(prompt_text="邮箱：foo @ bar.com", ocr_blocks=[])

    assert "110101 19900101 1234" in _candidate_texts(id_candidates, PIIAttributeType.ID_NUMBER)
    assert "foo @ bar.com" in _candidate_texts(email_candidates, PIIAttributeType.EMAIL)


def test_rule_based_detects_other_only_with_explicit_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    bare_candidates = detector.detect(prompt_text="今天是20240318", ocr_blocks=[])
    context_candidates = detector.detect(prompt_text="订单号：20240318", ocr_blocks=[])

    assert not _candidate_texts(bare_candidates, PIIAttributeType.OTHER)
    assert "20240318" in _candidate_texts(context_candidates, PIIAttributeType.OTHER)


def test_rule_based_records_block_id_and_span_for_partial_ocr_hits(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    ocr_blocks = [
        OCRTextBlock(
            text="请联系13800138000谢谢",
            bbox=BoundingBox(x=1, y=1, width=50, height=10),
            block_id="ocr-box-2",
        )
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)
    phone_candidates = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.PHONE]

    assert any(
        candidate.text == "13800138000"
        and candidate.block_id == "ocr-box-2"
        and candidate.span_start == 3
        and candidate.span_end == 14
        for candidate in phone_candidates
    )


def test_rule_based_dictionary_matches_ocr_name_with_inner_space(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)
    ocr_blocks = [
        OCRTextBlock(text="请联系张 三", bbox=BoundingBox(x=0, y=0, width=60, height=20), block_id="ocr-name-1"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.text == "张 三"
        and candidate.attr_type == PIIAttributeType.NAME
        and candidate.block_id == "ocr-name-1"
        and candidate.span_start == 3
        and candidate.span_end == 6
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_address_without_province_suffix(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"address": ["四川省成都市"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)
    ocr_blocks = [
        OCRTextBlock(text="四川成都市武侯区", bbox=BoundingBox(x=0, y=0, width=80, height=20), block_id="ocr-addr-1"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.text == "四川成都市"
        and candidate.attr_type == PIIAttributeType.ADDRESS
        and candidate.block_id == "ocr-addr-1"
        and candidate.span_start == 0
        and candidate.span_end == 5
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_address_fragment_from_detailed_local_address(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"address": ["广东广州天河体育西102"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)
    ocr_blocks = [
        OCRTextBlock(text="请到体育西路办理", bbox=BoundingBox(x=0, y=0, width=90, height=20), block_id="ocr-addr-2"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert any(
        candidate.text == "体育西路"
        and candidate.attr_type == PIIAttributeType.ADDRESS
        and candidate.block_id == "ocr-addr-2"
        and candidate.span_start == 2
        and candidate.span_end == 6
        for candidate in candidates
    )
    assert not any(candidate.text == "体育西" and "dictionary_local" in candidate.metadata.get("matched_by", []) for candidate in candidates)


def test_rule_based_dictionary_skips_ambiguous_local_address_alias_binding(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps({"address": ["广东广州天河体育西102", "上海徐汇体育西88"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)
    ocr_blocks = [
        OCRTextBlock(text="请到体育西路办理", bbox=BoundingBox(x=0, y=0, width=90, height=20), block_id="ocr-addr-3"),
    ]

    candidates = detector.detect(prompt_text="", ocr_blocks=ocr_blocks)

    assert candidates == []


def test_rule_based_dictionary_supports_entity_records_and_aliases(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps(
            {
                "entities": [
                    {
                        "entity_id": "friend_1",
                        "name": ["张三"],
                        "address": [{"value": "广东广州天河体育西102", "aliases": ["体育西路"]}],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="请到体育西路办理", ocr_blocks=[])

    assert any(
        candidate.text == "体育西路"
        and candidate.attr_type == PIIAttributeType.ADDRESS
        and candidate.metadata.get("local_entity_ids") == ["friend_1"]
        for candidate in candidates
    )


def test_rule_based_missing_dictionary_does_not_print_to_stdout(tmp_path, capsys) -> None:
    detector = RuleBasedPIIDetector(dictionary_path=tmp_path / "missing.json")

    detector.detect(prompt_text="请联系张三", ocr_blocks=[])
    captured = capsys.readouterr()

    assert captured.out == ""


def test_rule_based_dictionary_skips_ambiguous_entity_level_name_binding(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps(
            {
                "entities": [
                    {"entity_id": "friend_1", "name": ["张三"]},
                    {"entity_id": "friend_2", "name": ["张三"]},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="请联系张 三", ocr_blocks=[])

    assert candidates == []
