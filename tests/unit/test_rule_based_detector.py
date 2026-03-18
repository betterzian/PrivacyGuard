"""rule_based 检测器的高召回规则测试。"""

import json

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
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


def test_rule_based_detects_name_fields_with_chinese_keywords(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="患者姓名：李雷", ocr_blocks=[])

    assert "李雷" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_detects_self_introduced_name(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="你好，我叫韩梅梅，今天来咨询。", ocr_blocks=[])

    assert "韩梅梅" in _candidate_texts(candidates, PIIAttributeType.NAME)


def test_rule_based_detects_address_from_context_field(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="收货地址：上海市浦东新区世纪大道100号", ocr_blocks=[])

    assert "上海市浦东新区世纪大道100号" in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


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
