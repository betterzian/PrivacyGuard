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


def test_rule_based_masked_address_context_support_varies_by_protection_level(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = "地址：■■路102号；地址：■■■■"

    strong_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.STRONG)
    balanced_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.BALANCED)
    weak_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.WEAK)

    assert "■■路102号" in _candidate_texts(strong_candidates, PIIAttributeType.ADDRESS)
    assert "■■路102号" in _candidate_texts(balanced_candidates, PIIAttributeType.ADDRESS)
    assert "■■路102号" not in _candidate_texts(weak_candidates, PIIAttributeType.ADDRESS)
    assert "■■■■" not in _candidate_texts(weak_candidates, PIIAttributeType.ADDRESS)
    assert "■■■■" not in _candidate_texts(strong_candidates, PIIAttributeType.ADDRESS)
    assert "■■■■" not in _candidate_texts(balanced_candidates, PIIAttributeType.ADDRESS)


def test_rule_based_pure_masked_text_is_not_detected_as_generic_privacy(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = "XXX 和 ■■■■ 需要处理"

    strong_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.STRONG)
    balanced_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.BALANCED)
    weak_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.WEAK)

    assert _candidate_texts(strong_candidates, PIIAttributeType.OTHER) == set()
    assert _candidate_texts(balanced_candidates, PIIAttributeType.OTHER) == set()
    assert _candidate_texts(weak_candidates, PIIAttributeType.OTHER) == set()


def test_rule_based_pure_masked_name_is_not_detected(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    strong_candidates = detector.detect(prompt_text="我叫XXX", ocr_blocks=[], protection_level=ProtectionLevel.STRONG)
    balanced_candidates = detector.detect(prompt_text="我叫XXX", ocr_blocks=[], protection_level=ProtectionLevel.BALANCED)
    weak_candidates = detector.detect(prompt_text="我叫XXX", ocr_blocks=[], protection_level=ProtectionLevel.WEAK)

    assert "XXX" not in _candidate_texts(strong_candidates, PIIAttributeType.NAME)
    assert "XXX" not in _candidate_texts(balanced_candidates, PIIAttributeType.NAME)
    assert "XXX" not in _candidate_texts(weak_candidates, PIIAttributeType.NAME)


def test_rule_based_other_detection_is_filtered_by_profile_confidence_threshold(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = "订单号：20240318"

    strong_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.STRONG)
    balanced_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.BALANCED)
    weak_candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[], protection_level=ProtectionLevel.WEAK)

    assert "20240318" in _candidate_texts(strong_candidates, PIIAttributeType.OTHER)
    assert "20240318" in _candidate_texts(balanced_candidates, PIIAttributeType.OTHER)
    assert "20240318" not in _candidate_texts(weak_candidates, PIIAttributeType.OTHER)


def test_rule_based_detector_init_min_confidence_override_changes_default_thresholds(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(
        dictionary_path=dictionary_path,
        min_confidence_by_attr={PIIAttributeType.ORGANIZATION: 0.6},
    )

    candidates = detector.detect(
        prompt_text="我在腾讯科技工作",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert "腾讯科技" not in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_detector_request_overrides_can_tighten_rule_thresholds(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    default_candidates = detector.detect(
        prompt_text="我在腾讯科技工作",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )
    override_candidates = detector.detect(
        prompt_text="我在腾讯科技工作",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
        detector_overrides={"organization": 0.6},
    )

    assert "腾讯科技" in _candidate_texts(default_candidates, PIIAttributeType.ORGANIZATION)
    assert "腾讯科技" not in _candidate_texts(override_candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_partial_masked_address_fragment_is_detected_without_field_label(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    strong_candidates = detector.detect(prompt_text="请寄到■■路102号", ocr_blocks=[], protection_level=ProtectionLevel.STRONG)
    balanced_candidates = detector.detect(prompt_text="请寄到■■路102号", ocr_blocks=[], protection_level=ProtectionLevel.BALANCED)
    weak_candidates = detector.detect(prompt_text="请寄到■■路102号", ocr_blocks=[], protection_level=ProtectionLevel.WEAK)

    assert "■■路102号" in _candidate_texts(strong_candidates, PIIAttributeType.ADDRESS)
    assert "■■路102号" in _candidate_texts(balanced_candidates, PIIAttributeType.ADDRESS)
    assert "■■路102号" not in _candidate_texts(weak_candidates, PIIAttributeType.ADDRESS)


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


def test_rule_based_session_history_matches_address_shorthand_variant(tmp_path) -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-address-shorthand",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-address-shorthand",
                turn_id=1,
                candidate_id="cand-address-1",
                source_text="广东省广州市天河区体育西路102号",
                replacement_text="@地址1",
                attr_type=PIIAttributeType.ADDRESS,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    detector = RuleBasedPIIDetector(mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="请寄到广东广州天河体育西102",
        ocr_blocks=[],
        session_id="session-address-shorthand",
        turn_id=2,
    )

    assert any(
        candidate.text == "广东广州天河体育西102"
        and candidate.attr_type == PIIAttributeType.ADDRESS
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


def test_rule_based_context_address_blocks_later_lower_precision_address_heuristics(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="地址：广东省广州市天河区", ocr_blocks=[])

    address_candidates = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.ADDRESS]
    assert len(address_candidates) == 1
    assert address_candidates[0].metadata.get("matched_by") == ["context_address_field"]


def test_rule_based_trims_following_field_label_from_address_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="地址：广东省广州市天河区 电话：13800138000", ocr_blocks=[])

    assert "广东省广州市天河区" in _candidate_texts(candidates, PIIAttributeType.ADDRESS)
    assert "广东省广州市天河区 电话" not in _candidate_texts(candidates, PIIAttributeType.ADDRESS)


def test_rule_based_detects_organization_from_context_field(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="公司：腾讯科技", ocr_blocks=[])

    assert "腾讯科技" in _candidate_texts(candidates, PIIAttributeType.ORGANIZATION)


def test_rule_based_context_organization_blocks_later_suffix_heuristic(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="公司：腾讯科技", ocr_blocks=[])

    organization_candidates = [candidate for candidate in candidates if candidate.attr_type == PIIAttributeType.ORGANIZATION]
    assert len(organization_candidates) == 1
    assert organization_candidates[0].metadata.get("matched_by") == ["context_organization_field"]


def test_rule_based_shadow_text_keeps_organization_detection_after_phone_hit(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="我在13800138000腾讯科技工作", ocr_blocks=[])

    assert any(
        candidate.text == "13800138000"
        and candidate.attr_type == PIIAttributeType.PHONE
        for candidate in candidates
    )
    assert any(
        candidate.text == "腾讯科技"
        and candidate.attr_type == PIIAttributeType.ORGANIZATION
        and "regex_organization_suffix" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


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
        and "ocr_page_span" in candidate.metadata.get("matched_by", [])
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
        and "ocr_page_span" in candidate.metadata.get("matched_by", [])
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


def test_rule_based_detects_prefix_only_and_suffix_only_masked_high_precision_fields_from_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = (
        "手机号：154********；手机号：*******8000；"
        "信用卡号：6222************；信用卡号：************5678；"
        "银行账号：1234**************；银行账号：**************5678；"
        "邮箱：f***@bar.com；邮箱：***@bar.com；"
        "身份证号：110101************；身份证号：**************1234"
    )

    candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[])

    assert "154********" in _candidate_texts(candidates, PIIAttributeType.PHONE)
    assert "*******8000" in _candidate_texts(candidates, PIIAttributeType.PHONE)
    assert "6222************" in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)
    assert "************5678" in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)
    assert "1234**************" in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "**************5678" in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "f***@bar.com" in _candidate_texts(candidates, PIIAttributeType.EMAIL)
    assert "***@bar.com" in _candidate_texts(candidates, PIIAttributeType.EMAIL)
    assert "110101************" in _candidate_texts(candidates, PIIAttributeType.ID_NUMBER)
    assert "**************1234" in _candidate_texts(candidates, PIIAttributeType.ID_NUMBER)


def test_rule_based_detects_prefix_only_and_suffix_only_masked_passport_and_driver_license_from_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = (
        "护照号：E1*******；护照号：*****5678；"
        "驾驶证号：440301************；驾驶证号：**************1234"
    )

    candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[])

    assert "E1*******" in _candidate_texts(candidates, PIIAttributeType.PASSPORT_NUMBER)
    assert "*****5678" in _candidate_texts(candidates, PIIAttributeType.PASSPORT_NUMBER)
    assert "440301************" in _candidate_texts(candidates, PIIAttributeType.DRIVER_LICENSE)
    assert "**************1234" in _candidate_texts(candidates, PIIAttributeType.DRIVER_LICENSE)


def test_rule_based_detects_common_mask_symbols_for_high_precision_fields(tmp_path) -> None:
    detector = _make_detector(tmp_path)
    prompt_text = (
        "手机号：154XXXXXXXX；"
        "信用卡号：6222●●●●●●●●●●●●；"
        "银行账号：1234■■■■■■■■■■■■■■；"
        "邮箱：f●●@bar.com；"
        "身份证号：110101●●●●●●●●●●●●；"
        "护照号：E1●●●●●●●；"
        "驾驶证号：440301■■■■■■■■■■■■"
    )

    candidates = detector.detect(prompt_text=prompt_text, ocr_blocks=[])

    assert "154XXXXXXXX" in _candidate_texts(candidates, PIIAttributeType.PHONE)
    assert "6222●●●●●●●●●●●●" in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)
    assert "1234■■■■■■■■■■■■■■" in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "f●●@bar.com" in _candidate_texts(candidates, PIIAttributeType.EMAIL)
    assert "110101●●●●●●●●●●●●" in _candidate_texts(candidates, PIIAttributeType.ID_NUMBER)
    assert "E1●●●●●●●" in _candidate_texts(candidates, PIIAttributeType.PASSPORT_NUMBER)
    assert "440301■■■■■■■■■■■■" in _candidate_texts(candidates, PIIAttributeType.DRIVER_LICENSE)


def test_rule_based_detects_spaced_id_and_email_from_ocr_like_text(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    id_candidates = detector.detect(prompt_text="身份证：110101 19900101 1234", ocr_blocks=[])
    email_candidates = detector.detect(prompt_text="邮箱：foo @ bar.com", ocr_blocks=[])

    assert "110101 19900101 1234" in _candidate_texts(id_candidates, PIIAttributeType.ID_NUMBER)
    assert "foo @ bar.com" in _candidate_texts(email_candidates, PIIAttributeType.EMAIL)


def test_rule_based_detects_phone_email_id_with_ocr_punctuation_noise(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    phone_candidates = detector.detect(prompt_text="手机号：1380·0138_000", ocr_blocks=[])
    email_candidates = detector.detect(prompt_text="邮箱：foo＠bar，com", ocr_blocks=[])
    id_candidates = detector.detect(prompt_text="身份证：110101·19900101_1234", ocr_blocks=[])

    assert "1380·0138_000" in _candidate_texts(phone_candidates, PIIAttributeType.PHONE)
    assert "foo＠bar，com" in _candidate_texts(email_candidates, PIIAttributeType.EMAIL)
    assert "110101·19900101_1234" in _candidate_texts(id_candidates, PIIAttributeType.ID_NUMBER)


def test_rule_based_detects_other_only_with_explicit_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    bare_candidates = detector.detect(prompt_text="今天是20240318", ocr_blocks=[])
    context_candidates = detector.detect(prompt_text="订单号：20240318", ocr_blocks=[])

    assert not _candidate_texts(bare_candidates, PIIAttributeType.OTHER)
    assert "20240318" in _candidate_texts(context_candidates, PIIAttributeType.OTHER)


def test_rule_based_detects_card_number_from_explicit_context_with_ocr_noise(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="信用卡号：6222 0200-1234，5678", ocr_blocks=[])

    assert "6222 0200-1234，5678" in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)


def test_rule_based_detects_bank_account_from_explicit_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="银行账号：1234 5678-9012 345678", ocr_blocks=[])

    assert "1234 5678-9012 345678" in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "1234 5678-9012 345678" not in _candidate_texts(candidates, PIIAttributeType.OTHER)


def test_rule_based_detects_passport_number_from_context_and_regex(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    context_candidates = detector.detect(prompt_text="护照号：E12345678", ocr_blocks=[])
    regex_candidates = detector.detect(prompt_text="证件信息 E12345678", ocr_blocks=[])

    assert "E12345678" in _candidate_texts(context_candidates, PIIAttributeType.PASSPORT_NUMBER)
    assert "E12345678" in _candidate_texts(regex_candidates, PIIAttributeType.PASSPORT_NUMBER)
    assert "E12345678" not in _candidate_texts(context_candidates, PIIAttributeType.OTHER)


def test_rule_based_detects_driver_license_from_explicit_context(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="驾驶证号：440301199001011234", ocr_blocks=[])

    assert "440301199001011234" in _candidate_texts(candidates, PIIAttributeType.DRIVER_LICENSE)
    assert "440301199001011234" not in _candidate_texts(candidates, PIIAttributeType.OTHER)


def test_rule_based_regex_number_conflict_downgrades_order_like_long_number_to_other(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="订单号1234567890123", ocr_blocks=[])

    assert "1234567890123" in _candidate_texts(candidates, PIIAttributeType.OTHER)
    assert "1234567890123" not in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)


def test_rule_based_regex_number_conflict_prefers_id_with_birthdate_over_other_numeric_types(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="110101199001011234", ocr_blocks=[])

    assert "110101199001011234" in _candidate_texts(candidates, PIIAttributeType.ID_NUMBER)
    assert "110101199001011234" not in _candidate_texts(candidates, PIIAttributeType.CARD_NUMBER)
    assert "110101199001011234" not in _candidate_texts(candidates, PIIAttributeType.OTHER)


def test_rule_based_regex_number_conflict_prefers_super_long_account_as_bank_account(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="6217000012345678901234", ocr_blocks=[])

    assert "6217000012345678901234" in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "6217000012345678901234" not in _candidate_texts(candidates, PIIAttributeType.OTHER)


def test_rule_based_regex_number_conflict_downgrades_bare_12_digit_number_to_other(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="123456789012", ocr_blocks=[])

    assert "123456789012" in _candidate_texts(candidates, PIIAttributeType.OTHER)
    assert "123456789012" not in _candidate_texts(candidates, PIIAttributeType.BANK_ACCOUNT)
    assert "123456789012" not in _candidate_texts(candidates, PIIAttributeType.DRIVER_LICENSE)


def test_rule_based_regex_driver_license_alnum_keeps_specific_type_without_ambiguous_duplicate(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    candidates = detector.detect(prompt_text="C12345678901", ocr_blocks=[])

    driver_candidates = [candidate for candidate in candidates if candidate.text == "C12345678901"]
    assert any(candidate.attr_type == PIIAttributeType.DRIVER_LICENSE for candidate in driver_candidates)
    assert not any(candidate.attr_type == PIIAttributeType.OTHER for candidate in driver_candidates)


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


def test_rule_based_dictionary_matches_phone_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"phone": ["13800138000"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="请联系1380·0138_000", ocr_blocks=[])

    assert any(
        candidate.text == "1380·0138_000"
        and candidate.attr_type == PIIAttributeType.PHONE
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_card_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps({"card_number": ["6222020012345678"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="卡号是6222 0200-1234，5678", ocr_blocks=[])

    assert any(
        candidate.text == "6222 0200-1234，5678"
        and candidate.attr_type == PIIAttributeType.CARD_NUMBER
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_bank_account_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps({"bank_account": ["123456789012345678"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="收款账号1234 5678-9012，345678", ocr_blocks=[])

    assert any(
        candidate.text == "1234 5678-9012，345678"
        and candidate.attr_type == PIIAttributeType.BANK_ACCOUNT
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_passport_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps({"passport_number": ["E12345678"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="护照是E-1234 5678", ocr_blocks=[])

    assert any(
        candidate.text == "E-1234 5678"
        and candidate.attr_type == PIIAttributeType.PASSPORT_NUMBER
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_driver_license_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps({"driver_license": ["440301199001011234"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="驾驶证号440301-19900101 1234", ocr_blocks=[])

    assert any(
        candidate.text == "440301-19900101 1234"
        and candidate.attr_type == PIIAttributeType.DRIVER_LICENSE
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_prefix_only_and_suffix_only_masked_high_precision_values(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps(
            {
                "phone": ["15412348000"],
                "card_number": ["6222020012345678"],
                "bank_account": ["123456789012345678"],
                "email": ["foo@bar.com"],
                "id_number": ["110101199001011234"],
                "passport_number": ["E12345678"],
                "driver_license": ["440301199001011234"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(
        prompt_text=(
            "手机号154********；手机号尾号*******8000；"
            "卡号6222************；卡尾号************5678；"
            "账号1234**************；账号尾号**************5678；"
            "邮箱f***@bar.com；邮箱尾号***@bar.com；"
            "身份证110101************；身份证尾号**************1234；"
            "护照E1*******；护照尾号*****5678；"
            "驾驶证440301************；驾驶证尾号**************1234"
        ),
        ocr_blocks=[],
    )

    expected = {
        (PIIAttributeType.PHONE, "154********"),
        (PIIAttributeType.PHONE, "*******8000"),
        (PIIAttributeType.CARD_NUMBER, "6222************"),
        (PIIAttributeType.CARD_NUMBER, "************5678"),
        (PIIAttributeType.BANK_ACCOUNT, "1234**************"),
        (PIIAttributeType.BANK_ACCOUNT, "**************5678"),
        (PIIAttributeType.EMAIL, "f***@bar.com"),
        (PIIAttributeType.EMAIL, "***@bar.com"),
        (PIIAttributeType.ID_NUMBER, "110101************"),
        (PIIAttributeType.ID_NUMBER, "**************1234"),
        (PIIAttributeType.PASSPORT_NUMBER, "E1*******"),
        (PIIAttributeType.PASSPORT_NUMBER, "*****5678"),
        (PIIAttributeType.DRIVER_LICENSE, "440301************"),
        (PIIAttributeType.DRIVER_LICENSE, "**************1234"),
    }
    observed = {
        (candidate.attr_type, candidate.text)
        for candidate in candidates
        if "dictionary_local" in candidate.metadata.get("matched_by", [])
    }

    assert expected <= observed


def test_rule_based_session_history_matches_prefix_only_and_suffix_only_masked_phone(tmp_path) -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-masked-phone",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-masked-phone",
                turn_id=1,
                candidate_id="cand-1",
                source_text="15412348000",
                canonical_source_text="15412348000",
                replacement_text="@手机号1",
                attr_type=PIIAttributeType.PHONE,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    detector = RuleBasedPIIDetector(mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="请联系154********或*******8000",
        ocr_blocks=[],
        session_id="session-masked-phone",
        turn_id=2,
    )

    assert any(
        candidate.text == "154********"
        and candidate.attr_type == PIIAttributeType.PHONE
        and "dictionary_session" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )
    assert any(
        candidate.text == "*******8000"
        and candidate.attr_type == PIIAttributeType.PHONE
        and "dictionary_session" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_common_mask_symbols_for_high_precision_values(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(
        json.dumps(
            {
                "phone": ["15412348000"],
                "card_number": ["6222020012345678"],
                "bank_account": ["123456789012345678"],
                "email": ["foo@bar.com"],
                "id_number": ["110101199001011234"],
                "passport_number": ["E12345678"],
                "driver_license": ["440301199001011234"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(
        prompt_text=(
            "手机号154XXXXXXXX；"
            "卡号6222●●●●●●●●●●●●；"
            "账号1234■■■■■■■■■■■■■■；"
            "邮箱f●●@bar.com；"
            "身份证110101●●●●●●●●●●●●；"
            "护照E1●●●●●●●；"
            "驾驶证440301■■■■■■■■■■■■"
        ),
        ocr_blocks=[],
    )

    expected = {
        (PIIAttributeType.PHONE, "154XXXXXXXX"),
        (PIIAttributeType.CARD_NUMBER, "6222●●●●●●●●●●●●"),
        (PIIAttributeType.BANK_ACCOUNT, "1234■■■■■■■■■■■■■■"),
        (PIIAttributeType.EMAIL, "f●●@bar.com"),
        (PIIAttributeType.ID_NUMBER, "110101●●●●●●●●●●●●"),
        (PIIAttributeType.PASSPORT_NUMBER, "E1●●●●●●●"),
        (PIIAttributeType.DRIVER_LICENSE, "440301■■■■■■■■■■■■"),
    }
    observed = {
        (candidate.attr_type, candidate.text)
        for candidate in candidates
        if "dictionary_local" in candidate.metadata.get("matched_by", [])
    }

    assert expected <= observed


def test_rule_based_dictionary_matches_email_with_ocr_punctuation_noise(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"email": ["foo@bar.com"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="邮箱是foo＠bar，com", ocr_blocks=[])

    assert any(
        candidate.text == "foo＠bar，com"
        and candidate.attr_type == PIIAttributeType.EMAIL
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_matches_name_with_ocr_digit_noise_and_sets_canonical_source(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="请联系张1三处理", ocr_blocks=[])

    assert any(
        candidate.text == "张1三"
        and candidate.canonical_source_text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_does_not_match_name_prefix_inside_longer_name(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="张三丰是小说人物", ocr_blocks=[])

    assert not any(
        candidate.text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_dictionary_keeps_known_name_match_in_action_context(tmp_path) -> None:
    dictionary_path = tmp_path / "pii_dictionary.json"
    dictionary_path.write_text(json.dumps({"name": ["张三"]}, ensure_ascii=False), encoding="utf-8")
    detector = RuleBasedPIIDetector(dictionary_path=dictionary_path)

    candidates = detector.detect(prompt_text="请联系张三处理", ocr_blocks=[])

    assert any(
        candidate.text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_local" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_session_dictionary_matches_name_with_ocr_digit_noise_and_sets_canonical_source() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-name-noise",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-name-noise",
                turn_id=1,
                candidate_id="cand-name-1",
                source_text="张1三",
                canonical_source_text="张三",
                replacement_text="@姓名1",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    detector = RuleBasedPIIDetector(mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="请联系张1三处理",
        ocr_blocks=[],
        session_id="session-name-noise",
        turn_id=2,
    )

    assert any(
        candidate.text == "张1三"
        and candidate.canonical_source_text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_session" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_session_dictionary_does_not_match_name_prefix_inside_longer_name() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        session_id="session-name-prefix",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="session-name-prefix",
                turn_id=1,
                candidate_id="cand-name-1",
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
        prompt_text="张三丰是小说人物",
        ocr_blocks=[],
        session_id="session-name-prefix",
        turn_id=2,
    )

    assert not any(
        candidate.text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        and "dictionary_session" in candidate.metadata.get("matched_by", [])
        for candidate in candidates
    )


def test_rule_based_strong_name_rule_canonicalizes_ocr_digit_noise(tmp_path) -> None:
    detector = _make_detector(tmp_path)

    strong_candidates = detector.detect(
        prompt_text="我的名字是张1三",
        ocr_blocks=[],
        protection_level=ProtectionLevel.STRONG,
    )
    balanced_candidates = detector.detect(
        prompt_text="我的名字是张1三",
        ocr_blocks=[],
        protection_level=ProtectionLevel.BALANCED,
    )

    assert any(
        candidate.text == "张1三"
        and candidate.canonical_source_text == "张三"
        and candidate.attr_type == PIIAttributeType.NAME
        for candidate in strong_candidates
    )
    assert not any(candidate.attr_type == PIIAttributeType.NAME for candidate in balanced_candidates)


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


def test_rule_based_dictionary_downgrades_ambiguous_local_address_alias_binding_to_type_only_hit(tmp_path) -> None:
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

    assert any(
        candidate.text == "体育西路"
        and candidate.attr_type == PIIAttributeType.ADDRESS
        and candidate.metadata.get("matched_by") == ["dictionary_local_ambiguous"]
        and "ambiguous_binding_keys" in candidate.metadata
        and "local_entity_ids" not in candidate.metadata
        for candidate in candidates
    )


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


def test_rule_based_dictionary_downgrades_ambiguous_entity_level_name_binding_to_type_only_hit(tmp_path) -> None:
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

    assert any(
        candidate.text == "张 三"
        and candidate.attr_type == PIIAttributeType.NAME
        and candidate.metadata.get("matched_by") == ["dictionary_local_ambiguous"]
        and "ambiguous_binding_keys" in candidate.metadata
        for candidate in candidates
    )
