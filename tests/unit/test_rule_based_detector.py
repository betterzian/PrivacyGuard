"""Rule Based 检测器测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def _create_dictionary(tmp_path: Path) -> Path:
    """创建测试用字典文件。"""
    dictionary_path = tmp_path / "pii_dictionary.sample.json"
    dictionary_path.write_text(
        json.dumps(
            {
                "name": ["张三"],
                "phone": ["13800138000"],
                "email": ["demo@example.com"],
                "address": ["北京市海淀区XX路"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return dictionary_path


def test_rule_based_detects_dictionary_name_phone_email(tmp_path: Path) -> None:
    """验证可识别字典姓名、手机号和邮箱。"""
    detector = RuleBasedPIIDetector(dictionary_path=_create_dictionary(tmp_path))
    prompt = "联系人张三，电话13800138000，邮箱demo@example.com"
    blocks = [
        OCRTextBlock(
            text="张三住在北京市海淀区XX路",
            bbox=BoundingBox(x=1, y=1, width=20, height=10),
            score=0.9,
            line_id=0,
        )
    ]

    candidates = detector.detect(prompt_text=prompt, ocr_blocks=blocks)
    attr_types = {item.attr_type for item in candidates}

    assert PIIAttributeType.NAME in attr_types
    assert PIIAttributeType.PHONE in attr_types
    assert PIIAttributeType.EMAIL in attr_types


def test_rule_based_outputs_prompt_and_ocr_sources(tmp_path: Path) -> None:
    """验证 prompt 与 OCR 两种来源都能产生候选。"""
    detector = RuleBasedPIIDetector(dictionary_path=_create_dictionary(tmp_path))
    prompt = "手机号13800138000"
    blocks = [
        OCRTextBlock(
            text="13800138000",
            bbox=BoundingBox(x=2, y=2, width=18, height=8),
            score=0.8,
            line_id=1,
        )
    ]

    candidates = detector.detect(prompt_text=prompt, ocr_blocks=blocks)
    sources = {item.source for item in candidates}

    assert PIISourceType.PROMPT in sources
    assert PIISourceType.OCR in sources


def test_rule_based_deduplicates_repeated_hits(tmp_path: Path) -> None:
    """验证重复命中可去重。"""
    detector = RuleBasedPIIDetector(dictionary_path=_create_dictionary(tmp_path))
    prompt = "手机号13800138000，重复手机号13800138000"

    candidates = detector.detect(prompt_text=prompt, ocr_blocks=[])
    phones = [item for item in candidates if item.attr_type == PIIAttributeType.PHONE and item.source == PIISourceType.PROMPT]

    assert len(phones) == 1

