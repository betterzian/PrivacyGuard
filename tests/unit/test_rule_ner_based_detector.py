"""Rule + NER 检测器测试。"""

import json
from pathlib import Path

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.gliner_adapter import NERSpan
from privacyguard.infrastructure.pii.rule_ner_based_detector import RuleNerBasedPIIDetector


class UnavailableGLiNERAdapter:
    """测试用不可用 GLiNER 适配器。"""

    available = False

    def predict(self, text: str, labels: list[str] | None = None) -> list[NERSpan]:
        """在不可用场景下返回空结果。"""
        _ = (text, labels)
        return []


class FakeGLiNERAdapter:
    """测试用可用 GLiNER 适配器。"""

    available = True

    def predict(self, text: str, labels: list[str] | None = None) -> list[NERSpan]:
        """返回固定 NER 命中。"""
        _ = (text, labels)
        return [NERSpan(text="李四", label="person", score=0.91)]


def _create_dictionary(tmp_path: Path) -> Path:
    """创建测试字典。"""
    dictionary_path = tmp_path / "pii_dictionary.sample.json"
    dictionary_path.write_text(
        json.dumps({"name": ["张三"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    return dictionary_path


def test_rule_ner_detector_degrades_to_rule_based(tmp_path: Path) -> None:
    """验证 GLiNER 不可用时可优雅降级。"""
    detector = RuleNerBasedPIIDetector(
        dictionary_path=str(_create_dictionary(tmp_path)),
        gliner_adapter=UnavailableGLiNERAdapter(),
    )
    candidates = detector.detect(prompt_text="张三", ocr_blocks=[])
    assert any(item.attr_type == PIIAttributeType.NAME for item in candidates)


def test_rule_ner_detector_merges_gliner_results(tmp_path: Path) -> None:
    """验证 GLiNER 结果可并入最终候选列表。"""
    detector = RuleNerBasedPIIDetector(
        dictionary_path=str(_create_dictionary(tmp_path)),
        gliner_adapter=FakeGLiNERAdapter(),
    )
    candidates = detector.detect(prompt_text="李四", ocr_blocks=[])
    assert any(item.text == "李四" and item.attr_type == PIIAttributeType.NAME for item in candidates)
    assert any("ner_gliner" in item.metadata.get("matched_by", []) for item in candidates)

