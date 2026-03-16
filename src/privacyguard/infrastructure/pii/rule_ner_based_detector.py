"""规则 + NER 增强的 PII 检测器。"""

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.gliner_adapter import GLiNERAdapter
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector
from privacyguard.utils.text import normalize_text


class RuleNerBasedPIIDetector:
    """在规则检测基础上叠加 GLiNER 结果。"""

    def __init__(
        self,
        dictionary_path: str | None = None,
        detector_mode: str = "rule_ner_based",
        gliner_adapter: GLiNERAdapter | None = None,
        gliner: dict[str, object] | None = None,
    ) -> None:
        """初始化 rule_based 检测器与 GLiNER 适配器。"""
        self.detector_mode = detector_mode
        self.rule_based = RuleBasedPIIDetector(dictionary_path=dictionary_path, detector_mode=detector_mode)
        if gliner_adapter is not None:
            self.gliner_adapter = gliner_adapter
        else:
            gliner_config = gliner or {}
            self.gliner_adapter = GLiNERAdapter(
                model_name=str(gliner_config.get("model_name", "urchade/gliner_small-v2.1")),
                enabled=bool(gliner_config.get("enabled", True)),
            )

    def detect(self, prompt_text: str, ocr_blocks: list[OCRTextBlock]) -> list[PIICandidate]:
        """先运行规则检测，再融合 NER 结果。"""
        base_candidates = self.rule_based.detect(prompt_text=prompt_text, ocr_blocks=ocr_blocks)
        if not self.gliner_adapter.available:
            return base_candidates
        ner_candidates: list[PIICandidate] = []
        ner_candidates.extend(self._predict_from_text(prompt_text, PIISourceType.PROMPT, bbox=None))
        for block in ocr_blocks:
            ner_candidates.extend(self._predict_from_text(block.text, PIISourceType.OCR, bbox=block.bbox))
        merged = base_candidates + ner_candidates
        return self.rule_based.resolver.resolve_candidates(merged)

    def _predict_from_text(self, text: str, source: PIISourceType, bbox: object) -> list[PIICandidate]:
        """对单段文本执行 NER 并映射为候选实体。"""
        candidates: list[PIICandidate] = []
        spans = self.gliner_adapter.predict(text)
        for span in spans:
            attr_type = self._map_label_to_attr_type(span.label)
            if attr_type is None:
                continue
            normalized = normalize_text(span.text)
            entity_id = self.rule_based.resolver.build_candidate_id(
                detector_mode=self.detector_mode,
                source=source.value,
                normalized_text=normalized,
                attr_type=attr_type.value,
            )
            candidates.append(
                PIICandidate(
                    entity_id=entity_id,
                    text=span.text,
                    normalized_text=normalized,
                    attr_type=attr_type,
                    source=source,
                    bbox=bbox,
                    confidence=max(0.0, min(1.0, span.score)),
                    detector_mode=self.detector_mode,
                    metadata={"matched_by": ["ner_gliner"]},
                )
            )
        return candidates

    def _map_label_to_attr_type(self, label: str) -> PIIAttributeType | None:
        """将 NER 标签映射为统一 PII 属性类型。"""
        normalized = label.strip().lower()
        mapping = {
            "person": PIIAttributeType.NAME,
            "name": PIIAttributeType.NAME,
            "phone": PIIAttributeType.PHONE,
            "mobile": PIIAttributeType.PHONE,
            "email": PIIAttributeType.EMAIL,
            "address": PIIAttributeType.ADDRESS,
            "id": PIIAttributeType.ID_NUMBER,
            "id_number": PIIAttributeType.ID_NUMBER,
            "organization": PIIAttributeType.ORGANIZATION,
        }
        return mapping.get(normalized)
