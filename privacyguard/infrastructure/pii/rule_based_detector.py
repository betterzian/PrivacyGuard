"""基于规则与字典的 PII 检测器。"""

import json
import re
from pathlib import Path

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.utils.text import find_all_matches, normalize_text


class RuleBasedPIIDetector:
    """同时处理 prompt 与 OCR 文本的规则检测器。"""

    def __init__(self, dictionary_path: str | Path | None = None, detector_mode: str = "rule_based") -> None:
        """初始化规则、词典与候选解析服务。"""
        self.detector_mode = detector_mode
        self.dictionary_path = self._resolve_dictionary_path(dictionary_path)
        self.dictionary = self._load_dictionary(self.dictionary_path)
        self.resolver = CandidateResolverService()
        self.patterns = self._build_patterns()

    def detect(self, prompt_text: str, ocr_blocks: list[OCRTextBlock]) -> list[PIICandidate]:
        """对 prompt 与 OCR 两路输入执行候选识别。"""
        candidates: list[PIICandidate] = []
        candidates.extend(self._scan_text(prompt_text, PIISourceType.PROMPT, bbox=None))
        for block in ocr_blocks:
            candidates.extend(self._scan_text(block.text, PIISourceType.OCR, bbox=block.bbox))
        return self.resolver.resolve_candidates(candidates)

    def _resolve_dictionary_path(self, dictionary_path: str | Path | None) -> Path:
        """解析字典路径并应用默认路径。PrivacyGuard 包根目录为 __file__ 上 3 级，其下 data/ 为词典目录。"""
        if dictionary_path is not None:
            return Path(dictionary_path)
        # __file__ = .../PrivacyGuard/privacyguard/infrastructure/pii/rule_based_detector.py -> parents[3] = PrivacyGuard
        privacyguard_root = Path(__file__).resolve().parents[3]
        return privacyguard_root / "data" / "pii_dictionary.sample.json"

    def _load_dictionary(self, dictionary_path: Path) -> dict[PIIAttributeType, set[str]]:
        """读取 JSON 字典并映射到属性类型。"""
        if not dictionary_path.exists():
            print(f"[PrivacyGuard] rule_based 词典未找到，将仅使用正则: {dictionary_path}")
            return {}
        content = json.loads(dictionary_path.read_text(encoding="utf-8"))
        mapped: dict[PIIAttributeType, set[str]] = {}
        for raw_key, values in content.items():
            attr_type = self._to_attr_type(raw_key)
            if attr_type is None:
                continue
            mapped[attr_type] = {normalize_text(str(item)) for item in values}
        return mapped

    def _build_patterns(self) -> dict[PIIAttributeType, list[tuple[re.Pattern[str], str, float]]]:
        """构建正则规则集合。"""
        return {
            PIIAttributeType.PHONE: [
                (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "regex_phone", 0.78),
            ],
            PIIAttributeType.EMAIL: [
                (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "regex_email", 0.8),
            ],
            PIIAttributeType.OTHER: [
                (re.compile(r"(?<!\d)\d{4,8}(?!\d)"), "regex_code", 0.62),
            ],
            PIIAttributeType.ADDRESS: [
                (re.compile(r"(省|市|区|县|路|街|号|大厦|公寓)"), "regex_address_hint", 0.55),
            ],
        }

    def _scan_text(self, text: str, source: PIISourceType, bbox: object) -> list[PIICandidate]:
        """对单段文本执行字典与正则识别。"""
        normalized_text = normalize_text(text)
        collected: dict[tuple[str, str], PIICandidate] = {}
        self._collect_dictionary_hits(collected, text, normalized_text, source, bbox)
        self._collect_regex_hits(collected, text, source, bbox)
        return list(collected.values())

    def _collect_dictionary_hits(
        self,
        collected: dict[tuple[str, str], PIICandidate],
        raw_text: str,
        normalized_text: str,
        source: PIISourceType,
        bbox: object,
    ) -> None:
        """收集本地字典命中。"""
        for attr_type, terms in self.dictionary.items():
            for term in terms:
                if not term or term not in normalized_text:
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=term,
                    attr_type=attr_type,
                    source=source,
                    bbox=bbox,
                    confidence=0.85,
                    matched_by="dictionary_exact",
                )

    def _collect_regex_hits(
        self,
        collected: dict[tuple[str, str], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
    ) -> None:
        """收集正则规则命中。"""
        for attr_type, rule_items in self.patterns.items():
            for pattern, matched_by, confidence in rule_items:
                for matched_text in find_all_matches(pattern, raw_text):
                    if attr_type == PIIAttributeType.ADDRESS and len(matched_text.strip()) <= 1:
                        continue
                    self._upsert_candidate(
                        collected=collected,
                        text=raw_text,
                        matched_text=matched_text,
                        attr_type=attr_type,
                        source=source,
                        bbox=bbox,
                        confidence=confidence,
                        matched_by=matched_by,
                    )

    def _upsert_candidate(
        self,
        collected: dict[tuple[str, str], PIICandidate],
        text: str,
        matched_text: str,
        attr_type: PIIAttributeType,
        source: PIISourceType,
        bbox: object,
        confidence: float,
        matched_by: str,
    ) -> None:
        """插入候选，或更新已存在候选的置信度与元信息。"""
        normalized = normalize_text(matched_text)
        key = (normalized, attr_type.value)
        entity_id = self.resolver.build_candidate_id(self.detector_mode, source.value, normalized, attr_type.value)
        incoming = PIICandidate(
            entity_id=entity_id,
            text=matched_text if matched_text else text,
            normalized_text=normalized,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            confidence=confidence,
            metadata={"matched_by": [matched_by]},
        )
        previous = collected.get(key)
        if previous is None:
            collected[key] = incoming
            return
        merged_matched_by = sorted(set(previous.metadata.get("matched_by", [])) | {matched_by})
        if incoming.confidence > previous.confidence:
            incoming.metadata = {"matched_by": merged_matched_by}
            collected[key] = incoming
            return
        previous.metadata = {"matched_by": merged_matched_by}
        if "dictionary_exact" in merged_matched_by and any(item.startswith("regex_") for item in merged_matched_by):
            previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.1)

    def _to_attr_type(self, raw_key: str) -> PIIAttributeType | None:
        """将字典键名映射为领域枚举。"""
        key = raw_key.strip().lower()
        mapping = {
            "name": PIIAttributeType.NAME,
            "phone": PIIAttributeType.PHONE,
            "email": PIIAttributeType.EMAIL,
            "address": PIIAttributeType.ADDRESS,
            "id_number": PIIAttributeType.ID_NUMBER,
            "id": PIIAttributeType.ID_NUMBER,
            "organization": PIIAttributeType.ORGANIZATION,
        }
        return mapping.get(key)

