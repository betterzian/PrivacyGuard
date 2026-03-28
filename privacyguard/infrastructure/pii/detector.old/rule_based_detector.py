"""Unified stream-based PII detector."""

from __future__ import annotations

from pathlib import Path

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.rule_based_detector_shared import *
from privacyguard.infrastructure.pii.rule_based_detector_support import RuleBasedDetectorRuntimeSupport
from privacyguard.infrastructure.pii.stream_engine import UnifiedStreamDetectorEngine


class RuleBasedPIIDetector:
    def __init__(
        self,
        privacy_repository_path: str | Path | None = None,
        detector_mode: str = "rule_based",
        locale_profile: str = "mixed",
        mapping_store: MappingStore | None = None,
        min_confidence_by_attr: dict[PIIAttributeType | str, float] | None = None,
    ) -> None:
        self.detector_mode = detector_mode
        self.locale_profile = self._normalize_locale_profile(locale_profile)
        self.mapping_store = mapping_store
        self.resolver = CandidateResolverService()
        self.runtime = RuleBasedDetectorRuntimeSupport(self)
        self.privacy_repository_path = self.runtime._resolve_privacy_repository_path(privacy_repository_path)
        self.dictionary = self.runtime._load_dictionary(self.privacy_repository_path)
        self.min_confidence_by_attr = self.runtime._normalize_confidence_overrides(min_confidence_by_attr)
        self.engine = UnifiedStreamDetectorEngine(self)

    def detect(
        self,
        prompt_text: str,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_id: str | None = None,
        turn_id: int | None = None,
        protection_level: ProtectionLevel | str = ProtectionLevel.STRONG,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> list[PIICandidate]:
        session_entries = self.runtime._session_dictionary_entries(session_id=session_id, turn_id=turn_id)
        rule_profile = self.runtime._rule_profile(protection_level, detector_overrides=detector_overrides)
        candidates: list[PIICandidate] = []
        candidates.extend(
            self.engine.detect_text(
                prompt_text,
                source=PIISourceType.PROMPT,
                bbox=None,
                block_id=None,
                session_entries=session_entries,
                local_entries=self.dictionary,
                rule_profile=rule_profile,
            )
        )
        candidates.extend(
            self.engine.detect_ocr(
                ocr_blocks,
                session_entries=session_entries,
                local_entries=self.dictionary,
                rule_profile=rule_profile,
            )
        )
        return self.resolver.resolve_candidates(candidates)

    def reload_privacy_dictionary(self) -> None:
        self.dictionary = self.runtime._load_dictionary(self.privacy_repository_path)

    def _normalize_locale_profile(self, locale_profile: str) -> str:
        normalized = str(locale_profile or "mixed").strip().lower()
        if normalized not in {"zh_cn", "en_us", "mixed"}:
            raise ValueError(f"unsupported locale_profile: {locale_profile}")
        return normalized

    def _supports_zh(self) -> bool:
        return self.locale_profile in {"zh_cn", "mixed"}

    def _supports_en(self) -> bool:
        return self.locale_profile in {"en_us", "mixed"}
