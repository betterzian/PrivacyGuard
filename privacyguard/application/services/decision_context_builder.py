"""Build the base ``DecisionContext`` used by decision-related modules."""

from __future__ import annotations

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.models.decision_context import DecisionContext
from privacyguard.domain.models.mapping import SessionBinding
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate


class DecisionContextBuilder:
    """Assemble the stable, engine-agnostic decision context."""

    def __init__(self, mapping_store: MappingStore, persona_repository: PersonaRepository) -> None:
        self.mapping_store = mapping_store
        self.persona_repository = persona_repository

    def build(
        self,
        *,
        session_id: str,
        turn_id: int,
        prompt_text: str = "",
        protection_level: ProtectionLevel | str = ProtectionLevel.BALANCED,
        detector_overrides: dict[object, float] | None = None,
        ocr_blocks: list[OCRTextBlock] | None = None,
        candidates: list[PIICandidate] | None = None,
        session_binding: SessionBinding | None = None,
    ) -> DecisionContext:
        return DecisionContext(
            session_id=session_id,
            turn_id=turn_id,
            prompt_text=prompt_text,
            protection_level=self._normalize_protection_level(protection_level),
            detector_overrides=self._normalize_detector_overrides(detector_overrides),
            ocr_blocks=list(ocr_blocks or []),
            candidates=list(candidates or []),
            session_binding=session_binding,
            history_records=self._history_records(session_id=session_id),
            persona_profiles=self._persona_profiles(),
        )

    def _history_records(self, session_id: str):
        records = self.mapping_store.get_replacements(session_id=session_id)
        return sorted(records, key=lambda item: (item.turn_id, len(item.replacement_text)), reverse=True)

    def _persona_profiles(self) -> list[PersonaProfile]:
        personas = self.persona_repository.list_personas()
        return sorted(personas, key=lambda item: int(item.stats.get("exposure_count", 0) or 0))

    def _normalize_protection_level(self, protection_level: ProtectionLevel | str) -> ProtectionLevel:
        if isinstance(protection_level, ProtectionLevel):
            return protection_level
        normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
        return ProtectionLevel(normalized)

    def _normalize_detector_overrides(
        self,
        detector_overrides: dict[object, float] | None,
    ) -> dict[object, float]:
        normalized: dict[object, float] = {}
        for key, value in (detector_overrides or {}).items():
            normalized[key] = value
        return normalized

