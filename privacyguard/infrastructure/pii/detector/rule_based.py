"""Rewritten rule-based detector."""

from __future__ import annotations

import re
from pathlib import Path

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, DictionaryEntry
from privacyguard.infrastructure.pii.detector.ocr import apply_ocr_geometry
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_ocr_stream, build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.json_privacy_repository import DEFAULT_PRIVACY_REPOSITORY_PATH, JsonPrivacyRepository, parse_privacy_repository_document
from privacyguard.utils.pii_value import (
    address_components_from_levels,
    canonicalize_name_text,
    canonicalize_organization_text,
    compact_bank_account_value,
    compact_card_number_value,
    compact_driver_license_value,
    compact_email_value,
    compact_id_value,
    compact_other_code_value,
    compact_passport_value,
    compact_phone_value,
    render_address_components,
)


class RuleBasedPIIDetector:
    def __init__(
        self,
        privacy_repository_path: str | Path | None = None,
        detector_mode: str = "rule_based",
        locale_profile: str = "mixed",
        mapping_store: MappingStore | None = None,
    ) -> None:
        self.detector_mode = detector_mode
        self.locale_profile = self._normalize_locale_profile(locale_profile)
        self.mapping_store = mapping_store
        self.resolver = CandidateResolverService()
        self.privacy_repository_path = self._resolve_privacy_repository_path(privacy_repository_path)
        self.local_entries = self._load_local_dictionary()

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
        ctx = DetectContext(
            protection_level=ProtectionLevel(protection_level) if isinstance(protection_level, str) else protection_level,
            detector_overrides=detector_overrides,
            session_id=session_id,
            turn_id=turn_id,
        )
        session_entries = self._load_session_dictionary(session_id=session_id, turn_id=turn_id)
        parser = StreamParser(locale_profile=self.locale_profile, ctx=ctx)
        candidates: list[PIICandidate] = []

        prompt_stream = build_prompt_stream(prompt_text)
        prompt_bundle = build_clue_bundle(
            prompt_stream,
            ctx=ctx,
            session_entries=session_entries,
            local_entries=self.local_entries,
            locale_profile=self.locale_profile,
        )
        prompt_result = parser.parse(prompt_stream, prompt_bundle)
        candidates.extend(self._to_pii_candidates(prompt_result.candidates))

        ocr_stream, ocr_scene = build_ocr_stream(ocr_blocks)
        ocr_bundle = build_clue_bundle(
            ocr_stream,
            ctx=ctx,
            session_entries=session_entries,
            local_entries=self.local_entries,
            locale_profile=self.locale_profile,
        )
        ocr_result = parser.parse(ocr_stream, ocr_bundle)
        ocr_drafts = apply_ocr_geometry(
            stream=ocr_stream,
            scene=ocr_scene,
            bundle=ocr_bundle,
            parsed=ocr_result,
        )
        candidates.extend(self._to_pii_candidates(ocr_drafts))
        return self.resolver.resolve_candidates(candidates)

    def reload_privacy_dictionary(self) -> None:
        self.local_entries = self._load_local_dictionary()

    def _normalize_locale_profile(self, locale_profile: str) -> str:
        normalized = str(locale_profile or "mixed").strip().lower()
        if normalized not in {"zh_cn", "en_us", "mixed"}:
            raise ValueError(f"unsupported locale_profile: {locale_profile}")
        return normalized

    def _resolve_privacy_repository_path(self, path: str | Path | None) -> Path:
        if path is None:
            return Path(DEFAULT_PRIVACY_REPOSITORY_PATH)
        return Path(path)

    def _load_local_dictionary(self) -> tuple[DictionaryEntry, ...]:
        repository = JsonPrivacyRepository(path=str(self.privacy_repository_path))
        document = parse_privacy_repository_document(repository.load_raw())
        entries: list[DictionaryEntry] = []
        for persona in document.true_personas:
            slots = persona.slots
            persona_metadata = {"local_entity_ids": [persona.persona_id]}
            for slot in slots.name or []:
                entries.append(
                    self._dictionary_entry(
                        attr_type=PIIAttributeType.NAME,
                        text=slot.full.value,
                        aliases=list(slot.full.aliases),
                        matched_by="dictionary_local",
                        metadata={**persona_metadata, "name_component": ["full"]},
                    )
                )
                if slot.family:
                    entries.append(
                        self._dictionary_entry(
                            attr_type=PIIAttributeType.NAME,
                            text=slot.family.value,
                            aliases=list(slot.family.aliases),
                            matched_by="dictionary_local",
                            metadata={**persona_metadata, "name_component": ["family"]},
                        )
                    )
                if slot.given:
                    entries.append(
                        self._dictionary_entry(
                            attr_type=PIIAttributeType.NAME,
                            text=slot.given.value,
                            aliases=list(slot.given.aliases),
                            matched_by="dictionary_local",
                            metadata={**persona_metadata, "name_component": ["given"]},
                        )
                    )
                if slot.middle:
                    entries.append(
                        self._dictionary_entry(
                            attr_type=PIIAttributeType.NAME,
                            text=slot.middle.value,
                            aliases=list(slot.middle.aliases),
                            matched_by="dictionary_local",
                            metadata={**persona_metadata, "name_component": ["middle"]},
                        )
                    )
            entries.extend(self._scalar_slot_entries(PIIAttributeType.PHONE, slots.phone, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.CARD_NUMBER, slots.card_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.BANK_ACCOUNT, slots.bank_account, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.PASSPORT_NUMBER, slots.passport_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.DRIVER_LICENSE, slots.driver_license, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.EMAIL, slots.email, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.ID_NUMBER, slots.id_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.ORGANIZATION, slots.organization, persona.persona_id))
            for slot in slots.address or []:
                components = address_components_from_levels(
                    country_text=slot.country.value if slot.country else None,
                    province_text=slot.province.value if slot.province else None,
                    city_text=slot.city.value if slot.city else None,
                    district_text=slot.district.value if slot.district else None,
                    street_text=slot.street.value if slot.street else None,
                    building_text=slot.building.value if slot.building else None,
                    room_text=slot.room.value if slot.room else None,
                    postal_code_text=slot.postal_code.value if slot.postal_code else None,
                )
                full_text = render_address_components(components, include_country=bool(components.country_text), granularity="detail")
                entries.append(
                    self._dictionary_entry(
                        attr_type=PIIAttributeType.ADDRESS,
                        text=full_text,
                        aliases=[],
                        matched_by="dictionary_local",
                        metadata={"local_entity_ids": [persona.persona_id]},
                    )
                )
        return tuple(entries)

    def _load_session_dictionary(self, *, session_id: str | None, turn_id: int | None) -> tuple[DictionaryEntry, ...]:
        if self.mapping_store is None or not session_id:
            return ()
        records = self.mapping_store.get_replacements(session_id=session_id)
        entries: list[DictionaryEntry] = []
        for record in records:
            if turn_id is not None and record.turn_id >= turn_id:
                continue
            source_text = record.canonical_source_text or record.source_text
            if not source_text:
                continue
            metadata: dict[str, list[str]] = {"session_turn_ids": [str(record.turn_id)]}
            if record.persona_id:
                metadata["local_entity_ids"] = [record.persona_id]
            if record.metadata.get("name_component"):
                metadata["name_component"] = [record.metadata["name_component"]]
            aliases = [record.source_text] if record.source_text and record.source_text != source_text else []
            entries.append(
                self._dictionary_entry(
                    attr_type=record.attr_type,
                    text=source_text,
                    aliases=aliases,
                    matched_by="dictionary_session",
                    metadata=metadata,
                )
            )
        return tuple(entries)

    def _dictionary_entry(
        self,
        *,
        attr_type: PIIAttributeType,
        text: str,
        aliases: list[str],
        matched_by: str,
        metadata: dict[str, list[str]],
    ) -> DictionaryEntry:
        variants = tuple(dict.fromkeys([text, *aliases]))
        return DictionaryEntry(
            attr_type=attr_type,
            text=text,
            variants=variants,
            matched_by=matched_by,
            metadata={key: list(values) for key, values in metadata.items()},
        )

    def _scalar_slot_entries(self, attr_type, slots, persona_id: str) -> list[DictionaryEntry]:
        entries: list[DictionaryEntry] = []
        for slot in slots or []:
            entries.append(
                self._dictionary_entry(
                    attr_type=attr_type,
                    text=slot.value,
                    aliases=list(slot.aliases),
                    matched_by="dictionary_local",
                    metadata={"local_entity_ids": [persona_id]},
                )
            )
        return entries

    def _to_pii_candidates(self, drafts: list[CandidateDraft]) -> list[PIICandidate]:
        output: list[PIICandidate] = []
        for draft in drafts:
            normalized_text = self._normalize_candidate_text(draft.attr_type, draft.text)
            entity_id = self.resolver.build_candidate_id(
                detector_mode=self.detector_mode,
                source=draft.source.value,
                normalized_text=normalized_text,
                attr_type=draft.attr_type.value,
                block_id=draft.block_id,
                span_start=draft.span_start if draft.source == PIISourceType.OCR else draft.start,
                span_end=draft.span_end if draft.source == PIISourceType.OCR else draft.end,
            )
            output.append(
                PIICandidate(
                    entity_id=entity_id,
                    text=draft.text,
                    canonical_source_text=draft.text,
                    normalized_text=normalized_text,
                    attr_type=draft.attr_type,
                    source=draft.source,
                    bbox=draft.bbox,
                    block_id=draft.block_id,
                    span_start=draft.span_start if draft.source == PIISourceType.OCR else draft.start,
                    span_end=draft.span_end if draft.source == PIISourceType.OCR else draft.end,
                    metadata={key: list(dict.fromkeys(values)) for key, values in draft.metadata.items()},
                )
            )
        return output

    def _normalize_candidate_text(self, attr_type: PIIAttributeType, text: str) -> str:
        cleaned = str(text or "").strip()
        if attr_type == PIIAttributeType.NAME:
            return canonicalize_name_text(cleaned)
        if attr_type == PIIAttributeType.PHONE:
            return compact_phone_value(cleaned)
        if attr_type == PIIAttributeType.CARD_NUMBER:
            return compact_card_number_value(cleaned)
        if attr_type == PIIAttributeType.BANK_ACCOUNT:
            return compact_bank_account_value(cleaned)
        if attr_type == PIIAttributeType.PASSPORT_NUMBER:
            return compact_passport_value(cleaned)
        if attr_type == PIIAttributeType.DRIVER_LICENSE:
            return compact_driver_license_value(cleaned)
        if attr_type == PIIAttributeType.EMAIL:
            return compact_email_value(cleaned)
        if attr_type == PIIAttributeType.ID_NUMBER:
            return compact_id_value(cleaned)
        if attr_type == PIIAttributeType.ORGANIZATION:
            return canonicalize_organization_text(cleaned)
        if attr_type in {PIIAttributeType.ADDRESS, PIIAttributeType.DETAILS}:
            return re.sub(r"[\s,，;；:：/\\\-]+", "", cleaned.lower())
        return compact_other_code_value(cleaned)
