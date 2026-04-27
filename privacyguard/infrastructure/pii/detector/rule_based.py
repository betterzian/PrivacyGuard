"""Rewritten rule-based detector."""

from __future__ import annotations

from pathlib import Path
import re

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, DictionaryEntry, StructuredLookupIndex
from privacyguard.infrastructure.pii.detector.ocr import apply_ocr_geometry
from privacyguard.infrastructure.pii.detector.parser import StreamParser
from privacyguard.infrastructure.pii.detector.preprocess import build_ocr_stream, build_prompt_stream
from privacyguard.infrastructure.pii.detector.scanner import build_clue_bundle
from privacyguard.infrastructure.pii.json_privacy_repository import DEFAULT_PRIVACY_REPOSITORY_PATH, JsonPrivacyRepository, parse_privacy_repository_document
from privacyguard.infrastructure.repository.schemas import AddressLevel
from privacyguard.utils.normalized_pii import normalize_pii, normalized_primary_text
from privacyguard.utils.text import is_cjk_text

_ADDRESS_LEVEL_VALUES: frozenset[str] = frozenset(level.value for level in AddressLevel)
_GENERIC_FRAGMENT_MIN_LENGTH = 5
_NON_PII_STRUCTURED_ATTR_TYPES = frozenset({
    PIIAttributeType.TIME,
    PIIAttributeType.AMOUNT,
})


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
        structured_lookup_index = self._build_structured_lookup_index(
            session_entries=session_entries,
            local_entries=self.local_entries,
        )
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
        prompt_result = parser.parse(prompt_stream, prompt_bundle, structured_lookup_index=structured_lookup_index)
        candidates.extend(self._to_pii_candidates(prompt_result.candidates))

        prepared_ocr = build_ocr_stream(ocr_blocks)
        ocr_stream = prepared_ocr.stream
        ocr_bundle = build_clue_bundle(
            ocr_stream,
            ctx=ctx,
            session_entries=session_entries,
            local_entries=self.local_entries,
            locale_profile=self.locale_profile,
        )
        ocr_result = parser.parse(ocr_stream, ocr_bundle, structured_lookup_index=structured_lookup_index)
        ocr_drafts = apply_ocr_geometry(
            prepared=prepared_ocr,
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
            for slot in slots.name or []:
                entries.append(self._name_entry(component="full", value=slot.full.value, persona_id=persona.persona_id))
                # family / middle 只对非 CJK 文本发射 entry：中文 scanner 不消费这两类 component，
                # 避免单字姓或单字中间名造成过度召回。保留原字段是为了英文匹配需要。
                if slot.family and not is_cjk_text(slot.family.value):
                    entries.append(self._name_entry(component="family", value=slot.family.value, persona_id=persona.persona_id))
                if slot.given:
                    entries.append(self._name_entry(component="given", value=slot.given.value, persona_id=persona.persona_id))
                if slot.alias:
                    entries.append(self._name_entry(component="alias", value=slot.alias.value, persona_id=persona.persona_id))
                if slot.middle and not is_cjk_text(slot.middle.value):
                    entries.append(self._name_entry(component="middle", value=slot.middle.value, persona_id=persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.PHONE, slots.phone, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.BANK_NUMBER, slots.bank_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.PASSPORT_NUMBER, slots.passport_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.DRIVER_LICENSE, slots.driver_license, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.EMAIL, slots.email, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.ID_NUMBER, slots.id_number, persona.persona_id))
            entries.extend(self._scalar_slot_entries(PIIAttributeType.ORGANIZATION, slots.organization, persona.persona_id))
            for slot in slots.address or []:
                main_components = self._address_components_from_slot(slot)
                if main_components:
                    entries.append(
                        self._dictionary_entry(
                            attr_type=PIIAttributeType.ADDRESS,
                            match_terms=normalize_pii(
                                PIIAttributeType.ADDRESS,
                                "",
                                components=main_components,
                            ).match_terms,
                            matched_by="dictionary_local",
                            metadata={"local_entity_ids": [persona.persona_id]},
                        )
                    )
                # 扁平组件袋：每条 (level, value) 独立发射一个 DictionaryEntry，
                # 由 scanner 侧按字数/预置强度决定 ClaimStrength。
                for component in slot.components:
                    metadata: dict[str, list[str]] = {
                        "local_entity_ids": [persona.persona_id],
                        "address_level": [component.level.value],
                    }
                    if component.strength is not None:
                        metadata["claim_strength"] = [component.strength.value]
                    entries.append(
                        self._dictionary_entry(
                            attr_type=PIIAttributeType.ADDRESS,
                            match_terms=(component.value,),
                            matched_by="dictionary_local",
                            metadata=metadata,
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
            normalized = record.normalized_source or normalize_pii(record.attr_type, record.source_text, metadata=record.metadata)
            # 对 session 地址：优先复用持久化的结构化 components，并用统一归一逻辑重建 match_terms，
            # 避免“session/local 裁剪规则不一致”导致的漂移（如 南京东路 -> 南京 / 南京东）。
            if record.attr_type == PIIAttributeType.ADDRESS and normalized.components:
                normalized = normalize_pii(
                    PIIAttributeType.ADDRESS,
                    record.source_text,
                    components=normalized.components,
                    metadata=record.metadata,
                )
            base_metadata: dict[str, list[str]] = {"session_turn_ids": [str(record.turn_id)]}
            if record.persona_id:
                base_metadata["local_entity_ids"] = [record.persona_id]

            if record.attr_type == PIIAttributeType.NAME:
                entries.extend(self._session_name_entries(record=record, normalized=normalized, base_metadata=base_metadata))
                continue

            source_text = normalized_primary_text(normalized)
            if not source_text:
                continue
            metadata = dict(base_metadata)
            entries.append(
                self._dictionary_entry(
                    attr_type=record.attr_type,
                    match_terms=self._structured_match_terms(record.source_text, normalized.match_terms or ((source_text,) if source_text else ())),
                    matched_by="dictionary_session",
                    metadata=metadata,
                )
            )
            # 地址主结构 entry 已发射；再追加扁平组件袋（含 suspect）供 scanner 独立匹配。
            if record.attr_type == PIIAttributeType.ADDRESS:
                entries.extend(self._session_address_component_entries(normalized=normalized, base_metadata=base_metadata))
        return tuple(entries)

    def _session_name_entries(
        self,
        *,
        record,
        normalized,
        base_metadata: dict[str, list[str]],
    ) -> list[DictionaryEntry]:
        """按 locale 展开 session 姓名 record 为多条词典条目。

        - ZH：若 normalized.components 同时有 family 与 given，发 full + given（family 丢弃）；
          否则只发 full。
        - EN：按空白切分 full；≥2 词 → full + family=last + given=others；否则只发 full。
        不产 middle。
        """
        entries: list[DictionaryEntry] = []
        components = dict(normalized.components or {})
        full_text = str(components.get("full") or record.source_text or "").strip()
        if not full_text:
            return entries

        def _emit(component: str, value: str) -> None:
            text = str(value or "").strip()
            if not text:
                return
            metadata = dict(base_metadata)
            metadata["name_component"] = [component]
            entries.append(
                self._dictionary_entry(
                    attr_type=PIIAttributeType.NAME,
                    match_terms=(text,),
                    matched_by="dictionary_session",
                    metadata=metadata,
                )
            )

        if is_cjk_text(full_text):
            _emit("full", full_text)
            family = str(components.get("family") or "").strip()
            given = str(components.get("given") or "").strip()
            if family and given:
                _emit("given", given)
            return entries

        # EN / 非 CJK
        tokens = full_text.split()
        _emit("full", full_text)
        if len(tokens) >= 2:
            _emit("family", tokens[-1])
            _emit("given", " ".join(tokens[:-1]))
        return entries

    def _session_address_component_entries(
        self,
        *,
        normalized,
        base_metadata: dict[str, list[str]],
    ) -> list[DictionaryEntry]:
        """把 normalized.ordered_components 展开为扁平 per-level 条目，与 local 侧对齐。"""
        entries: list[DictionaryEntry] = []
        valid_levels = {level_value for level_value in _ADDRESS_LEVEL_VALUES}
        seen: set[tuple[str, str]] = set()

        def _emit(level_text: str, value_text: str) -> None:
            level_text = str(level_text or "").strip()
            value_text = str(value_text or "").strip()
            if not level_text or not value_text or level_text not in valid_levels:
                return
            key = (level_text, value_text)
            if key in seen:
                return
            seen.add(key)
            metadata = dict(base_metadata)
            metadata["address_level"] = [level_text]
            entries.append(
                self._dictionary_entry(
                    attr_type=PIIAttributeType.ADDRESS,
                    match_terms=(value_text,),
                    matched_by="dictionary_session",
                    metadata=metadata,
                )
            )

        for component in normalized.ordered_components or ():
            level_tuple = getattr(component, "level", ()) or ()
            primary_level = level_tuple[-1] if level_tuple else getattr(component, "component_type", "")
            value = getattr(component, "value", "")
            if isinstance(value, tuple):
                for item in value:
                    _emit(primary_level, item)
            else:
                _emit(primary_level, value)
            for suspect in getattr(component, "suspected", ()) or ():
                suspect_levels = getattr(suspect, "levels", ()) or ()
                suspect_level = suspect_levels[-1] if suspect_levels else ""
                _emit(suspect_level, getattr(suspect, "value", ""))
        return entries

    def _dictionary_entry(
        self,
        *,
        attr_type: PIIAttributeType,
        match_terms: tuple[str, ...],
        matched_by: str,
        metadata: dict[str, list[str]],
    ) -> DictionaryEntry:
        return DictionaryEntry(
            attr_type=attr_type,
            match_terms=tuple(dict.fromkeys(term for term in match_terms if str(term).strip())),
            matched_by=matched_by,
            metadata={key: list(values) for key, values in metadata.items()},
        )

    def _scalar_slot_entries(self, attr_type, slots, persona_id: str) -> list[DictionaryEntry]:
        entries: list[DictionaryEntry] = []
        for slot in slots or []:
            normalized = normalize_pii(attr_type, slot.value)
            entries.append(
                self._dictionary_entry(
                    attr_type=attr_type,
                    match_terms=self._structured_match_terms(
                        slot.value,
                        normalized.match_terms or ((normalized_primary_text(normalized),) if normalized_primary_text(normalized) else ()),
                    ),
                    matched_by="persona",
                    metadata={"local_entity_ids": [persona_id]},
                )
            )
        return entries

    def _build_structured_lookup_index(
        self,
        *,
        session_entries: tuple[DictionaryEntry, ...],
        local_entries: tuple[DictionaryEntry, ...],
    ) -> StructuredLookupIndex:
        index = StructuredLookupIndex()
        for entry in (*session_entries, *local_entries):
            if entry.attr_type in {
                PIIAttributeType.NAME,
                PIIAttributeType.EMAIL,
                PIIAttributeType.ADDRESS,
                PIIAttributeType.ORGANIZATION,
                PIIAttributeType.TIME,
            }:
                continue
            for term in entry.match_terms:
                text = str(term or "").strip()
                if not text:
                    continue
                has_letter = any(char.isalpha() for char in text)
                has_digit = any(char.isdigit() for char in text)
                if has_digit and not has_letter:
                    key = re.sub(r"\D", "", text)
                    if key and key not in index.numeric_entries:
                        index.numeric_entries[key] = entry
                    continue
                if has_digit and has_letter:
                    key = re.sub(r"[^0-9A-Za-z]", "", text).upper()
                    if key and key not in index.alnum_entries:
                        index.alnum_entries[key] = entry
        return index

    def _structured_match_terms(self, raw_value: str, normalized_terms: tuple[str, ...]) -> tuple[str, ...]:
        terms = [term for term in normalized_terms if str(term).strip()]
        raw_text = str(raw_value or "").strip()
        if raw_text:
            has_letter = any(char.isalpha() for char in raw_text)
            has_digit = any(char.isdigit() for char in raw_text)
            if has_digit and has_letter:
                alnum_text = re.sub(r"[^0-9A-Za-z]", "", raw_text).upper()
                if alnum_text:
                    terms.append(alnum_text)
            elif has_digit:
                digits = re.sub(r"\D", "", raw_text)
                if digits:
                    terms.append(digits)
        return tuple(dict.fromkeys(terms))

    def _to_pii_candidates(self, drafts: list[CandidateDraft]) -> list[PIICandidate]:
        output: list[PIICandidate] = []
        for draft in drafts:
            if not self._should_emit_candidate_draft(draft):
                continue
            normalized = normalize_pii(
                draft.attr_type,
                draft.text,
                metadata=draft.metadata,
            )
            canonical_source_text = normalized.canonical or None
            normalized_text = normalized_primary_text(normalized)
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
                    normalized_source=normalized,
                    canonical_source_text=canonical_source_text,
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

    def _should_emit_candidate_draft(self, draft: CandidateDraft) -> bool:
        """过滤不应进入最终 PII 实体的结构化片段。"""
        if draft.attr_type in _NON_PII_STRUCTURED_ATTR_TYPES:
            return False
        if draft.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
            return True
        return self._generic_fragment_length(draft.text) >= _GENERIC_FRAGMENT_MIN_LENGTH

    def _generic_fragment_length(self, text: str) -> int:
        """按隐私判定口径计算 NUM / ALNUM 的有效长度。"""
        compact = re.sub(r"[^0-9A-Za-z]", "", str(text or ""))
        return len(compact)

    def _name_entry(self, *, component: str, value: str, persona_id: str) -> DictionaryEntry:
        normalized = normalize_pii(
            PIIAttributeType.NAME,
            value,
            components={component: value, "full": value},
        )
        match_term = normalized.components.get(component) or value
        return self._dictionary_entry(
            attr_type=PIIAttributeType.NAME,
            match_terms=(match_term,),
            matched_by="dictionary_local",
            metadata={"local_entity_ids": [persona_id], "name_component": [component]},
        )

    def _address_components_from_slot(self, slot) -> dict[str, str]:
        return {
            key: getattr(slot, key).value
            for key in (
                "province",
                "city",
                "district",
                "subdistrict",
                "road",
                "number",
                "poi",
                "building",
                "detail",
            )
            if getattr(slot, key, None) is not None
        }
