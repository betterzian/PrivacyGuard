"""RuleBasedPIIDetector internal helper functions."""

from privacyguard.infrastructure.pii.rule_based_detector_shared import *

def _resolve_privacy_repository_path(self, privacy_repository_path: str | Path | None) -> Path | None:
    """解析 privacy_repository 路径；未提供时默认使用空词库。"""
    if privacy_repository_path is None:
        return None
    return Path(privacy_repository_path)

def _load_dictionary(self, dictionary_path: Path | None) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
    """读取本地 privacy 词条（``true_personas``）。"""
    if dictionary_path is None:
        return {}
    if not dictionary_path.exists():
        LOGGER.warning("rule_based privacy_repository not found; falling back to rules only: %s", dictionary_path)
        return {}
    raw = json.loads(dictionary_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise InvalidPrivacyRepositoryError("privacy_repository JSON 顶层必须是对象")
    document = parse_privacy_repository_document(raw)
    return self._load_privacy_dictionary(document.model_dump(mode="json"))

def _load_privacy_dictionary(self, content: dict[str, object]) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
    mapped: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {}
    for raw_persona in content.get("true_personas", []):
        if not isinstance(raw_persona, dict):
            continue
        entity_id = str(raw_persona.get("persona_id") or "").strip() or None
        slots = raw_persona.get("slots", {})
        if not isinstance(slots, dict):
            continue
        for raw_key, values in slots.items():
            attr_type = self._to_attr_type(raw_key)
            if attr_type is None:
                continue
            if attr_type == PIIAttributeType.ADDRESS:
                self._append_dictionary_values(
                    mapped=mapped,
                    attr_type=attr_type,
                    values=self._expand_structured_address_slot(values),
                    entity_id=entity_id,
                )
                continue
            self._append_dictionary_values(
                mapped=mapped,
                attr_type=attr_type,
                values=[values],
                entity_id=entity_id,
            )
    return mapped

def _expand_structured_address_slot(self, address_slot) -> list[object]:
    if not isinstance(address_slot, dict):
        return []

    rendered_parts: list[str] = []
    aliases: list[str] = []
    expanded: list[object] = []
    province_value: str | None = None
    country_value: str | None = None

    for level_name in ("country", "province", "city", "district", "street", "building", "room"):
        level = address_slot.get(level_name)
        if not isinstance(level, dict):
            continue
        value = str(level.get("value") or "").strip()
        if not value:
            continue
        if level_name == "country":
            country_value = value
        if level_name == "province":
            province_value = value
        if level_name == "country":
            rendered_parts.append(value)
        elif level_name != "city" or value != province_value:
            rendered_parts.append(value)
        aliases.extend(self._normalize_aliases(level.get("aliases")))
        expanded.append(level)

    full_value = "".join(rendered_parts)
    unique_aliases = [alias for alias in dict.fromkeys(aliases) if alias and alias != full_value]
    if country_value and country_value != full_value:
        unique_aliases.append(country_value)
    if full_value:
        expanded.insert(0, {"value": full_value, "aliases": unique_aliases})
    return expanded

def _append_dictionary_values(
    self,
    mapped: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
    attr_type: PIIAttributeType,
    values,
    entity_id: str | None,
    default_aliases=None,
) -> None:
    """向词典映射追加词条（含 value / aliases 字典项）。"""
    if isinstance(values, (str, int, float)):
        entries = [values]
    elif isinstance(values, list):
        entries = values
    else:
        return
    for item in entries:
        value, aliases = self._parse_dictionary_item(item, default_aliases=default_aliases)
        if not value:
            continue
        source_term = canonicalize_pii_value(attr_type, value)
        binding_key = f"entity:{entity_id}" if entity_id else f"value:{source_term}"
        local_entity_ids = (entity_id,) if entity_id else ()
        mapped.setdefault(attr_type, []).append(
            _LocalDictionaryEntry(
                value=value,
                source_term=source_term,
                canonical_source_text=self._canonical_dictionary_source_text(attr_type, value),
                binding_key=binding_key,
                aliases=aliases,
                local_entity_ids=local_entity_ids,
                matched_by="dictionary_local",
                confidence=0.99 if entity_id else 0.98,
            )
        )

def _session_dictionary_entries(
    self,
    *,
    session_id: str | None,
    turn_id: int | None,
) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
    """把前序 turn 的 replacement source_text 转成会话级匹配词条。"""
    if self.mapping_store is None or not session_id:
        return {}
    records = self.mapping_store.get_replacements(session_id=session_id)
    if turn_id is not None:
        records = [record for record in records if record.turn_id < turn_id]
    aggregated: dict[tuple[PIIAttributeType, str], ReplacementRecord] = {}
    aliases_by_key: dict[tuple[PIIAttributeType, str], set[str]] = {}
    turn_index: dict[tuple[PIIAttributeType, str], set[str]] = {}
    for record in sorted(records, key=lambda item: (item.turn_id, len(item.source_text)), reverse=True):
        if not record.source_text:
            continue
        canonical_source_text = record.canonical_source_text or record.source_text
        canonical = canonicalize_pii_value(record.attr_type, canonical_source_text)
        if not canonical:
            continue
        key = (record.attr_type, canonical)
        aggregated.setdefault(key, record)
        aliases_by_key.setdefault(key, set()).add(record.source_text)
        turn_index.setdefault(key, set()).add(str(record.turn_id))
    session_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {}
    for (attr_type, canonical), record in aggregated.items():
        metadata = {"session_turn_ids": sorted(turn_index.get((attr_type, canonical), set()))}
        canonical_source_text = record.canonical_source_text or self._canonical_dictionary_source_text(
            attr_type,
            record.source_text,
        )
        value = canonical_source_text or record.source_text
        aliases = tuple(
            alias
            for alias in sorted(aliases_by_key.get((attr_type, canonical), set()))
            if alias and alias != value
        )
        session_entries.setdefault(attr_type, []).append(
            _LocalDictionaryEntry(
                value=value,
                source_term=canonical,
                canonical_source_text=canonical_source_text,
                binding_key=f"session:{attr_type.value}:{canonical}",
                aliases=aliases,
                matched_by="dictionary_session",
                confidence=0.97,
                metadata=metadata,
            )
        )
    return session_entries

def _canonical_dictionary_source_text(self, attr_type: PIIAttributeType, value: str) -> str | None:
    if attr_type != PIIAttributeType.NAME:
        return None
    return self._canonical_name_source_text(value, allow_ocr_noise=True)

def _rule_profile(
    self,
    protection_level: ProtectionLevel | str,
    detector_overrides: dict[PIIAttributeType | str, float] | None = None,
) -> _RuleStrengthProfile:
    """把入参保护度归一到内部规则强度配置。"""
    if isinstance(protection_level, ProtectionLevel):
        base_profile = _RULE_PROFILES[protection_level]
    else:
        normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
        try:
            base_profile = _RULE_PROFILES[ProtectionLevel(normalized)]
        except ValueError:
            base_profile = _RULE_PROFILES[ProtectionLevel.BALANCED]
    merged = dict(base_profile.min_confidence_by_attr)
    merged.update(self.min_confidence_by_attr)
    merged.update(self._normalize_confidence_overrides(detector_overrides))
    return replace(base_profile, min_confidence_by_attr=merged)

def _normalize_confidence_overrides(
    self,
    overrides: dict[PIIAttributeType | str, float] | None,
) -> dict[PIIAttributeType, float]:
    if not overrides:
        return {}
    normalized: dict[PIIAttributeType, float] = {}
    for raw_key, raw_value in overrides.items():
        attr_type = self._to_attr_type(raw_key)
        if attr_type is None or attr_type not in _TUNABLE_RULE_ATTR_TYPES:
            continue
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            continue
        normalized[attr_type] = max(0.0, min(1.0, value))
    return normalized

def _build_dictionary_index(
    self,
    entries_by_attr: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
) -> dict[PIIAttributeType, _CompiledDictionaryIndex]:
    """把词条预编译成首字符/长度索引，降低逐词条线性扫描开销。"""
    compiled: dict[PIIAttributeType, _CompiledDictionaryIndex] = {}
    for attr_type, entries in entries_by_attr.items():
        raw_index: dict[str, dict[int, dict[str, list[_LocalDictionaryEntry]]]] = {}
        for entry in entries:
            for variant in self._dictionary_entry_variants(attr_type, entry):
                if not variant:
                    continue
                by_length = raw_index.setdefault(variant[0], {})
                by_variant = by_length.setdefault(len(variant), {})
                by_variant.setdefault(variant, []).append(entry)
        if not raw_index:
            continue
        compiled[attr_type] = _CompiledDictionaryIndex(
            by_first_char={
                first_char: {
                    length: {
                        variant: tuple(items)
                        for variant, items in variants.items()
                    }
                    for length, variants in by_length.items()
                }
                for first_char, by_length in raw_index.items()
            },
            lengths_by_first_char={
                first_char: tuple(sorted(by_length.keys(), reverse=True))
                for first_char, by_length in raw_index.items()
            },
        )
    return compiled

def _parse_dictionary_item(self, item, default_aliases=None) -> tuple[str, tuple[str, ...]]:
    """把词库 JSON 中的一项解析成 (value, aliases)。"""
    aliases: list[str] = []
    if default_aliases is not None:
        aliases.extend(self._normalize_aliases(default_aliases))
    if isinstance(item, dict):
        raw_value = item.get("value") or item.get("text") or item.get("source")
        aliases.extend(self._normalize_aliases(item.get("aliases")))
    else:
        raw_value = item
    value = str(raw_value).strip() if raw_value is not None else ""
    unique_aliases = tuple(dict.fromkeys(alias for alias in aliases if alias and alias != value))
    return value, unique_aliases

def _normalize_aliases(self, raw_aliases) -> list[str]:
    if raw_aliases is None:
        return []
    if isinstance(raw_aliases, (str, int, float)):
        values = [raw_aliases]
    elif isinstance(raw_aliases, list):
        values = raw_aliases
    else:
        return []
    return [str(item).strip() for item in values if str(item).strip()]
