from __future__ import annotations

from dataclasses import dataclass, field
from re import Pattern

from privacyguard.domain.enums import ProtectionLevel


@dataclass(frozen=True, slots=True)
class AddressInput:
    text: str
    has_ocr_breaks: bool = False


@dataclass(frozen=True, slots=True)
class AddressComponentMatch:
    component_type: str
    start: int
    end: int
    text: str
    strength: str = "medium"


@dataclass(frozen=True, slots=True)
class AddressSpan:
    start: int
    end: int
    text: str
    matched_by: str
    confidence: float
    terminated_by: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AddressComponent:
    component_type: str
    text: str
    start_offset: int
    end_offset: int
    privacy_level: str
    confidence: float


@dataclass(frozen=True, slots=True)
class AddressParseResult:
    span: AddressSpan
    components: tuple[AddressComponent, ...]
    address_kind: str
    confidence: float


@dataclass(frozen=True, slots=True)
class AddressParseConfig:
    locale_profile: str
    protection_level: ProtectionLevel
    min_confidence: float
    field_label_pattern: Pattern[str] | None = None
    emit_component_candidates: bool = True
    extra_metadata: dict[str, list[str]] = field(default_factory=dict)
