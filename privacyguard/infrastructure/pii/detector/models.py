"""Core models for the rewritten detector."""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock

from enum import Enum


class ClaimStrength(str, Enum):
    HARD = "hard"
    SOFT = "soft"


class ClueFamily(str, Enum):
    STRUCTURED = "structured"
    ADDRESS = "address"
    NAME = "name"
    ORGANIZATION = "organization"
    BREAK = "break"


@dataclass(frozen=True, slots=True)
class SourceRef:
    source: PIISourceType
    block_id: str | None
    bbox: BoundingBox | None
    block_char_index: int | None


@dataclass(frozen=True, slots=True)
class StreamSpan:
    kind: str
    start: int
    end: int
    block_id: str | None = None
    bbox: BoundingBox | None = None


@dataclass(slots=True)
class StreamInput:
    source: PIISourceType
    raw_text: str
    char_refs: tuple[SourceRef | None, ...]
    spans: tuple[StreamSpan, ...]
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def is_ocr(self) -> bool:
        return self.source == PIISourceType.OCR


@dataclass(frozen=True, slots=True)
class LabelSpec:
    keyword: str
    attr_type: PIIAttributeType
    priority: int
    matched_by: str
    ocr_matched_by: str
    stack_kind: str
    component_hint: str | None = None
    ascii_boundary: bool = False


@dataclass(slots=True)
class Claim:
    start: int
    end: int
    attr_type: PIIAttributeType
    strength: ClaimStrength
    owner_stack_id: str


@dataclass(slots=True)
class CandidateDraft:
    attr_type: PIIAttributeType
    start: int
    end: int
    text: str
    source: PIISourceType
    confidence: float
    matched_by: str
    claim_strength: ClaimStrength = ClaimStrength.SOFT
    metadata: dict[str, list[str]] = field(default_factory=dict)
    label_clue_ids: set[str] = field(default_factory=set)
    block_ids: tuple[str, ...] = ()
    block_id: str | None = None
    bbox: BoundingBox | None = None
    span_start: int | None = None
    span_end: int | None = None


@dataclass(frozen=True, slots=True)
class Clue:
    clue_id: str
    family: ClueFamily
    kind: str
    start: int
    end: int
    text: str
    priority: int
    hard: bool
    attr_type: PIIAttributeType | None
    matched_by: str
    payload: dict[str, object] = field(default_factory=dict)

@dataclass(slots=True)
class ClueBundle:
    label_clues: tuple[Clue, ...]
    all_clues: tuple[Clue, ...]


@dataclass(frozen=True, slots=True)
class DictionaryEntry:
    attr_type: PIIAttributeType
    text: str
    variants: tuple[str, ...]
    confidence: float
    matched_by: str
    metadata: dict[str, list[str]]


@dataclass(frozen=True, slots=True)
class OCRSceneBlock:
    block: OCRTextBlock
    block_id: str
    order_index: int
    line_index: int
    raw_start: int
    raw_end: int


@dataclass(slots=True)
class OCRScene:
    blocks: tuple[OCRSceneBlock, ...]
    id_to_block: dict[str, OCRSceneBlock]
    line_to_blocks: dict[int, tuple[OCRSceneBlock, ...]]


@dataclass(slots=True)
class ParseResult:
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)
