"""重写版 detector 的核心数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock


class ClaimStrength(str, Enum):
    HARD = "hard"
    SOFT = "soft"

class ClueRole(str, Enum):
    HARD = "hard"
    LABEL = "label"
    KEY = "key"
    VALUE = "value"
    START = "start"
    SURNAME = "surname"
    GIVEN_NAME = "given_name"
    SUFFIX = "suffix"
    BREAK = "break"
    CONNECTOR = "connector"
    NEGATIVE = "negative"


class AddressComponentType(str, Enum):
    PROVINCE = "province"
    CITY = "city"
    DISTRICT = "district"
    STREET_ADMIN = "street_admin"
    TOWN = "town"
    VILLAGE = "village"
    ROAD = "road"
    STREET = "street"
    COMPOUND = "compound"
    BUILDING = "building"
    UNIT = "unit"
    FLOOR = "floor"
    ROOM = "room"
    STATE = "state"
    POSTAL_CODE = "postal_code"


class BreakType(str, Enum):
    OCR = "ocr"
    PUNCT = "punct"
    NEWLINE = "newline"


class NameComponentHint(str, Enum):
    FULL = "full"
    FAMILY = "family"
    GIVEN = "given"
    ALIAS = "alias"
    MIDDLE = "middle"


@dataclass(frozen=True, slots=True)
class SourceRef:
    source: PIISourceType
    block_id: str | None
    bbox: BoundingBox | None
    block_char_index: int | None
    raw_index: int | None = None


@dataclass(frozen=True, slots=True)
class StreamUnit:
    kind: str
    text: str
    char_start: int
    char_end: int


@dataclass(slots=True)
class StreamInput:
    source: PIISourceType
    text: str
    units: tuple[StreamUnit, ...]
    char_to_unit: tuple[int, ...]
    char_refs: tuple[SourceRef | None, ...]
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def is_ocr(self) -> bool:
        return self.source == PIISourceType.OCR


@dataclass(frozen=True, slots=True)
class LabelSpec:
    keyword: str
    attr_type: PIIAttributeType
    priority: int
    source_kind: str
    ocr_source_kind: str
    component_hint: NameComponentHint | None = None
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
    source_kind: str
    unit_start: int = 0
    unit_end: int = 0
    canonical_text: str | None = None
    claim_strength: ClaimStrength = ClaimStrength.SOFT
    metadata: dict[str, list[str]] = field(default_factory=dict)
    label_clue_ids: set[str] = field(default_factory=set)
    label_driven: bool = False
    block_ids: tuple[str, ...] = ()
    block_id: str | None = None
    bbox: BoundingBox | None = None
    span_start: int | None = None
    span_end: int | None = None


@dataclass(frozen=True, slots=True)
class Clue:
    clue_id: str
    role: ClueRole
    attr_type: PIIAttributeType | None
    start: int
    end: int
    text: str
    priority: int
    source_kind: str
    unit_start: int = 0
    unit_end: int = 0
    component_type: AddressComponentType | None = None
    component_hint: NameComponentHint | None = None
    break_type: BreakType | None = None
    hard_source: str | None = None
    placeholder: str | None = None
    ocr_source_kind: str | None = None
    source_metadata: dict[str, list[str]] = field(default_factory=dict)

@dataclass(slots=True)
class ClueBundle:
    all_clues: tuple[Clue, ...]

    @property
    def label_clues(self) -> tuple[Clue, ...]:
        return tuple(clue for clue in self.all_clues if clue.role == ClueRole.LABEL)


@dataclass(frozen=True, slots=True)
class DictionaryEntry:
    attr_type: PIIAttributeType
    match_terms: tuple[str, ...]
    matched_by: str
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OCRSceneBlock:
    block: OCRTextBlock
    block_id: str
    order_index: int
    line_index: int
    raw_start: int
    raw_end: int
    clean_start: int
    clean_end: int
    clean_text: str


@dataclass(slots=True)
class OCRScene:
    blocks: tuple[OCRSceneBlock, ...]
    id_to_block: dict[str, OCRSceneBlock]
    line_to_blocks: dict[int, tuple[OCRSceneBlock, ...]]


@dataclass(slots=True)
class PreparedOCRContext:
    raw_text: str
    stream: StreamInput
    scene: OCRScene


@dataclass(slots=True)
class ParseResult:
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)
