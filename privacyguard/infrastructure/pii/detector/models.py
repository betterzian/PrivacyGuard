"""重写版 detector 的核心数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock

NEGATIVE_SCOPES: tuple[str, ...] = (
    "name",
    "address",
    "organization",
    "ui",
    "generic",
)


class ClaimStrength(str, Enum):
    HARD = "hard"
    SOFT = "soft"
    WEAK = "weak"


_STRENGTH_ORDER: dict[ClaimStrength, int] = {
    ClaimStrength.WEAK: 0,
    ClaimStrength.SOFT: 1,
    ClaimStrength.HARD: 2,
}


def strength_ge(a: ClaimStrength, b: ClaimStrength) -> bool:
    """判断 strength a 是否 >= b。"""
    return _STRENGTH_ORDER[a] >= _STRENGTH_ORDER[b]


class ClueFamily(str, Enum):
    """线索所属的 stack 家族，用于分发到对应 stack。"""
    NAME = "name"
    ORGANIZATION = "organization"
    ADDRESS = "address"
    LICENSE_PLATE = "license_plate"
    STRUCTURED = "structured"
    CONTROL = "control"


class ClueRole(str, Enum):
    """线索的语义角色。各 family 可用的合法 role 由注册表约束。"""
    # 通用（所有 PII family 共享）
    LABEL = "label"
    VALUE = "value"
    START = "start"

    # NAME family
    FAMILY_NAME = "family_name"
    GIVEN_NAME = "given_name"
    FULL_NAME = "full_name"
    ALIAS = "alias"

    # ORGANIZATION family
    SUFFIX = "suffix"

    # ADDRESS family
    KEY = "key"

    # CONTROL（不触发任何 stack）
    BREAK = "break"
    NEGATIVE = "negative"


class AddressComponentType(str, Enum):
    """地址组件类型。"""
    PROVINCE = "province"
    CITY = "city"
    DISTRICT = "district"
    # 县级市（张家港等）。行政等级与 DISTRICT 同级（_ADMIN_RANK=2），
    # 与 DISTRICT 互斥占用同一槽位。
    DISTRICT_CITY = "district_city"
    SUBDISTRICT = "subdistrict"
    ROAD = "road"
    NUMBER = "number"
    HOUSE_NUMBER = "house_number"
    POI = "poi"
    BUILDING = "building"
    DETAIL = "detail"
    POSTAL_CODE = "postal_code"
    COUNTRY = "country"
    # MULTI_ADMIN 是 `_DraftComponent.level` 元组长度 >= 2 时的 derived 视图，
    # 表示同一 value 同时承担多个行政层级（例：北京 = PROVINCE + CITY）。
    # 真实占位写入 occupancy 时按 `level` 元组中的各层分别记录，
    # 不另设 MULTI_ADMIN 槽位。
    MULTI_ADMIN = "multi_admin"


class BreakType(str, Enum):
    OCR = "ocr"
    PUNCT = "punct"
    NEWLINE = "newline"
    DETERMINER = "determiner"


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
    order_index: int
    source_kind: str
    ocr_source_kind: str
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
    unit_last: int = -1
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
    # 标记候选的 attr_type 已由 H 档 validator 或 persona 精匹配锁定，
    # 下游不得再由 label 或启发式路径改写。
    attr_locked: bool = False


@dataclass(frozen=True, slots=True)
class Clue:
    # —— 核心标识 ——
    clue_id: str
    family: ClueFamily
    role: ClueRole
    attr_type: PIIAttributeType | None
    strength: ClaimStrength

    # —— 位置 ——
    start: int
    end: int
    text: str
    unit_start: int = 0
    unit_last: int = -1

    # —— 来源 ——
    source_kind: str = ""
    source_metadata: dict[str, list[str]] = field(default_factory=dict)

    # —— family 专属（可选） ——
    component_type: AddressComponentType | None = None
    component_levels: tuple[AddressComponentType, ...] = ()
    break_type: BreakType | None = None


@dataclass(frozen=True, slots=True)
class UnitBucket:
    """unit 轴上的唯一运行时索引。"""

    flag: str | None = None
    structured_clues: tuple[int, ...] = ()
    license_plate_clues: tuple[int, ...] = ()
    address_clues: tuple[int, ...] = ()
    name_clues: tuple[int, ...] = ()
    organization_clues: tuple[int, ...] = ()
    covering_clues: tuple[int, ...] = ()
    inspire_entries: tuple[int, ...] = ()
    can_start_parser: tuple[ClueFamily, ...] = ()
    break_start: bool = False
    negative_cover_scopes: tuple[str, ...] = ()
    negative_start_scopes: tuple[str, ...] = ()


def bucket_family_clues(bucket: UnitBucket, family: ClueFamily) -> tuple[int, ...]:
    """按 family 读取当前 unit 的起始 clue tuple。"""
    if family == ClueFamily.STRUCTURED:
        return bucket.structured_clues
    if family == ClueFamily.LICENSE_PLATE:
        return bucket.license_plate_clues
    if family == ClueFamily.ADDRESS:
        return bucket.address_clues
    if family == ClueFamily.NAME:
        return bucket.name_clues
    if family == ClueFamily.ORGANIZATION:
        return bucket.organization_clues
    return ()


def empty_unit_index(unit_count: int) -> tuple[UnitBucket, ...]:
    """构造固定长度的空 unit 索引。"""
    safe_count = max(0, int(unit_count))
    return tuple(UnitBucket() for _ in range(safe_count))


@dataclass(slots=True)
class ClueBundle:
    all_clues: tuple[Clue, ...]
    unit_index: tuple[UnitBucket, ...] = ()
    negative_clues: tuple[Clue, ...] = ()
    inspire_entries: tuple["InspireEntry", ...] = ()

    @property
    def label_clues(self) -> tuple[Clue, ...]:
        return tuple(clue for clue in self.all_clues if clue.role == ClueRole.LABEL)


@dataclass(frozen=True, slots=True)
class DictionaryEntry:
    attr_type: PIIAttributeType
    match_terms: tuple[str, ...]
    matched_by: str
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class StructuredLookupIndex:
    numeric_entries: dict[str, DictionaryEntry] = field(default_factory=dict)
    alnum_entries: dict[str, DictionaryEntry] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StructuredAnchor:
    """parser 流式维护的最近结构化 LABEL/START 锚点。"""

    attr_type: PIIAttributeType
    role: ClueRole
    unit_last: int
    clue_index: int
    clue_id: str


@dataclass(frozen=True, slots=True)
class InspireEntry:
    """非 STRUCTURED label 降级后的近距离增强锚点。"""

    attr_type: PIIAttributeType
    family: ClueFamily
    start: int
    end: int
    unit_start: int
    unit_last: int
    clue_id: str


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

