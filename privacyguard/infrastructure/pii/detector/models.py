"""重写版 detector 的核心数据模型。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock


class ClaimStrength(str, Enum):
    HARD = "hard"
    SOFT = "soft"


class ClueFamily(str, Enum):
    """线索所属的 stack 家族，用于分发到对应 stack。"""
    NAME = "name"
    ORGANIZATION = "organization"
    ADDRESS = "address"
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
    SUBDISTRICT = "subdistrict"
    ROAD = "road"
    NUMBER = "number"
    HOUSE_NUMBER = "house_number"
    POI = "poi"
    BUILDING = "building"
    DETAIL = "detail"
    POSTAL_CODE = "postal_code"
    COUNTRY = "country"


class BreakType(str, Enum):
    OCR = "ocr"
    PUNCT = "punct"
    NEWLINE = "newline"


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
    unit_end: int = 0

    # —— 来源 ——
    source_kind: str = ""
    source_metadata: dict[str, list[str]] = field(default_factory=dict)

    # —— family 专属（可选） ——
    component_type: AddressComponentType | None = None
    break_type: BreakType | None = None


def _normalize_negative_unit_range(unit_count: int, unit_start: int, unit_end: int) -> tuple[int, int]:
    """裁剪 negative 查询区间，统一转成合法的半开区间。"""
    if unit_count <= 0:
        return (0, 0)
    start = max(0, min(unit_count, int(unit_start)))
    end = max(0, min(unit_count, int(unit_end)))
    if end <= start:
        return (start, start)
    return (start, end)


def build_negative_unit_index(
    unit_count: int,
    unit_spans: Sequence[tuple[int, int]],
) -> tuple[list[int], list[int], int]:
    """按 unit 区间构建 negative 覆盖索引与前缀和。"""
    safe_unit_count = max(0, int(unit_count))
    start_weight = safe_unit_count + 1
    marks = [0] * safe_unit_count
    for raw_start, raw_end in unit_spans:
        start, end = _normalize_negative_unit_range(safe_unit_count, raw_start, raw_end)
        if end <= start:
            continue
        marks[start] = max(marks[start], start_weight)
        for unit_index in range(start + 1, end):
            if marks[unit_index] < start_weight:
                marks[unit_index] = 1

    prefix_sum = [0]
    running = 0
    for mark in marks:
        running += mark
        prefix_sum.append(running)
    return marks, prefix_sum, start_weight


def negative_has_cover(prefix_sum: Sequence[int], unit_count: int, unit_start: int, unit_end: int) -> bool:
    """判断 unit 区间内是否存在任意 negative 覆盖。"""
    start, end = _normalize_negative_unit_range(unit_count, unit_start, unit_end)
    if end <= start or len(prefix_sum) <= end:
        return False
    return prefix_sum[end] - prefix_sum[start] > 0


def negative_has_start(
    prefix_sum: Sequence[int],
    unit_count: int,
    unit_start: int,
    unit_end: int,
) -> bool:
    """判断 unit 区间内是否存在 negative 起点。"""
    start, end = _normalize_negative_unit_range(unit_count, unit_start, unit_end)
    if end <= start or len(prefix_sum) <= end:
        return False
    return prefix_sum[end] - prefix_sum[start] > (end - start)


def negative_is_fully_covered(marks: Sequence[int], unit_start: int, unit_end: int) -> bool:
    """判断给定 unit 区间是否被 negative 完整覆盖。"""
    start, end = _normalize_negative_unit_range(len(marks), unit_start, unit_end)
    if end <= start:
        return False
    return all(mark > 0 for mark in marks[start:end])


def negative_next_start_unit(marks: Sequence[int], start_weight: int, unit_start: int) -> int | None:
    """返回给定 unit 起，首个 negative 起点所在的 unit 下标。"""
    start, end = _normalize_negative_unit_range(len(marks), unit_start, len(marks))
    if end <= start or start_weight <= 0:
        return None
    for unit_index in range(start, end):
        if marks[unit_index] >= start_weight:
            return unit_index
    return None


def negative_prev_covered_end_unit(marks: Sequence[int], before_unit: int) -> int | None:
    """返回左侧最近一个被 negative 覆盖 unit 的结束下标。"""
    unit_count = len(marks)
    if unit_count <= 0:
        return None
    end = max(0, min(unit_count, int(before_unit)))
    for unit_index in range(end - 1, -1, -1):
        if marks[unit_index] > 0:
            return unit_index + 1
    return None


@dataclass(slots=True)
class ClueBundle:
    all_clues: tuple[Clue, ...]
    negative_unit_marks: list[int] = field(default_factory=list)
    negative_prefix_sum: list[int] = field(default_factory=lambda: [0])
    negative_start_weight: int = 0

    @property
    def label_clues(self) -> tuple[Clue, ...]:
        return tuple(clue for clue in self.all_clues if clue.role == ClueRole.LABEL)

    def has_negative_cover(self, unit_start: int, unit_end: int) -> bool:
        """判断给定 unit 区间内是否存在任意 negative 覆盖。"""
        return negative_has_cover(
            self.negative_prefix_sum,
            len(self.negative_unit_marks),
            unit_start,
            unit_end,
        )

    def has_negative_start(self, unit_start: int, unit_end: int) -> bool:
        """判断给定 unit 区间内是否存在 negative 起点。"""
        return negative_has_start(
            self.negative_prefix_sum,
            len(self.negative_unit_marks),
            unit_start,
            unit_end,
        )


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
