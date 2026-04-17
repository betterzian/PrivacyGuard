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
class ClueIndex:
    """按 unit 轴的 clue 位置索引。构建 O(n)，查询 O(1)。

    - ``clues_starting_at[unit]``：该 unit 起始的所有 clue 下标。
    - ``family_starts[family][unit]``：该 family 在 unit 起始的 clue 下标。
    - ``blocker_prefix_sum[i]``：[0, i) 内被 BREAK/NEGATIVE 覆盖的 unit 计数。
    - ``cover_prefix_sum[i]``：[0, i) 内被任意 clue 覆盖的 unit 计数。
    """
    clues_starting_at: tuple[tuple[int, ...], ...]
    family_starts: dict[ClueFamily, tuple[tuple[int, ...], ...]]
    blocker_prefix_sum: tuple[int, ...]
    cover_prefix_sum: tuple[int, ...]
    unit_count: int


def build_clue_index(unit_count: int, clues: tuple[Clue, ...]) -> ClueIndex:
    """一次遍历构建 ClueIndex。"""
    safe_count = max(0, unit_count)
    all_starting: list[list[int]] = [[] for _ in range(safe_count)]
    family_buckets: dict[ClueFamily, list[list[int]]] = {
        f: [[] for _ in range(safe_count)] for f in ClueFamily
    }
    # 差分数组用于区间覆盖标记。
    blocker_diff = [0] * (safe_count + 1)
    cover_diff = [0] * (safe_count + 1)

    for idx, clue in enumerate(clues):
        us, ue = clue.unit_start, clue.unit_end
        if 0 <= us < safe_count:
            all_starting[us].append(idx)
            family_buckets[clue.family][us].append(idx)
        if us < ue:
            clamped_start = max(0, us)
            clamped_end = min(ue, safe_count)
            if clamped_start < clamped_end:
                cover_diff[clamped_start] += 1
                cover_diff[clamped_end] -= 1
                if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE}:
                    blocker_diff[clamped_start] += 1
                    blocker_diff[clamped_end] -= 1

    # 从差分构建前缀和：prefix_sum[i] = [0, i) 中被覆盖的 unit 数。
    blocker_prefix = [0]
    cover_prefix = [0]
    b_running = 0
    c_running = 0
    for i in range(safe_count):
        b_running += blocker_diff[i]
        c_running += cover_diff[i]
        blocker_prefix.append(blocker_prefix[-1] + (1 if b_running > 0 else 0))
        cover_prefix.append(cover_prefix[-1] + (1 if c_running > 0 else 0))

    return ClueIndex(
        clues_starting_at=tuple(tuple(b) for b in all_starting),
        family_starts={f: tuple(tuple(b) for b in buckets) for f, buckets in family_buckets.items()},
        blocker_prefix_sum=tuple(blocker_prefix),
        cover_prefix_sum=tuple(cover_prefix),
        unit_count=safe_count,
    )


_EMPTY_CLUE_INDEX = None


def _get_empty_clue_index() -> ClueIndex:
    """惰性创建空 ClueIndex 单例。"""
    global _EMPTY_CLUE_INDEX
    if _EMPTY_CLUE_INDEX is None:
        _EMPTY_CLUE_INDEX = build_clue_index(0, ())
    return _EMPTY_CLUE_INDEX


# ── InspireIndex：label 降级后的反向查询 ──


@dataclass(frozen=True, slots=True)
class InspireEntry:
    """被降级的 label clue 保留为 inspire 条目，供后续消歧使用。"""
    attr_type: PIIAttributeType
    unit_start: int
    unit_end: int
    text: str
    source_kind: str


@dataclass(slots=True)
class InspireIndex:
    """按 unit 轴的 inspire 条目索引。用于在 STRUCTURED 候选提交时提供上下文暗示。

    - ``_entries_at_unit[unit]``：起始于该 unit 的 InspireEntry 列表。
    - ``_type_units[attr_type]``：该类型的所有条目所覆盖的 unit 集合（用于快速范围查找）。
    """
    _entries_at_unit: tuple[tuple[InspireEntry, ...], ...]
    _type_units: dict[PIIAttributeType, frozenset[int]]
    unit_count: int

    def has_inspire_nearby(
        self,
        attr_type: PIIAttributeType,
        unit_start: int,
        unit_end: int,
        window: int = 15,
    ) -> bool:
        """判断 [unit_start - window, unit_end + window) 范围内是否有指定类型的 inspire 条目。"""
        covered = self._type_units.get(attr_type)
        if not covered:
            return False
        lo = max(0, unit_start - window)
        hi = min(self.unit_count, unit_end + window)
        for u in range(lo, hi):
            if u in covered:
                return True
        return False

    def inspire_entries_in_range(self, unit_start: int, unit_end: int) -> list[InspireEntry]:
        """返回 [unit_start, unit_end) 范围内起始的所有 inspire 条目。"""
        result: list[InspireEntry] = []
        lo = max(0, unit_start)
        hi = min(len(self._entries_at_unit), unit_end)
        for u in range(lo, hi):
            result.extend(self._entries_at_unit[u])
        return result


def build_inspire_index(unit_count: int, entries: Sequence[InspireEntry]) -> InspireIndex:
    """一次遍历构建 InspireIndex。"""
    safe_count = max(0, unit_count)
    buckets: list[list[InspireEntry]] = [[] for _ in range(safe_count)]
    type_unit_sets: dict[PIIAttributeType, set[int]] = {}

    for entry in entries:
        us = entry.unit_start
        if 0 <= us < safe_count:
            buckets[us].append(entry)
        # 记录该类型覆盖的所有 unit。
        covered_lo = max(0, entry.unit_start)
        covered_hi = min(safe_count, entry.unit_end)
        unit_set = type_unit_sets.setdefault(entry.attr_type, set())
        for u in range(covered_lo, covered_hi):
            unit_set.add(u)

    return InspireIndex(
        _entries_at_unit=tuple(tuple(b) for b in buckets),
        _type_units={k: frozenset(v) for k, v in type_unit_sets.items()},
        unit_count=safe_count,
    )


_EMPTY_INSPIRE_INDEX = None


def _get_empty_inspire_index() -> InspireIndex:
    """惰性创建空 InspireIndex 单例。"""
    global _EMPTY_INSPIRE_INDEX
    if _EMPTY_INSPIRE_INDEX is None:
        _EMPTY_INSPIRE_INDEX = build_inspire_index(0, ())
    return _EMPTY_INSPIRE_INDEX


@dataclass(slots=True)
class ClueBundle:
    all_clues: tuple[Clue, ...]
    negative_clues: tuple[Clue, ...] = ()
    negative_unit_marks: list[int] = field(default_factory=list)
    negative_prefix_sum: list[int] = field(default_factory=lambda: [0])
    negative_start_weight: int = 0
    clue_index: ClueIndex | None = None
    inspire_index: InspireIndex | None = None

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
