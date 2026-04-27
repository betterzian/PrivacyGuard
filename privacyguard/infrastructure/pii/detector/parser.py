"""按 stack 注册表路由的单主栈 parser。

冲突裁决策略：
- 只要冲突涉及 NAME，统一按 claim_strength 裁决；同级保留 NAME。
- NAME 胜出时仅提交 NAME，本轮只按成功路径的真实 frontier 推进。
- NAME 未赢时，先尝试把 NAME 裁掉冲突区；裁后仍满足姓名提交条件则与赢家一并提交，否则仅提交赢家。
- parser 维护全局 commit_frontier_last_unit；它只负责后续 parser 起栈快进。
- 语义 value 锁拆成全局锁和按 family 的局部锁，只限制候选取值边界，不阻止 parser 继续尝试。
- 不涉及 NAME 时，沿用现有 hard/soft + soft_priority + fallback 机制。
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    Claim,
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ClueRole,
    InspireEntry,
    ParseResult,
    StructuredAnchor,
    StructuredLookupIndex,
    StreamInput,
    UnitBucket,
    bucket_family_clues,
)
from privacyguard.infrastructure.pii.detector.stacks import BaseStack, StackManager, StackRun, get_stack_spec
from privacyguard.infrastructure.pii.detector.stacks.structured import ALLOWED_DETECTOR_OUTPUT_ATTRS
from privacyguard.utils.normalized_pii import normalize_pii, normalized_primary_text, same_entity

# persona / 本地词典精匹配出口的 source_kind 白名单，豁免 detector 主路径的 attr_type 断言。
_PERSONA_SOURCE_KINDS = frozenset({
    "dictionary_session",
    "persona",
})
_SEMANTIC_VALUE_LOCK_FAMILIES = (
    ClueFamily.NAME,
    ClueFamily.ORGANIZATION,
    ClueFamily.ADDRESS,
)

_CandidateIdentityKey = tuple[PIIAttributeType, int, int, int, int, str]
_FrozenMetadataItems = tuple[tuple[str, tuple[str, ...]], ...]
_AddressNormalizedCacheSignature = tuple[str, _FrozenMetadataItems]


def _is_control_clue(clue: Clue) -> bool:
    """控制 clue 不建 stack，只供 stack 扩张时观察。"""
    return clue.family == ClueFamily.CONTROL


def _candidates_overlap(a: CandidateDraft, b: CandidateDraft) -> bool:
    return a.unit_start <= b.unit_last and b.unit_start <= a.unit_last


def _unit_span_strictly_contains(outer_start: int, outer_last: int, inner_start: int, inner_last: int) -> bool:
    """判断闭区间 unit span 是否严格包含。"""
    if outer_last < outer_start or inner_last < inner_start:
        return False
    if outer_start > inner_start or inner_last > outer_last:
        return False
    return outer_start < inner_start or inner_last < outer_last


def _strict_unit_container_winner_key(a: CandidateDraft, b: CandidateDraft) -> str | None:
    """若一方在 unit 区间上严格包含另一方，返回 ``\"a\"`` / ``\"b\"``；同区间或仅部分重叠返回 ``None``。"""
    if _unit_span_strictly_contains(a.unit_start, a.unit_last, b.unit_start, b.unit_last):
        return "a"
    if _unit_span_strictly_contains(b.unit_start, b.unit_last, a.unit_start, a.unit_last):
        return "b"
    return None


def _claim_strength_rank(strength: ClaimStrength) -> int:
    return {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }[strength]


def _upgrade_claim_strength_by_levels(strength: ClaimStrength, levels: int) -> ClaimStrength:
    """把 claim_strength 提升指定层级，最高封顶到 HARD。"""
    upgraded = strength
    for _ in range(max(0, levels)):
        if upgraded == ClaimStrength.WEAK:
            upgraded = ClaimStrength.SOFT
            continue
        upgraded = ClaimStrength.HARD
        break
    return upgraded


_ADDRESS_STRUCTURAL_METADATA_KEYS = frozenset({
    "address_component_trace",
    "address_component_key_trace",
    "address_component_levels",
    "address_component_suspected",
    "address_component_type",
    "address_component_level",
})
_ADDRESS_STRUCTURAL_SEQUENCE_KEYS = frozenset({
    "address_component_trace",
    "address_component_key_trace",
    "address_component_levels",
    "address_component_suspected",
    "address_component_type",
    "address_component_level",
    "address_details_type",
    "address_details_text",
})


def _metadata_values(value: object) -> list[str]:
    """统一把 metadata 值转成稳定字符串列表。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        values = [str(item) for item in value if str(item)]
        return values
    text = str(value)
    return [text] if text else []


def _copy_metadata(metadata: Mapping[str, object]) -> dict[str, list[str]]:
    """复制 metadata，避免在候选吸收时共享可变列表。"""
    copied: dict[str, list[str]] = {}
    for key, value in metadata.items():
        copied[key] = list(_metadata_values(value))
    return copied


def _freeze_metadata_items(metadata: Mapping[str, object]) -> _FrozenMetadataItems:
    """将 metadata 冻结为稳定键，便于本轮 parse 内复用结果。"""
    return tuple(
        (key, tuple(_metadata_values(metadata[key])))
        for key in sorted(metadata)
    )


def _candidate_identity_key(candidate: CandidateDraft) -> _CandidateIdentityKey:
    """构造候选查重键。"""
    return (
        candidate.attr_type,
        candidate.unit_start,
        candidate.unit_last,
        candidate.start,
        candidate.end,
        candidate.text,
    )


def _address_normalized_cache_signature(candidate: CandidateDraft) -> _AddressNormalizedCacheSignature:
    """构造地址归一化缓存签名。"""
    return (candidate.text, _freeze_metadata_items(candidate.metadata))


def _merge_address_absorb_metadata(
    longer_metadata: Mapping[str, object],
    shorter_metadata: Mapping[str, object],
) -> dict[str, list[str]]:
    """地址子集吸收时保留长地址结构字段，只并入短地址的非结构信息。"""
    merged = _copy_metadata(longer_metadata)
    for key, value in shorter_metadata.items():
        if key in _ADDRESS_STRUCTURAL_METADATA_KEYS:
            continue
        values = _metadata_values(value)
        if not values:
            continue
        bucket = merged.setdefault(key, [])
        for item in values:
            if item not in bucket:
                bucket.append(item)
    return merged


def _merge_address_fragment_metadata(
    fuller_metadata: Mapping[str, object],
    fragment_metadata: Mapping[str, object],
    *,
    prepend_fragment: bool,
) -> dict[str, list[str]]:
    """吸收英文地址碎片时，同时保留组件级结构字段。"""
    merged = _copy_metadata(fuller_metadata)
    fragment_copied = _copy_metadata(fragment_metadata)
    for key in _ADDRESS_STRUCTURAL_SEQUENCE_KEYS:
        fuller_values = merged.get(key, [])
        fragment_values = fragment_copied.get(key, [])
        if prepend_fragment:
            merged[key] = [*fragment_values, *fuller_values]
        else:
            merged[key] = [*fuller_values, *fragment_values]
    for key, value in fragment_metadata.items():
        if key in _ADDRESS_STRUCTURAL_SEQUENCE_KEYS:
            continue
        values = _metadata_values(value)
        if not values:
            continue
        bucket = merged.setdefault(key, [])
        for item in values:
            if item not in bucket:
                bucket.append(item)
    return merged


def _is_punct_or_space_only(text: str) -> bool:
    """相邻候选之间只允许空白或 Unicode 标点。"""
    for char in text:
        if char.isspace():
            continue
        if unicodedata.category(char).startswith("P"):
            continue
        return False
    return True


def _address_components_subset(shorter_primary: Mapping[str, object], longer_primary: Mapping[str, object]) -> bool:
    """同地址前缀吸收时，短地址已有组件必须都能在长地址对应组件中命中。"""
    comparable = {
        key: str(value or "").strip()
        for key, value in shorter_primary.items()
        if key != "poi_key" and str(value or "").strip()
    }
    if not comparable:
        return False
    for key, shorter_value in comparable.items():
        longer_value = str(longer_primary.get(key) or "").strip()
        if not longer_value or shorter_value not in longer_value:
            return False
    return True


def _address_component_keys(normalized: object) -> set[str]:
    components = getattr(normalized, "components", {})
    if not isinstance(components, Mapping):
        return set()
    return {
        str(key)
        for key, value in components.items()
        if key != "poi_key" and str(value or "").strip()
    }


def _is_prefix_fragment_address(normalized: object) -> bool:
    keys = _address_component_keys(normalized)
    return bool(keys) and keys <= {"poi", "building", "unit", "room", "suite", "detail"}


def _is_leading_road_fragment_address(normalized: object) -> bool:
    """英文地址前段若只含门牌号/路名，可并回后续 building/admin 组件。"""
    keys = _address_component_keys(normalized)
    return bool(keys) and keys <= {"road", "number"}


def _is_tail_fragment_address(normalized: object) -> bool:
    keys = _address_component_keys(normalized)
    return bool(keys) and keys <= {"multi_admin", "city", "province", "postal_code", "country"}


def _is_trailing_detail_admin_fragment_address(normalized: object) -> bool:
    """英文地址尾段可只剩 detail/admin。"""
    keys = _address_component_keys(normalized)
    return bool(keys) and keys <= {
        "building",
        "unit",
        "room",
        "suite",
        "detail",
        "multi_admin",
        "city",
        "province",
        "postal_code",
        "country",
    }


def _has_main_address_shape(normalized: object) -> bool:
    keys = _address_component_keys(normalized)
    return bool(keys & {"road", "number", "multi_admin", "city", "province", "postal_code", "country", "poi"})


def _has_trailing_address_context(normalized: object) -> bool:
    """后段需至少带有 building/detail/admin/poi，避免把两个独立门牌段硬并。"""
    keys = _address_component_keys(normalized)
    return bool(keys & {
        "building",
        "unit",
        "room",
        "suite",
        "detail",
        "multi_admin",
        "city",
        "province",
        "postal_code",
        "country",
        "poi",
    })


def _looks_like_english_address_text(text: str) -> bool:
    return any(("A" <= char <= "Z") or ("a" <= char <= "z") for char in str(text or ""))


@dataclass(slots=True)
class StackContext:
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel = ProtectionLevel.STRONG
    clues: tuple[Clue, ...] = ()
    unit_index: tuple[UnitBucket, ...] = ()
    negative_clues: tuple[Clue, ...] = ()
    inspire_entries: tuple[InspireEntry, ...] = ()
    structured_lookup_index: StructuredLookupIndex = field(default_factory=StructuredLookupIndex)
    commit_frontier_last_unit: int = -1
    all_candidate_value_cannot_get_this_unit: int = -1
    stack_value_cannot_get_this_unit: dict[ClueFamily, int] = field(
        default_factory=lambda: {family: -1 for family in _SEMANTIC_VALUE_LOCK_FAMILIES}
    )
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)
    candidate_identity_index: dict[_CandidateIdentityKey, CandidateDraft] = field(default_factory=dict)
    address_normalized_cache: dict[int, tuple[_AddressNormalizedCacheSignature, object]] = field(default_factory=dict)
    recent_structured_anchor: StructuredAnchor | None = None
    recent_inspire_anchor: InspireEntry | None = None
    inspire_boosted_clue_ids: set[str] = field(default_factory=set)

    def _bucket_matches_negative_scopes(
        self,
        bucket_scopes: Sequence[str],
        scopes: Sequence[str] | None,
    ) -> bool:
        """判断 bucket 上记录的 negative scope 是否命中查询集合。"""
        if not bucket_scopes:
            return False
        if scopes is None:
            return True
        scope_set = {str(scope) for scope in scopes if str(scope)}
        if not scope_set:
            return False
        return any(scope in scope_set for scope in bucket_scopes)

    def has_negative_cover(
        self,
        unit_start: int,
        unit_last: int,
        scopes: Sequence[str] | None = None,
    ) -> bool:
        """判断给定 unit 区间是否存在指定 scope 的 negative 覆盖。"""
        if not self.unit_index or unit_last < unit_start:
            return False
        start = max(0, unit_start)
        end = min(unit_last, len(self.unit_index) - 1)
        return any(
            self._bucket_matches_negative_scopes(self.unit_index[ui].negative_cover_scopes, scopes)
            for ui in range(start, end + 1)
        )

    def has_negative_start(
        self,
        unit_start: int,
        unit_last: int,
        scopes: Sequence[str] | None = None,
    ) -> bool:
        """判断给定 unit 区间是否存在指定 scope 的 negative 起点。"""
        if not self.unit_index or unit_last < unit_start:
            return False
        start = max(0, unit_start)
        end = min(unit_last, len(self.unit_index) - 1)
        return any(
            self._bucket_matches_negative_scopes(self.unit_index[ui].negative_start_scopes, scopes)
            for ui in range(start, end + 1)
        )

    def is_negative_fully_covered(
        self,
        unit_start: int,
        unit_last: int,
        scopes: Sequence[str] | None = None,
    ) -> bool:
        """判断给定 unit 区间是否被指定 scope 的 negative 完整覆盖。"""
        if not self.unit_index or unit_last < unit_start:
            return False
        start = max(0, unit_start)
        end = min(unit_last, len(self.unit_index) - 1)
        return all(
            self._bucket_matches_negative_scopes(self.unit_index[ui].negative_cover_scopes, scopes)
            for ui in range(start, end + 1)
        )

    def next_negative_start_char(
        self,
        char_index: int,
        scopes: Sequence[str] | None = None,
    ) -> int | None:
        """返回当前位置右侧最近的指定 scope negative 起点 char。"""
        unit_index = self._unit_index_at_or_after(char_index)
        for ui in range(unit_index, len(self.unit_index)):
            if self._bucket_matches_negative_scopes(self.unit_index[ui].negative_start_scopes, scopes):
                return self.stream.units[ui].char_start
        return None

    def previous_negative_end_char(
        self,
        char_index: int,
        scopes: Sequence[str] | None = None,
    ) -> int | None:
        """返回左侧最近一个指定 scope negative 覆盖 unit 的结束位置。"""
        before_unit = self._unit_index_at_or_after(char_index)
        for ui in range(min(before_unit - 1, len(self.unit_index) - 1), -1, -1):
            if self._bucket_matches_negative_scopes(self.unit_index[ui].negative_cover_scopes, scopes):
                return self.stream.units[ui].char_end
        return None

    def has_negative_cover_left_of_char(
        self,
        char_index: int,
        scopes: Sequence[str] | None = None,
    ) -> bool:
        """判断 cursor 左侧紧邻位置是否处于指定 scope 的 negative 覆盖内部。"""
        if char_index <= 0 or not self.stream.char_to_unit or not self.unit_index:
            return False
        left_char = min(char_index - 1, len(self.stream.char_to_unit) - 1)
        unit_index = self.stream.char_to_unit[left_char]
        if unit_index < 0 or unit_index >= len(self.unit_index):
            return False
        return self._bucket_matches_negative_scopes(self.unit_index[unit_index].negative_cover_scopes, scopes)

    def _unit_index_at_or_after(self, char_index: int) -> int:
        if not self.stream.char_to_unit or char_index >= len(self.stream.char_to_unit):
            return len(self.stream.units)
        unit_index = self.stream.char_to_unit[max(0, char_index)]
        while unit_index < len(self.stream.units) and self.stream.units[unit_index].char_end <= char_index:
            unit_index += 1
        return unit_index

    def raise_all_value_floor(self, unit_last: int) -> None:
        """推进全局 value 锁，并同步抬升三个语义 family 的局部锁。"""
        if unit_last < 0:
            return
        self.all_candidate_value_cannot_get_this_unit = max(
            self.all_candidate_value_cannot_get_this_unit,
            unit_last,
        )
        for family in _SEMANTIC_VALUE_LOCK_FAMILIES:
            self.raise_stack_value_floor(family, self.all_candidate_value_cannot_get_this_unit)

    def raise_stack_value_floor(self, family: ClueFamily, unit_last: int) -> None:
        """推进指定语义 family 的局部 value 锁。"""
        if family not in self.stack_value_cannot_get_this_unit or unit_last < 0:
            return
        self.stack_value_cannot_get_this_unit[family] = max(
            self.stack_value_cannot_get_this_unit[family],
            unit_last,
        )

    def effective_value_floor_unit(self, family: ClueFamily) -> int:
        """返回语义 family 当前生效的 unit 级 value 锁。"""
        return max(
            self.all_candidate_value_cannot_get_this_unit,
            self.stack_value_cannot_get_this_unit.get(family, -1),
        )

    def effective_value_floor_char(self, family: ClueFamily) -> int:
        """把 unit 级 value 锁换算成 char 起点下界。"""
        locked_unit = self.effective_value_floor_unit(family)
        if locked_unit < 0 or locked_unit >= len(self.stream.units):
            return 0
        return self.stream.units[locked_unit].char_end

    def blocks_unit_start(self, unit_start: int) -> bool:
        """判断给定候选起点是否越过 parser 的全局起栈锁。"""
        return self.commit_frontier_last_unit >= 0 and unit_start <= self.commit_frontier_last_unit


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    """一次 parser 分支裁决后的推进结果。"""

    committed: bool
    next_unit_cursor: int = -1

    @classmethod
    def no_commit(cls) -> "ResolutionResult":
        return cls(committed=False, next_unit_cursor=-1)


@dataclass(frozen=True, slots=True)
class _MaterializedRun:
    """同一 start group 中已成功起栈的候选。"""

    clue_index: int
    run: StackRun
    stack: BaseStack | None


class StreamParser:
    def __init__(self, *, locale_profile: str, ctx: DetectContext) -> None:
        self.locale_profile = locale_profile
        self.ctx = ctx
        self.stack_manager = StackManager()

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------

    def parse(
        self,
        stream: StreamInput,
        bundle: ClueBundle,
        *,
        structured_lookup_index: StructuredLookupIndex | None = None,
    ) -> ParseResult:
        context = StackContext(
            stream=stream,
            locale_profile=self.locale_profile,
            protection_level=self.ctx.protection_level,
            clues=bundle.all_clues,
            unit_index=bundle.unit_index,
            negative_clues=bundle.negative_clues,
            inspire_entries=bundle.inspire_entries,
            structured_lookup_index=structured_lookup_index or StructuredLookupIndex(),
        )
        unit_cursor = 0
        start_group_cursor = 0
        while unit_cursor < len(context.unit_index):
            if context.blocks_unit_start(unit_cursor):
                context.recent_inspire_anchor = None
                unit_cursor = context.commit_frontier_last_unit + 1
                start_group_cursor = 0
                continue
            self._advance_semantic_value_locks_at_unit(context, unit_cursor)
            self._advance_inspire_anchor_at_unit(context, unit_cursor)
            self._remember_structured_anchors_at_unit(context, unit_cursor)
            start_groups = self._start_groups_at_unit(context, unit_cursor)
            if not start_groups:
                unit_cursor += 1
                start_group_cursor = 0
                continue
            if start_group_cursor >= len(start_groups):
                unit_cursor += 1
                start_group_cursor = 0
                continue
            current_start, current_group = start_groups[start_group_cursor]
            selected = self._select_start_group_run(context, current_group)
            if selected is None:
                start_group_cursor += 1
                continue
            current_run, current_stack = selected

            if current_run.pending_challenge is not None:
                if current_run.pending_challenge.challenge_kind == "name_address_conflict":
                    resolution = self._resolve_name_address_pending_challenge(
                        context,
                        current_run,
                        current_stack,
                    )
                    if resolution is not None:
                        if resolution.committed:
                            context.recent_inspire_anchor = None
                            unit_cursor = resolution.next_unit_cursor
                            start_group_cursor = 0
                        else:
                            start_group_cursor += 1
                        continue
                if current_run.pending_challenge is not None:
                    current_run = self._resolve_pending_challenge(context, current_run)
                    if context.blocks_unit_start(current_run.candidate.unit_start):
                        start_group_cursor += 1
                        continue

            challenger_run, challenger_stack = self._find_challenger(
                context,
                current_run,
                unit_cursor,
                current_start,
            )
            if challenger_run is None or not _candidates_overlap(current_run.candidate, challenger_run.candidate):
                resolution = self._commit_runs(context, current_run)
                if resolution.committed:
                    context.recent_inspire_anchor = None
                unit_cursor = resolution.next_unit_cursor if resolution.committed else unit_cursor
                start_group_cursor = 0 if resolution.committed else start_group_cursor + 1
                continue

            resolution = self._resolve_with_priority(
                context,
                current_run,
                current_stack,
                challenger_run,
                challenger_stack,
            )
            if resolution.committed:
                context.recent_inspire_anchor = None
                unit_cursor = resolution.next_unit_cursor
                start_group_cursor = 0
            else:
                start_group_cursor += 1

        return ParseResult(
            candidates=context.candidates,
            claims=context.claims,
            handled_label_clue_ids=context.handled_label_clue_ids,
        )

    # ------------------------------------------------------------------
    # 冲突裁决：优先级 + shrink
    # ------------------------------------------------------------------

    def _resolve_with_priority(
        self,
        context: StackContext,
        run_a: StackRun, stack_a: BaseStack | None,
        run_b: StackRun, stack_b: BaseStack | None,
    ) -> ResolutionResult:
        """按类型优先级裁决两个重叠的 StackRun。

        0. unit 区间严格包含：包含方胜出（不比较 claim_strength），败方丢弃。
        1. 比较 hard / soft：hard 一方直接胜出，soft 一方 shrink。
        2. 同为 soft：按 ATTR_TYPE_PRIORITY 裁决。
        3. 优先级相同或同类型：fallback 到 score 比分。
        4. 败方尝试 shrink，成功则双方都 commit。
        """
        ca, cb = run_a.candidate, run_b.candidate
        if PIIAttributeType.LICENSE_PLATE in {ca.attr_type, cb.attr_type}:
            return self._resolve_license_plate_conflict(context, run_a, run_b)
        win_key = _strict_unit_container_winner_key(ca, cb)
        if win_key == "a":
            return self._commit_winner_and_drop_loser(context, run_a, run_b)
        if win_key == "b":
            return self._commit_winner_and_drop_loser(context, run_b, run_a)
        if ca.attr_type == cb.attr_type:
            return self._resolve_same_attr_conflict(context, run_a, run_b)
        if PIIAttributeType.NAME in {ca.attr_type, cb.attr_type}:
            return self._resolve_name_conflict(
                context,
                run_a,
                stack_a,
                run_b,
                stack_b,
            )

        hard_a = ca.claim_strength == ClaimStrength.HARD
        hard_b = cb.claim_strength == ClaimStrength.HARD

        if hard_a and not hard_b:
            return self._commit_winner_and_shrink_loser(context, run_a, None, run_b, stack_b)
        if hard_b and not hard_a:
            return self._commit_winner_and_shrink_loser(context, run_b, None, run_a, stack_a)

        if hard_a and hard_b:
            hard_address_numeric = frozenset({ca.attr_type, cb.attr_type}) == {
                PIIAttributeType.ADDRESS,
                PIIAttributeType.NUM,
            }
            if hard_address_numeric:
                if ca.attr_type == PIIAttributeType.ADDRESS:
                    return self._commit_winner_and_drop_loser(context, run_a, run_b)
                return self._commit_winner_and_drop_loser(context, run_b, run_a)

        if hard_a and hard_b:
            return self._fallback_conflict(context, run_a, run_b)

        prio_a = self._soft_priority(ca.attr_type)
        prio_b = self._soft_priority(cb.attr_type)

        if prio_a > prio_b:
            return self._commit_winner_and_shrink_loser(context, run_a, stack_a, run_b, stack_b)
        if prio_b > prio_a:
            return self._commit_winner_and_shrink_loser(context, run_b, stack_b, run_a, stack_a)

        return self._fallback_conflict(context, run_a, run_b)

    def _resolve_name_conflict(
        self,
        context: StackContext,
        run_a: StackRun,
        stack_a: BaseStack | None,
        run_b: StackRun,
        stack_b: BaseStack | None,
    ) -> ResolutionResult:
        """统一处理 NAME 相关冲突。NAME 失败时可尝试裁剪保留未冲突片段。"""
        ca, cb = run_a.candidate, run_b.candidate
        rank_a = _claim_strength_rank(ca.claim_strength)
        rank_b = _claim_strength_rank(cb.claim_strength)

        if rank_a > rank_b:
            winner_run, loser_run = run_a, run_b
        elif rank_b > rank_a:
            winner_run, loser_run = run_b, run_a
        elif ca.attr_type == PIIAttributeType.NAME and cb.attr_type != PIIAttributeType.NAME:
            winner_run, loser_run = run_a, run_b
        elif cb.attr_type == PIIAttributeType.NAME and ca.attr_type != PIIAttributeType.NAME:
            winner_run, loser_run = run_b, run_a
        elif (ca.unit_last - ca.unit_start) >= (cb.unit_last - cb.unit_start):
            winner_run, loser_run = run_a, run_b
        else:
            winner_run, loser_run = run_b, run_a

        if winner_run.candidate.attr_type == PIIAttributeType.NAME:
            return self._commit_name_winner_and_keep_loser(context, winner_run)
        loser_stack = stack_a if loser_run is run_a else stack_b
        return self._commit_winner_and_shrink_loser(
            context,
            winner_run,
            None,
            loser_run,
            loser_stack,
        )

    def _resolve_license_plate_conflict(
        self,
        context: StackContext,
        run_a: StackRun,
        run_b: StackRun,
    ) -> ResolutionResult:
        """LICENSE_PLATE 与其他类型冲突时始终保留 LICENSE_PLATE。"""
        ca, cb = run_a.candidate, run_b.candidate
        if ca.attr_type == cb.attr_type == PIIAttributeType.LICENSE_PLATE:
            return self._resolve_same_attr_conflict(context, run_a, run_b)
        if ca.attr_type == PIIAttributeType.LICENSE_PLATE:
            return self._commit_winner_and_drop_loser(context, run_a, run_b)
        return self._commit_winner_and_drop_loser(context, run_b, run_a)

    def _resolve_same_attr_conflict(
        self,
        context: StackContext,
        run_a: StackRun,
        run_b: StackRun,
    ) -> ResolutionResult:
        """同属性冲突不再走打分，统一按强度/跨度裁决。"""
        ca, cb = run_a.candidate, run_b.candidate
        rank_a = _claim_strength_rank(ca.claim_strength)
        rank_b = _claim_strength_rank(cb.claim_strength)
        if rank_a > rank_b:
            return self._commit_runs(context, run_a)
        if rank_b > rank_a:
            return self._commit_runs(context, run_b)
        if (
            ca.start == cb.start
            and ca.end == cb.end
            and ca.unit_start == cb.unit_start
            and ca.unit_last == cb.unit_last
        ):
            return self._commit_runs(context, run_a, run_b)
        len_a = ca.unit_last - ca.unit_start + 1
        len_b = cb.unit_last - cb.unit_start + 1
        if len_a > len_b:
            return self._commit_runs(context, run_a)
        if len_b > len_a:
            return self._commit_runs(context, run_b)
        return self._commit_runs(context, run_b)

    def _commit_winner_and_shrink_loser(
        self,
        context: StackContext,
        winner_run: StackRun,
        winner_stack: BaseStack | None,
        loser_run: StackRun,
        loser_stack: BaseStack | None,
    ) -> ResolutionResult:
        """提交胜方，再尝试保留败方裁掉冲突区后的残片。"""
        if loser_stack is None:
            self._commit_run(context, winner_run)
            context.handled_label_clue_ids |= loser_run.handled_label_clue_ids
            return self._result_from_runs(winner_run)

        wc = winner_run.candidate
        shrunk = loser_stack.shrink(loser_run, wc.unit_start, wc.unit_last)
        if shrunk is not None:
            sc = shrunk.candidate
            if sc.unit_last < wc.unit_start:
                self._commit_run(context, shrunk)
                self._commit_run(context, winner_run)
            else:
                self._commit_run(context, winner_run)
                self._commit_run(context, shrunk)
            return self._result_from_runs(winner_run, shrunk)
        self._commit_run(context, winner_run)
        context.handled_label_clue_ids |= loser_run.handled_label_clue_ids
        return self._result_from_runs(winner_run)

    def _commit_winner_and_drop_loser(
        self,
        context: StackContext,
        winner_run: StackRun,
        loser_run: StackRun,
    ) -> ResolutionResult:
        """仅提交胜方；败方不再通过 consumed 机制被锁死。"""
        self._commit_run(context, winner_run)
        context.handled_label_clue_ids |= loser_run.handled_label_clue_ids
        return self._result_from_runs(winner_run)

    def _commit_name_winner_and_keep_loser(
        self,
        context: StackContext,
        winner_run: StackRun,
    ) -> ResolutionResult:
        """NAME 胜出时只提交 NAME，本轮只按 NAME 自身 frontier 推进。"""
        self._commit_run(context, winner_run)
        return self._result_from_runs(winner_run)

    def _fallback_conflict(
        self,
        context: StackContext,
        run_a: StackRun,
        run_b: StackRun,
    ) -> ResolutionResult:
        """仅保留跨属性 fallback：按既有业务规则提交 surviving candidate。"""
        outcome = self.stack_manager.resolve_conflict(context, run_a.candidate, run_b.candidate)
        committed_runs: list[StackRun] = []
        if not outcome.drop_existing:
            if outcome.replace_existing is not None:
                self._commit_candidate(context, outcome.replace_existing)
                committed_runs.append(run_a)
            else:
                self._commit_candidate(context, run_a.candidate)
                committed_runs.append(run_a)
        if outcome.incoming is not None:
            self._commit_candidate(context, outcome.incoming)
            committed_runs.append(run_b)
        context.handled_label_clue_ids |= run_a.handled_label_clue_ids
        context.handled_label_clue_ids |= run_b.handled_label_clue_ids
        return self._result_from_runs(*committed_runs)

    # ------------------------------------------------------------------
    # Stack 运行
    # ------------------------------------------------------------------

    def _try_run_stack(
        self,
        context: StackContext,
        index: int,
    ) -> tuple[StackRun | None, BaseStack | None]:
        """按 clue index 尝试启动 stack。"""
        clue = context.clues[index]
        spec = get_stack_spec(clue.family)
        if spec is None or clue.role not in spec.start_roles:
            return None, None
        stack = spec.stack_cls(clue=clue, clue_index=index, context=context)
        run = stack.run()
        if run is None or not run.candidate.text.strip():
            return None, None
        if context.blocks_unit_start(run.candidate.unit_start):
            return None, None
        if run.frontier_last_unit < run.candidate.unit_last:
            run.frontier_last_unit = run.candidate.unit_last
        return run, stack

    def _try_run_stack_at_unit(
        self,
        context: StackContext,
        unit_index: int,
        family: ClueFamily,
        *,
        suppress_start_clue_ids: frozenset[str] = frozenset(),
    ) -> tuple[StackRun | None, BaseStack | None]:
        """在指定 unit / family 下，按 tuple 顺序尝试可起栈 clue。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return None, None
        for clue_index in bucket_family_clues(context.unit_index[unit_index], family):
            if context.clues[clue_index].clue_id in suppress_start_clue_ids:
                continue
            self._apply_inspire_boost_to_clue(context, clue_index)
            run, stack = self._try_run_stack(context, clue_index)
            if run is not None:
                return run, stack
        return None, None

    def _start_groups_at_unit(
        self,
        context: StackContext,
        unit_index: int,
        *,
        suppress_start_clue_ids: frozenset[str] = frozenset(),
    ) -> list[tuple[int, tuple[int, ...]]]:
        """按 clue.start 对当前 unit 的可起栈 clue 分组。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return []
        bucket = context.unit_index[unit_index]
        startable_indices: list[int] = []
        for family in bucket.can_start_parser:
            spec = get_stack_spec(family)
            if spec is None:
                continue
            for clue_index in bucket_family_clues(bucket, family):
                clue = context.clues[clue_index]
                if clue.clue_id in suppress_start_clue_ids:
                    continue
                if clue.role not in spec.start_roles:
                    continue
                startable_indices.append(clue_index)
        startable_indices.sort(key=lambda clue_index: context.clues[clue_index].start)

        groups: list[tuple[int, tuple[int, ...]]] = []
        current_start: int | None = None
        current_group: list[int] = []
        for clue_index in startable_indices:
            clue_start = context.clues[clue_index].start
            if current_start is None or clue_start != current_start:
                if current_group:
                    groups.append((current_start, tuple(current_group)))
                current_start = clue_start
                current_group = [clue_index]
                continue
            current_group.append(clue_index)
        if current_group and current_start is not None:
            groups.append((current_start, tuple(current_group)))
        return groups

    def _same_start_priority_key(self, candidate: CandidateDraft) -> tuple[int, int, int, int, int]:
        """为同起点候选提供稳定优先级键。"""
        return (
            _claim_strength_rank(candidate.claim_strength),
            1 if candidate.attr_type == PIIAttributeType.NAME else 0,
            self._soft_priority(candidate.attr_type),
            candidate.unit_last - candidate.unit_start + 1,
            candidate.end - candidate.start,
        )

    def _merge_equivalent_materialized_runs(
        self,
        current: _MaterializedRun,
        challenger: _MaterializedRun,
    ) -> _MaterializedRun:
        """同属性同跨度的等价 run 合并 handled clue，避免同组内重复丢失。"""
        merged_run = StackRun(
            attr_type=current.run.attr_type,
            candidate=current.run.candidate,
            handled_label_clue_ids=current.run.handled_label_clue_ids | challenger.run.handled_label_clue_ids,
            frontier_last_unit=max(current.run.frontier_last_unit, challenger.run.frontier_last_unit),
            pending_challenge=current.run.pending_challenge or challenger.run.pending_challenge,
            suppress_challenger_clue_ids=(
                current.run.suppress_challenger_clue_ids | challenger.run.suppress_challenger_clue_ids
            ),
        )
        return _MaterializedRun(
            clue_index=current.clue_index,
            run=merged_run,
            stack=current.stack,
        )

    def _prefer_same_start_materialized_run(
        self,
        current: _MaterializedRun,
        challenger: _MaterializedRun,
    ) -> _MaterializedRun:
        """在同一 clue.start 上用轻量规则预选本轮主栈。"""
        current_candidate = current.run.candidate
        challenger_candidate = challenger.run.candidate
        if (
            current_candidate.attr_type == challenger_candidate.attr_type
            and current_candidate.start == challenger_candidate.start
            and current_candidate.end == challenger_candidate.end
            and current_candidate.unit_start == challenger_candidate.unit_start
            and current_candidate.unit_last == challenger_candidate.unit_last
            and current_candidate.text == challenger_candidate.text
        ):
            return self._merge_equivalent_materialized_runs(current, challenger)
        win_key = _strict_unit_container_winner_key(current_candidate, challenger_candidate)
        if win_key == "a":
            return current
        if win_key == "b":
            return challenger
        if self._same_start_priority_key(challenger_candidate) > self._same_start_priority_key(current_candidate):
            return challenger
        return current

    def _select_start_group_run(
        self,
        context: StackContext,
        clue_indices: Sequence[int],
    ) -> tuple[StackRun, BaseStack | None] | None:
        """对同一起点 group 的多个起栈 clue 做局部预选。"""
        materialized_runs: list[_MaterializedRun] = []
        for clue_index in clue_indices:
            self._apply_inspire_boost_to_clue(context, clue_index)
            run, stack = self._try_run_stack(context, clue_index)
            if run is None:
                continue
            materialized_runs.append(_MaterializedRun(clue_index=clue_index, run=run, stack=stack))
        if not materialized_runs:
            return None
        current = materialized_runs[0]
        for challenger in materialized_runs[1:]:
            current = self._prefer_same_start_materialized_run(current, challenger)
        return current.run, current.stack

    def _find_challenger(
        self,
        context: StackContext,
        current_run: StackRun,
        current_unit_cursor: int,
        current_start: int,
    ) -> tuple[StackRun | None, BaseStack | None]:
        """在当前候选覆盖窗内寻找更晚起点的 challenger。"""
        start_unit = current_run.candidate.unit_start
        end_unit = min(current_run.candidate.unit_last, len(context.unit_index) - 1)
        suppress_ids = (
            current_run.suppress_challenger_clue_ids
            if current_run.candidate.attr_type == PIIAttributeType.ADDRESS
            else frozenset()
        )
        for unit_index in range(start_unit, end_unit + 1):
            self._advance_semantic_value_locks_at_unit(context, unit_index)
            start_groups = self._start_groups_at_unit(
                context,
                unit_index,
                suppress_start_clue_ids=suppress_ids,
            )
            for group_start, clue_indices in start_groups:
                if unit_index == current_unit_cursor and group_start <= current_start:
                    continue
                selected = self._select_start_group_run(context, clue_indices)
                if selected is None:
                    continue
                run, stack = selected
                if _candidates_overlap(current_run.candidate, run.candidate):
                    return run, stack
        if current_run.candidate.attr_type in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
            # 中文地址的 numberish key（如“号楼”“单元”）会从右邻 unit 起栈，再向左吸收当前数字。
            # 若只扫当前 candidate 覆盖窗，会让 NUM 先提交、地址候选随后被 frontier 挡掉。
            next_unit = end_unit + 1
            if next_unit < len(context.unit_index):
                run, stack = self._try_run_stack_at_unit(
                    context,
                    next_unit,
                    ClueFamily.ADDRESS,
                    suppress_start_clue_ids=suppress_ids,
                )
                if run is not None and _candidates_overlap(current_run.candidate, run.candidate):
                    return run, stack
        bridge_run, bridge_stack = self._find_address_bridge_challenger(
            context,
            current_run,
            suppress_ids=suppress_ids,
        )
        if bridge_run is not None:
            return bridge_run, bridge_stack
        return None, None

    def _candidate_is_short_address_bridge_source(self, run: StackRun) -> bool:
        """英文地址桥接只处理短 NUM / ALNUM。"""
        if run.candidate.attr_type not in {PIIAttributeType.NUM, PIIAttributeType.ALNUM}:
            return False
        compact = "".join(char for char in str(run.candidate.text or "") if char.isalnum())
        return 0 < len(compact) <= 5

    def _unit_blocks_address_bridge(self, context: StackContext, unit_index: int) -> bool:
        """桥接只允许穿过同一局部片段，不跨标点、break 或 direct seed。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return True
        bucket = context.unit_index[unit_index]
        if bucket.break_start or bucket.flag == "OCR_BREAK":
            return True
        if self._has_non_structured_direct_seed_at_unit(context, unit_index):
            return True
        return bucket.flag not in {None, "SPACE", "INLINE_GAP"}

    def _is_non_admin_address_bridge_seed(self, clue: Clue) -> bool:
        """只允许非 admin 地址 clue 触发左侧数值桥接。"""
        return (
            clue.attr_type == PIIAttributeType.ADDRESS
            and clue.role != ClueRole.LABEL
            and clue.component_type in {
                AddressComponentType.ROAD,
                AddressComponentType.BUILDING,
                AddressComponentType.POI,
                AddressComponentType.DETAIL,
            }
        )

    def _find_address_bridge_challenger(
        self,
        context: StackContext,
        current_run: StackRun,
        *,
        suppress_ids: frozenset[str],
    ) -> tuple[StackRun | None, BaseStack | None]:
        """短 NUM / ALNUM 向右寻找英文地址 seed。"""
        if not self._candidate_is_short_address_bridge_source(current_run):
            return None, None
        start_unit = current_run.candidate.unit_last + 1
        end_unit = min(len(context.unit_index) - 1, current_run.candidate.unit_last + 6)
        for unit_index in range(start_unit, end_unit + 1):
            if self._unit_blocks_address_bridge(context, unit_index):
                break
            self._advance_semantic_value_locks_at_unit(context, unit_index)
            start_groups = self._start_groups_at_unit(
                context,
                unit_index,
                suppress_start_clue_ids=suppress_ids,
            )
            for _group_start, clue_indices in start_groups:
                address_seed_indices = tuple(
                    clue_index
                    for clue_index in clue_indices
                    if self._is_non_admin_address_bridge_seed(context.clues[clue_index])
                )
                if not address_seed_indices:
                    continue
                selected = self._select_start_group_run(context, address_seed_indices)
                if selected is None:
                    continue
                run, stack = selected
                if run.attr_type != PIIAttributeType.ADDRESS:
                    continue
                if run.pending_challenge is not None:
                    run = self._resolve_pending_challenge(context, run)
                if _candidates_overlap(current_run.candidate, run.candidate):
                    return run, stack
        return None, None

    def _resolve_pending_challenge(self, context: StackContext, run: StackRun) -> StackRun:
        """挑战裁决：运行 StructuredStack 判定 digit_run，决定使用保守还是扩展候选。"""
        challenge = run.pending_challenge
        assert challenge is not None
        struct_run, _ = self._try_run_stack(context, challenge.clue_index)
        use_extended = False
        if struct_run is None:
            use_extended = True
        else:
            use_extended = struct_run.candidate.attr_type in {
                PIIAttributeType.NUM,
                PIIAttributeType.ALNUM,
            }
        if use_extended:
            return StackRun(
                attr_type=run.attr_type,
                candidate=challenge.extended_candidate,
                handled_label_clue_ids=run.handled_label_clue_ids,
                frontier_last_unit=challenge.extended_last_unit,
                suppress_challenger_clue_ids=run.suppress_challenger_clue_ids,
            )
        run.pending_challenge = None
        return run

    def _resolve_name_address_pending_challenge(
        self,
        context: StackContext,
        name_run: StackRun,
        name_stack: BaseStack | None,
    ) -> ResolutionResult | None:
        """在 commit 前直接裁决 NAME 与内部 ADDRESS 候选，避免单姓保守抢跑。"""
        challenge = name_run.pending_challenge
        assert challenge is not None
        if name_stack is None:
            name_run.pending_challenge = None
            return None

        address_run, _ = self._try_run_stack(context, challenge.clue_index)
        if address_run is None or address_run.candidate.attr_type != PIIAttributeType.ADDRESS:
            name_run.pending_challenge = None
            return None
        if address_run.pending_challenge is not None:
            address_run = self._resolve_pending_challenge(context, address_run)
        if not _candidates_overlap(name_run.candidate, address_run.candidate):
            name_run.pending_challenge = None
            return None

        name_run.pending_challenge = None
        win_key = _strict_unit_container_winner_key(name_run.candidate, address_run.candidate)
        if win_key == "a":
            self._commit_run(context, name_run)
            return self._result_from_runs(name_run)
        if win_key == "b":
            self._commit_run(context, address_run)
            return self._result_from_runs(address_run)

        shrunk = BaseStack.shrink(
            name_stack,
            name_run,
            address_run.candidate.unit_start,
            address_run.candidate.unit_last,
        )
        if shrunk is not None and (shrunk.candidate.unit_last - shrunk.candidate.unit_start + 1) > 1:
            if shrunk.candidate.unit_last < address_run.candidate.unit_start:
                self._commit_run(context, shrunk)
                self._commit_run(context, address_run)
            else:
                self._commit_run(context, address_run)
                self._commit_run(context, shrunk)
            return self._result_from_runs(address_run, shrunk)

        if _claim_strength_rank(name_run.candidate.claim_strength) >= _claim_strength_rank(address_run.candidate.claim_strength):
            self._commit_run(context, name_run)
            return self._result_from_runs(name_run)

        self._commit_run(context, address_run)
        return self._result_from_runs(address_run)

    def _soft_priority(self, attr_type: PIIAttributeType) -> int:
        """按 attr_type 推导 family 后查询 soft_priority。"""
        from privacyguard.infrastructure.pii.detector.scanner import _attr_to_family
        spec = get_stack_spec(_attr_to_family(attr_type))
        if spec is None:
            return 0
        return spec.soft_priority

    def _has_non_structured_direct_seed_at_unit(self, context: StackContext, unit_index: int) -> bool:
        """判断当前 unit 是否出现新的非结构化 direct LABEL/START。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return False
        for family in (
            ClueFamily.LICENSE_PLATE,
            ClueFamily.ADDRESS,
            ClueFamily.NAME,
            ClueFamily.ORGANIZATION,
        ):
            for clue_index in bucket_family_clues(context.unit_index[unit_index], family):
                clue = context.clues[clue_index]
                if clue.role in {ClueRole.LABEL, ClueRole.START}:
                    return True
        return False

    def _advance_semantic_value_locks_at_unit(self, context: StackContext, unit_index: int) -> None:
        """流式维护 NAME / ORG / ADDRESS 的局部 value 锁。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return
        bucket = context.unit_index[unit_index]
        for family in _SEMANTIC_VALUE_LOCK_FAMILIES:
            for clue_index in bucket_family_clues(bucket, family):
                clue = context.clues[clue_index]
                if clue.role in {ClueRole.LABEL, ClueRole.START}:
                    context.raise_stack_value_floor(clue.family, clue.unit_last)
        for inspire_index in bucket.inspire_entries:
            inspire = context.inspire_entries[inspire_index]
            context.raise_stack_value_floor(inspire.family, inspire.unit_last)

    def _advance_inspire_anchor_at_unit(self, context: StackContext, unit_index: int) -> None:
        """流式维护最近的非结构化 inspire 锚点。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return
        bucket = context.unit_index[unit_index]
        if (
            bucket.flag == "OCR_BREAK"
            or bucket.break_start
            or self._has_non_structured_direct_seed_at_unit(context, unit_index)
        ):
            context.recent_inspire_anchor = None
        for inspire_index in bucket.inspire_entries:
            context.recent_inspire_anchor = context.inspire_entries[inspire_index]

    def _scan_recent_inspire_anchor_before_unit(
        self,
        context: StackContext,
        unit_start: int,
    ) -> InspireEntry | None:
        """按 unit 索引差回看最近 inspire，并应用显式失效条件。"""
        recent: InspireEntry | None = None
        start_unit = max(0, unit_start - 6)
        for unit_index in range(start_unit, min(unit_start, len(context.unit_index))):
            bucket = context.unit_index[unit_index]
            if (
                bucket.flag == "OCR_BREAK"
                or bucket.break_start
                or self._has_non_structured_direct_seed_at_unit(context, unit_index)
            ):
                recent = None
            for inspire_index in bucket.inspire_entries:
                recent = context.inspire_entries[inspire_index]
        return recent

    def _find_applicable_inspire_anchor(self, context: StackContext, clue: Clue) -> InspireEntry | None:
        """为当前起栈 clue 查找可用的 inspire 锚点。"""
        if (
            clue.family == ClueFamily.STRUCTURED
            or clue.family == ClueFamily.ADDRESS
            or clue.role in {ClueRole.LABEL, ClueRole.START}
            or clue.attr_type is None
        ):
            return None
        fallback = self._scan_recent_inspire_anchor_before_unit(context, clue.unit_start)
        if (
            fallback is None
            or fallback.attr_type != clue.attr_type
            or fallback.unit_last >= clue.unit_start
            or clue.unit_start - fallback.unit_last > 6
        ):
            return None
        return fallback

    def _inspire_boost_levels(self, clue: Clue, inspire: InspireEntry) -> int:
        """按 inspire 与 clue 的 unit 距离返回应提升的层级数。"""
        unit_distance = clue.unit_start - inspire.unit_last
        if unit_distance <= 0 or unit_distance > 6:
            return 0
        if unit_distance <= 3:
            return 2
        return 1

    def _apply_inspire_boost_to_clue(self, context: StackContext, clue_index: int) -> Clue:
        """把 inspire 提升直接回写到 context.clues，避免 stack 再读到旧强度。"""
        clue = context.clues[clue_index]
        if clue.strength == ClaimStrength.HARD or clue.clue_id in context.inspire_boosted_clue_ids:
            return clue
        inspire = self._find_applicable_inspire_anchor(context, clue)
        if inspire is None:
            return clue
        boosted_strength = _upgrade_claim_strength_by_levels(
            clue.strength,
            self._inspire_boost_levels(clue, inspire),
        )
        context.inspire_boosted_clue_ids.add(clue.clue_id)
        if boosted_strength == clue.strength:
            return clue
        updated_clue = replace(clue, strength=boosted_strength)
        updated_clues = list(context.clues)
        updated_clues[clue_index] = updated_clue
        context.clues = tuple(updated_clues)
        return updated_clue

    def _remember_structured_anchor(self, context: StackContext, clue: Clue, clue_index: int) -> None:
        """流式记录最近的结构化 LABEL/START，供 Structured VALUE 直接读取。"""
        if clue.family != ClueFamily.STRUCTURED or clue.role not in {ClueRole.LABEL, ClueRole.START}:
            return
        if clue.attr_type is None:
            return
        current = context.recent_structured_anchor
        if (
            current is not None
            and current.unit_last == clue.unit_last
            and current.role == ClueRole.START
            and clue.role != ClueRole.START
        ):
            return
        context.recent_structured_anchor = StructuredAnchor(
            attr_type=clue.attr_type,
            role=clue.role,
            unit_last=clue.unit_last,
            clue_index=clue_index,
            clue_id=clue.clue_id,
        )

    def _remember_structured_anchors_at_unit(self, context: StackContext, unit_index: int) -> None:
        """在当前 unit 上流式记录 structured LABEL/START。"""
        if unit_index < 0 or unit_index >= len(context.unit_index):
            return
        for clue_index in context.unit_index[unit_index].structured_clues:
            self._remember_structured_anchor(context, context.clues[clue_index], clue_index)

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    def _commit_run(self, context: StackContext, run: StackRun) -> None:
        """提交 run。"""
        self._commit_candidate(context, run.candidate)
        context.handled_label_clue_ids |= run.handled_label_clue_ids

    def _commit_runs(self, context: StackContext, *runs: StackRun) -> ResolutionResult:
        committed_runs = [run for run in runs if run is not None]
        for run in committed_runs:
            self._commit_run(context, run)
        return self._result_from_runs(*committed_runs)

    def _result_from_runs(self, *runs: StackRun) -> ResolutionResult:
        if not runs:
            return ResolutionResult.no_commit()
        return ResolutionResult(
            committed=True,
            next_unit_cursor=max(run.frontier_last_unit for run in runs) + 1,
        )

    def _commit_candidate(self, context: StackContext, candidate: CandidateDraft) -> None:
        if context.blocks_unit_start(candidate.unit_start):
            return
        existing = self._find_identical(context, candidate)
        if existing is not None:
            existing.metadata = merge_metadata(existing.metadata, candidate.metadata)
            existing.label_clue_ids |= candidate.label_clue_ids
            context.handled_label_clue_ids |= candidate.label_clue_ids
            return
        if self._try_absorb_adjacent_address_candidate(context, candidate):
            return
        # detector 主路径（非 persona 出口）仅允许产出 ALLOWED_DETECTOR_OUTPUT_ATTRS 内的类型。
        if candidate.source_kind not in _PERSONA_SOURCE_KINDS:
            assert candidate.attr_type in ALLOWED_DETECTOR_OUTPUT_ATTRS, (
                f"detector 主路径产出非法 attr_type: {candidate.attr_type} "
                f"(source_kind={candidate.source_kind})"
            )
        context.candidates.append(candidate)
        context.candidate_identity_index[_candidate_identity_key(candidate)] = candidate
        context.claims.append(
            Claim(
                start=candidate.start,
                end=candidate.end,
                attr_type=candidate.attr_type,
                strength=candidate.claim_strength,
                owner_stack_id=f"{candidate.attr_type.value}:{candidate.start}:{candidate.end}",
            )
        )
        context.handled_label_clue_ids |= candidate.label_clue_ids
        context.commit_frontier_last_unit = max(context.commit_frontier_last_unit, candidate.unit_last)
        context.raise_all_value_floor(context.commit_frontier_last_unit)

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    def _find_identical(self, context: StackContext, candidate: CandidateDraft) -> CandidateDraft | None:
        return context.candidate_identity_index.get(_candidate_identity_key(candidate))

    def _get_cached_address_normalized(self, context: StackContext, candidate: CandidateDraft) -> object:
        signature = _address_normalized_cache_signature(candidate)
        cached = context.address_normalized_cache.get(id(candidate))
        if cached is not None and cached[0] == signature:
            return cached[1]
        normalized = normalize_pii(
            PIIAttributeType.ADDRESS,
            candidate.text,
            metadata=candidate.metadata,
        )
        context.address_normalized_cache[id(candidate)] = (signature, normalized)
        return normalized

    def _try_absorb_adjacent_address_candidate(
        self,
        context: StackContext,
        candidate: CandidateDraft,
    ) -> bool:
        """紧邻同源地址若是同一实体的真子集，则把短地址吸收到长地址里。"""
        if candidate.attr_type != PIIAttributeType.ADDRESS or not context.candidates:
            return False
        previous = context.candidates[-1]
        if previous.attr_type != PIIAttributeType.ADDRESS:
            return False
        if previous.source != candidate.source:
            return False
        if candidate.start < previous.end:
            return False
        gap_text = context.stream.text[previous.end:candidate.start]
        if not _is_punct_or_space_only(gap_text):
            return False

        previous_key = _candidate_identity_key(previous)
        previous_normalized = self._get_cached_address_normalized(context, previous)
        candidate_normalized = self._get_cached_address_normalized(context, candidate)
        previous_primary = normalized_primary_text(previous_normalized)
        candidate_primary = normalized_primary_text(candidate_normalized)
        absorb_mode: str | None = None
        english_fragment_merge = _looks_like_english_address_text(previous.text) or _looks_like_english_address_text(candidate.text)
        if (
            english_fragment_merge
            and _is_prefix_fragment_address(previous_normalized)
            and _has_main_address_shape(candidate_normalized)
        ):
            longer = candidate
            shorter = previous
            longer_normalized = candidate_normalized
            shorter_normalized = previous_normalized
            absorb_mode = "prepend_fragment"
        elif (
            english_fragment_merge
            and _is_leading_road_fragment_address(previous_normalized)
            and _has_trailing_address_context(candidate_normalized)
        ):
            longer = candidate
            shorter = previous
            longer_normalized = candidate_normalized
            shorter_normalized = previous_normalized
            absorb_mode = "prepend_fragment"
        elif (
            english_fragment_merge
            and _is_trailing_detail_admin_fragment_address(candidate_normalized)
            and _has_main_address_shape(previous_normalized)
        ):
            longer = previous
            shorter = candidate
            longer_normalized = previous_normalized
            shorter_normalized = candidate_normalized
            absorb_mode = "append_fragment"
        elif (
            english_fragment_merge
            and _is_tail_fragment_address(candidate_normalized)
            and _has_main_address_shape(previous_normalized)
        ):
            longer = previous
            shorter = candidate
            longer_normalized = previous_normalized
            shorter_normalized = candidate_normalized
            absorb_mode = "append_fragment"
        else:
            if not previous_primary or not candidate_primary or previous_primary == candidate_primary:
                return False
            if previous_primary in candidate_primary:
                longer = candidate
                shorter = previous
                longer_normalized = candidate_normalized
                shorter_normalized = previous_normalized
            elif candidate_primary in previous_primary:
                longer = previous
                shorter = candidate
                longer_normalized = previous_normalized
                shorter_normalized = candidate_normalized
            else:
                return False
            if not same_entity(previous_normalized, candidate_normalized):
                if not _address_components_subset(shorter_normalized.components, longer_normalized.components):
                    return False

        previous.start = min(previous.start, candidate.start)
        previous.end = max(previous.end, candidate.end)
        previous.unit_start = min(previous.unit_start, candidate.unit_start)
        previous.unit_last = max(previous.unit_last, candidate.unit_last)
        previous.text = context.stream.text[previous.start:previous.end]
        previous.source_kind = longer.source_kind
        previous.canonical_text = longer.canonical_text
        previous.claim_strength = longer.claim_strength
        if absorb_mode == "prepend_fragment":
            previous.metadata = _merge_address_fragment_metadata(
                longer.metadata,
                shorter.metadata,
                prepend_fragment=True,
            )
        elif absorb_mode == "append_fragment":
            previous.metadata = _merge_address_fragment_metadata(
                longer.metadata,
                shorter.metadata,
                prepend_fragment=False,
            )
        else:
            previous.metadata = _merge_address_absorb_metadata(longer.metadata, shorter.metadata)
        context.address_normalized_cache.pop(id(previous), None)
        previous.label_clue_ids |= candidate.label_clue_ids
        previous.label_driven = previous.label_driven or candidate.label_driven
        previous.block_ids = longer.block_ids
        previous.block_id = longer.block_id
        previous.bbox = longer.bbox
        span_starts = [value for value in (previous.span_start, candidate.span_start) if value is not None]
        previous.span_start = min(span_starts) if span_starts else None
        span_ends = [value for value in (previous.span_end, candidate.span_end) if value is not None]
        previous.span_end = max(span_ends) if span_ends else None

        claim = context.claims[-1]
        claim.start = previous.start
        claim.end = previous.end
        claim.strength = previous.claim_strength
        claim.owner_stack_id = f"{previous.attr_type.value}:{previous.start}:{previous.end}"
        context.candidate_identity_index.pop(previous_key, None)
        context.candidate_identity_index[_candidate_identity_key(previous)] = previous
        context.handled_label_clue_ids |= candidate.label_clue_ids
        context.commit_frontier_last_unit = max(context.commit_frontier_last_unit, previous.unit_last)
        context.raise_all_value_floor(context.commit_frontier_last_unit)
        return True

