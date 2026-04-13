"""按 stack 注册表路由的单主栈 parser。

冲突裁决策略：
- hard clue 直接产出候选，不参与 soft 竞争。
- soft 类型间按静态优先级裁决：ADDRESS > NAME > ORGANIZATION。
- 低优先级 stack 遇到高优先级 challenger 时，通过 shrink 回缩让渡重叠区域。
- 同优先级 / 同类型 fallback 到 StackManager.score 比分。
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.context import DetectContext
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    CandidateDraft,
    Claim,
    ClaimStrength,
    Clue,
    ClueBundle,
    ClueFamily,
    ParseResult,
    StructuredLookupIndex,
    StreamInput,
    negative_has_cover,
    negative_has_start,
    negative_is_fully_covered,
    negative_next_start_unit,
    negative_prev_covered_end_unit,
)
from privacyguard.infrastructure.pii.detector.stacks import BaseStack, StackManager, StackRun, get_stack_spec
from privacyguard.utils.normalized_pii import normalize_pii, normalized_primary_text, same_entity

_CandidateIdentityKey = tuple[PIIAttributeType, int, int, int, int, str]
_FrozenMetadataItems = tuple[tuple[str, tuple[str, ...]], ...]
_AddressNormalizedCacheSignature = tuple[str, _FrozenMetadataItems]


def _is_control_clue(clue: Clue) -> bool:
    """控制 clue 不建 stack，只供 stack 扩张时观察。"""
    return clue.family == ClueFamily.CONTROL


def _candidates_overlap(a: CandidateDraft, b: CandidateDraft) -> bool:
    return a.unit_start < b.unit_end and b.unit_start < a.unit_end


_ADDRESS_STRUCTURAL_METADATA_KEYS = frozenset({
    "address_component_trace",
    "address_component_key_trace",
    "address_component_suspected",
    "address_component_type",
})
_ADDRESS_STRUCTURAL_SEQUENCE_KEYS = frozenset({
    "address_component_trace",
    "address_component_key_trace",
    "address_component_suspected",
    "address_component_type",
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
        candidate.unit_end,
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
    return bool(keys) and keys <= {"detail", "building"}


def _is_tail_fragment_address(normalized: object) -> bool:
    keys = _address_component_keys(normalized)
    return bool(keys) and keys <= {"city", "province", "postal_code", "country"}


def _has_main_address_shape(normalized: object) -> bool:
    keys = _address_component_keys(normalized)
    return bool(keys & {"road", "house_number", "city", "province", "postal_code", "country", "poi"})


def _looks_like_english_address_text(text: str) -> bool:
    return any(("A" <= char <= "Z") or ("a" <= char <= "z") for char in str(text or ""))


@dataclass(slots=True)
class StackContext:
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel = ProtectionLevel.STRONG
    clues: tuple[Clue, ...] = ()
    negative_unit_marks: list[int] = field(default_factory=list)
    negative_prefix_sum: list[int] = field(default_factory=lambda: [0])
    negative_start_weight: int = 0
    structured_lookup_index: StructuredLookupIndex = field(default_factory=StructuredLookupIndex)
    committed_until: int = 0
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)
    candidate_identity_index: dict[_CandidateIdentityKey, CandidateDraft] = field(default_factory=dict)
    address_normalized_cache: dict[int, tuple[_AddressNormalizedCacheSignature, object]] = field(default_factory=dict)

    def has_negative_cover(self, unit_start: int, unit_end: int) -> bool:
        """判断给定 unit 区间是否存在任意 negative 覆盖。"""
        return negative_has_cover(
            self.negative_prefix_sum,
            len(self.negative_unit_marks),
            unit_start,
            unit_end,
        )

    def has_negative_start(self, unit_start: int, unit_end: int) -> bool:
        """判断给定 unit 区间是否存在 negative 起点。"""
        return negative_has_start(
            self.negative_prefix_sum,
            len(self.negative_unit_marks),
            unit_start,
            unit_end,
        )

    def is_negative_fully_covered(self, unit_start: int, unit_end: int) -> bool:
        """判断给定 unit 区间是否被 negative 完整覆盖。"""
        return negative_is_fully_covered(self.negative_unit_marks, unit_start, unit_end)

    def next_negative_start_char(self, char_index: int) -> int | None:
        """返回当前位置右侧最近的 negative 起点 char，下游可将其作为边界。"""
        unit_index = self._unit_index_at_or_after(char_index)
        next_unit = negative_next_start_unit(
            self.negative_unit_marks,
            self.negative_start_weight,
            unit_index,
        )
        if next_unit is None or next_unit >= len(self.stream.units):
            return None
        return self.stream.units[next_unit].char_start

    def previous_negative_end_char(self, char_index: int) -> int | None:
        """返回左侧最近一个 negative 覆盖 unit 的结束位置。"""
        before_unit = self._unit_index_at_or_after(char_index)
        end_unit = negative_prev_covered_end_unit(self.negative_unit_marks, before_unit)
        if end_unit is None or end_unit <= 0 or end_unit > len(self.stream.units):
            return None
        return self.stream.units[end_unit - 1].char_end

    def has_negative_cover_left_of_char(self, char_index: int) -> bool:
        """判断 cursor 左侧紧邻位置是否处于 negative 覆盖内部。"""
        if char_index <= 0 or not self.stream.char_to_unit or not self.negative_unit_marks:
            return False
        left_char = min(char_index - 1, len(self.stream.char_to_unit) - 1)
        unit_index = self.stream.char_to_unit[left_char]
        if unit_index < 0 or unit_index >= len(self.negative_unit_marks):
            return False
        return self.negative_unit_marks[unit_index] > 0

    def _unit_index_at_or_after(self, char_index: int) -> int:
        if not self.stream.char_to_unit or char_index >= len(self.stream.char_to_unit):
            return len(self.stream.units)
        unit_index = self.stream.char_to_unit[max(0, char_index)]
        while unit_index < len(self.stream.units) and self.stream.units[unit_index].char_end <= char_index:
            unit_index += 1
        return unit_index


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
            negative_unit_marks=list(bundle.negative_unit_marks),
            negative_prefix_sum=list(bundle.negative_prefix_sum),
            negative_start_weight=bundle.negative_start_weight,
            structured_lookup_index=structured_lookup_index or StructuredLookupIndex(),
        )
        # consumed_ids 仅在 _commit_run 时追加，不在构建 run 时提前标记。
        # 这样 shrink 失败时败方 clue 不会被永久锁死。
        consumed_ids: set[str] = set()
        index = 0
        while index < len(context.clues):
            clue = context.clues[index]
            if clue.clue_id in consumed_ids or _is_control_clue(clue):
                index += 1
                continue

            current_run, current_stack = self._try_run_stack(context, index)
            if current_run is None:
                index += 1
                continue

            if current_run.pending_challenge is not None:
                current_run = self._resolve_pending_challenge(context, current_run)

            # 查找下一个不在 current_run 中、不同类型的 clue 作为 challenger。
            challenger_run, challenger_stack = None, None
            skip_ids = consumed_ids | current_run.consumed_ids
            next_index = self._next_unconsumed_index(context.clues, current_run.next_index, skip_ids)
            if next_index is not None:
                next_clue = context.clues[next_index]
                if next_clue.attr_type != current_run.attr_type:
                    if (
                        current_run.candidate.attr_type == PIIAttributeType.ADDRESS
                        and next_clue.clue_id in current_run.suppress_challenger_clue_ids
                    ):
                        challenger_run, challenger_stack = None, None
                    else:
                        challenger_run, challenger_stack = self._try_run_stack(context, next_index)

            # 无 challenger 或不重叠 → 直接 commit。
            if challenger_run is None or not _candidates_overlap(current_run.candidate, challenger_run.candidate):
                self._commit_run(context, current_run, consumed_ids)
                index = self._next_unconsumed_index(context.clues, current_run.next_index, consumed_ids) or len(context.clues)
                continue

            # 有重叠 → 按类型优先级 + shrink 裁决。
            winner_next_index = self._resolve_with_priority(
                context, consumed_ids,
                current_run, current_stack,
                challenger_run, challenger_stack,
            )

            index = self._next_unconsumed_index(
                context.clues,
                winner_next_index,
                consumed_ids,
            ) or len(context.clues)

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
        consumed_ids: set[str],
        run_a: StackRun, stack_a: BaseStack | None,
        run_b: StackRun, stack_b: BaseStack | None,
    ) -> int:
        """按类型优先级裁决两个重叠的 StackRun。

        1. 比较 hard / soft：hard 一方直接胜出，soft 一方 shrink。
        2. 同为 soft：按 ATTR_TYPE_PRIORITY 裁决。
        3. 优先级相同或同类型：fallback 到 score 比分。
        4. 败方尝试 shrink，成功则双方都 commit。

        parser 主循环只使用胜方 stack 返回的 next_index。
        败方即使 shrink 成功，也不能把主循环游标整体推到自己的 next_index。
        """
        ca, cb = run_a.candidate, run_b.candidate
        hard_a = ca.claim_strength == ClaimStrength.HARD
        hard_b = cb.claim_strength == ClaimStrength.HARD

        # hard vs soft：hard 胜，soft 做 shrink。
        if hard_a and not hard_b:
            return self._commit_winner_and_shrink_loser(context, consumed_ids, run_a, None, run_b, stack_b)
        if hard_b and not hard_a:
            return self._commit_winner_and_shrink_loser(context, consumed_ids, run_b, None, run_a, stack_a)

        # 都是 hard：旧逻辑 fallback。
        if hard_a and hard_b:
            return self._fallback_conflict(context, consumed_ids, run_a, run_b)

        # 都是 soft：按注册表优先级。
        prio_a = self._soft_priority(ca.attr_type)
        prio_b = self._soft_priority(cb.attr_type)

        if prio_a > prio_b:
            return self._commit_winner_and_shrink_loser(context, consumed_ids, run_a, stack_a, run_b, stack_b)
        if prio_b > prio_a:
            return self._commit_winner_and_shrink_loser(context, consumed_ids, run_b, stack_b, run_a, stack_a)

        # 优先级相同（含同类型）→ score 比分。
        return self._fallback_conflict(context, consumed_ids, run_a, run_b)

    def _commit_winner_and_shrink_loser(
        self,
        context: StackContext,
        consumed_ids: set[str],
        winner_run: StackRun,
        winner_stack: BaseStack | None,
        loser_run: StackRun,
        loser_stack: BaseStack | None,
    ) -> int:
        """commit winner，然后让 loser 尝试 shrink；shrink 成功也 commit。

        consumed_ids 仅在实际 commit 时追加——shrink 失败则败方 clue 不被锁死。
        """
        self._commit_run(context, winner_run, consumed_ids)

        if loser_stack is None:
            context.handled_label_clue_ids |= loser_run.handled_label_clue_ids
            return winner_run.next_index

        wc = winner_run.candidate
        shrunk = loser_stack.shrink(loser_run, wc.unit_start, wc.unit_end)
        if shrunk is not None:
            self._commit_run(context, shrunk, consumed_ids)
        else:
            # shrink 失败：只标记 label，不锁死 clue。
            context.handled_label_clue_ids |= loser_run.handled_label_clue_ids
        return winner_run.next_index

    def _fallback_conflict(
        self,
        context: StackContext,
        consumed_ids: set[str],
        run_a: StackRun,
        run_b: StackRun,
    ) -> int:
        """同优先级 / 同类型冲突 fallback：score 高者胜，败者丢弃。"""
        outcome = self.stack_manager.resolve_conflict(context, run_a.candidate, run_b.candidate)
        next_index = run_a.next_index
        if not outcome.drop_existing:
            if outcome.replace_existing is not None:
                self._commit_candidate(context, outcome.replace_existing)
            else:
                self._commit_candidate(context, run_a.candidate)
        if outcome.incoming is not None:
            self._commit_candidate(context, outcome.incoming)
            if outcome.drop_existing:
                next_index = run_b.next_index
        # fallback 场景下两方的 clue 都标记消费（胜败都已裁决完毕）。
        consumed_ids |= run_a.consumed_ids
        consumed_ids |= run_b.consumed_ids
        context.handled_label_clue_ids |= run_a.handled_label_clue_ids
        context.handled_label_clue_ids |= run_b.handled_label_clue_ids
        return next_index

    # ------------------------------------------------------------------
    # Stack 运行
    # ------------------------------------------------------------------

    def _try_run_stack(self, context: StackContext, index: int) -> tuple[StackRun | None, BaseStack | None]:
        """尝试在 index 处启动 stack，返回 (run, stack_instance)。"""
        clue = context.clues[index]
        spec = get_stack_spec(clue.family)
        if spec is None:
            return None, None
        if clue.role not in spec.start_roles:
            return None, None
        stack = spec.stack_cls(clue=clue, clue_index=index, context=context)
        run = stack.run()
        if run is None or not run.candidate.text.strip():
            return None, None
        return run, stack

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
                PIIAttributeType.NUMERIC,
                PIIAttributeType.ALNUM,
            }
        if use_extended:
            return StackRun(
                attr_type=run.attr_type,
                candidate=challenge.extended_candidate,
                consumed_ids=challenge.extended_consumed_ids,
                handled_label_clue_ids=run.handled_label_clue_ids,
                next_index=challenge.extended_next_index,
                suppress_challenger_clue_ids=run.suppress_challenger_clue_ids,
            )
        run.pending_challenge = None
        return run

    def _soft_priority(self, attr_type: PIIAttributeType) -> int:
        """按 attr_type 推导 family 后查询 soft_priority。"""
        from privacyguard.infrastructure.pii.detector.scanner import _attr_to_family
        spec = get_stack_spec(_attr_to_family(attr_type))
        if spec is None:
            return 0
        return spec.soft_priority

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    def _commit_run(self, context: StackContext, run: StackRun, consumed_ids: set[str]) -> None:
        """提交 run 并将其 consumed_ids 标记为已消费。"""
        consumed_ids |= run.consumed_ids
        self._commit_candidate(context, run.candidate)
        context.handled_label_clue_ids |= run.handled_label_clue_ids

    def _commit_candidate(self, context: StackContext, candidate: CandidateDraft) -> None:
        existing = self._find_identical(context, candidate)
        if existing is not None:
            existing.metadata = merge_metadata(existing.metadata, candidate.metadata)
            existing.label_clue_ids |= candidate.label_clue_ids
            context.handled_label_clue_ids |= candidate.label_clue_ids
            return
        if self._try_absorb_adjacent_address_candidate(context, candidate):
            return
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
        context.committed_until = max(context.committed_until, candidate.unit_end)

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
        previous.unit_end = max(previous.unit_end, candidate.unit_end)
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
        context.committed_until = max(context.committed_until, previous.unit_end)
        return True

    def _next_unconsumed_index(self, clues: tuple[Clue, ...], start_index: int, consumed_ids: set[str]) -> int | None:
        for index in range(start_index, len(clues)):
            clue = clues[index]
            if clue.clue_id in consumed_ids or _is_control_clue(clue):
                continue
            return index
        return None
