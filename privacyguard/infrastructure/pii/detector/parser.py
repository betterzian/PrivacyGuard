"""按 stack 注册表路由的单主栈 parser。

冲突裁决策略：
- hard clue 直接产出候选，不参与 soft 竞争。
- soft 类型间按静态优先级裁决：ADDRESS > NAME > ORGANIZATION。
- 低优先级 stack 遇到高优先级 challenger 时，通过 shrink 回缩让渡重叠区域。
- 同优先级 / 同类型 fallback 到 StackManager.score 比分。
"""

from __future__ import annotations

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
)
from privacyguard.infrastructure.pii.detector.stacks import BaseStack, StackManager, StackRun, get_stack_spec


def _is_control_clue(clue: Clue) -> bool:
    """控制 clue 不建 stack，只供 stack 扩张时观察。"""
    return clue.family == ClueFamily.CONTROL


def _candidates_overlap(a: CandidateDraft, b: CandidateDraft) -> bool:
    return a.unit_start < b.unit_end and b.unit_start < a.unit_end


@dataclass(slots=True)
class StackContext:
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel = ProtectionLevel.STRONG
    clues: tuple[Clue, ...] = ()
    structured_lookup_index: StructuredLookupIndex = field(default_factory=StructuredLookupIndex)
    committed_until: int = 0
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)


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
        existing = self._find_identical(context.candidates, candidate)
        if existing is not None:
            existing.metadata = merge_metadata(existing.metadata, candidate.metadata)
            existing.label_clue_ids |= candidate.label_clue_ids
            context.handled_label_clue_ids |= candidate.label_clue_ids
            return
        context.candidates.append(candidate)
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

    def _find_identical(self, candidates: list[CandidateDraft], candidate: CandidateDraft) -> CandidateDraft | None:
        for existing in candidates:
            if (
                existing.attr_type == candidate.attr_type
                and existing.unit_start == candidate.unit_start
                and existing.unit_end == candidate.unit_end
                and existing.start == candidate.start
                and existing.end == candidate.end
                and existing.text == candidate.text
            ):
                return existing
        return None

    def _next_unconsumed_index(self, clues: tuple[Clue, ...], start_index: int, consumed_ids: set[str]) -> int | None:
        for index in range(start_index, len(clues)):
            clue = clues[index]
            if clue.clue_id in consumed_ids or _is_control_clue(clue):
                continue
            return index
        return None
