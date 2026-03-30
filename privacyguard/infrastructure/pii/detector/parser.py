"""Clean single-main-stack parser."""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, Claim, ClaimStrength, Clue, ClueBundle, ClueFamily, ParseResult, StreamInput
from privacyguard.infrastructure.pii.detector.stacks import (
    AddressStack,
    BaseStack,
    ConflictOutcome,
    NameStack,
    OrganizationStack,
    StackManager,
    StackRun,
    StructuredValueStack,
)

_STACK_REGISTRY = {
    ClueFamily.STRUCTURED: StructuredValueStack,
    ClueFamily.ADDRESS: AddressStack,
    ClueFamily.NAME: NameStack,
    ClueFamily.ORGANIZATION: OrganizationStack,
}


@dataclass(slots=True)
class StackContext:
    stream: StreamInput
    locale_profile: str
    clues: tuple[Clue, ...] = ()
    committed_until: int = 0
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_clue_ids: set[str] = field(default_factory=set)


class StreamParser:
    def __init__(self, *, locale_profile: str) -> None:
        self.locale_profile = locale_profile
        self.stack_manager = StackManager()

    def parse(self, stream: StreamInput, bundle: ClueBundle) -> ParseResult:
        context = StackContext(
            stream=stream,
            locale_profile=self.locale_profile,
            clues=bundle.all_clues,
        )
        consumed_ids: set[str] = set()
        index = 0
        while index < len(context.clues):
            clue = context.clues[index]
            if clue.clue_id in consumed_ids or clue.family == ClueFamily.BREAK:
                index += 1
                continue
            current = self._run_stack(context, index)
            if current is None:
                index += 1
                continue
            consumed_ids |= current.consumed_ids
            next_index = self._next_unconsumed_index(context.clues, current.next_index, consumed_ids)
            challenger = None
            if next_index is not None:
                next_clue = context.clues[next_index]
                if next_clue.family not in {ClueFamily.BREAK, current.family}:
                    challenger = self._run_stack(context, next_index)
            if challenger is not None:
                if challenger.candidate.start < current.candidate.end:
                    consumed_ids |= challenger.consumed_ids
                    self._apply_conflict(context, current, challenger)
                    index = self._next_unconsumed_index(context.clues, max(current.next_index, challenger.next_index), consumed_ids) or len(context.clues)
                    continue
            self._commit_run(context, current)
            index = self._next_unconsumed_index(context.clues, current.next_index, consumed_ids) or len(context.clues)
        return ParseResult(
            candidates=context.candidates,
            claims=context.claims,
            handled_label_clue_ids=context.handled_label_clue_ids,
        )

    def _run_stack(self, context: StackContext, index: int) -> StackRun | None:
        clue = context.clues[index]
        stack_cls = _STACK_REGISTRY.get(clue.family)
        if stack_cls is None:
            return None
        stack: BaseStack = stack_cls(clue=clue, clue_index=index, context=context)
        run = stack.run()
        if run is None or not run.candidate.text.strip():
            return None
        return run

    def _apply_conflict(self, context: StackContext, current: StackRun, challenger: StackRun) -> None:
        outcome = self.stack_manager.resolve_conflict(context, current.candidate, challenger.candidate)
        if not outcome.drop_existing:
            if outcome.replace_existing is not None:
                self._commit_candidate(context, outcome.replace_existing)
            else:
                self._commit_candidate(context, current.candidate)
        if outcome.incoming is not None:
            self._commit_candidate(context, outcome.incoming)
        context.handled_label_clue_ids |= current.handled_label_clue_ids
        context.handled_label_clue_ids |= challenger.handled_label_clue_ids

    def _commit_run(self, context: StackContext, run: StackRun) -> None:
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
        context.committed_until = max(context.committed_until, candidate.end)

    def _find_identical(self, candidates: list[CandidateDraft], candidate: CandidateDraft) -> CandidateDraft | None:
        for existing in candidates:
            if (
                existing.attr_type == candidate.attr_type
                and existing.start == candidate.start
                and existing.end == candidate.end
                and existing.text == candidate.text
            ):
                return existing
        return None

    def _next_unconsumed_index(self, clues: tuple[Clue, ...], start_index: int, consumed_ids: set[str]) -> int | None:
        for index in range(start_index, len(clues)):
            if clues[index].clue_id not in consumed_ids:
                return index
        return None
