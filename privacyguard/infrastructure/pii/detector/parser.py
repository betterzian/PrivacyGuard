"""新 detector 主链的左到右流式解析与冲突裁决。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, Claim, ClaimStrength, EventBundle, EventKind, ParseResult, StreamEvent, StreamInput
from privacyguard.infrastructure.pii.detector.stacks import (
    AddressStack,
    NameStack,
    OrganizationStack,
    StructuredValueStack,
    has_organization_suffix,
    name_component_hint,
    rebuild_candidate_from_span,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

_STACK_REGISTRY = {
    "structured": StructuredValueStack,
    "address": AddressStack,
    "organization": OrganizationStack,
    "name": NameStack,
}


@dataclass(slots=True)
class StackContext:
    stream: StreamInput
    bundle: EventBundle
    locale_profile: str
    min_confidence_by_attr: dict[PIIAttributeType, float]
    events: tuple[StreamEvent, ...]
    commit_cursor: int = 0
    candidates: list[CandidateDraft] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    handled_label_ids: set[str] = field(default_factory=set)

    def next_boundary(self, start: int, *, ignore_event_id: str | None = None) -> int:
        boundary = len(self.stream.raw_text)
        for event in self.events:
            if event.event_id == ignore_event_id:
                continue
            if event.start <= start:
                continue
            if event.kind in {EventKind.HARD_VALUE, EventKind.LABEL}:
                boundary = min(boundary, event.start)
                break
        break_index = self.stream.raw_text.find(_OCR_SEMANTIC_BREAK_TOKEN, start, boundary)
        if break_index >= 0:
            boundary = min(boundary, break_index)
        return boundary


@dataclass(slots=True)
class ConflictOutcome:
    incoming: CandidateDraft | None
    drop_existing: bool = False
    replace_existing: CandidateDraft | None = None


@dataclass(slots=True)
class StackProposal:
    """由单个事件派生出的栈提案。"""

    stack_id: str
    event: StreamEvent
    primary: CandidateDraft
    nested: list[CandidateDraft] = field(default_factory=list)

    @property
    def attr_type(self) -> PIIAttributeType:
        return self.primary.attr_type

    @property
    def start(self) -> int:
        return self.primary.start

    @property
    def end(self) -> int:
        return self.primary.end


@dataclass(slots=True)
class ActiveStackState:
    """当前未决窗口的活跃栈状态。"""

    stack_id: str
    event: StreamEvent
    primary: CandidateDraft
    nested: list[CandidateDraft] = field(default_factory=list)
    safe_commit_end: int = 0

    @property
    def attr_type(self) -> PIIAttributeType:
        return self.primary.attr_type

    @property
    def start(self) -> int:
        return self.primary.start

    @property
    def end(self) -> int:
        return self.primary.end


class StackManager:
    def score(self, candidate: CandidateDraft) -> float:
        score = candidate.confidence
        if candidate.claim_strength == ClaimStrength.HARD:
            score += 0.2
            score += 0.03 * _candidate_hard_source_rank(candidate)
        if candidate.matched_by.startswith("dictionary_"):
            score += 0.2
        elif candidate.matched_by.startswith("context_") or candidate.matched_by.startswith("ocr_label_"):
            score += 0.08
        elif candidate.matched_by.startswith("regex_"):
            score += 0.05
        if candidate.attr_type == PIIAttributeType.DETAILS:
            score -= 0.05
        return score

    def _accept(self, context: StackContext, candidate: CandidateDraft, *, owner_stack_id: str) -> None:
        existing = _find_identical_candidate(context.candidates, candidate)
        if existing is not None:
            existing.confidence = max(existing.confidence, candidate.confidence)
            existing.metadata = _merge_metadata(existing.metadata, candidate.metadata)
            existing.label_event_ids |= candidate.label_event_ids
            context.handled_label_ids |= candidate.label_event_ids
            return
        context.candidates.append(candidate)
        context.claims.append(
            Claim(
                start=candidate.start,
                end=candidate.end,
                attr_type=candidate.attr_type,
                strength=candidate.claim_strength,
                owner_stack_id=owner_stack_id,
            )
        )
        context.handled_label_ids |= candidate.label_event_ids

    def resolve_conflict(self, context: StackContext, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if _can_keep_nested_pair(existing, incoming):
            return ConflictOutcome(incoming=incoming)
        if existing.attr_type == incoming.attr_type:
            return self._resolve_same_attr(existing, incoming)
        if existing.claim_strength == ClaimStrength.HARD and incoming.claim_strength == ClaimStrength.HARD:
            return self._resolve_hard_hard(existing, incoming)
        if existing.claim_strength == ClaimStrength.HARD and incoming.claim_strength != ClaimStrength.HARD:
            return ConflictOutcome(incoming=self._trim_candidate(context, incoming, existing, preferred_side="left"))
        if incoming.claim_strength == ClaimStrength.HARD and existing.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context, existing, incoming, preferred_side="left")
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        attr_pair = frozenset({existing.attr_type, incoming.attr_type})
        if attr_pair == {PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION}:
            return self._resolve_address_organization(context, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
            return self._resolve_name_organization(context, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ADDRESS}:
            return self._resolve_name_address(context, existing, incoming)
        return self._resolve_by_score(existing, incoming)

    def _resolve_hard_hard(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        existing_length = _candidate_effective_length(existing)
        incoming_length = _candidate_effective_length(incoming)
        if incoming_length > existing_length:
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        if incoming_length < existing_length:
            return ConflictOutcome(incoming=None)
        if _candidate_hard_source_rank(incoming) > _candidate_hard_source_rank(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _resolve_same_attr(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if _can_keep_same_attr_nested(existing, incoming):
            return ConflictOutcome(incoming=incoming)
        incoming_score = self.score(incoming)
        existing_score = self.score(existing)
        incoming_length = _candidate_effective_length(incoming)
        existing_length = _candidate_effective_length(existing)
        if incoming_length > existing_length and incoming_score >= existing_score - 0.02:
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        if incoming_score > existing_score + 0.02:
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _resolve_address_organization(
        self,
        context: StackContext,
        existing: CandidateDraft,
        incoming: CandidateDraft,
    ) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        organization_strong = has_organization_suffix(organization.text) or _is_organization_label_driven(organization)
        if not organization_strong:
            return self._resolve_by_score(existing, incoming)
        if organization is incoming:
            trimmed_address = self._trim_candidate(context, address, organization, preferred_side="left")
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed_address is None, replace_existing=trimmed_address)
        trimmed_address = self._trim_candidate(context, address, organization, preferred_side="left")
        return ConflictOutcome(incoming=trimmed_address)

    def _resolve_name_organization(
        self,
        context: StackContext,
        existing: CandidateDraft,
        incoming: CandidateDraft,
    ) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        organization_strong = has_organization_suffix(organization.text) or _is_organization_label_driven(organization)
        if not organization_strong:
            return ConflictOutcome(incoming=incoming if incoming.attr_type == PIIAttributeType.NAME else None)
        if organization is incoming:
            trimmed_name = self._trim_name_for_organization(context, name, organization)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed_name is None, replace_existing=trimmed_name)
        trimmed_name = self._trim_name_for_organization(context, name, organization)
        return ConflictOutcome(incoming=trimmed_name)

    def _resolve_name_address(
        self,
        context: StackContext,
        existing: CandidateDraft,
        incoming: CandidateDraft,
    ) -> ConflictOutcome:
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        if name is incoming:
            return ConflictOutcome(incoming=self._trim_candidate(context, name, address, preferred_side=None))
        trimmed_name = self._trim_candidate(context, name, address, preferred_side=None)
        return ConflictOutcome(incoming=incoming, drop_existing=trimmed_name is None, replace_existing=trimmed_name)

    def _resolve_by_score(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        overlap_ratio = _overlap_ratio(existing, incoming)
        if existing.attr_type != incoming.attr_type and overlap_ratio < 0.45:
            return ConflictOutcome(incoming=incoming)
        incoming_score = self.score(incoming)
        existing_score = self.score(existing)
        if incoming_score > existing_score + 0.02:
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _trim_name_for_organization(
        self,
        context: StackContext,
        name: CandidateDraft,
        organization: CandidateDraft,
    ) -> CandidateDraft | None:
        suffix_index = _organization_suffix_absolute_start(organization)
        boundary = organization.start if suffix_index is None else suffix_index
        if name.start >= boundary:
            return None
        return rebuild_candidate_from_span(name, context.stream.raw_text, start=name.start, end=min(name.end, boundary))

    def _trim_candidate(
        self,
        context: StackContext,
        candidate: CandidateDraft,
        blocker: CandidateDraft,
        *,
        preferred_side: str | None,
    ) -> CandidateDraft | None:
        options: list[tuple[str, CandidateDraft]] = []
        if candidate.start < blocker.start:
            rebuilt = rebuild_candidate_from_span(candidate, context.stream.raw_text, start=candidate.start, end=blocker.start)
            if rebuilt is not None:
                options.append(("left", rebuilt))
        if blocker.end < candidate.end:
            rebuilt = rebuild_candidate_from_span(candidate, context.stream.raw_text, start=blocker.end, end=candidate.end)
            if rebuilt is not None:
                options.append(("right", rebuilt))
        if not options:
            return None
        if preferred_side is not None:
            options.sort(
                key=lambda item: (
                    item[0] == preferred_side,
                    self.score(item[1]),
                    _candidate_effective_length(item[1]),
                ),
                reverse=True,
            )
            return options[0][1]
        return max(options, key=lambda item: (self.score(item[1]), _candidate_effective_length(item[1])))[1]


class StreamParser:
    def __init__(self, *, locale_profile: str, min_confidence_by_attr: dict[PIIAttributeType, float] | None = None) -> None:
        self.locale_profile = locale_profile
        self.min_confidence_by_attr = dict(min_confidence_by_attr or {})
        self.stack_manager = StackManager()

    def parse(self, stream: StreamInput, bundle: EventBundle) -> ParseResult:
        context = StackContext(
            stream=stream,
            bundle=bundle,
            locale_profile=self.locale_profile,
            min_confidence_by_attr=self.min_confidence_by_attr,
            events=bundle.all_events,
        )
        proposals = self._build_proposals(context)
        current: ActiveStackState | None = None
        for proposal in proposals:
            if proposal.end <= context.commit_cursor:
                continue
            if current is None:
                current = self._activate_proposal(proposal)
                continue
            if proposal.attr_type == current.attr_type:
                current = self._merge_same_attr_state(current, proposal)
                continue
            if proposal.start >= current.end:
                self._commit_state(context, current)
                current = self._activate_proposal(proposal)
                continue
            current = self._resolve_state_conflict(context, current, proposal)
        if current is not None:
            self._commit_state(context, current)
        return ParseResult(
            candidates=context.candidates,
            claims=context.claims,
            handled_label_ids=context.handled_label_ids,
        )

    def _build_proposals(self, context: StackContext) -> list[StackProposal]:
        proposals: list[StackProposal] = []
        for event in context.bundle.all_events:
            stack_cls = _STACK_REGISTRY.get(event.stack_kind)
            if stack_cls is None:
                continue
            stack = stack_cls(event=event, context=context, stack_id=f"{event.stack_kind}:{event.event_id}")
            extracted = [replace(candidate) for candidate in stack.extract() if self._candidate_allowed(context, candidate)]
            proposal = self._proposal_from_event(stack.stack_id, event, extracted)
            if proposal is None:
                continue
            proposals.append(proposal)
        return sorted(
            proposals,
            key=lambda item: (
                item.primary.start,
                item.event.start,
                -self.stack_manager.score(item.primary),
                -(item.primary.end - item.primary.start),
            ),
        )

    def _candidate_allowed(self, context: StackContext, candidate: CandidateDraft) -> bool:
        threshold = context.min_confidence_by_attr.get(candidate.attr_type, 0.0)
        return candidate.confidence >= threshold and bool(candidate.text.strip())

    def _proposal_from_event(
        self,
        stack_id: str,
        event: StreamEvent,
        extracted: list[CandidateDraft],
    ) -> StackProposal | None:
        if not extracted:
            return None
        primary = max(
            extracted,
            key=lambda item: (
                item.attr_type != PIIAttributeType.DETAILS,
                self.stack_manager.score(item),
                item.end - item.start,
            ),
        )
        nested = [candidate for candidate in extracted if candidate is not primary]
        nested = sorted(
            nested,
            key=lambda item: (
                item.start,
                item.end,
                item.attr_type.value,
            ),
        )
        return StackProposal(
            stack_id=stack_id,
            event=event,
            primary=primary,
            nested=nested,
        )

    def _activate_proposal(self, proposal: StackProposal) -> ActiveStackState:
        nested = self._normalize_nested_for_primary(proposal.primary, proposal.nested)
        return ActiveStackState(
            stack_id=proposal.stack_id,
            event=proposal.event,
            primary=proposal.primary,
            nested=nested,
            safe_commit_end=proposal.primary.start,
        )

    def _merge_same_attr_state(self, current: ActiveStackState, proposal: StackProposal) -> ActiveStackState:
        if _can_keep_same_attr_nested(current.primary, proposal.primary):
            merged_nested = self._merge_nested_candidates(current.nested, [proposal.primary, *proposal.nested], current.primary)
            return ActiveStackState(
                stack_id=current.stack_id,
                event=current.event,
                primary=current.primary,
                nested=merged_nested,
                safe_commit_end=current.safe_commit_end,
            )
        outcome = self.stack_manager._resolve_same_attr(current.primary, proposal.primary)
        next_primary = current.primary
        if outcome.incoming is not None and outcome.drop_existing:
            next_primary = outcome.incoming
        merged_nested = self._merge_nested_candidates(current.nested, proposal.nested, next_primary)
        return ActiveStackState(
            stack_id=current.stack_id if next_primary is current.primary else proposal.stack_id,
            event=current.event if next_primary is current.primary else proposal.event,
            primary=next_primary,
            nested=merged_nested,
            safe_commit_end=min(current.safe_commit_end, next_primary.start),
        )

    def _resolve_state_conflict(
        self,
        context: StackContext,
        current: ActiveStackState,
        proposal: StackProposal,
    ) -> ActiveStackState | None:
        outcome = self.stack_manager.resolve_conflict(context, current.primary, proposal.primary)
        surviving_current = None if outcome.drop_existing else (outcome.replace_existing or current.primary)
        surviving_challenger = outcome.incoming
        if surviving_current is not None and surviving_challenger is None:
            filtered_nested = self._merge_nested_candidates(current.nested, [], surviving_current)
            return ActiveStackState(
                stack_id=current.stack_id,
                event=current.event,
                primary=surviving_current,
                nested=filtered_nested,
                safe_commit_end=min(current.safe_commit_end, surviving_current.start),
            )
        if surviving_current is None and surviving_challenger is not None:
            return self._activate_proposal(
                StackProposal(
                    stack_id=proposal.stack_id,
                    event=proposal.event,
                    primary=surviving_challenger,
                    nested=proposal.nested,
                )
            )
        if surviving_current is not None and surviving_challenger is not None:
            committed_state = ActiveStackState(
                stack_id=current.stack_id,
                event=current.event,
                primary=surviving_current,
                nested=self._merge_nested_candidates(current.nested, [], surviving_current),
                safe_commit_end=surviving_current.start,
            )
            self._commit_state(context, committed_state)
            return self._activate_proposal(
                StackProposal(
                    stack_id=proposal.stack_id,
                    event=proposal.event,
                    primary=surviving_challenger,
                    nested=proposal.nested,
                )
            )
        return None

    def _commit_state(self, context: StackContext, state: ActiveStackState) -> None:
        primary = replace(state.primary)
        self.stack_manager._accept(context, primary, owner_stack_id=state.stack_id)
        for nested in self._normalize_nested_for_primary(primary, state.nested):
            self.stack_manager._accept(context, replace(nested), owner_stack_id=state.stack_id)
        context.commit_cursor = max(context.commit_cursor, state.end)

    def _normalize_nested_for_primary(self, primary: CandidateDraft, nested: list[CandidateDraft]) -> list[CandidateDraft]:
        kept: list[CandidateDraft] = []
        for candidate in nested:
            if candidate.start < primary.start or candidate.end > primary.end:
                continue
            if candidate.attr_type == primary.attr_type and not _can_keep_same_attr_nested(primary, candidate):
                continue
            if candidate.attr_type != primary.attr_type and not _can_keep_nested_pair(primary, candidate):
                continue
            duplicate = _find_identical_candidate(kept, candidate)
            if duplicate is not None:
                duplicate.confidence = max(duplicate.confidence, candidate.confidence)
                duplicate.metadata = _merge_metadata(duplicate.metadata, candidate.metadata)
                duplicate.label_event_ids |= candidate.label_event_ids
                continue
            kept.append(candidate)
        return sorted(kept, key=lambda item: (item.start, item.end, item.attr_type.value))

    def _merge_nested_candidates(
        self,
        current_nested: list[CandidateDraft],
        incoming_nested: list[CandidateDraft],
        primary: CandidateDraft,
    ) -> list[CandidateDraft]:
        return self._normalize_nested_for_primary(primary, [*current_nested, *incoming_nested])


def _find_identical_candidate(candidates: list[CandidateDraft], incoming: CandidateDraft) -> CandidateDraft | None:
    for candidate in candidates:
        if (
            candidate.attr_type == incoming.attr_type
            and candidate.start == incoming.start
            and candidate.end == incoming.end
            and candidate.text == incoming.text
        ):
            return candidate
    return None


def _merge_metadata(left: dict[str, list[str]], right: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for source in (left, right):
        for key, values in source.items():
            merged[key] = list(dict.fromkeys([*merged.get(key, []), *values]))
    return merged


def _overlap(left: CandidateDraft, right: CandidateDraft) -> int:
    return max(0, min(left.end, right.end) - max(left.start, right.start))


def _overlap_ratio(left: CandidateDraft, right: CandidateDraft) -> float:
    overlap = _overlap(left, right)
    if overlap <= 0:
        return 0.0
    return overlap / float(min(left.end - left.start, right.end - right.start))


def _candidate_effective_length(candidate: CandidateDraft) -> int:
    compact = "".join(char for char in candidate.text if not char.isspace())
    return len(compact) or max(0, candidate.end - candidate.start)


def _candidate_hard_source_rank(candidate: CandidateDraft) -> int:
    values = candidate.metadata.get("hard_source", [])
    if not values:
        return 0
    source = str(values[0])
    if source == "session":
        return 4
    if source == "local":
        return 3
    if source == "prompt":
        return 2
    if source == "regex":
        return 1
    return 0


def _can_keep_same_attr_nested(existing: CandidateDraft, incoming: CandidateDraft) -> bool:
    if PIIAttributeType.DETAILS in {existing.attr_type, incoming.attr_type}:
        return True
    if existing.attr_type == PIIAttributeType.ADDRESS and incoming.attr_type == PIIAttributeType.ADDRESS:
        return existing.matched_by.startswith("address_component_") or incoming.matched_by.startswith("address_component_")
    if existing.attr_type == PIIAttributeType.NAME and incoming.attr_type == PIIAttributeType.NAME:
        existing_component = name_component_hint(existing)
        incoming_component = name_component_hint(incoming)
        if existing_component != incoming_component and "full" in {existing_component, incoming_component}:
            return True
    return False


def _can_keep_nested_pair(existing: CandidateDraft, incoming: CandidateDraft) -> bool:
    attr_pair = {existing.attr_type, incoming.attr_type}
    if attr_pair == {PIIAttributeType.ADDRESS, PIIAttributeType.DETAILS}:
        return True
    return False


def _is_organization_label_driven(candidate: CandidateDraft) -> bool:
    return candidate.matched_by.startswith("context_organization") or candidate.matched_by.startswith("ocr_label_organization")


def _organization_suffix_absolute_start(candidate: CandidateDraft) -> int | None:
    lowered = candidate.text
    suffix_patterns = (
        "股份有限公司",
        "有限责任公司",
        "有限公司",
        "研究院",
        "实验室",
        "工作室",
        "事务所",
        "公司",
        "集团",
        "大学",
        "学院",
        "银行",
        "酒店",
        "医院",
        "中心",
        "incorporated",
        "corporation",
        "company",
        "limited",
        "inc",
        "corp",
        "co",
        "ltd",
        "llc",
        "plc",
        "gmbh",
        "pte",
        "bank",
        "hotel",
        "hospital",
        "clinic",
        "university",
        "college",
        "lab",
        "labs",
    )
    text_lower = lowered.lower()
    earliest: int | None = None
    for pattern in suffix_patterns:
        index = text_lower.find(pattern.lower())
        if index < 0:
            continue
        if earliest is None or index < earliest:
            earliest = index
    if earliest is None:
        return None
    return candidate.start + earliest

