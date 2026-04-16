"""跨栈冲突裁决。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.candidate_utils import has_organization_suffix, trim_candidate
from privacyguard.infrastructure.pii.detector.models import CandidateDraft, ClaimStrength, StreamInput
from privacyguard.infrastructure.pii.detector.stacks.common import _unit_char_end, _unit_char_start


@dataclass(slots=True)
class ConflictOutcome:
    incoming: CandidateDraft | None
    drop_existing: bool = False
    replace_existing: CandidateDraft | None = None


class StackManager:
    """非 NAME 冲突的通用裁决器。"""

    def score(self, candidate: CandidateDraft) -> float:
        score = 0.0
        if candidate.claim_strength == ClaimStrength.HARD:
            score += 0.4
            score += 0.02 * _candidate_hard_source_rank(candidate)
        if candidate.source_kind.startswith("dictionary_"):
            score += 0.25
        elif candidate.label_driven:
            score += 0.08
        return score

    def resolve_conflict(self, context, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if existing.attr_type == incoming.attr_type:
            return self._resolve_same_attr(existing, incoming)
        if existing.claim_strength == ClaimStrength.HARD and incoming.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream, incoming, existing)
            return ConflictOutcome(incoming=trimmed)
        if incoming.claim_strength == ClaimStrength.HARD and existing.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream, existing, incoming)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        attr_pair = frozenset({existing.attr_type, incoming.attr_type})
        if attr_pair == {PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION}:
            return self._resolve_address_organization(context.stream, existing, incoming)
        return self._resolve_by_score(existing, incoming)

    def _resolve_same_attr(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        if (incoming.unit_end - incoming.unit_start) > (existing.unit_end - existing.unit_start):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _resolve_address_organization(self, stream: StreamInput, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        if not has_organization_suffix(organization.text):
            return self._resolve_by_score(existing, incoming)
        if organization is incoming:
            trimmed = self._trim_candidate(stream, address, organization)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = self._trim_candidate(stream, address, organization)
        return ConflictOutcome(incoming=trimmed)

    def _resolve_by_score(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _trim_candidate(self, stream: StreamInput, candidate: CandidateDraft, blocker: CandidateDraft) -> CandidateDraft | None:
        if blocker.unit_start <= candidate.unit_start and blocker.unit_end >= candidate.unit_end:
            return None
        if blocker.unit_start <= candidate.unit_start:
            next_unit_start, next_unit_end = blocker.unit_end, candidate.unit_end
        else:
            next_unit_start, next_unit_end = candidate.unit_start, blocker.unit_start
        return trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, next_unit_start),
            end=_unit_char_end(stream, next_unit_end),
            unit_start=next_unit_start,
            unit_end=next_unit_end,
        )


def _candidate_hard_source_rank(candidate: CandidateDraft) -> int:
    values = candidate.metadata.get("hard_source")
    if not values:
        return 0
    source = str(values[0])
    return {"session": 4, "local": 3, "prompt": 2, "regex": 1}.get(source, 0)
