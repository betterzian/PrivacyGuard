from __future__ import annotations

from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.pii.detector.models import (
    CandidateDraft,
    ClaimStrength,
    EventBundle,
    EventKind,
    OCRScene,
    OCRSceneBlock,
    StreamEvent,
    StreamInput,
)
from privacyguard.infrastructure.pii.detector.ocr import OCROwnershipProposal, _resolve_ownership_proposals
from privacyguard.infrastructure.pii.detector.parser import StackContext, StackManager
from privacyguard.infrastructure.pii.rule_based_detector import RuleBasedPIIDetector


def _find_candidate(candidates, attr_type: PIIAttributeType):
    for candidate in candidates:
        if candidate.attr_type == attr_type:
            return candidate
    return None


def _empty_bundle() -> EventBundle:
    return EventBundle(
        modified_text="",
        modified_to_raw=(),
        structured_events=(),
        dictionary_events=(),
        label_events=(),
        anchor_events=(),
        all_events=(),
    )


def _build_context(raw_text: str) -> StackContext:
    stream = StreamInput(
        source=PIISourceType.PROMPT,
        raw_text=raw_text,
        char_refs=(None,) * len(raw_text),
        spans=(),
    )
    return StackContext(
        stream=stream,
        bundle=_empty_bundle(),
        locale_profile="mixed",
        min_confidence_by_attr={},
        events=(),
    )


def _ocr_scene_block(
    *,
    text: str,
    block_id: str,
    x: int,
    y: int,
    order_index: int,
    line_index: int,
) -> OCRSceneBlock:
    return OCRSceneBlock(
        block=OCRTextBlock(
            text=text,
            block_id=block_id,
            bbox=BoundingBox(x=x, y=y, width=max(20, len(text) * 12), height=20),
        ),
        block_id=block_id,
        order_index=order_index,
        line_index=line_index,
        raw_start=0,
        raw_end=len(text),
    )


def test_label_label_prefers_longer_keyword_and_keeps_email_only() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="邮箱地址：alice@example.com",
        ocr_blocks=[],
    )

    email = _find_candidate(candidates, PIIAttributeType.EMAIL)

    assert email is not None
    assert email.text == "alice@example.com"
    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_hard_hard_prefers_session_over_prompt_and_regex_on_equal_length() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-email",
        1,
        [
            ReplacementRecord(
                session_id="session-email",
                turn_id=1,
                candidate_id="c-email",
                source_text="alice@example.com",
                canonical_source_text="alice@example.com",
                replacement_text="[EMAIL]",
                attr_type=PIIAttributeType.EMAIL,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    detector = RuleBasedPIIDetector(locale_profile="mixed", mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="邮箱地址：alice@example.com",
        ocr_blocks=[],
        session_id="session-email",
        turn_id=2,
    )

    email = _find_candidate(candidates, PIIAttributeType.EMAIL)

    assert email is not None
    assert email.text == "alice@example.com"
    assert email.metadata["matched_by"] == ["dictionary_session"]
    assert email.metadata["hard_source"] == ["session"]


def test_hard_hard_allows_longer_prompt_value_to_override_shorter_session_value() -> None:
    mapping_store = InMemoryMappingStore()
    mapping_store.save_replacements(
        "session-phone",
        1,
        [
            ReplacementRecord(
                session_id="session-phone",
                turn_id=1,
                candidate_id="c-phone",
                source_text="1380013800",
                canonical_source_text="1380013800",
                replacement_text="[PHONE]",
                attr_type=PIIAttributeType.PHONE,
                action_type=ActionType.GENERICIZE,
            )
        ],
    )
    detector = RuleBasedPIIDetector(locale_profile="mixed", mapping_store=mapping_store)

    candidates = detector.detect(
        prompt_text="手机号码：13800138000",
        ocr_blocks=[],
        session_id="session-phone",
        turn_id=2,
    )

    phone = _find_candidate(candidates, PIIAttributeType.PHONE)

    assert phone is not None
    assert phone.text == "13800138000"
    assert phone.metadata["hard_source"] == ["prompt"]


def test_hard_soft_boundary_stops_address_before_phone() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="家庭住址：上海市浦东新区世纪大道100号 13800138000",
        ocr_blocks=[],
    )

    address = _find_candidate(candidates, PIIAttributeType.ADDRESS)
    phone = _find_candidate(candidates, PIIAttributeType.PHONE)

    assert address is not None
    assert phone is not None
    assert address.text == "上海市浦东新区世纪大道100号"
    assert "13800138000" not in address.text


def test_same_attr_keeps_main_address_and_components() -> None:
    detector = RuleBasedPIIDetector(locale_profile="en_us")

    candidates = detector.detect(
        prompt_text="Address: 123 Main St Apt 4B, Springfield, IL 62704",
        ocr_blocks=[],
    )

    observed = {
        (candidate.attr_type, candidate.text)
        for candidate in candidates
        if candidate.attr_type in {PIIAttributeType.ADDRESS, PIIAttributeType.DETAILS}
    }

    assert (PIIAttributeType.ADDRESS, "123 Main St Apt 4B, Springfield, IL 62704") in observed
    assert (PIIAttributeType.ADDRESS, "123 Main St") in observed
    assert (PIIAttributeType.DETAILS, "Apt 4B") in observed


def test_address_organization_conflict_prefers_organization_suffix_path() -> None:
    detector = RuleBasedPIIDetector(locale_profile="mixed")

    candidates = detector.detect(
        prompt_text="浦东新区阳光科技有限公司",
        ocr_blocks=[],
    )

    organization = _find_candidate(candidates, PIIAttributeType.ORGANIZATION)

    assert organization is not None
    assert organization.text.endswith("有限公司")
    assert not any(candidate.attr_type == PIIAttributeType.ADDRESS for candidate in candidates)


def test_name_organization_conflict_trims_name_and_keeps_organization() -> None:
    context = _build_context("王伟工作室")
    manager = StackManager()
    existing_name = CandidateDraft(
        attr_type=PIIAttributeType.NAME,
        start=0,
        end=5,
        text="王伟工作室",
        source=PIISourceType.PROMPT,
        confidence=0.92,
        matched_by="context_name_field",
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": ["context_name_field"], "name_component": ["full"]},
    )
    incoming_organization = CandidateDraft(
        attr_type=PIIAttributeType.ORGANIZATION,
        start=0,
        end=5,
        text="王伟工作室",
        source=PIISourceType.PROMPT,
        confidence=0.78,
        matched_by="regex_organization_suffix",
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": ["regex_organization_suffix"]},
    )

    outcome = manager.resolve_conflict(context, existing_name, incoming_organization)

    assert outcome.incoming is not None
    assert outcome.incoming.attr_type == PIIAttributeType.ORGANIZATION
    assert outcome.incoming.text == "王伟工作室"
    assert outcome.replace_existing is not None
    assert outcome.replace_existing.attr_type == PIIAttributeType.NAME
    assert outcome.replace_existing.text == "王伟"
    assert not outcome.drop_existing


def test_name_address_conflict_drops_name_when_address_already_owns_span() -> None:
    context = _build_context("朝阳路")
    manager = StackManager()
    existing_address = CandidateDraft(
        attr_type=PIIAttributeType.ADDRESS,
        start=0,
        end=3,
        text="朝阳路",
        source=PIISourceType.PROMPT,
        confidence=0.9,
        matched_by="context_address_field",
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": ["context_address_field"], "address_kind": ["private_address"]},
    )
    incoming_name = CandidateDraft(
        attr_type=PIIAttributeType.NAME,
        start=0,
        end=2,
        text="朝阳",
        source=PIISourceType.PROMPT,
        confidence=0.76,
        matched_by="context_name_self_intro_zh",
        claim_strength=ClaimStrength.SOFT,
        metadata={"matched_by": ["context_name_self_intro_zh"], "name_component": ["full"]},
    )

    outcome = manager.resolve_conflict(context, existing_address, incoming_name)

    assert outcome.incoming is None
    assert not outcome.drop_existing
    assert outcome.replace_existing is None


def test_ocr_geometry_ownership_prefers_attribute_segment_owner() -> None:
    name_label = _ocr_scene_block(text="Name", block_id="label-name", x=0, y=0, order_index=0, line_index=0)
    organization_label = _ocr_scene_block(text="Company Name", block_id="label-org", x=0, y=40, order_index=0, line_index=1)
    shared_value = _ocr_scene_block(text="阳光科技有限公司", block_id="value-1", x=120, y=40, order_index=1, line_index=1)
    scene = OCRScene(
        blocks=(name_label, organization_label, shared_value),
        id_to_block={block.block_id: block for block in (name_label, organization_label, shared_value)},
        line_to_blocks={
            0: (name_label,),
            1: (organization_label, shared_value),
        },
    )
    proposals = [
        OCROwnershipProposal(
            event=StreamEvent(
                event_id="evt-name",
                kind=EventKind.LABEL,
                attr_type=PIIAttributeType.NAME,
                start=0,
                end=4,
                strength=ClaimStrength.SOFT,
                priority=200,
                stack_kind="name",
                matched_by="ocr_label_name_field",
                payload={"component_hint": "full"},
            ),
            label_block=name_label,
            candidate_blocks=(shared_value,),
        ),
        OCROwnershipProposal(
            event=StreamEvent(
                event_id="evt-org",
                kind=EventKind.LABEL,
                attr_type=PIIAttributeType.ORGANIZATION,
                start=0,
                end=12,
                strength=ClaimStrength.SOFT,
                priority=200,
                stack_kind="organization",
                matched_by="ocr_label_organization_field",
                payload={},
            ),
            label_block=organization_label,
            candidate_blocks=(shared_value,),
        ),
    ]

    resolved = _resolve_ownership_proposals(proposals)

    assert len(resolved) == 1
    assert resolved[0].event.attr_type == PIIAttributeType.ORGANIZATION
    assert resolved[0].candidate_blocks[0].block_id == "value-1"
