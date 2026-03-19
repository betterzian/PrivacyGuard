"""领域模型聚合导出。"""

from privacyguard.domain.models.action import RestoredSlot
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.decision_context import (
    CandidateDecisionFeatures,
    DecisionContext,
    PageDecisionFeatures,
    PersonaDecisionFeatures,
)
from privacyguard.domain.models.mapping import ReplacementRecord, SessionBinding, TurnMappingSnapshot
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock, PolygonPoint
from privacyguard.domain.models.persona import PersonaProfile, PersonaSlotValue
from privacyguard.domain.models.pii import PIICandidate

__all__ = [
    "BoundingBox",
    "PolygonPoint",
    "OCRTextBlock",
    "PIICandidate",
    "PersonaProfile",
    "PersonaSlotValue",
    "ReplacementRecord",
    "SessionBinding",
    "TurnMappingSnapshot",
    "DecisionAction",
    "DecisionPlan",
    "PageDecisionFeatures",
    "CandidateDecisionFeatures",
    "PersonaDecisionFeatures",
    "DecisionContext",
    "RestoredSlot",
]
