"""应用服务导出。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
    from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator
    from privacyguard.application.services.replacement_service import ReplacementService
    from privacyguard.application.services.resolver_service import CandidateResolverService
    from privacyguard.application.services.session_service import SessionService

__all__ = [
    "CandidateResolverService",
    "DecisionContextBuilder",
    "ReplacementService",
    "SessionPlaceholderAllocator",
    "SessionService",
]


def __getattr__(name: str):
    if name == "CandidateResolverService":
        from privacyguard.application.services.resolver_service import CandidateResolverService

        return CandidateResolverService
    if name == "DecisionContextBuilder":
        from privacyguard.application.services.decision_context_builder import DecisionContextBuilder

        return DecisionContextBuilder
    if name == "ReplacementService":
        from privacyguard.application.services.replacement_service import ReplacementService

        return ReplacementService
    if name == "SessionPlaceholderAllocator":
        from privacyguard.application.services.placeholder_allocator import SessionPlaceholderAllocator

        return SessionPlaceholderAllocator
    if name == "SessionService":
        from privacyguard.application.services.session_service import SessionService

        return SessionService
    raise AttributeError(name)
