from typing import Any

from privacyguard.bootstrap.factories import _build_component, register_default_components
from privacyguard.bootstrap.mode_config import (
    DEFAULT_DECISION_MODE,
    DEFAULT_DETECTOR_MODE,
    normalize_decision_mode,
    normalize_detector_mode,
)
from privacyguard.bootstrap.registry import ComponentRegistry, create_default_registry
from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector

# 对外统一入口：默认值与归一化均来自 bootstrap.mode_config
__all__ = [
    "build_detector",
    "build_decision",
    "get_or_create_registry",
    "normalize_detector_mode",
    "normalize_decision_mode",
    "DEFAULT_DETECTOR_MODE",
    "DEFAULT_DECISION_MODE",
]


def get_or_create_registry(registry: ComponentRegistry | None = None) -> ComponentRegistry:
    """获取组件注册表；若未提供则创建并注册默认组件。"""
    work_registry = registry or create_default_registry()
    if not work_registry.ocr_providers:
        register_default_components(work_registry)
    return work_registry


def build_detector(
    detector_mode: str,
    registry: ComponentRegistry,
    detector_config: dict[str, Any] | None = None,
) -> PIIDetector:
    """根据 detector_mode 构建检测器实例。"""
    normalized_mode = normalize_detector_mode(detector_mode)
    return _build_component(registry.detector_modes, normalized_mode, "detector mode", detector_config)


def build_decision(
    decision_mode: str,
    registry: ComponentRegistry,
    persona_repo: PersonaRepository,
    mapping_table: MappingStore,
    decision_config: dict[str, Any] | None = None,
) -> DecisionEngine:
    """根据 decision_mode 构建决策引擎并注入共享依赖。"""
    normalized_mode = normalize_decision_mode(decision_mode)
    return _build_component(
        registry.decision_modes,
        normalized_mode,
        "decision mode",
        decision_config,
        injected_dependencies={"persona_repository": persona_repo, "mapping_store": mapping_table},
    )
