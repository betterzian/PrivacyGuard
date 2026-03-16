"""组件注册中心。"""

from dataclasses import dataclass, field
from typing import TypeVar

from privacyguard.domain.interfaces.decision_engine import DecisionEngine
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.interfaces.ocr_engine import OCREngine
from privacyguard.domain.interfaces.persona_repository import PersonaRepository
from privacyguard.domain.interfaces.pii_detector import PIIDetector
from privacyguard.domain.interfaces.rendering_engine import RenderingEngine
from privacyguard.domain.interfaces.restoration_module import RestorationModule

T = TypeVar("T")


@dataclass
class ComponentRegistry:
    """保存各模块模式标签到实现类的映射。"""

    ocr_providers: dict[str, type[OCREngine]] = field(default_factory=dict)
    detector_modes: dict[str, type[PIIDetector]] = field(default_factory=dict)
    decision_modes: dict[str, type[DecisionEngine]] = field(default_factory=dict)
    mapping_store_types: dict[str, type[MappingStore]] = field(default_factory=dict)
    persona_repository_types: dict[str, type[PersonaRepository]] = field(default_factory=dict)
    rendering_modes: dict[str, type[RenderingEngine]] = field(default_factory=dict)
    restoration_modes: dict[str, type[RestorationModule]] = field(default_factory=dict)

    def register_ocr_provider(self, name: str, impl: type[OCREngine]) -> None:
        """注册 OCR provider 实现类。"""
        self.ocr_providers[name] = impl

    def register_detector_mode(self, name: str, impl: type[PIIDetector]) -> None:
        """注册 PII detector 模式实现类。"""
        self.detector_modes[name] = impl

    def register_decision_mode(self, name: str, impl: type[DecisionEngine]) -> None:
        """注册 decision 模式实现类。"""
        self.decision_modes[name] = impl

    def register_mapping_store_type(self, name: str, impl: type[MappingStore]) -> None:
        """注册 mapping store 实现类。"""
        self.mapping_store_types[name] = impl

    def register_persona_repository_type(self, name: str, impl: type[PersonaRepository]) -> None:
        """注册 persona repository 实现类。"""
        self.persona_repository_types[name] = impl

    def register_rendering_mode(self, name: str, impl: type[RenderingEngine]) -> None:
        """注册 rendering 模式实现类。"""
        self.rendering_modes[name] = impl

    def register_restoration_mode(self, name: str, impl: type[RestorationModule]) -> None:
        """注册 restoration 模式实现类。"""
        self.restoration_modes[name] = impl


def create_default_registry() -> ComponentRegistry:
    """创建空注册表，供工厂按需填充默认占位实现。"""
    return ComponentRegistry()

