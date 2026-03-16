"""启动与装配模块导出。"""

from privacyguard.bootstrap.registry import ComponentRegistry, create_default_registry

__all__ = [
    "ComponentRegistry",
    "create_default_registry",
]
