"""启动与装配模块导出。"""

from privacyguard.bootstrap.factories import create_facade, create_facade_from_file, load_config
from privacyguard.bootstrap.registry import ComponentRegistry, create_default_registry

__all__ = [
    "load_config",
    "create_facade",
    "create_facade_from_file",
    "ComponentRegistry",
    "create_default_registry",
]

