"""新地址子系统。"""

from privacyguard.infrastructure.pii.address.lexicon import collect_components
from privacyguard.infrastructure.pii.address.types import AddressComponent, AddressToken

__all__ = [
    "AddressComponent",
    "AddressToken",
    "collect_components",
]
