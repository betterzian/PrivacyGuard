"""Mapping 存储实现导出。"""

from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from privacyguard.infrastructure.mapping.json_mapping_store import JsonMappingStore

__all__ = ["InMemoryMappingStore", "JsonMappingStore"]

