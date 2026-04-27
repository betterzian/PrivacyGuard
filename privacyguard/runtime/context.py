"""进程内 runtime 上下文。

`SessionPlaceholderAllocator` 三级查找链需要 `RepoEntityIndex` 才能命中 repo
路径；该索引由 `JsonPrivacyRepository.load_indexed_entities` 现场归一构建，
开销不低，长驻进程每次 sanitize 都重建会显著卡顿。

本模块提供：

- `RuntimeContext`：单进程单例上下文，懒加载并缓存 `RepoEntityIndex`；
- `init_runtime_context` / `get_runtime_context` / `clear_runtime_context`：
  对外初始化、读取与清理接口；
- 当 `JsonPrivacyRepository.merge_and_write` 落盘后，仓库会回调
  `invalidate_repo_index` 让缓存在下次取用时重建。

并发约定：单进程内多线程/异步直接函数调用即可；跨进程部署再加 RPC，本期不做。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 避免 runtime 包反向依赖 infrastructure 实例化时的循环。
    from privacyguard.infrastructure.pii.json_privacy_repository import (
        JsonPrivacyRepository,
        RepoEntityIndex,
    )


@dataclass(slots=True)
class RuntimeContext:
    """单进程内共享的运行时上下文。"""

    privacy_repository: "JsonPrivacyRepository"
    _repo_index_cache: "RepoEntityIndex | None" = field(default=None)
    _lock: RLock = field(default_factory=RLock)

    def get_repo_index(self) -> "RepoEntityIndex":
        """返回 repo entity 索引；首次调用时构建，之后命中缓存。"""
        with self._lock:
            if self._repo_index_cache is None:
                self._repo_index_cache = self.privacy_repository.load_indexed_entities()
            return self._repo_index_cache

    def invalidate_repo_index(self) -> None:
        """让 repo 索引缓存失效；下次 `get_repo_index` 时重建。"""
        with self._lock:
            self._repo_index_cache = None


_GLOBAL_CONTEXT: RuntimeContext | None = None
_GLOBAL_LOCK = RLock()


def init_runtime_context(
    privacy_repository: "JsonPrivacyRepository",
) -> RuntimeContext:
    """幂等初始化全局上下文；已初始化时返回旧实例。"""
    global _GLOBAL_CONTEXT
    with _GLOBAL_LOCK:
        if _GLOBAL_CONTEXT is None:
            _GLOBAL_CONTEXT = RuntimeContext(privacy_repository=privacy_repository)
        return _GLOBAL_CONTEXT


def get_runtime_context() -> RuntimeContext | None:
    """返回当前全局上下文；未初始化时返回 None。"""
    with _GLOBAL_LOCK:
        return _GLOBAL_CONTEXT


def clear_runtime_context() -> None:
    """重置全局上下文（仅供测试 / 重启场景使用）。"""
    global _GLOBAL_CONTEXT
    with _GLOBAL_LOCK:
        _GLOBAL_CONTEXT = None


__all__ = [
    "RuntimeContext",
    "clear_runtime_context",
    "get_runtime_context",
    "init_runtime_context",
]
