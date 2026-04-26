"""PrivacyGuard 项目包入口。"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from privacyguard.app.privacy_guard import PrivacyGuard
    from privacyguard.runtime.context import RuntimeContext

__all__ = ["PrivacyGuard", "bootstrap"]


def __getattr__(name: str):
    if name == "PrivacyGuard":
        from privacyguard.app.privacy_guard import PrivacyGuard

        return PrivacyGuard
    if name == "bootstrap":
        return bootstrap
    raise AttributeError(name)


def bootstrap(privacy_repository_path: str | None = None) -> "RuntimeContext":
    """长驻进程启动时调用一次，初始化全局 RuntimeContext 并预热 repo 索引。

    短任务也可不调用：``PrivacyGuard.__init__`` 在构造时会自动初始化（幂等）。
    """
    from privacyguard.infrastructure.pii.json_privacy_repository import (
        DEFAULT_PRIVACY_REPOSITORY_PATH,
        JsonPrivacyRepository,
    )
    from privacyguard.runtime.context import init_runtime_context

    repo = JsonPrivacyRepository(path=privacy_repository_path or DEFAULT_PRIVACY_REPOSITORY_PATH)
    return init_runtime_context(repo)
