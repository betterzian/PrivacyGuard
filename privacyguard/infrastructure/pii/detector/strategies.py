"""Stack 处理策略定义。

每个 ProtectionLevel 对应一组策略函数，注入到各 Stack 中控制：
- should_start: 是否基于当前 clue 开始构建 candidate draft。
- accept_clue: 是否接纳后续 clue 扩展已有 draft。

扫描层（scanner）对所有 level 产出完全相同的全量 clue；
差异化逻辑仅在此处体现，提交层统一直接 commit。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import Clue, ClueFamily, ClueRole


# ---------------------------------------------------------------------------
# 策略数据结构
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class StackStrategy:
    """单个 Stack 类型的行为策略。"""
    should_start: Callable[[Clue, _StrategyContext], bool]
    accept_clue: Callable[[Clue, _StrategyContext], bool]


@dataclass(frozen=True, slots=True)
class _StrategyContext:
    """策略函数可访问的只读上下文。

    从 StackContext 提取与策略决策相关的信号，
    避免策略函数直接依赖整个 StackContext。
    """
    has_preceding_label: bool
    locale_profile: str


# ---------------------------------------------------------------------------
# Structured（hard clue 类：email/phone/id 等）
# ---------------------------------------------------------------------------

def _structured_should_start_always(clue: Clue, _sctx: _StrategyContext) -> bool:
    """hard clue 或对应 label → 始终允许开始。"""
    return clue.role in {ClueRole.HARD, ClueRole.LABEL}


def _structured_accept_always(_clue: Clue, _sctx: _StrategyContext) -> bool:
    return True


# ---------------------------------------------------------------------------
# Name
# ---------------------------------------------------------------------------

def _name_should_start_strong(clue: Clue, _sctx: _StrategyContext) -> bool:
    """STRONG: surname / given_name / label / name_start 均可触发。"""
    return clue.role in {ClueRole.LABEL, ClueRole.START, ClueRole.SURNAME, ClueRole.GIVEN_NAME}


def _name_should_start_balanced(clue: Clue, sctx: _StrategyContext) -> bool:
    """BALANCED: label / name_start 可触发；单 surname / given_name 需有前方 label。"""
    if clue.role in {ClueRole.LABEL, ClueRole.START}:
        return True
    if clue.role in {ClueRole.SURNAME, ClueRole.GIVEN_NAME}:
        return sctx.has_preceding_label
    return False


def _name_should_start_weak(clue: Clue, _sctx: _StrategyContext) -> bool:
    """WEAK: 仅 label 触发。"""
    return clue.role == ClueRole.LABEL


def _name_accept_always(_clue: Clue, _sctx: _StrategyContext) -> bool:
    return True


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------

def _org_should_start_strong(clue: Clue, _sctx: _StrategyContext) -> bool:
    """STRONG: label 或 suffix 均可触发。"""
    return clue.role in {ClueRole.LABEL, ClueRole.SUFFIX}


def _org_should_start_balanced(clue: Clue, _sctx: _StrategyContext) -> bool:
    """BALANCED: 同 STRONG（公司后缀是强信号）。"""
    return clue.role in {ClueRole.LABEL, ClueRole.SUFFIX}


def _org_should_start_weak(clue: Clue, _sctx: _StrategyContext) -> bool:
    """WEAK: 仅 label 触发；suffix 需要 label 配合。"""
    return clue.role == ClueRole.LABEL


def _org_accept_always(_clue: Clue, _sctx: _StrategyContext) -> bool:
    return True


# ---------------------------------------------------------------------------
# Address
# ---------------------------------------------------------------------------

def _addr_should_start_strong(clue: Clue, _sctx: _StrategyContext) -> bool:
    """STRONG: label / value / key 均可触发地址构建。"""
    return clue.role in {ClueRole.LABEL, ClueRole.VALUE, ClueRole.KEY}


def _addr_should_start_balanced(clue: Clue, _sctx: _StrategyContext) -> bool:
    """BALANCED: label 或 value（地名 geo_db 命中）可触发；单 key 不行。"""
    return clue.role in {ClueRole.LABEL, ClueRole.VALUE}


def _addr_should_start_weak(clue: Clue, _sctx: _StrategyContext) -> bool:
    """WEAK: 仅 label 触发。"""
    return clue.role == ClueRole.LABEL


def _addr_accept_always(_clue: Clue, _sctx: _StrategyContext) -> bool:
    return True


# ---------------------------------------------------------------------------
# 注册表
# ---------------------------------------------------------------------------

STACK_STRATEGIES: dict[ProtectionLevel, dict[ClueFamily, StackStrategy]] = {
    ProtectionLevel.STRONG: {
        ClueFamily.STRUCTURED: StackStrategy(_structured_should_start_always, _structured_accept_always),
        ClueFamily.NAME: StackStrategy(_name_should_start_strong, _name_accept_always),
        ClueFamily.ORGANIZATION: StackStrategy(_org_should_start_strong, _org_accept_always),
        ClueFamily.ADDRESS: StackStrategy(_addr_should_start_strong, _addr_accept_always),
    },
    ProtectionLevel.BALANCED: {
        ClueFamily.STRUCTURED: StackStrategy(_structured_should_start_always, _structured_accept_always),
        ClueFamily.NAME: StackStrategy(_name_should_start_balanced, _name_accept_always),
        ClueFamily.ORGANIZATION: StackStrategy(_org_should_start_balanced, _org_accept_always),
        ClueFamily.ADDRESS: StackStrategy(_addr_should_start_balanced, _addr_accept_always),
    },
    ProtectionLevel.WEAK: {
        ClueFamily.STRUCTURED: StackStrategy(_structured_should_start_always, _structured_accept_always),
        ClueFamily.NAME: StackStrategy(_name_should_start_weak, _name_accept_always),
        ClueFamily.ORGANIZATION: StackStrategy(_org_should_start_weak, _org_accept_always),
        ClueFamily.ADDRESS: StackStrategy(_addr_should_start_weak, _addr_accept_always),
    },
}


def resolve_strategies(
    level: ProtectionLevel,
    overrides: dict | None = None,
) -> dict[ClueFamily, StackStrategy]:
    """根据 protection_level 和 overrides 返回最终策略集。"""
    strategies = dict(STACK_STRATEGIES.get(level, STACK_STRATEGIES[ProtectionLevel.STRONG]))
    # overrides 预留扩展点，当前暂无具体覆盖逻辑。
    return strategies


def build_strategy_context(
    *,
    has_preceding_label: bool,
    locale_profile: str,
) -> _StrategyContext:
    """构建策略函数所需的只读上下文。"""
    return _StrategyContext(
        has_preceding_label=has_preceding_label,
        locale_profile=locale_profile,
    )


__all__ = [
    "StackStrategy",
    "STACK_STRATEGIES",
    "build_strategy_context",
    "resolve_strategies",
]
