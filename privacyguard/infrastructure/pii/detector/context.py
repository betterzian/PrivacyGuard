"""检测上下文，承载单次 detect 调用的全局状态。

替代原先模块级全局 _clue_id_seq，同时统一挂载 protection_level、
detector_overrides、session 信息等，避免到处传参。
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel


@dataclass(slots=True)
class DetectContext:
    """单次 detect 调用的上下文容器。

    每次 RuleBasedPIIDetector.detect() 创建一个实例，
    贯穿 scan → parse → ocr geometry → finalize 全流程。
    """

    protection_level: ProtectionLevel = ProtectionLevel.STRONG
    detector_overrides: dict[PIIAttributeType | str, float] | None = None
    session_id: str | None = None
    turn_id: int | None = None
    _counter: itertools.count = field(default_factory=itertools.count, repr=False)

    def next_clue_id(self) -> str:
        """生成本次 detect 内唯一的 clue 编号。"""
        return f"clue-{next(self._counter)}"
