"""新地址子系统的核心数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field

from privacyguard.infrastructure.pii.detector.models import AddressComponentType, Clue


@dataclass(frozen=True, slots=True)
class AddressSuspectEntry:
    """地址组件上的疑似行政子组件。"""

    level: str
    value: str
    key: str = ""
    origin: str = "value"


@dataclass(frozen=True, slots=True)
class AddressComponent:
    """地址组件。

    - value / key 对 POI 类型可能为 list[str]。
    - raw_chain 保存主循环中被链式吸收的原始 clue。
    - suspected 由 fixup 阶段填充的疑似行政层级信息。
    """

    component_type: AddressComponentType
    start: int
    end: int
    value: str | list[str]
    key: str | list[str]
    is_detail: bool = False
    raw_chain: tuple[Clue, ...] = ()
    suspected: tuple[AddressSuspectEntry, ...] = field(default_factory=tuple)
