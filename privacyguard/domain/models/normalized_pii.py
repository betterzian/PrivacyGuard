"""统一 PII 归一结果模型。"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from privacyguard.domain.enums import PIIAttributeType


class NormalizedAddressSuspectEntry(BaseModel):
    """地址组件上的疑似行政子组件。"""

    model_config = ConfigDict(extra="forbid")

    levels: tuple[str, ...]
    value: str
    key: str = ""
    origin: str


class NormalizedAddressComponent(BaseModel):
    """地址组件级归一结果。"""

    model_config = ConfigDict(extra="forbid")

    component_type: str
    value: str | tuple[str, ...]
    key: str | tuple[str, ...] = ""
    levels: tuple[str, ...] = Field(default_factory=tuple)
    suspected: tuple[NormalizedAddressSuspectEntry, ...] = Field(default_factory=tuple)


class NormalizedPII(BaseModel):
    """承载统一 canonical、组件、匹配词与身份信息。"""

    model_config = ConfigDict(extra="forbid")

    attr_type: PIIAttributeType
    raw_text: str
    canonical: str = ""
    components: dict[str, str] = Field(default_factory=dict)
    match_terms: tuple[str, ...] = ()
    identity: dict[str, str] = Field(default_factory=dict)
    # 地址专属：从左到右提取的数字/字母序列（号/栋/单元/楼/室等 detail 层级）。
    # 用于同一地址判定时的逆序对齐匹配。
    numbers: tuple[str, ...] = ()
    # 地址专属：有明确 key 的数字，如 {"building": "10", "floor": "3", "room": "201"}。
    # 用于 keyed 比对路径——双方共有的 key 值必须相等，缺失的 key 忽略。
    keyed_numbers: dict[str, str] = Field(default_factory=dict)
    # 地址专属：按 detector/结构化输入顺序保存的组件级结果。
    ordered_components: tuple[NormalizedAddressComponent, ...] = Field(default_factory=tuple)


__all__ = [
    "NormalizedAddressComponent",
    "NormalizedAddressSuspectEntry",
    "NormalizedPII",
]
