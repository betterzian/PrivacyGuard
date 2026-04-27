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
    # 组件真实承担的行政层级（按 rank 降序的字符串元组）。
    # 单层 component 为 ("road",) / ("province",) 等；
    # MULTI_ADMIN 为 ("province", "city") 等按 rank 降序排列；
    # 非地址/未提供 trace 时保持空元组。
    level: tuple[str, ...] = ()
    value: str | tuple[str, ...]
    key: str | tuple[str, ...] = ""
    levels: tuple[str, ...] = Field(default_factory=tuple)
    suspected: tuple[NormalizedAddressSuspectEntry, ...] = Field(default_factory=tuple)
    # 占位符 display 用短码，取值之一："prov" / "city" / "dist" / "road" / "dtl" / ""。
    # - 由 canonical 侧 component_type + level 推导，仅影响 SPEC 生成，不参与 same_address 判定。
    # - POSTAL_CODE 等不展示的层级保持空串。
    # - MULTI_ADMIN 取 level 元组中 rank 最低的层级映射（典型"北京" → "city"）。
    display_level: str = ""


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
    # 地址专属：预计算标志——是否存在可判定"行政层级"的组件
    # （province / city / district / district_city；subdistrict 偏 detail 不计入）。
    # 在 _normalize_address 构造时基于 ordered_components 的 level 计算。
    has_admin_static: bool = False


__all__ = [
    "NormalizedAddressComponent",
    "NormalizedAddressSuspectEntry",
    "NormalizedPII",
]
