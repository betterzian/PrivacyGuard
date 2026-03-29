"""新地址子系统的核心数据结构。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AddressComponent:
    component_type: str
    text: str
    start: int
    end: int
    value_text: str
    value_start: int
    value_end: int
    key_text: str
    key_start: int
    key_end: int
    is_detail: bool = False


@dataclass(frozen=True, slots=True)
class AddressToken:
    component_type: str
    token_role: str
    text: str
    start: int
    end: int
