"""Detector 的边界优先 stack 实现。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import (
    build_name_candidate_from_value,
    build_organization_candidate_from_value,
    clean_value,
    has_organization_suffix,
    name_component_hint,
    organization_suffix_start,
    trim_candidate,
)
from privacyguard.infrastructure.pii.detector.metadata import merge_metadata
from privacyguard.infrastructure.pii.detector.models import (
    AddressComponentType,
    CandidateDraft,
    ClaimStrength,
    Clue,
    ClueRole,
    NameComponentHint,
    StreamInput,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCR_INLINE_GAP_TOKEN,
    _OCR_SEMANTIC_BREAK_TOKEN,
    is_any_break,
    is_hard_break,
    is_name_joiner,
    is_soft_break,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _is_cjk as _shared_is_cjk,
)


# 地址组件层级（粗粒度）。
# 同一层内任意顺序；跨层允许回退 1 层（容忍跳级和轻微逆序）。
# 层级设计同时兼容中文（大→小）和英文（小→大）地址。
#
# 示例：
#   中文 "四川成都阳光小区"     → 省(T1) 市(T1) 小区(T2)           ✅ 跳过区级
#   中文 "上海，中国"          → 市(T1) 省(T1)                    ✅ 同层内逆序
#   英文 "123 Main St, NYC, NY" → 路(T2) 市(T1) 州(T1)           ✅ 回退 1 层
#   英文 "Portland, OR 97201"  → 市(T1) 州(T1) 邮编(T4)          ✅ 跳过 T2/T3

_TIER_ADMIN = 1       # 行政区划（省/市/区/州/县/镇/乡/村）
_TIER_STREET = 2      # 街道级（路/街/道/小区/大厦）
_TIER_DETAIL = 3      # 楼层详情（栋/单元/层/室）
_TIER_POSTAL = 4      # 邮编

_COMPONENT_TIER: dict[AddressComponentType, int] = {
    AddressComponentType.PROVINCE: _TIER_ADMIN,
    AddressComponentType.STATE: _TIER_ADMIN,
    AddressComponentType.CITY: _TIER_ADMIN,
    AddressComponentType.DISTRICT: _TIER_ADMIN,
    AddressComponentType.STREET_ADMIN: _TIER_ADMIN,
    AddressComponentType.TOWN: _TIER_ADMIN,
    AddressComponentType.VILLAGE: _TIER_ADMIN,
    AddressComponentType.ROAD: _TIER_STREET,
    AddressComponentType.STREET: _TIER_STREET,
    AddressComponentType.COMPOUND: _TIER_STREET,
    AddressComponentType.BUILDING: _TIER_DETAIL,
    AddressComponentType.UNIT: _TIER_DETAIL,
    AddressComponentType.FLOOR: _TIER_DETAIL,
    AddressComponentType.ROOM: _TIER_DETAIL,
    AddressComponentType.POSTAL_CODE: _TIER_POSTAL,
}

# 允许的最大层级回退幅度。1 表示允许从 TIER_STREET 回到 TIER_ADMIN。
_MAX_TIER_BACKTRACK = 1
_DETAIL_COMPONENTS = {
    AddressComponentType.BUILDING,
    AddressComponentType.UNIT,
    AddressComponentType.FLOOR,
    AddressComponentType.ROOM,
}
_PREFIX_EN_KEYWORDS = {"apt", "apartment", "suite", "ste", "unit", "#", "floor", "fl", "room", "rm"}


class StackContextLike(Protocol):
    stream: StreamInput
    locale_profile: str
    protection_level: ProtectionLevel
    clues: tuple[Clue, ...]


@dataclass(slots=True)
class StackRun:
    attr_type: PIIAttributeType
    candidate: CandidateDraft
    consumed_ids: set[str]
    handled_label_clue_ids: set[str] = field(default_factory=set)
    next_index: int = 0


@dataclass(slots=True)
class BaseStack:
    clue: Clue
    clue_index: int
    context: StackContextLike

    def run(self) -> StackRun | None:
        raise NotImplementedError

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """被更高优先级 candidate 抢占 [blocker_start, blocker_end) 后，尝试缩减自身候选。

        默认实现：用 trim_candidate 做文本级截断。
        子类可覆盖以提供更精确的语义级回缩。
        返回缩减后的 StackRun，或 None（缩减后无效，放弃）。
        """
        c = run.candidate
        stream = self.context.stream
        raw_text = stream.text
        if blocker_start <= c.unit_start:
            new_unit_start, new_unit_end = blocker_end, c.unit_end
        elif blocker_end >= c.unit_end:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        else:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        new_start = _unit_char_start(stream, new_unit_start)
        new_end = _unit_char_end(stream, new_unit_end)
        trimmed = trim_candidate(
            c,
            raw_text,
            start=new_start,
            end=new_end,
            unit_start=new_unit_start,
            unit_end=new_unit_end,
        )
        if trimmed is None:
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def _value_locale(self) -> str:
        """以栈即将处理的第一个字符判断语言。

        - LABEL / START / KEY 等引导型 seed → 跳过分隔符后看第一个字符。
        - FAMILY_NAME / GIVEN_NAME / VALUE / SUFFIX 等值型 seed → 看 seed 自身文本首字符。
        返回 "zh" 或 "en"。
        """
        raw_text = self.context.stream.text
        if self.clue.role in {ClueRole.LABEL, ClueRole.START, ClueRole.KEY}:
            pos = _skip_separators(raw_text, self.clue.end)
            if pos < len(raw_text) and "\u4e00" <= raw_text[pos] <= "\u9fff":
                return "zh"
            return "en"
        # 值型 seed：看自身文本首字符。
        text = self.clue.text
        if text and "\u4e00" <= text[0] <= "\u9fff":
            return "zh"
        return "en"

    def _build_hard_run(self) -> StackRun | None:
        if self.clue.attr_type is None:
            return None
        candidate = _build_hard_candidate(self.clue, self.context.stream.source)
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id},
            next_index=self.clue_index + 1,
        )

def is_break_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.BREAK


def is_negative_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.NEGATIVE


def is_connector_clue(clue: Clue) -> bool:
    return clue.role == ClueRole.CONNECTOR


def is_control_clue(clue: Clue) -> bool:
    return clue.attr_type is None


def _is_stop_control_clue(clue: Clue) -> bool:
    return clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR}


_NAME_COMPONENT_ROLES = frozenset(
    {
        ClueRole.FAMILY_NAME,
        ClueRole.GIVEN_NAME,
        ClueRole.FULL_NAME,
        ClueRole.ALIAS,
    }
)


@dataclass(slots=True)
class StructuredBaseStack(BaseStack):
    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()
        if self.clue.role != ClueRole.LABEL:
            return None
        hard_clue, hard_index = self._find_bound_hard_clue()
        if hard_clue is None:
            return None
        candidate = _build_hard_candidate(hard_clue, self.context.stream.source)
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata, {"bound_label_clue_ids": [self.clue.clue_id]})
        return StackRun(
            attr_type=candidate.attr_type,
            candidate=candidate,
            consumed_ids={self.clue.clue_id, hard_clue.clue_id},
            handled_label_clue_ids={self.clue.clue_id},
            next_index=hard_index + 1,
        )

    def _find_bound_hard_clue(self) -> tuple[Clue | None, int]:
        raw_text = self.context.stream.text
        cursor = self.clue.end
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if is_control_clue(clue):
                cursor = max(cursor, clue.end)
                continue
            gap_text = raw_text[cursor:clue.start]
            if gap_text and not all(ch.isspace() or is_soft_break(ch) for ch in gap_text):
                return (None, -1)
            if clue.role == ClueRole.HARD and clue.attr_type == self.clue.attr_type:
                return (clue, index)
            if clue.role in {ClueRole.LABEL, ClueRole.HARD} and clue.attr_type != self.clue.attr_type:
                return (None, -1)
            cursor = max(cursor, clue.end)
        return (None, -1)


class EmailStack(StructuredBaseStack):
    pass


class PhoneStack(StructuredBaseStack):
    pass


class IdNumberStack(StructuredBaseStack):
    pass


class CardNumberStack(StructuredBaseStack):
    pass


class BankAccountStack(StructuredBaseStack):
    pass


class PassportStack(StructuredBaseStack):
    pass


class DriverLicenseStack(StructuredBaseStack):
    pass


class NumericStack(StructuredBaseStack):
    pass


@dataclass(slots=True)
class NameStack(BaseStack):
    """姓名检测 stack。

    所有 seed 都先受通用边界约束，再按 seed 类型决定扩张方式。
    规则摘要：
    1. FULL_NAME / ALIAS 直接取 clue 自身值并结束。
    2. 中文 GIVEN_NAME 直接取 clue 自身值并结束。
    3. 英文 GIVEN_NAME 可向左补 1 个未被 clue 覆盖的普通单词，
       并按 given 链规则向右吸收后续 GIVEN_NAME。
    4. FAMILY_NAME / LABEL / START 从起点向右扫描；
       英文吞到 GIVEN_NAME 后，会切换到 GIVEN_NAME 的右扩逻辑。
    """

    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()
        locale = self._value_locale()
        if self.clue.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
            return self._build_name_run(start=self.clue.start, end=self.clue.end)
        if self.clue.role in {ClueRole.LABEL, ClueRole.START}:
            start = _skip_separators(self.context.stream.text, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._expand_seed_right(
                start=start,
                end=start,
                search_index=self.clue_index + 1,
                locale=locale,
            )
            return self._build_name_run(start=start, end=end)
        if self.clue.role == ClueRole.FAMILY_NAME:
            end = self._expand_seed_right(
                start=self.clue.start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
                locale=locale,
            )
            return self._build_name_run(start=self.clue.start, end=end)
        if self.clue.role == ClueRole.GIVEN_NAME:
            if locale == "zh":
                return self._build_name_run(start=self.clue.start, end=self.clue.end)
            start = self._extend_given_left_en(self.clue.start)
            end = self._extend_given_chain_right_en(
                start=start,
                end=self.clue.end,
                search_index=self.clue_index + 1,
            )
            return self._build_name_run(start=start, end=end)
        return None

    def _build_name_run(self, *, start: int, end: int) -> StackRun | None:
        is_label_seed = self.clue.role == ClueRole.LABEL
        label_driven = is_label_seed
        if end <= start:
            return None

        component_hint = self._effective_hint(start, end)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_name_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            component_hint=component_hint,
            unit_start=unit_start,
            unit_end=unit_end,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=label_driven,
        )
        if candidate is None:
            return None

        name_clues = self._name_clues_in_span(start, end)
        unique_roles = {clue.role for _index, clue in name_clues}
        if self.clue.role in _NAME_COMPONENT_ROLES:
            unique_roles.discard(self.clue.role)
        clue_count = 1 + len(unique_roles)
        negative_count = len(self._negative_clue_ids_in_span(start, end))

        if self.clue.role not in {ClueRole.FULL_NAME, ClueRole.ALIAS} and not self._meets_commit_threshold(
            candidate_text=candidate.text,
            clue_count=clue_count,
            negative_count=negative_count,
            name_clues=name_clues,
        ):
            return None

        consumed_ids = {self.clue.clue_id}
        consumed_ids.update(clue.clue_id for _index, clue in name_clues)
        last_name_index = max((index for index, _clue in name_clues), default=self.clue_index)
        return StackRun(
            attr_type=PIIAttributeType.NAME,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids={self.clue.clue_id} if is_label_seed else set(),
            next_index=max(self.clue_index + 1, last_name_index + 1),
        )

    def _extend_given_left_en(self, start: int) -> int:
        """英文 given seed 最多向左补 1 个未命中 clue 的普通单词。"""
        word_span = self._previous_plain_ascii_word(start)
        if word_span is None:
            return start
        word_start, word_end = word_span
        if self._span_has_any_clue_overlap(word_start, word_end):
            return start
        if self._span_has_blocker(word_end, start):
            return start
        return word_start

    def _expand_seed_right(
        self,
        *,
        start: int,
        end: int,
        search_index: int,
        locale: str,
    ) -> int:
        """从 LABEL / START / FAMILY_NAME seed 向右推进。

        规则：
        1. 先吞普通姓名文本。
        2. 遇到 FULL_NAME / ALIAS 时整段纳入并结束。
        3. 遇到 GIVEN_NAME 时，中文结束；英文切换到 given 链逻辑。
        4. FAMILY_NAME 可继续串联，但同属性计数仍只算 1 次。
        """
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor):
                return cursor

            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(cursor, next_index)

            plain_limit = len(self.context.stream.text)
            if next_component is not None:
                plain_limit = next_component[1].start
            if next_blocker is not None and next_blocker[1].start < plain_limit:
                plain_limit = next_blocker[1].start

            scanned = self._scan_plain_right(start=start, cursor=cursor, upper=plain_limit, locale=locale)
            cursor = scanned
            if cursor < plain_limit:
                return cursor

            if next_component is None or next_component[1].start != cursor:
                return cursor

            component_index, component = next_component
            cursor = component.end
            next_index = component_index + 1

            if component.role == ClueRole.FAMILY_NAME:
                continue
            if component.role in {ClueRole.FULL_NAME, ClueRole.ALIAS}:
                return cursor
            if locale == "zh":
                return cursor
            return self._extend_given_chain_right_en(
                start=start,
                end=cursor,
                search_index=next_index,
            )

    def _extend_given_chain_right_en(self, start: int, end: int, search_index: int) -> int:
        """英文 given 可继续吸收间隔最多 1 个普通单词的后续 GIVEN_NAME。"""
        cursor = end
        next_index = search_index
        while True:
            if self._has_active_stop_overlap(cursor):
                return cursor
            next_component = self._find_next_component_clue(cursor, next_index)
            next_blocker = self._find_next_right_blocker(cursor, next_index)
            if next_component is None:
                return cursor
            component_index, component = next_component
            if component.role != ClueRole.GIVEN_NAME:
                return cursor
            if next_blocker is not None and next_blocker[1].start < component.start:
                return cursor
            if not self._gap_allows_single_plain_word(cursor, component.start):
                return cursor
            cursor = component.end
            next_index = component_index + 1

    def _effective_hint(self, start: int, end: int) -> NameComponentHint:
        """若扩展后文本比 seed 更长，提升为 FULL；否则保留原始 hint。"""
        base = self._component_hint()
        if base in {NameComponentHint.FAMILY, NameComponentHint.GIVEN, NameComponentHint.MIDDLE}:
            candidate_text = self.context.stream.text[start:end].strip()
            if len(candidate_text) > len(self.clue.text):
                return NameComponentHint.FULL
        return base

    def _component_hint(self) -> NameComponentHint:
        if self.clue.role == ClueRole.FAMILY_NAME:
            return NameComponentHint.FAMILY
        if self.clue.role == ClueRole.GIVEN_NAME:
            return self.clue.component_hint or NameComponentHint.GIVEN
        if self.clue.role == ClueRole.ALIAS:
            return NameComponentHint.ALIAS
        if self.clue.role == ClueRole.FULL_NAME:
            return NameComponentHint.FULL
        return self.clue.component_hint or NameComponentHint.FULL

    def _scan_plain_right(self, *, start: int, cursor: int, upper: int, locale: str) -> int:
        """在下一个 clue 或 blocker 之前吞普通姓名文本。"""
        if upper <= cursor:
            return cursor
        raw_text = self.context.stream.text
        units = self.context.stream.units
        if not units or cursor >= len(raw_text):
            return cursor

        if locale == "zh":
            cjk_count = sum(1 for i in range(start, cursor) if _shared_is_cjk(raw_text[i]))
            max_cjk = 4
            cursor_end = cursor
            ui = self._unit_index_at_or_after(cursor)
            while ui < len(units) and cjk_count < max_cjk:
                unit = units[ui]
                if unit.char_start >= upper:
                    break
                if unit.kind == "cjk_char":
                    cjk_count += 1
                    cursor_end = unit.char_end
                    ui += 1
                    continue
                if unit.kind == "punct":
                    left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
                    right_char = _peek_unit_first_char(units, ui + 1)
                    if is_name_joiner(unit.text, left_char, right_char):
                        cursor_end = unit.char_end
                        ui += 1
                        continue
                break
            return max(cursor, cursor_end)

        cursor_end = cursor
        ui = self._unit_index_at_or_after(cursor)
        max_len = 80
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= upper:
                break
            if unit.char_end - start > max_len:
                break
            if unit.kind == "ascii_word":
                cursor_end = unit.char_end
                ui += 1
                continue
            if unit.kind == "space":
                next_ui = ui + 1
                while next_ui < len(units) and units[next_ui].kind == "space":
                    next_ui += 1
                if next_ui < len(units) and units[next_ui].kind == "ascii_word" and units[next_ui].char_start <= upper:
                    cursor_end = unit.char_end
                    ui += 1
                    continue
                break
            if unit.kind == "punct":
                left_char = raw_text[unit.char_start - 1] if unit.char_start > 0 else None
                right_char = _peek_unit_first_char(units, ui + 1)
                if is_name_joiner(unit.text, left_char, right_char):
                    cursor_end = unit.char_end
                    ui += 1
                    continue
            break
        return max(cursor, cursor_end)

    def _find_next_component_clue(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
        for index in range(search_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start < cursor:
                continue
            if clue.attr_type == PIIAttributeType.NAME and clue.role in _NAME_COMPONENT_ROLES:
                return (index, clue)
        return None

    def _find_next_right_blocker(self, cursor: int, search_index: int) -> tuple[int, Clue] | None:
        for index in range(search_index, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start < cursor:
                continue
            if self._is_name_blocker(clue):
                return (index, clue)
        return None

    def _has_active_stop_overlap(self, cursor: int) -> bool:
        for clue in self.context.clues:
            if clue.start < cursor < clue.end and self._is_name_blocker(clue):
                return True
        return False

    def _is_name_blocker(self, clue: Clue) -> bool:
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR}:
            return True
        if clue.attr_type is None:
            return False
        return clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES

    def _gap_allows_single_plain_word(self, start: int, end: int) -> bool:
        """英文 given 链之间只允许空白，或 1 个未命中 clue 的普通单词。"""
        if end <= start:
            return True
        if self._span_has_any_clue_overlap(start, end):
            return False
        units = self.context.stream.units
        word_count = 0
        ui = self._unit_index_at_or_after(start)
        while ui < len(units):
            unit = units[ui]
            if unit.char_start >= end:
                break
            if unit.kind == "space":
                ui += 1
                continue
            if unit.kind == "ascii_word":
                word_count += 1
                if word_count > 1:
                    return False
                ui += 1
                continue
            return False
        return True

    def _previous_plain_ascii_word(self, start: int) -> tuple[int, int] | None:
        if start <= 0 or not self.context.stream.units:
            return None
        units = self.context.stream.units
        ui = self._unit_index_left_of(start)
        while ui >= 0 and units[ui].kind == "space":
            ui -= 1
        if ui < 0 or units[ui].kind != "ascii_word":
            return None
        word = units[ui]
        for gap_index in range(ui + 1, len(units)):
            gap_unit = units[gap_index]
            if gap_unit.char_start >= start:
                break
            if gap_unit.kind != "space":
                return None
        return (word.char_start, word.char_end)

    def _span_has_any_clue_overlap(self, start: int, end: int) -> bool:
        for clue in self.context.clues:
            if clue.start < end and clue.end > start:
                return True
        return False

    def _span_has_blocker(self, start: int, end: int) -> bool:
        for clue in self.context.clues:
            if clue.start < end and clue.end > start and self._is_name_blocker(clue):
                return True
        return False

    def _unit_index_at_or_after(self, char_index: int) -> int:
        if char_index >= len(self.context.stream.char_to_unit):
            return len(self.context.stream.units)
        ui = self.context.stream.char_to_unit[char_index]
        while ui < len(self.context.stream.units) and self.context.stream.units[ui].char_end <= char_index:
            ui += 1
        return ui

    def _unit_index_left_of(self, char_index: int) -> int:
        if char_index <= 0 or not self.context.stream.char_to_unit:
            return -1
        ui = self.context.stream.char_to_unit[char_index - 1]
        while ui >= 0 and self.context.stream.units[ui].char_start >= char_index:
            ui -= 1
        return ui

    def _name_clues_in_span(self, start: int, end: int) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.attr_type != PIIAttributeType.NAME or clue.role not in _NAME_COMPONENT_ROLES:
                continue
            if clue.start < end and clue.end > start:
                matches.append((index, clue))
        return matches

    def _negative_clue_ids_in_span(self, start: int, end: int) -> set[str]:
        negative_ids: set[str] = set()
        for clue in self.context.clues:
            if clue.role != ClueRole.NEGATIVE:
                continue
            if clue.start < end and clue.end > start:
                negative_ids.add(clue.clue_id)
        return negative_ids

    def _meets_commit_threshold(
        self,
        *,
        candidate_text: str,
        clue_count: int,
        negative_count: int,
        name_clues: list[tuple[int, Clue]],
    ) -> bool:
        if negative_count > 0:
            return False
        if self.context.protection_level == ProtectionLevel.STRONG:
            return clue_count >= 2 or len(candidate_text) > 1
        if self.context.protection_level == ProtectionLevel.BALANCED:
            if clue_count != 1 or len(candidate_text) <= 1 or len(name_clues) != 1:
                return False
            only_clue = name_clues[0][1]
            return only_clue.role == ClueRole.GIVEN_NAME and only_clue.source_kind.startswith("dictionary_")
        return clue_count >= 2


@dataclass(slots=True)
class OrganizationStack(BaseStack):
    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """组织名回缩：后缀被截 → 放弃；前缀被截 → 重建并检查后缀是否仍在。"""
        c = run.candidate
        stream = self.context.stream
        raw_text = stream.text
        if blocker_start <= c.unit_start:
            new_unit_start, new_unit_end = blocker_end, c.unit_end
        elif blocker_end >= c.unit_end:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        else:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        trimmed = trim_candidate(
            c,
            raw_text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_end),
            unit_start=new_unit_start,
            unit_end=new_unit_end,
        )
        if trimmed is None:
            return None
        if not _is_organization_candidate_usable(trimmed.text, label_driven=trimmed.label_driven):
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def run(self) -> StackRun | None:
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()
        is_label_seed = self.clue.role == ClueRole.LABEL
        locale = self._value_locale()
        if is_label_seed:
            start = _skip_separators(self.context.stream.text, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._resolve_label_end(start=start, locale=locale)
            handled = {self.clue.clue_id}
        elif self.clue.role == ClueRole.SUFFIX:
            start = self._resolve_suffix_start(locale=locale)
            end = self.clue.end
            handled = set()
        else:
            return None
        matches = self._organization_clues_in_span(start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=_char_span_to_unit_span(self.context.stream, start, end)[0],
            unit_end=_char_span_to_unit_span(self.context.stream, start, end)[1],
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=is_label_seed,
        )
        if candidate is None:
            return None
        if not _organization_has_body_before_suffix(candidate.text):
            return None
        consumed_ids = {clue.clue_id for _index, clue in matches}
        consumed_ids.add(self.clue.clue_id)
        last_index = max((index for index, _clue in matches), default=self.clue_index)
        return StackRun(
            attr_type=PIIAttributeType.ORGANIZATION,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=handled,
            next_index=last_index + 1,
        )

    def _resolve_label_end(self, *, start: int, locale: str) -> int:
        """label 起栈：先找近距离 suffix，否则按中英文配额截断。"""
        upper = self._resolve_label_upper_boundary(start)
        if upper <= start:
            return start
        suffix_end = self._find_suffix_end_within_window(start=start, upper=upper)
        if suffix_end is not None:
            return suffix_end
        return _extend_organization_right_with_limit(
            self.context.stream,
            start=start,
            upper=upper,
            locale=locale,
        )

    def _resolve_suffix_start(self, *, locale: str) -> int:
        """suffix 起栈：先取通用左边界，再按主体长度上限左扩。"""
        floor = _left_expand_text_boundary(self.context.stream.text, self.context.clues, self.clue.start)
        return _extend_organization_left_with_limit(
            self.context.stream,
            floor=floor,
            start=self.clue.start,
            locale=locale,
        )

    def _resolve_label_upper_boundary(self, start: int) -> int:
        """组织名右扩的通用停止边界。"""
        blocker_start = self._next_label_blocker_start(start)
        upper = blocker_start if blocker_start is not None else len(self.context.stream.text)
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(self.context.stream.units):
            unit = self.context.stream.units[ui]
            if unit.char_start >= upper:
                break
            if unit.kind in {"inline_gap", "semantic_break"}:
                return unit.char_start
            if unit.kind == "punct" and is_hard_break(unit.text):
                return unit.char_start
            ui += 1
        return upper

    def _next_label_blocker_start(self, start: int) -> int | None:
        for clue in self.context.clues:
            if clue.clue_id == self.clue.clue_id:
                continue
            if clue.start < start < clue.end and self._is_label_right_blocker(clue):
                return start
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.end <= start:
                continue
            if self._is_label_right_blocker(clue):
                return max(start, clue.start)
        return None

    def _is_label_right_blocker(self, clue: Clue) -> bool:
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.CONNECTOR, ClueRole.LABEL}:
            return True
        if clue.role == ClueRole.HARD:
            return True
        if clue.attr_type is None:
            return False
        return clue.attr_type != PIIAttributeType.ORGANIZATION

    def _find_suffix_end_within_window(self, *, start: int, upper: int) -> int | None:
        if start >= upper or not self.context.stream.char_to_unit:
            return None
        start_ui = _unit_index_at_or_after(self.context.stream, start)
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start >= upper:
                break
            if clue.end <= start:
                continue
            if clue.attr_type != PIIAttributeType.ORGANIZATION or clue.role != ClueRole.SUFFIX:
                continue
            suffix_ui = self.context.stream.char_to_unit[clue.start]
            if _count_non_space_units(self.context.stream.units, start_ui, suffix_ui + 1) <= 10:
                return clue.end
        return None

    def _organization_clues_in_span(self, start: int, end: int) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.end <= start:
                continue
            if clue.start >= end:
                break
            if clue.attr_type != PIIAttributeType.ORGANIZATION:
                continue
            if clue.role == ClueRole.HARD:
                continue
            matches.append((index, clue))
        return matches


@dataclass(slots=True)
class AddressStack(BaseStack):
    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """地址回缩：截断后检查剩余文本是否仍含地址信号。"""
        from privacyguard.infrastructure.pii.detector.candidate_utils import has_address_signal
        c = run.candidate
        stream = self.context.stream
        raw_text = stream.text
        if blocker_start <= c.unit_start:
            new_unit_start, new_unit_end = blocker_end, c.unit_end
        elif blocker_end >= c.unit_end:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        else:
            new_unit_start, new_unit_end = c.unit_start, blocker_start
        trimmed = trim_candidate(
            c,
            raw_text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_end),
            unit_start=new_unit_start,
            unit_end=new_unit_end,
        )
        if trimmed is None:
            return None
        # 截断后仍需含地址信号词（省/市/路/street 等）。
        if not has_address_signal(trimmed.text) and not trimmed.label_driven:
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            consumed_ids=run.consumed_ids,
            handled_label_clue_ids=run.handled_label_clue_ids,
            next_index=run.next_index,
        )

    def run(self) -> StackRun | None:
        """地址 stack 主入口。

        组件串联规则：
        1. VALUE / KEY 都独立构成一个"证据 clue"。
        2. VALUE + 同层 KEY 合并为 1 个证据；VALUE + 不同层 KEY / VALUE+VALUE / KEY+KEY 各自独立计数。
        3. KEY 入口或独立 KEY 会向左扩展取值（中文 2 字符，英文 1 单词）。
        4. 按 protection_level 决定提交门槛（见 _meets_commit_threshold）。
        """
        if self.clue.role == ClueRole.HARD:
            return self._build_hard_run()

        raw_text = self.context.stream.text
        locale = self._value_locale()
        is_label_seed = self.clue.role == ClueRole.LABEL

        if is_label_seed:
            address_start = _skip_separators(raw_text, self.clue.end)
            first_index = _next_address_index(
                self.context.clues, self.clue_index + 1,
                locale=locale, raw_text=raw_text,
            )
            if first_index is None:
                return None
            scan_index = first_index
            consumed_ids: set[str] = {self.clue.clue_id}
            handled_labels: set[str] = {self.clue.clue_id}
            evidence_count = 1  # label 自身算 1 个证据。
        else:
            address_start = self._seed_left_boundary()
            scan_index = self.clue_index
            consumed_ids = set()
            handled_labels = set()
            evidence_count = 0
        if address_start is None:
            return None

        # ── 串联地址 clue ──
        components: list[dict[str, object]] = []
        last_end = address_start
        last_tier = 0
        # pending_value: 等待被后续同层 KEY 合并的 VALUE clue。
        pending_value: dict[AddressComponentType, Clue] = {}
        i = scan_index

        while i < len(self.context.clues):
            clue = self.context.clues[i]

            # 非 address clue 处理。
            if clue.attr_type != PIIAttributeType.ADDRESS:
                if is_break_clue(clue) or is_negative_clue(clue):
                    break
                if _has_nearby_address_clue(self.context.clues, i + 1, last_end,
                                            locale=locale, raw_text=raw_text):
                    i += 1
                    continue
                break
            if clue.role == ClueRole.LABEL:
                i += 1
                continue
            if clue.start < address_start:
                i += 1
                continue

            # 间距检查。
            gap_text = raw_text[last_end:clue.start]
            if clue.start > last_end and _address_gap_too_wide(gap_text, locale):
                break

            comp_type = clue.component_type
            if comp_type is None:
                i += 1
                continue
            tier = _COMPONENT_TIER.get(comp_type, 999)
            if last_tier and tier < last_tier - _MAX_TIER_BACKTRACK:
                break

            consumed_ids.add(clue.clue_id)

            if clue.role == ClueRole.VALUE:
                if comp_type in pending_value:
                    # 同 comp_type 再次出现 → 地址序列结束。
                    break
                self._flush_pending_values(
                    raw_text, pending_value, tier, components, address_start,
                )
                pending_value[comp_type] = clue
                last_end = max(last_end, clue.end)
                last_tier = tier
                i += 1
                continue

            # KEY clue 处理。
            same_tier_value = pending_value.pop(comp_type, None)
            # 先刷出其他不同层的 pending value。
            flushed = self._flush_pending_values(
                raw_text, pending_value, tier, components, address_start,
            )
            evidence_count += flushed

            if same_tier_value is not None:
                # VALUE + 同层 KEY → 尝试合并。
                comp, merged = _build_value_key_component(
                    raw_text, same_tier_value, clue, comp_type,
                    locale=locale,
                )
                if merged:
                    # 紧连合并成功 → 1 个组件，1 个证据。
                    if comp is not None:
                        components.append(comp)
                        evidence_count += 1
                        last_end = max(last_end, int(comp["end"]))
                        last_tier = tier
                else:
                    # 不紧连 → VALUE 和 KEY 各自独立。
                    standalone = _build_standalone_address_component(same_tier_value, comp_type)
                    if standalone is not None:
                        components.append(standalone)
                        evidence_count += 1
                        last_end = max(last_end, int(standalone["end"]))
                    key_comp = self._build_key_component(raw_text, clue, comp_type, i, locale)
                    if key_comp is not None:
                        components.append(key_comp)
                        evidence_count += 1
                        last_end = max(last_end, int(key_comp["end"]))
                    last_tier = tier
            else:
                # 独立 KEY → 左扩取值，1 个证据。
                comp = self._build_key_component(raw_text, clue, comp_type, i, locale)
                if comp is not None:
                    components.append(comp)
                    evidence_count += 1
                    last_end = max(last_end, int(comp["end"]))
                    last_tier = tier
            i += 1

        # 刷出剩余的 pending values。
        evidence_count += self._flush_all_pending(
            raw_text, pending_value, components, address_start,
        )

        if not components:
            return None
        if not _meets_commit_threshold(
            evidence_count, components, locale,
            protection_level=self.context.protection_level,
        ):
            return None

        final_start = min(int(c["start"]) for c in components)
        final_end = max(int(c["end"]) for c in components)
        text = clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_start + len(text),
            unit_start=_char_span_to_unit_span(self.context.stream, absolute_start, absolute_start + len(text))[0],
            unit_end=_char_span_to_unit_span(self.context.stream, absolute_start, absolute_start + len(text))[1],
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata=_address_metadata(self.clue, components),
            label_clue_ids=handled_labels,
            label_driven=is_label_seed,
        )
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=handled_labels,
            next_index=i,
        )

    def _flush_pending_values(
        self,
        raw_text: str,
        pending: dict[AddressComponentType, Clue],
        current_tier: int,
        components: list[dict[str, object]],
        address_start: int,
    ) -> int:
        """将不同层的 pending VALUE 刷出为独立组件。返回刷出的证据数。"""
        flushed = 0
        to_remove: list[AddressComponentType] = []
        for comp_type, value_clue in pending.items():
            value_tier = _COMPONENT_TIER.get(comp_type, 999)
            if value_tier == current_tier:
                continue  # 同层，留给后续 KEY 合并。
            comp = _build_standalone_address_component(value_clue, comp_type)
            if comp is not None:
                components.append(comp)
                flushed += 1
            to_remove.append(comp_type)
        for key in to_remove:
            del pending[key]
        return flushed

    def _flush_all_pending(
        self,
        raw_text: str,
        pending: dict[AddressComponentType, Clue],
        components: list[dict[str, object]],
        address_start: int,
    ) -> int:
        """刷出所有剩余的 pending VALUE 为独立组件。"""
        flushed = 0
        for comp_type, value_clue in pending.items():
            comp = _build_standalone_address_component(value_clue, comp_type)
            if comp is not None:
                components.append(comp)
                flushed += 1
        pending.clear()
        return flushed

    def _build_key_component(
        self,
        raw_text: str,
        clue: Clue,
        comp_type: AddressComponentType,
        clue_index: int,
        locale: str,
    ) -> dict[str, object] | None:
        """用边界函数左扩（或前缀 KEY 右取）构建 KEY 组件。"""
        key_text = clue.text

        # 前缀 KEY（apt / suite 等）→ 向右取值。
        if key_text.lower() in _PREFIX_EN_KEYWORDS:
            value_start = _skip_separators(raw_text, clue.end)
            value_end = _scan_forward_value_end(
                raw_text, value_start,
                upper_bound=min(len(raw_text), clue.end + 30),
            )
            if value_end <= value_start:
                return None
            value = _normalize_address_value(comp_type, raw_text[value_start:value_end])
            if not value:
                return None
            return {
                "component_type": comp_type,
                "start": clue.start,
                "end": value_end,
                "value": value,
                "key": key_text,
                "is_detail": comp_type in _DETAIL_COMPONENTS,
            }

        # 后缀 KEY → 用边界函数左扩。
        floor = _left_address_floor(self.context.clues, clue_index)
        if locale.startswith("en"):
            expand_start = _left_expand_en_word(raw_text, clue.start, floor)
        else:
            expand_start = _left_expand_zh_chars(raw_text, clue.start, floor, max_chars=2)

        value = _normalize_address_value(comp_type, raw_text[expand_start:clue.start])
        if not value:
            return None
        return {
            "component_type": comp_type,
            "start": expand_start,
            "end": clue.end,
            "value": value,
            "key": key_text,
            "is_detail": comp_type in _DETAIL_COMPONENTS,
        }

    def _seed_left_boundary(self) -> int | None:
        """seed 左边界。KEY 的左扩由 _build_key_component 统一处理。"""
        if self.clue.role in {ClueRole.VALUE, ClueRole.KEY}:
            return self.clue.start
        return None


def _build_hard_candidate(clue: Clue, source: PIISourceType) -> CandidateDraft:
    metadata = {key: list(values) for key, values in clue.source_metadata.items()}
    metadata = merge_metadata(metadata, {"matched_by": [clue.source_kind], "hard_source": [str(clue.hard_source or "regex")]})
    return CandidateDraft(
        attr_type=clue.attr_type,
        start=clue.start,
        end=clue.end,
        unit_start=clue.unit_start,
        unit_end=clue.unit_end,
        text=clue.text,
        source=source,
        source_kind=clue.source_kind,
        claim_strength=ClaimStrength.HARD,
        metadata=metadata,
    )


@dataclass(slots=True)
class ConflictOutcome:
    incoming: CandidateDraft | None
    drop_existing: bool = False
    replace_existing: CandidateDraft | None = None


class StackManager:
    def score(self, candidate: CandidateDraft) -> float:
        score = 0.0
        if candidate.claim_strength == ClaimStrength.HARD:
            score += 0.4
            score += 0.02 * _candidate_hard_source_rank(candidate)
        if candidate.source_kind.startswith("dictionary_"):
            score += 0.25
        elif candidate.label_driven:
            score += 0.08
        return score

    def resolve_conflict(self, context, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if existing.attr_type == incoming.attr_type:
            return self._resolve_same_attr(existing, incoming)
        if existing.claim_strength == ClaimStrength.HARD and incoming.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream, incoming, existing)
            return ConflictOutcome(incoming=trimmed)
        if incoming.claim_strength == ClaimStrength.HARD and existing.claim_strength != ClaimStrength.HARD:
            trimmed = self._trim_candidate(context.stream, existing, incoming)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        attr_pair = frozenset({existing.attr_type, incoming.attr_type})
        if attr_pair == {PIIAttributeType.ADDRESS, PIIAttributeType.ORGANIZATION}:
            return self._resolve_address_organization(context.stream, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
            return self._resolve_name_organization(context.stream, existing, incoming)
        if attr_pair == {PIIAttributeType.NAME, PIIAttributeType.ADDRESS}:
            return self._resolve_name_address(context.stream, existing, incoming)
        return self._resolve_by_score(existing, incoming)

    def _resolve_same_attr(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        if (incoming.unit_end - incoming.unit_start) > (existing.unit_end - existing.unit_start):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _resolve_address_organization(self, stream: StreamInput, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        if not has_organization_suffix(organization.text):
            return self._resolve_by_score(existing, incoming)
        if organization is incoming:
            trimmed = self._trim_candidate(stream, address, organization)
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = self._trim_candidate(stream, address, organization)
        return ConflictOutcome(incoming=trimmed)

    def _resolve_name_organization(self, stream: StreamInput, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        organization = incoming if incoming.attr_type == PIIAttributeType.ORGANIZATION else existing
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        if not has_organization_suffix(organization.text):
            return ConflictOutcome(incoming=incoming if incoming.attr_type == PIIAttributeType.NAME else None)
        suffix_start = organization_suffix_start(organization.text)
        if suffix_start <= 0:
            return ConflictOutcome(incoming=organization if incoming is organization else None, drop_existing=name is existing)
        trim_end = min(name.end, organization.start + suffix_start)
        trim_unit_start, trim_unit_end = _char_span_to_unit_span(stream, name.start, trim_end)
        if organization is incoming:
            trimmed = trim_candidate(
                name,
                stream.text,
                start=name.start,
                end=trim_end,
                unit_start=trim_unit_start,
                unit_end=trim_unit_end,
            )
            return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)
        trimmed = trim_candidate(
            name,
            stream.text,
            start=name.start,
            end=trim_end,
            unit_start=trim_unit_start,
            unit_end=trim_unit_end,
        )
        return ConflictOutcome(incoming=trimmed)

    def _resolve_name_address(self, stream: StreamInput, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        """Name vs Address：address 优先，name 做 trim；trim 后无效则丢弃 name。"""
        address = incoming if incoming.attr_type == PIIAttributeType.ADDRESS else existing
        name = incoming if incoming.attr_type == PIIAttributeType.NAME else existing
        if name is incoming:
            trimmed = self._trim_candidate(stream, name, address)
            return ConflictOutcome(incoming=trimmed)
        # name 是 existing，address 是 incoming。
        trimmed = self._trim_candidate(stream, name, address)
        return ConflictOutcome(incoming=incoming, drop_existing=trimmed is None, replace_existing=trimmed)

    def _resolve_by_score(self, existing: CandidateDraft, incoming: CandidateDraft) -> ConflictOutcome:
        if self.score(incoming) > self.score(existing):
            return ConflictOutcome(incoming=incoming, drop_existing=True)
        return ConflictOutcome(incoming=None)

    def _trim_candidate(self, stream: StreamInput, candidate: CandidateDraft, blocker: CandidateDraft) -> CandidateDraft | None:
        if blocker.unit_start <= candidate.unit_start and blocker.unit_end >= candidate.unit_end:
            return None
        if blocker.unit_start <= candidate.unit_start:
            next_unit_start, next_unit_end = blocker.unit_end, candidate.unit_end
        else:
            next_unit_start, next_unit_end = candidate.unit_start, blocker.unit_start
        return trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, next_unit_start),
            end=_unit_char_end(stream, next_unit_end),
            unit_start=next_unit_start,
            unit_end=next_unit_end,
        )


def _next_address_index(
    clues: tuple[Clue, ...],
    start_index: int,
    *,
    locale: str,
    raw_text: str,
) -> int | None:
    """从 start_index 向右查找第一个非 label 的 address clue。

    跳过夹在中间的非 address soft clue（如与路名重合的姓氏），
    但遇到 break / negative 时中断。
    距离阈值：英文 ≤5 词，中文 ≤10 字符。
    """
    last_pos = clues[start_index - 1].end if start_index > 0 else 0
    for index in range(start_index, len(clues)):
        clue = clues[index]
        if is_break_clue(clue) or is_negative_clue(clue):
            return None
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role == ClueRole.LABEL:
            continue
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            return index
        if is_control_clue(clue):
            continue
        # 非 address 的 soft clue：检查距离，过远则放弃。
        gap_text = raw_text[last_pos:clue.start]
        if locale.startswith("en"):
            if len(gap_text.split()) > 5:
                return None
        else:
            if len(gap_text) > 10:
                return None
        continue
    return None


def _has_nearby_address_clue(
    clues: tuple[Clue, ...],
    start_index: int,
    last_end: int,
    *,
    locale: str,
    raw_text: str | None = None,
) -> bool:
    """检查从 start_index 起，距离 last_end 不超过阈值内是否有 address clue。

    距离阈值因 locale 而异：英文按单词数（≤3 词），中文按字符数（≤6 字符）。
    """
    for index in range(start_index, len(clues)):
        clue = clues[index]
        gap_chars = clue.start - last_end
        if gap_chars > 30:
            # 绝对上界：无论语言都不跨越 30 字符。
            return False
        if is_break_clue(clue) or is_negative_clue(clue):
            return False
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            # 对英文按单词数校验；中文按字符数。
            if locale.startswith("en") and raw_text is not None:
                gap_text = raw_text[last_end:clue.start]
                if len(gap_text.split()) > 3:
                    return False
            elif gap_chars > 6:
                return False
            return True
    return False


# ---------------------------------------------------------------------------
# 地址证据模型 helper
# ---------------------------------------------------------------------------

def _address_gap_too_wide(gap_text: str, locale: str) -> bool:
    """判断两个地址组件之间的间距是否过大。

    三层约束：
    1. 硬断句或 OCR 语义分割符 → 一定过宽。
    2. 结构检查：至多 1 个标点符号（连续标点不合理）。
    3. 宽度检查：英文 >3 词、中文 >6 字符即过宽。
    """
    if not gap_text:
        return False
    # 硬断句或 OCR 分割符。
    if _OCR_SEMANTIC_BREAK_TOKEN in gap_text or _OCR_INLINE_GAP_TOKEN in gap_text:
        return True
    if any(is_hard_break(ch) for ch in gap_text):
        return True
    # 结构检查：至多 1 个标点符号。
    punct_count = sum(1 for ch in gap_text if is_soft_break(ch))
    if punct_count > 1:
        return True
    # 宽度检查。
    if locale.startswith("en"):
        return len(gap_text.split()) > 3
    return len(gap_text) > 6


_EN_VALUE_KEY_GAP_RE = re.compile(r"^[ ]*$")


def _build_value_key_component(
    raw_text: str,
    value_clue: Clue,
    key_clue: Clue,
    comp_type: AddressComponentType,
    locale: str,
) -> tuple[dict[str, object] | None, bool]:
    """VALUE + 同层 KEY 尝试合并为 1 个组件。

    返回 (component, merged)：
    - merged=True 时 component 是合并后的单组件。
    - merged=False 时两者不紧连，不能合并，component 为 None；
      调用方应将 VALUE 和 KEY 各自作为独立证据处理。

    紧连规则：
    - 中文：VALUE.end == KEY.start，不允许任何间距（直连）。
    - 英文：之间只允许空格。
    """
    # 确定前后顺序。
    if value_clue.end <= key_clue.start:
        gap = raw_text[value_clue.end:key_clue.start]
    elif key_clue.end <= value_clue.start:
        gap = raw_text[key_clue.end:value_clue.start]
    else:
        gap = ""  # 重叠，视为紧连。

    if gap:
        if locale.startswith("en"):
            if not _EN_VALUE_KEY_GAP_RE.fullmatch(gap):
                return None, False
        else:
            # 中文：不允许任何间距。
            return None, False

    start = min(value_clue.start, key_clue.start)
    end = max(value_clue.end, key_clue.end)
    value = _normalize_address_value(comp_type, value_clue.text)
    if not value:
        return None, True  # 合并成功但 value 无效。
    return {
        "component_type": comp_type,
        "start": start,
        "end": end,
        "value": value,
        "key": key_clue.text,
        "is_detail": comp_type in _DETAIL_COMPONENTS,
    }, True


def _left_expand_en_word(raw_text: str, pos: int, floor: int) -> int:
    """从 pos 向左跳过空白后取 1 个英文单词的起始位置。"""
    cursor = pos
    # 跳过紧邻的空白。
    while cursor > floor and raw_text[cursor - 1] in " \t":
        cursor -= 1
    # 向左取连续字母/数字（1 个单词）。
    while cursor > floor and raw_text[cursor - 1].isalnum():
        cursor -= 1
    return cursor


def _left_expand_zh_chars(raw_text: str, pos: int, floor: int, *, max_chars: int) -> int:
    """从 pos 向左取最多 max_chars 个 CJK 字符。"""
    cursor = pos
    count = 0
    while cursor > floor and count < max_chars:
        ch = raw_text[cursor - 1]
        if "\u4e00" <= ch <= "\u9fff":
            cursor -= 1
            count += 1
        else:
            break
    return cursor


_SINGLE_EVIDENCE_ADMIN = {
    AddressComponentType.PROVINCE,
    AddressComponentType.STATE,
    AddressComponentType.CITY,
}


def _meets_commit_threshold(
    evidence_count: int,
    components: list[dict[str, object]],
    locale: str,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
) -> bool:
    """根据 protection_level 判断累计证据数是否满足提交门槛。

    - STRONG：1 个证据即可提交。
    - BALANCED：省/市/州单证据可提交；其余需 ≥2。
    - WEAK：一律 ≥2。
    """
    if evidence_count <= 0:
        return False
    if protection_level == ProtectionLevel.STRONG:
        return True
    if protection_level == ProtectionLevel.BALANCED:
        if evidence_count >= 2:
            return True
        # 单证据时，仅省/市/州放行。
        return any(comp["component_type"] in _SINGLE_EVIDENCE_ADMIN for comp in components)
    # WEAK：需 ≥2 证据。
    return evidence_count >= 2


def _build_standalone_address_component(clue: Clue, component_type: AddressComponentType) -> dict[str, object] | None:
    value = _normalize_address_value(component_type, clue.text)
    if not value:
        return None
    return {"component_type": component_type, "start": clue.start, "end": clue.end, "value": value, "key": "", "is_detail": component_type in _DETAIL_COMPONENTS}


def _left_address_floor(clues: tuple[Clue, ...], clue_index: int) -> int:
    for index in range(clue_index - 1, -1, -1):
        clue = clues[index]
        if _is_stop_control_clue(clue):
            return clue.end
        if is_control_clue(clue):
            continue
        if clue.attr_type != PIIAttributeType.ADDRESS:
            return clue.end
    return 0


def _scan_forward_value_end(raw_text: str, start: int, upper_bound: int) -> int:
    """向前扫描取值，遇到任何断点符号即停止。"""
    index = start
    while index < upper_bound:
        current = raw_text[index]
        if is_any_break(current):
            break
        index += 1
    return index


def _extend_street_tail(raw_text: str, end: int) -> int:
    """扩展路/街后的门牌号，支持：123号、甲1号、之2、3-5号 等变体。"""
    tail = raw_text[end:]
    match = re.match(r"\s*[甲乙丙丁]?\d{1,6}(?:[之\-]\d{1,4})?(?:号|號)?", tail)
    if match is None:
        return end
    return end + match.end()


def _address_metadata(origin_clue: Clue, components: list[dict[str, object]]) -> dict[str, list[str]]:
    component_types: list[str] = []
    component_trace: list[str] = []
    component_key_trace: list[str] = []
    detail_types: list[str] = []
    detail_values: list[str] = []
    for component in components:
        component_type = component["component_type"].value
        value = str(component["value"])
        key = str(component["key"])
        component_types.append(component_type)
        component_trace.append(f"{component_type}:{value}")
        if key:
            component_key_trace.append(f"{component_type}:{key}")
        if bool(component["is_detail"]):
            detail_types.append(component_type)
            detail_values.append(value)
    return {
        "matched_by": [origin_clue.source_kind],
        "address_kind": ["private_address"],
        "address_match_origin": [origin_clue.text if origin_clue.role == ClueRole.LABEL else origin_clue.source_kind],
        "address_component_type": component_types,
        "address_component_trace": component_trace,
        "address_component_key_trace": component_key_trace,
        "address_details_type": detail_types,
        "address_details_text": detail_values,
    }


def _normalize_address_value(component_type: AddressComponentType, raw_value: str) -> str:
    cleaned = clean_value(raw_value)
    if component_type in _DETAIL_COMPONENTS:
        alnum = "".join(re.findall(r"[A-Za-z0-9]+", cleaned))
        if re.search(r"[A-Za-z]", alnum):
            return alnum
        digits = "".join(re.findall(r"\d+", cleaned))
        if digits:
            return digits
    return cleaned


def _candidate_hard_source_rank(candidate: CandidateDraft) -> int:
    values = candidate.metadata.get("hard_source")
    if not values:
        return 0
    source = str(values[0])
    return {"session": 4, "local": 3, "prompt": 2, "regex": 1}.get(source, 0)


def _char_span_to_unit_span(stream: StreamInput, start: int, end: int) -> tuple[int, int]:
    if not stream.char_to_unit or start >= end:
        return (0, 0)
    return (stream.char_to_unit[start], stream.char_to_unit[end - 1] + 1)


def _unit_char_start(stream: StreamInput, unit_index: int) -> int:
    if not stream.units:
        return 0
    if unit_index <= 0:
        return 0
    if unit_index >= len(stream.units):
        return len(stream.text)
    return stream.units[unit_index].char_start


def _unit_char_end(stream: StreamInput, unit_index: int) -> int:
    if not stream.units:
        return 0
    if unit_index <= 0:
        return 0
    if unit_index > len(stream.units):
        return len(stream.text)
    return stream.units[unit_index - 1].char_end


def _skip_separators(text: str, start: int) -> int:
    """跳过 label→value 之间的空白和轻分隔符。"""
    index = start
    while index < len(text) and (text[index].isspace() or is_soft_break(text[index])):
        index += 1
    return index


def _left_expand_text_boundary(raw_text: str, clues: tuple[Clue, ...], start: int) -> int:
    """组织名向左扩展文本边界。遇到任何断点符号（hard 或 soft）即停止。"""
    floor = 0
    for clue in reversed(clues):
        if clue.end <= start:
            if _is_stop_control_clue(clue):
                floor = clue.end
                break
            if clue.role == ClueRole.LABEL:
                floor = clue.end
                break
    index = start
    while index > floor:
        previous = raw_text[index - 1]
        if is_any_break(previous):
            break
        index -= 1
    return index


def _unit_index_at_or_after(stream: StreamInput, char_index: int) -> int:
    if not stream.char_to_unit or char_index >= len(stream.char_to_unit):
        return len(stream.units)
    ui = stream.char_to_unit[char_index]
    while ui < len(stream.units) and stream.units[ui].char_end <= char_index:
        ui += 1
    return ui


def _unit_index_left_of(stream: StreamInput, char_index: int) -> int:
    if char_index <= 0 or not stream.char_to_unit:
        return -1
    ui = stream.char_to_unit[char_index - 1]
    while ui >= 0 and stream.units[ui].char_start >= char_index:
        ui -= 1
    return ui


def _count_non_space_units(units, start_ui: int, end_ui: int) -> int:
    count = 0
    for ui in range(max(0, start_ui), min(len(units), end_ui)):
        if units[ui].kind != "space":
            count += 1
    return count


def _organization_body_limit(locale: str) -> int:
    return 6 if locale == "zh" else 4


def _is_organization_count_unit(kind: str, locale: str) -> bool:
    if locale == "zh":
        return kind == "cjk_char"
    return kind == "ascii_word"


def _extend_organization_right_with_limit(
    stream: StreamInput,
    *,
    start: int,
    upper: int,
    locale: str,
) -> int:
    """组织名右扩：优先保留主体，空格和标点可带出但不计配额。"""
    if upper <= start:
        return start
    ui = _unit_index_at_or_after(stream, start)
    if ui >= len(stream.units):
        return start
    limit = _organization_body_limit(locale)
    count = 0
    end = start
    while ui < len(stream.units):
        unit = stream.units[ui]
        if unit.char_start >= upper:
            break
        if unit.kind in {"space", "punct"}:
            if end > start:
                end = min(unit.char_end, upper)
                ui += 1
                continue
            break
        if _is_organization_count_unit(unit.kind, locale):
            if count >= limit:
                break
            count += 1
            end = min(unit.char_end, upper)
            ui += 1
            continue
        break
    return end


def _extend_organization_left_with_limit(
    stream: StreamInput,
    *,
    floor: int,
    start: int,
    locale: str,
) -> int:
    """组织名左扩：只限制主体长度，空格和标点可一起带出。"""
    if start <= floor:
        return start
    ui = _unit_index_left_of(stream, start)
    if ui < 0:
        return start
    limit = _organization_body_limit(locale)
    count = 0
    next_start = start
    while ui >= 0:
        unit = stream.units[ui]
        if unit.char_end <= floor:
            break
        if unit.kind in {"space", "punct"}:
            next_start = max(floor, unit.char_start)
            ui -= 1
            continue
        if _is_organization_count_unit(unit.kind, locale):
            if count >= limit:
                break
            count += 1
            next_start = max(floor, unit.char_start)
            ui -= 1
            continue
        break
    return next_start


def _organization_has_body_before_suffix(text: str) -> bool:
    suffix_start = organization_suffix_start(text)
    if suffix_start < 0:
        return bool(clean_value(text))
    return bool(clean_value(text[:suffix_start]))


def _is_organization_candidate_usable(text: str, *, label_driven: bool) -> bool:
    if not text:
        return False
    if not has_organization_suffix(text) and not label_driven:
        return False
    return _organization_has_body_before_suffix(text)


def _extend_name_boundary(
    stream: StreamInput,
    start: int,
    end: int,
    clues: tuple[Clue, ...],
    next_clue_index: int,
) -> int:
    """从 end 向右扩展，基于 stream units 逐步推进捕获姓名字符。

    策略：从 end 所在 unit 的下一个 unit 开始，逐个检查：
    - cjk_char / ascii_word → 扩展（姓名主体）。
    - space → peek 下一个 unit，是姓名主体则继续，否则停。
    - punct 且满足三元组（左邻+符号+右邻）→ 扩展。
    - 其余（hard break、soft break、其他）→ 停。

    中文名：从 start 算起最多 4 个 CJK 字符（含三元组连接符）。
    英文名：最多 80 字符。
    """
    raw_text = stream.text
    units = stream.units
    if not units or end >= len(raw_text):
        return end

    # 上界：下一个 non-name clue 的起始位置。
    upper = len(raw_text)
    for i in range(next_clue_index, len(clues)):
        c = clues[i]
        if _is_stop_control_clue(c):
            upper = min(upper, c.start)
            break
        if is_control_clue(c):
            continue
        if c.attr_type != PIIAttributeType.NAME:
            upper = min(upper, c.start)
            break

    # 判断中英文。
    is_zh = start < len(raw_text) and _shared_is_cjk(raw_text[start])
    if is_zh:
        return _extend_name_right_zh(raw_text, units, stream.char_to_unit, start, end, upper)
    return _extend_name_right_en(raw_text, units, stream.char_to_unit, start, end, upper)


def _extend_name_right_zh(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    upper: int,
) -> int:
    """中文姓名向右扩展。从 start 算起最多 4 个 CJK 字符。"""
    # 统计 start→end 之间已有的 CJK 字符数。
    cjk_count = sum(1 for i in range(start, end) if _shared_is_cjk(raw_text[i]))
    max_cjk = 4

    cursor_end = end
    ui = char_to_unit[end - 1] + 1 if end > 0 and end <= len(char_to_unit) else len(units)

    while ui < len(units) and cjk_count < max_cjk:
        u = units[ui]
        if u.char_start >= upper:
            break
        if u.kind == "cjk_char":
            cjk_count += 1
            cursor_end = u.char_end
            ui += 1
            continue
        if u.kind == "punct":
            # 三元组检查：左邻 + punct + 右邻。
            left_char = raw_text[u.char_start - 1] if u.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if is_name_joiner(u.text, left_char, right_char):
                cursor_end = u.char_end
                ui += 1
                continue
            break
        break

    return max(end, cursor_end)


def _extend_name_right_en(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    upper: int,
) -> int:
    """英文姓名向右扩展。逐 unit 推进，最多 80 字符。"""
    cursor_end = end
    ui = char_to_unit[end - 1] + 1 if end > 0 and end <= len(char_to_unit) else len(units)
    max_len = 80

    while ui < len(units):
        u = units[ui]
        if u.char_start >= upper:
            break
        if u.char_end - start > max_len:
            break

        if u.kind == "ascii_word":
            cursor_end = u.char_end
            ui += 1
            continue

        if u.kind == "space":
            # peek 下一个非 space unit，是 ascii_word 则继续。
            next_ui = ui + 1
            while next_ui < len(units) and units[next_ui].kind == "space":
                next_ui += 1
            if next_ui < len(units) and units[next_ui].kind == "ascii_word" and units[next_ui].char_start < upper:
                cursor_end = u.char_end  # 先纳入 space。
                ui += 1
                continue
            break

        if u.kind == "punct":
            # 三元组检查。
            left_char = raw_text[u.char_start - 1] if u.char_start > 0 else None
            right_char = _peek_unit_first_char(units, ui + 1)
            if is_name_joiner(u.text, left_char, right_char):
                cursor_end = u.char_end
                ui += 1
                continue
            break

        # digit_char, cjk_char, other_char, semantic_break, inline_gap → 停。
        break

    return max(end, cursor_end)


def _extend_name_boundary_left(
    stream: StreamInput,
    start: int,
    end: int,
    clues: tuple[Clue, ...],
    clue_index: int,
) -> int:
    """从 start 向左扩展，基于 stream units 逐步推进捕获姓名字符。

    用于 given seed 的左扩阶段：向左找 family/given 片段，
    同时允许姓名内部连接符继续保留。
    """
    raw_text = stream.text
    units = stream.units
    if not units or start <= 0:
        return start

    # 下界：最近的 non-name clue 的 end。
    lower = 0
    for i in range(clue_index - 1, -1, -1):
        c = clues[i]
        if _is_stop_control_clue(c):
            lower = c.end
            break
        if is_control_clue(c):
            continue
        if c.attr_type != PIIAttributeType.NAME:
            lower = c.end
            break

    # 判断中英文（基于 start 左侧第一个字符）。
    is_zh = _shared_is_cjk(raw_text[start - 1])
    if is_zh:
        return _extend_name_left_zh(raw_text, units, stream.char_to_unit, start, end, lower)
    return _extend_name_left_en(raw_text, units, stream.char_to_unit, start, end, lower)


def _extend_name_left_zh(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    lower: int,
) -> int:
    """中文姓名向左扩展。最多 4 个 CJK 字符。"""
    cjk_count = sum(1 for i in range(start, end) if _shared_is_cjk(raw_text[i]))
    max_cjk = 4

    cursor_start = start
    ui = char_to_unit[start] - 1 if start < len(char_to_unit) else -1

    while ui >= 0 and cjk_count < max_cjk:
        u = units[ui]
        if u.char_end <= lower:
            break
        if u.kind == "cjk_char":
            cjk_count += 1
            cursor_start = u.char_start
            ui -= 1
            continue
        if u.kind == "punct":
            # 三元组检查。
            left_char = _peek_unit_last_char(units, ui - 1)
            right_char = raw_text[u.char_end] if u.char_end < len(raw_text) else None
            if is_name_joiner(u.text, left_char, right_char):
                cursor_start = u.char_start
                ui -= 1
                continue
            break
        break

    return min(start, cursor_start)


def _extend_name_left_en(
    raw_text: str,
    units: tuple[StreamUnit, ...],
    char_to_unit: tuple[int, ...],
    start: int,
    end: int,
    lower: int,
) -> int:
    """英文姓名向左扩展。最多 80 字符。"""
    cursor_start = start
    ui = char_to_unit[start] - 1 if start < len(char_to_unit) else -1
    max_len = 80

    while ui >= 0:
        u = units[ui]
        if u.char_end <= lower:
            break
        if end - u.char_start > max_len:
            break

        if u.kind == "ascii_word":
            cursor_start = u.char_start
            ui -= 1
            continue

        if u.kind == "space":
            # peek 左邻 unit，是 ascii_word 则继续。
            prev_ui = ui - 1
            while prev_ui >= 0 and units[prev_ui].kind == "space":
                prev_ui -= 1
            if prev_ui >= 0 and units[prev_ui].kind == "ascii_word" and units[prev_ui].char_end > lower:
                cursor_start = u.char_start  # 先纳入 space。
                ui -= 1
                continue
            break

        if u.kind == "punct":
            # 三元组检查。
            left_char = _peek_unit_last_char(units, ui - 1)
            right_char = raw_text[u.char_end] if u.char_end < len(raw_text) else None
            if is_name_joiner(u.text, left_char, right_char):
                cursor_start = u.char_start
                ui -= 1
                continue
            break

        break

    return min(start, cursor_start)


def _peek_unit_first_char(units: tuple[StreamUnit, ...], ui: int) -> str | None:
    """取第 ui 个 unit 的首字符；越界返回 None。"""
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[0] if units[ui].text else None


def _peek_unit_last_char(units: tuple[StreamUnit, ...], ui: int) -> str | None:
    """取第 ui 个 unit 的末字符；越界返回 None。"""
    if ui < 0 or ui >= len(units):
        return None
    return units[ui].text[-1] if units[ui].text else None
