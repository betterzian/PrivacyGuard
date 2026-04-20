"""组织名 stack 基类与组织名专属 helper。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import (
    build_organization_candidate_from_value,
    clean_value,
    has_organization_suffix,
    organization_suffix_start,
    trim_candidate,
)
from privacyguard.infrastructure.pii.detector.models import ClaimStrength, ClueFamily, Clue, ClueRole, StreamInput
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _count_non_space_units,
    _label_seed_start_char,
    _unit_char_end,
    _unit_char_start,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_control_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_any_break, is_hard_break


@dataclass(slots=True)
class BaseOrganizationStack(BaseStack):
    """组织名检测 stack 基类。"""

    STACK_LOCALE = "zh"

    def need_break(self, subject, **kwargs) -> bool:
        del kwargs
        if isinstance(subject, Clue):
            return subject.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.LABEL}
        return False

    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """组织名回缩：后缀被截即放弃，前缀被截后需重新校验。"""
        candidate = run.candidate
        stream = self.context.stream
        if blocker_start <= candidate.unit_start:
            new_unit_start, new_unit_end = blocker_end, candidate.unit_end
        elif blocker_end >= candidate.unit_end:
            new_unit_start, new_unit_end = candidate.unit_start, blocker_start
        else:
            new_unit_start, new_unit_end = candidate.unit_start, blocker_start
        trimmed = trim_candidate(
            candidate,
            stream.text,
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
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}
        locale = self.STACK_LOCALE
        if is_label_seed:
            start = _label_seed_start_char(self.context.stream, self.clue.end)
            if start >= len(self.context.stream.text):
                return None
            end = self._resolve_label_end(start=start, locale=locale)
            handled = {self.clue.clue_id}
        elif self.clue.role == ClueRole.SUFFIX:
            start = self._resolve_suffix_start(locale=locale)
            end = self.clue.end
            handled = set()
        elif self.clue.role == ClueRole.VALUE:
            return self._build_value_seed_run(locale=locale)
        else:
            return None
        matches = self._organization_clues_in_span(start, end)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=unit_start,
            unit_end=unit_end,
            label_clue_id=self.clue.clue_id if is_label_seed else None,
            label_driven=(self.clue.role == ClueRole.LABEL),
        )
        if candidate is None:
            return None
        if not _organization_has_body_before_suffix(candidate.text):
            return None
        evidence = self._build_org_evidence(
            start=start,
            end=end,
            is_label_seed=is_label_seed,
            default_suffix_strength=self.clue.strength if self.clue.role == ClueRole.SUFFIX else None,
            default_value_strength=self.clue.strength if self.clue.role == ClueRole.VALUE else None,
        )
        if not _meets_org_commit_threshold(
            evidence=evidence,
            locale=locale,
            protection_level=self.context.protection_level,
        ):
            return None
        candidate.claim_strength = evidence.max_clue_strength
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
        floor = _left_expand_text_boundary(self.context, self.clue.start, should_break=self.need_break)
        return _extend_organization_left_with_limit(
            self.context.stream,
            floor=floor,
            start=self.clue.start,
            locale=locale,
        )

    def _resolve_label_upper_boundary(self, start: int) -> int:
        blocker_start = self._next_label_blocker_start(start)
        upper = blocker_start if blocker_start is not None else len(self.context.stream.text)
        ui = _unit_index_at_or_after(self.context.stream, start)
        while ui < len(self.context.stream.units):
            unit = self.context.stream.units[ui]
            if unit.char_start >= upper:
                break
            if unit.kind in {"inline_gap", "ocr_break"}:
                return unit.char_start
            if unit.kind == "punct" and is_hard_break(unit.text):
                return unit.char_start
            ui += 1
        return upper

    def _next_label_blocker_start(self, start: int) -> int | None:
        blocker_start = start if self.context.has_negative_cover_left_of_char(start) else self.context.next_negative_start_char(start)
        ci = self.context.clue_index
        stream = self.context.stream
        # 检查 cursor 是否在某个 blocker clue 内部（cover_prefix_sum 快速排除）。
        if stream.char_to_unit and 0 < start < len(stream.char_to_unit):
            cursor_unit = stream.char_to_unit[start]
            if cursor_unit < ci.unit_count and ci.cover_prefix_sum[cursor_unit + 1] - ci.cover_prefix_sum[cursor_unit] > 0:
                for clue in self.context.clues:
                    if clue.clue_id == self.clue.clue_id:
                        continue
                    if clue.start < start < clue.end and self._is_label_right_blocker(clue):
                        return start if blocker_start is None else min(blocker_start, start)
        # 向右查找第一个 blocker。
        if stream.char_to_unit and start < len(stream.char_to_unit):
            start_unit = stream.char_to_unit[min(start, len(stream.char_to_unit) - 1)]
            clues = self.context.clues
            for u in range(start_unit, ci.unit_count):
                for idx in ci.clues_starting_at[u]:
                    if idx <= self.clue_index:
                        continue
                    clue = clues[idx]
                    if clue.end <= start:
                        continue
                    if self._is_label_right_blocker(clue):
                        candidate = max(start, clue.start)
                        blocker_start = candidate if blocker_start is None else min(blocker_start, candidate)
                        return blocker_start
        return blocker_start

    def _is_label_right_blocker(self, clue: Clue) -> bool:
        if clue.role in {ClueRole.BREAK, ClueRole.NEGATIVE, ClueRole.LABEL}:
            return True
        if clue.strength == ClaimStrength.HARD:
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

    def _build_value_seed_run(self, *, locale: str) -> StackRun | None:
        """VALUE seed：已知公司名起栈，向右搜索 suffix 以扩展。"""
        value_start = self.clue.start
        value_end = self.clue.end
        # 向右搜索 suffix。
        suffix_clue = self._find_suffix_after_value(value_end, locale=locale)
        consumed_ids = {self.clue.clue_id}
        if suffix_clue is not None:
            # 有 suffix → 吸收 value ~ suffix 区间。
            end = suffix_clue.end
            consumed_ids.add(suffix_clue.clue_id)
        else:
            end = value_end
        start = value_start
        matches = self._organization_clues_in_span(start, end)
        unit_start, unit_end = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=unit_start,
            unit_end=unit_end,
            value_driven=True,
        )
        if candidate is None:
            return None
        evidence = self._build_org_evidence(
            start=start,
            end=end,
            is_label_seed=False,
            default_suffix_strength=suffix_clue.strength if suffix_clue is not None else None,
            default_value_strength=self.clue.strength,
        )
        if not _meets_org_commit_threshold(
            evidence=evidence,
            locale=locale,
            protection_level=self.context.protection_level,
        ):
            return None
        candidate.claim_strength = evidence.max_clue_strength
        consumed_ids.update(clue_id for _index, clue in matches for clue_id in [clue.clue_id])
        last_index = max(
            (index for index, _clue in matches),
            default=self.clue_index,
        )
        return StackRun(
            attr_type=PIIAttributeType.ORGANIZATION,
            candidate=candidate,
            consumed_ids=consumed_ids,
            handled_label_clue_ids=set(),
            next_index=last_index + 1,
        )

    def _find_suffix_after_value(self, value_end: int, *, locale: str) -> Clue | None:
        """在 value 右侧窗口内查找 SUFFIX clue（中文 ≤6 unit，英文 ≤2 word-token）。"""
        stream = self.context.stream
        if not stream.char_to_unit or value_end >= len(stream.text):
            return None
        value_end_ui = _unit_index_at_or_after(stream, value_end)
        window_limit = 6 if locale == "zh" else 2
        body_count = 0
        # 逐 unit 计数，在窗口内查找 suffix。
        upper_char = len(stream.text)
        ui = value_end_ui
        while ui < len(stream.units) and body_count < window_limit:
            unit = stream.units[ui]
            if unit.kind in {"space", "punct"}:
                ui += 1
                continue
            if _is_organization_count_unit(unit.kind, locale):
                body_count += 1
                upper_char = unit.char_end
                ui += 1
                continue
            break
        # 在窗口范围内搜索 suffix clue。
        for index in range(self.clue_index + 1, len(self.context.clues)):
            clue = self.context.clues[index]
            if clue.start > upper_char:
                break
            if clue.start < value_end:
                continue
            if clue.attr_type != PIIAttributeType.ORGANIZATION or clue.role != ClueRole.SUFFIX:
                continue
            return clue
        return None

    def _organization_clues_in_span(self, start: int, end: int, *, include_hard: bool = False) -> list[tuple[int, Clue]]:
        ci = self.context.clue_index
        us, ue = _char_span_to_unit_span(self.context.stream, start, end)
        org_starts = ci.family_starts.get(ClueFamily.ORGANIZATION)
        if org_starts is None or ue <= us:
            return []
        clues = self.context.clues
        matches: list[tuple[int, Clue]] = []
        for u in range(max(0, us), min(ue, ci.unit_count)):
            for idx in org_starts[u]:
                clue = clues[idx]
                if clue.attr_type != PIIAttributeType.ORGANIZATION:
                    continue
                if clue.strength == ClaimStrength.HARD and not include_hard:
                    continue
                if clue.start < end and clue.end > start:
                    matches.append((idx, clue))
        return matches

    def _build_org_evidence(
        self,
        *,
        start: int,
        end: int,
        is_label_seed: bool,
        default_suffix_strength: ClaimStrength | None,
        default_value_strength: ClaimStrength | None,
    ) -> "_OrgEvidence":
        """聚合组织候选证据，为提交阈值提供统一输入。"""
        has_suffix = False
        has_value = False
        suffix_strength = default_suffix_strength or ClaimStrength.WEAK
        value_strength = default_value_strength or ClaimStrength.WEAK
        for _index, clue in self._organization_clues_in_span(start, end, include_hard=True):
            if clue.role == ClueRole.SUFFIX:
                has_suffix = True
                suffix_strength = _max_strength(suffix_strength, clue.strength)
            elif clue.role == ClueRole.VALUE:
                has_value = True
                value_strength = _max_strength(value_strength, clue.strength)
        if self.clue.role == ClueRole.SUFFIX:
            has_suffix = True
            suffix_strength = _max_strength(suffix_strength, self.clue.strength)
        if self.clue.role == ClueRole.VALUE:
            has_value = True
            value_strength = _max_strength(value_strength, self.clue.strength)
        return _OrgEvidence(
            has_suffix=has_suffix,
            suffix_strength=suffix_strength,
            has_value=has_value,
            value_strength=value_strength,
            has_label=is_label_seed,
            max_clue_strength=_max_strength(suffix_strength, value_strength),
        )


@dataclass(frozen=True, slots=True)
class _OrgEvidence:
    """组织候选提交阈值所需的证据摘要。"""
    has_suffix: bool = False
    suffix_strength: ClaimStrength = ClaimStrength.WEAK
    has_value: bool = False
    value_strength: ClaimStrength = ClaimStrength.WEAK
    has_label: bool = False
    max_clue_strength: ClaimStrength = ClaimStrength.WEAK


def _max_strength(left: ClaimStrength, right: ClaimStrength) -> ClaimStrength:
    order = {
        ClaimStrength.WEAK: 0,
        ClaimStrength.SOFT: 1,
        ClaimStrength.HARD: 2,
    }
    return left if order[left] >= order[right] else right


def _meets_org_commit_threshold(
    *,
    evidence: _OrgEvidence,
    locale: str,
    protection_level: ProtectionLevel,
) -> bool:
    """组织候选提交阈值。

    规则来自 guide 里的 6 组场景矩阵：
    1) HARD suffix / VALUE+suffix / LABEL seed 全级别通过。
    2) suffix-only 按语言+强度+保护级别收敛。
    3) value-only：HARD 在 STRONG/BALANCED 通过，SOFT 仅 STRONG 通过。
    """
    if evidence.has_label:
        return True
    if evidence.has_suffix and evidence.suffix_strength == ClaimStrength.HARD:
        return True
    if evidence.has_suffix and evidence.has_value:
        return True
    is_strong = protection_level == ProtectionLevel.STRONG
    is_balanced = protection_level == ProtectionLevel.BALANCED
    if evidence.has_suffix and not evidence.has_value:
        if evidence.suffix_strength == ClaimStrength.SOFT:
            if locale == "zh":
                # inspire 机制移除后，zh + SOFT suffix-only 仅在 STRONG 通过。
                return is_strong
            return is_strong or is_balanced
        if evidence.suffix_strength == ClaimStrength.WEAK:
            # inspire 机制移除后，WEAK suffix-only 一律拒绝。
            return False
        return False
    if evidence.has_value and not evidence.has_suffix:
        if evidence.value_strength == ClaimStrength.HARD:
            return is_strong or is_balanced
        if evidence.value_strength == ClaimStrength.SOFT:
            return is_strong
    return False


def _left_expand_text_boundary(context, start: int, *, should_break) -> int:
    """组织名向左扩展文本边界。遇到任何断点符号即停止。"""
    raw_text = context.stream.text
    clues = context.clues
    floor = 0
    negative_floor = context.previous_negative_end_char(start)
    if negative_floor is not None:
        floor = max(floor, negative_floor)
    for clue in reversed(clues):
        if clue.end <= start:
            if should_break(clue):
                floor = clue.end
                break
    index = start
    while index > floor:
        previous = raw_text[index - 1]
        if is_any_break(previous):
            break
        index -= 1
    return index


def _organization_body_limit(locale: str) -> int:
    return 6 if locale == "zh" else 4


def _is_organization_count_unit(kind: str, locale: str) -> bool:
    if locale == "zh":
        return kind in {"cjk_char", "ascii_word"}
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
        if unit.kind == "space":
            if locale == "en" and end > start:
                end = min(unit.char_end, upper)
                ui += 1
                continue
            break
        if unit.kind == "punct":
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
        if unit.kind == "space":
            if locale != "en":
                break
            next_start = max(floor, unit.char_start)
            ui -= 1
            continue
        if unit.kind == "punct":
            break
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
