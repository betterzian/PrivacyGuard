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
    _family_value_floor_char,
    _floor_clamped_label_seed_start_char,
    _count_non_space_units,
    _starter_is_before_family_value_floor,
    _unit_char_end,
    _unit_char_start,
    _unit_index_at_or_after,
    _unit_index_left_of,
    is_control_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import is_any_break, is_hard_break

_ORG_SOFT_NEGATIVE_SCOPES = ("organization", "ui")


@dataclass(slots=True)
class BaseOrganizationStack(BaseStack):
    """组织名检测 stack 基类。"""

    STACK_LOCALE = "zh"

    def _has_organization_negative_cover(self, unit_start: int, unit_last: int) -> bool:
        """组织栈的负向由显式 negative、LABEL 与 START 构成，不吸收 inspire。"""
        return self._has_semantic_negative_cover(
            unit_start,
            unit_last,
            scopes=_ORG_SOFT_NEGATIVE_SCOPES,
            include_seed_roles=True,
            include_inspire=False,
        )

    def _value_floor_char(self) -> int:
        """返回 ORGANIZATION 当前生效的 value 起点下界。"""
        return _family_value_floor_char(self.context, ClueFamily.ORGANIZATION)

    def _starter_is_before_value_floor(self) -> bool:
        """非 LABEL/START 起栈不得从已锁住的 value 区间左侧开始。"""
        return _starter_is_before_family_value_floor(self.context, self.clue, ClueFamily.ORGANIZATION)

    def should_break_clue(self, subject, **kwargs) -> bool:
        del kwargs
        if isinstance(subject, Clue):
            if subject.role == ClueRole.BREAK:
                return True
            if subject.role in {ClueRole.LABEL, ClueRole.START}:
                return subject.attr_type != PIIAttributeType.ORGANIZATION
            return subject.strength == ClaimStrength.HARD and subject.attr_type not in {
                None,
                PIIAttributeType.ORGANIZATION,
            }
        return False

    def shrink(self, run: StackRun, blocker_start: int, blocker_last: int) -> StackRun | None:
        """组织名回缩：后缀被截即放弃，前缀被截后需重新校验。"""
        candidate = run.candidate
        stream = self.context.stream
        if blocker_start <= candidate.unit_start:
            new_unit_start, new_unit_last = blocker_last + 1, candidate.unit_last
        elif blocker_last >= candidate.unit_last:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        else:
            new_unit_start, new_unit_last = candidate.unit_start, blocker_start - 1
        if new_unit_last < new_unit_start:
            return None
        trimmed = trim_candidate(
            candidate,
            stream.text,
            start=_unit_char_start(stream, new_unit_start),
            end=_unit_char_end(stream, new_unit_last),
            unit_start=new_unit_start,
            unit_last=new_unit_last,
        )
        if trimmed is None:
            return None
        if not _is_organization_candidate_usable(trimmed.text, label_driven=trimmed.label_driven):
            return None
        return StackRun(
            attr_type=run.attr_type,
            candidate=trimmed,
            handled_label_clue_ids=run.handled_label_clue_ids,
            frontier_last_unit=trimmed.unit_last,
        )

    def run(self) -> StackRun | None:
        if self._starter_is_before_value_floor():
            return None
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}
        locale = self.STACK_LOCALE
        if is_label_seed:
            start = _floor_clamped_label_seed_start_char(self.context, ClueFamily.ORGANIZATION, self.clue.end)
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
        start, end = self._soft_trim_negative_edges(start=start, end=end, locale=locale)
        if end <= start:
            return None
        matches = self._organization_clues_in_span(start, end)
        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=unit_start,
            unit_last=unit_last,
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
        return StackRun(
            attr_type=PIIAttributeType.ORGANIZATION,
            candidate=candidate,
            handled_label_clue_ids=handled,
            frontier_last_unit=candidate.unit_last,
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
        floor = _left_expand_text_boundary(self.context, self.clue.start, should_break=self.should_break_clue)
        floor = max(floor, self._value_floor_char())
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
        blocker_start = None
        for clue in self.context.clues:
            if clue.clue_id == self.clue.clue_id:
                continue
            if clue.start < start < clue.end and self._is_label_right_blocker(clue):
                return start if blocker_start is None else min(blocker_start, start)
            if clue.end > start and self._is_label_right_blocker(clue):
                candidate = max(start, clue.start)
                blocker_start = candidate if blocker_start is None else min(blocker_start, candidate)
                return blocker_start
        return blocker_start

    def _is_label_right_blocker(self, clue: Clue) -> bool:
        if clue.role == ClueRole.BREAK:
            return True
        if clue.role in {ClueRole.LABEL, ClueRole.START}:
            return clue.attr_type != PIIAttributeType.ORGANIZATION
        if clue.strength == ClaimStrength.HARD and clue.attr_type != PIIAttributeType.ORGANIZATION:
            return True
        return False

    def _find_suffix_end_within_window(self, *, start: int, upper: int) -> int | None:
        if start >= upper or not self.context.stream.char_to_unit:
            return None
        start_ui = _unit_index_at_or_after(self.context.stream, start)
        for clue in self.context.clues[self.clue_index + 1 :]:
            if clue.start >= upper:
                break
            if clue.end <= start:
                continue
            if clue.attr_type == PIIAttributeType.ORGANIZATION and clue.role == ClueRole.SUFFIX:
                suffix_ui = self.context.stream.char_to_unit[clue.start]
                if _count_non_space_units(self.context.stream.units, start_ui, suffix_ui + 1) <= 10:
                    return clue.end
        return None

    def _build_value_seed_run(self, *, locale: str) -> StackRun | None:
        """VALUE seed：已知公司名起栈，向右搜索 suffix 以扩展。"""
        if self._starter_is_before_value_floor():
            return None
        value_start = self.clue.start
        value_end = self.clue.end
        # 向右搜索 suffix。
        suffix_clue = self._find_suffix_after_value(value_end, locale=locale)
        if suffix_clue is not None:
            # 有 suffix → 吸收 value ~ suffix 区间。
            end = suffix_clue.end
        else:
            end = value_end
        start = value_start
        start, end = self._soft_trim_negative_edges(start=start, end=end, locale=locale)
        if end <= start:
            return None
        matches = self._organization_clues_in_span(start, end)
        unit_start, unit_last = _char_span_to_unit_span(self.context.stream, start, end)
        candidate = build_organization_candidate_from_value(
            source=self.context.stream.source,
            value_text=self.context.stream.text[start:end],
            value_start=start,
            value_end=end,
            source_kind=self.clue.source_kind,
            unit_start=unit_start,
            unit_last=unit_last,
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
        return StackRun(
            attr_type=PIIAttributeType.ORGANIZATION,
            candidate=candidate,
            handled_label_clue_ids=set(),
            frontier_last_unit=candidate.unit_last,
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
        for clue in self.context.clues[self.clue_index + 1 :]:
            if clue.start > upper_char:
                break
            if clue.start < value_end:
                continue
            if clue.attr_type == PIIAttributeType.ORGANIZATION and clue.role == ClueRole.SUFFIX:
                return clue
        return None

    def _organization_clues_in_span(self, start: int, end: int, *, include_hard: bool = False) -> list[tuple[int, Clue]]:
        matches: list[tuple[int, Clue]] = []
        for index, clue in enumerate(self.context.clues):
            if clue.start >= end:
                break
            if clue.attr_type == PIIAttributeType.ORGANIZATION:
                if clue.strength != ClaimStrength.HARD or include_hard:
                    if clue.end > start:
                        matches.append((index, clue))
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
            capitalized_body_tokens=_max_adjacent_capitalized_body_tokens(
                self.context.stream,
                start=start,
                end=end,
            ),
        )

    def _soft_trim_negative_edges(self, *, start: int, end: int, locale: str) -> tuple[int, int]:
        """普通 negative 只在组织候选两端做软裁边，不参与硬拒绝。"""
        if end <= start or not self.context.stream.units:
            return start, end
        stream = self.context.stream
        unit_start, unit_last = _char_span_to_unit_span(stream, start, end)
        while unit_start <= unit_last and self._has_organization_negative_cover(unit_start, unit_start):
            if _organization_edge_unit_is_protected(
                stream,
                self.context.clues,
                unit_start,
                locale=locale,
            ):
                break
            unit_start += 1
        while unit_last >= unit_start and self._has_organization_negative_cover(unit_last, unit_last):
            if _organization_edge_unit_is_protected(
                stream,
                self.context.clues,
                unit_last,
                locale=locale,
            ):
                break
            unit_last -= 1
        if unit_last < unit_start:
            return start, start
        return (_unit_char_start(stream, unit_start), _unit_char_end(stream, unit_last))


@dataclass(frozen=True, slots=True)
class _OrgEvidence:
    """组织候选提交阈值所需的证据摘要。"""
    has_suffix: bool = False
    suffix_strength: ClaimStrength = ClaimStrength.WEAK
    has_value: bool = False
    value_strength: ClaimStrength = ClaimStrength.WEAK
    has_label: bool = False
    max_clue_strength: ClaimStrength = ClaimStrength.WEAK
    capitalized_body_tokens: int = 0


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
        if locale != "en":
            return True
        return (
            evidence.has_value
            or evidence.has_suffix
            or evidence.capitalized_body_tokens >= 2
        )
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


def _organization_edge_unit_is_protected(
    stream: StreamInput,
    clues: tuple[Clue, ...],
    unit_index: int,
    *,
    locale: str,
) -> bool:
    """负向仅作软裁边时，主体 token / capitalized token / suffix 不应被裁掉。"""
    if unit_index < 0 or unit_index >= len(stream.units):
        return False
    unit = stream.units[unit_index]
    if unit.kind == "space":
        return False
    if unit.kind == "ascii_word" and _is_capitalized_ascii_org_unit(unit.text):
        return True
    if _is_organization_count_unit(unit.kind, locale):
        return True
    unit_start = unit.char_start
    unit_end = unit.char_end
    return any(
        clue.attr_type == PIIAttributeType.ORGANIZATION
        and clue.role == ClueRole.SUFFIX
        and clue.start < unit_end
        and clue.end > unit_start
        for clue in clues
    )


def _is_capitalized_ascii_org_unit(text: str) -> bool:
    token = str(text or "").strip()
    if not token:
        return False
    first_char = token[0]
    return first_char.isascii() and first_char.isalpha() and first_char.isupper()


def _max_adjacent_capitalized_body_tokens(
    stream: StreamInput,
    *,
    start: int,
    end: int,
) -> int:
    """统计候选内部最长的连续首字母大写 ASCII token 片段。"""
    if end <= start or not stream.units or not stream.char_to_unit:
        return 0
    unit_start, unit_last = _char_span_to_unit_span(stream, start, end)
    current = 0
    best = 0
    awaiting_next_token = False
    for ui in range(unit_start, unit_last + 1):
        unit = stream.units[ui]
        if unit.kind == "space":
            awaiting_next_token = current > 0
            continue
        if unit.kind == "ascii_word" and _is_capitalized_ascii_org_unit(unit.text):
            current = current + 1 if current > 0 and awaiting_next_token else 1
            best = max(best, current)
            awaiting_next_token = False
            continue
        current = 0
        awaiting_next_token = False
    return best


def _is_organization_candidate_usable(text: str, *, label_driven: bool) -> bool:
    if not text:
        return False
    if not has_organization_suffix(text) and not label_driven:
        return False
    return _organization_has_body_before_suffix(text)

