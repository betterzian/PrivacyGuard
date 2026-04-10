"""地址 stack 与地址专属 helper。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.infrastructure.pii.detector.candidate_utils import clean_value, has_address_signal, trim_candidate
from privacyguard.infrastructure.pii.detector.models import AddressComponentType, CandidateDraft, ClaimStrength, Clue, ClueRole
from privacyguard.infrastructure.pii.detector.lexicon_loader import (
    load_en_address_keyword_groups,
    load_zh_address_keyword_groups,
 )
from privacyguard.infrastructure.pii.detector.stacks.base import BaseStack, PendingChallenge, StackRun
from privacyguard.infrastructure.pii.detector.stacks.common import (
    _char_span_to_unit_span,
    _is_stop_control_clue,
    _skip_separators,
    _unit_index_at_or_after,
    _unit_index_left_of,
    _unit_char_end,
    _unit_char_start,
    is_break_clue,
    is_control_clue,
    is_negative_clue,
)
from privacyguard.infrastructure.pii.rule_based_detector_shared import (
    _OCR_INLINE_GAP_TOKEN,
    OCR_BREAK,
    is_any_break,
    is_hard_break,
    is_soft_break,
)

_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY, AddressComponentType.DISTRICT,
    AddressComponentType.SUBDISTRICT,
})

# 精简后的后继图（9 节点）。
_VALID_SUCCESSORS: dict[AddressComponentType, frozenset[AddressComponentType]] = {
    AddressComponentType.PROVINCE:    frozenset({AddressComponentType.CITY, AddressComponentType.DISTRICT,
                                                 AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI}),
    AddressComponentType.CITY:        frozenset({AddressComponentType.DISTRICT, AddressComponentType.SUBDISTRICT,
                                                 AddressComponentType.ROAD, AddressComponentType.POI}),
    AddressComponentType.DISTRICT:    frozenset({AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI}),
    AddressComponentType.SUBDISTRICT: frozenset({AddressComponentType.SUBDISTRICT, AddressComponentType.ROAD,
                                                 AddressComponentType.POI, AddressComponentType.NUMBER}),
    AddressComponentType.ROAD:        frozenset({AddressComponentType.NUMBER, AddressComponentType.POI,
                                                 AddressComponentType.BUILDING, AddressComponentType.DETAIL}),
    AddressComponentType.NUMBER:      frozenset({AddressComponentType.POI, AddressComponentType.BUILDING,
                                                 AddressComponentType.DETAIL}),
    AddressComponentType.POI:         frozenset({AddressComponentType.NUMBER, AddressComponentType.BUILDING,
                                                 AddressComponentType.DETAIL}),
    AddressComponentType.BUILDING:    frozenset({AddressComponentType.DETAIL}),
    AddressComponentType.DETAIL:      frozenset({AddressComponentType.DETAIL}),
}

# 可在地址末尾逆序追加的顶层 ADMIN（仅省/市/区），且必须此前未出现过。
_TRAILING_ADMIN_TYPES = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY, AddressComponentType.DISTRICT,
})

# POI 延迟提交时，这些后续 KEY 类型视为「可组合」——丢弃 POI 语义，用后续 KEY 的类型构建。
_POI_COMBINABLE_TYPES = frozenset({
    AddressComponentType.ROAD, AddressComponentType.BUILDING,
    AddressComponentType.DETAIL, AddressComponentType.SUBDISTRICT,
    AddressComponentType.POI,
})

# 省/市 VALUE 出现在这些层级后面时，降级为路名前缀文字而非独立 admin 组件。
_ADMIN_DEMOTABLE_AFTER = frozenset({
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
    AddressComponentType.DISTRICT,
})


def _compute_reachable(
    successors: dict[AddressComponentType, frozenset[AddressComponentType]],
) -> dict[AddressComponentType, frozenset[AddressComponentType]]:
    """计算传递闭包：从每个节点出发可多步到达的所有节点集合。"""
    reachable: dict[AddressComponentType, set[AddressComponentType]] = {}
    for node in successors:
        visited: set[AddressComponentType] = set()
        stack = list(successors.get(node, frozenset()))
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            stack.extend(successors.get(cur, frozenset()))
        reachable[node] = visited
    return {k: frozenset(v) for k, v in reachable.items()}


_REACHABLE = _compute_reachable(_VALID_SUCCESSORS)
_ALL_TYPES = frozenset(AddressComponentType)

_DETAIL_COMPONENTS = {
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
}


def _en_prefix_keywords() -> set[str]:
    """从外部 lexicon 派生英文前缀关键字集合（detail 类如 apt/suite/unit/floor/room/# 等）。"""
    keywords: set[str] = set()
    for group in load_en_address_keyword_groups():
        if group.component_type != AddressComponentType.DETAIL:
            continue
        for kw in group.keywords:
            text = str(kw or "").strip().lower()
            if text:
                keywords.add(text)
    keywords.add("#")
    return keywords


_PREFIX_EN_KEYWORDS = _en_prefix_keywords()
_EN_VALUE_KEY_GAP_RE = re.compile(r"^[ ]*$")
_SINGLE_EVIDENCE_ADMIN = {
    AddressComponentType.PROVINCE,
    AddressComponentType.CITY,
}

# 地址内可吸收的非 ADDRESS attr_type——数字片段和字母数字片段。
_ABSORBABLE_DIGIT_ATTR_TYPES = frozenset({PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM})


def _is_absorbable_digit_clue(clue: Clue) -> bool:
    """判断非 ADDRESS clue 是否为可被地址栈吸收的数字片段（≤5 位）。"""
    if clue.attr_type not in _ABSORBABLE_DIGIT_ATTR_TYPES:
        return False
    digits = (clue.source_metadata.get("pure_digits") or [""])[0]
    return len(digits) <= 5


@dataclass(slots=True)
class AddressStack(BaseStack):
    def shrink(self, run: StackRun, blocker_start: int, blocker_end: int) -> StackRun | None:
        """地址回缩：截断后若失去地址信号则放弃。"""
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
        """地址 stack 主入口。"""
        if self.clue.strength == ClaimStrength.HARD:
            return self._build_direct_run()

        raw_text = self.context.stream.text
        stream = self.context.stream
        locale = self._value_locale()
        is_label_seed = self.clue.role in {ClueRole.LABEL, ClueRole.START}

        if is_label_seed:
            address_start = _skip_separators(raw_text, self.clue.end)
            start_unit = _unit_index_at_or_after(stream, address_start)
            seed_index = _label_seed_address_index(self.context.clues, start_unit, max_units=6)
            if seed_index is None:
                return None
            scan_index = seed_index
            consumed_ids: set[str] = {self.clue.clue_id}
            handled_labels: set[str] = {self.clue.clue_id}
            evidence_count = 1
        else:
            address_start = self._seed_left_boundary()
            scan_index = self.clue_index
            consumed_ids = set()
            handled_labels = set()
            evidence_count = 0
        if address_start is None:
            return None

        components: list[dict[str, object]] = []
        last_end = address_start
        last_component_type: AddressComponentType | None = None
        seen_types: set[AddressComponentType] = set()
        in_trailing_admin = False
        pending_value: dict[AddressComponentType, Clue] = {}
        index = scan_index
        negative_spans: list[tuple[int, int]] = []
        last_consumed_address_clue: Clue | None = None
        last_value_clue: Clue | None = None
        absorbed_digit_unit_end: int = 0
        # POI 延迟提交状态。
        deferred_poi: Clue | None = None
        deferred_poi_index: int = -1
        # 省/市 VALUE 降级为路名前缀时，记录首个降级 VALUE 的 start 位置。
        demoted_value_start: int | None = None

        while index < len(self.context.clues):
            clue = self.context.clues[index]

            if is_break_clue(clue):
                break
            if is_negative_clue(clue):
                negative_spans.append((clue.start, clue.end))
                index += 1
                continue
            if clue.attr_type is None:
                index += 1
                continue
            if clue.attr_type != PIIAttributeType.ADDRESS:
                if _is_absorbable_digit_clue(clue):
                    absorbed_digit_unit_end = max(absorbed_digit_unit_end, clue.unit_end)
                    index += 1
                    continue
                if clue.attr_type in {PIIAttributeType.NAME, PIIAttributeType.ORGANIZATION}:
                    if _has_nearby_address_clue(self.context.clues, index + 1, clue.end,
                                                locale=locale, raw_text=raw_text):
                        absorbed_digit_unit_end = max(absorbed_digit_unit_end, clue.unit_end)
                        index += 1
                        continue
                    break
                break
            if clue.role == ClueRole.LABEL:
                index += 1
                continue
            if clue.start < address_start:
                index += 1
                continue

            # gap 检查：6 unit 以内没有新 clue 则截止。
            if last_consumed_address_clue is not None:
                gap_anchor = max(last_consumed_address_clue.unit_end, absorbed_digit_unit_end)
                if clue.unit_start - gap_anchor > 6:
                    break

            comp_type = clue.component_type
            if comp_type is None:
                index += 1
                continue

            # "号"上下文重映射：NUMBER 出现在 BUILDING/DETAIL 后面时重映射为 DETAIL。
            if comp_type == AddressComponentType.NUMBER:
                if last_component_type in {AddressComponentType.BUILDING, AddressComponentType.DETAIL}:
                    comp_type = AddressComponentType.DETAIL

            # ---- 邻接表检查 ----
            if last_component_type is not None:
                if in_trailing_admin:
                    if comp_type not in _TRAILING_ADMIN_TYPES or comp_type in seen_types:
                        break
                elif comp_type not in _REACHABLE.get(last_component_type, _ALL_TYPES):
                    if comp_type in _TRAILING_ADMIN_TYPES and comp_type not in seen_types:
                        # 逆序必须有逗号。
                        gap_text = raw_text[last_end:clue.start]
                        if ',' not in gap_text and '，' not in gap_text:
                            break
                        in_trailing_admin = True
                    elif (comp_type in {AddressComponentType.PROVINCE, AddressComponentType.CITY}
                          and clue.role == ClueRole.VALUE
                          and last_component_type in _ADMIN_DEMOTABLE_AFTER):
                        # 省/市 VALUE 出现在区以上层级后面 → 降级为路名前缀文字。
                        if demoted_value_start is None:
                            demoted_value_start = clue.start
                        consumed_ids.add(clue.clue_id)
                        last_consumed_address_clue = clue
                        last_end = max(last_end, clue.end)
                        index += 1
                        continue
                    else:
                        break

            # ---- POI 延迟提交（KEY 和 VALUE 统一） ----
            if comp_type == AddressComponentType.POI and clue.role in {ClueRole.KEY, ClueRole.VALUE}:
                # 先处理前一个 deferred_poi（如果有）。
                if deferred_poi is not None:
                    poi_adjacent = _is_adjacent(raw_text, deferred_poi, clue)
                    if poi_adjacent:
                        pass  # POI 叠 POI 且相邻 → 替换，旧 deferred 文字保留在跨度内。
                    else:
                        poi_comp = self._submit_deferred_poi(raw_text, deferred_poi, deferred_poi_index, locale)
                        if poi_comp is not None:
                            components.append(poi_comp)
                            evidence_count += 1
                            last_end = max(last_end, int(poi_comp["end"]))
                            last_component_type = AddressComponentType.POI
                # 存为新的 deferred。
                seen_types.add(comp_type)
                consumed_ids.add(clue.clue_id)
                last_consumed_address_clue = clue
                last_end = max(last_end, clue.end)
                deferred_poi = clue
                deferred_poi_index = index
                index += 1
                continue

            # 非 POI clue 到达时，解决已有的 deferred_poi。
            if deferred_poi is not None:
                if clue.role == ClueRole.KEY:
                    adjacent = _is_adjacent(raw_text, deferred_poi, clue)
                    if adjacent and comp_type in _POI_COMBINABLE_TYPES:
                        combo = self._build_deferred_poi_combo(raw_text, deferred_poi, deferred_poi_index,
                                                               clue, comp_type, index, locale)
                        deferred_poi = None
                        deferred_poi_index = -1
                        seen_types.add(comp_type)
                        consumed_ids.add(clue.clue_id)
                        last_consumed_address_clue = clue
                        if combo is not None:
                            components.append(combo)
                            evidence_count += 1
                            last_end = max(last_end, int(combo["end"]))
                            last_component_type = comp_type
                        index += 1
                        continue
                # 不可组合 / 不相邻 / 当前是 VALUE → 独立提交 deferred_poi。
                poi_comp = self._submit_deferred_poi(raw_text, deferred_poi, deferred_poi_index, locale)
                if poi_comp is not None:
                    components.append(poi_comp)
                    evidence_count += 1
                    last_end = max(last_end, int(poi_comp["end"]))
                    last_component_type = AddressComponentType.POI
                deferred_poi = None
                deferred_poi_index = -1
                # 继续正常处理当前 clue（不 continue）。

            seen_types.add(comp_type)
            consumed_ids.add(clue.clue_id)
            last_consumed_address_clue = clue

            if clue.role == ClueRole.VALUE:
                # 正常 VALUE 到达，清除之前的降级记录。
                demoted_value_start = None
                if comp_type in pending_value:
                    previous = pending_value[comp_type]
                    default_key = _default_key_for_component_type(comp_type, locale)
                    standalone = _build_standalone_address_component_with_key(previous, comp_type, key=default_key)
                    if standalone is not None:
                        components.append(standalone)
                        evidence_count += 1
                        last_end = max(last_end, int(standalone["end"]))
                    del pending_value[comp_type]
                self._flush_pending_values(pending_value, comp_type, components)
                pending_value[comp_type] = clue
                last_value_clue = clue
                last_end = max(last_end, clue.end)
                last_component_type = comp_type
                index += 1
                continue

            same_tier_value = pending_value.pop(comp_type, None)
            flushed = self._flush_pending_values(pending_value, comp_type, components)
            evidence_count += flushed

            if same_tier_value is not None:
                demoted_value_start = None  # 同层合并优先，清除降级记录。
                component, merged = _build_value_key_component(
                    raw_text,
                    same_tier_value,
                    clue,
                    comp_type,
                    locale=locale,
                )
                if merged:
                    if component is not None:
                        components.append(component)
                        evidence_count += 1
                        last_end = max(last_end, int(component["end"]))
                        last_component_type = comp_type
                else:
                    standalone = _build_standalone_address_component(same_tier_value, comp_type)
                    if standalone is not None:
                        components.append(standalone)
                        evidence_count += 1
                        last_end = max(last_end, int(standalone["end"]))
                    key_comp = self._build_key_component(raw_text, clue, comp_type, index, locale)
                    if key_comp is not None:
                        components.append(key_comp)
                        evidence_count += 1
                        last_end = max(last_end, int(key_comp["end"]))
                    last_component_type = comp_type
            else:
                component = None
                # 有被降级的省/市 VALUE → 用其 start 作为 value 左边界。
                if demoted_value_start is not None:
                    dv_start = demoted_value_start
                    demoted_value_start = None
                    value_text = raw_text[dv_start:clue.start]
                    value = _normalize_address_value(comp_type, value_text)
                    if value:
                        component = {
                            "component_type": comp_type,
                            "start": dv_start,
                            "end": clue.end,
                            "value": value,
                            "key": clue.text,
                            "is_detail": comp_type in _DETAIL_COMPONENTS,
                        }
                elif last_value_clue is not None and clue.unit_start - last_value_clue.unit_end <= 1:
                    component = _build_cross_tier_value_key_component(raw_text, last_value_clue, clue, comp_type)
                if component is None:
                    component = self._build_key_component(raw_text, clue, comp_type, index, locale)
                if component is not None:
                    components.append(component)
                    evidence_count += 1
                    last_end = max(last_end, int(component["end"]))
                    last_component_type = comp_type
            index += 1

        # 循环结束后提交残留的 deferred_poi。
        if deferred_poi is not None:
            poi_comp = self._submit_deferred_poi(raw_text, deferred_poi, deferred_poi_index, locale)
            if poi_comp is not None:
                components.append(poi_comp)
                evidence_count += 1
                last_end = max(last_end, int(poi_comp["end"]))
            deferred_poi = None

        evidence_count += self._flush_all_pending(pending_value, components)

        if not components:
            return None
        if negative_spans:
            components = _pop_components_overlapping_negative(components, negative_spans)
            if not components:
                return None

        # digit_tail 三路分支：不扩展 / 直接扩展 / 挑战 StructuredStack。
        tail = _analyze_digit_tail(components, stream, self.context.clues, index)
        if tail is None:
            pass
        elif tail.followed_by_address_key:
            components = [*components, *tail.new_components]
        else:
            conservative_run = self._build_address_run(
                components, consumed_ids, handled_labels,
                evidence_count, locale, index,
            )
            if conservative_run is None:
                return None
            extended_run = self._build_address_run(
                [*components, *tail.new_components], consumed_ids, handled_labels,
                evidence_count, locale, index,
            )
            if extended_run is None:
                return conservative_run
            if tail.challenge_clue_index is None:
                # 没有对应的 NUMERIC/ALNUM clue，无竞争，直接用扩展候选。
                return extended_run
            conservative_run.pending_challenge = PendingChallenge(
                clue_index=tail.challenge_clue_index,
                cached_digit_text=tail.unit_text,
                cached_pure_digits=tail.pure_digits,
                extended_candidate=extended_run.candidate,
                extended_consumed_ids=extended_run.consumed_ids,
                extended_next_index=extended_run.next_index,
            )
            return conservative_run

        return self._build_address_run(
            components, consumed_ids, handled_labels,
            evidence_count, locale, index,
        )

    def _build_address_run(
        self,
        components: list[dict[str, object]],
        consumed_ids: set[str],
        handled_labels: set[str],
        evidence_count: int,
        locale: str,
        next_index: int,
    ) -> StackRun | None:
        """从 components 构建地址候选并包装为 StackRun。"""
        if not _meets_commit_threshold(
            evidence_count,
            components,
            locale,
            protection_level=self.context.protection_level,
        ):
            return None
        raw_text = self.context.stream.text
        final_start = min(int(c["start"]) for c in components)
        final_end = max(int(c["end"]) for c in components)
        text = clean_value(raw_text[final_start:final_end])
        if not text:
            return None
        relative = raw_text[final_start:final_end].find(text)
        absolute_start = final_start + max(0, relative)
        unit_start, unit_end = _char_span_to_unit_span(
            self.context.stream,
            absolute_start,
            absolute_start + len(text),
        )
        candidate = CandidateDraft(
            attr_type=PIIAttributeType.ADDRESS,
            start=absolute_start,
            end=absolute_start + len(text),
            unit_start=unit_start,
            unit_end=unit_end,
            text=text,
            source=self.context.stream.source,
            source_kind=self.clue.source_kind,
            claim_strength=ClaimStrength.SOFT,
            metadata=_address_metadata(self.clue, components),
            label_clue_ids=set(handled_labels),
            label_driven=(self.clue.role == ClueRole.LABEL),
        )
        return StackRun(
            attr_type=PIIAttributeType.ADDRESS,
            candidate=candidate,
            consumed_ids=set(consumed_ids),
            handled_label_clue_ids=set(handled_labels),
            next_index=next_index,
        )

    def _flush_pending_values(
        self,
        pending: dict[AddressComponentType, Clue],
        current_type: AddressComponentType,
        components: list[dict[str, object]],
    ) -> int:
        """将 pending 中与 current_type 不同类型的 VALUE flush 为独立 component。"""
        flushed = 0
        to_remove: list[AddressComponentType] = []
        for comp_type, value_clue in pending.items():
            if comp_type == current_type:
                continue
            component = _build_standalone_address_component(value_clue, comp_type)
            if component is not None:
                components.append(component)
                flushed += 1
            to_remove.append(comp_type)
        for comp_type in to_remove:
            del pending[comp_type]
        return flushed

    def _flush_all_pending(
        self,
        pending: dict[AddressComponentType, Clue],
        components: list[dict[str, object]],
    ) -> int:
        flushed = 0
        for comp_type, value_clue in pending.items():
            component = _build_standalone_address_component(value_clue, comp_type)
            if component is not None:
                components.append(component)
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
        key_text = clue.text
        if key_text.lower() in _PREFIX_EN_KEYWORDS:
            value_start = _skip_separators(raw_text, clue.end)
            value_end = _scan_forward_value_end(
                raw_text,
                value_start,
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

        floor = _left_address_floor(self.context.clues, clue_index)
        if locale.startswith("en"):
            expand_start = _left_expand_en_word(raw_text, clue.start, floor)
        else:
            # 中文 key：优先吸收 key 左侧紧邻的 digit_run unit（如 “100号”“3楼”“201室”）。
            stream = self.context.stream
            left_ui = _unit_index_left_of(stream, clue.start)
            if 0 <= left_ui < len(stream.units) and stream.units[left_ui].kind == "digit_run":
                expand_start = stream.units[left_ui].char_start
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

    def _submit_deferred_poi(
        self,
        raw_text: str,
        poi_clue: Clue,
        poi_index: int,
        locale: str,
    ) -> dict[str, object] | None:
        """将 deferred_poi 作为独立 POI 提交。KEY 走 _build_key_component，VALUE 走 standalone。"""
        if poi_clue.role == ClueRole.KEY:
            return self._build_key_component(raw_text, poi_clue,
                                             AddressComponentType.POI, poi_index, locale)
        return _build_standalone_address_component(poi_clue, AddressComponentType.POI)

    def _build_deferred_poi_combo(
        self,
        raw_text: str,
        poi_clue: Clue,
        poi_index: int,
        next_key: Clue,
        next_comp_type: AddressComponentType,
        next_index: int,
        locale: str,
    ) -> dict[str, object] | None:
        """POI 延迟提交的组合构建：用 deferred_poi 的位置取 value，next_key 的类型构建 component。"""
        if poi_clue.role == ClueRole.VALUE:
            # VALUE 自身就是完整文字，不需要左扩展。
            expand_start = poi_clue.start
        else:
            # KEY：左扩展找 value。
            floor = _left_address_floor(self.context.clues, poi_index)
            if locale.startswith("en"):
                expand_start = _left_expand_en_word(raw_text, poi_clue.start, floor)
            else:
                stream = self.context.stream
                left_ui = _unit_index_left_of(stream, poi_clue.start)
                if 0 <= left_ui < len(stream.units) and stream.units[left_ui].kind == "digit_run":
                    expand_start = stream.units[left_ui].char_start
                else:
                    expand_start = _left_expand_zh_chars(raw_text, poi_clue.start, floor, max_chars=2)
        value_text = raw_text[expand_start:next_key.start]
        value = _normalize_address_value(next_comp_type, value_text)
        if not value:
            return None
        return {
            "component_type": next_comp_type,
            "start": expand_start,
            "end": next_key.end,
            "value": value,
            "key": next_key.text,
            "is_detail": next_comp_type in _DETAIL_COMPONENTS,
        }

    def _seed_left_boundary(self) -> int | None:
        if self.clue.role in {ClueRole.VALUE, ClueRole.KEY}:
            return self.clue.start
        return None


def _is_adjacent(raw_text: str, left_clue: Clue, right_clue: Clue) -> bool:
    """判断两个 clue 是否紧邻（中间无有效字符，仅允许空白）。"""
    if left_clue.end > right_clue.start:
        return False
    gap = raw_text[left_clue.end:right_clue.start]
    return not gap or gap.isspace()


def _next_address_index(
    clues: tuple[Clue, ...],
    start_index: int,
    *,
    locale: str,
    raw_text: str,
) -> int | None:
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
        gap_text = raw_text[last_pos:clue.start]
        if locale.startswith("en"):
            if len(gap_text.split()) > 5:
                return None
        else:
            if len(gap_text) > 10:
                return None
    return None


def _has_nearby_address_clue(
    clues: tuple[Clue, ...],
    start_index: int,
    last_end: int,
    *,
    locale: str,
    raw_text: str | None = None,
) -> bool:
    for index in range(start_index, len(clues)):
        clue = clues[index]
        gap_chars = clue.start - last_end
        if gap_chars > 30:
            return False
        if is_break_clue(clue) or is_negative_clue(clue):
            return False
        if clue.attr_type == PIIAttributeType.ADDRESS and clue.role != ClueRole.LABEL:
            if locale.startswith("en") and raw_text is not None:
                gap_text = raw_text[last_end:clue.start]
                if len(gap_text.split()) > 3:
                    return False
            elif gap_chars > 6:
                return False
            return True
    return False


def _address_gap_too_wide(gap_text: str, locale: str) -> bool:
    if not gap_text:
        return False
    if OCR_BREAK in gap_text or _OCR_INLINE_GAP_TOKEN in gap_text:
        return True
    if any(is_hard_break(ch) for ch in gap_text):
        return True
    punct_count = sum(1 for ch in gap_text if is_soft_break(ch))
    if punct_count > 1:
        return True
    if locale.startswith("en"):
        return len(gap_text.split()) > 3
    return len(gap_text) > 6


def _build_value_key_component(
    raw_text: str,
    value_clue: Clue,
    key_clue: Clue,
    comp_type: AddressComponentType,
    locale: str,
) -> tuple[dict[str, object] | None, bool]:
    if value_clue.end <= key_clue.start:
        gap = raw_text[value_clue.end:key_clue.start]
    elif key_clue.end <= value_clue.start:
        gap = raw_text[key_clue.end:value_clue.start]
    else:
        gap = ""

    if gap:
        if locale.startswith("en"):
            if not _EN_VALUE_KEY_GAP_RE.fullmatch(gap):
                return None, False
        else:
            return None, False

    start = min(value_clue.start, key_clue.start)
    end = max(value_clue.end, key_clue.end)
    value = _normalize_address_value(comp_type, value_clue.text)
    if not value:
        return None, True
    return {
        "component_type": comp_type,
        "start": start,
        "end": end,
        "value": value,
        "key": key_clue.text,
        "is_detail": comp_type in _DETAIL_COMPONENTS,
    }, True


def _label_seed_address_index(clues: tuple[Clue, ...], start_unit: int, *, max_units: int) -> int | None:
    """label 起栈：start_unit 覆盖的 VALUE 优先，否则 max_units 内必须有 KEY。"""
    key_index: int | None = None
    for idx, clue in enumerate(clues):
        if clue.attr_type != PIIAttributeType.ADDRESS:
            continue
        if clue.role == ClueRole.LABEL:
            continue
        if clue.role == ClueRole.VALUE and clue.unit_start <= start_unit < clue.unit_end:
            return idx
        if clue.role == ClueRole.KEY and clue.unit_start >= start_unit and clue.unit_start - start_unit <= max_units:
            if key_index is None or clue.unit_start < clues[key_index].unit_start:
                key_index = idx
    return key_index


def _build_cross_tier_value_key_component(
    raw_text: str,
    value_clue: Clue,
    key_clue: Clue,
    comp_type: AddressComponentType,
) -> dict[str, object] | None:
    del raw_text
    start = min(value_clue.start, key_clue.start)
    end = max(value_clue.end, key_clue.end)
    value = _normalize_address_value(comp_type, value_clue.text)
    if not value:
        return None
    return {
        "component_type": comp_type,
        "start": start,
        "end": end,
        "value": value,
        "key": key_clue.text,
        "is_detail": comp_type in _DETAIL_COMPONENTS,
    }


def _overlaps_any_span(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _pop_components_overlapping_negative(
    components: list[dict[str, object]],
    negative_spans: list[tuple[int, int]],
) -> list[dict[str, object]]:
    """仅按最右组件判断 negative，避免中间命中连坐整个右尾。"""
    ordered = sorted(components, key=lambda c: (int(c["end"]), int(c["start"])))
    while ordered:
        last = ordered[-1]
        if not _overlaps_any_span(int(last["start"]), int(last["end"]), negative_spans):
            return ordered
        ordered.pop()
    return []


# digit_tail 每个层级的长度上限：(含字母时, 纯数字时)。
_DIGIT_TAIL_MAX_LEN: dict[AddressComponentType, tuple[int, int]] = {
    AddressComponentType.BUILDING: (5, 4),
    AddressComponentType.DETAIL: (5, 4),
}

_DIGIT_TAIL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9]+$")


def _max_dashes_for_prev_type(prev_type: AddressComponentType) -> int:
    """根据前驱 component 类型返回 digit_tail 允许的最大 dash 数。"""
    if prev_type in {AddressComponentType.ROAD, AddressComponentType.POI, AddressComponentType.NUMBER}:
        return 3
    if prev_type == AddressComponentType.BUILDING:
        return 2
    if prev_type == AddressComponentType.DETAIL:
        return 1
    return 0


def _parse_digit_tail(text: str, max_dashes: int) -> tuple[str, ...] | None:
    """解析 digit_run unit.text，按 '-' 分段，dash 数不超过 max_dashes。"""
    cleaned = str(text or "").strip()
    if not cleaned:
        return None
    dash_count = cleaned.count("-")
    if dash_count > max_dashes:
        return None
    if dash_count == 0:
        if not _DIGIT_TAIL_SEGMENT_RE.fullmatch(cleaned):
            return None
        return (cleaned,)
    segments: list[str] = []
    for part in cleaned.split("-"):
        seg = part.strip()
        if not seg or not _DIGIT_TAIL_SEGMENT_RE.fullmatch(seg):
            return None
        segments.append(seg)
    return tuple(segments) if segments else None


def _digit_tail_segment_valid(seg: str, comp_type: AddressComponentType) -> bool:
    """检查 digit_tail 段长度是否符合对应层级上限（纯数字上限 - 1）。"""
    limits = _DIGIT_TAIL_MAX_LEN.get(comp_type)
    if limits is None:
        return False
    alnum_max, digit_max = limits
    max_len = digit_max if seg.isdigit() else alnum_max
    return len(seg) <= max_len


_DETAIL_HIERARCHY = (
    AddressComponentType.BUILDING,
    AddressComponentType.DETAIL,
)


def _available_types_after(prev: AddressComponentType) -> list[AddressComponentType]:
    """由前驱 component 返回 digit_tail 可用的有序类型列表（贪心匹配用）。"""
    if prev in {AddressComponentType.ROAD, AddressComponentType.POI, AddressComponentType.NUMBER}:
        return list(_DETAIL_HIERARCHY)
    if prev == AddressComponentType.BUILDING:
        return [AddressComponentType.DETAIL]
    if prev == AddressComponentType.DETAIL:
        return [AddressComponentType.DETAIL]
    return list(_DETAIL_HIERARCHY)


def _greedy_assign_types(
    segments: tuple[str, ...],
    available: list[AddressComponentType],
) -> list[AddressComponentType] | None:
    """贪心为每段分配类型：依次尝试可用类型，第一个通过长度验证的即采用。

    返回与 segments 等长的类型列表；若某段无可用类型则返回 None。
    """
    result: list[AddressComponentType] = []
    avail = list(available)
    for seg in segments:
        assigned = False
        while avail:
            candidate_type = avail[0]
            if _digit_tail_segment_valid(seg, candidate_type):
                result.append(candidate_type)
                avail.pop(0)
                assigned = True
                break
            avail.pop(0)
        if not assigned:
            return None
    return result


def _digit_tail_step_down(comp_type: AddressComponentType) -> AddressComponentType:
    """严格层级下降：BUILDING → DETAIL。"""
    if comp_type == AddressComponentType.BUILDING:
        return AddressComponentType.DETAIL
    return AddressComponentType.DETAIL


@dataclass(slots=True)
class DigitTailResult:
    """digit_tail 分析结果。"""
    new_components: list[dict[str, object]]
    unit_text: str
    pure_digits: str
    followed_by_address_key: bool
    challenge_clue_index: int | None


def _find_clue_for_digit_run(
    clues: tuple[Clue, ...],
    unit_char_start: int,
    unit_char_end: int,
    from_index: int = 0,
) -> int | None:
    """在 clues 中查找覆盖指定 digit_run 区间的 NUMERIC/ALNUM clue 索引。"""
    for i in range(from_index, len(clues)):
        c = clues[i]
        if c.start > unit_char_end:
            break
        if c.attr_type in {PIIAttributeType.NUMERIC, PIIAttributeType.ALNUM}:
            if c.start <= unit_char_start and c.end >= unit_char_end:
                return i
    return None


def _has_following_address_key(
    clues: tuple[Clue, ...],
    digit_char_end: int,
    raw_text: str,
    from_index: int = 0,
) -> bool:
    """digit_run 后紧邻是否存在地址 KEY clue（gap 内无 hard break）。"""
    gap = raw_text[digit_char_end:digit_char_end + 6] if digit_char_end < len(raw_text) else ""
    if any(is_hard_break(ch) for ch in gap):
        return False
    for i in range(from_index, len(clues)):
        c = clues[i]
        if c.start > digit_char_end + 6:
            break
        if c.start < digit_char_end:
            continue
        if c.attr_type == PIIAttributeType.ADDRESS and c.role == ClueRole.KEY:
            return True
    return False


def _analyze_digit_tail(
    components: list[dict[str, object]],
    stream,
    clues: tuple[Clue, ...],
    clue_scan_index: int,
) -> DigitTailResult | None:
    """分析地址尾部 digit_run，返回 DigitTailResult 或 None（不扩展）。

    三路分支：
    1. 段不符合长度限制 -> None。
    2. 段符合 + 后接 KEY -> followed_by_address_key=True。
    3. 段符合 + 无 KEY -> followed_by_address_key=False，填 challenge_clue_index。
    """
    if not components or not getattr(stream, "units", None):
        return None
    last = max(components, key=lambda c: (int(c["end"]), int(c["start"])))
    end_char = int(last["end"])
    if end_char >= len(stream.text):
        return None
    next_ui = _unit_index_at_or_after(stream, end_char)
    if next_ui >= len(stream.units):
        return None
    next_unit = stream.units[next_ui]
    if next_unit.kind != "digit_run":
        return None
    prev_type = last.get("component_type")
    if not isinstance(prev_type, AddressComponentType):
        return None

    max_dashes = _max_dashes_for_prev_type(prev_type)
    parts = _parse_digit_tail(next_unit.text, max_dashes)
    if parts is None:
        return None

    available = _available_types_after(prev_type)
    assigned_types = _greedy_assign_types(parts, available)
    if assigned_types is None:
        return None

    # 防御性缓存 digit_run 原文和纯数字。
    cached_text = next_unit.text
    cached_digits = re.sub(r"\D", "", cached_text)

    new_components: list[dict[str, object]] = []
    cursor = next_unit.char_start
    for seg, comp_type in zip(parts, assigned_types):
        seg_start = stream.text.find(seg, cursor, next_unit.char_end)
        if seg_start < 0:
            seg_start = cursor
        seg_end = seg_start + len(seg)
        new_components.append({
            "component_type": comp_type,
            "start": seg_start,
            "end": seg_end,
            "value": seg,
            "key": "",
            "is_detail": comp_type in _DETAIL_COMPONENTS,
        })
        cursor = seg_end

    raw_text = stream.text
    if _has_following_address_key(clues, next_unit.char_end, raw_text, clue_scan_index):
        return DigitTailResult(
            new_components=new_components,
            unit_text=cached_text,
            pure_digits=cached_digits,
            followed_by_address_key=True,
            challenge_clue_index=None,
        )

    clue_idx = _find_clue_for_digit_run(
        clues, next_unit.char_start, next_unit.char_end, clue_scan_index,
    )
    return DigitTailResult(
        new_components=new_components,
        unit_text=cached_text,
        pure_digits=cached_digits,
        followed_by_address_key=False,
        challenge_clue_index=clue_idx,
    )


def _left_expand_en_word(raw_text: str, pos: int, floor: int) -> int:
    cursor = pos
    while cursor > floor and raw_text[cursor - 1] in " \t":
        cursor -= 1
    while cursor > floor and raw_text[cursor - 1].isalnum():
        cursor -= 1
    return cursor


def _left_expand_zh_chars(raw_text: str, pos: int, floor: int, *, max_chars: int) -> int:
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


def _meets_commit_threshold(
    evidence_count: int,
    components: list[dict[str, object]],
    locale: str,
    protection_level: ProtectionLevel = ProtectionLevel.STRONG,
) -> bool:
    del locale
    if evidence_count <= 0:
        return False
    if protection_level == ProtectionLevel.STRONG:
        return True
    if protection_level == ProtectionLevel.BALANCED:
        if evidence_count >= 2:
            return True
        return any(component["component_type"] in _SINGLE_EVIDENCE_ADMIN for component in components)
    return evidence_count >= 2


def _build_standalone_address_component(clue: Clue, component_type: AddressComponentType) -> dict[str, object] | None:
    value = _normalize_address_value(component_type, clue.text)
    if not value:
        return None
    return {
        "component_type": component_type,
        "start": clue.start,
        "end": clue.end,
        "value": value,
        "key": "",
        "is_detail": component_type in _DETAIL_COMPONENTS,
    }


def _build_standalone_address_component_with_key(
    clue: Clue,
    component_type: AddressComponentType,
    *,
    key: str,
) -> dict[str, object] | None:
    component = _build_standalone_address_component(clue, component_type)
    if component is None:
        return None
    component["key"] = str(key or "")
    return component


@lru_cache(maxsize=1)
def _default_zh_address_keys() -> dict[AddressComponentType, str]:
    """从 `zh_address_keywords.json` 推导每个 component_type 的默认 key（用于 value-only 的自动补全）。"""
    keys: dict[AddressComponentType, str] = {}
    for group in load_zh_address_keyword_groups():
        if not group.keywords:
            continue
        # 选择更通用的短 key（如 “区”“路”“号”），避免 “新区/大道/街道” 这类更具体后缀。
        keys[group.component_type] = min(group.keywords, key=len)
    return keys


@lru_cache(maxsize=1)
def _default_en_address_keys() -> dict[AddressComponentType, str]:
    """从 `en_address_keywords.json` 推导每个 component_type 的默认 key。"""
    keys: dict[AddressComponentType, str] = {}
    for group in load_en_address_keyword_groups():
        if not group.keywords:
            continue
        keys[group.component_type] = min(group.keywords, key=len)
    return keys


def _default_key_for_component_type(component_type: AddressComponentType, locale: str) -> str:
    if locale.startswith("en"):
        return _default_en_address_keys().get(component_type, "")
    return _default_zh_address_keys().get(component_type, "")


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
    index = start
    while index < upper_bound:
        if is_any_break(raw_text[index]):
            break
        index += 1
    return index


def _extend_street_tail(raw_text: str, end: int) -> int:
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
