"""OCR label 布局可信度管理。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import Clue, OCRScene, OCRSceneBlock


_LABEL_SEPARATOR_CHARS = frozenset({":", "：", "-", "—", "–", "|"})
_HEIGHT_WINDOW_SPAN = 12.0
_X_WINDOW_SPAN = 64.0
_DY_WINDOW_SPAN = 12.0
_MIN_LAYOUT_SUPPORT = 3
_INSUFFICIENT_LAYOUT_SUPPORT = "insufficient_layout_support"


@dataclass(frozen=True, slots=True)
class LabelBindingInfo:
    """普通 clue gate 已经证实的 label-value 绑定。"""

    label_id: str
    attr_type: PIIAttributeType
    relation: str | None = None


@dataclass(frozen=True, slots=True)
class LabelLayoutDecision:
    """单个 label 的布局判定结果。"""

    clue_id: str
    layout_score: float
    trusted: bool
    drop_reason: str | None


@dataclass(frozen=True, slots=True)
class _LabelEntry:
    clue: Clue
    block: OCRSceneBlock
    layout_score: float
    x: float
    y_center: float
    height: float
    has_separator: bool
    already_bound: bool


class LabelLayoutManager:
    """只负责 OCR label 的空间可信度，不判断具体 PII 类型。"""

    def __init__(
        self,
        *,
        scene: OCRScene,
        label_clues: tuple[Clue, ...],
        label_blocks: dict[str, OCRSceneBlock],
        bindings: tuple[LabelBindingInfo, ...],
    ) -> None:
        self._scene = scene
        self._label_clues = label_clues
        self._label_blocks = label_blocks
        self._bindings = {binding.label_id: binding for binding in bindings}

    def evaluate(self) -> dict[str, LabelLayoutDecision]:
        """返回每个 label 的布局评分与保留/剔除原因。"""
        entries = self._build_entries()
        if not entries:
            return {}

        height_ids = self._height_cluster_ids(entries)
        if len(height_ids) < _MIN_LAYOUT_SUPPORT:
            return self._insufficient_support_decisions(entries)
        x_entries = tuple(entry for entry in entries if entry.clue.clue_id in height_ids)
        x_ids = self._main_x_window_ids(x_entries)
        if len(x_ids) < _MIN_LAYOUT_SUPPORT:
            return self._insufficient_support_decisions(entries)
        rhythm_entries = tuple(entry for entry in x_entries if entry.clue.clue_id in x_ids)
        rhythm_ids = self._main_y_rhythm_ids(rhythm_entries)
        if len(rhythm_ids) < _MIN_LAYOUT_SUPPORT:
            return self._insufficient_support_decisions(entries)

        decisions: dict[str, LabelLayoutDecision] = {}
        for entry in entries:
            clue_id = entry.clue.clue_id
            if entry.already_bound:
                decisions[clue_id] = self._trusted_decision(entry)
                continue
            if clue_id not in height_ids:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.layout_score,
                    trusted=False,
                    drop_reason="height_outlier",
                )
                continue
            if clue_id not in x_ids:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.layout_score,
                    trusted=False,
                    drop_reason="outside_main_x_window",
                )
                continue
            if clue_id not in rhythm_ids:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.layout_score,
                    trusted=False,
                    drop_reason="off_y_rhythm",
                )
                continue
            decisions[clue_id] = self._trusted_decision(entry)
        return decisions

    def _trusted_decision(self, entry: _LabelEntry) -> LabelLayoutDecision:
        return LabelLayoutDecision(
            clue_id=entry.clue.clue_id,
            layout_score=entry.layout_score,
            trusted=True,
            drop_reason=None,
        )

    def _insufficient_support_decisions(self, entries: tuple[_LabelEntry, ...]) -> dict[str, LabelLayoutDecision]:
        """布局样本不足时，只保留已由 value 证实的 label。"""
        return {
            entry.clue.clue_id: (
                self._trusted_decision(entry)
                if entry.already_bound
                else LabelLayoutDecision(
                    clue_id=entry.clue.clue_id,
                    layout_score=entry.layout_score,
                    trusted=False,
                    drop_reason=_INSUFFICIENT_LAYOUT_SUPPORT,
                )
            )
            for entry in entries
        }

    def _build_entries(self) -> tuple[_LabelEntry, ...]:
        entries: list[_LabelEntry] = []
        for clue in self._label_clues:
            block = self._label_blocks.get(clue.clue_id)
            if block is None or block.block.bbox is None:
                continue
            box = block.block.bbox
            binding = self._bindings.get(clue.clue_id)
            already_bound = binding is not None
            has_separator = _label_has_separator(clue, block)
            layout_score = 1.0
            if has_separator:
                layout_score += 2.0
            if already_bound:
                layout_score += 3.0
                if binding.relation == "right":
                    layout_score += 1.5
                elif binding.relation == "below":
                    layout_score += 1.0
            if _label_text_long_enough(clue.text):
                layout_score += 0.3
            entries.append(
                _LabelEntry(
                    clue=clue,
                    block=block,
                    layout_score=layout_score,
                    x=float(box.x),
                    y_center=float(box.y) + float(box.height) / 2.0,
                    height=float(box.height),
                    has_separator=has_separator,
                    already_bound=already_bound,
                )
            )
        return tuple(entries)

    def _height_cluster_ids(self, entries: tuple[_LabelEntry, ...]) -> set[str]:
        selected = _best_entry_window(entries, value_getter=lambda entry: entry.height, span=_HEIGHT_WINDOW_SPAN)
        return {entry.clue.clue_id for entry in selected}

    def _main_x_window_ids(self, entries: tuple[_LabelEntry, ...]) -> set[str]:
        selected = _best_entry_window(entries, value_getter=lambda entry: entry.x, span=_X_WINDOW_SPAN)
        return {entry.clue.clue_id for entry in selected}

    def _main_y_rhythm_ids(self, entries: tuple[_LabelEntry, ...]) -> set[str]:
        if len(entries) < _MIN_LAYOUT_SUPPORT:
            return set()
        ordered = tuple(sorted(entries, key=lambda entry: entry.y_center))
        dy_pairs = [
            (ordered[index], ordered[index + 1], ordered[index + 1].y_center - ordered[index].y_center)
            for index in range(len(ordered) - 1)
        ]
        selected_range = _best_value_range(
            tuple(dy for _left, _right, dy in dy_pairs),
            span=_DY_WINDOW_SPAN,
        )
        if selected_range is None:
            return set()
        lower, upper = selected_range

        best_chain: list[_LabelEntry] = []
        current_chain: list[_LabelEntry] = [ordered[0]]
        for index, (_left, right, dy) in enumerate(dy_pairs):
            if lower <= dy <= upper:
                current_chain.append(right)
            else:
                best_chain = _better_chain(best_chain, current_chain)
                current_chain = [ordered[index + 1]]
        best_chain = _better_chain(best_chain, current_chain)
        return {entry.clue.clue_id for entry in best_chain}


def _best_entry_window(
    entries: tuple[_LabelEntry, ...],
    *,
    value_getter,
    span: float,
) -> tuple[_LabelEntry, ...]:
    if not entries:
        return ()
    ordered = tuple(sorted(entries, key=value_getter))
    best: tuple[_LabelEntry, ...] = ()
    best_score: tuple[float, float, float, float] | None = None
    right = 0
    for left, entry in enumerate(ordered):
        start = float(value_getter(entry))
        while right < len(ordered) and float(value_getter(ordered[right])) <= start + span:
            right += 1
        window = ordered[left:right]
        values = [float(value_getter(item)) for item in window]
        score = (
            float(len(window)),
            float(sum(1 for item in window if item.already_bound)),
            float(sum(1 for item in window if item.has_separator)),
            -_variance(values),
        )
        if best_score is None or score > best_score:
            best_score = score
            best = window
    return best


def _best_value_range(values: tuple[float, ...], *, span: float) -> tuple[float, float] | None:
    if not values:
        return None
    ordered = tuple(sorted(float(value) for value in values))
    best_range: tuple[float, float] | None = None
    best_score: tuple[float, float] | None = None
    right = 0
    for left, start in enumerate(ordered):
        while right < len(ordered) and ordered[right] <= start + span:
            right += 1
        window = ordered[left:right]
        score = (float(len(window)), -_variance(list(window)))
        if best_score is None or score > best_score:
            best_score = score
            best_range = (start, start + span)
    return best_range


def _variance(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def _better_chain(best: list[_LabelEntry], current: list[_LabelEntry]) -> list[_LabelEntry]:
    if not best:
        return list(current)
    best_score = (len(best), sum(entry.layout_score for entry in best))
    current_score = (len(current), sum(entry.layout_score for entry in current))
    return list(current) if current_score > best_score else best


def _label_has_separator(clue: Clue, block: OCRSceneBlock) -> bool:
    if (clue.source_metadata.get("seed_has_connector_after") or ["0"])[0] == "1":
        return True
    return any(char in _LABEL_SEPARATOR_CHARS for char in f"{clue.text}{block.clean_text}")


def _label_text_long_enough(text: str) -> bool:
    compact = "".join(char for char in str(text or "") if char.isalnum() or "\u4e00" <= char <= "\u9fff")
    if any("\u4e00" <= char <= "\u9fff" for char in compact):
        return len(compact) >= 2
    return len(compact) >= 3


__all__ = ["LabelBindingInfo", "LabelLayoutDecision", "LabelLayoutManager"]
