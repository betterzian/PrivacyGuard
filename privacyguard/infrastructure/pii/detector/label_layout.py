"""OCR label 布局可信度管理。"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import Clue, OCRScene, OCRSceneBlock


_LABEL_SEPARATOR_CHARS = frozenset({":", "：", "-", "—", "–", "|"})
_X_BUCKET_COUNT = 10
_X_WINDOW_SIZE = 3
_STRONG_WINDOW_BONUS = 1.5
_MIN_BUCKET_WIDTH = 1.0
_MIN_DY_BUCKET_HEIGHT = 8.0


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
    weight: float
    bucket_x: int
    y_center: float
    height: float
    strong: bool
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
        main_buckets = self._main_x_window(entries)
        rhythm_entries = tuple(entry for entry in entries if entry.bucket_x in main_buckets or entry.already_bound)
        y_trusted = self._y_rhythm_trusted_ids(rhythm_entries)
        decisions: dict[str, LabelLayoutDecision] = {}
        for entry in entries:
            clue_id = entry.clue.clue_id
            in_x_window = entry.bucket_x in main_buckets
            if entry.already_bound:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.weight,
                    trusted=True,
                    drop_reason=None,
                )
                continue
            if not in_x_window:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.weight,
                    trusted=False,
                    drop_reason="outside_main_x_window",
                )
                continue
            if clue_id not in y_trusted:
                decisions[clue_id] = LabelLayoutDecision(
                    clue_id=clue_id,
                    layout_score=entry.weight,
                    trusted=False,
                    drop_reason="off_y_rhythm",
                )
                continue
            decisions[clue_id] = LabelLayoutDecision(
                clue_id=clue_id,
                layout_score=entry.weight,
                trusted=True,
                drop_reason=None,
            )
        return decisions

    def trusted_label_ids(self) -> set[str]:
        """返回通过布局筛选的 label clue id 集合。"""
        return {
            clue_id
            for clue_id, decision in self.evaluate().items()
            if decision.trusted
        }

    def _build_entries(self) -> tuple[_LabelEntry, ...]:
        scene_min_x, scene_width = self._scene_x_range()
        entries: list[_LabelEntry] = []
        for clue in self._label_clues:
            block = self._label_blocks.get(clue.clue_id)
            if block is None or block.block.bbox is None:
                continue
            box = block.block.bbox
            binding = self._bindings.get(clue.clue_id)
            already_bound = binding is not None
            has_separator = _label_has_separator(clue, block)
            weight = 1.0
            if has_separator:
                weight += 2.0
            if already_bound:
                weight += 3.0
                if binding.relation == "right":
                    weight += 1.5
                elif binding.relation == "below":
                    weight += 1.0
            if _label_text_long_enough(clue.text):
                weight += 0.3
            bucket_x = _bucket_x(float(box.x), scene_min_x=scene_min_x, scene_width=scene_width)
            entries.append(
                _LabelEntry(
                    clue=clue,
                    block=block,
                    weight=weight,
                    bucket_x=bucket_x,
                    y_center=float(box.y) + float(box.height) / 2.0,
                    height=float(box.height),
                    strong=has_separator or already_bound,
                    already_bound=already_bound,
                )
            )
        return tuple(entries)

    def _scene_x_range(self) -> tuple[float, float]:
        boxes = [block.block.bbox for block in self._scene.blocks if block.block.bbox is not None]
        if not boxes:
            return (0.0, _MIN_BUCKET_WIDTH * _X_BUCKET_COUNT)
        min_x = min(float(box.x) for box in boxes)
        max_x = max(float(box.x + box.width) for box in boxes)
        return (min_x, max(max_x - min_x, _MIN_BUCKET_WIDTH * _X_BUCKET_COUNT))

    def _main_x_window(self, entries: tuple[_LabelEntry, ...]) -> set[int]:
        scores: list[tuple[float, int]] = []
        for start_bucket in range(0, _X_BUCKET_COUNT - _X_WINDOW_SIZE + 1):
            window = set(range(start_bucket, start_bucket + _X_WINDOW_SIZE))
            labels = [entry for entry in entries if entry.bucket_x in window]
            score = sum(entry.weight for entry in labels)
            score += _STRONG_WINDOW_BONUS * sum(entry.weight for entry in labels if entry.strong)
            scores.append((score, start_bucket))
        _score, best_start = max(scores, key=lambda item: (item[0], -item[1]))
        return set(range(best_start, best_start + _X_WINDOW_SIZE))

    def _y_rhythm_trusted_ids(self, entries: tuple[_LabelEntry, ...]) -> set[str]:
        if len(entries) <= 2:
            return {entry.clue.clue_id for entry in entries}
        ordered = tuple(sorted(entries, key=lambda entry: entry.y_center))
        median_h = float(median(entry.height for entry in ordered))
        bucket_base = max(median_h * 0.75, _MIN_DY_BUCKET_HEIGHT)
        dy_buckets = [
            round((ordered[index + 1].y_center - ordered[index].y_center) / bucket_base)
            for index in range(len(ordered) - 1)
        ]
        main_bucket = _mode_int(dy_buckets)
        trusted: set[str] = set()
        for index, entry in enumerate(ordered):
            if entry.already_bound:
                trusted.add(entry.clue.clue_id)
                continue
            tolerance = 2 if entry.strong else 1
            left_ok = index > 0 and abs(dy_buckets[index - 1] - main_bucket) <= tolerance
            right_ok = index < len(dy_buckets) and abs(dy_buckets[index] - main_bucket) <= tolerance
            if left_ok or right_ok:
                trusted.add(entry.clue.clue_id)
        return trusted


def _bucket_x(x: float, *, scene_min_x: float, scene_width: float) -> int:
    width = max(scene_width / _X_BUCKET_COUNT, _MIN_BUCKET_WIDTH)
    bucket = int((x - scene_min_x) // width)
    return max(0, min(_X_BUCKET_COUNT - 1, bucket))


def _mode_int(values: list[int]) -> int:
    counts: dict[int, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return max(counts.items(), key=lambda item: (item[1], -abs(item[0])))[0]


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
