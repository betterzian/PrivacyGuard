"""无额外依赖的 Aho-Corasick 多模式精确匹配器。"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Iterator


@dataclass(slots=True)
class _AutomatonNode:
    transitions: dict[str, int] = field(default_factory=dict)
    fail_index: int = 0
    outputs: tuple[str, ...] = ()


class AhoCorasickMatcher:
    """基于 Aho-Corasick 自动机的多模式精确匹配器。"""

    def __init__(self, patterns: Iterable[str]) -> None:
        unique_patterns = sorted({str(item).strip() for item in patterns if str(item).strip()}, key=lambda item: (-len(item), item))
        self._patterns = tuple(unique_patterns)
        self._nodes: list[_AutomatonNode] = [_AutomatonNode()]
        for pattern in self._patterns:
            self._insert(pattern)
        self._build_failure_links()

    def finditer(self, text: str) -> Iterator[tuple[int, int, str]]:
        """按流式扫描顺序产出 ``(start, end, pattern)`` 形式的匹配。"""
        if not text or not self._patterns:
            return
        state = 0
        for index, char in enumerate(text):
            while state and char not in self._nodes[state].transitions:
                state = self._nodes[state].fail_index
            state = self._nodes[state].transitions.get(char, 0)
            for pattern in self._nodes[state].outputs:
                yield (index - len(pattern) + 1, index + 1, pattern)

    def _insert(self, pattern: str) -> None:
        node_index = 0
        for char in pattern:
            next_index = self._nodes[node_index].transitions.get(char)
            if next_index is None:
                next_index = len(self._nodes)
                self._nodes[node_index].transitions[char] = next_index
                self._nodes.append(_AutomatonNode())
            node_index = next_index
        if pattern not in self._nodes[node_index].outputs:
            self._nodes[node_index].outputs = (*self._nodes[node_index].outputs, pattern)

    def _build_failure_links(self) -> None:
        queue: deque[int] = deque()
        for child_index in self._nodes[0].transitions.values():
            self._nodes[child_index].fail_index = 0
            queue.append(child_index)

        while queue:
            node_index = queue.popleft()
            node = self._nodes[node_index]
            for char, child_index in node.transitions.items():
                fail_index = node.fail_index
                while fail_index and char not in self._nodes[fail_index].transitions:
                    fail_index = self._nodes[fail_index].fail_index
                self._nodes[child_index].fail_index = self._nodes[fail_index].transitions.get(char, 0)
                inherited = self._nodes[self._nodes[child_index].fail_index].outputs
                self._nodes[child_index].outputs = self._merge_outputs(self._nodes[child_index].outputs, inherited)
                queue.append(child_index)

    def _merge_outputs(self, left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
        if not right:
            return left
        merged = list(left)
        seen = set(left)
        for item in right:
            if item in seen:
                continue
            merged.append(item)
            seen.add(item)
        return tuple(merged)
