"""Detector scanner 使用的 Aho-Corasick 多模式匹配工具。"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


def _is_ascii_token_char(char: str) -> bool:
    return ("0" <= char <= "9") or ("A" <= char <= "Z") or ("a" <= char <= "z")


def _ascii_boundary_ok(text: str, start: int, end: int) -> bool:
    if start > 0 and _is_ascii_token_char(text[start - 1]):
        return False
    if end < len(text) and _is_ascii_token_char(text[end]):
        return False
    return True


@dataclass(frozen=True, slots=True)
class AhoPattern:
    text: str
    payload: object
    ascii_boundary: bool = False


@dataclass(frozen=True, slots=True)
class AhoMatch:
    start: int
    end: int
    matched_text: str
    pattern_text: str
    ascii_boundary: bool
    payload: object


@dataclass(frozen=True, slots=True)
class _CompiledPattern:
    length: int
    text: str
    payload: object
    ascii_boundary: bool


@dataclass(slots=True)
class _Node:
    transitions: dict[str, int] = field(default_factory=dict)
    fail: int = 0
    outputs: list[_CompiledPattern] = field(default_factory=list)


class AhoMatcher:
    def __init__(
        self,
        *,
        exact_nodes: tuple[_Node, ...],
        ascii_nodes: tuple[_Node, ...],
        has_ascii: bool,
        has_exact: bool,
    ) -> None:
        self._exact_nodes = exact_nodes
        self._ascii_nodes = ascii_nodes
        self._has_ascii = has_ascii
        self._has_exact = has_exact

    @classmethod
    def from_patterns(cls, patterns: tuple[AhoPattern, ...]) -> AhoMatcher:
        exact_patterns = tuple(pattern for pattern in patterns if pattern.text and not pattern.ascii_boundary)
        ascii_patterns = tuple(pattern for pattern in patterns if pattern.text and pattern.ascii_boundary)
        exact_nodes = cls._build_automaton(exact_patterns, normalize=False) if exact_patterns else ()
        ascii_nodes = cls._build_automaton(ascii_patterns, normalize=True) if ascii_patterns else ()
        return cls(
            exact_nodes=exact_nodes,
            ascii_nodes=ascii_nodes,
            has_ascii=bool(ascii_patterns),
            has_exact=bool(exact_patterns),
        )

    @staticmethod
    def _build_automaton(patterns: tuple[AhoPattern, ...], *, normalize: bool) -> tuple[_Node, ...]:
        nodes: list[_Node] = [_Node()]
        for pattern in patterns:
            token = pattern.text.lower() if normalize else pattern.text
            state = 0
            for char in token:
                next_state = nodes[state].transitions.get(char)
                if next_state is None:
                    next_state = len(nodes)
                    nodes[state].transitions[char] = next_state
                    nodes.append(_Node())
                state = next_state
            nodes[state].outputs.append(
                _CompiledPattern(
                    length=len(pattern.text),
                    text=pattern.text,
                    payload=pattern.payload,
                    ascii_boundary=pattern.ascii_boundary,
                )
            )

        queue: deque[int] = deque()
        for child_state in nodes[0].transitions.values():
            nodes[child_state].fail = 0
            queue.append(child_state)

        while queue:
            state = queue.popleft()
            for char, next_state in nodes[state].transitions.items():
                queue.append(next_state)
                fail_state = nodes[state].fail
                while fail_state and char not in nodes[fail_state].transitions:
                    fail_state = nodes[fail_state].fail
                nodes[next_state].fail = nodes[fail_state].transitions.get(char, 0)
                nodes[next_state].outputs.extend(nodes[nodes[next_state].fail].outputs)

        return tuple(nodes)

    def find_matches(self, text: str, *, folded_text: str | None = None) -> list[AhoMatch]:
        matches: list[AhoMatch] = []
        if self._has_exact:
            matches.extend(self._scan(self._exact_nodes, text, text))
        if self._has_ascii:
            folded = folded_text if folded_text is not None else text.lower()
            matches.extend(self._scan(self._ascii_nodes, folded, text))
        matches.sort(key=lambda item: (item.start, item.end, -(item.end - item.start)))
        return matches

    @staticmethod
    def _scan(
        nodes: tuple[_Node, ...],
        haystack: str,
        raw_text: str,
    ) -> list[AhoMatch]:
        matches: list[AhoMatch] = []
        state = 0
        for index, char in enumerate(haystack):
            while state and char not in nodes[state].transitions:
                state = nodes[state].fail
            state = nodes[state].transitions.get(char, 0)
            if not nodes[state].outputs:
                continue
            for output in nodes[state].outputs:
                start = index - output.length + 1
                end = index + 1
                if start < 0:
                    continue
                matches.append(
                    AhoMatch(
                        start=start,
                        end=end,
                        matched_text=raw_text[start:end],
                        pattern_text=output.text,
                        ascii_boundary=output.ascii_boundary,
                        payload=output.payload,
                    )
                )
        return matches


__all__ = ["AhoMatch", "AhoMatcher", "AhoPattern"]
