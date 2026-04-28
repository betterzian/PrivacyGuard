"""Shared metadata helpers for the clean detector chain."""

from __future__ import annotations


def merge_metadata(left: dict[str, list[str]], right: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {key: [str(item) for item in values] for key, values in left.items()}
    for key, values in right.items():
        merged[key] = list(dict.fromkeys([*merged.get(key, []), *[str(item) for item in values]]))
    return merged


GENERIC_CONTEXT_GATE_METADATA = "generic_context_gate"
GENERIC_CONTEXT_GATE_FAILED_METADATA = "generic_context_gate_failed"
GENERIC_CONTEXT_GATE_TEXT = "text"
GENERIC_CONTEXT_GATE_GEOMETRY = "geometry"
GENERIC_CONTEXT_GATE_NO_CONTEXT = "no_context"
