"""Shared metadata helpers for the clean detector chain."""

from __future__ import annotations


def merge_metadata(left: dict[str, list[str]], right: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {key: [str(item) for item in values] for key, values in left.items()}
    for key, values in right.items():
        merged[key] = list(dict.fromkeys([*merged.get(key, []), *[str(item) for item in values]]))
    return merged
