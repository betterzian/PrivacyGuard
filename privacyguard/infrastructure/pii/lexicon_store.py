"""共享的 scanner lexicon 读取工具。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


def scanner_lexicon_root() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "scanner_lexicons"


@lru_cache(maxsize=None)
def read_scanner_lexicon_json(filename: str) -> object:
    path = scanner_lexicon_root() / filename
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = ["read_scanner_lexicon_json", "scanner_lexicon_root"]
