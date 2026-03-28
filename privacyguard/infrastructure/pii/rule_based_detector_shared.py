"""新主链共享常量。

地址旧流仍依赖一批归档期共享词典与后缀常量，这里按需从归档模块加载，
避免重新挂回旧 detector 主链。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import sys
import types


_OCR_SEMANTIC_BREAK_TOKEN = " <OCR_BREAK> "

_LEGACY_EXPORTS = {
    "_ADDRESS_FIELD_KEYWORDS",
    "_BUILTIN_EN_GEO_LEXICON",
    "_BUILTIN_GEO_LEXICON",
    "_BUILTIN_UI_BLACKLIST_EN",
    "_BUILTIN_UI_BLACKLIST_ZH",
    "_EMAIL_FIELD_KEYWORDS",
    "_EN_GEO_TIER_A_STATE_PATTERN",
    "_EN_ORGANIZATION_STRONG_SUFFIXES",
    "_EN_ORGANIZATION_WEAK_SUFFIXES",
    "_GEO_LEXICON_MATCHER",
    "_ID_FIELD_KEYWORDS",
    "_ORGANIZATION_STRONG_SUFFIXES",
    "_ORGANIZATION_WEAK_SUFFIXES",
    "_PHONE_FIELD_KEYWORDS",
}


@lru_cache(maxsize=1)
def _load_legacy_shared():
    module_path = Path(__file__).resolve().parent / "detector.old" / "rule_based_detector_shared.py"
    if not module_path.exists():
        raise ImportError(f"cannot load legacy shared module: {module_path}")
    module = types.ModuleType("privacyguard.infrastructure.pii._legacy_rule_based_detector_shared")
    module.__dict__["__file__"] = str(Path(__file__).resolve())
    module.__dict__["__name__"] = module.__name__
    sys.modules[module.__name__] = module
    code = compile(module_path.read_text(encoding="utf-8"), str(module_path), "exec")
    exec(code, module.__dict__)
    return module


_LEGACY_SHARED = _load_legacy_shared()
for _name in _LEGACY_EXPORTS:
    globals()[_name] = getattr(_LEGACY_SHARED, _name)


__all__ = [
    "_OCR_SEMANTIC_BREAK_TOKEN",
    *_LEGACY_EXPORTS,
]
