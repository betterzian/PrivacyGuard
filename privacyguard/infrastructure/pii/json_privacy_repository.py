"""基于 JSON 文件的 privacy 词库（rule_based detector 词典）读写。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_PRIVACY_REPOSITORY_PATH = "data/privacy_repository.json"


def _dedupe_str_list(values: list[str]) -> list[str]:
    """保持顺序的去重。"""
    return list(dict.fromkeys(values))


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return [text] if text else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    return []


def _merge_top_level_lists(existing: Any, incoming: Any) -> list[str]:
    return _dedupe_str_list(_as_str_list(existing) + _as_str_list(incoming))


def _deep_merge_entity(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """合并同一 entity_id 下的实体条目。"""
    merged = dict(old)
    for key, value in new.items():
        if key in {"entity_id", "id"}:
            continue
        if key not in merged:
            merged[key] = value
            continue
        prev = merged[key]
        if isinstance(prev, list) and isinstance(value, list):
            if _is_flat_str_list(prev) and _is_flat_str_list(value):
                merged[key] = _dedupe_str_list([str(x).strip() for x in prev + value if str(x).strip()])
            else:
                merged[key] = list(prev) + list(value)
        elif isinstance(prev, dict) and isinstance(value, dict):
            sub = dict(prev)
            sub.update(value)
            merged[key] = sub
        else:
            merged[key] = value
    return merged


def _is_flat_str_list(items: list[Any]) -> bool:
    return all(isinstance(x, (str, int, float)) for x in items)


def _merge_entities(existing: Any, incoming: Any) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for raw in existing if isinstance(existing, list) else []:
        if not isinstance(raw, dict):
            continue
        eid = str(raw.get("entity_id") or raw.get("id") or "").strip()
        if not eid:
            continue
        by_id[eid] = dict(raw)
    for raw in incoming if isinstance(incoming, list) else []:
        if not isinstance(raw, dict):
            continue
        eid = str(raw.get("entity_id") or raw.get("id") or "").strip()
        if not eid:
            continue
        if eid in by_id:
            by_id[eid] = _deep_merge_entity(by_id[eid], raw)
        else:
            by_id[eid] = dict(raw)
    return list(by_id.values())


def merge_privacy_documents(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """将 patch 合并进 base，返回新字典（不修改输入）。"""
    out = dict(base)
    for key, value in patch.items():
        if key == "entities":
            out["entities"] = _merge_entities(out.get("entities"), value)
            continue
        if value is None:
            continue
        if key not in out:
            out[key] = _dedupe_str_list(_as_str_list(value))
            continue
        out[key] = _merge_top_level_lists(out[key], value)
    return out


class JsonPrivacyRepository:
    """读写 rule_based 检测器使用的本地 privacy JSON 词库。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else Path(DEFAULT_PRIVACY_REPOSITORY_PATH)

    def load_raw(self) -> dict[str, Any]:
        """读取 JSON；文件不存在时返回空对象。"""
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}

    def merge_and_write(self, patch: dict[str, Any]) -> None:
        """将 patch 合并进现有文件并原子写入。"""
        base = self.load_raw()
        merged = merge_privacy_documents(base, patch)
        self._atomic_write(merged)

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.path)
