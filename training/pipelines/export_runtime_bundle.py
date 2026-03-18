"""运行时 bundle 导出入口骨架。"""

from __future__ import annotations

import json
from pathlib import Path

from training.export import RuntimeBundleSpec, build_runtime_metadata


def export_runtime_bundle(bundle: RuntimeBundleSpec, *, policy_name: str) -> Path:
    """导出运行时 metadata 文件，模型本体由外部训练框架生成。"""
    bundle.metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata = build_runtime_metadata(
        feature_version=bundle.feature_version,
        max_candidates=bundle.max_candidates,
        max_personas=bundle.max_personas,
        policy_name=policy_name,
    )
    metadata["format"] = bundle.format
    metadata["model_path"] = str(bundle.model_path)
    metadata["extra_files"] = json.dumps([str(item) for item in bundle.extra_files], ensure_ascii=False)
    bundle.metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return bundle.metadata_path
