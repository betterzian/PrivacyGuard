"""从训练产物到运行时 bundle 的导出描述。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class RuntimeBundleSpec:
    """运行时模型 bundle 描述。"""

    format: str
    model_path: Path
    metadata_path: Path
    feature_version: str
    max_candidates: int
    max_personas: int
    extra_files: list[Path] = field(default_factory=list)


def build_runtime_metadata(
    *,
    feature_version: str,
    max_candidates: int,
    max_personas: int,
    policy_name: str,
) -> dict[str, str]:
    """构造随模型一起导出的 metadata。"""
    return {
        "policy_name": policy_name,
        "feature_version": feature_version,
        "max_candidates": str(max_candidates),
        "max_personas": str(max_personas),
    }
