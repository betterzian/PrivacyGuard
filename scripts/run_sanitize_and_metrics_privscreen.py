"""批量运行 sanitize（label_only）并计算文本指标（PrivScreen 复现口径）。

目标：
- 遍历 `data/download` 下的截图数据集（默认按 PrivScreen layout：*/images/*.png）
- 对每张图分别以 ProtectionLevel: strong/balanced/weak 跑一次 sanitize
- 存储每张图的：
  - 原图 OCR 输出（blocks）
  - detector 输出（PIICandidate 列表）
  - render 输出（masked image 文件）
  - masked 图 OCR 输出（blocks）
- 计算并汇总 6 个指标：LR、MS、BLEU、ROUGE-L、BERTScore、CS

说明：
- BLEU/ROUGE-L/BERTScore/CS 直接复用 `tmp/gui_privacy_protection/PrivScreen_evaluation/utils.py`
  中的 `compute_text_metrics` 实现，以保持口径一致。
- LR/MS 的实现对齐 PrivScreen 复现：MS 为 match score 平均值，LR 为 match_score>0.6 的比例。
  这里的 “true” 取 detector 在原图识别出的 candidate.text；“pred” 取 masked OCR 中与其最相似的 block 文本。
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from privacyguard.app.privacy_guard import PrivacyGuard
from privacyguard.api.dto import SanitizeRequest
from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.application.services.replacement_generation import apply_post_decision_steps
from privacyguard.application.services.session_service import SessionService
from privacyguard.domain.enums import ProtectionLevel


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_ROOT = REPO_ROOT / "data" / "privscreen"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "outputs" / "privscreen_sanitize_eval"
EVAL_UTILS_DIR = REPO_ROOT / "tmp" / "gui_privacy_protection" / "PrivScreen_evaluation"
DEFAULT_HF_DOWNLOAD_ROOT = REPO_ROOT / "data" / "_hf_privscreen"


def _import_compute_text_metrics():
    sys.path.insert(0, str(EVAL_UTILS_DIR))
    try:
        from utils import compute_text_metrics  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            f"无法从 {EVAL_UTILS_DIR} 导入 compute_text_metrics。"
            "请确认 `tmp/gui_privacy_protection/PrivScreen_evaluation/utils.py` 存在且可导入。"
        ) from e
    return compute_text_metrics


compute_text_metrics = _import_compute_text_metrics()


def _progress(iterable: Iterable[Any], *, total: int, desc: str):
    """尽量使用 tqdm；不可用时退化为原 iterable。"""
    try:
        from tqdm import tqdm  # type: ignore

        # conda run / CI / IDE capture 等场景下可能被判定为非 TTY 而默认禁用；
        # 这里强制开启并指定输出流，同时启用 leave 以便用户能看到最终状态。
        return tqdm(
            iterable,
            total=total,
            desc=desc,
            disable=False,
            file=sys.stdout,
            dynamic_ncols=True,
            leave=True,
            mininterval=0.5,
        )
    except Exception as e:
        # tqdm 不可用或被破坏时，退化为“每 N 张打印一次”的纯文本进度。
        print(f"[progress] tqdm unavailable for '{desc}': {type(e).__name__}: {e}")

        def _gen():
            count = 0
            for item in iterable:
                yield item
                count += 1
                if count == 1 or count % 10 == 0 or count == total:
                    print(f"[progress] {desc}: {count}/{total}")

        return _gen()


def _iter_image_files(data_root: Path) -> list[Path]:
    """遍历 data_root 下真实图片文件。

    约定优先按 PrivScreen layout：`*/images/*.(png|jpg|jpeg|webp)`，避免把 `.metadata` 误当图片。
    """
    exts = {".png", ".jpg", ".jpeg", ".webp"}
    files: list[Path] = []
    for p in data_root.rglob("*"):
        if not p.is_file():
            continue
        if p.name.endswith(".metadata"):
            continue
        if p.suffix.lower() not in exts:
            continue
        # 收敛到 images 目录（PrivScreen 标准结构）；若用户传入扁平目录，则允许直接图片
        parts_lower = {part.lower() for part in p.parts}
        if "images" in parts_lower or p.parent == data_root:
            files.append(p)
    return sorted(files)


def _has_only_metadata_images(data_root: Path) -> bool:
    """判断是否出现了 `*.png.metadata` 但没有真实图片的情况。"""
    meta_hits = list(data_root.rglob("*.png.metadata"))
    if not meta_hits:
        return False
    real = _iter_image_files(data_root)
    return len(real) == 0


def _has_privscreen_qa_but_no_images(data_root: Path) -> bool:
    """判断是否是“只有 QA JSON，没有 images/ 真实图片”的 PrivScreen 目录。"""
    if _iter_image_files(data_root):
        return False
    privacy = list(data_root.rglob("privacy_qa.json"))
    normal = list(data_root.rglob("normal_qa.json"))
    return bool(privacy and normal)


def _auto_download_privscreen(target_dir: Path, repo_id: str = "fyzzzzzz/PrivScreen") -> Path:
    """当本地只有 `.metadata` 时自动下载 PrivScreen 到 target_dir。

    返回下载后的数据根目录（可能是 `target_dir/privscreen`，也可能是 `target_dir`）。
    """
    try:
        from huggingface_hub import snapshot_download
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "检测到本地只有 `.metadata`，但未安装 huggingface_hub，无法自动下载 PrivScreen。"
            "请先在当前环境安装：pip install huggingface_hub"
        ) from e
    _ensure_dir(target_dir)
    snapshot_download(
        repo_id=repo_id,
        local_dir=str(target_dir),
        local_dir_use_symlinks=False,
    )
    # 兼容两种布局：有的会落在 target_dir/privscreen
    if (target_dir / "privscreen").exists():
        return (target_dir / "privscreen").resolve()
    return target_dir.resolve()


def _ocr_blocks_to_jsonable(blocks: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in blocks:
        bbox = getattr(b, "bbox", None)
        polygon = getattr(b, "polygon", None)
        out.append(
            {
                "text": getattr(b, "text", ""),
                "score": getattr(b, "score", None),
                "line_id": getattr(b, "line_id", None),
                "block_id": getattr(b, "block_id", None),
                "rotation_degrees": getattr(b, "rotation_degrees", None),
                "bbox": None
                if bbox is None
                else {
                    "x": getattr(bbox, "x", None),
                    "y": getattr(bbox, "y", None),
                    "width": getattr(bbox, "width", None),
                    "height": getattr(bbox, "height", None),
                },
                "polygon": None
                if not polygon
                else [{"x": getattr(p, "x", None), "y": getattr(p, "y", None)} for p in polygon],
            }
        )
    return out


def _candidates_to_jsonable(cands: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in cands:
        if hasattr(c, "model_dump"):
            out.append(c.model_dump())
        else:
            out.append(asdict(c) if hasattr(c, "__dataclass_fields__") else {"text": getattr(c, "text", str(c))})
    return out


def _blocks_text(blocks: list[Any]) -> list[str]:
    texts: list[str] = []
    for b in blocks:
        t = str(getattr(b, "text", "")).strip()
        if t:
            texts.append(t)
    return texts


_PUNCT_RE = re.compile(r"[\u0000-\u002F\u003A-\u0040\u005B-\u0060\u007B-\u007F]+")


def _normalize_for_match(s: str) -> str:
    s = (s or "").lower().strip()
    s = _PUNCT_RE.sub(" ", s)
    s = " ".join(s.split())
    return s


def _sequence_ratio(a: str, b: str) -> float:
    from difflib import SequenceMatcher

    return float(SequenceMatcher(None, a, b).ratio())


def _best_block_match(true_text: str, masked_block_texts: list[str]) -> tuple[str, float]:
    """返回 (best_pred_text, best_ratio)。"""
    t = (true_text or "").strip()
    if not t or not masked_block_texts:
        return ("", 0.0)
    best_pred = ""
    best_score = 0.0
    t_n = _normalize_for_match(t)
    for cand in masked_block_texts:
        c = (cand or "").strip()
        if not c:
            continue
        c_n = _normalize_for_match(c)
        if not t_n or not c_n:
            continue
        score = _sequence_ratio(t_n, c_n)
        if score > best_score:
            best_score = score
            best_pred = c
    return (best_pred, best_score)


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _save_pil_image(img: Any, out_path: Path) -> None:
    try:
        from PIL import Image

        if isinstance(img, Image.Image):
            _ensure_dir(out_path.parent)
            img.save(out_path)
            return
    except Exception:
        pass
    raise RuntimeError("masked_image 不是 PIL.Image，无法保存。")


def run_once(
    *,
    guard: PrivacyGuard,
    image_path: Path,
    protection_level: ProtectionLevel,
    output_root: Path,
    leak_threshold: float = 0.6,
    cached_ocr_blocks: list[Any] | None = None,
) -> dict[str, Any]:
    # 1) 原图 OCR（支持外部缓存复用）
    ocr_blocks = list(cached_ocr_blocks) if cached_ocr_blocks is not None else guard.ocr.extract(image_path)
    candidates = guard.detector.detect(
        prompt_text="",
        ocr_blocks=ocr_blocks,
        session_id=f"{image_path.stem}-{protection_level.value}",
        turn_id=0,
        protection_level=protection_level,
        detector_overrides={},
    )

    # 2) 绕过 sanitize：用缓存 OCR blocks 直接走 detector -> decision -> render
    session_id = f"{image_path.stem}-{protection_level.value}"
    turn_id = 0
    request = SanitizeRequest(
        session_id=session_id,
        turn_id=turn_id,
        prompt_text="",
        screenshot=str(image_path),
        protection_level=protection_level,
        detector_overrides={},
    )
    session_service = SessionService(mapping_store=guard.mapping_table, persona_repository=guard.persona_repo)
    session_binding = session_service.get_or_create_binding(session_id)
    context = DecisionContextBuilder(mapping_store=guard.mapping_table, persona_repository=guard.persona_repo).build(
        session_id=session_id,
        turn_id=turn_id,
        prompt_text=request.prompt_text,
        protection_level=protection_level,
        detector_overrides=request.detector_overrides,
        ocr_blocks=ocr_blocks,
        candidates=candidates,
        session_binding=session_binding,
    )
    decision_plan = guard.decision_engine.plan(context)
    replacement_plan = apply_post_decision_steps(
        decision_plan,
        context,
        guard.mapping_table,
        guard.persona_repo,
    )
    # render_text 返回 (sanitized, records)，records 用于写入 mapping store
    sanitized_prompt_text, applied_replacements = guard.renderer.render_text(request.prompt_text, replacement_plan)
    masked_image = guard.renderer.render_image(request.screenshot, replacement_plan, ocr_blocks=ocr_blocks)
    session_service.append_turn_replacements(session_id, turn_id, applied_replacements)
    if replacement_plan.active_persona_id:
        session_service.bind_active_persona(session_id, replacement_plan.active_persona_id, turn_id)

    masked_image_path = output_root / protection_level.value / "render" / f"{image_path.stem}.png"
    _save_pil_image(masked_image, masked_image_path)

    # 3) masked 图 OCR
    masked_ocr_blocks = guard.ocr.extract(masked_image_path)

    # 4) 指标：以 detector 的 candidate.text 为 “true”，masked OCR 中最佳相似 block 为 “pred”
    masked_texts = _blocks_text(masked_ocr_blocks)
    per_candidate: list[dict[str, Any]] = []
    ratios: list[float] = []
    leaked = 0
    bert_f1_list: list[float] = []
    cosine_list: list[float] = []
    bleu_list: list[float] = []
    rouge_list: list[float] = []

    for c in candidates:
        true_text = str(getattr(c, "text", "")).strip()
        if not true_text:
            continue
        pred_text, score = _best_block_match(true_text, masked_texts)
        ratios.append(score)
        if score > leak_threshold:
            leaked += 1
        tm = compute_text_metrics(pred_text or "", true_text or "")
        if tm.get("bertscore_f1") is not None:
            bert_f1_list.append(float(tm["bertscore_f1"]))
        if tm.get("cosine_sim") is not None:
            cosine_list.append(float(tm["cosine_sim"]))
        if tm.get("bleu") is not None:
            bleu_list.append(float(tm["bleu"]))
        if tm.get("rouge_l") is not None:
            rouge_list.append(float(tm["rouge_l"]))
        per_candidate.append(
            {
                "candidate": c.model_dump() if hasattr(c, "model_dump") else {"text": true_text},
                "best_pred_block_text": pred_text,
                "match_score": score,
                "bertscore_f1": tm.get("bertscore_f1"),
                "cosine_sim": tm.get("cosine_sim"),
                "bleu": tm.get("bleu"),
                "rouge_l": tm.get("rouge_l"),
                "leaked": bool(score > leak_threshold),
            }
        )

    def _avg(xs: list[float]) -> float | None:
        return (sum(xs) / len(xs)) if xs else None

    ms = _avg(ratios) or 0.0
    lr = (leaked / len(ratios)) if ratios else 0.0

    return {
        "image_path": str(image_path),
        "protection_level": protection_level.value,
        "ocr_blocks": _ocr_blocks_to_jsonable(ocr_blocks),
        "detector_candidates": _candidates_to_jsonable(candidates),
        "render_path": str(masked_image_path),
        "masked_ocr_blocks": _ocr_blocks_to_jsonable(masked_ocr_blocks),
        "metrics": {
            "LR": lr,
            "MS": ms,
            "BLEU": _avg(bleu_list),
            "ROUGE_L": _avg(rouge_list),
            "BERTScore": _avg(bert_f1_list),
            "CS": _avg(cosine_list),
            "candidate_count": len(ratios),
            "leaked_count": leaked,
            "leak_threshold": leak_threshold,
        },
        "per_candidate": per_candidate,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=str, default=str(DEFAULT_DATA_ROOT))
    parser.add_argument("--output-root", type=str, default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--limit", type=int, default=0, help=">0 时只跑前 N 张")
    parser.add_argument("--leak-threshold", type=float, default=0.6)
    parser.add_argument("--detector-locale-profile", type=str, default="en_us", choices=["zh_cn", "en_us", "mixed"])
    parser.add_argument("--auto-download-privscreen", action="store_true", help="当 data_root 只有 .metadata 时自动下载 PrivScreen")
    parser.add_argument("--hf-download-root", type=str, default=str(DEFAULT_HF_DOWNLOAD_ROOT), help="自动下载 PrivScreen 的落盘目录")
    args = parser.parse_args()

    data_root = Path(args.data_root).resolve()
    output_root = Path(args.output_root).resolve()
    _ensure_dir(output_root)

    if _has_only_metadata_images(data_root) or _has_privscreen_qa_but_no_images(data_root):
        if args.auto_download_privscreen:
            data_root = _auto_download_privscreen(Path(args.hf_download_root).resolve())
        else:
            if _has_only_metadata_images(data_root):
                hint = "只发现了 `*.png.metadata`，没有真实图片文件。"
            else:
                hint = "发现了 `privacy_qa.json/normal_qa.json`，但没有 `images/` 下的真实图片文件。"
            raise RuntimeError(
                f"在 {data_root} {hint}"
                "请加上 `--auto-download-privscreen` 自动下载（推荐），或手动把真实图片放到该目录。"
            )

    images = _iter_image_files(data_root)
    if args.limit and args.limit > 0:
        images = images[: args.limit]
    if not images:
        raise RuntimeError(f"未在 {data_root} 找到图片文件。")
    print(f"Found {len(images)} images under: {data_root}")

    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"locale_profile": str(args.detector_locale_profile)},
    )
    levels = [ProtectionLevel.STRONG, ProtectionLevel.BALANCED, ProtectionLevel.WEAK]

    # 原图 OCR 只做一次，三档强度复用
    ocr_cache: dict[str, list[Any]] = {}

    # 输出：每个 level 一个 jsonl + 一个 aggregate.json
    for level in levels:
        print(f"\n=== Running protection_level={level.value} ===")
        out_jsonl = output_root / f"results_{level.value}.jsonl"
        agg = {
            "protection_level": level.value,
            "count": 0,
            "LR": 0.0,
            "MS": 0.0,
            "BLEU": None,
            "ROUGE_L": None,
            "BERTScore": None,
            "CS": None,
        }
        sum_lr = 0.0
        sum_ms = 0.0
        bleu_list: list[float] = []
        rouge_list: list[float] = []
        bert_list: list[float] = []
        cs_list: list[float] = []

        with open(out_jsonl, "w", encoding="utf-8") as f:
            for img_path in _progress(images, total=len(images), desc=f"sanitize[{level.value}]"):
                key = str(img_path)
                if key not in ocr_cache:
                    ocr_cache[key] = guard.ocr.extract(img_path)
                row = run_once(
                    guard=guard,
                    image_path=img_path,
                    protection_level=level,
                    output_root=output_root,
                    leak_threshold=float(args.leak_threshold),
                    cached_ocr_blocks=ocr_cache[key],
                )
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                m = row["metrics"]
                agg["count"] += 1
                sum_lr += float(m["LR"])
                sum_ms += float(m["MS"])
                if m.get("BLEU") is not None:
                    bleu_list.append(float(m["BLEU"]))
                if m.get("ROUGE_L") is not None:
                    rouge_list.append(float(m["ROUGE_L"]))
                if m.get("BERTScore") is not None:
                    bert_list.append(float(m["BERTScore"]))
                if m.get("CS") is not None:
                    cs_list.append(float(m["CS"]))

        def _avg(xs: list[float]) -> float | None:
            return (sum(xs) / len(xs)) if xs else None

        agg["LR"] = sum_lr / agg["count"] if agg["count"] else 0.0
        agg["MS"] = sum_ms / agg["count"] if agg["count"] else 0.0
        agg["BLEU"] = _avg(bleu_list)
        agg["ROUGE_L"] = _avg(rouge_list)
        agg["BERTScore"] = _avg(bert_list)
        agg["CS"] = _avg(cs_list)

        with open(output_root / f"aggregate_{level.value}.json", "w", encoding="utf-8") as af:
            json.dump(agg, af, indent=2, ensure_ascii=False)

    print(f"Done. Outputs saved under: {output_root}")


if __name__ == "__main__":
    main()

