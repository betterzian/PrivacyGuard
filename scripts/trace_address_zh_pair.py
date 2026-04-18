"""对两条中文地址跑 detector → NormalizedPII，并逐步打印 same_entity 判定链（含 admin 逐层）。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.models.normalized_pii import NormalizedAddressComponent, NormalizedPII
from privacyguard.infrastructure.pii.detector.rule_based import RuleBasedPIIDetector
from privacyguard.utils import normalized_pii as nz
from privacyguard.utils.normalized_pii import same_entity


def _component_to_dict(c: NormalizedAddressComponent) -> dict[str, Any]:
    return {
        "component_type": c.component_type,
        "level": list(c.level),
        "value": c.value if not isinstance(c.value, tuple) else list(c.value),
        "key": c.key if not isinstance(c.key, tuple) else list(c.key),
        "suspected": [
            {"levels": list(s.levels), "value": s.value, "key": s.key, "origin": s.origin}
            for s in c.suspected
        ],
    }


def _normalized_dump(n: NormalizedPII) -> dict[str, Any]:
    return {
        "raw_text": n.raw_text,
        "canonical": n.canonical,
        "components": dict(n.components),
        "identity": dict(n.identity),
        "match_terms": list(n.match_terms),
        "numbers": list(n.numbers),
        "keyed_numbers": dict(n.keyed_numbers),
        "has_admin_static": n.has_admin_static,
        "ordered_components": [_component_to_dict(c) for c in n.ordered_components],
    }


def _first_address_normalized(detector: RuleBasedPIIDetector, text: str) -> NormalizedPII:
    for c in detector.detect(text, []):
        if c.attr_type == PIIAttributeType.ADDRESS and c.normalized_source is not None:
            return c.normalized_source
    raise RuntimeError("未检测到 ADDRESS")


def _trace_admin_levels(left: NormalizedPII, right: NormalizedPII) -> list[str]:
    lines: list[str] = []
    empty: dict[int, str] = {}
    for level in nz._ADMIN_LEVEL_KEYS:
        lv = nz._admin_value_at_level(left, level, empty)
        rv = nz._admin_value_at_level(right, level, empty)
        ls = nz._level_candidates(left, level, empty)
        rs = nz._level_candidates(right, level, empty)
        lines.append(f"### admin 层 `{level}`")
        lines.append(f"- 硬值：左 `{lv}` | 右 `{rv}`")
        lines.append(f"- 候选集（硬值 ∪ suspect 裸 value，已 canonicalize）：左 `{sorted(ls)}` | 右 `{sorted(rs)}`")

        if lv is None and rv is None:
            if not ls and not rs:
                lines.append("- 判定：双侧硬值与候选俱空 → 跳过本层。")
                continue
            if not ls or not rs:
                lines.append("- 判定：候选一侧为空 → 真双缺或单侧缺 → 跳过。")
                continue
            ok = nz._sets_subset_either(ls, rs)
            lines.append(f"- 判定：双侧候选非空 → 子串互容={ok}；若不成立则 **admin mismatch**。")
            continue

        if lv is None or rv is None:
            if not ls or not rs:
                lines.append("- 判定：单侧硬值缺且任一侧候选空 → **单侧真缺**，本层不证伪。")
                continue
            ok = nz._sets_subset_either(ls, rs)
            lines.append(
                f"- 判定：单侧硬值缺但两侧候选均非空 → 须存在一对子串互容 → **{ok}**。"
                + (" 若不成立则 **admin mismatch**（本对地址通常死在这里）。" if not ok else "")
            )
            continue

        if nz._admin_value_match(str(lv), str(rv)):
            lines.append("- 判定：双侧硬值子串互容 → 本层命中。")
            continue
        rec = nz._suspect_chain_can_reconcile(left, right, level, empty, empty)
        lines.append(f"- 判定：硬值不互容 → suspect 补救={rec}；False 则 **admin mismatch**。")
    return lines


def _trace_same_entity_steps(left: NormalizedPII, right: NormalizedPII) -> list[str]:
    lines: list[str] = []
    lap = left.identity.get("address_part", "")
    rap = right.identity.get("address_part", "")
    lines.append("## same_entity 逐步判定（与 `_same_address` 对齐）")
    lines.append("")
    lines.append("### 0) `address_part` 闸门")
    lines.append(f"- 左：`{lap}`")
    lines.append(f"- 右：`{rap}`")
    lines.append(f"- 通过：`{bool(lap and rap)}`")
    if not lap or not rap:
        return lines

    lines.append("")
    lines.append("### 1) 顶层 identity：双侧俱存时必须相等")
    for key in ("country", "province", "house_number", "postal_code"):
        lv = str(left.identity.get(key) or "").strip()
        rv = str(right.identity.get(key) or "").strip()
        if lv and rv:
            ok = lv == rv
            lines.append(f"- `{key}`：左=`{lv}` 右=`{rv}` → {'相等' if ok else '**不等 → 整体失败**'}")
        elif lv or rv:
            lines.append(f"- `{key}`：仅一侧有值（`{lv!r}` vs `{rv!r}`）→ 规则允许，不否决。")
        else:
            lines.append(f"- `{key}`：双侧皆空 → 跳过。")

    lines.append("")
    lines.append("### 2) 非 admin 层：`road` / `poi` / `building` / `detail`（值子串 + suspect OR 链）")
    left_has = left.has_admin_static
    right_has = right.has_admin_static
    for key in ("road", "poi", "building", "detail"):
        ok, la, ra = nz._compare_peer_with_suspect_case2(left, right, key)
        left_has = left_has or la
        right_has = right_has or ra
        lines.append(f"- `{key}`：match_ok={ok}，左 Case2 admin 信号={la}，右={ra}")
        if not ok:
            lines.append("  → **本层失败则 same_entity 为 False**")

    lines.append("")
    lines.append("### 3) admin 层：多解释枚举 → `_compare_admin_levels_with_interpretations`")
    admin = nz._compare_admin_levels_with_interpretations(left, right)
    lines.extend(_trace_admin_levels(left, right))
    lines.append("")
    lines.append(f"- **聚合结果**：`{admin}`（`match` / `inconclusive` / `mismatch`）")

    lines.append("")
    lines.append("### 4) `inconclusive` × 双方 has_admin（动态累计）")
    lines.append(f"- left_has_admin（static ∪ Case2）：`{left_has}`")
    lines.append(f"- right_has_admin：`{right_has}`")
    if admin == "inconclusive" and left_has and right_has:
        lines.append("- **双方 has_admin 且 inconclusive → 否决（False）**")
    elif admin == "inconclusive":
        lines.append("- 至少一侧无 has_admin → inconclusive 可放行（继续后续步骤）。")
    elif admin == "mismatch":
        lines.append("- **admin mismatch → `_same_address` 在此处直接 `return False`**（后续 numbers / POI 比例等**不会**再执行；下列仅作对照参考）。")

    lines.append("")
    lines.append("### 5) `numbers` / `keyed_numbers`（mismatch 时实现中已跳过）")
    lines.append(f"- `_numbers_match` → `{nz._numbers_match(left.numbers, right.numbers, left.keyed_numbers, right.keyed_numbers)}`")

    lines.append("")
    lines.append("### 6) `subdistrict`（mismatch 时实现中已跳过）")
    ok_sd, _, _ = nz._compare_peer_with_suspect_case2(left, right, "subdistrict")
    lines.append(f"- match_ok → `{ok_sd}`")

    lines.append("")
    lines.append("### 7) POI 列表（mismatch 时实现中已跳过）")
    lines.append(f"- → `{nz._compare_poi_list(left, right)}`")

    denom = min(len(left.ordered_components), len(right.ordered_components))
    lines.append("")
    lines.append(f"### 8) 参考：`ordered_components` 长度比（denom={denom}）")
    lines.append(f"- **`same_entity` = `{same_entity(left, right)}`**")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="追踪两条中文地址的归一化与同址判定")
    parser.add_argument("--full", type=str, default="北京市北京市朝阳区望京街道中山路286号锦绣大厦A座1203室")
    parser.add_argument("--variant", type=str, default="中山路286号锦绣大厦A座1203室,朝阳区")
    parser.add_argument("--json-out", type=Path, default=None, help="可选：写出完整 JSON")
    args = parser.parse_args()

    detector = RuleBasedPIIDetector(locale_profile="zh_cn")
    left = _first_address_normalized(detector, args.full)
    right = _first_address_normalized(detector, args.variant)

    payload = {
        "full_text": args.full,
        "variant_text": args.variant,
        "left": _normalized_dump(left),
        "right": _normalized_dump(right),
        "same_entity": same_entity(left, right),
        "markdown_steps": "\n".join(_trace_same_entity_steps(left, right)),
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(args.json_out)
    else:
        print(json.dumps({"left": payload["left"], "right": payload["right"], "same_entity": payload["same_entity"]}, ensure_ascii=False, indent=2))
        print()
        print(payload["markdown_steps"])


if __name__ == "__main__":
    main()
