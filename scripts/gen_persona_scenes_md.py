"""Generate docs/persona_scenes_summary.md from structured privacy eval JSON."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path


def md_escape(s: object) -> str:
    if s is None:
        return ""
    return str(s).replace("|", "\\|")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def persona_block(p: dict, locale_label: str) -> str:
    pid = p["persona_id"]
    tier = p.get("linkability_tier", "")
    cp = p.get("core_profile") or {}
    ph = cp.get("placeholders") or {}
    lines: list[str] = []
    lines.append(f"### {pid}（{locale_label}，关联强度：{tier}）")
    lines.append("")
    lines.append(f"- **本人姓名**：{md_escape(cp.get('self_name'))}")
    lines.append(f"- **生日**：{md_escape(cp.get('birthday'))}")
    lines.append(
        f"- **手机**：主 {md_escape(cp.get('self_phone_primary'))}；"
        f"副 {md_escape(cp.get('self_phone_secondary'))}"
    )
    lines.append(
        f"- **邮箱**：个人 {md_escape(cp.get('self_email'))}；"
        f"工作 {md_escape(cp.get('work_email'))}"
    )
    lines.append(f"- **住址**：{md_escape(cp.get('home_address_full'))}")
    if cp.get("home_city_state"):
        lines.append(f"- **所在城市/州**：{md_escape(cp.get('home_city_state'))}")
    if cp.get("home_address_area"):
        lines.append(f"- **所在区划**：{md_escape(cp.get('home_address_area'))}")
    lines.append(f"- **工作单位**：{md_escape(cp.get('work_org'))}")
    lines.append(f"- **工作地址**：{md_escape(cp.get('work_address_full'))}")
    lines.append(f"- **车牌**：{md_escape(cp.get('license_plate'))}")
    aid, mid = cp.get("account_id"), cp.get("member_id")
    lines.append(
        f"- **账户/会员标识**：account_id `{md_escape(aid)}`；member_id `{md_escape(mid)}`"
    )
    lines.append(f"- **配偶**：{md_escape(cp.get('spouse_name'))}")
    lines.append(f"- **子女**：{md_escape(cp.get('child_name'))}")
    lines.append(f"- **朋友**：{md_escape(cp.get('friend_name'))}")
    lines.append(f"- **老师**：{md_escape(cp.get('teacher_name'))}")
    lines.append(f"- **学校**：{md_escape(cp.get('school_name'))}")
    lines.append("- **占位敏感信息（placeholders）**：")
    for k in sorted(ph.keys()):
        lines.append(f"  - `{k}`：{md_escape(ph.get(k))}")
    scenes = p.get("scene_set") or []
    lines.append(f"- **场景数**：{len(scenes)}")
    lines.append("- **场景列表**：")
    for s in sorted(scenes):
        lines.append(f"  - {md_escape(s)}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    data = root / "data" / "dataset"
    en = load(data / "privacy_eval_realistic_1200_en_release_structured.json")
    zh = load(data / "privacy_eval_realistic_1200_zh_release_structured.json")
    out: list[str] = []
    out.append("# 评测数据集中的人设与场景汇总")
    out.append("")
    out.append(
        "> 由 `privacy_eval_realistic_1200_en_release_structured.json` 与 "
        "`privacy_eval_realistic_1200_zh_release_structured.json` 自动生成。"
        f"日期：{date.today().isoformat()}。"
    )
    out.append("")
    out.append(
        "按人设列出稳定 `core_profile` 与每人 `scene_set`；"
        "文末为两套数据中**所有场景标签的并集**（中英分别列出）。"
    )
    out.append("")
    out.append("---")
    out.append("")
    out.append("## 英文人设（EN，60）")
    out.append("")
    for p in sorted(en["personas"], key=lambda x: x["persona_id"]):
        out.append(persona_block(p, "英文"))
    out.append("---")
    out.append("")
    out.append("## 中文人设（CN，60）")
    out.append("")
    for p in sorted(zh["personas"], key=lambda x: x["persona_id"]):
        out.append(persona_block(p, "中文"))

    en_scenes: set[str] = set()
    zh_scenes: set[str] = set()
    for p in en["personas"]:
        en_scenes.update(p.get("scene_set") or [])
    for p in zh["personas"]:
        zh_scenes.update(p.get("scene_set") or [])

    out.append("---")
    out.append("")
    out.append("## 场景综合（全人设并集）")
    out.append("")
    out.append("英文数据集中出现过的全部场景（去重、排序）：")
    out.append("")
    for s in sorted(en_scenes):
        out.append(f"- {md_escape(s)}")
    out.append("")
    out.append(f"**合计**：{len(en_scenes)} 个场景标签。")
    out.append("")
    out.append("中文数据集中出现过的全部场景（去重、排序）：")
    out.append("")
    for s in sorted(zh_scenes):
        out.append(f"- {md_escape(s)}")
    out.append("")
    out.append(f"**合计**：{len(zh_scenes)} 个场景标签。")
    out.append("")

    dest = root / "docs" / "persona_scenes_summary.md"
    text = "\n".join(out)
    dest.write_text(text, encoding="utf-8")
    line_count = text.count("\n") + (1 if text else 0)
    print(f"Wrote {dest} ({line_count} lines)")


if __name__ == "__main__":
    main()
