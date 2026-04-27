"""POI 类别优先级表。

restore 阶段在同实体累积态包含多个 POI 时（如 ``[阳光小区, 万达广场]``），
需要按"居住实体优先于商业体优先于配套"的语义挑选回填值。
本模块提供单一真源的类别 → rank 映射，``rank`` 越小优先级越高。

注意：
- 这里的类别词表与检测器抽取阶段无关——`stacks/common.py` 的左数词与
  `candidate_utils.py` 的 address signal 仍各自服务于"切词 / 启发抽取"，
  本表只用于"还原时挑哪个 POI"。后续可考虑统一真源（已在计划 follow-up 中记录）。
"""

from __future__ import annotations

# 优先级分组：每条 tuple 内的类别同 rank；表索引即 rank。
POI_KEY_PRIORITY: tuple[tuple[str, ...], ...] = (
    ("小区", "社区", "公寓", "宿舍"),  # 居住实体（最高）
    ("园区", "花园", "家园", "苑", "庭", "府", "湾"),  # 园区 / 苑落
    ("楼", "栋", "幢", "座", "单元", "室", "房", "户"),  # 建筑 / 单元
    ("大厦", "中心", "广场", "商场", "百货"),  # 商业体
    ("停车场", "车库"),  # 配套（最低）
)

_UNKNOWN_RANK = 999

_KEY_TO_RANK: dict[str, int] = {
    key: rank for rank, group in enumerate(POI_KEY_PRIORITY) for key in group
}


def poi_key_rank(poi_key: str) -> int:
    """返回 POI 类别 rank；不在优先级表内或为空时返回 ``_UNKNOWN_RANK``。"""
    key = (poi_key or "").strip()
    if not key:
        return _UNKNOWN_RANK
    return _KEY_TO_RANK.get(key, _UNKNOWN_RANK)


def select_priority_poi(
    poi: str,
    poi_key: str,
) -> str:
    """在 entity 累积态的 ``poi`` / ``poi_key`` 串中按优先级挑出一个 POI 值。

    规则：
    - poi 与 poi_key 以 ``|`` 分隔且按下标对齐（**不过滤空段**以保对齐）；
    - 优先级 rank 最小者优先；同 rank 内按 poi 出现顺序取首个；
    - 空 poi 段跳过；无可选 POI 时返回空串。
    """
    raw_pois = (poi or "").split("|")
    raw_keys = (poi_key or "").split("|")
    best_index = -1
    best_rank = _UNKNOWN_RANK + 1  # 任意已知/未知 rank 都更优
    for i, raw in enumerate(raw_pois):
        value = raw.strip()
        if not value:
            continue
        k = raw_keys[i].strip() if i < len(raw_keys) else ""
        r = poi_key_rank(k)
        if r < best_rank:
            best_rank = r
            best_index = i
    if best_index == -1:
        return ""
    return raw_pois[best_index].strip()


__all__ = [
    "POI_KEY_PRIORITY",
    "poi_key_rank",
    "select_priority_poi",
]
