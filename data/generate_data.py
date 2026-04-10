"""生成用于地址 detector 评测的中文/英文地址数据。"""

from __future__ import annotations

import json
import random
from pathlib import Path


SEED = 42
COUNT = 1000
ROOT = Path(__file__).resolve().parent


CN_LOCATIONS = [
    {"province": "北京市", "city": "北京市", "district": "海淀区", "subdistrict": "中关村街道"},
    {"province": "北京市", "city": "北京市", "district": "朝阳区", "subdistrict": "望京街道"},
    {"province": "上海市", "city": "上海市", "district": "浦东新区", "subdistrict": "花木街道"},
    {"province": "上海市", "city": "上海市", "district": "徐汇区", "subdistrict": "虹梅街道"},
    {"province": "广东省", "city": "深圳市", "district": "南山区", "subdistrict": "粤海街道"},
    {"province": "广东省", "city": "广州市", "district": "天河区", "subdistrict": "石牌街道"},
    {"province": "江苏省", "city": "南京市", "district": "江宁区", "subdistrict": "东山街道"},
    {"province": "江苏省", "city": "苏州市", "district": "虎丘区", "subdistrict": "狮山街道"},
    {"province": "浙江省", "city": "杭州市", "district": "西湖区", "subdistrict": "古荡街道"},
    {"province": "四川省", "city": "成都市", "district": "高新区", "subdistrict": "桂溪街道"},
    {"province": "湖北省", "city": "武汉市", "district": "洪山区", "subdistrict": "关山街道"},
    {"province": "湖南省", "city": "长沙市", "district": "岳麓区", "subdistrict": "望城坡街道"},
    {"province": "山东省", "city": "青岛市", "district": "市南区", "subdistrict": "香港中路街道"},
    {"province": "福建省", "city": "厦门市", "district": "思明区", "subdistrict": "嘉莲街道"},
]

CN_ROADS = [
    "中山路",
    "新华路",
    "解放路",
    "建设路",
    "文一西路",
    "科技园路",
    "星海路",
    "软件大道",
    "滨江路",
    "湖滨路",
    "长安街",
    "天元西路",
    "科苑路",
    "金钟路",
]

CN_POIS = [
    "阳光花园",
    "锦绣大厦",
    "星河中心",
    "天悦家园",
    "紫荆雅苑",
    "科创园区",
    "云景新城",
    "晨曦广场",
    "海棠府",
    "观澜湾",
]

CN_BUILDINGS = ["1栋", "2栋", "3栋", "5号楼", "A座", "B座", "C幢"]
CN_DETAILS = ["101室", "502室", "1203室", "2单元502室", "3层301室", "18层1802室"]


EN_LOCATIONS = [
    {"city": "Seattle", "state": "WA"},
    {"city": "Chicago", "state": "IL"},
    {"city": "Austin", "state": "TX"},
    {"city": "Boston", "state": "MA"},
    {"city": "Phoenix", "state": "AZ"},
    {"city": "Denver", "state": "CO"},
    {"city": "Portland", "state": "OR"},
    {"city": "Detroit", "state": "MI"},
    {"city": "Nashville", "state": "TN"},
    {"city": "Bellevue", "state": "WA"},
    {"city": "Tacoma", "state": "WA"},
    {"city": "Yakima", "state": "WA"},
]

EN_ROADS = [
    "MainStreet",
    "OakAvenue",
    "PineRoad",
    "MapleLane",
    "ElmStreet",
    "LakeDrive",
    "RiverRoad",
    "ParkAvenue",
    "LincolnAvenue",
    "OceanDrive",
    "NorthLakeWay",
    "QueenAnneAvenue",
]

EN_POIS = [
    "SunsetPlaza",
    "HarborCenter",
    "LakeViewResidence",
    "RiverPark",
    "OakHeights",
    "MapleEstate",
]

EN_BUILDINGS = ["7Building", "BTower", "CBlock", "9House"]
EN_DETAILS = ["Apt205", "Unit18", "Suite300", "Room1203", "Floor8"]


def _compact(text: str) -> str:
    """移除所有空白，确保生成地址不含空格。"""
    return "".join(str(text).split())


def _cn_record(index: int) -> dict[str, object]:
    location = random.choice(CN_LOCATIONS)
    road = random.choice(CN_ROADS)
    poi = random.choice(CN_POIS)
    building = random.choice(CN_BUILDINGS)
    detail = random.choice(CN_DETAILS)
    number = f"{random.randint(1, 999)}号"
    style = random.choice(
        [
            "forward_full",
            "forward_no_subdistrict",
            "forward_no_poi",
            "reverse_tail_full",
            "reverse_tail_city_district",
            "reverse_tail_segmented",
        ]
    )

    if style == "forward_full":
        text = f"{location['province']}{location['city']}{location['district']}{location['subdistrict']}{road}{number}{poi}{building}{detail}"
        components = {
            "province": location["province"],
            "city": location["city"],
            "district": location["district"],
            "subdistrict": location["subdistrict"],
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    elif style == "forward_no_subdistrict":
        text = f"{location['province']}{location['city']}{location['district']}{road}{number}{poi}{building}{detail}"
        components = {
            "province": location["province"],
            "city": location["city"],
            "district": location["district"],
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    elif style == "forward_no_poi":
        text = f"{location['province']}{location['city']}{location['district']}{location['subdistrict']}{road}{number}{building}{detail}"
        components = {
            "province": location["province"],
            "city": location["city"],
            "district": location["district"],
            "subdistrict": location["subdistrict"],
            "road": road,
            "number": number,
            "building": building,
            "detail": detail,
        }
    elif style == "reverse_tail_full":
        text = f"{road}{number}{poi}{building}{detail},{location['district']}{location['city']}{location['province']}"
        components = {
            "province": location["province"],
            "city": location["city"],
            "district": location["district"],
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    elif style == "reverse_tail_city_district":
        text = f"{location['subdistrict']}{road}{number}{building}{detail},{location['city']}{location['district']}"
        components = {
            "city": location["city"],
            "district": location["district"],
            "subdistrict": location["subdistrict"],
            "road": road,
            "number": number,
            "building": building,
            "detail": detail,
        }
    else:
        text = f"{road}{number}{poi}{building}{detail},{location['district']},{location['city']},{location['province']}"
        components = {
            "province": location["province"],
            "city": location["city"],
            "district": location["district"],
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }

    return {
        "id": index,
        "locale": "zh_cn",
        "text": _compact(text),
        "format": style,
        "components": components,
    }


def _en_record(index: int) -> dict[str, object]:
    location = random.choice(EN_LOCATIONS)
    road = random.choice(EN_ROADS)
    poi = random.choice(EN_POIS)
    building = random.choice(EN_BUILDINGS)
    detail = random.choice(EN_DETAILS)
    number = str(random.randint(1000, 9999))
    zip_code = str(random.randint(10000, 99999))
    style = random.choice(
        [
            "forward_basic",
            "forward_with_detail",
            "forward_with_poi",
            "forward_with_building",
            "forward_full",
        ]
    )

    if style == "forward_basic":
        text = f"{number}{road},{location['city']},{location['state']},{zip_code}"
        components = {
            "city": location["city"],
            "province": location["state"],
            "road": road,
            "number": number,
            "detail": zip_code,
        }
    elif style == "forward_with_detail":
        text = f"{detail},{number}{road},{location['city']},{location['state']},{zip_code}"
        components = {
            "city": location["city"],
            "province": location["state"],
            "road": road,
            "number": number,
            "detail": detail,
        }
    elif style == "forward_with_poi":
        text = f"{number}{road},{poi},{location['city']},{location['state']},{zip_code}"
        components = {
            "city": location["city"],
            "province": location["state"],
            "road": road,
            "number": number,
            "poi": poi,
            "detail": zip_code,
        }
    elif style == "forward_with_building":
        text = f"{number}{road},{building},{location['city']},{location['state']},{zip_code}"
        components = {
            "city": location["city"],
            "province": location["state"],
            "road": road,
            "number": number,
            "building": building,
            "detail": zip_code,
        }
    else:
        text = f"{detail},{number}{road},{building},{poi},{location['city']},{location['state']},{zip_code}"
        components = {
            "city": location["city"],
            "province": location["state"],
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }

    return {
        "id": index,
        "locale": "en_us",
        "text": _compact(text),
        "format": style,
        "components": components,
    }


def _write_lines(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("\n".join(str(record["text"]) for record in records) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    random.seed(SEED)

    cn_records = [_cn_record(index) for index in range(1, COUNT + 1)]
    en_records = [_en_record(index) for index in range(1, COUNT + 1)]

    _write_lines(ROOT / "chinese_addresses.txt", cn_records)
    _write_lines(ROOT / "english_addresses.txt", en_records)
    _write_jsonl(ROOT / "chinese_addresses.jsonl", cn_records)
    _write_jsonl(ROOT / "english_addresses.jsonl", en_records)

    print("正在生成地址文件...")
    print("✅ 生成完成。")
    print(f"   {ROOT / 'chinese_addresses.txt'}")
    print(f"   {ROOT / 'english_addresses.txt'}")
    print(f"   {ROOT / 'chinese_addresses.jsonl'}")
    print(f"   {ROOT / 'english_addresses.jsonl'}")


if __name__ == "__main__":
    main()
