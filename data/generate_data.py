"""生成地址评测数据（中文/英文）"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

SEED = 42
COUNT = 1000
ROOT = Path(__file__).resolve().parent

CN_LOCATIONS = [
    ("北京市", "北京市", "海淀区", "中关村街道"),
    ("北京市", "北京市", "朝阳区", "望京街道"),
    ("上海市", "上海市", "浦东新区", "花木街道"),
    ("广东省", "深圳市", "南山区", "粤海街道"),
    ("江苏省", "南京市", "江宁区", "东山街道"),
    ("浙江省", "杭州市", "西湖区", "古荡街道"),
]
CN_ROADS = ["中山路", "新华路", "解放路", "建设路", "软件大道", "滨江路", "科苑路"]
CN_POIS = ["阳光国际社区", "锦绣大厦", "星河中心", "天悦家园", "科创园区"]
CN_BUILDINGS = ["1栋", "2栋", "3栋", "A座", "B座", "5号楼"]
CN_DETAILS = ["101室", "502室", "1203室", "2单元502室", "3层301室", "18层1802室"]

EN_LOCATIONS = [("Seattle", "WA"), ("Chicago", "IL"), ("Austin", "TX"), ("Boston", "MA"), ("Portland", "OR"), ("Bellevue", "WA")]
EN_ROADS = ["Main Street", "Oak Avenue", "Pine Road", "Maple Lane", "Lake Drive", "Queen Anne Avenue"]
EN_POIS = ["Sunset Plaza", "Harbor Center", "Lake View Residence", "River Park"]
EN_BUILDINGS = ["Building 7", "Tower B", "Block C", "House 9"]
EN_DETAILS = ["Apt 205", "Unit 18", "Suite 300", "Room 1203"]


def _compact(text: str) -> str:
    return "".join(str(text).split())


def _normalize_en_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", str(text).strip())
    return re.sub(r"\s*,\s*", ", ", normalized)


def _cn_record(index: int) -> dict[str, object]:
    province, city, district, subdistrict = random.choice(CN_LOCATIONS)
    road = random.choice(CN_ROADS)
    poi = random.choice(CN_POIS)
    building = random.choice(CN_BUILDINGS)
    detail = random.choice(CN_DETAILS)
    number = f"{random.randint(1, 999)}号"
    style = random.choice(("forward_full", "forward_no_subdistrict", "reverse_tail_full", "reverse_tail_segmented"))
    if style == "forward_full":
        text = f"{province}{city}{district}{subdistrict}{road}{number}{poi}{building}{detail}"
        components = {
            "province": province,
            "city": city,
            "district": district,
            "subdistrict": subdistrict,
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    elif style == "forward_no_subdistrict":
        text = f"{province}{city}{district}{road}{number}{poi}{building}{detail}"
        components = {
            "province": province,
            "city": city,
            "district": district,
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    elif style == "reverse_tail_full":
        text = f"{road}{number}{poi}{building}{detail},{district}{city}{province}"
        components = {
            "province": province,
            "city": city,
            "district": district,
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    else:
        text = f"{road}{number}{poi}{building}{detail},{district},{city},{province}"
        components = {
            "province": province,
            "city": city,
            "district": district,
            "road": road,
            "number": number,
            "poi": poi,
            "building": building,
            "detail": detail,
        }
    return {"id": index, "locale": "zh_cn", "text": _compact(text), "format": style, "components": components}


def _en_record(index: int) -> dict[str, object]:
    city, state = random.choice(EN_LOCATIONS)
    road = random.choice(EN_ROADS)
    poi = random.choice(EN_POIS)
    building = random.choice(EN_BUILDINGS)
    detail = random.choice(EN_DETAILS)
    number = str(random.randint(1000, 9999))
    zip_code = str(random.randint(10000, 99999))
    style = random.choice(("forward_basic", "forward_with_detail", "forward_with_poi", "forward_with_building"))
    if style == "forward_basic":
        text = f"{number} {road}, {city}, {state} {zip_code}"
        components = {"city": city, "province": state, "road": road, "number": number, "detail": zip_code}
    elif style == "forward_with_detail":
        text = f"{detail}, {number} {road}, {city}, {state} {zip_code}"
        components = {"city": city, "province": state, "road": road, "number": number, "detail": detail}
    elif style == "forward_with_poi":
        text = f"{number} {road}, {poi}, {city}, {state} {zip_code}"
        components = {"city": city, "province": state, "road": road, "number": number, "poi": poi, "detail": zip_code}
    else:
        text = f"{number} {road}, {building}, {city}, {state} {zip_code}"
        components = {"city": city, "province": state, "road": road, "number": number, "building": building, "detail": zip_code}
    return {"id": index, "locale": "en_us", "text": _normalize_en_text(text), "format": style, "components": components}


def _write_lines(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("\n".join(str(x["text"]) for x in rows) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    random.seed(SEED)
    zh = [_cn_record(i) for i in range(1, COUNT + 1)]
    en = [_en_record(i) for i in range(1, COUNT + 1)]
    _write_lines(ROOT / "chinese_addresses.txt", zh)
    _write_lines(ROOT / "english_addresses.txt", en)
    _write_jsonl(ROOT / "chinese_addresses.jsonl", zh)
    _write_jsonl(ROOT / "english_addresses.jsonl", en)
    print("✅ generated:", COUNT, COUNT)


if __name__ == "__main__":
    main()
