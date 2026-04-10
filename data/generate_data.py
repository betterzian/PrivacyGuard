import random

# 设置随机种子，保证每次运行结果一致（你可以改成别的数字）
random.seed(42)

# ==================== 中文地址组件 ====================
chinese_provinces = [
    "北京市", "上海市", "天津市", "重庆市", "广东省", "江苏省", "浙江省", "四川省",
    "山东省", "河南省", "河北省", "辽宁省", "黑龙江省", "湖南省", "湖北省", "福建省",
    "陕西省", "山西省", "广西壮族自治区", "云南省", "贵州省", "吉林省", "甘肃省",
    "内蒙古自治区", "新疆维吾尔自治区", "安徽省", "江西省", "海南省"
]

chinese_districts = [
    "朝阳区", "徐汇区", "沈河区", "青秀区", "江宁区", "武昌区", "雁塔区", "南岗区",
    "浦东新区", "越秀区", "海淀区", "黄浦区", "和平区", "河东区", "西湖区", "天河区",
    "高新区", "滨江区", "洪山区", "宝山区", "闵行区", "静安区"
]

chinese_streets = [
    "新华路", "杭州路", "南京路", "广州路", "胜利路", "复兴路", "北京路", "长安街",
    "中山路", "人民路", "解放路", "建设路", "文化路", "体育路", "湖滨路", "江滨路",
    "黄河路", "长江路", "和平路", "阳光大道"
]

cn_formats = [
    "{province}{district}{street}{num}号",
    "{district}{street}{num}号 {room}室",
    "{province}{street}{num}弄",
    "{street}{num}号 {room}楼",
    "靠近{street}{num}号, {province}{district}",
    "{province} {district} {street} {num}号 {room}室",
    "{district}{street}{num}号 {room}栋",
    "{province}{district} {street}{num}号",
    "{street}{num}号, {district}",
    "靠近 {street}{num}号 {room}楼, {province}"
]

# ==================== 英文地址组件 ====================
us_cities = [
    "Los Angeles", "New York", "Chicago", "Houston", "Phoenix", "Philadelphia",
    "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
    "Fort Worth", "Columbus", "Indianapolis", "Charlotte", "Seattle", "Denver",
    "Nashville", "Detroit", "Boston", "Memphis", "Portland", "Oklahoma City", "Las Vegas"
]

us_states = ["CA", "NY", "IL", "TX", "AZ", "PA", "FL", "OH", "MI", "NC", "WA", "CO", "TN", "MA", "NV", "OK", "OR"]

eng_streets = [
    "Main Street", "Oak Avenue", "Pine Road", "Maple Lane", "Elm Street",
    "Cedar Boulevard", "Lake Drive", "River Road", "Sunset Boulevard",
    "School Road", "Park Avenue", "Washington Street", "Lincoln Avenue", "Ocean Drive"
]

eng_formats = [
    "{num} {street}, {city}, {state} {zip}",
    "P.O. Box {po}, {city}, {state} {zip}",
    "{street} {num}-{apt}, {city} {state} {zip}",
    "{num}-{apt} {street}, {city}, {state} {zip}",
    "{city}, {state} - {num} {street} {zip}",
    "Unit {apt}, {street} {num}, {city} {state} {zip}",
    "P.O. Box {po}, {city} {state} {zip}",
    "{street} {num}, {city} {state} {zip} Apt {apt}"
]

# ==================== 生成中文地址 ====================
def generate_chinese_address():
    province = random.choice(chinese_provinces)
    district = random.choice(chinese_districts)
    street = random.choice(chinese_streets)
    num = random.randint(1, 999)
    room = random.randint(101, 999)
    fmt = random.choice(cn_formats)
    return fmt.format(province=province, district=district, street=street, num=num, room=room)

# ==================== 生成英文地址 ====================
def generate_english_address():
    city = random.choice(us_cities)
    state = random.choice(us_states)
    street = random.choice(eng_streets)
    num = random.randint(1000, 9999)
    apt = random.randint(1, 999)
    po = random.randint(1000, 9999)
    zip_code = random.randint(10000, 99999)
    fmt = random.choice(eng_formats)
    return fmt.format(num=num, street=street, city=city, state=state, zip=zip_code, apt=apt, po=po)

# ==================== 写入文件 ====================
print("正在生成地址文件...")

# 中文地址文件
with open('chinese_addresses.txt', 'w', encoding='utf-8') as f:
    f.write("=== 1000个中文地址 ===\n\n")
    for i in range(1000):
        addr = generate_chinese_address()
        f.write(f"{i+1}. {addr}\n")

# 英文地址文件
with open('english_addresses.txt', 'w', encoding='utf-8') as f:
    f.write("=== 1000 English Addresses ===\n\n")
    for i in range(1000):
        addr = generate_english_address()
        f.write(f"{i+1}. {addr}\n")

print("✅ 生成完成！")
print("   chinese_addresses.txt 已保存（1000个中文地址）")
print("   english_addresses.txt 已保存（1000个英文地址）")
print("你可以直接打开这两个TXT文件使用啦～")