"""基于规则与字典的 PII 检测器。"""

from dataclasses import dataclass, field, replace
import json
import logging
import re
from pathlib import Path
from typing import Callable

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, PIISourceType, ProtectionLevel
from privacyguard.domain.interfaces.mapping_store import MappingStore
from privacyguard.domain.models.mapping import ReplacementRecord
from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.pii.json_privacy_repository import (
    InvalidPrivacyRepositoryError,
    parse_privacy_repository_document,
)
from privacyguard.utils.aho_matcher import AhoCorasickMatcher
from privacyguard.utils.pii_value import (
    address_components_from_levels,
    render_address_components,
    build_match_text,
    classify_content_shape_attr,
    canonicalize_name_text,
    compact_bank_account_value,
    canonicalize_pii_value,
    compact_card_number_value,
    compact_driver_license_value,
    compact_email_value,
    compact_id_value,
    compact_passport_value,
    compact_other_code_value,
    compact_phone_value,
    dictionary_match_variants,
)

LOGGER = logging.getLogger(__name__)

_DATA_ROOT = Path(__file__).resolve().parents[3] / "data"
_GEO_ADMIN_SUFFIXES = ("特别行政区", "自治区", "自治州", "省", "市", "州", "盟", "区", "县", "旗", "乡", "镇")
_GEO_ADDRESS_SUFFIXES = (
    "地铁站",
    "火车站",
    "高铁站",
    "机场",
    "码头",
    "街道",
    "社区",
    "小区",
    "公寓",
    "大厦",
    "广场",
    "花园",
    "家园",
    "园区",
    "校区",
    "宿舍",
    "公园",
    "景区",
    "商圈",
    "路",
    "街",
    "巷",
    "弄",
    "胡同",
    "大道",
    "道",
    "村",
    "苑",
    "庭",
    "府",
    "湾",
    "城",
    "里",
    "站",
)


@dataclass(frozen=True, slots=True)
class _BuiltinGeoLexicon:
    provinces: frozenset[str]
    cities: frozenset[str]
    districts: frozenset[str]
    local_places: frozenset[str]
    address_tokens: frozenset[str]
    ordered_tokens: tuple[str, ...]


def _normalize_geo_entries(values) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    normalized = []
    for item in values:
        text = str(item).strip()
        if text:
            normalized.append(text)
    return tuple(dict.fromkeys(normalized))


def _expand_city_tokens(values: tuple[str, ...]) -> frozenset[str]:
    expanded: set[str] = set()
    for value in values:
        expanded.add(value)
        if not value.endswith(("市", "地区", "自治州", "盟", "新区")):
            expanded.add(f"{value}市")
    return frozenset(expanded)


def _load_builtin_geo_lexicon() -> _BuiltinGeoLexicon:
    lexicon_path = _DATA_ROOT / "china_geo_lexicon.json"
    if not lexicon_path.exists():
        LOGGER.warning("builtin geo lexicon not found: %s", lexicon_path)
        return _BuiltinGeoLexicon(
            provinces=frozenset(),
            cities=frozenset(),
            districts=frozenset(),
            local_places=frozenset(),
            address_tokens=frozenset(),
            ordered_tokens=(),
        )
    content = json.loads(lexicon_path.read_text(encoding="utf-8"))
    provinces = frozenset(_normalize_geo_entries(content.get("provinces")))
    cities = _expand_city_tokens(_normalize_geo_entries(content.get("cities")))
    districts = frozenset(_normalize_geo_entries(content.get("districts")))
    local_places = frozenset(_normalize_geo_entries(content.get("local_places")))
    address_tokens = frozenset(
        token for token in (districts | local_places) if token.endswith(_GEO_ADDRESS_SUFFIXES) or token in local_places
    )
    ordered_tokens = tuple(sorted(provinces | cities | districts | local_places, key=lambda item: (-len(item), item)))
    return _BuiltinGeoLexicon(
        provinces=provinces,
        cities=cities,
        districts=districts,
        local_places=local_places,
        address_tokens=address_tokens,
        ordered_tokens=ordered_tokens,
    )

_MASK_CHAR_CLASS_COMMON = r"[*＊●○◦◯⚫⚪■□▪▫█▇▉◆◇★☆※×✕✖╳]"
_MASK_CHAR_CLASS_WITH_X = r"[*＊xX●○◦◯⚫⚪■□▪▫█▇▉◆◇★☆※×✕✖╳]"
_TEXT_MASK_CHAR_CLASS = r"[Xx某*＊●○◦◯⚫⚪■□▪▫█▇▉◆◇★☆※]"
_TEXT_MASK_SYMBOLS = set("Xx某*＊●○◦◯⚫⚪■□▪▫█▇▉◆◇★☆※")
_TEXT_MASK_ALPHA_SYMBOLS = {"X", "x", "某"}
_TEXT_MASK_VISUAL_SYMBOLS = _TEXT_MASK_SYMBOLS - _TEXT_MASK_ALPHA_SYMBOLS
_ADDRESS_MASK_CHAR_CLASS = r"[*＊xX某●○◦◯⚫⚪■□▪▫█▇▉◆◇★☆※]"

_COMMON_SINGLE_CHAR_SURNAMES = set(
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐费"
    "廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元顾孟平黄和穆"
    "萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁杜阮"
    "蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍虞万"
    "支柯管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包左石崔吉钮龚程嵇邢滑"
    "裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富巫乌焦巴弓牧隗山谷车"
    "侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘斜厉戎祖武符刘景詹束龙叶幸司韶黎"
    "乔苍双闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍却璩桑桂濮牛寿通边扈燕冀郏"
    "浦尚农温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都"
    "耿满弘匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简"
    "饶空曾沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公仉督岳帅缑亢况郈"
    "有琴归海晋楚闫法汝鄢涂钦岳帅亓佘佟哈墨赏谯笪年爱阳佴第五言福百家官"
)
_COMMON_COMPOUND_SURNAMES = {
    "欧阳",
    "太史",
    "端木",
    "上官",
    "司马",
    "东方",
    "独孤",
    "南宫",
    "万俟",
    "闻人",
    "夏侯",
    "诸葛",
    "尉迟",
    "公羊",
    "赫连",
    "澹台",
    "皇甫",
    "宗政",
    "濮阳",
    "公冶",
    "太叔",
    "申屠",
    "公孙",
    "慕容",
    "仲孙",
    "钟离",
    "长孙",
    "宇文",
    "司徒",
    "鲜于",
    "司空",
    "闾丘",
    "子车",
    "亓官",
    "司寇",
    "巫马",
    "公西",
    "颛孙",
    "壤驷",
    "公良",
    "漆雕",
    "乐正",
    "宰父",
    "谷梁",
    "拓跋",
    "夹谷",
    "轩辕",
    "令狐",
    "段干",
    "百里",
    "呼延",
    "东郭",
    "南门",
    "羊舌",
    "微生",
    "公户",
    "公玉",
    "梁丘",
    "左丘",
    "东门",
    "西门",
    "第五",
}
_NAME_BLACKLIST = {
    "姓名",
    "名字",
    "昵称",
    "称呼",
    "联系人",
    "收件人",
    "寄件人",
    "住址",
    "地址",
    "电话",
    "手机",
    "邮箱",
    "客户",
    "用户",
    "先生",
    "女士",
    "老师",
    "医生",
    "经理",
}
_NON_PERSON_TOKENS = {
    "项目",
    "产品",
    "前端",
    "后端",
    "测试",
    "运营",
    "销售",
    "客服",
    "部门",
    "团队",
    "用户",
    "客户",
    "老板",
    "助理",
}
_NON_PERSON_TOKENS_EN = {
    "account",
    "address",
    "admin",
    "agent",
    "alert",
    "contact",
    "customer",
    "dashboard",
    "editor",
    "help",
    "home",
    "message",
    "notification",
    "profile",
    "project",
    "pronoun",
    "pronouns",
    "service",
    "settings",
    "system",
    "support",
    "team",
    "user",
}
_UI_OPERATION_NAME_WHITELIST = {
    "公告",
    "通知",
    "通知群",
    "文件",
    "搜索",
    "设置",
    "编辑",
    "删除",
    "转发",
    "收藏",
    "添加",
    "发送",
    "分享",
    "回复",
    "撤回",
    "复制",
    "粘贴",
    "拍照",
    "相册",
    "扫一扫",
    "返回",
    "关闭",
    "打开",
    "刷新",
    "保存",
    "上传",
    "下载",
    "add",
    "back",
    "cancel",
    "close",
    "copy",
    "delete",
    "download",
    "edit",
    "file",
    "forward",
    "open",
    "refresh",
    "reply",
    "save",
    "search",
    "send",
    "settings",
    "share",
    "upload",
}
_LOCATION_ACTIVITY_TOKENS = (
    "拼车",
    "滑雪",
    "住宿",
    "酒店",
    "旅馆",
    "民宿",
    "旅行",
    "旅游",
    "出发",
    "返程",
    "集合",
    "探店",
    "租房",
    "求职",
    "兼职",
    "上班",
    "夜跑",
    "搭子",
    "airport",
    "checkin",
    "commute",
    "hotel",
    "office",
    "pickup",
    "ride",
    "school",
    "travel",
    "trip",
    "work",
)
_OCR_FRAGMENT_DELIMITERS = "-－—_/|｜"
_OCR_SEMANTIC_BREAK_TOKEN = " <OCR_BREAK> "
_BUILTIN_GEO_LEXICON = _load_builtin_geo_lexicon()
_COMMON_CITY_TOKENS = set(_BUILTIN_GEO_LEXICON.cities)
_COMMON_DISTRICT_TOKENS = set(_BUILTIN_GEO_LEXICON.districts)
_COMMON_BUSINESS_AREA_TOKENS = set(_BUILTIN_GEO_LEXICON.local_places)
_LOCATION_CLUE_TOKENS = _BUILTIN_GEO_LEXICON.ordered_tokens
_LOCATION_CLUE_MATCHER = AhoCorasickMatcher(_LOCATION_CLUE_TOKENS)
_TITLE_SEGMENT_PATTERN = re.compile(r"[-—_|｜/／]")
_NAME_FIELD_KEYWORDS = (
    "name",
    "full name",
    "username",
    "realname",
    "real name",
    "真实姓名",
    "姓名",
    "住客姓名",
    "名字",
    "昵称",
    "称呼",
    "联系人",
    "联系人姓名",
    "收件人",
    "收货人",
    "寄件人",
    "收件姓名",
    "申请人",
    "委托人",
    "监护人",
    "法定代表人",
    "户主",
    "住户",
    "本人",
    "客户",
    "用户",
    "病人姓名",
    "患者姓名",
)
_NAME_FAMILY_FIELD_KEYWORDS = (
    "family name",
    "last name",
    "surname",
    "姓",
    "姓氏",
)
_NAME_GIVEN_FIELD_KEYWORDS = (
    "first name",
    "given name",
    "名字",
    "名",
)
_NAME_MIDDLE_FIELD_KEYWORDS = (
    "middle name",
    "middle",
    "中间名",
)
_ADDRESS_FIELD_KEYWORDS = (
    "address",
    "addr",
    "mailing address",
    "shipping address",
    "location",
    "所在地",
    "地址",
    "住址",
    "详细地址",
    "联系地址",
    "家庭地址",
    "户籍地址",
    "户籍所在地",
    "现住址",
    "居住地址",
    "常住地址",
    "配送地址",
    "收货地址",
    "收件地址",
    "寄件地址",
    "学校地址",
    "公司地址",
    "单位地址",
    "籍贯",
)
_PHONE_FIELD_KEYWORDS = (
    "phone",
    "phone number",
    "mobile",
    "mobile number",
    "tel",
    "telephone",
    "联系电话",
    "联系电话码",
    "联系电话号码",
    "联系号码",
    "联系手机",
    "手机号",
    "手机号码",
    "电话",
    "手机",
    "紧急联系人电话",
)
_CARD_FIELD_KEYWORDS = (
    "card",
    "card_number",
    "bank_card",
    "credit_card",
    "debit_card",
    "卡号",
    "银行卡号",
    "银行卡",
    "信用卡号",
    "信用卡",
    "借记卡号",
    "借记卡",
)
_BANK_ACCOUNT_FIELD_KEYWORDS = (
    "bank_account",
    "bank account",
    "account_number",
    "account number",
    "bank_account_number",
    "银行账号",
    "银行账户",
    "银行账户号",
    "银行账号号",
    "收款账号",
    "收款账户",
    "对公账号",
    "对公账户",
    "转账账号",
    "汇款账号",
)
_PASSPORT_FIELD_KEYWORDS = (
    "passport",
    "passport_number",
    "passport number",
    "护照",
    "护照号",
    "护照号码",
)
_DRIVER_LICENSE_FIELD_KEYWORDS = (
    "driver_license",
    "driver license",
    "driver_license_number",
    "driver license number",
    "driving_license",
    "驾照",
    "驾照号",
    "驾驶证",
    "驾驶证号",
    "驾驶证档案编号",
    "驾驶证编号",
)
_EMAIL_FIELD_KEYWORDS = (
    "email",
    "e-mail",
    "mail",
    "邮箱",
    "电子邮箱",
    "联系邮箱",
)
_ID_FIELD_KEYWORDS = (
    "id",
    "id no",
    "id number",
    "identity number",
    "idno",
    "id_number",
    "身份证",
    "身份证号",
    "身份证号码",
    "证件号",
    "证件号码",
    "公民身份号码",
)
_OTHER_FIELD_KEYWORDS = (
    "code",
    "token",
    "otp",
    "验证码",
    "校验码",
    "订单号",
    "单号",
    "编号",
    "工号",
    "学号",
    "会员号",
    "客户号",
    "流水号",
)
_ORGANIZATION_FIELD_KEYWORDS = (
    "organization",
    "org",
    "company",
    "institution",
    "employer",
    "school",
    "hospital",
    "bank",
    "firm",
    "机构",
    "组织",
    "单位",
    "公司",
    "企业",
    "工作单位",
    "所在单位",
    "任职单位",
    "就职公司",
    "学校",
    "医院",
    "银行",
    "毕业院校",
    "就读学校",
    "律所",
    "事务所",
    "研究院",
    "研究所",
)
_NAME_HONORIFICS = (
    "先生",
    "女士",
    "小姐",
    "老师",
    "医生",
    "经理",
    "总监",
    "总",
    "警官",
    "同学",
)
_EN_NAME_HONORIFICS = (
    "mr",
    "mr.",
    "mrs",
    "mrs.",
    "ms",
    "ms.",
    "miss",
    "dr",
    "dr.",
    "prof",
    "prof.",
)
_NAME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000·•・")
_NAME_DICTIONARY_ALLOWED_NEXT_CHARS = (
    set("的了呢吗吧啊呀哦哈呗嘛是在于与和及并或给让把将向从到回处办找发传交送问说看来去要想会能可应需请先再就已未还都也被把按")
    | {item[0] for item in _NAME_HONORIFICS if item}
)
_NAME_CONTEXT_PREFIX_TOKENS = (
    "联系",
    "找",
    "叫",
    "叫做",
    "姓名",
    "名字",
    "昵称",
    "联系人",
    "收件人",
    "寄件人",
    "申请人",
    "委托人",
    "法定代表人",
    "患者",
    "病人",
    "同学",
    "老师",
    "医生",
    "经理",
    "群主",
)
_NAME_CONTEXT_CARRIER_TOKENS = (
    "药房",
    "药店",
    "店铺",
    "商店",
    "超市",
    "饭店",
    "酒店",
    "宾馆",
    "民宿",
    "公司",
    "工厂",
    "学校",
    "医院",
    "银行",
    "门店",
    "车队",
    "群",
)
_NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS = (
    "大学",
    "学院",
    "公司",
    "集团",
    "科技",
    "信息",
    "软件",
    "平台",
    "鞋",
    "店",
    "馆",
    "牌",
)
_NAME_STANDALONE_NEGATIVE_SUFFIXES = (
    "录",
    "册",
    "表",
)
_NAME_STANDALONE_NEGATIVE_SUFFIXES_EN = (
    "app",
    "bot",
    "group",
    "menu",
    "page",
    "room",
    "tab",
)
_GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS = (
    "大学",
    "学院",
    "医院",
    "银行",
    "公司",
    "集团",
    "科技",
    "软件",
    "信息",
    "药房",
    "药店",
    "超市",
    "门店",
    "bank",
    "college",
    "company",
    "hospital",
    "institute",
    "school",
    "university",
)
_ORGANIZATION_BLACKLIST = {
    "机构",
    "组织",
    "单位",
    "公司",
    "企业",
    "学校",
    "医院",
    "银行",
    "部门",
    "团队",
    "平台",
    "集团",
    "研究院",
    "研究所",
    "事务所",
    "委员会",
    "科技",
    "company",
    "corporation",
    "group",
    "hospital",
    "institute",
    "organization",
    "school",
    "team",
    "university",
}
_ORGANIZATION_SENTENCE_NOISE_TOKENS = {
    "这个",
    "那个",
    "方案",
    "系统",
    "功能",
    "产品",
    "平台",
    "服务",
    "很",
    "太",
    "真",
    "非常",
    "比较",
    "feature",
    "platform",
    "product",
    "service",
    "system",
}
_REGION_TOKENS = set(_BUILTIN_GEO_LEXICON.provinces)
_EN_ADDRESS_STREET_SUFFIXES = (
    "street",
    "st",
    "road",
    "rd",
    "avenue",
    "ave",
    "boulevard",
    "blvd",
    "drive",
    "dr",
    "lane",
    "ln",
    "court",
    "ct",
    "place",
    "pl",
    "parkway",
    "pkwy",
    "terrace",
    "ter",
    "circle",
    "cir",
    "way",
    "highway",
    "hwy",
)
_EN_ADDRESS_UNIT_TOKENS = (
    "apartment",
    "apt",
    "suite",
    "ste",
    "unit",
    "floor",
    "fl",
    "room",
    "rm",
)
_EN_ADDRESS_SUFFIX_PATTERN = re.compile(
    rf"\b(?:{'|'.join(map(re.escape, _EN_ADDRESS_STREET_SUFFIXES))})\.?\b",
    re.IGNORECASE,
)
_EN_ADDRESS_UNIT_PATTERN = re.compile(
    rf"(?:\b(?:{'|'.join(map(re.escape, _EN_ADDRESS_UNIT_TOKENS))})\.?\b|\#)\s*[A-Za-z0-9\-]+",
    re.IGNORECASE,
)
_EN_ADDRESS_NUMBER_PATTERN = re.compile(
    r"\b\d{1,6}(?:-\d{1,6})?\b",
    re.IGNORECASE,
)
_EN_PO_BOX_PATTERN = re.compile(
    r"\bP\.?\s*O\.?\s*Box\s+\d{1,10}\b",
    re.IGNORECASE,
)
_EN_STATE_OR_REGION_PATTERN = re.compile(
    r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY)\b",
    re.IGNORECASE,
)
_EN_POSTAL_CODE_PATTERN = re.compile(
    r"\b\d{5}(?:-\d{4})?\b",
    re.IGNORECASE,
)
_EN_ADDRESS_SPAN_PATTERNS = (
    re.compile(
        rf"\b\d{{1,6}}(?:-\d{{1,6}})?\s+[A-Za-z0-9][A-Za-z0-9.'\- ]{{1,48}}?\s+"
        rf"(?:{'|'.join(map(re.escape, _EN_ADDRESS_STREET_SUFFIXES))})\.?"
        rf"(?:\s*,?\s*(?:{'|'.join(map(re.escape, _EN_ADDRESS_UNIT_TOKENS))}|#)\.?\s*[A-Za-z0-9\-]+)?"
        rf"(?:\s*,?\s*[A-Za-z .'\-]{{2,32}})?"
        rf"(?:\s*,?\s*(?:[A-Z]{{2}}|\d{{5}}(?:-\d{{4}})?))?",
        re.IGNORECASE,
    ),
    _EN_PO_BOX_PATTERN,
)
_ADDRESS_SUFFIX_PATTERN = re.compile(
    r"(?:特别行政区|自治区|自治州|盟|省|市|区|县|旗|乡|镇|街道|村|屯|组|路|街|巷|弄|胡同|大道|道|"
    r"社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|城|里|园区|校区|宿舍|号院|号楼|栋|幢|座|单元|室|层|号)"
)
_ADDRESS_NUMBER_PATTERN = re.compile(r"(?:\d{1,5}|[A-Za-z]\d{1,5})(?:号院|号楼|栋|幢|座|单元|室|层|号|户)")
_STANDALONE_ADDRESS_FRAGMENT_PATTERN = re.compile(
    rf"^[A-Za-z0-9#\-－—一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{1,24}}(?:区|县|旗|乡|镇|街道|村|路|街|巷|弄|胡同|大道|道|"
    r"社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍|号院|号楼|栋|幢|座|单元|室|层|号)$"
)
_SHORT_ADDRESS_TOKEN_PATTERN = re.compile(
    r"^[一-龥]{2,12}(?:区|县|旗|乡|镇|街道|村|路|街|巷|弄|胡同|大道|道|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾)$"
)
_ADDRESS_SPAN_PATTERNS = (
    re.compile(
        r"(?:北京|上海|天津|重庆|香港|澳门|内蒙古|广西|西藏|宁夏|新疆|"
        r"[一-龥]{2,7}省|[一-龥]{2,7}市|[一-龥]{2,7}区|[一-龥]{2,7}县)"
        rf"[A-Za-z0-9#\-－—一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{0,24}}"
    ),
    re.compile(
        rf"[A-Za-z0-9#\-－—一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{2,24}}"
        r"(?:路|街|巷|弄|胡同|大道|道|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍)"
        rf"[A-Za-z0-9#\-－—一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{0,16}}"
    ),
    re.compile(r"(?:\d{1,5}|[A-Za-z]\d{1,5})(?:号院|号楼|栋|幢|座|单元|室|层|号|户)(?:\d{0,4}(?:室|层|户))?"),
)
_GENERIC_GEO_FRAGMENT_PATTERNS = (
    re.compile(r"[一-龥]{2,12}(?:省|市|州|盟)"),
    re.compile(r"[一-龥]{2,12}(?:区|县|旗|乡|镇|街道)"),
    re.compile(r"[一-龥]{2,18}(?:路|街|巷|弄|胡同|大道|道)"),
    re.compile(r"[一-龥]{2,18}(?:地铁站|火车站|高铁站|机场|码头|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍|公园|景区|商圈|站)"),
)
_GENERIC_NUMBER_PATTERN = re.compile(r"(?<!\d)(?:\d(?:[\s\-－—_.,，。·•]?\d){3,})(?!\d)")
_LEADING_ADDRESS_NOISE_PATTERN = re.compile(
    r"^(?:请)?(?:在|住在|我住在|我住|位于|位于中国|地址在|住址在|家住|家住在|现住|居住于|收货到|寄往|寄到|送到|派送至|发往|前往|来自|来自于|发自|到达)\s*"
)
_LEADING_ADDRESS_NOISE_PATTERN_EN = re.compile(
    r"^(?:address|addr|location|located at|live at|lives at|resides at|ship to|send to|deliver to|from)\s*(?:[:=,-]|is|at)?\s*",
    re.IGNORECASE,
)
_ORGANIZATION_STRONG_SUFFIXES = (
    "有限责任公司",
    "股份有限公司",
    "有限公司",
    "集团",
    "银行",
    "医院",
    "大学",
    "学院",
    "中学",
    "小学",
    "幼儿园",
    "法院",
    "检察院",
    "事务所",
    "研究院",
    "研究所",
    "实验室",
    "基金会",
    "协会",
    "委员会",
    "派出所",
    "公安局",
    "分局",
    "工作室",
    "公司",
)
_EN_ORGANIZATION_STRONG_SUFFIXES = (
    "inc",
    "inc.",
    "corp",
    "corp.",
    "corporation",
    "company",
    "co.",
    "llc",
    "ltd",
    "ltd.",
    "bank",
    "hospital",
    "university",
    "college",
    "school",
    "institute",
    "foundation",
    "association",
    "laboratory",
    "lab",
    "clinic",
    "group",
)
_EN_ORGANIZATION_WEAK_SUFFIXES = (
    "analytics",
    "consulting",
    "design",
    "digital",
    "media",
    "network",
    "software",
    "studio",
    "systems",
    "technology",
    "tech",
)
_ORGANIZATION_WEAK_SUFFIXES = (
    "科技",
    "信息",
    "网络",
    "软件",
    "电子",
    "传媒",
    "咨询",
    "设计",
    "贸易",
)
_ORGANIZATION_SUFFIX_PATTERN = re.compile(
    rf"(?:{'|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})$"
)
_ORGANIZATION_STRONG_SUFFIX_PATTERN = re.compile(
    rf"(?:{'|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES))})$"
)
_ORGANIZATION_WEAK_SUFFIX_PATTERN = re.compile(
    rf"(?:{'|'.join(map(re.escape, _ORGANIZATION_WEAK_SUFFIXES))})$"
)
_ORGANIZATION_SPAN_PATTERNS = (
    re.compile(
        rf"[A-Za-z0-9&()（）·\s一-龥]{{2,48}}"
        rf"(?:{'|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})"
    ),
)
_EN_ORGANIZATION_SPAN_PATTERNS = (
    re.compile(
        rf"\b[A-Za-z][A-Za-z0-9&().,'\- ]{{1,64}}?\s+"
        rf"(?:{'|'.join(map(re.escape, _EN_ORGANIZATION_STRONG_SUFFIXES + _EN_ORGANIZATION_WEAK_SUFFIXES))})\b",
        re.IGNORECASE,
    ),
)
_LEADING_ORGANIZATION_NOISE_PATTERN = re.compile(
    r"^(?:(?:我|你|他|她|其|本人|我们|他们|她们)\s*)?"
    r"(?:在|于|来自|来自于|就职于|任职于|供职于|实习于|毕业于|就读于|所在|所在的|当前在|目前在|曾在|曾就职于|曾任职于)\s*"
)
_LEADING_ORGANIZATION_NOISE_PATTERN_EN = re.compile(
    r"^(?:(?:i|we|they|he|she)\s+)?(?:work(?:s|ed)?\s+at|study(?:s|ied)?\s+at|from|joined|joining|employed by|currently at|previously at)\s+",
    re.IGNORECASE,
)
_ORGANIZATION_FIELD_PREFIX_PATTERN = re.compile(
    r"^(?:机构|组织|单位|公司|企业|工作单位|所在单位|任职单位|就职公司|学校|医院|银行|毕业院校|就读学校)\s*(?:[:：=]|是|为)?\s*"
)
_ORGANIZATION_FIELD_PREFIX_PATTERN_EN = re.compile(
    r"^(?:organization|organisation|org|company|employer|institution|school|college|university|hospital|bank)\s*(?:[:：=]|is|was|at)?\s*",
    re.IGNORECASE,
)
_FIELD_LABEL_CONNECTOR_PATTERN = re.compile(r"^\s*(?:[:：=]|是|为|is|was|at)", re.IGNORECASE)


@dataclass(slots=True)
class _DictionaryMatch:
    matched_text: str
    span_start: int
    span_end: int
    source_term: str
    binding_key: str
    canonical_source_text: str | None = None
    local_entity_ids: tuple[str, ...] = ()
    matched_by: str = "dictionary_local"
    confidence: float = 0.95
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _LocalDictionaryEntry:
    value: str
    source_term: str
    binding_key: str
    canonical_source_text: str | None = None
    aliases: tuple[str, ...] = ()
    local_entity_ids: tuple[str, ...] = ()
    matched_by: str = "dictionary_local"
    confidence: float = 0.95
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _RuleStrengthProfile:
    level: ProtectionLevel
    enable_self_name_patterns: bool
    enable_honorific_name_pattern: bool
    enable_full_text_address: bool
    address_min_confidence: float
    allow_weak_org_suffix: bool
    enable_context_masked_text: bool
    enable_standalone_masked_text: bool
    masked_text_min_run: int
    allow_alpha_mask_text: bool
    min_confidence_by_attr: dict[PIIAttributeType, float]


@dataclass(frozen=True, slots=True)
class _OCRPageDocument:
    line_index: int
    blocks: tuple[OCRTextBlock, ...]
    text: str
    char_refs: tuple[tuple[int, int] | None, ...]


@dataclass(frozen=True, slots=True)
class _OCRSceneIndex:
    lines: tuple[tuple[int, ...], ...]
    position_by_block_index: dict[int, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class _CompiledDictionaryIndex:
    by_first_char: dict[str, dict[int, dict[str, tuple[_LocalDictionaryEntry, ...]]]]
    lengths_by_first_char: dict[str, tuple[int, ...]]


@dataclass(frozen=True, slots=True)
class _ShadowTextDocument:
    text: str
    index_map: tuple[int | None, ...]


_RULE_PROFILES = {
    ProtectionLevel.STRONG: _RuleStrengthProfile(
        level=ProtectionLevel.STRONG,
        enable_self_name_patterns=True,
        enable_honorific_name_pattern=True,
        enable_full_text_address=True,
        address_min_confidence=0.35,
        allow_weak_org_suffix=False,
        enable_context_masked_text=True,
        enable_standalone_masked_text=False,
        masked_text_min_run=3,
        allow_alpha_mask_text=True,
        min_confidence_by_attr={
            PIIAttributeType.NAME: 0.72,
            PIIAttributeType.LOCATION_CLUE: 0.48,
            PIIAttributeType.ADDRESS: 0.35,
            PIIAttributeType.ORGANIZATION: 0.48,
            PIIAttributeType.TIME: 0.76,
            PIIAttributeType.NUMERIC: 0.76,
            PIIAttributeType.TEXTUAL: 0.76,
            PIIAttributeType.OTHER: 0.76,
            PIIAttributeType.PHONE: 0.74,
            PIIAttributeType.CARD_NUMBER: 0.74,
            PIIAttributeType.BANK_ACCOUNT: 0.74,
            PIIAttributeType.PASSPORT_NUMBER: 0.74,
            PIIAttributeType.DRIVER_LICENSE: 0.74,
            PIIAttributeType.EMAIL: 0.74,
            PIIAttributeType.ID_NUMBER: 0.74,
        },
    ),
    ProtectionLevel.BALANCED: _RuleStrengthProfile(
        level=ProtectionLevel.BALANCED,
        enable_self_name_patterns=True,
        enable_honorific_name_pattern=True,
        enable_full_text_address=True,
        address_min_confidence=0.45,
        allow_weak_org_suffix=False,
        enable_context_masked_text=True,
        enable_standalone_masked_text=False,
        masked_text_min_run=4,
        allow_alpha_mask_text=False,
        min_confidence_by_attr={
            PIIAttributeType.NAME: 0.72,
            PIIAttributeType.LOCATION_CLUE: 0.52,
            PIIAttributeType.ADDRESS: 0.45,
            PIIAttributeType.ORGANIZATION: 0.48,
            PIIAttributeType.TIME: 0.76,
            PIIAttributeType.NUMERIC: 0.76,
            PIIAttributeType.TEXTUAL: 0.76,
            PIIAttributeType.OTHER: 0.76,
            PIIAttributeType.PHONE: 0.74,
            PIIAttributeType.CARD_NUMBER: 0.74,
            PIIAttributeType.BANK_ACCOUNT: 0.74,
            PIIAttributeType.PASSPORT_NUMBER: 0.74,
            PIIAttributeType.DRIVER_LICENSE: 0.74,
            PIIAttributeType.EMAIL: 0.74,
            PIIAttributeType.ID_NUMBER: 0.74,
        },
    ),
    ProtectionLevel.WEAK: _RuleStrengthProfile(
        level=ProtectionLevel.WEAK,
        enable_self_name_patterns=False,
        enable_honorific_name_pattern=False,
        enable_full_text_address=False,
        address_min_confidence=0.6,
        allow_weak_org_suffix=False,
        enable_context_masked_text=False,
        enable_standalone_masked_text=False,
        masked_text_min_run=99,
        allow_alpha_mask_text=False,
        min_confidence_by_attr={
            PIIAttributeType.NAME: 0.9,
            PIIAttributeType.LOCATION_CLUE: 0.9,
            PIIAttributeType.ADDRESS: 0.6,
            PIIAttributeType.ORGANIZATION: 0.74,
            PIIAttributeType.TIME: 0.9,
            PIIAttributeType.NUMERIC: 0.9,
            PIIAttributeType.TEXTUAL: 0.9,
            PIIAttributeType.OTHER: 0.9,
            PIIAttributeType.PHONE: 0.74,
            PIIAttributeType.CARD_NUMBER: 0.74,
            PIIAttributeType.BANK_ACCOUNT: 0.74,
            PIIAttributeType.PASSPORT_NUMBER: 0.74,
            PIIAttributeType.DRIVER_LICENSE: 0.74,
            PIIAttributeType.EMAIL: 0.74,
            PIIAttributeType.ID_NUMBER: 0.74,
        },
    ),
}

_TUNABLE_RULE_ATTR_TYPES = {
    PIIAttributeType.NAME,
    PIIAttributeType.LOCATION_CLUE,
    PIIAttributeType.ADDRESS,
    PIIAttributeType.ORGANIZATION,
    PIIAttributeType.OTHER,
}

_HIGH_PRECISION_NUMERIC_ATTR_TYPES = {
    PIIAttributeType.CARD_NUMBER,
    PIIAttributeType.BANK_ACCOUNT,
    PIIAttributeType.PASSPORT_NUMBER,
    PIIAttributeType.DRIVER_LICENSE,
    PIIAttributeType.ID_NUMBER,
}

__all__ = [name for name in globals() if not name.startswith("__")]
