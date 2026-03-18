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
from privacyguard.utils.pii_value import (
    build_match_text,
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
_NAME_FIELD_KEYWORDS = (
    "name",
    "username",
    "realname",
    "姓名",
    "名字",
    "昵称",
    "称呼",
    "联系人",
    "收件人",
    "寄件人",
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
_ADDRESS_FIELD_KEYWORDS = (
    "address",
    "addr",
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
    "mobile",
    "tel",
    "联系电话",
    "联系电话码",
    "联系号码",
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
    "mail",
    "邮箱",
    "电子邮箱",
    "联系邮箱",
)
_ID_FIELD_KEYWORDS = (
    "id",
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
_NAME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000·•・")
_NAME_DICTIONARY_ALLOWED_NEXT_CHARS = (
    set("的了呢吗吧啊呀哦哈呗嘛是在于与和及并或给让把将向从到回处办找发传交送问说看来去要想会能可应需请先再就已未还都也被把按")
    | {item[0] for item in _NAME_HONORIFICS if item}
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
}
_REGION_TOKENS = {
    "北京",
    "北京市",
    "上海",
    "上海市",
    "天津",
    "天津市",
    "重庆",
    "重庆市",
    "香港",
    "香港特别行政区",
    "澳门",
    "澳门特别行政区",
    "台湾",
    "安徽",
    "安徽省",
    "福建",
    "福建省",
    "甘肃",
    "甘肃省",
    "广东",
    "广东省",
    "广西",
    "广西壮族自治区",
    "贵州",
    "贵州省",
    "海南",
    "海南省",
    "河北",
    "河北省",
    "河南",
    "河南省",
    "黑龙江",
    "黑龙江省",
    "湖北",
    "湖北省",
    "湖南",
    "湖南省",
    "吉林",
    "吉林省",
    "江苏",
    "江苏省",
    "江西",
    "江西省",
    "辽宁",
    "辽宁省",
    "内蒙古",
    "内蒙古自治区",
    "宁夏",
    "宁夏回族自治区",
    "青海",
    "青海省",
    "山东",
    "山东省",
    "山西",
    "山西省",
    "陕西",
    "陕西省",
    "四川",
    "四川省",
    "西藏",
    "西藏自治区",
    "新疆",
    "新疆维吾尔自治区",
    "云南",
    "云南省",
    "浙江",
    "浙江省",
}
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
_LEADING_ADDRESS_NOISE_PATTERN = re.compile(
    r"^(?:请)?(?:在|住在|我住在|我住|位于|位于中国|地址在|住址在|家住|家住在|现住|居住于|收货到|寄往|寄到|送到|派送至|发往|前往|来自|来自于|发自|到达)\s*"
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
_LEADING_ORGANIZATION_NOISE_PATTERN = re.compile(
    r"^(?:(?:我|你|他|她|其|本人|我们|他们|她们)\s*)?"
    r"(?:在|于|来自|来自于|就职于|任职于|供职于|实习于|毕业于|就读于|所在|所在的|当前在|目前在|曾在|曾就职于|曾任职于)\s*"
)
_ORGANIZATION_FIELD_PREFIX_PATTERN = re.compile(
    r"^(?:机构|组织|单位|公司|企业|工作单位|所在单位|任职单位|就职公司|学校|医院|银行|毕业院校|就读学校)\s*(?:[:：=]|是|为)?\s*"
)
_FIELD_LABEL_CONNECTOR_PATTERN = re.compile(r"^\s*(?:[:：=]|是|为)")


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
        allow_weak_org_suffix=True,
        enable_context_masked_text=True,
        enable_standalone_masked_text=False,
        masked_text_min_run=3,
        allow_alpha_mask_text=True,
        min_confidence_by_attr={
            PIIAttributeType.NAME: 0.72,
            PIIAttributeType.ADDRESS: 0.35,
            PIIAttributeType.ORGANIZATION: 0.48,
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
        allow_weak_org_suffix=True,
        enable_context_masked_text=True,
        enable_standalone_masked_text=False,
        masked_text_min_run=4,
        allow_alpha_mask_text=False,
        min_confidence_by_attr={
            PIIAttributeType.NAME: 0.72,
            PIIAttributeType.ADDRESS: 0.45,
            PIIAttributeType.ORGANIZATION: 0.48,
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
            PIIAttributeType.ADDRESS: 0.6,
            PIIAttributeType.ORGANIZATION: 0.86,
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


class RuleBasedPIIDetector:
    """同时处理 prompt 与 OCR 文本的规则检测器。"""

    def __init__(
        self,
        dictionary_path: str | Path | None = None,
        detector_mode: str = "rule_based",
        mapping_store: MappingStore | None = None,
        min_confidence_by_attr: dict[PIIAttributeType | str, float] | None = None,
    ) -> None:
        """初始化规则、词典与候选解析服务。"""
        self.detector_mode = detector_mode
        self.dictionary_path = self._resolve_dictionary_path(dictionary_path)
        self.dictionary = self._load_dictionary(self.dictionary_path)
        self.dictionary_index = self._build_dictionary_index(self.dictionary)
        self.mapping_store = mapping_store
        self.min_confidence_by_attr = self._normalize_confidence_overrides(min_confidence_by_attr)
        self.resolver = CandidateResolverService()
        self.patterns = self._build_patterns()
        self.context_rules = self._build_context_rules()
        self.self_name_patterns = self._build_self_name_patterns()
        self.masked_text_pattern = self._build_masked_text_pattern()
        self.field_label_pattern = self._build_field_label_pattern()
        self.trailing_field_label_pattern = self._build_trailing_field_label_pattern()
        compound_surname_pattern = "|".join(
            sorted((re.escape(item) for item in _COMMON_COMPOUND_SURNAMES), key=len, reverse=True)
        )
        single_surname_pattern = f"[{''.join(sorted(_COMMON_SINGLE_CHAR_SURNAMES))}]"
        self.name_title_pattern = re.compile(
            rf"(?P<value>(?:(?:{compound_surname_pattern})[一-龥·]{{1,3}}|(?:{single_surname_pattern})[一-龥·]{{0,2}})"
            rf"(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))}))"
        )

    def detect(
        self,
        prompt_text: str,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_id: str | None = None,
        turn_id: int | None = None,
        protection_level: ProtectionLevel | str = ProtectionLevel.BALANCED,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> list[PIICandidate]:
        """对 prompt 与 OCR 两路输入执行候选识别。"""
        session_entries = self._session_dictionary_entries(session_id=session_id, turn_id=turn_id)
        session_index = self._build_dictionary_index(session_entries)
        rule_profile = self._rule_profile(protection_level, detector_overrides=detector_overrides)
        candidates: list[PIICandidate] = []
        candidates.extend(
            self._scan_text(
                prompt_text,
                PIISourceType.PROMPT,
                bbox=None,
                block_id=None,
                session_index=session_index,
                local_index=self.dictionary_index,
                rule_profile=rule_profile,
            )
        )
        candidates.extend(
            self._scan_ocr_page(
                ocr_blocks,
                session_index=session_index,
                local_index=self.dictionary_index,
                rule_profile=rule_profile,
            )
        )
        return self.resolver.resolve_candidates(candidates)

    def _resolve_dictionary_path(self, dictionary_path: str | Path | None) -> Path | None:
        """解析词典路径；未提供时默认使用空词库。"""
        if dictionary_path is None:
            return None
        return Path(dictionary_path)

    def _load_dictionary(self, dictionary_path: Path | None) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
        """读取 JSON 字典并映射到属性类型。

        支持两种格式：
        1. 旧格式：{"name": ["张三"], "address": ["北京市海淀区XX路"]}
        2. 实体格式：
           {
             "entities": [
               {
                 "entity_id": "friend_1",
                 "name": ["张三"],
                 "address": [{"value": "广东广州天河体育西102", "aliases": ["体育西路"]}]
               }
             ]
           }
        """
        if dictionary_path is None:
            return {}
        if not dictionary_path.exists():
            LOGGER.warning("rule_based dictionary not found; falling back to rules only: %s", dictionary_path)
            return {}
        content = json.loads(dictionary_path.read_text(encoding="utf-8"))
        mapped: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {}
        for raw_key, values in content.items():
            if raw_key == "entities":
                continue
            attr_type = self._to_attr_type(raw_key)
            if attr_type is None:
                continue
            self._append_dictionary_values(
                mapped=mapped,
                attr_type=attr_type,
                values=values,
                entity_id=None,
            )
        for raw_entity in content.get("entities", []):
            if not isinstance(raw_entity, dict):
                continue
            entity_id = str(raw_entity.get("entity_id") or raw_entity.get("id") or "").strip() or None
            aliases_by_attr = raw_entity.get("aliases", {}) if isinstance(raw_entity.get("aliases", {}), dict) else {}
            for raw_key, values in raw_entity.items():
                if raw_key in {"entity_id", "id", "aliases", "label", "name_aliases"}:
                    continue
                attr_type = self._to_attr_type(raw_key)
                if attr_type is None:
                    continue
                self._append_dictionary_values(
                    mapped=mapped,
                    attr_type=attr_type,
                    values=values,
                    entity_id=entity_id,
                    default_aliases=aliases_by_attr.get(raw_key),
                )
        return mapped

    def _append_dictionary_values(
        self,
        mapped: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        attr_type: PIIAttributeType,
        values,
        entity_id: str | None,
        default_aliases=None,
    ) -> None:
        """向词典映射追加兼容旧格式与实体格式的词条。"""
        if isinstance(values, (str, int, float)):
            entries = [values]
        elif isinstance(values, list):
            entries = values
        else:
            return
        for item in entries:
            value, aliases = self._parse_dictionary_item(item, default_aliases=default_aliases)
            if not value:
                continue
            source_term = canonicalize_pii_value(attr_type, value)
            binding_key = f"entity:{entity_id}" if entity_id else f"value:{source_term}"
            local_entity_ids = (entity_id,) if entity_id else ()
            mapped.setdefault(attr_type, []).append(
                _LocalDictionaryEntry(
                    value=value,
                    source_term=source_term,
                    canonical_source_text=self._canonical_dictionary_source_text(attr_type, value),
                    binding_key=binding_key,
                    aliases=aliases,
                    local_entity_ids=local_entity_ids,
                    matched_by="dictionary_local",
                    confidence=0.99 if entity_id else 0.98,
                )
            )

    def _session_dictionary_entries(
        self,
        *,
        session_id: str | None,
        turn_id: int | None,
    ) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
        """把前序 turn 的 replacement source_text 转成会话级匹配词条。"""
        if self.mapping_store is None or not session_id:
            return {}
        records = self.mapping_store.get_replacements(session_id=session_id)
        if turn_id is not None:
            records = [record for record in records if record.turn_id < turn_id]
        aggregated: dict[tuple[PIIAttributeType, str], ReplacementRecord] = {}
        aliases_by_key: dict[tuple[PIIAttributeType, str], set[str]] = {}
        turn_index: dict[tuple[PIIAttributeType, str], set[str]] = {}
        for record in sorted(records, key=lambda item: (item.turn_id, len(item.source_text)), reverse=True):
            if not record.source_text:
                continue
            canonical_source_text = record.canonical_source_text or record.source_text
            canonical = canonicalize_pii_value(record.attr_type, canonical_source_text)
            if not canonical:
                continue
            key = (record.attr_type, canonical)
            aggregated.setdefault(key, record)
            aliases_by_key.setdefault(key, set()).add(record.source_text)
            turn_index.setdefault(key, set()).add(str(record.turn_id))
        session_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {}
        for (attr_type, canonical), record in aggregated.items():
            metadata = {"session_turn_ids": sorted(turn_index.get((attr_type, canonical), set()))}
            canonical_source_text = record.canonical_source_text or self._canonical_dictionary_source_text(
                attr_type,
                record.source_text,
            )
            value = canonical_source_text or record.source_text
            aliases = tuple(
                alias
                for alias in sorted(aliases_by_key.get((attr_type, canonical), set()))
                if alias and alias != value
            )
            session_entries.setdefault(attr_type, []).append(
                _LocalDictionaryEntry(
                    value=value,
                    source_term=canonical,
                    canonical_source_text=canonical_source_text,
                    binding_key=f"session:{attr_type.value}:{canonical}",
                    aliases=aliases,
                    matched_by="dictionary_session",
                    confidence=0.97,
                    metadata=metadata,
                )
            )
        return session_entries

    def _canonical_dictionary_source_text(self, attr_type: PIIAttributeType, value: str) -> str | None:
        if attr_type != PIIAttributeType.NAME:
            return None
        return self._canonical_name_source_text(value, allow_ocr_noise=True)

    def _rule_profile(
        self,
        protection_level: ProtectionLevel | str,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> _RuleStrengthProfile:
        """把入参保护度归一到内部规则强度配置。"""
        if isinstance(protection_level, ProtectionLevel):
            base_profile = _RULE_PROFILES[protection_level]
        else:
            normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
            try:
                base_profile = _RULE_PROFILES[ProtectionLevel(normalized)]
            except ValueError:
                base_profile = _RULE_PROFILES[ProtectionLevel.BALANCED]
        merged = dict(base_profile.min_confidence_by_attr)
        merged.update(self.min_confidence_by_attr)
        merged.update(self._normalize_confidence_overrides(detector_overrides))
        return replace(base_profile, min_confidence_by_attr=merged)

    def _normalize_confidence_overrides(
        self,
        overrides: dict[PIIAttributeType | str, float] | None,
    ) -> dict[PIIAttributeType, float]:
        if not overrides:
            return {}
        normalized: dict[PIIAttributeType, float] = {}
        for raw_key, raw_value in overrides.items():
            attr_type = self._to_attr_type(raw_key)
            if attr_type is None or attr_type not in _TUNABLE_RULE_ATTR_TYPES:
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue
            normalized[attr_type] = max(0.0, min(1.0, value))
        return normalized

    def _build_dictionary_index(
        self,
        entries_by_attr: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
    ) -> dict[PIIAttributeType, _CompiledDictionaryIndex]:
        """把词条预编译成首字符/长度索引，降低逐词条线性扫描开销。"""
        compiled: dict[PIIAttributeType, _CompiledDictionaryIndex] = {}
        for attr_type, entries in entries_by_attr.items():
            raw_index: dict[str, dict[int, dict[str, list[_LocalDictionaryEntry]]]] = {}
            for entry in entries:
                for variant in self._dictionary_entry_variants(attr_type, entry):
                    if not variant:
                        continue
                    by_length = raw_index.setdefault(variant[0], {})
                    by_variant = by_length.setdefault(len(variant), {})
                    by_variant.setdefault(variant, []).append(entry)
            if not raw_index:
                continue
            compiled[attr_type] = _CompiledDictionaryIndex(
                by_first_char={
                    first_char: {
                        length: {
                            variant: tuple(items)
                            for variant, items in variants.items()
                        }
                        for length, variants in by_length.items()
                    }
                    for first_char, by_length in raw_index.items()
                },
                lengths_by_first_char={
                    first_char: tuple(sorted(by_length.keys(), reverse=True))
                    for first_char, by_length in raw_index.items()
                },
            )
        return compiled

    def _parse_dictionary_item(self, item, default_aliases=None) -> tuple[str, tuple[str, ...]]:
        """把词库 JSON 中的一项解析成 (value, aliases)。"""
        aliases: list[str] = []
        if default_aliases is not None:
            aliases.extend(self._normalize_aliases(default_aliases))
        if isinstance(item, dict):
            raw_value = item.get("value") or item.get("text") or item.get("source")
            aliases.extend(self._normalize_aliases(item.get("aliases")))
        else:
            raw_value = item
        value = str(raw_value).strip() if raw_value is not None else ""
        unique_aliases = tuple(dict.fromkeys(alias for alias in aliases if alias and alias != value))
        return value, unique_aliases

    def _normalize_aliases(self, raw_aliases) -> list[str]:
        if raw_aliases is None:
            return []
        if isinstance(raw_aliases, (str, int, float)):
            values = [raw_aliases]
        elif isinstance(raw_aliases, list):
            values = raw_aliases
        else:
            return []
        return [str(item).strip() for item in values if str(item).strip()]

    def _build_patterns(self) -> dict[PIIAttributeType, list[tuple[re.Pattern[str], str, float]]]:
        """构建正则规则集合。"""
        return {
            PIIAttributeType.PHONE: [
                (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "regex_phone_mobile", 0.86),
                (
                    re.compile(r"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•()（）]?\d{4}){2}(?!\d)"),
                    "regex_phone_mobile_sep",
                    0.84,
                ),
                (
                    re.compile(r"(?<!\d)0\d{2,3}(?:[\s\-－—_.,，。·•]?\d){7,8}(?!\d)"),
                    "regex_phone_landline",
                    0.78,
                ),
                (
                    re.compile(rf"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•]?{_MASK_CHAR_CLASS_WITH_X}{{4}})(?:[\s\-－—_.,，。·•]?\d{{4}})(?!\d)"),
                    "regex_phone_masked",
                    0.82,
                ),
                (
                    re.compile(rf"(?<!\d)1[3-9]\d(?:[\s\-－—_.,，。·•]?{_MASK_CHAR_CLASS_WITH_X}){{8}}(?!\d)"),
                    "regex_phone_masked_prefix_only",
                    0.8,
                ),
            ],
            PIIAttributeType.CARD_NUMBER: [
                (
                    re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){13,19}(?![A-Za-z0-9])"),
                    "regex_card_number",
                    0.83,
                ),
                (
                    re.compile(rf"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){{4}}(?:{_MASK_CHAR_CLASS_WITH_X}[\s\-－—_.,，。·•]?){{5,15}}(?:\d[\s\-－—_.,，。·•]?){{0,4}}(?![A-Za-z0-9])"),
                    "regex_card_number_masked",
                    0.81,
                ),
            ],
            PIIAttributeType.BANK_ACCOUNT: [
                (
                    re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){10,30}(?![A-Za-z0-9])"),
                    "regex_bank_account_number",
                    0.78,
                ),
                (
                    re.compile(rf"(?<![A-Za-z0-9])(?:\d[\s\-－—_.,，。·•]?){{4,8}}(?:{_MASK_CHAR_CLASS_WITH_X}[\s\-－—_.,，。·•]?){{4,26}}(?:\d[\s\-－—_.,，。·•]?){{0,6}}(?![A-Za-z0-9])"),
                    "regex_bank_account_masked",
                    0.76,
                ),
            ],
            PIIAttributeType.PASSPORT_NUMBER: [
                (
                    re.compile(r"(?<![A-Z0-9])[A-Z][\s\-－—_.,，。·•]?\d(?:[\s\-－—_.,，。·•]?\d){7,8}(?![A-Z0-9])", re.IGNORECASE),
                    "regex_passport_number",
                    0.8,
                ),
                (
                    re.compile(
                        rf"(?<![A-Z0-9])(?:[A-Z0-9][\s\-－—_.,，。·•]?){{1,2}}(?:{_MASK_CHAR_CLASS_COMMON}[\s\-－—_.,，。·•]?){{3,12}}"
                        rf"(?:[A-Z0-9][\s\-－—_.,，。·•]?){{0,4}}(?![A-Z0-9])",
                        re.IGNORECASE,
                    ),
                    "regex_passport_number_masked",
                    0.76,
                ),
            ],
            PIIAttributeType.DRIVER_LICENSE: [
                (
                    re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])"),
                    "regex_driver_license_12",
                    0.74,
                ),
                (
                    re.compile(r"(?<![A-Za-z0-9])\d{15}(?![A-Za-z0-9])"),
                    "regex_driver_license_15",
                    0.76,
                ),
                (
                    re.compile(r"(?<![A-Z0-9])[A-Z]{1,3}(?:[\s\-－—_.,，。·•]?\d){7,17}(?![A-Z0-9])", re.IGNORECASE),
                    "regex_driver_license_alnum",
                    0.76,
                ),
                (
                    re.compile(rf"(?<![A-Z0-9])(?:[A-Z0-9][\s\-－—_.,，。·•]?){{2,8}}(?:{_MASK_CHAR_CLASS_COMMON}[\s\-－—_.,，。·•]?){{4,16}}(?:[A-Z0-9][\s\-－—_.,，。·•]?){{0,4}}(?![A-Z0-9])", re.IGNORECASE),
                    "regex_driver_license_masked",
                    0.74,
                ),
            ],
            PIIAttributeType.EMAIL: [
                (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "regex_email", 0.85),
                (
                    re.compile(r"[A-Za-z0-9._%+\-]+\s*@\s*[A-Za-z0-9.\-]+\s*\.\s*[A-Za-z]{2,}"),
                    "regex_email_spaced",
                    0.82,
                ),
                (
                    re.compile(r"[A-Za-z0-9._%+\-]+\s*[@＠]\s*[A-Za-z0-9.\-]+\s*[.,，。．、·•]\s*[A-Za-z]{2,}"),
                    "regex_email_ocr_noise",
                    0.81,
                ),
                (
                    re.compile(rf"[A-Za-z0-9._%+\-*＊{_MASK_CHAR_CLASS_COMMON[1:-1]}]+\s*[@＠]\s*[A-Za-z0-9.\-*＊{_MASK_CHAR_CLASS_COMMON[1:-1]}]+\s*(?:\.|[，。．、·•])\s*[A-Za-z*＊]{{2,}}"),
                    "regex_email_masked",
                    0.79,
                ),
            ],
            PIIAttributeType.ID_NUMBER: [
                (
                    re.compile(r"(?<![A-Za-z0-9])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![A-Za-z0-9])"),
                    "regex_cn_id_18",
                    0.92,
                ),
                (
                    re.compile(
                        r"(?<![A-Za-z0-9])[1-9]\d{5}(?:[\s\-－—_.,，。·•]?(?:18|19|20)\d{2})(?:[\s\-－—_.,，。·•]?(?:0[1-9]|1[0-2]))"
                        r"(?:[\s\-－—_.,，。·•]?(?:0[1-9]|[12]\d|3[01]))(?:[\s\-－—_.,，。·•]?\d{3})(?:[\s\-－—_.,，。·•]?[\dXx])(?![A-Za-z0-9])"
                    ),
                    "regex_cn_id_18_spaced",
                    0.9,
                ),
                (re.compile(r"(?<![A-Za-z0-9])[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?![A-Za-z0-9])"), "regex_cn_id_15", 0.82),
                (
                    re.compile(
                        r"(?<![A-Za-z0-9])[1-9]\d{7}(?:[\s\-－—_.,，。·•]?(?:0[1-9]|1[0-2]))(?:[\s\-－—_.,，。·•]?(?:0[1-9]|[12]\d|3[01]))"
                        r"(?:[\s\-－—_.,，。·•]?\d{3})(?![A-Za-z0-9])"
                    ),
                    "regex_cn_id_15_spaced",
                    0.8,
                ),
                (re.compile(rf"(?<![A-Za-z0-9])[1-9]\d{{5}}{_MASK_CHAR_CLASS_COMMON}{{8,10}}[\dXx]{{2,4}}(?![A-Za-z0-9])"), "regex_cn_id_masked", 0.86),
                (re.compile(rf"(?<![A-Za-z0-9])[1-9]\d{{5}}{_MASK_CHAR_CLASS_COMMON}{{9,12}}(?![A-Za-z0-9])"), "regex_cn_id_masked_prefix_only", 0.84),
            ],
        }

    def _build_context_rules(self) -> list[tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]]:
        """构建基于字段上下文的检测规则。"""
        return [
            self._build_context_rule(
                keywords=_NAME_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.NAME,
                value_pattern=rf"[A-Za-z][A-Za-z .'\-]{{1,40}}|[一-龥·\s0-9]{{2,12}}|[一-龥][*＊xX某]{{1,3}}|{_TEXT_MASK_CHAR_CLASS}{{2,12}}",
                confidence=0.90,
                matched_by="context_name_field",
                validator=self._is_name_candidate,
            ),
            self._build_context_rule(
                keywords=_ADDRESS_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ADDRESS,
                value_pattern=rf"[A-Za-z0-9#\-－—()（）·\s一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]{{2,80}}",
                confidence=0.90,
                matched_by="context_address_field",
                validator=self._looks_like_address_candidate,
            ),
            self._build_context_rule(
                keywords=_PHONE_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.PHONE,
                value_pattern=rf"[0-9*＊+＋\-－—_.,，。·•/\\()（）\s{_MASK_CHAR_CLASS_WITH_X[1:-1]}]{{7,32}}",
                confidence=0.88,
                matched_by="context_phone_field",
                validator=self._is_phone_candidate,
            ),
            self._build_context_rule(
                keywords=_CARD_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.CARD_NUMBER,
                value_pattern=rf"[0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{13,40}}",
                confidence=0.9,
                matched_by="context_card_field",
                validator=self._is_context_card_number_candidate,
            ),
            self._build_context_rule(
                keywords=_BANK_ACCOUNT_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.BANK_ACCOUNT,
                value_pattern=rf"[0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{8,40}}",
                confidence=0.9,
                matched_by="context_bank_account_field",
                validator=self._is_bank_account_candidate,
            ),
            self._build_context_rule(
                keywords=_PASSPORT_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.PASSPORT_NUMBER,
                value_pattern=rf"[A-Za-z0-9*＊xX\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{5,24}}",
                confidence=0.9,
                matched_by="context_passport_field",
                validator=self._is_passport_candidate,
            ),
            self._build_context_rule(
                keywords=_DRIVER_LICENSE_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.DRIVER_LICENSE,
                value_pattern=rf"[A-Za-z0-9Xx*＊\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{8,32}}",
                confidence=0.9,
                matched_by="context_driver_license_field",
                validator=self._is_driver_license_candidate,
            ),
            self._build_context_rule(
                keywords=_EMAIL_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.EMAIL,
                value_pattern=rf"[A-Za-z0-9._%+\-*＊@＠,，。．、·•\s{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{5,80}}",
                confidence=0.90,
                matched_by="context_email_field",
                validator=self._is_email_candidate,
            ),
            self._build_context_rule(
                keywords=_ID_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ID_NUMBER,
                value_pattern=rf"[0-9Xx*＊\s\-－—_.,，。·•/\\()（）{_MASK_CHAR_CLASS_COMMON[1:-1]}]{{6,40}}",
                confidence=0.90,
                matched_by="context_id_field",
                validator=self._is_id_candidate,
            ),
            self._build_context_rule(
                keywords=_OTHER_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.OTHER,
                value_pattern=r"[A-Za-z0-9\-\s－—_.,，。·•]{4,40}",
                confidence=0.76,
                matched_by="context_other_field",
                validator=self._is_other_candidate,
            ),
            self._build_context_rule(
                keywords=_ORGANIZATION_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ORGANIZATION,
                value_pattern=r"[A-Za-z0-9&()（）·\s一-龥]{2,80}",
                confidence=0.86,
                matched_by="context_organization_field",
                validator=self._is_organization_candidate,
            ),
        ]

    def _build_self_name_patterns(self) -> list[tuple[re.Pattern[str], str, float]]:
        """构建自我介绍与口语化姓名规则。"""
        return [
            (
                re.compile(rf"(?:我叫|名叫|叫做|我的名字是)\s*(?P<value>[一-龥·\s0-9]{{2,10}}|[一-龥][*＊xX某]{{1,3}}|{_TEXT_MASK_CHAR_CLASS}{{2,10}})"),
                "context_name_self_intro",
                0.78,
            ),
            (
                re.compile(r"(?:my\s+name\s+is)\s*(?P<value>[A-Za-z][A-Za-z .'\-]{1,40})", re.IGNORECASE),
                "context_name_self_intro_en",
                0.76,
            ),
        ]

    def _build_masked_text_pattern(self) -> re.Pattern[str]:
        """构建通用重复掩码字符检测模式。"""
        return re.compile(rf"(?P<value>(?P<char>{_TEXT_MASK_CHAR_CLASS})(?:\s*(?P=char)){{2,}})")

    def _build_context_rule(
        self,
        keywords: tuple[str, ...],
        attr_type: PIIAttributeType,
        value_pattern: str,
        confidence: float,
        matched_by: str,
        validator: Callable[[str], bool],
    ) -> tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]:
        """根据关键词动态构建上下文字段规则。"""
        keyword_pattern = "|".join(sorted((re.escape(item) for item in keywords), key=len, reverse=True))
        pattern = re.compile(
            rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?:{keyword_pattern})\s*(?:[:：=]|是|为)?\s*(?P<value>{value_pattern})",
            re.IGNORECASE,
        )
        return (attr_type, pattern, matched_by, confidence, validator)

    def _build_field_label_pattern(self) -> re.Pattern[str]:
        """构建用于识别字段标签边界的通用模式。"""
        keyword_pattern = "|".join(sorted((re.escape(item) for item in self._all_field_keywords()), key=len, reverse=True))
        return re.compile(
            rf"(?:^|[\s{{\[\(（【<「『\"',，;；])(?P<label>{keyword_pattern})\s*(?:[:：=]|是|为)",
            re.IGNORECASE,
        )

    def _build_trailing_field_label_pattern(self) -> re.Pattern[str]:
        """构建用于截断“值 + 下一个字段标签”串联的尾部模式。"""
        keyword_pattern = "|".join(sorted((re.escape(item) for item in self._all_field_keywords()), key=len, reverse=True))
        return re.compile(
            rf"(?P<body>.*?)(?:[\s,，;；/|]*)?(?P<label>{keyword_pattern})$",
            re.IGNORECASE,
        )

    def _all_field_keywords(self) -> tuple[str, ...]:
        """汇总所有字段标签关键词，供边界识别复用。"""
        return tuple(
            dict.fromkeys(
                (
                    *_NAME_FIELD_KEYWORDS,
                    *_ADDRESS_FIELD_KEYWORDS,
                    *_PHONE_FIELD_KEYWORDS,
                    *_CARD_FIELD_KEYWORDS,
                    *_BANK_ACCOUNT_FIELD_KEYWORDS,
                    *_PASSPORT_FIELD_KEYWORDS,
                    *_DRIVER_LICENSE_FIELD_KEYWORDS,
                    *_EMAIL_FIELD_KEYWORDS,
                    *_ID_FIELD_KEYWORDS,
                    *_OTHER_FIELD_KEYWORDS,
                    *_ORGANIZATION_FIELD_KEYWORDS,
                )
            )
        )

    def _scan_text(
        self,
        text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        session_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
        local_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
        rule_profile: _RuleStrengthProfile,
    ) -> list[PIICandidate]:
        """对单段文本执行分层识别。

        顺序按精度从高到低推进，并在组间刷新 protected spans：
        session -> local -> (context + regex) -> organization -> name -> address
        """
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
        self._collect_dictionary_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            dictionary_index=session_index,
        )
        protected_spans = self._protected_spans_from_dictionary_hits(collected, rule_profile=rule_profile)
        self._collect_dictionary_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            dictionary_index=local_index,
            skip_spans=protected_spans,
        )
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        self._collect_context_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
        )
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        self._collect_regex_hits(collected, text, source, bbox, block_id, skip_spans=protected_spans)
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        organization_shadow = self._build_shadow_text(text, collected)
        self._collect_organization_hits(
            collected,
            organization_shadow.text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
            original_text=text,
            shadow_index_map=organization_shadow.index_map,
        )
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        name_shadow = self._build_shadow_text(text, collected)
        self._collect_name_hits(
            collected,
            name_shadow.text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
            original_text=text,
            shadow_index_map=name_shadow.index_map,
        )
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        address_shadow = self._build_shadow_text(text, collected)
        self._collect_address_hits(
            collected,
            address_shadow.text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
            original_text=text,
            shadow_index_map=address_shadow.index_map,
        )
        protected_spans = self._protected_spans_from_candidates(collected, rule_profile=rule_profile)
        masked_shadow = self._build_shadow_text(text, collected)
        self._collect_masked_text_hits(
            collected,
            masked_shadow.text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
            original_text=text,
            shadow_index_map=masked_shadow.index_map,
        )
        return [
            candidate
            for candidate in collected.values()
            if self._meets_confidence_threshold(candidate.attr_type, candidate.confidence, rule_profile)
        ]

    def _scan_ocr_page(
        self,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
        local_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
        rule_profile: _RuleStrengthProfile,
    ) -> list[PIICandidate]:
        """将整页 OCR 聚合成单文档扫描，再映射回原始 block。"""
        remapped_candidates: list[PIICandidate] = []
        document = self._build_ocr_page_document(ocr_blocks)
        if document is None:
            return remapped_candidates
        document_candidates = self._scan_text(
            document.text,
            PIISourceType.OCR,
            bbox=None,
            block_id=None,
            session_index=session_index,
            local_index=local_index,
            rule_profile=rule_profile,
        )
        for candidate in document_candidates:
            remapped = self._remap_ocr_page_candidate(candidate, document)
            if remapped is not None:
                remapped_candidates.append(remapped)
            remapped_candidates.extend(self._derive_address_block_candidates(candidate, document))
        return remapped_candidates

    def _build_ocr_page_document(self, ocr_blocks: list[OCRTextBlock]) -> _OCRPageDocument | None:
        """把整页 OCR block 聚合成单个扫描文档，减少重复扫描成本。"""
        if not ocr_blocks:
            return None
        merged_chars: list[str] = []
        char_refs: list[tuple[int, int] | None] = []
        ordered_blocks: list[OCRTextBlock] = []
        lines = self._group_blocks_by_page_line(ocr_blocks)
        assigned_blocks = {id(block) for line in lines for block in line if block.text.strip()}
        line_count = 0
        for line_blocks in lines:
            visible_blocks = [block for block in line_blocks if block.text.strip()]
            if not visible_blocks:
                continue
            if line_count > 0:
                merged_chars.append("\n")
                char_refs.append(None)
            for block in visible_blocks:
                if ordered_blocks:
                    prev_block = ordered_blocks[-1]
                    if prev_block in visible_blocks:
                        separator = self._block_join_separator(prev_block, block)
                        if separator:
                            merged_chars.append(separator)
                            char_refs.append(None)
                block_index = len(ordered_blocks)
                ordered_blocks.append(block)
                for char_index, char in enumerate(block.text):
                    merged_chars.append(char)
                    char_refs.append((block_index, char_index))
            line_count += 1
        for block in ocr_blocks:
            if id(block) in assigned_blocks or not block.text.strip():
                continue
            if line_count > 0:
                merged_chars.append("\n")
                char_refs.append(None)
            block_index = len(ordered_blocks)
            ordered_blocks.append(block)
            for char_index, char in enumerate(block.text):
                merged_chars.append(char)
                char_refs.append((block_index, char_index))
            line_count += 1
        if not ordered_blocks:
            return None
        return _OCRPageDocument(
            line_index=0,
            blocks=tuple(ordered_blocks),
            text="".join(merged_chars),
            char_refs=tuple(char_refs),
        )

    def _group_blocks_by_page_line(self, ocr_blocks: list[OCRTextBlock]) -> list[list[OCRTextBlock]]:
        """按 bbox 的垂直重叠关系将 OCR block 近似聚成页面文本行。"""
        sortable = [block for block in ocr_blocks if block.bbox is not None and block.text.strip()]
        sortable.sort(key=lambda item: (self._bbox_center_y(item.bbox), item.bbox.x))
        lines: list[list[OCRTextBlock]] = []
        for block in sortable:
            assigned = False
            for line in lines:
                if self._belongs_to_same_page_line(line, block):
                    line.append(block)
                    line.sort(key=lambda item: item.bbox.x if item.bbox is not None else 0)
                    assigned = True
                    break
            if not assigned:
                lines.append([block])
        return lines

    def _belongs_to_same_page_line(self, line: list[OCRTextBlock], block: OCRTextBlock) -> bool:
        """判断一个 OCR block 是否应并入已有页面文本行。"""
        if block.bbox is None or not line:
            return False
        line_tops = [item.bbox.y for item in line if item.bbox is not None]
        line_bottoms = [item.bbox.y + item.bbox.height for item in line if item.bbox is not None]
        line_centers = [self._bbox_center_y(item.bbox) for item in line if item.bbox is not None]
        if not line_tops or not line_bottoms or not line_centers:
            return False
        line_top = min(line_tops)
        line_bottom = max(line_bottoms)
        overlap = min(line_bottom, block.bbox.y + block.bbox.height) - max(line_top, block.bbox.y)
        min_height = min(
            block.bbox.height,
            min((item.bbox.height for item in line if item.bbox is not None), default=block.bbox.height),
        )
        center_delta = abs(sum(line_centers) / len(line_centers) - self._bbox_center_y(block.bbox))
        return overlap >= max(1, int(min_height * 0.35)) or center_delta <= max(6.0, block.bbox.height * 0.6)

    def _block_join_separator(self, left: OCRTextBlock, right: OCRTextBlock) -> str:
        """决定两个相邻 OCR block 在拼接时是否需要补空格。"""
        if left.bbox is None or right.bbox is None:
            return ""
        left_char = left.text[-1:] if left.text else ""
        right_char = right.text[:1] if right.text else ""
        if not left_char or not right_char:
            return ""
        gap = right.bbox.x - (left.bbox.x + left.bbox.width)
        threshold = max(6, int(min(left.bbox.height, right.bbox.height) * 0.6))
        if gap <= threshold:
            return ""
        if left_char.isascii() and left_char.isalnum() and right_char.isascii() and right_char.isalnum():
            return " "
        return ""

    def _remap_ocr_page_candidate(
        self,
        candidate: PIICandidate,
        document: _OCRPageDocument,
    ) -> PIICandidate | None:
        """将页面扫描候选映射回单 block 或多 block 联合候选。"""
        if candidate.span_start is None or candidate.span_end is None:
            return None
        covered: dict[int, list[int]] = {}
        covered_block_ids: list[str] = []
        for ref in document.char_refs[candidate.span_start:candidate.span_end]:
            if ref is None:
                continue
            block_index, char_index = ref
            covered.setdefault(block_index, []).append(char_index)
            block_id = document.blocks[block_index].block_id
            if block_id and block_id not in covered_block_ids:
                covered_block_ids.append(block_id)
        if not covered:
            return None
        extra_metadata = {"ocr_block_ids": covered_block_ids}
        if len(document.blocks) > 1:
            extra_metadata["matched_by"] = ["ocr_page_span"]
        remapped_metadata = self._merge_candidate_metadata(candidate.metadata, extra_metadata)
        if len(covered) == 1:
            block_index, positions = next(iter(covered.items()))
            block = document.blocks[block_index]
            local_start = min(positions)
            local_end = max(positions) + 1
            local_text = block.text[local_start:local_end]
            normalized = canonicalize_pii_value(candidate.attr_type, local_text)
            entity_id = self.resolver.build_candidate_id(
                self.detector_mode,
                PIISourceType.OCR.value,
                normalized,
                candidate.attr_type.value,
                block_id=block.block_id,
                span_start=local_start,
                span_end=local_end,
            )
            return PIICandidate(
                entity_id=entity_id,
                text=local_text,
                normalized_text=normalized,
                attr_type=candidate.attr_type,
                source=PIISourceType.OCR,
                bbox=block.bbox,
                block_id=block.block_id,
                span_start=local_start,
                span_end=local_end,
                confidence=candidate.confidence,
                metadata=remapped_metadata,
            )
        covered_indices = set(covered)
        combined_bbox = self._combine_bboxes(
            block.bbox
            for index, block in enumerate(document.blocks)
            if index in covered_indices and block.bbox is not None
        )
        merge_block_id = "ocr-merge-" + "-".join(
            item.block_id or f"{document.line_index}-{index}"
            for index, item in enumerate(document.blocks)
            if index in covered
        )
        entity_id = self.resolver.build_candidate_id(
            self.detector_mode,
            PIISourceType.OCR.value,
            candidate.normalized_text,
            candidate.attr_type.value,
            block_id=merge_block_id,
            span_start=None,
            span_end=None,
        )
        return PIICandidate(
            entity_id=entity_id,
            text=candidate.text,
            normalized_text=candidate.normalized_text,
            attr_type=candidate.attr_type,
            source=PIISourceType.OCR,
            bbox=combined_bbox,
            block_id=merge_block_id,
            span_start=None,
            span_end=None,
            confidence=candidate.confidence,
            metadata=remapped_metadata,
        )

    def _combine_bboxes(self, boxes) -> BoundingBox | None:
        """将多个 bbox 合并成一个外接矩形。"""
        valid_boxes = [box for box in boxes if box is not None]
        if not valid_boxes:
            return None
        min_x = min(box.x for box in valid_boxes)
        min_y = min(box.y for box in valid_boxes)
        max_x = max(box.x + box.width for box in valid_boxes)
        max_y = max(box.y + box.height for box in valid_boxes)
        return BoundingBox(
            x=max(0, int(min_x)),
            y=max(0, int(min_y)),
            width=max(1, int(max_x - min_x)),
            height=max(1, int(max_y - min_y)),
        )

    def _bbox_center_y(self, bbox) -> float:
        return bbox.y + bbox.height / 2

    def _derive_address_block_candidates(
        self,
        candidate: PIICandidate,
        document: _OCRPageDocument,
    ) -> list[PIICandidate]:
        """对多 block 地址命中补充派生单 block 地址碎片，避免丢失原始块级信息。"""
        if candidate.attr_type != PIIAttributeType.ADDRESS:
            return []
        if candidate.span_start is None or candidate.span_end is None:
            return []
        if len(document.blocks) <= 1:
            return []
        covered_positions: dict[int, list[int]] = {}
        for ref in document.char_refs[candidate.span_start:candidate.span_end]:
            if ref is None:
                continue
            block_index, char_index = ref
            covered_positions.setdefault(block_index, []).append(char_index)
        if len(covered_positions) <= 1:
            return []
        fragments: list[PIICandidate] = []
        for block_index, positions in covered_positions.items():
            block = document.blocks[block_index]
            if not positions:
                continue
            local_start = min(positions)
            local_end = max(positions) + 1
            local_text = block.text[local_start:local_end]
            if not self._looks_like_address_candidate(local_text):
                continue
            normalized = canonicalize_pii_value(PIIAttributeType.ADDRESS, local_text)
            entity_id = self.resolver.build_candidate_id(
                self.detector_mode,
                PIISourceType.OCR.value,
                normalized,
                PIIAttributeType.ADDRESS.value,
                block_id=block.block_id,
                span_start=local_start,
                span_end=local_end,
            )
            fragments.append(
                PIICandidate(
                    entity_id=entity_id,
                    text=local_text,
                    normalized_text=normalized,
                    attr_type=PIIAttributeType.ADDRESS,
                    source=PIISourceType.OCR,
                    bbox=block.bbox,
                    block_id=block.block_id,
                    span_start=local_start,
                    span_end=local_end,
                    confidence=max(0.4, candidate.confidence - 0.08),
                    metadata=self._merge_candidate_metadata(
                        candidate.metadata,
                        {
                            "matched_by": ["ocr_page_fragment"],
                            "ocr_block_ids": [block.block_id] if block.block_id else [],
                        },
                    ),
                )
            )
        return fragments

    def _build_shadow_text(
        self,
        raw_text: str,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    ) -> _ShadowTextDocument:
        """将已识别 span 替换为类型占位符，保留后续弱规则所需的局部语义。"""
        protected_candidates = sorted(
            (
                candidate
                for candidate in collected.values()
                if candidate.span_start is not None and candidate.span_end is not None and candidate.span_start < candidate.span_end
            ),
            key=lambda item: (item.span_start, item.span_end),
        )
        shadow_chars: list[str] = []
        index_map: list[int | None] = []
        cursor = 0
        for candidate in protected_candidates:
            span_start = candidate.span_start
            span_end = candidate.span_end
            if span_start is None or span_end is None or span_start < cursor:
                continue
            for index in range(cursor, span_start):
                shadow_chars.append(raw_text[index])
                index_map.append(index)
            token = self._shadow_token(candidate.attr_type)
            for char in token:
                shadow_chars.append(char)
                index_map.append(None)
            cursor = span_end
        for index in range(cursor, len(raw_text)):
            shadow_chars.append(raw_text[index])
            index_map.append(index)
        return _ShadowTextDocument(text="".join(shadow_chars), index_map=tuple(index_map))

    def _shadow_token(self, attr_type: PIIAttributeType) -> str:
        mapping = {
            PIIAttributeType.NAME: " <NAME> ",
            PIIAttributeType.PHONE: " <PHONE> ",
            PIIAttributeType.CARD_NUMBER: " <CARD> ",
            PIIAttributeType.BANK_ACCOUNT: " <ACCOUNT> ",
            PIIAttributeType.PASSPORT_NUMBER: " <PASSPORT> ",
            PIIAttributeType.DRIVER_LICENSE: " <DL> ",
            PIIAttributeType.EMAIL: " <EMAIL> ",
            PIIAttributeType.ID_NUMBER: " <ID> ",
            PIIAttributeType.ADDRESS: " <ADDR> ",
            PIIAttributeType.ORGANIZATION: " <ORG> ",
            PIIAttributeType.OTHER: " <CODE> ",
        }
        return mapping[attr_type]

    def _collect_dictionary_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        dictionary_index: dict[PIIAttributeType, _CompiledDictionaryIndex],
        skip_spans: list[tuple[int, int]] | None = None,
    ) -> None:
        """收集本地字典命中。"""
        for attr_type, compiled_index in dictionary_index.items():
            pending_matches: list[_DictionaryMatch] = []
            for match in self._find_index_dictionary_matches(raw_text, attr_type, compiled_index):
                pending_matches.append(match)
            for match in self._select_dictionary_matches(pending_matches):
                canonical_source_text = match.canonical_source_text
                if canonical_source_text is None and attr_type == PIIAttributeType.NAME:
                    canonical_source_text = self._canonical_name_source_text(
                        match.matched_text,
                        reference_text=match.source_term,
                        allow_ocr_noise=True,
                    )
                if attr_type == PIIAttributeType.NAME and not self._is_name_dictionary_match_allowed(
                    raw_text,
                    match.span_start,
                    match.span_end,
                ):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=match.matched_text,
                    attr_type=attr_type,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=match.span_start,
                    span_end=match.span_end,
                    confidence=match.confidence,
                    matched_by=match.matched_by,
                    canonical_source_text=canonical_source_text,
                    metadata=self._dictionary_match_metadata(match),
                    skip_spans=skip_spans,
                )

    def _collect_context_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
        rule_profile: _RuleStrengthProfile,
    ) -> None:
        """收集字段上下文命中。"""
        for attr_type, pattern, matched_by, confidence, validator in self.context_rules:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(raw_text, *match.span("value"))
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                trimmed = self._trim_context_value(raw_text, value, span_start, span_end)
                if trimmed is None:
                    continue
                value, span_start, span_end = trimmed
                canonical_source_text = None
                validator_value = value
                if attr_type == PIIAttributeType.NAME:
                    if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                        continue
                    canonical_source_text = self._canonical_name_source_text(
                        value,
                        allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                    )
                    if canonical_source_text:
                        validator_value = canonical_source_text
                if attr_type == PIIAttributeType.ADDRESS and self._contains_mask_char(
                    value,
                    allow_alpha_masks=True,
                ) and not rule_profile.enable_context_masked_text:
                    continue
                candidate_matched_by = matched_by
                candidate_confidence = confidence
                is_valid = bool(value) and validator(validator_value)
                if not is_valid and self._is_context_masked_text_candidate(
                    value,
                    attr_type=attr_type,
                    rule_profile=rule_profile,
                ):
                    is_valid = True
                    candidate_matched_by = f"{matched_by}_masked"
                    candidate_confidence = max(0.62, confidence - 0.14)
                if not is_valid:
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=attr_type,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=candidate_confidence,
                    matched_by=candidate_matched_by,
                    canonical_source_text=canonical_source_text,
                    skip_spans=skip_spans,
                )

    def _trim_context_value(
        self,
        raw_text: str,
        value: str,
        span_start: int,
        span_end: int,
    ) -> tuple[str, int, int] | None:
        """截断被贪婪 value_pattern 吞进去的后续字段标签。"""
        current_value = value
        current_end = span_end
        while current_value and current_end < len(raw_text):
            if _FIELD_LABEL_CONNECTOR_PATTERN.match(raw_text[current_end:]) is None:
                break
            match = self.trailing_field_label_pattern.fullmatch(current_value)
            if match is None:
                break
            trimmed = match.group("body").rstrip()
            if not trimmed or trimmed == current_value:
                break
            current_end = span_start + len(trimmed)
            current_value = trimmed
        if not current_value:
            return None
        return current_value, span_start, current_end

    def _is_context_masked_text_candidate(
        self,
        value: str,
        *,
        attr_type: PIIAttributeType,
        rule_profile: _RuleStrengthProfile,
    ) -> bool:
        if not rule_profile.enable_context_masked_text:
            return False
        if attr_type != PIIAttributeType.ADDRESS:
            return False
        return self._looks_like_masked_address_candidate(
            value,
            min_confidence=rule_profile.address_min_confidence,
            allow_alpha_masks=rule_profile.allow_alpha_mask_text,
        )

    def _contains_mask_char(self, value: str, *, allow_alpha_masks: bool) -> bool:
        compact = re.sub(r"\s+", "", value or "")
        for char in compact:
            if char in _TEXT_MASK_VISUAL_SYMBOLS or char in {"*", "＊"}:
                return True
            if allow_alpha_masks and char in _TEXT_MASK_ALPHA_SYMBOLS:
                return True
        return False

    def _is_repeated_mask_text(
        self,
        value: str,
        *,
        min_run: int,
        allow_alpha_masks: bool,
    ) -> bool:
        compact = re.sub(r"\s+", "", value or "")
        if len(compact) < min_run:
            return False
        repeated_char = compact[0]
        if any(char != repeated_char for char in compact):
            return False
        if repeated_char not in _TEXT_MASK_SYMBOLS:
            return False
        if not allow_alpha_masks and repeated_char in _TEXT_MASK_ALPHA_SYMBOLS:
            return False
        if repeated_char in _TEXT_MASK_VISUAL_SYMBOLS:
            return True
        return repeated_char in _TEXT_MASK_ALPHA_SYMBOLS

    def _collect_regex_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
    ) -> None:
        """收集格式型正则规则命中。"""
        for attr_type, rule_items in self.patterns.items():
            for pattern, matched_by, confidence in rule_items:
                for match in pattern.finditer(raw_text):
                    extracted = self._extract_match(raw_text, *match.span(0))
                    if extracted is None:
                        continue
                    matched_text, span_start, span_end = extracted
                    resolved = self._resolve_regex_match(
                        raw_text=raw_text,
                        matched_text=matched_text,
                        attr_type=attr_type,
                        matched_by=matched_by,
                        confidence=confidence,
                        span_start=span_start,
                        span_end=span_end,
                    )
                    if resolved is None:
                        continue
                    resolved_attr_type, resolved_matched_by, resolved_confidence, resolved_metadata = resolved
                    self._upsert_regex_candidate(
                        collected=collected,
                        text=raw_text,
                        matched_text=matched_text,
                        attr_type=resolved_attr_type,
                        source=source,
                        bbox=bbox,
                        block_id=block_id,
                        span_start=span_start,
                        span_end=span_end,
                        confidence=resolved_confidence,
                        matched_by=resolved_matched_by,
                        metadata=resolved_metadata,
                        skip_spans=skip_spans,
                    )

    def _upsert_regex_candidate(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        text: str,
        matched_text: str,
        attr_type: PIIAttributeType,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        span_start: int | None,
        span_end: int | None,
        confidence: float,
        matched_by: str,
        metadata: dict[str, list[str]] | None = None,
        skip_spans: list[tuple[int, int]] | None = None,
    ) -> None:
        """在 regex 阶段对同一 span 的高精度数字类型做冲突收敛。"""
        if span_start is None or span_end is None:
            self._upsert_candidate(
                collected=collected,
                text=text,
                matched_text=matched_text,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by=matched_by,
                metadata=metadata,
                skip_spans=skip_spans,
            )
            return
        if not self._is_regex_numeric_candidate_type(attr_type, matched_by):
            self._upsert_candidate(
                collected=collected,
                text=text,
                matched_text=matched_text,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by=matched_by,
                metadata=metadata,
                skip_spans=skip_spans,
            )
            return

        same_span_items = self._same_span_numeric_regex_items(
            collected,
            span_start=span_start,
            span_end=span_end,
        )
        specific_items = [
            item
            for item in same_span_items
            if item[1].attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES
        ]
        ambiguous_items = [
            item
            for item in same_span_items
            if self._is_regex_ambiguous_number_candidate(item[1])
        ]

        incoming_is_ambiguous = attr_type == PIIAttributeType.OTHER and matched_by == "regex_number_ambiguous"
        if incoming_is_ambiguous:
            if specific_items:
                return
            if ambiguous_items:
                self._merge_ambiguous_numeric_candidate(
                    candidate=ambiguous_items[0][1],
                    metadata=metadata,
                    confidence=confidence,
                )
                return
            self._upsert_candidate(
                collected=collected,
                text=text,
                matched_text=matched_text,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by=matched_by,
                metadata=metadata,
                skip_spans=skip_spans,
            )
            return

        same_attr_items = [item for item in specific_items if item[1].attr_type == attr_type]
        conflicting_specific_items = [item for item in specific_items if item[1].attr_type != attr_type]
        if conflicting_specific_items:
            ambiguous_types = {attr_type.value}
            for _, existing in same_span_items:
                if existing.attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES:
                    ambiguous_types.add(existing.attr_type.value)
                ambiguous_types.update(existing.metadata.get("ambiguous_numeric_types", []))
            for key, _ in same_span_items:
                collected.pop(key, None)
            self._upsert_candidate(
                collected=collected,
                text=text,
                matched_text=matched_text,
                attr_type=PIIAttributeType.OTHER,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=max(0.8, confidence),
                matched_by="regex_number_ambiguous",
                metadata={"ambiguous_numeric_types": sorted(ambiguous_types)},
                skip_spans=skip_spans,
            )
            return

        if ambiguous_items:
            for key, _ in ambiguous_items:
                collected.pop(key, None)
        if same_attr_items:
            self._upsert_candidate(
                collected=collected,
                text=text,
                matched_text=matched_text,
                attr_type=attr_type,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by=matched_by,
                metadata=metadata,
                skip_spans=skip_spans,
            )
            return
        self._upsert_candidate(
            collected=collected,
            text=text,
            matched_text=matched_text,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            matched_by=matched_by,
            metadata=metadata,
            skip_spans=skip_spans,
        )

    def _resolve_regex_match(
        self,
        *,
        raw_text: str,
        matched_text: str,
        attr_type: PIIAttributeType,
        matched_by: str,
        confidence: float,
        span_start: int,
        span_end: int,
    ) -> tuple[PIIAttributeType, str, float, dict[str, list[str]] | None] | None:
        """对 regex 命中的高精度字段做二次校验与歧义降级。"""
        if attr_type == PIIAttributeType.PHONE:
            return (attr_type, matched_by, confidence, None) if self._is_phone_candidate(matched_text) else None
        if attr_type == PIIAttributeType.EMAIL:
            return (attr_type, matched_by, confidence, None) if self._is_email_candidate(matched_text) else None
        if attr_type == PIIAttributeType.PASSPORT_NUMBER:
            if not self._is_passport_candidate(matched_text):
                return None
            if self._has_other_number_context(raw_text, span_start, span_end):
                return (
                    PIIAttributeType.OTHER,
                    "regex_number_ambiguous",
                    max(0.8, confidence),
                    {"ambiguous_numeric_types": [PIIAttributeType.PASSPORT_NUMBER.value]},
                )
            return (attr_type, matched_by, confidence, None)
        if attr_type not in {
            PIIAttributeType.CARD_NUMBER,
            PIIAttributeType.BANK_ACCOUNT,
            PIIAttributeType.DRIVER_LICENSE,
            PIIAttributeType.ID_NUMBER,
        }:
            return (attr_type, matched_by, confidence, None)
        numeric_candidates = self._numeric_candidate_types(matched_text)
        if not numeric_candidates:
            return None
        preferred_attr_type = self._preferred_numeric_attr_type(
            raw_text=raw_text,
            matched_text=matched_text,
            current_attr_type=attr_type,
            matched_by=matched_by,
            numeric_candidates=numeric_candidates,
            span_start=span_start,
            span_end=span_end,
        )
        if preferred_attr_type is not None:
            if preferred_attr_type != attr_type:
                return None
            return (preferred_attr_type, matched_by, confidence, None)
        return (
            PIIAttributeType.OTHER,
            "regex_number_ambiguous",
            max(0.8, confidence),
            {"ambiguous_numeric_types": [item.value for item in sorted(numeric_candidates, key=lambda x: x.value)]},
        )

    def _numeric_candidate_types(self, value: str) -> set[PIIAttributeType]:
        """收集一个数字串可能对应的高精度数字类型。"""
        candidates: set[PIIAttributeType] = set()
        if self._is_id_candidate(value):
            candidates.add(PIIAttributeType.ID_NUMBER)
        if self._is_card_number_candidate(value):
            candidates.add(PIIAttributeType.CARD_NUMBER)
        if self._is_bank_account_candidate(value):
            candidates.add(PIIAttributeType.BANK_ACCOUNT)
        if self._is_driver_license_candidate(value):
            candidates.add(PIIAttributeType.DRIVER_LICENSE)
        return candidates

    def _preferred_numeric_attr_type(
        self,
        *,
        raw_text: str,
        matched_text: str,
        current_attr_type: PIIAttributeType,
        matched_by: str,
        numeric_candidates: set[PIIAttributeType],
        span_start: int,
        span_end: int,
    ) -> PIIAttributeType | None:
        """在高精度数字类型冲突时选出可明确归类的类型，否则返回 None。"""
        keyword_bias = self._numeric_keyword_bias(raw_text, span_start, span_end)
        if keyword_bias is not None and keyword_bias in numeric_candidates:
            return keyword_bias
        if PIIAttributeType.ID_NUMBER in numeric_candidates and (
            matched_by.startswith("regex_cn_id") or self._looks_like_cn_id_with_birthdate(matched_text)
        ):
            return PIIAttributeType.ID_NUMBER
        if len(numeric_candidates) == 1:
            return next(iter(numeric_candidates))
        card_compact = compact_card_number_value(matched_text)
        if (
            current_attr_type == PIIAttributeType.CARD_NUMBER
            and PIIAttributeType.CARD_NUMBER in numeric_candidates
            and re.fullmatch(r"\d{13,19}", card_compact)
            and self._passes_luhn(card_compact)
        ):
            return PIIAttributeType.CARD_NUMBER
        bank_compact = compact_bank_account_value(matched_text)
        if (
            current_attr_type == PIIAttributeType.BANK_ACCOUNT
            and PIIAttributeType.BANK_ACCOUNT in numeric_candidates
            and len(re.sub(r"[^0-9*＊xX]", "", bank_compact)) > 19
        ):
            return PIIAttributeType.BANK_ACCOUNT
        driver_compact = compact_driver_license_value(matched_text)
        if (
            current_attr_type == PIIAttributeType.DRIVER_LICENSE
            and PIIAttributeType.DRIVER_LICENSE in numeric_candidates
            and self._is_strong_driver_license_shape(driver_compact)
        ):
            return PIIAttributeType.DRIVER_LICENSE
        if self._has_other_number_context(raw_text, span_start, span_end):
            return None
        if (
            current_attr_type == PIIAttributeType.CARD_NUMBER
            and numeric_candidates == {PIIAttributeType.CARD_NUMBER, PIIAttributeType.BANK_ACCOUNT}
        ):
            return None
        return None

    def _numeric_keyword_bias(
        self,
        raw_text: str,
        span_start: int,
        span_end: int,
    ) -> PIIAttributeType | None:
        """根据附近字段关键词给高精度数字优先归类。"""
        window = self._match_context_window(raw_text, span_start, span_end)
        if self._window_has_keywords(window, _CARD_FIELD_KEYWORDS):
            return PIIAttributeType.CARD_NUMBER
        if self._window_has_keywords(window, _BANK_ACCOUNT_FIELD_KEYWORDS):
            return PIIAttributeType.BANK_ACCOUNT
        if self._window_has_keywords(window, _DRIVER_LICENSE_FIELD_KEYWORDS):
            return PIIAttributeType.DRIVER_LICENSE
        if self._window_has_keywords(window, _ID_FIELD_KEYWORDS):
            return PIIAttributeType.ID_NUMBER
        return None

    def _has_other_number_context(self, raw_text: str, span_start: int, span_end: int) -> bool:
        """判断命中数字周围是否更像订单号/编号等泛化编号语境。"""
        window = self._match_context_window(raw_text, span_start, span_end)
        return self._window_has_keywords(window, _OTHER_FIELD_KEYWORDS)

    def _match_context_window(self, raw_text: str, span_start: int, span_end: int, *, radius: int = 12) -> str:
        left = max(0, span_start - radius)
        right = min(len(raw_text), span_end + radius)
        return raw_text[left:right]

    def _window_has_keywords(self, window: str, keywords: tuple[str, ...]) -> bool:
        lowered = window.lower()
        return any(keyword.lower() in lowered for keyword in keywords)

    def _looks_like_cn_id_with_birthdate(self, value: str) -> bool:
        compact = compact_id_value(value)
        return bool(
            re.fullmatch(r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]", compact)
            or re.fullmatch(r"[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}", compact)
        )

    def _is_non_id_driver_license_shape(self, compact: str) -> bool:
        compact_alnum = re.sub(r"[^A-Z0-9*＊xX]", "", compact.upper())
        return bool(
            re.fullmatch(r"\d{12}", compact_alnum)
            or re.fullmatch(r"\d{15}", compact_alnum)
            or re.fullmatch(r"[A-Z]{1,3}\d{7,17}", compact_alnum)
            or re.fullmatch(r"[A-Z0-9]{2,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact_alnum)
        )

    def _is_strong_driver_license_shape(self, compact: str) -> bool:
        compact_alnum = re.sub(r"[^A-Z0-9*＊xX]", "", compact.upper())
        return bool(
            re.fullmatch(r"[A-Z]{1,3}\d{7,17}", compact_alnum)
            or (
                any(char.isalpha() for char in compact_alnum)
                and re.fullmatch(r"[A-Z0-9]{2,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact_alnum)
            )
        )

    def _same_span_numeric_regex_items(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        *,
        span_start: int,
        span_end: int,
    ) -> list[tuple[tuple[str, str, int | None, int | None], PIICandidate]]:
        return [
            (key, candidate)
            for key, candidate in collected.items()
            if candidate.span_start == span_start
            and candidate.span_end == span_end
            and self._is_regex_numeric_candidate(candidate)
        ]

    def _is_regex_numeric_candidate(self, candidate: PIICandidate) -> bool:
        matched_by_items = candidate.metadata.get("matched_by", [])
        return any(
            item.startswith("regex_") and self._is_regex_numeric_candidate_type(candidate.attr_type, item)
            for item in matched_by_items
        )

    def _is_regex_numeric_candidate_type(self, attr_type: PIIAttributeType, matched_by: str) -> bool:
        return attr_type in _HIGH_PRECISION_NUMERIC_ATTR_TYPES or (
            attr_type == PIIAttributeType.OTHER and matched_by == "regex_number_ambiguous"
        )

    def _is_regex_ambiguous_number_candidate(self, candidate: PIICandidate) -> bool:
        return candidate.attr_type == PIIAttributeType.OTHER and "regex_number_ambiguous" in candidate.metadata.get("matched_by", [])

    def _merge_ambiguous_numeric_candidate(
        self,
        *,
        candidate: PIICandidate,
        metadata: dict[str, list[str]] | None,
        confidence: float,
    ) -> None:
        merged_metadata = self._merge_candidate_metadata(candidate.metadata, metadata or {})
        candidate.metadata = merged_metadata
        candidate.confidence = max(candidate.confidence, confidence)

    def _collect_name_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
        rule_profile: _RuleStrengthProfile,
        original_text: str | None = None,
        shadow_index_map: tuple[int | None, ...] | None = None,
    ) -> None:
        """收集姓名相关的上下文与敬称规则。"""
        if rule_profile.enable_self_name_patterns:
            for pattern, matched_by, confidence in self.self_name_patterns:
                for match in pattern.finditer(raw_text):
                    extracted = self._extract_match(
                        raw_text,
                        *match.span("value"),
                        original_text=original_text,
                        shadow_index_map=shadow_index_map,
                    )
                    if extracted is None:
                        continue
                    value, span_start, span_end = extracted
                    canonical_source_text = self._canonical_name_source_text(
                        value,
                        allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                    )
                    validator_value = canonical_source_text or value
                    if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                        continue
                    if not self._is_name_candidate(validator_value):
                        continue
                    self._upsert_candidate(
                        collected=collected,
                        text=raw_text,
                        matched_text=value,
                        attr_type=PIIAttributeType.NAME,
                        source=source,
                        bbox=bbox,
                        block_id=block_id,
                        span_start=span_start,
                        span_end=span_end,
                        confidence=confidence,
                        matched_by=matched_by,
                        canonical_source_text=canonical_source_text,
                        skip_spans=skip_spans,
                    )
        if rule_profile.enable_honorific_name_pattern:
            for match in self.name_title_pattern.finditer(raw_text):
                extracted = self._extract_match(
                    raw_text,
                    *match.span("value"),
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if self._is_repeated_mask_text(value, min_run=2, allow_alpha_masks=True):
                    continue
                canonical_source_text = self._canonical_name_source_text(
                    value,
                    allow_ocr_noise=rule_profile.level == ProtectionLevel.STRONG,
                )
                validator_value = canonical_source_text or value
                if not self._looks_like_name_with_title(validator_value):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=PIIAttributeType.NAME,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=0.72,
                    matched_by="regex_name_honorific",
                    canonical_source_text=canonical_source_text,
                    skip_spans=skip_spans,
                )

    def _collect_masked_text_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
        rule_profile: _RuleStrengthProfile,
        original_text: str | None = None,
        shadow_index_map: tuple[int | None, ...] | None = None,
    ) -> None:
        if not rule_profile.enable_standalone_masked_text:
            return
        for match in self.masked_text_pattern.finditer(raw_text):
            extracted = self._extract_match(
                raw_text,
                *match.span("value"),
                original_text=original_text,
                shadow_index_map=shadow_index_map,
            )
            if extracted is None:
                continue
            value, span_start, span_end = extracted
            if not self._is_repeated_mask_text(
                value,
                min_run=rule_profile.masked_text_min_run,
                allow_alpha_masks=rule_profile.allow_alpha_mask_text,
            ):
                continue
            confidence = 0.62 if re.sub(r"\s+", "", value)[0] in _TEXT_MASK_VISUAL_SYMBOLS else 0.56
            self._upsert_candidate(
                collected=collected,
                text=raw_text,
                matched_text=value,
                attr_type=PIIAttributeType.OTHER,
                source=source,
                bbox=bbox,
                block_id=block_id,
                span_start=span_start,
                span_end=span_end,
                confidence=confidence,
                matched_by="heuristic_masked_text",
                skip_spans=skip_spans,
            )

    def _collect_address_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
        rule_profile: _RuleStrengthProfile,
        original_text: str | None = None,
        shadow_index_map: tuple[int | None, ...] | None = None,
    ) -> None:
        """收集地址整段与碎片命中。"""
        full_text_candidate = self._clean_address_candidate(raw_text)
        if self._contains_mask_char(full_text_candidate, allow_alpha_masks=True) and not rule_profile.enable_context_masked_text:
            full_text_candidate = ""
        if rule_profile.enable_full_text_address and self._should_collect_full_text_address(raw_text, full_text_candidate, rule_profile=rule_profile):
            extracted = self._extract_match(
                raw_text,
                0,
                len(raw_text),
                cleaner=self._clean_address_candidate,
                original_text=original_text,
                shadow_index_map=shadow_index_map,
            )
            if extracted is not None:
                matched_text, span_start, span_end = extracted
                confidence = self._address_confidence(full_text_candidate)
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=matched_text,
                    attr_type=PIIAttributeType.ADDRESS,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=confidence,
                    matched_by="heuristic_address_fragment",
                    skip_spans=skip_spans,
                )
        for pattern in _ADDRESS_SPAN_PATTERNS:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(
                    raw_text,
                    *match.span(0),
                    cleaner=self._clean_address_candidate,
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if self._contains_mask_char(value, allow_alpha_masks=True) and not rule_profile.enable_context_masked_text:
                    continue
                if not self._looks_like_address_candidate(value, min_confidence=rule_profile.address_min_confidence):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=PIIAttributeType.ADDRESS,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=self._address_confidence(value),
                    matched_by="regex_address_span",
                    skip_spans=skip_spans,
                )

    def _collect_organization_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        skip_spans: list[tuple[int, int]],
        rule_profile: _RuleStrengthProfile,
        original_text: str | None = None,
        shadow_index_map: tuple[int | None, ...] | None = None,
    ) -> None:
        """收集机构名后缀与就业/就读语境下的机构命中。"""
        for pattern in _ORGANIZATION_SPAN_PATTERNS:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(
                    raw_text,
                    *match.span(0),
                    cleaner=self._clean_organization_candidate,
                    original_text=original_text,
                    shadow_index_map=shadow_index_map,
                )
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if not self._is_organization_candidate(value, allow_weak_suffix=rule_profile.allow_weak_org_suffix):
                    continue
                self._upsert_candidate(
                    collected=collected,
                    text=raw_text,
                    matched_text=value,
                    attr_type=PIIAttributeType.ORGANIZATION,
                    source=source,
                    bbox=bbox,
                    block_id=block_id,
                    span_start=span_start,
                    span_end=span_end,
                    confidence=self._organization_confidence(value, allow_weak_suffix=rule_profile.allow_weak_org_suffix),
                    matched_by="regex_organization_suffix",
                    skip_spans=skip_spans,
                )

    def _extract_match(
        self,
        raw_text: str,
        start: int,
        end: int,
        cleaner: Callable[[str], str] | None = None,
        *,
        original_text: str | None = None,
        shadow_index_map: tuple[int | None, ...] | None = None,
    ) -> tuple[str, int, int] | None:
        """提取命中文本，并返回清洗后的内容及其在原文中的 span。"""
        snippet = raw_text[start:end]
        cleaned = cleaner(snippet) if cleaner is not None else self._clean_extracted_value(snippet)
        if not cleaned:
            return None
        relative_start = snippet.find(cleaned)
        if relative_start < 0:
            relative_start = snippet.lower().find(cleaned.lower())
        if relative_start < 0:
            return None
        absolute_start = start + relative_start
        absolute_end = absolute_start + len(cleaned)
        if shadow_index_map is not None:
            return self._remap_shadow_span(
                absolute_start,
                absolute_end,
                original_text=original_text,
                shadow_index_map=shadow_index_map,
                cleaner=cleaner,
            )
        return cleaned, absolute_start, absolute_end

    def _remap_shadow_span(
        self,
        shadow_start: int,
        shadow_end: int,
        *,
        original_text: str | None,
        shadow_index_map: tuple[int | None, ...],
        cleaner: Callable[[str], str] | None = None,
    ) -> tuple[str, int, int] | None:
        if original_text is None:
            return None
        covered = [index for index in shadow_index_map[shadow_start:shadow_end] if index is not None]
        if not covered:
            return None
        original_start = min(covered)
        original_end = max(covered) + 1
        if len(covered) != original_end - original_start:
            return None
        return self._extract_match(original_text, original_start, original_end, cleaner=cleaner)

    def _find_literal_matches(self, raw_text: str, needle: str) -> list[tuple[str, int, int]]:
        """在原文中查找字典项对应的全部匹配，并返回原文片段与 span。"""
        matches: list[tuple[str, int, int]] = []
        escaped = re.escape(needle)
        for match in re.finditer(escaped, raw_text, re.IGNORECASE):
            matched_text = raw_text[match.start():match.end()]
            matches.append((matched_text, match.start(), match.end()))
        return matches

    def _find_index_dictionary_matches(
        self,
        raw_text: str,
        attr_type: PIIAttributeType,
        compiled_index: _CompiledDictionaryIndex,
    ) -> list[_DictionaryMatch]:
        """用预编译索引执行容错匹配，并返回候选词条命中。"""
        raw_match_text, index_map = build_match_text(attr_type, raw_text)
        if not raw_match_text:
            return []
        matches: list[_DictionaryMatch] = []
        for pos, first_char in enumerate(raw_match_text):
            by_length = compiled_index.by_first_char.get(first_char)
            if by_length is None:
                continue
            for variant_length in compiled_index.lengths_by_first_char.get(first_char, ()):
                end = pos + variant_length
                if end > len(raw_match_text):
                    continue
                variant = raw_match_text[pos:end]
                matched_entries = by_length.get(variant_length, {}).get(variant)
                if not matched_entries:
                    continue
                raw_start = index_map[pos]
                raw_end = index_map[end - 1] + 1
                matched_text = raw_text[raw_start:raw_end]
                for entry in matched_entries:
                    matches.append(
                        _DictionaryMatch(
                            matched_text=matched_text,
                            span_start=raw_start,
                            span_end=raw_end,
                            source_term=entry.source_term,
                            canonical_source_text=entry.canonical_source_text,
                            binding_key=entry.binding_key,
                            local_entity_ids=entry.local_entity_ids,
                            matched_by=entry.matched_by,
                            confidence=entry.confidence,
                            metadata=dict(entry.metadata),
                        )
                    )
        return matches

    def _select_dictionary_matches(self, matches: list[_DictionaryMatch]) -> list[_DictionaryMatch]:
        """对本地词库命中做唯一性与最长片段裁剪。"""
        if not matches:
            return []
        grouped_by_span: dict[tuple[int, int], list[_DictionaryMatch]] = {}
        for match in matches:
            grouped_by_span.setdefault((match.span_start, match.span_end), []).append(match)

        unique_matches: list[_DictionaryMatch] = []
        for span, items in grouped_by_span.items():
            binding_keys = {item.binding_key for item in items}
            if len(binding_keys) != 1:
                unique_matches.append(self._build_ambiguous_dictionary_match(items))
                continue
            longest = max(items, key=lambda item: len(item.matched_text))
            unique_matches.append(longest)

        ordered = sorted(
            unique_matches,
            key=lambda item: (-(item.span_end - item.span_start), item.span_start, item.span_end),
        )
        selected: list[_DictionaryMatch] = []
        covered_spans: list[tuple[int, int]] = []
        for item in ordered:
            if any(item.span_start >= left and item.span_end <= right for left, right in covered_spans):
                continue
            selected.append(item)
            covered_spans.append((item.span_start, item.span_end))
        return sorted(selected, key=lambda item: (item.span_start, item.span_end))

    def _build_ambiguous_dictionary_match(self, items: list[_DictionaryMatch]) -> _DictionaryMatch:
        """将同 span 多实体词库命中降级为“仅识别隐私类型”的候选。"""
        first = max(items, key=lambda item: len(item.matched_text))
        matched_by = f"{first.matched_by}_ambiguous"
        metadata = {
            "ambiguous_binding_keys": sorted({item.binding_key for item in items}),
        }
        session_turn_ids: set[str] = set()
        for item in items:
            session_turn_ids.update(item.metadata.get("session_turn_ids", []))
        if session_turn_ids:
            metadata["session_turn_ids"] = sorted(session_turn_ids)
        return _DictionaryMatch(
            matched_text=first.matched_text,
            span_start=first.span_start,
            span_end=first.span_end,
            source_term=first.matched_text,
            binding_key=f"ambiguous:{matched_by}:{first.span_start}:{first.span_end}",
            canonical_source_text=None,
            local_entity_ids=(),
            matched_by=matched_by,
            confidence=max(item.confidence for item in items),
            metadata=metadata,
        )

    def _protected_spans_from_dictionary_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        *,
        rule_profile: _RuleStrengthProfile,
    ) -> list[tuple[int, int]]:
        """提取本地词库与 session 历史已命中的区间，供后续 rule 扫描避让。"""
        return self._protected_spans_from_candidates(
            collected,
            matched_by_prefixes=("dictionary_",),
            rule_profile=rule_profile,
        )

    def _protected_spans_from_candidates(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        *,
        matched_by_prefixes: tuple[str, ...] | None = None,
        rule_profile: _RuleStrengthProfile,
    ) -> list[tuple[int, int]]:
        """提取已接受候选区间，供更低精度阶段避让。"""
        protected: list[tuple[int, int]] = []
        for candidate in collected.values():
            if not self._meets_confidence_threshold(candidate.attr_type, candidate.confidence, rule_profile):
                continue
            matched_by = candidate.metadata.get("matched_by", [])
            if matched_by_prefixes is not None and not any(
                any(item.startswith(prefix) for prefix in matched_by_prefixes)
                for item in matched_by
            ):
                continue
            if candidate.span_start is None or candidate.span_end is None:
                continue
            protected.append((candidate.span_start, candidate.span_end))
        return protected

    def _meets_confidence_threshold(
        self,
        attr_type: PIIAttributeType,
        confidence: float,
        rule_profile: _RuleStrengthProfile,
    ) -> bool:
        return confidence >= rule_profile.min_confidence_by_attr.get(attr_type, 0.0)

    def _clean_extracted_value(self, value: str) -> str:
        """清理上下文提取值两侧的噪声字符。"""
        cleaned = value.strip()
        cleaned = re.sub(r"^[\s\[{(<（【「『\"'`]+", "", cleaned)
        cleaned = re.sub(r"[\s\]})>）】」』\"'`.,，;；、]+$", "", cleaned)
        return cleaned.strip()

    def _clean_address_candidate(self, value: str) -> str:
        """清理地址候选前后的连接词与标点。"""
        cleaned = self._clean_extracted_value(value)
        cleaned = _LEADING_ADDRESS_NOISE_PATTERN.sub("", cleaned)
        cleaned = re.sub(r"^(?:地址|住址|详细地址|联系地址|收货地址|户籍地址)\s*(?:[:：=])?\s*", "", cleaned)
        return cleaned.strip()

    def _clean_organization_candidate(self, value: str) -> str:
        """清理机构候选前后的上下文噪声。"""
        cleaned = self._clean_extracted_value(value)
        cleaned = _LEADING_ORGANIZATION_NOISE_PATTERN.sub("", cleaned)
        cleaned = _ORGANIZATION_FIELD_PREFIX_PATTERN.sub("", cleaned)
        cleaned = re.sub(r"^(?:加入|进入|任职|就职|供职|实习|毕业|就读)\s*", "", cleaned)
        return cleaned.strip()

    def _is_name_dictionary_match_allowed(self, raw_text: str, span_start: int, span_end: int) -> bool:
        """过滤姓名词条前缀误命中，如“张三丰”不应命中“张三”。

        这里只收紧“姓名后面紧跟另一个中文字符”的情况；像“张三老师”“张三处理”
        这类常见敬称或动作上下文仍允许通过。
        """
        next_char = self._next_significant_char(raw_text, span_end)
        if next_char is None or not self._is_cjk_char(next_char):
            return True
        return next_char in _NAME_DICTIONARY_ALLOWED_NEXT_CHARS

    def _next_significant_char(self, raw_text: str, start: int) -> str | None:
        index = start
        while index < len(raw_text):
            current = raw_text[index]
            if current in _NAME_MATCH_IGNORABLE:
                index += 1
                continue
            return current
        return None

    def _is_cjk_char(self, char: str) -> bool:
        return bool(char) and "\u4e00" <= char <= "\u9fff"

    def _canonical_name_source_text(
        self,
        value: str,
        *,
        reference_text: str | None = None,
        allow_ocr_noise: bool = False,
    ) -> str | None:
        """为姓名命中生成规范源值，用于 session/mapping 级统一。"""
        compact = self._compact_name_value(value, allow_ocr_noise=allow_ocr_noise)
        if not compact:
            return None
        if reference_text is not None:
            reference_compact = self._compact_name_value(reference_text, allow_ocr_noise=True)
            if reference_compact and compact == reference_compact:
                return reference_compact
            return None
        if not self._is_name_candidate(compact):
            return None
        return compact

    def _compact_name_value(self, value: str, *, allow_ocr_noise: bool) -> str:
        cleaned = self._clean_extracted_value(value)
        compact = "".join(char for char in cleaned if char not in _NAME_MATCH_IGNORABLE)
        if allow_ocr_noise:
            compact = re.sub(r"[0-9０-９]+", "", compact)
        return compact

    def _is_phone_candidate(self, value: str) -> bool:
        """判断是否为手机号或座机片段。"""
        compact = compact_phone_value(value)
        return bool(
            re.fullmatch(r"1[3-9]\d{9}", compact)
            or re.fullmatch(r"1[3-9]\d[*＊xX]{4}\d{4}", compact)
            or re.fullmatch(r"1[3-9]\d[*＊xX]{8}", compact)
            or re.fullmatch(r"[*＊xX]{7}\d{4}", compact)
            or re.fullmatch(r"0\d{9,11}", compact)
        )

    def _is_card_number_candidate(self, value: str) -> bool:
        """判断是否为银行卡/信用卡号。"""
        compact = compact_card_number_value(value)
        if re.fullmatch(r"\d{13,19}", compact):
            if self._is_phone_candidate(compact) or self._is_id_candidate(compact):
                return False
            return self._passes_luhn(compact)
        if not re.fullmatch(r"[\d*＊xX]{13,19}", compact):
            return False
        if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
            return False
        if (
            not re.fullmatch(r"\d{4}[*＊xX]{5,15}\d{0,4}", compact)
            and not re.fullmatch(r"[*＊xX]{5,15}\d{4}", compact)
        ):
            return False
        return not self._is_phone_candidate(compact)

    def _is_context_card_number_candidate(self, value: str) -> bool:
        """显式卡号字段可接受比 free-text 更宽的校验。"""
        compact = compact_card_number_value(value)
        if re.fullmatch(r"\d{13,19}", compact):
            return not self._is_phone_candidate(compact) and not self._is_id_candidate(compact)
        if not re.fullmatch(r"[\d*＊xX]{13,19}", compact):
            return False
        if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
            return False
        return bool(
            re.fullmatch(r"\d{4}[*＊xX]{5,15}\d{0,4}", compact)
            or re.fullmatch(r"[*＊xX]{5,15}\d{4}", compact)
        )

    def _is_bank_account_candidate(self, value: str) -> bool:
        """判断是否为银行账号；仅配合显式字段上下文使用。"""
        compact = compact_bank_account_value(value)
        if re.fullmatch(r"\d{10,30}", compact):
            if self._is_phone_candidate(compact):
                return False
            return True
        if not re.fullmatch(r"[\d*＊xX]{10,30}", compact):
            return False
        if compact.count("*") + compact.count("＊") + compact.count("x") + compact.count("X") < 4:
            return False
        if (
            not re.fullmatch(r"\d{4,6}[*＊xX]{4,26}\d{0,4}", compact)
            and not re.fullmatch(r"[*＊xX]{4,26}\d{4,6}", compact)
        ):
            return False
        return not self._is_phone_candidate(compact)

    def _is_passport_candidate(self, value: str) -> bool:
        """判断是否为护照号。"""
        compact = compact_passport_value(value)
        return bool(
            re.fullmatch(r"[A-Z]\d{8}", compact)
            or re.fullmatch(r"[A-Z]\d{7}", compact)
            or re.fullmatch(r"[A-Z]{2}\d{7}", compact)
            or re.fullmatch(r"[A-Z0-9]{1,2}[*＊xX]{3,12}[A-Z0-9]{0,4}", compact)
            or re.fullmatch(r"[*＊xX]{3,12}[A-Z0-9]{2,4}", compact)
        )

    def _is_driver_license_candidate(self, value: str) -> bool:
        """判断是否为驾驶证号；仅配合显式字段上下文使用。"""
        compact = compact_driver_license_value(value)
        return bool(
            re.fullmatch(r"\d{12}", compact)
            or re.fullmatch(r"\d{15}", compact)
            or re.fullmatch(r"\d{17}[\dX]", compact)
            or re.fullmatch(r"[A-Z0-9]{10,20}", compact)
            or re.fullmatch(r"[A-Z0-9]{4,8}[*＊xX]{4,16}[A-Z0-9]{0,4}", compact)
            or re.fullmatch(r"[*＊xX]{4,16}[A-Z0-9]{4,8}", compact)
        )

    def _is_email_candidate(self, value: str) -> bool:
        """判断是否为邮箱。"""
        compact = compact_email_value(value)
        if re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", compact):
            return True
        if "*" not in compact and "＊" not in compact:
            return False
        if compact.count("@") != 1:
            return False
        local_part, domain_part = compact.split("@", 1)
        if not local_part or not domain_part or "." not in domain_part:
            return False
        if not re.fullmatch(r"[A-Za-z0-9._%+\-*＊]+", local_part):
            return False
        if not re.fullmatch(r"[A-Za-z0-9.\-*＊]+", domain_part):
            return False
        labels = domain_part.split(".")
        if any(not label for label in labels):
            return False
        if not re.fullmatch(r"[A-Za-z*＊]{2,}", labels[-1]):
            return False
        visible_local = re.sub(r"[*＊xX]", "", local_part)
        visible_domain = re.sub(r"[*＊xX.]", "", domain_part)
        return bool(visible_local or visible_domain)

    def _is_id_candidate(self, value: str) -> bool:
        """判断是否为身份证号或脱敏后的身份证号。"""
        compact = compact_id_value(value)
        return bool(
            self._looks_like_cn_id_with_birthdate(compact)
            or re.fullmatch(r"[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}", compact)
            or re.fullmatch(r"[1-9]\d{5}[*＊]{9,12}", compact)
            or re.fullmatch(r"[*＊]{11,16}[\dXx]{2,4}", compact)
        )

    def _is_other_candidate(self, value: str) -> bool:
        """判断是否为需要保守脱敏的编号类字段。"""
        compact = compact_other_code_value(value)
        if not re.fullmatch(r"[A-Za-z0-9]{4,32}", compact):
            return False
        if (
            self._is_phone_candidate(compact)
            or self._is_card_number_candidate(compact)
            or self._is_bank_account_candidate(compact)
            or self._is_passport_candidate(compact)
            or self._is_driver_license_candidate(compact)
            or self._is_id_candidate(compact)
            or self._is_email_candidate(compact)
        ):
            return False
        digits_only = re.sub(r"\D", "", compact)
        if len(digits_only) < 4:
            return False
        if 12 <= len(digits_only) <= 19:
            return True
        return True

    def _passes_luhn(self, digits: str) -> bool:
        total = 0
        reverse_digits = digits[::-1]
        for index, char in enumerate(reverse_digits):
            value = int(char)
            if index % 2 == 1:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0

    def _is_name_candidate(self, value: str) -> bool:
        """判断是否像姓名。"""
        cleaned = self._clean_extracted_value(value)
        compact = cleaned.replace(" ", "")
        if not compact or compact in _NAME_BLACKLIST:
            return False
        if compact in _NON_PERSON_TOKENS:
            return False
        if any(char.isdigit() for char in compact):
            return False
        if compact in _REGION_TOKENS:
            return False
        if _ADDRESS_SUFFIX_PATTERN.search(compact):
            return False
        if self._looks_like_address_candidate(compact):
            return False
        if re.fullmatch(r"[A-Za-z][A-Za-z .'\-]{1,40}", cleaned):
            return True
        if re.fullmatch(r"[一-龥][*＊xX某]{1,3}", compact):
            return True
        if "·" in compact and re.fullmatch(r"[一-龥]{1,4}·[一-龥]{1,6}", compact):
            return True
        if re.fullmatch(r"[一-龥·]{2,8}", compact):
            if compact[:2] in _COMMON_COMPOUND_SURNAMES:
                return 3 <= len(compact) <= 6
            return compact[0] in _COMMON_SINGLE_CHAR_SURNAMES and 2 <= len(compact) <= 4
        return False

    def _is_organization_candidate(self, value: str, *, allow_weak_suffix: bool = True) -> bool:
        """判断是否像机构名。"""
        cleaned = self._clean_organization_candidate(value)
        compact = re.sub(r"\s+", "", cleaned)
        if not compact or compact in _ORGANIZATION_BLACKLIST:
            return False
        if compact in _ADDRESS_FIELD_KEYWORDS or compact in _NAME_FIELD_KEYWORDS:
            return False
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9 .&'\-]{2,40}", cleaned):
            return len(cleaned.replace(" ", "")) >= 4
        if self._looks_like_address_candidate(compact):
            return False
        if self._is_name_candidate(compact):
            return False
        if _ORGANIZATION_STRONG_SUFFIX_PATTERN.search(compact):
            return len(compact) >= 3
        if _ORGANIZATION_WEAK_SUFFIX_PATTERN.search(compact):
            if not allow_weak_suffix:
                return False
            if any(token in compact for token in _ORGANIZATION_SENTENCE_NOISE_TOKENS):
                return False
            return len(compact) >= 4
        return False

    def _looks_like_name_with_title(self, value: str) -> bool:
        """判断是否为带敬称的姓名片段。"""
        if not re.fullmatch(rf"[一-龥·]{{1,5}}(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))})", value):
            return False
        core = value
        for honorific in _NAME_HONORIFICS:
            if core.endswith(honorific):
                core = core[: -len(honorific)]
                break
        if core in _NON_PERSON_TOKENS:
            return False
        if len(core) == 1:
            return core in _COMMON_SINGLE_CHAR_SURNAMES
        return self._is_name_candidate(core)

    def _looks_like_address_candidate(self, value: str, *, min_confidence: float = 0.45) -> bool:
        """判断是否像地址或地址碎片。"""
        cleaned = self._clean_address_candidate(value)
        if not cleaned or len(cleaned) > 80:
            return False
        if cleaned in _ADDRESS_FIELD_KEYWORDS:
            return False
        confidence = self._address_confidence(cleaned)
        if confidence >= min_confidence:
            return True
        return self._looks_like_masked_address_candidate(cleaned, min_confidence=min_confidence)

    def _looks_like_masked_address_candidate(
        self,
        value: str,
        *,
        min_confidence: float = 0.45,
        allow_alpha_masks: bool = True,
    ) -> bool:
        cleaned = self._clean_address_candidate(value)
        compact = re.sub(r"\s+", "", cleaned)
        if not compact:
            return False
        visible = "".join(
            char
            for char in compact
            if char not in _TEXT_MASK_VISUAL_SYMBOLS and char not in {"*", "＊"} and (allow_alpha_masks or char not in _TEXT_MASK_ALPHA_SYMBOLS)
        )
        mask_count = len(compact) - len(visible)
        if mask_count <= 0 or not visible:
            return False
        if not (
            _ADDRESS_SUFFIX_PATTERN.search(compact)
            or _ADDRESS_NUMBER_PATTERN.search(compact)
            or any(token in visible for token in _REGION_TOKENS)
        ):
            return False
        confidence = self._address_confidence(cleaned)
        if mask_count >= 2:
            confidence += 0.12
        if _ADDRESS_NUMBER_PATTERN.search(compact):
            confidence += 0.08
        if _ADDRESS_SUFFIX_PATTERN.search(compact):
            confidence += 0.06
        return confidence >= min_confidence

    def _should_collect_full_text_address(
        self,
        raw_text: str,
        cleaned: str,
        *,
        rule_profile: _RuleStrengthProfile,
    ) -> bool:
        """仅在整段文本本身已经像独立地址片段时才直接收整段。"""
        if not self._looks_like_address_candidate(cleaned, min_confidence=rule_profile.address_min_confidence):
            return False
        base_text = self._clean_extracted_value(raw_text)
        if sum(1 for _ in self.field_label_pattern.finditer(base_text)) > 1:
            return False
        if re.search(r"[，,。！？；;、]", base_text):
            return False
        return len(base_text) - len(cleaned) <= 6

    def _address_confidence(self, value: str) -> float:
        """根据地址信号强度计算置信度。"""
        cleaned = self._clean_address_candidate(value)
        if not cleaned:
            return 0.0
        score = 0.0
        suffix_hits = _ADDRESS_SUFFIX_PATTERN.findall(cleaned)
        if any(token in cleaned for token in _REGION_TOKENS):
            score += 0.34
        if suffix_hits:
            score += min(0.36, 0.18 * len(suffix_hits))
        if _ADDRESS_NUMBER_PATTERN.search(cleaned):
            score += 0.28
        if _STANDALONE_ADDRESS_FRAGMENT_PATTERN.fullmatch(cleaned):
            score += 0.24
        if _SHORT_ADDRESS_TOKEN_PATTERN.fullmatch(cleaned):
            score += 0.10
        if any(keyword in cleaned for keyword in _ADDRESS_FIELD_KEYWORDS):
            score += 0.18
        if len(cleaned) >= 6 and re.fullmatch(rf"[A-Za-z0-9#\-－—()（）·\s一-龥{_ADDRESS_MASK_CHAR_CLASS[1:-1]}]+", cleaned):
            score += 0.08
        if re.fullmatch(r"(?:\d{1,5}|[A-Za-z]\d{1,5})(?:号院|号楼|栋|幢|座|单元|室|层|号|户)(?:\d{0,4}(?:室|层|户))?", cleaned):
            score += 0.20
        return min(0.96, score)

    def _organization_confidence(self, value: str, *, allow_weak_suffix: bool = True) -> float:
        """根据机构后缀与格式特征估算置信度。"""
        cleaned = self._clean_organization_candidate(value)
        compact = re.sub(r"\s+", "", cleaned)
        if not compact:
            return 0.0
        score = 0.0
        if _ORGANIZATION_STRONG_SUFFIX_PATTERN.search(compact):
            score += 0.62
        elif _ORGANIZATION_WEAK_SUFFIX_PATTERN.search(compact):
            if not allow_weak_suffix:
                return 0.0
            score += 0.48
        if re.search(r"[A-Za-z]", cleaned):
            score += 0.08
        if any(token in compact for token in ("大学", "学院", "医院", "银行", "公司", "集团", "法院", "研究院")):
            score += 0.12
        if len(compact) >= 6:
            score += 0.08
        return min(0.92, score)

    def _upsert_candidate(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        text: str,
        matched_text: str,
        attr_type: PIIAttributeType,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        span_start: int | None,
        span_end: int | None,
        confidence: float,
        matched_by: str,
        canonical_source_text: str | None = None,
        metadata: dict[str, list[str]] | None = None,
        skip_spans: list[tuple[int, int]] | None = None,
    ) -> None:
        """插入候选，或更新已存在候选的置信度与元信息。"""
        cleaned_text = self._clean_extracted_value(matched_text)
        if not cleaned_text:
            return
        if skip_spans and span_start is not None and span_end is not None:
            if self._overlaps_any_span(span_start, span_end, skip_spans):
                return
        normalized = canonicalize_pii_value(attr_type, cleaned_text)
        key = (normalized, attr_type.value, span_start, span_end)
        entity_id = self.resolver.build_candidate_id(
            self.detector_mode,
            source.value,
            normalized,
            attr_type.value,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
        )
        incoming = PIICandidate(
            entity_id=entity_id,
            text=cleaned_text,
            canonical_source_text=canonical_source_text,
            normalized_text=normalized,
            attr_type=attr_type,
            source=source,
            bbox=bbox,
            block_id=block_id,
            span_start=span_start,
            span_end=span_end,
            confidence=confidence,
            metadata=self._candidate_metadata(matched_by=matched_by, metadata=metadata),
        )
        previous = collected.get(key)
        if previous is None:
            collected[key] = incoming
            return
        merged_metadata = self._merge_candidate_metadata(previous.metadata, incoming.metadata)
        merged_matched_by = merged_metadata.get("matched_by", [])
        if incoming.confidence > previous.confidence:
            incoming.metadata = merged_metadata
            if incoming.canonical_source_text is None:
                incoming.canonical_source_text = previous.canonical_source_text
            collected[key] = incoming
            return
        previous.metadata = merged_metadata
        if previous.canonical_source_text is None and incoming.canonical_source_text is not None:
            previous.canonical_source_text = incoming.canonical_source_text
        if any(item.startswith("context_") for item in merged_matched_by) and any(item.startswith("regex_") for item in merged_matched_by):
            previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.08)
        elif "heuristic_address_fragment" in merged_matched_by and "regex_address_span" in merged_matched_by:
            previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.06)

    def _overlaps_any_span(
        self,
        span_start: int,
        span_end: int,
        spans: list[tuple[int, int]],
    ) -> bool:
        """判断候选区间是否与已保护区间重叠。"""
        for left, right in spans:
            if not (span_end <= left or span_start >= right):
                return True
        return False

    def _dictionary_entry_variants(self, attr_type: PIIAttributeType, entry: _LocalDictionaryEntry) -> set[str]:
        """生成本地词条的匹配变体，包含显式 alias。"""
        variants = set(dictionary_match_variants(attr_type, entry.value))
        for alias in entry.aliases:
            variants.update(dictionary_match_variants(attr_type, alias))
        return variants

    def _dictionary_match_metadata(self, match: _DictionaryMatch) -> dict[str, list[str]] | None:
        """将本地词库命中携带的实体信息写入 metadata。"""
        merged = dict(match.metadata)
        if match.local_entity_ids:
            merged["local_entity_ids"] = list(match.local_entity_ids)
        return merged or None

    def _candidate_metadata(self, matched_by: str, metadata: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
        base = {"matched_by": [matched_by]}
        if metadata is None:
            return base
        return self._merge_candidate_metadata(base, metadata)

    def _merge_candidate_metadata(
        self,
        left: dict[str, list[str]] | None,
        right: dict[str, list[str]] | None,
    ) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for source in (left or {}, right or {}):
            for key, values in source.items():
                merged[key] = sorted(set(merged.get(key, [])) | set(values))
        return merged

    def _to_attr_type(self, raw_key: str | PIIAttributeType) -> PIIAttributeType | None:
        """将字典键名映射为领域枚举。"""
        if isinstance(raw_key, PIIAttributeType):
            return raw_key
        key = raw_key.strip().lower()
        mapping = {
            "name": PIIAttributeType.NAME,
            "phone": PIIAttributeType.PHONE,
            "card_number": PIIAttributeType.CARD_NUMBER,
            "card": PIIAttributeType.CARD_NUMBER,
            "credit_card": PIIAttributeType.CARD_NUMBER,
            "bank_card": PIIAttributeType.CARD_NUMBER,
            "debit_card": PIIAttributeType.CARD_NUMBER,
            "bank_account": PIIAttributeType.BANK_ACCOUNT,
            "account_number": PIIAttributeType.BANK_ACCOUNT,
            "passport_number": PIIAttributeType.PASSPORT_NUMBER,
            "passport": PIIAttributeType.PASSPORT_NUMBER,
            "driver_license": PIIAttributeType.DRIVER_LICENSE,
            "driver_license_number": PIIAttributeType.DRIVER_LICENSE,
            "email": PIIAttributeType.EMAIL,
            "address": PIIAttributeType.ADDRESS,
            "id_number": PIIAttributeType.ID_NUMBER,
            "id": PIIAttributeType.ID_NUMBER,
            "organization": PIIAttributeType.ORGANIZATION,
        }
        return mapping.get(key)
