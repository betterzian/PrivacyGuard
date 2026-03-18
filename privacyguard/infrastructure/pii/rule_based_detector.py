"""基于规则与字典的 PII 检测器。"""

from dataclasses import dataclass, field
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
from privacyguard.utils.pii_value import build_match_text, canonicalize_pii_value, dictionary_match_variants

LOGGER = logging.getLogger(__name__)

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
    r"^[A-Za-z0-9#\-－—一-龥]{1,24}(?:区|县|旗|乡|镇|街道|村|路|街|巷|弄|胡同|大道|道|"
    r"社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍|号院|号楼|栋|幢|座|单元|室|层|号)$"
)
_SHORT_ADDRESS_TOKEN_PATTERN = re.compile(
    r"^[一-龥]{2,12}(?:区|县|旗|乡|镇|街道|村|路|街|巷|弄|胡同|大道|道|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾)$"
)
_ADDRESS_SPAN_PATTERNS = (
    re.compile(
        r"(?:北京|上海|天津|重庆|香港|澳门|内蒙古|广西|西藏|宁夏|新疆|"
        r"[一-龥]{2,7}省|[一-龥]{2,7}市|[一-龥]{2,7}区|[一-龥]{2,7}县)"
        r"[A-Za-z0-9#\-－—一-龥]{0,24}"
    ),
    re.compile(
        r"[A-Za-z0-9#\-－—一-龥]{2,24}"
        r"(?:路|街|巷|弄|胡同|大道|道|社区|小区|公寓|大厦|广场|花园|家园|苑|庭|府|湾|园区|校区|宿舍)"
        r"[A-Za-z0-9#\-－—一-龥]{0,16}"
    ),
    re.compile(r"(?:\d{1,5}|[A-Za-z]\d{1,5})(?:号院|号楼|栋|幢|座|单元|室|层|号|户)(?:\d{0,4}(?:室|层|户))?"),
)
_LEADING_ADDRESS_NOISE_PATTERN = re.compile(
    r"^(?:在|住在|我住在|我住|位于|位于中国|地址在|住址在|家住|家住在|现住|居住于|收货到|寄往|寄到|送到|派送至|发往|前往|来自|来自于|发自|到达)\s*"
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
    local_entity_ids: tuple[str, ...] = ()
    matched_by: str = "dictionary_local"
    confidence: float = 0.95
    metadata: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _LocalDictionaryEntry:
    value: str
    source_term: str
    binding_key: str
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


@dataclass(frozen=True, slots=True)
class _OCRScanDocument:
    line_index: int
    blocks: tuple[OCRTextBlock, ...]
    text: str
    char_refs: tuple[tuple[int, int] | None, ...]


_RULE_PROFILES = {
    ProtectionLevel.STRONG: _RuleStrengthProfile(
        level=ProtectionLevel.STRONG,
        enable_self_name_patterns=True,
        enable_honorific_name_pattern=True,
        enable_full_text_address=True,
        address_min_confidence=0.35,
        allow_weak_org_suffix=True,
    ),
    ProtectionLevel.BALANCED: _RuleStrengthProfile(
        level=ProtectionLevel.BALANCED,
        enable_self_name_patterns=True,
        enable_honorific_name_pattern=True,
        enable_full_text_address=True,
        address_min_confidence=0.45,
        allow_weak_org_suffix=True,
    ),
    ProtectionLevel.WEAK: _RuleStrengthProfile(
        level=ProtectionLevel.WEAK,
        enable_self_name_patterns=False,
        enable_honorific_name_pattern=False,
        enable_full_text_address=False,
        address_min_confidence=0.6,
        allow_weak_org_suffix=False,
    ),
}


class RuleBasedPIIDetector:
    """同时处理 prompt 与 OCR 文本的规则检测器。"""

    def __init__(
        self,
        dictionary_path: str | Path | None = None,
        detector_mode: str = "rule_based",
        mapping_store: MappingStore | None = None,
    ) -> None:
        """初始化规则、词典与候选解析服务。"""
        self.detector_mode = detector_mode
        self.dictionary_path = self._resolve_dictionary_path(dictionary_path)
        self.dictionary = self._load_dictionary(self.dictionary_path)
        self.mapping_store = mapping_store
        self.resolver = CandidateResolverService()
        self.patterns = self._build_patterns()
        self.context_rules = self._build_context_rules()
        self.self_name_patterns = self._build_self_name_patterns()
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
    ) -> list[PIICandidate]:
        """对 prompt 与 OCR 两路输入执行候选识别。"""
        session_entries = self._session_dictionary_entries(session_id=session_id, turn_id=turn_id)
        local_entries = self.dictionary
        rule_profile = self._rule_profile(protection_level)
        candidates: list[PIICandidate] = []
        candidates.extend(
            self._scan_text(
                prompt_text,
                PIISourceType.PROMPT,
                bbox=None,
                block_id=None,
                session_entries=session_entries,
                local_entries=local_entries,
                rule_profile=rule_profile,
            )
        )
        candidates.extend(
            self._scan_ocr_documents(
                ocr_blocks,
                session_entries=session_entries,
                local_entries=local_entries,
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
                    binding_key=binding_key,
                    aliases=aliases,
                    local_entity_ids=local_entity_ids,
                    matched_by="dictionary_local",
                    confidence=0.99 if entity_id else 0.98,
                )
            )

    def _effective_dictionary(
        self,
        *,
        session_id: str | None,
        turn_id: int | None,
    ) -> dict[PIIAttributeType, list[_LocalDictionaryEntry]]:
        """合并本地隐私库与 session 历史映射构造本轮优先匹配词典。"""
        merged: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {
            attr_type: list(entries)
            for attr_type, entries in self.dictionary.items()
        }
        for attr_type, entries in self._session_dictionary_entries(session_id=session_id, turn_id=turn_id).items():
            merged.setdefault(attr_type, []).extend(entries)
        return merged

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
        turn_index: dict[tuple[PIIAttributeType, str], set[str]] = {}
        for record in sorted(records, key=lambda item: (item.turn_id, len(item.source_text)), reverse=True):
            if not record.source_text:
                continue
            canonical = canonicalize_pii_value(record.attr_type, record.source_text)
            if not canonical:
                continue
            key = (record.attr_type, canonical)
            aggregated.setdefault(key, record)
            turn_index.setdefault(key, set()).add(str(record.turn_id))
        session_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]] = {}
        for (attr_type, canonical), record in aggregated.items():
            metadata = {"session_turn_ids": sorted(turn_index.get((attr_type, canonical), set()))}
            session_entries.setdefault(attr_type, []).append(
                _LocalDictionaryEntry(
                    value=record.source_text,
                    source_term=canonical,
                    binding_key=f"session:{attr_type.value}:{canonical}",
                    matched_by="dictionary_session",
                    confidence=0.97,
                    metadata=metadata,
                )
            )
        return session_entries

    def _rule_profile(self, protection_level: ProtectionLevel | str) -> _RuleStrengthProfile:
        """把入参保护度归一到内部规则强度配置。"""
        if isinstance(protection_level, ProtectionLevel):
            return _RULE_PROFILES[protection_level]
        normalized = str(protection_level or ProtectionLevel.BALANCED.value).strip().lower()
        try:
            return _RULE_PROFILES[ProtectionLevel(normalized)]
        except ValueError:
            return _RULE_PROFILES[ProtectionLevel.BALANCED]

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
                (re.compile(r"(?<!\d)1[3-9]\d(?:[-\s]?\d{4}){2}(?!\d)"), "regex_phone_mobile_sep", 0.84),
                (re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)"), "regex_phone_landline", 0.78),
                (re.compile(r"(?<!\d)1[3-9]\d[-\s]?[*＊xX]{4}[-\s]?\d{4}(?!\d)"), "regex_phone_masked", 0.82),
            ],
            PIIAttributeType.EMAIL: [
                (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "regex_email", 0.85),
                (
                    re.compile(r"[A-Za-z0-9._%+\-]+\s*@\s*[A-Za-z0-9.\-]+\s*\.\s*[A-Za-z]{2,}"),
                    "regex_email_spaced",
                    0.82,
                ),
            ],
            PIIAttributeType.ID_NUMBER: [
                (
                    re.compile(r"(?<![\dXx])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"),
                    "regex_cn_id_18",
                    0.92,
                ),
                (
                    re.compile(
                        r"(?<![\dXx])[1-9]\d{5}(?:[\s\-]?(?:18|19|20)\d{2})(?:[\s\-]?(?:0[1-9]|1[0-2]))"
                        r"(?:[\s\-]?(?:0[1-9]|[12]\d|3[01]))(?:[\s\-]?\d{3})(?:[\s\-]?[\dXx])(?![\dXx])"
                    ),
                    "regex_cn_id_18_spaced",
                    0.9,
                ),
                (re.compile(r"(?<!\d)[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?!\d)"), "regex_cn_id_15", 0.82),
                (
                    re.compile(
                        r"(?<!\d)[1-9]\d{7}(?:[\s\-]?(?:0[1-9]|1[0-2]))(?:[\s\-]?(?:0[1-9]|[12]\d|3[01]))"
                        r"(?:[\s\-]?\d{3})(?!\d)"
                    ),
                    "regex_cn_id_15_spaced",
                    0.8,
                ),
                (re.compile(r"(?<![\dXx])[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}(?![\dXx])"), "regex_cn_id_masked", 0.86),
            ],
        }

    def _build_context_rules(self) -> list[tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]]:
        """构建基于字段上下文的检测规则。"""
        return [
            self._build_context_rule(
                keywords=_NAME_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.NAME,
                value_pattern=r"[A-Za-z][A-Za-z .'\-]{1,40}|[一-龥·\s]{2,12}|[一-龥][*＊xX某]{1,3}",
                confidence=0.90,
                matched_by="context_name_field",
                validator=self._is_name_candidate,
            ),
            self._build_context_rule(
                keywords=_ADDRESS_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ADDRESS,
                value_pattern=r"[A-Za-z0-9#\-－—()（）·\s一-龥]{2,80}",
                confidence=0.90,
                matched_by="context_address_field",
                validator=self._looks_like_address_candidate,
            ),
            self._build_context_rule(
                keywords=_PHONE_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.PHONE,
                value_pattern=r"[0-9*＊+\-()\s]{7,24}",
                confidence=0.88,
                matched_by="context_phone_field",
                validator=self._is_phone_candidate,
            ),
            self._build_context_rule(
                keywords=_EMAIL_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.EMAIL,
                value_pattern=r"[A-Za-z0-9._%+\-@\s]{5,80}",
                confidence=0.90,
                matched_by="context_email_field",
                validator=self._is_email_candidate,
            ),
            self._build_context_rule(
                keywords=_ID_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ID_NUMBER,
                value_pattern=r"[0-9Xx*＊\s\-]{6,32}",
                confidence=0.90,
                matched_by="context_id_field",
                validator=self._is_id_candidate,
            ),
            self._build_context_rule(
                keywords=_OTHER_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.OTHER,
                value_pattern=r"[A-Za-z0-9\-]{4,20}",
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
                re.compile(r"(?:我叫|名叫|叫做|我的名字是)\s*(?P<value>[一-龥·\s]{2,10}|[一-龥][*＊xX某]{1,3})"),
                "context_name_self_intro",
                0.78,
            ),
            (
                re.compile(r"(?:my\s+name\s+is)\s*(?P<value>[A-Za-z][A-Za-z .'\-]{1,40})", re.IGNORECASE),
                "context_name_self_intro_en",
                0.76,
            ),
        ]

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
        session_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        local_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        rule_profile: _RuleStrengthProfile,
    ) -> list[PIICandidate]:
        """对单段文本执行 session、本地词库与规则识别。"""
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
        self._collect_dictionary_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            dictionary_entries=session_entries,
        )
        protected_spans = self._protected_spans_from_dictionary_hits(collected)
        self._collect_dictionary_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            dictionary_entries=local_entries,
            skip_spans=protected_spans,
        )
        protected_spans = self._protected_spans_from_dictionary_hits(collected)
        self._collect_context_hits(collected, text, source, bbox, block_id, skip_spans=protected_spans)
        self._collect_regex_hits(collected, text, source, bbox, block_id, skip_spans=protected_spans)
        self._collect_name_hits(collected, text, source, bbox, block_id, skip_spans=protected_spans, rule_profile=rule_profile)
        self._collect_organization_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
        )
        self._collect_address_hits(
            collected,
            text,
            source,
            bbox,
            block_id,
            skip_spans=protected_spans,
            rule_profile=rule_profile,
        )
        return list(collected.values())

    def _scan_ocr_documents(
        self,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        local_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        rule_profile: _RuleStrengthProfile,
    ) -> list[PIICandidate]:
        """按视觉行聚合 OCR 文本后统一扫描，再映射回原始 block。"""
        remapped_candidates: list[PIICandidate] = []
        for document in self._build_ocr_scan_documents(ocr_blocks):
            document_candidates = self._scan_text(
                document.text,
                PIISourceType.OCR,
                bbox=None,
                block_id=None,
                session_entries=session_entries,
                local_entries=local_entries,
                rule_profile=rule_profile,
            )
            for candidate in document_candidates:
                remapped = self._remap_ocr_document_candidate(candidate, document)
                if remapped is not None:
                    remapped_candidates.append(remapped)
                remapped_candidates.extend(self._derive_address_fragment_candidates(candidate, document))
        return remapped_candidates

    def _build_ocr_scan_documents(self, ocr_blocks: list[OCRTextBlock]) -> list[_OCRScanDocument]:
        """把整页 OCR block 聚合成单个扫描文档，减少重复扫描成本。"""
        if not ocr_blocks:
            return []
        merged_chars: list[str] = []
        char_refs: list[tuple[int, int] | None] = []
        ordered_blocks: list[OCRTextBlock] = []
        lines = self._group_blocks_by_visual_line(ocr_blocks)
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
                        separator = self._cross_block_separator(prev_block, block)
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
            return []
        return [
            _OCRScanDocument(
                line_index=0,
                blocks=tuple(ordered_blocks),
                text="".join(merged_chars),
                char_refs=tuple(char_refs),
            )
        ]

    def _group_blocks_by_visual_line(self, ocr_blocks: list[OCRTextBlock]) -> list[list[OCRTextBlock]]:
        """按 bbox 的垂直重叠关系将 OCR block 近似聚成视觉行。"""
        sortable = [block for block in ocr_blocks if block.bbox is not None and block.text.strip()]
        sortable.sort(key=lambda item: (self._bbox_center_y(item.bbox), item.bbox.x))
        lines: list[list[OCRTextBlock]] = []
        for block in sortable:
            assigned = False
            for line in lines:
                if self._belongs_to_same_visual_line(line, block):
                    line.append(block)
                    line.sort(key=lambda item: item.bbox.x if item.bbox is not None else 0)
                    assigned = True
                    break
            if not assigned:
                lines.append([block])
        return lines

    def _belongs_to_same_visual_line(self, line: list[OCRTextBlock], block: OCRTextBlock) -> bool:
        """判断一个 OCR block 是否应并入已有视觉行。"""
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

    def _merge_block_window_text(
        self,
        blocks: list[OCRTextBlock],
    ) -> tuple[str, list[tuple[int, int] | None]]:
        """将相邻 block 窗口拼接成文本，并保留字符到 block 的映射。"""
        merged_chars: list[str] = []
        char_refs: list[tuple[int, int] | None] = []
        for index, block in enumerate(blocks):
            if index > 0:
                separator = self._cross_block_separator(blocks[index - 1], block)
                if separator:
                    merged_chars.append(separator)
                    char_refs.append(None)
            for char_index, char in enumerate(block.text):
                merged_chars.append(char)
                char_refs.append((index, char_index))
        return "".join(merged_chars), char_refs

    def _cross_block_separator(self, left: OCRTextBlock, right: OCRTextBlock) -> str:
        """决定两个相邻 block 在拼接时是否需要补空格。"""
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

    def _remap_ocr_document_candidate(
        self,
        candidate: PIICandidate,
        document: _OCRScanDocument,
    ) -> PIICandidate | None:
        """将聚合 OCR 文档上的候选映射回单 block 或多 block 联合候选。"""
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
            extra_metadata["matched_by"] = ["cross_block_window"]
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

    def _derive_address_fragment_candidates(
        self,
        candidate: PIICandidate,
        document: _OCRScanDocument,
    ) -> list[PIICandidate]:
        """对跨 block 地址命中补充派生单 block 地址碎片，避免丢失原始块级信息。"""
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
                            "matched_by": ["cross_block_fragment"],
                            "ocr_block_ids": [block.block_id] if block.block_id else [],
                        },
                    ),
                )
            )
        return fragments

    def _collect_dictionary_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
        *,
        dictionary_entries: dict[PIIAttributeType, list[_LocalDictionaryEntry]],
        skip_spans: list[tuple[int, int]] | None = None,
    ) -> None:
        """收集本地字典命中。"""
        for attr_type, entries in dictionary_entries.items():
            pending_matches: list[_DictionaryMatch] = []
            for entry in entries:
                for matched_text, span_start, span_end in self._find_dictionary_matches(raw_text, attr_type, entry):
                    pending_matches.append(
                        _DictionaryMatch(
                            matched_text=matched_text,
                            span_start=span_start,
                            span_end=span_end,
                            source_term=entry.source_term,
                            binding_key=entry.binding_key,
                            local_entity_ids=entry.local_entity_ids,
                            matched_by=entry.matched_by,
                            confidence=entry.confidence,
                            metadata=dict(entry.metadata),
                        )
                    )
            for match in self._select_dictionary_matches(pending_matches):
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
                if not value or not validator(value):
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
                    confidence=confidence,
                    matched_by=matched_by,
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
                    self._upsert_candidate(
                        collected=collected,
                        text=raw_text,
                        matched_text=matched_text,
                        attr_type=attr_type,
                        source=source,
                        bbox=bbox,
                        block_id=block_id,
                        span_start=span_start,
                        span_end=span_end,
                        confidence=confidence,
                        matched_by=matched_by,
                        skip_spans=skip_spans,
                    )

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
    ) -> None:
        """收集姓名相关的上下文与敬称规则。"""
        if rule_profile.enable_self_name_patterns:
            for pattern, matched_by, confidence in self.self_name_patterns:
                for match in pattern.finditer(raw_text):
                    extracted = self._extract_match(raw_text, *match.span("value"))
                    if extracted is None:
                        continue
                    value, span_start, span_end = extracted
                    if not self._is_name_candidate(value):
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
                        skip_spans=skip_spans,
                    )
        if rule_profile.enable_honorific_name_pattern:
            for match in self.name_title_pattern.finditer(raw_text):
                extracted = self._extract_match(raw_text, *match.span("value"))
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if not self._looks_like_name_with_title(value):
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
    ) -> None:
        """收集地址整段与碎片命中。"""
        full_text_candidate = self._clean_address_candidate(raw_text)
        if rule_profile.enable_full_text_address and self._should_collect_full_text_address(raw_text, full_text_candidate, rule_profile=rule_profile):
            extracted = self._extract_match(raw_text, 0, len(raw_text), cleaner=self._clean_address_candidate)
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
                extracted = self._extract_match(raw_text, *match.span(0), cleaner=self._clean_address_candidate)
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
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
    ) -> None:
        """收集机构名后缀与就业/就读语境下的机构命中。"""
        for pattern in _ORGANIZATION_SPAN_PATTERNS:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(raw_text, *match.span(0), cleaner=self._clean_organization_candidate)
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
        return cleaned, absolute_start, absolute_end

    def _find_literal_matches(self, raw_text: str, needle: str) -> list[tuple[str, int, int]]:
        """在原文中查找字典项对应的全部匹配，并返回原文片段与 span。"""
        matches: list[tuple[str, int, int]] = []
        escaped = re.escape(needle)
        for match in re.finditer(escaped, raw_text, re.IGNORECASE):
            matched_text = raw_text[match.start():match.end()]
            matches.append((matched_text, match.start(), match.end()))
        return matches

    def _find_dictionary_matches(
        self,
        raw_text: str,
        attr_type: PIIAttributeType,
        entry: _LocalDictionaryEntry,
    ) -> list[tuple[str, int, int]]:
        """对本地隐私库词条执行容错匹配，并返回原文 span。"""
        if not entry.value:
            return []
        raw_match_text, index_map = build_match_text(attr_type, raw_text)
        if not raw_match_text:
            return []
        collected: list[tuple[str, int, int]] = []
        seen_spans: set[tuple[int, int]] = set()
        variants = sorted(
            self._dictionary_entry_variants(attr_type, entry),
            key=len,
            reverse=True,
        )
        for variant in variants:
            start_at = 0
            while start_at < len(raw_match_text):
                found_at = raw_match_text.find(variant, start_at)
                if found_at < 0:
                    break
                end_at = found_at + len(variant)
                raw_start = index_map[found_at]
                raw_end = index_map[end_at - 1] + 1
                span = (raw_start, raw_end)
                if span not in seen_spans:
                    collected.append((raw_text[raw_start:raw_end], raw_start, raw_end))
                    seen_spans.add(span)
                start_at = found_at + 1
        return collected

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

    def _protected_spans_from_dictionary_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
    ) -> list[tuple[int, int]]:
        """提取本地词库与 session 历史已命中的区间，供后续 rule 扫描避让。"""
        protected: list[tuple[int, int]] = []
        for candidate in collected.values():
            matched_by = candidate.metadata.get("matched_by", [])
            if not any(item.startswith("dictionary_") for item in matched_by):
                continue
            if candidate.span_start is None or candidate.span_end is None:
                continue
            protected.append((candidate.span_start, candidate.span_end))
        return protected

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

    def _is_phone_candidate(self, value: str) -> bool:
        """判断是否为手机号或座机片段。"""
        compact = re.sub(r"[\s\-()]+", "", value)
        return bool(
            re.fullmatch(r"1[3-9]\d{9}", compact)
            or re.fullmatch(r"1[3-9]\d[*＊xX]{4}\d{4}", compact)
            or re.fullmatch(r"0\d{9,11}", compact)
        )

    def _is_email_candidate(self, value: str) -> bool:
        """判断是否为邮箱。"""
        compact = re.sub(r"\s+", "", value)
        return bool(re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", compact))

    def _is_id_candidate(self, value: str) -> bool:
        """判断是否为身份证号或脱敏后的身份证号。"""
        compact = re.sub(r"[\s\-]+", "", value)
        return bool(
            re.fullmatch(r"[1-9]\d{16}[\dXx]", compact)
            or re.fullmatch(r"[1-9]\d{14}", compact)
            or re.fullmatch(r"[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}", compact)
        )

    def _is_other_candidate(self, value: str) -> bool:
        """判断是否为需要保守脱敏的编号类字段。"""
        compact = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9\-]{4,20}", compact):
            return False
        if self._is_phone_candidate(compact) or self._is_id_candidate(compact) or self._is_email_candidate(compact):
            return False
        digits_only = re.sub(r"\D", "", compact)
        if len(digits_only) < 4:
            return False
        return True

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
        return self._address_confidence(cleaned) >= min_confidence

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
        if len(cleaned) >= 6 and re.fullmatch(r"[A-Za-z0-9#\-－—()（）·\s一-龥]+", cleaned):
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
            collected[key] = incoming
            return
        previous.metadata = merged_metadata
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

    def _to_attr_type(self, raw_key: str) -> PIIAttributeType | None:
        """将字典键名映射为领域枚举。"""
        key = raw_key.strip().lower()
        mapping = {
            "name": PIIAttributeType.NAME,
            "phone": PIIAttributeType.PHONE,
            "email": PIIAttributeType.EMAIL,
            "address": PIIAttributeType.ADDRESS,
            "id_number": PIIAttributeType.ID_NUMBER,
            "id": PIIAttributeType.ID_NUMBER,
            "organization": PIIAttributeType.ORGANIZATION,
        }
        return mapping.get(key)
