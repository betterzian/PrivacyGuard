"""基于规则与字典的 PII 检测器。"""

import json
import re
from pathlib import Path
from typing import Callable

from privacyguard.application.services.resolver_service import CandidateResolverService
from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.utils.text import normalize_text

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


class RuleBasedPIIDetector:
    """同时处理 prompt 与 OCR 文本的规则检测器。"""

    def __init__(self, dictionary_path: str | Path | None = None, detector_mode: str = "rule_based") -> None:
        """初始化规则、词典与候选解析服务。"""
        self.detector_mode = detector_mode
        self.dictionary_path = self._resolve_dictionary_path(dictionary_path)
        self.dictionary = self._load_dictionary(self.dictionary_path)
        self.resolver = CandidateResolverService()
        self.patterns = self._build_patterns()
        self.context_rules = self._build_context_rules()
        self.self_name_patterns = self._build_self_name_patterns()
        self.name_title_pattern = re.compile(
            rf"(?P<value>[一-龥·]{{2,5}}(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))}))"
        )

    def detect(self, prompt_text: str, ocr_blocks: list[OCRTextBlock]) -> list[PIICandidate]:
        """对 prompt 与 OCR 两路输入执行候选识别。"""
        candidates: list[PIICandidate] = []
        candidates.extend(self._scan_text(prompt_text, PIISourceType.PROMPT, bbox=None, block_id=None))
        for block in ocr_blocks:
            candidates.extend(self._scan_text(block.text, PIISourceType.OCR, bbox=block.bbox, block_id=block.block_id))
        return self.resolver.resolve_candidates(candidates)

    def _resolve_dictionary_path(self, dictionary_path: str | Path | None) -> Path:
        """解析字典路径并应用默认路径。PrivacyGuard 包根目录为 __file__ 上 3 级，其下 data/ 为词典目录。"""
        if dictionary_path is not None:
            return Path(dictionary_path)
        privacyguard_root = Path(__file__).resolve().parents[3]
        return privacyguard_root / "data" / "pii_dictionary.sample.json"

    def _load_dictionary(self, dictionary_path: Path) -> dict[PIIAttributeType, set[str]]:
        """读取 JSON 字典并映射到属性类型。"""
        if not dictionary_path.exists():
            print(f"[PrivacyGuard] rule_based 词典未找到，将仅使用正则: {dictionary_path}")
            return {}
        content = json.loads(dictionary_path.read_text(encoding="utf-8"))
        mapped: dict[PIIAttributeType, set[str]] = {}
        for raw_key, values in content.items():
            attr_type = self._to_attr_type(raw_key)
            if attr_type is None:
                continue
            mapped[attr_type] = {normalize_text(str(item)) for item in values}
        return mapped

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
            ],
            PIIAttributeType.ID_NUMBER: [
                (
                    re.compile(r"(?<![\dXx])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"),
                    "regex_cn_id_18",
                    0.92,
                ),
                (re.compile(r"(?<!\d)[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?!\d)"), "regex_cn_id_15", 0.82),
                (re.compile(r"(?<![\dXx])[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}(?![\dXx])"), "regex_cn_id_masked", 0.86),
            ],
            PIIAttributeType.OTHER: [
                (re.compile(r"(?<!\d)\d{4,8}(?!\d)"), "regex_code", 0.62),
            ],
        }

    def _build_context_rules(self) -> list[tuple[PIIAttributeType, re.Pattern[str], str, float, Callable[[str], bool]]]:
        """构建基于字段上下文的检测规则。"""
        return [
            self._build_context_rule(
                keywords=_NAME_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.NAME,
                value_pattern=r"[A-Za-z][A-Za-z .'\-]{1,40}|[一-龥·]{2,8}|[一-龥][*＊xX某]{1,3}",
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
                value_pattern=r"[A-Za-z0-9._%+\-@]{5,80}",
                confidence=0.90,
                matched_by="context_email_field",
                validator=self._is_email_candidate,
            ),
            self._build_context_rule(
                keywords=_ID_FIELD_KEYWORDS,
                attr_type=PIIAttributeType.ID_NUMBER,
                value_pattern=r"[0-9Xx*＊]{6,24}",
                confidence=0.90,
                matched_by="context_id_field",
                validator=self._is_id_candidate,
            ),
        ]

    def _build_self_name_patterns(self) -> list[tuple[re.Pattern[str], str, float]]:
        """构建自我介绍与口语化姓名规则。"""
        return [
            (
                re.compile(r"(?:我叫|我是|名叫|叫做|本人是|我的名字是)\s*(?P<value>[一-龥·]{2,5}|[一-龥][*＊xX某]{1,3})"),
                "context_name_self_intro",
                0.78,
            ),
            (
                re.compile(r"(?:my\s+name\s+is|i\s+am)\s*(?P<value>[A-Za-z][A-Za-z .'\-]{1,40})", re.IGNORECASE),
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

    def _scan_text(self, text: str, source: PIISourceType, bbox: object, block_id: str | None) -> list[PIICandidate]:
        """对单段文本执行字典、上下文与正则识别。"""
        normalized_text = normalize_text(text)
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate] = {}
        self._collect_dictionary_hits(collected, text, normalized_text, source, bbox, block_id)
        self._collect_context_hits(collected, text, source, bbox, block_id)
        self._collect_regex_hits(collected, text, source, bbox, block_id)
        self._collect_name_hits(collected, text, source, bbox, block_id)
        self._collect_address_hits(collected, text, source, bbox, block_id)
        return list(collected.values())

    def _collect_dictionary_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        normalized_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
    ) -> None:
        """收集本地字典命中。"""
        for attr_type, terms in self.dictionary.items():
            for term in terms:
                if not term or term not in normalized_text:
                    continue
                for matched_text, span_start, span_end in self._find_literal_matches(raw_text, term):
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
                        confidence=0.85,
                        matched_by="dictionary_exact",
                    )

    def _collect_context_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
    ) -> None:
        """收集字段上下文命中。"""
        for attr_type, pattern, matched_by, confidence, validator in self.context_rules:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(raw_text, *match.span("value"))
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
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
                )

    def _collect_regex_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
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
                    )

    def _collect_name_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
    ) -> None:
        """收集姓名相关的上下文与敬称规则。"""
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
                )
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
            )

    def _collect_address_hits(
        self,
        collected: dict[tuple[str, str, int | None, int | None], PIICandidate],
        raw_text: str,
        source: PIISourceType,
        bbox: object,
        block_id: str | None,
    ) -> None:
        """收集地址整段与碎片命中。"""
        full_text_candidate = self._clean_address_candidate(raw_text)
        if self._should_collect_full_text_address(raw_text, full_text_candidate):
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
                )
        for pattern in _ADDRESS_SPAN_PATTERNS:
            for match in pattern.finditer(raw_text):
                extracted = self._extract_match(raw_text, *match.span(0), cleaner=self._clean_address_candidate)
                if extracted is None:
                    continue
                value, span_start, span_end = extracted
                if not self._looks_like_address_candidate(value):
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
        return bool(re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", value))

    def _is_id_candidate(self, value: str) -> bool:
        """判断是否为身份证号或脱敏后的身份证号。"""
        compact = value.replace(" ", "")
        return bool(
            re.fullmatch(r"[1-9]\d{16}[\dXx]", compact)
            or re.fullmatch(r"[1-9]\d{14}", compact)
            or re.fullmatch(r"[1-9]\d{5}[*＊]{8,10}[\dXx]{2,4}", compact)
        )

    def _is_name_candidate(self, value: str) -> bool:
        """判断是否像姓名。"""
        cleaned = self._clean_extracted_value(value)
        compact = cleaned.replace(" ", "")
        if not compact or compact in _NAME_BLACKLIST:
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
        if re.fullmatch(r"[一-龥·]{2,8}", compact):
            if compact[:2] in _COMMON_COMPOUND_SURNAMES:
                return True
            return compact[0] in _COMMON_SINGLE_CHAR_SURNAMES or len(compact) <= 4
        return False

    def _looks_like_name_with_title(self, value: str) -> bool:
        """判断是否为带敬称的姓名片段。"""
        if not re.fullmatch(rf"[一-龥·]{{2,5}}(?:{'|'.join(map(re.escape, _NAME_HONORIFICS))})", value):
            return False
        core = value
        for honorific in _NAME_HONORIFICS:
            if core.endswith(honorific):
                core = core[: -len(honorific)]
                break
        return self._is_name_candidate(core)

    def _looks_like_address_candidate(self, value: str) -> bool:
        """判断是否像地址或地址碎片。"""
        cleaned = self._clean_address_candidate(value)
        if not cleaned or len(cleaned) > 80:
            return False
        if cleaned in _ADDRESS_FIELD_KEYWORDS:
            return False
        return self._address_confidence(cleaned) >= 0.45

    def _should_collect_full_text_address(self, raw_text: str, cleaned: str) -> bool:
        """仅在整段文本本身已经像独立地址片段时才直接收整段。"""
        if not self._looks_like_address_candidate(cleaned):
            return False
        base_text = self._clean_extracted_value(raw_text)
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
    ) -> None:
        """插入候选，或更新已存在候选的置信度与元信息。"""
        cleaned_text = self._clean_extracted_value(matched_text)
        if not cleaned_text:
            return
        normalized = normalize_text(cleaned_text)
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
            metadata={"matched_by": [matched_by]},
        )
        previous = collected.get(key)
        if previous is None:
            collected[key] = incoming
            return
        merged_matched_by = sorted(set(previous.metadata.get("matched_by", [])) | {matched_by})
        if incoming.confidence > previous.confidence:
            incoming.metadata = {"matched_by": merged_matched_by}
            collected[key] = incoming
            return
        previous.metadata = {"matched_by": merged_matched_by}
        if any(item.startswith("context_") for item in merged_matched_by) and any(item.startswith("regex_") for item in merged_matched_by):
            previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.08)
        elif "heuristic_address_fragment" in merged_matched_by and "regex_address_span" in merged_matched_by:
            previous.confidence = min(1.0, max(previous.confidence, incoming.confidence) + 0.06)

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
