# rule_based_detector_shared.py L337–1291 符号引用清单

## 汇总（共 79 个符号）

| 归类 | 数量 | 含义 |
|------|------|------|
| **负向为主** | 20 | 黑名单、UI/电商噪声、非人名 token、负面右文、组织句噪等，多用于 **拒绝/降置信度/过滤** |
| **正向为主** | 55 | 字段关键词、内置地理/英文地名词表、Aho-Corasick 匹配器、姓名/地址/组织相关正则与后缀、姓名语境词等，多用于 **触发提取、加分、构造模式** |
| **结构/前处理（中性）** | 4 | OCR 断点、碎片分隔符、地址引导语剥离正则，**不切分正负向「线索」**，属切分与清洗 |

**负向（20）**：`_NAME_BLACKLIST`, `_NON_PERSON_TOKENS`, `_NON_PERSON_TOKENS_EN`, `_NON_PERSON_PHRASES_EN`, `_UI_NEGATIVE_TERMS_ZH`, `_UI_NEGATIVE_TERMS_EN`, `_UI_NEGATIVE_PHRASES_ZH`, `_UI_NEGATIVE_PHRASES_EN`, `_LOCATION_UI_NEGATIVE_TERMS_ZH`, `_LOCATION_UI_NEGATIVE_TERMS_EN`, `_LOCATION_UI_NEGATIVE_PHRASES_ZH`, `_LOCATION_UI_NEGATIVE_PHRASES_EN`, `_BUILTIN_UI_BLACKLIST_ZH`, `_BUILTIN_UI_BLACKLIST_EN`, `_NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS`, `_NAME_STANDALONE_NEGATIVE_SUFFIXES`, `_NAME_STANDALONE_NEGATIVE_SUFFIXES_EN`, `_GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS`, `_ORGANIZATION_BLACKLIST`, `_ORGANIZATION_SENTENCE_NOISE_TOKENS`

**正向（55）**：`_COMMON_COMPOUND_SURNAMES`, `_LOCATION_ACTIVITY_TOKENS`, `_BUILTIN_GEO_LEXICON`, `_BUILTIN_EN_GEO_LEXICON`, `_BUILTIN_EN_NAME_LEXICON`, `_COMMON_CITY_TOKENS`, `_COMMON_DISTRICT_TOKENS`, `_COMMON_BUSINESS_AREA_TOKENS`, `_GEO_LEXICON_ORDERED_TOKENS`, `_GEO_LEXICON_MATCHER`, `_EN_GEO_TIER_A_STATE_PATTERN`, `_EN_GEO_TIER_A_CODE_PATTERN`, `_EN_GEO_TIER_B_PATTERN`, `_EN_GEO_TIER_C_PATTERN`, `_EN_GEO_ALL_TOKENS`, `_TITLE_SEGMENT_PATTERN`, `_NAME_FIELD_KEYWORDS`, `_NAME_FAMILY_FIELD_KEYWORDS`, `_NAME_GIVEN_FIELD_KEYWORDS`, `_NAME_MIDDLE_FIELD_KEYWORDS`, `_ADDRESS_FIELD_KEYWORDS`, `_PHONE_FIELD_KEYWORDS`, `_CARD_FIELD_KEYWORDS`, `_BANK_ACCOUNT_FIELD_KEYWORDS`, `_PASSPORT_FIELD_KEYWORDS`, `_DRIVER_LICENSE_FIELD_KEYWORDS`, `_EMAIL_FIELD_KEYWORDS`, `_ID_FIELD_KEYWORDS`, `_OTHER_FIELD_KEYWORDS`, `_ORGANIZATION_FIELD_KEYWORDS`, `_NAME_HONORIFICS`, `_EN_NAME_HONORIFICS`, `_NAME_MATCH_IGNORABLE`, `_NAME_DICTIONARY_ALLOWED_NEXT_CHARS`, `_NAME_CONTEXT_PREFIX_TOKENS`, `_NAME_CONTEXT_CARRIER_TOKENS`, `_REGION_TOKENS`, `_EN_ADDRESS_STREET_SUFFIXES`, `_EN_ADDRESS_UNIT_TOKENS`, `_EN_ADDRESS_SUFFIX_PATTERN`, `_EN_ADDRESS_UNIT_PATTERN`, `_EN_ADDRESS_NUMBER_PATTERN`, `_EN_PO_BOX_PATTERN`, `_EN_STATE_OR_REGION_PATTERN`, `_EN_POSTAL_CODE_PATTERN`, `_ADDRESS_SUFFIX_PATTERN`, `_ADDRESS_NUMBER_PATTERN`, `_STANDALONE_ADDRESS_FRAGMENT_PATTERN`, `_SHORT_ADDRESS_TOKEN_PATTERN`, `_GENERIC_GEO_FRAGMENT_PATTERNS`, `_GENERIC_NUMBER_PATTERN`, `_ORGANIZATION_STRONG_SUFFIXES`, `_EN_ORGANIZATION_STRONG_SUFFIXES`, `_EN_ORGANIZATION_WEAK_SUFFIXES`, `_ORGANIZATION_WEAK_SUFFIXES`

**结构/中性（4）**：`_OCR_FRAGMENT_DELIMITERS`, `_OCR_SEMANTIC_BREAK_TOKEN`, `_LEADING_ADDRESS_NOISE_PATTERN`, `_LEADING_ADDRESS_NOISE_PATTERN_EN`

**主要消费模块**：`rule_based_detector_validation.py`（`*` 导入，体量最大）、`rule_based_detector_ocr.py`、`rule_based_detector_collectors.py`、`rule_based_detector_patterns.py`、`rule_based_detector_scan.py`、`rule_based_detector_dictionary.py`、`rule_based_detector.py`、`rule_based_detector_labels.py`；地址子系统：`address/lexicon.py`、`address/event_stream_scanner.py`；另有 `utils/pii_value.py` 内 **重复定义** 了一份 `_COMMON_COMPOUND_SURNAMES`（与 shared 内容应对齐）。

---

**说明**：「角色」按符号语义与命名归纳；「引用行提示」对单行做了粗分类（正向≈匹配/加分，负向≈拒绝/降权/黑名单）。逐符号的 **完整文件:行号与代码片段** 见下文各节。

## `_COMMON_COMPOUND_SURNAMES`
- **主要角色**: 正向为主
- **出现次数**: 共 7 处（本文件外 6 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector.py:38`  — 引用行中性/配置传递
    ```
                sorted((re.escape(item) for item in _COMMON_COMPOUND_SURNAMES), key=len, reverse=True)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:337` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_COMPOUND_SURNAMES = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:530`  — 引用行中性/配置传递
    ```
        is_compound = value[:2] in _COMMON_COMPOUND_SURNAMES
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:917`  — 引用行中性/配置传递
    ```
            if compact[:2] in _COMMON_COMPOUND_SURNAMES:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:933`  — 引用行中性/配置传递
    ```
        if compact[:2] in _COMMON_COMPOUND_SURNAMES and len(compact) == 2:
    ```
  - `privacyguard/utils/pii_value.py:210`  — 引用行中性/配置传递
    ```
    _COMMON_COMPOUND_SURNAMES = {
    ```
  - `privacyguard/utils/pii_value.py:1053`  — 引用行中性/配置传递
    ```
        if len(full_text) >= 3 and full_text[:2] in _COMMON_COMPOUND_SURNAMES:
    ```

## `_NAME_BLACKLIST`
- **主要角色**: 负向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:401` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_BLACKLIST = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:873`  — 引用行中性/配置传递
    ```
        if not compact or compact in _NAME_BLACKLIST:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:927`  — 引用行中性/配置传递
    ```
        if not compact or compact in _NAME_BLACKLIST or any(char.isdigit() for char in compact):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:951`  — 引用行中性/配置传递
    ```
        if not compact or compact in _NAME_BLACKLIST or any(char.isdigit() for char in compact):
    ```

## `_NON_PERSON_TOKENS`
- **主要角色**: 负向为主
- **出现次数**: 共 6 处（本文件外 5 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:422` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NON_PERSON_TOKENS = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:528`  — 引用行中性/配置传递
    ```
        if any(token in value for token in _NON_PERSON_TOKENS):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:877`  — 引用行中性/配置传递
    ```
        if compact in _NON_PERSON_TOKENS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:931`  — 引用行中性/配置传递
    ```
        if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:955`  — 引用行中性/配置传递
    ```
        if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1083`  — 引用行中性/配置传递
    ```
        if core in _NON_PERSON_TOKENS:
    ```

## `_NON_PERSON_TOKENS_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 7 处（本文件外 6 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:440` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NON_PERSON_TOKENS_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:344`  — 引用行偏负向/过滤
    ```
        return bool(tokens) and any(token in _NON_PERSON_TOKENS_EN or token in _UI_NEGATIVE_TERMS_EN for token in tokens)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:472`  — 引用行中性/配置传递
    ```
        if any(token in _NON_PERSON_TOKENS_EN for token in lowered_tokens):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:879`  — 引用行中性/配置传递
    ```
        if compact_lower in _NON_PERSON_TOKENS_EN:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:897`  — 引用行中性/配置传递
    ```
            if any(token.lower() in _NON_PERSON_TOKENS_EN for token in tokens):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:931`  — 引用行中性/配置传递
    ```
        if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:955`  — 引用行中性/配置传递
    ```
        if compact_lower in _NON_PERSON_TOKENS_EN or compact in _NON_PERSON_TOKENS:
    ```

## `_NON_PERSON_PHRASES_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:480` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NON_PERSON_PHRASES_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:339`  — 引用行中性/配置传递
    ```
        if lowered in _NON_PERSON_PHRASES_EN:
    ```

## `_UI_NEGATIVE_TERMS_ZH`
- **主要角色**: 负向为主
- **出现次数**: 共 4 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:1856`  — 引用行偏负向/过滤
    ```
        if compact in _UI_NEGATIVE_TERMS_ZH or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:498` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_ZH = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:662` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_ZH = frozenset(_UI_NEGATIVE_TERMS_ZH) \| _BUILTIN_UI_BLACKLIST_ZH.standalone_exact
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:301`  — 引用行偏负向/过滤
    ```
        if compact in _UI_NEGATIVE_TERMS_ZH:
    ```

## `_UI_NEGATIVE_TERMS_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 6 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:1860`  — 引用行偏负向/过滤
    ```
        return any(lowered.startswith(token) for token in _UI_NEGATIVE_TERMS_EN)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:536` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:663` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_EN = frozenset(_UI_NEGATIVE_TERMS_EN) \| _BUILTIN_UI_BLACKLIST_EN.standalone_exact
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:305`  — 引用行偏负向/过滤
    ```
        return any(token in lowered.split() for token in _UI_NEGATIVE_TERMS_EN)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:344`  — 引用行偏负向/过滤
    ```
        return bool(tokens) and any(token in _NON_PERSON_TOKENS_EN or token in _UI_NEGATIVE_TERMS_EN for token in tokens)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1021`  — 引用行偏负向/过滤
    ```
            if tokens and any(token in _UI_NEGATIVE_TERMS_EN for token in tokens):
    ```

## `_UI_NEGATIVE_PHRASES_ZH`
- **主要角色**: 负向为主
- **出现次数**: 共 5 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:1856`  — 引用行偏负向/过滤
    ```
        if compact in _UI_NEGATIVE_TERMS_ZH or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:567` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_ZH = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:664` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_ZH = frozenset(_UI_NEGATIVE_PHRASES_ZH) \| _BUILTIN_UI_BLACKLIST_ZH.standalone_contains
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:303`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1013`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```

## `_UI_NEGATIVE_PHRASES_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 6 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:1858`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:571` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:665` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_EN = frozenset(_UI_NEGATIVE_PHRASES_EN) \| _BUILTIN_UI_BLACKLIST_EN.standalone_contains
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:303`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:341`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1013`  — 引用行偏负向/过滤
    ```
        if lowered in _UI_NEGATIVE_PHRASES_EN or cleaned in _UI_NEGATIVE_PHRASES_ZH:
    ```

## `_LOCATION_UI_NEGATIVE_TERMS_ZH`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:579` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _LOCATION_UI_NEGATIVE_TERMS_ZH = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:318`  — 引用行偏负向/过滤
    ```
        if any(token in compact for token in _LOCATION_UI_NEGATIVE_TERMS_ZH):
    ```

## `_LOCATION_UI_NEGATIVE_TERMS_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:595` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _LOCATION_UI_NEGATIVE_TERMS_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:320`  — 引用行偏负向/过滤
    ```
        return any(token in lowered.split() for token in _LOCATION_UI_NEGATIVE_TERMS_EN)
    ```

## `_LOCATION_UI_NEGATIVE_PHRASES_ZH`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:611` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _LOCATION_UI_NEGATIVE_PHRASES_ZH = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:314`  — 引用行偏负向/过滤
    ```
        if any(phrase in cleaned for phrase in _LOCATION_UI_NEGATIVE_PHRASES_ZH):
    ```

## `_LOCATION_UI_NEGATIVE_PHRASES_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:618` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _LOCATION_UI_NEGATIVE_PHRASES_EN = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:316`  — 引用行偏负向/过滤
    ```
        if any(phrase in lowered for phrase in _LOCATION_UI_NEGATIVE_PHRASES_EN):
    ```

## `_LOCATION_ACTIVITY_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:624` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _LOCATION_ACTIVITY_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:291`  — 引用行中性/配置传递
    ```
        if any(compact.startswith(token) or compact_lower.startswith(token.lower()) for token in _LOCATION_ACTIVITY_TOKENS):
    ```

## `_OCR_FRAGMENT_DELIMITERS`
- **主要角色**: 结构/前处理（中性，或剥离噪声）
- **出现次数**: 共 3 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:655` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _OCR_FRAGMENT_DELIMITERS = "-－—_/\|｜"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:287`  — 引用行中性/配置传递
    ```
        compact = re.sub(rf"^[\s{re.escape(_OCR_FRAGMENT_DELIMITERS)}:：,，;；]+", "", value)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:573`  — 引用行中性/配置传递
    ```
            or right_char in _OCR_FRAGMENT_DELIMITERS
    ```

## `_OCR_SEMANTIC_BREAK_TOKEN`
- **主要角色**: 结构/前处理（中性，或剥离噪声）
- **出现次数**: 共 17 处（本文件外 16 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:15`  — 引用行中性/配置传递
    ```
    from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:178`  — 引用行中性/配置传递
    ```
            if text[max(0, pos - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : pos + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:220`  — 引用行中性/配置传递
    ```
            if text[max(0, pos - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : pos + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:561`  — 引用行中性/配置传递
    ```
        if _OCR_SEMANTIC_BREAK_TOKEN in gap:
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:592`  — 引用行中性/配置传递
    ```
            if text[max(0, i - len(_OCR_SEMANTIC_BREAK_TOKEN) + 1) : i + 1] == _OCR_SEMANTIC_BREAK_TOKEN:
    ```
  - `privacyguard/infrastructure/pii/address/input_adapter.py:4`  — 引用行中性/配置传递
    ```
    from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN
    ```
  - `privacyguard/infrastructure/pii/address/input_adapter.py:8`  — 引用行中性/配置传递
    ```
        return AddressInput(text=text or "", has_ocr_breaks=_OCR_SEMANTIC_BREAK_TOKEN in (text or ""))
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:18`  — 引用行中性/配置传递
    ```
        _OCR_SEMANTIC_BREAK_TOKEN,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:114`  — 引用行偏负向/过滤
    ```
        compact = text.replace(_OCR_SEMANTIC_BREAK_TOKEN, "").strip()
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:120`  — 引用行中性/配置传递
    ```
        break_index = text.find(_OCR_SEMANTIC_BREAK_TOKEN)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:38`  — 引用行中性/配置传递
    ```
                self._append_ocr_page_separator(merged_chars, char_refs, _OCR_SEMANTIC_BREAK_TOKEN)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:339`  — 引用行中性/配置传递
    ```
            return _OCR_SEMANTIC_BREAK_TOKEN
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:483`  — 引用行中性/配置传递
    ```
            return _OCR_SEMANTIC_BREAK_TOKEN
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:517`  — 引用行中性/配置传递
    ```
        return _OCR_SEMANTIC_BREAK_TOKEN
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_ocr.py:1594`  — 引用行中性/配置传递
    ```
                if separator == _OCR_SEMANTIC_BREAK_TOKEN:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:656` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _OCR_SEMANTIC_BREAK_TOKEN = " <OCR_BREAK> "
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:33`  — 引用行偏负向/过滤
    ```
        token = _OCR_SEMANTIC_BREAK_TOKEN.strip()
    ```

## `_BUILTIN_GEO_LEXICON`
- **主要角色**: 正向为主
- **出现次数**: 共 13 处（本文件外 7 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:12`  — 引用行中性/配置传递
    ```
        _BUILTIN_GEO_LEXICON,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:241`  — 引用行中性/配置传递
    ```
            if token in _BUILTIN_GEO_LEXICON.provinces:
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:243`  — 引用行中性/配置传递
    ```
            elif token in _BUILTIN_GEO_LEXICON.cities:
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:245`  — 引用行中性/配置传递
    ```
            elif token in _BUILTIN_GEO_LEXICON.districts:
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:247`  — 引用行中性/配置传递
    ```
            elif token in _BUILTIN_GEO_LEXICON.local_places:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:657` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _BUILTIN_GEO_LEXICON = _load_builtin_geo_lexicon()
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:666` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_CITY_TOKENS = set(_BUILTIN_GEO_LEXICON.cities)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:667` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_DISTRICT_TOKENS = set(_BUILTIN_GEO_LEXICON.districts)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:668` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_BUSINESS_AREA_TOKENS = set(_BUILTIN_GEO_LEXICON.local_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:669` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _GEO_LEXICON_ORDERED_TOKENS = _BUILTIN_GEO_LEXICON.ordered_tokens
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1112` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _REGION_TOKENS = set(_BUILTIN_GEO_LEXICON.provinces)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1217`  — 引用行中性/配置传递
    ```
            or any(token in visible for token in _BUILTIN_GEO_LEXICON.address_tokens)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1238`  — 引用行中性/配置传递
    ```
        if any(token in cleaned for token in _BUILTIN_GEO_LEXICON.address_tokens):
    ```

## `_BUILTIN_EN_GEO_LEXICON`
- **主要角色**: 正向为主
- **出现次数**: 共 16 处（本文件外 7 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:11`  — 引用行中性/配置传递
    ```
        _BUILTIN_EN_GEO_LEXICON,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:64`  — 引用行中性/配置传递
    ```
        rf"\b(?:{'\|'.join(sorted((re.escape(item) for item in (_BUILTIN_EN_GEO_LEXICON.tier_b_places \| _BUILTIN_EN_GEO_LEXICON.tier_c_places))
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:66`  — 引用行偏正向/匹配
    ```
    ) if (_BUILTIN_EN_GEO_LEXICON.tier_b_places or _BUILTIN_EN_GEO_LEXICON.tier_c_places) else re.compile(r"(?!x)x")
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:658` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _BUILTIN_EN_GEO_LEXICON = _load_builtin_en_geo_lexicon()
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:671` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_A_STATE_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_a_state_names)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:672` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_A_CODE_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_a_state_codes)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:673` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_B_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_b_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:674` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_C_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_c_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:676` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        _BUILTIN_EN_GEO_LEXICON.tier_a_state_names
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:677` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        \| _BUILTIN_EN_GEO_LEXICON.tier_a_state_codes
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:678` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        \| _BUILTIN_EN_GEO_LEXICON.tier_b_places
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:679` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        \| _BUILTIN_EN_GEO_LEXICON.tier_c_places
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:373`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_GEO_LEXICON.tier_a_state_names or lowered in _BUILTIN_EN_GEO_LEXICON.tier_a_state_codes:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:375`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_GEO_LEXICON.tier_b_places:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:377`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_GEO_LEXICON.tier_c_places:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:479`  — 引用行中性/配置传递
    ```
        if any(token in _BUILTIN_EN_GEO_LEXICON.tier_a_state_codes for token in lowered_tokens):
    ```

## `_BUILTIN_EN_NAME_LEXICON`
- **主要角色**: 正向为主
- **出现次数**: 共 7 处（本文件外 6 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:659` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _BUILTIN_EN_NAME_LEXICON = _load_builtin_en_name_lexicon()
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:349`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.given_tier_a:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:351`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.given_tier_b:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:353`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.given_tier_c:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:360`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.surname_tier_a:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:362`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.surname_tier_b:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:364`  — 引用行中性/配置传递
    ```
        if lowered in _BUILTIN_EN_NAME_LEXICON.surname_tier_c:
    ```

## `_BUILTIN_UI_BLACKLIST_ZH`
- **主要角色**: 负向为主
- **出现次数**: 共 5 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:14`  — 引用行中性/配置传递
    ```
        _BUILTIN_UI_BLACKLIST_ZH,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:141`  — 引用行中性/配置传递
    ```
        for keyword, expansions in _BUILTIN_UI_BLACKLIST_ZH.address_keyword_expansions.items():
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:660` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _BUILTIN_UI_BLACKLIST_ZH = _load_ui_keyword_blacklist("ui_keyword_blacklist_zh.json", lower=False)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:662` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_ZH = frozenset(_UI_NEGATIVE_TERMS_ZH) \| _BUILTIN_UI_BLACKLIST_ZH.standalone_exact
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:664` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_ZH = frozenset(_UI_NEGATIVE_PHRASES_ZH) \| _BUILTIN_UI_BLACKLIST_ZH.standalone_contains
    ```

## `_BUILTIN_UI_BLACKLIST_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 5 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:13`  — 引用行中性/配置传递
    ```
        _BUILTIN_UI_BLACKLIST_EN,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:156`  — 引用行中性/配置传递
    ```
        for keyword, expansions in _BUILTIN_UI_BLACKLIST_EN.address_keyword_expansions.items():
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:661` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _BUILTIN_UI_BLACKLIST_EN = _load_ui_keyword_blacklist("ui_keyword_blacklist_en.json", lower=True)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:663` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_TERMS_EN = frozenset(_UI_NEGATIVE_TERMS_EN) \| _BUILTIN_UI_BLACKLIST_EN.standalone_exact
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:665` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _UI_NEGATIVE_PHRASES_EN = frozenset(_UI_NEGATIVE_PHRASES_EN) \| _BUILTIN_UI_BLACKLIST_EN.standalone_contains
    ```

## `_COMMON_CITY_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:666` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_CITY_TOKENS = set(_BUILTIN_GEO_LEXICON.cities)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:885`  — 引用行中性/配置传递
    ```
        if compact in _COMMON_CITY_TOKENS or compact in _COMMON_DISTRICT_TOKENS or compact in _COMMON_BUSINESS_AREA_TOKENS:
    ```

## `_COMMON_DISTRICT_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:667` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_DISTRICT_TOKENS = set(_BUILTIN_GEO_LEXICON.districts)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:885`  — 引用行中性/配置传递
    ```
        if compact in _COMMON_CITY_TOKENS or compact in _COMMON_DISTRICT_TOKENS or compact in _COMMON_BUSINESS_AREA_TOKENS:
    ```

## `_COMMON_BUSINESS_AREA_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:668` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _COMMON_BUSINESS_AREA_TOKENS = set(_BUILTIN_GEO_LEXICON.local_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:885`  — 引用行中性/配置传递
    ```
        if compact in _COMMON_CITY_TOKENS or compact in _COMMON_DISTRICT_TOKENS or compact in _COMMON_BUSINESS_AREA_TOKENS:
    ```

## `_GEO_LEXICON_ORDERED_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 3 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:669` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _GEO_LEXICON_ORDERED_TOKENS = _BUILTIN_GEO_LEXICON.ordered_tokens
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:670` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _GEO_LEXICON_MATCHER = AhoCorasickMatcher(_GEO_LEXICON_ORDERED_TOKENS)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:293`  — 引用行中性/配置传递
    ```
        return any(compact.startswith(token) or compact_lower.startswith(token.lower()) for token in _GEO_LEXICON_ORDERED_TOKENS)
    ```

## `_GEO_LEXICON_MATCHER`
- **主要角色**: 正向为主
- **出现次数**: 共 3 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:209`  — 引用行偏正向/匹配
    ```
        from privacyguard.infrastructure.pii.rule_based_detector_shared import _GEO_LEXICON_MATCHER
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:237`  — 引用行偏正向/匹配
    ```
        for start, end, token in _GEO_LEXICON_MATCHER.finditer(text):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:670` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _GEO_LEXICON_MATCHER = AhoCorasickMatcher(_GEO_LEXICON_ORDERED_TOKENS)
    ```

## `_EN_GEO_TIER_A_STATE_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:15`  — 引用行偏正向/匹配
    ```
        _EN_GEO_TIER_A_STATE_PATTERN,
    ```
  - `privacyguard/infrastructure/pii/address/lexicon.py:62`  — 引用行偏正向/匹配
    ```
    _EN_STATE_NAME_RE = _EN_GEO_TIER_A_STATE_PATTERN
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:671` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_A_STATE_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_a_state_names)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1136`  — 引用行偏正向/匹配
    ```
        has_state_name = bool(_EN_GEO_TIER_A_STATE_PATTERN.search(cleaned))
    ```

## `_EN_GEO_TIER_A_CODE_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:672` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_A_CODE_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_a_state_codes)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1137`  — 引用行偏正向/匹配
    ```
        has_state_code = bool(_EN_GEO_TIER_A_CODE_PATTERN.search(cleaned))
    ```

## `_EN_GEO_TIER_B_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:673` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_B_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_b_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1138`  — 引用行偏正向/匹配
    ```
        has_major_place = bool(_EN_GEO_TIER_B_PATTERN.search(cleaned))
    ```

## `_EN_GEO_TIER_C_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:674` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_GEO_TIER_C_PATTERN = _compile_en_phrase_pattern(_BUILTIN_EN_GEO_LEXICON.tier_c_places)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1139`  — 引用行偏正向/匹配
    ```
        has_city_clue = bool(_EN_GEO_TIER_C_PATTERN.search(cleaned))
    ```

## `_EN_GEO_ALL_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:675` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _EN_GEO_ALL_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:906`  — 引用行中性/配置传递
    ```
                if token in _EN_GEO_ALL_TOKENS and self._english_given_name_weight(tokens[0]) <= 0.0 and self._english_surname_weight(tokens[0])
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:942`  — 引用行中性/配置传递
    ```
        if lowered in _EN_GEO_ALL_TOKENS and self._english_surname_weight(cleaned) <= 0.0:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:964`  — 引用行中性/配置传递
    ```
        if lowered in _EN_GEO_ALL_TOKENS and self._english_given_name_weight(cleaned) <= 0.0:
    ```

## `_TITLE_SEGMENT_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 1 处（本文件外 0 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:681` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _TITLE_SEGMENT_PATTERN = re.compile(r"[-—_\|｜/／]")
    ```

## `_NAME_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:17`  — 引用行偏正向/匹配
    ```
        _NAME_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:86`  — 引用行偏正向/匹配
    ```
            keywords=_NAME_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:260`  — 引用行偏正向/匹配
    ```
                    *_NAME_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:682` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _NAME_FIELD_KEYWORDS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1011`  — 引用行偏正向/匹配
    ```
        if compact in _ADDRESS_FIELD_KEYWORDS or compact in _NAME_FIELD_KEYWORDS:
    ```

## `_NAME_FAMILY_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:16`  — 引用行偏正向/匹配
    ```
        _NAME_FAMILY_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:53`  — 引用行偏正向/匹配
    ```
            keywords=_NAME_FAMILY_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:261`  — 引用行偏正向/匹配
    ```
                    *_NAME_FAMILY_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:712` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _NAME_FAMILY_FIELD_KEYWORDS = (
    ```

## `_NAME_GIVEN_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:18`  — 引用行偏正向/匹配
    ```
        _NAME_GIVEN_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:64`  — 引用行偏正向/匹配
    ```
            keywords=_NAME_GIVEN_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:262`  — 引用行偏正向/匹配
    ```
                    *_NAME_GIVEN_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:719` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _NAME_GIVEN_FIELD_KEYWORDS = (
    ```

## `_NAME_MIDDLE_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:19`  — 引用行偏正向/匹配
    ```
        _NAME_MIDDLE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:75`  — 引用行偏正向/匹配
    ```
            keywords=_NAME_MIDDLE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:263`  — 引用行偏正向/匹配
    ```
                    *_NAME_MIDDLE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:725` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _NAME_MIDDLE_FIELD_KEYWORDS = (
    ```

## `_ADDRESS_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 9 处（本文件外 8 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:10`  — 引用行偏正向/匹配
    ```
        _ADDRESS_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:10`  — 引用行偏正向/匹配
    ```
        _ADDRESS_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:97`  — 引用行偏正向/匹配
    ```
            keywords=_ADDRESS_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:264`  — 引用行偏正向/匹配
    ```
                    *_ADDRESS_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:730` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ADDRESS_FIELD_KEYWORDS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1011`  — 引用行偏正向/匹配
    ```
        if compact in _ADDRESS_FIELD_KEYWORDS or compact in _NAME_FIELD_KEYWORDS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1165`  — 引用行偏正向/匹配
    ```
        if cleaned in _ADDRESS_FIELD_KEYWORDS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1187`  — 引用行偏正向/匹配
    ```
        if cleaned in _ADDRESS_FIELD_KEYWORDS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1248`  — 引用行偏正向/匹配
    ```
        if any(keyword in cleaned for keyword in _ADDRESS_FIELD_KEYWORDS):
    ```

## `_PHONE_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:19`  — 引用行偏正向/匹配
    ```
        _PHONE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:23`  — 引用行偏正向/匹配
    ```
        _PHONE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:108`  — 引用行偏正向/匹配
    ```
            keywords=_PHONE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:265`  — 引用行偏正向/匹配
    ```
                    *_PHONE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:784` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _PHONE_FIELD_KEYWORDS = (
    ```

## `_CARD_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:655`  — 引用行偏正向/匹配
    ```
        if self._window_has_keywords(window, _CARD_FIELD_KEYWORDS):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:12`  — 引用行偏正向/匹配
    ```
        _CARD_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:118`  — 引用行偏正向/匹配
    ```
            keywords=_CARD_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:266`  — 引用行偏正向/匹配
    ```
                    *_CARD_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:802` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _CARD_FIELD_KEYWORDS = (
    ```

## `_BANK_ACCOUNT_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:657`  — 引用行偏正向/匹配
    ```
        if self._window_has_keywords(window, _BANK_ACCOUNT_FIELD_KEYWORDS):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:11`  — 引用行偏正向/匹配
    ```
        _BANK_ACCOUNT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:128`  — 引用行偏正向/匹配
    ```
            keywords=_BANK_ACCOUNT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:267`  — 引用行偏正向/匹配
    ```
                    *_BANK_ACCOUNT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:816` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _BANK_ACCOUNT_FIELD_KEYWORDS = (
    ```

## `_PASSPORT_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:22`  — 引用行偏正向/匹配
    ```
        _PASSPORT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:138`  — 引用行偏正向/匹配
    ```
            keywords=_PASSPORT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:268`  — 引用行偏正向/匹配
    ```
                    *_PASSPORT_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:833` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _PASSPORT_FIELD_KEYWORDS = (
    ```

## `_DRIVER_LICENSE_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:659`  — 引用行偏正向/匹配
    ```
        if self._window_has_keywords(window, _DRIVER_LICENSE_FIELD_KEYWORDS):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:13`  — 引用行偏正向/匹配
    ```
        _DRIVER_LICENSE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:148`  — 引用行偏正向/匹配
    ```
            keywords=_DRIVER_LICENSE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:269`  — 引用行偏正向/匹配
    ```
                    *_DRIVER_LICENSE_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:841` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _DRIVER_LICENSE_FIELD_KEYWORDS = (
    ```

## `_EMAIL_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:16`  — 引用行偏正向/匹配
    ```
        _EMAIL_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:14`  — 引用行偏正向/匹配
    ```
        _EMAIL_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:158`  — 引用行偏正向/匹配
    ```
            keywords=_EMAIL_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:270`  — 引用行偏正向/匹配
    ```
                    *_EMAIL_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:854` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EMAIL_FIELD_KEYWORDS = (
    ```

## `_ID_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 6 处（本文件外 5 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/lexicon.py:17`  — 引用行偏正向/匹配
    ```
        _ID_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:661`  — 引用行偏正向/匹配
    ```
        if self._window_has_keywords(window, _ID_FIELD_KEYWORDS):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:15`  — 引用行偏正向/匹配
    ```
        _ID_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:168`  — 引用行偏正向/匹配
    ```
            keywords=_ID_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:271`  — 引用行偏正向/匹配
    ```
                    *_ID_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:862` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ID_FIELD_KEYWORDS = (
    ```

## `_OTHER_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:668`  — 引用行偏正向/匹配
    ```
        return self._window_has_keywords(window, _OTHER_FIELD_KEYWORDS)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:21`  — 引用行偏正向/匹配
    ```
        _OTHER_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:178`  — 引用行偏正向/匹配
    ```
            keywords=_OTHER_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:272`  — 引用行偏正向/匹配
    ```
                    *_OTHER_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:876` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _OTHER_FIELD_KEYWORDS = (
    ```

## `_ORGANIZATION_FIELD_KEYWORDS`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:20`  — 引用行偏正向/匹配
    ```
        _ORGANIZATION_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_labels.py:188`  — 引用行偏正向/匹配
    ```
            keywords=_ORGANIZATION_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_patterns.py:273`  — 引用行偏正向/匹配
    ```
                    *_ORGANIZATION_FIELD_KEYWORDS,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:908` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ORGANIZATION_FIELD_KEYWORDS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1038`  — 引用行偏正向/匹配
    ```
        if self._window_has_keywords(window, _ORGANIZATION_FIELD_KEYWORDS):
    ```

## `_NAME_HONORIFICS`
- **主要角色**: 正向为主
- **出现次数**: 共 6 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector.py:43`  — 引用行中性/配置传递
    ```
                rf"(?:{'\|'.join(map(re.escape, _NAME_HONORIFICS))}))"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:943` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_HONORIFICS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:971` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        \| {item[0] for item in _NAME_HONORIFICS if item}
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:563`  — 引用行中性/配置传递
    ```
        if any(value.endswith(honorific) for honorific in _NAME_HONORIFICS) and not self._looks_like_name_with_title(value):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1076`  — 引用行中性/配置传递
    ```
        if not re.fullmatch(rf"[一-龥·]{{1,5}}(?:{'\|'.join(map(re.escape, _NAME_HONORIFICS))})", value):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1079`  — 引用行中性/配置传递
    ```
        for honorific in _NAME_HONORIFICS:
    ```

## `_EN_NAME_HONORIFICS`
- **主要角色**: 正向为主
- **出现次数**: 共 1 处（本文件外 0 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:955` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _EN_NAME_HONORIFICS = (
    ```

## `_NAME_MATCH_IGNORABLE`
- **主要角色**: 正向为主
- **出现次数**: 共 7 处（本文件外 6 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:968` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_MATCH_IGNORABLE = set(" \t\r\n\f\v\u3000·•・")
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:264`  — 引用行中性/配置传递
    ```
            if current in _NAME_MATCH_IGNORABLE:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:274`  — 引用行中性/配置传递
    ```
            if current in _NAME_MATCH_IGNORABLE:
    ```
  - `privacyguard/utils/pii_value.py:301`  — 引用行中性/配置传递
    ```
    _NAME_MATCH_IGNORABLE = _NAME_SPACE_CHARS \| set("·•・0123456789０１２３４５６７８９")
    ```
  - `privacyguard/utils/pii_value.py:736`  — 引用行中性/配置传递
    ```
                if normalized_char in (_NAME_MATCH_IGNORABLE - _NAME_SPACE_CHARS):
    ```
  - `privacyguard/utils/pii_value.py:769`  — 引用行偏负向/过滤
    ```
            if char not in _NAME_MATCH_IGNORABLE
    ```
  - `privacyguard/utils/pii_value.py:1861`  — 引用行中性/配置传递
    ```
            return char in _NAME_MATCH_IGNORABLE
    ```

## `_NAME_DICTIONARY_ALLOWED_NEXT_CHARS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:969` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_DICTIONARY_ALLOWED_NEXT_CHARS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:258`  — 引用行中性/配置传递
    ```
        return next_char in _NAME_DICTIONARY_ALLOWED_NEXT_CHARS
    ```

## `_NAME_CONTEXT_PREFIX_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:973` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_CONTEXT_PREFIX_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:569`  — 引用行中性/配置传递
    ```
        left_support = any(left_context.endswith(token) for token in (*_NAME_CONTEXT_PREFIX_TOKENS, *_NAME_CONTEXT_CARRIER_TOKENS))
    ```

## `_NAME_CONTEXT_CARRIER_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:995` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _NAME_CONTEXT_CARRIER_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:569`  — 引用行中性/配置传递
    ```
        left_support = any(left_context.endswith(token) for token in (*_NAME_CONTEXT_PREFIX_TOKENS, *_NAME_CONTEXT_CARRIER_TOKENS))
    ```

## `_NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1014` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:576`  — 引用行偏负向/过滤
    ```
        if any(right_context.startswith(token) for token in _NAME_NEGATIVE_RIGHT_CONTEXT_TOKENS) and not left_support:
    ```

## `_NAME_STANDALONE_NEGATIVE_SUFFIXES`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1028` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _NAME_STANDALONE_NEGATIVE_SUFFIXES = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:526`  — 引用行偏负向/过滤
    ```
        if any(value.endswith(suffix) for suffix in _NAME_STANDALONE_NEGATIVE_SUFFIXES):
    ```

## `_NAME_STANDALONE_NEGATIVE_SUFFIXES_EN`
- **主要角色**: 负向为主
- **出现次数**: 共 1 处（本文件外 0 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1033` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _NAME_STANDALONE_NEGATIVE_SUFFIXES_EN = (
    ```

## `_GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1042` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1111`  — 引用行偏负向/过滤
    ```
        if any(right_context.startswith(token) for token in _GEO_NEGATIVE_RIGHT_CONTEXT_TOKENS):
    ```

## `_ORGANIZATION_BLACKLIST`
- **主要角色**: 负向为主
- **出现次数**: 共 3 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1064` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _ORGANIZATION_BLACKLIST = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:993`  — 引用行中性/配置传递
    ```
        if not compact or compact in _ORGANIZATION_BLACKLIST:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1009`  — 引用行中性/配置传递
    ```
        if not compact or compact in _ORGANIZATION_BLACKLIST:
    ```

## `_ORGANIZATION_SENTENCE_NOISE_TOKENS`
- **主要角色**: 负向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1092` 【本文件定义/拼合】 — 引用行偏负向/过滤
    ```
    _ORGANIZATION_SENTENCE_NOISE_TOKENS = {
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1031`  — 引用行偏负向/过滤
    ```
            if any(token in compact for token in _ORGANIZATION_SENTENCE_NOISE_TOKENS):
    ```

## `_REGION_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1112` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _REGION_TOKENS = set(_BUILTIN_GEO_LEXICON.provinces)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:883`  — 引用行中性/配置传递
    ```
        if compact in _REGION_TOKENS:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1216`  — 引用行中性/配置传递
    ```
            or any(token in visible for token in _REGION_TOKENS)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1236`  — 引用行中性/配置传递
    ```
        if any(token in cleaned for token in _REGION_TOKENS):
    ```

## `_EN_ADDRESS_STREET_SUFFIXES`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1113` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _EN_ADDRESS_STREET_SUFFIXES = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1152` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"\b(?:{'\|'.join(map(re.escape, _EN_ADDRESS_STREET_SUFFIXES))})\.?\b",
    ```
  - `privacyguard/utils/pii_value.py:99`  — 引用行中性/配置传递
    ```
    _EN_ADDRESS_STREET_SUFFIXES = (
    ```
  - `privacyguard/utils/pii_value.py:279`  — 引用行中性/配置传递
    ```
        rf"\b(?:{'\|'.join(map(re.escape, _EN_ADDRESS_STREET_SUFFIXES))})\.?\b",
    ```
  - `privacyguard/utils/pii_value.py:290`  — 引用行中性/配置传递
    ```
        rf"(?:{'\|'.join(map(re.escape, _EN_ADDRESS_STREET_SUFFIXES))})\.?(?:\s+(?:N\|S\|E\|W\|NE\|NW\|SE\|SW))?"
    ```

## `_EN_ADDRESS_UNIT_TOKENS`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 0 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1140` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
    _EN_ADDRESS_UNIT_TOKENS = (
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1156` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"(?:\b(?:{'\|'.join(map(re.escape, _EN_ADDRESS_UNIT_TOKENS))})\.?\b\|\#)\s*[A-Za-z0-9\-]+",
    ```

## `_EN_ADDRESS_SUFFIX_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1151` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_ADDRESS_SUFFIX_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:414`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_SUFFIX_PATTERN.search(window) or _EN_POSTAL_CODE_PATTERN.search(window):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1144`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_SUFFIX_PATTERN.search(cleaned):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1154`  — 引用行偏正向/匹配
    ```
        if has_city_clue and (_EN_STATE_OR_REGION_PATTERN.search(cleaned) or has_state_name or has_state_code or _EN_POSTAL_CODE_PATTERN.search(
    ```

## `_EN_ADDRESS_UNIT_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1155` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_ADDRESS_UNIT_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1146`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_UNIT_PATTERN.search(cleaned):
    ```
  - `privacyguard/utils/pii_value.py:283`  — 引用行偏正向/匹配
    ```
    _EN_ADDRESS_UNIT_PATTERN = re.compile(
    ```
  - `privacyguard/utils/pii_value.py:1463`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_UNIT_PATTERN.fullmatch(text):
    ```
  - `privacyguard/utils/pii_value.py:1499`  — 引用行偏正向/匹配
    ```
        unit_match = _EN_ADDRESS_UNIT_PATTERN.search(cleaned)
    ```

## `_EN_ADDRESS_NUMBER_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1159` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_ADDRESS_NUMBER_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1142`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_NUMBER_PATTERN.search(cleaned):
    ```

## `_EN_PO_BOX_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1163` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_PO_BOX_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1140`  — 引用行偏正向/匹配
    ```
        if _EN_PO_BOX_PATTERN.search(cleaned):
    ```

## `_EN_STATE_OR_REGION_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 3 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1167` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_STATE_OR_REGION_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1148`  — 引用行偏正向/匹配
    ```
        if _EN_STATE_OR_REGION_PATTERN.search(cleaned) or has_state_name or has_state_code:
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1154`  — 引用行偏正向/匹配
    ```
        if has_city_clue and (_EN_STATE_OR_REGION_PATTERN.search(cleaned) or has_state_name or has_state_code or _EN_POSTAL_CODE_PATTERN.search(
    ```

## `_EN_POSTAL_CODE_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1171` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_POSTAL_CODE_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:414`  — 引用行偏正向/匹配
    ```
        if _EN_ADDRESS_SUFFIX_PATTERN.search(window) or _EN_POSTAL_CODE_PATTERN.search(window):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1150`  — 引用行偏正向/匹配
    ```
        if _EN_POSTAL_CODE_PATTERN.search(cleaned):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1154`  — 引用行偏正向/匹配
    ```
        if has_city_clue and (_EN_STATE_OR_REGION_PATTERN.search(cleaned) or has_state_name or has_state_code or _EN_POSTAL_CODE_PATTERN.search(
    ```

## `_ADDRESS_SUFFIX_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 5 处（本文件外 4 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1175` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ADDRESS_SUFFIX_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:887`  — 引用行偏正向/匹配
    ```
        if _ADDRESS_SUFFIX_PATTERN.search(compact):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1214`  — 引用行偏正向/匹配
    ```
            _ADDRESS_SUFFIX_PATTERN.search(compact)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1225`  — 引用行偏正向/匹配
    ```
        if _ADDRESS_SUFFIX_PATTERN.search(compact):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1235`  — 引用行偏正向/匹配
    ```
        suffix_hits = _ADDRESS_SUFFIX_PATTERN.findall(cleaned)
    ```

## `_ADDRESS_NUMBER_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 4 处（本文件外 3 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1179` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ADDRESS_NUMBER_PATTERN = re.compile(r"(?:\d{1,5}\|[A-Za-z]\d{1,5})(?:号院\|号楼\|栋\|幢\|座\|单元\|室\|层\|号\|户)")
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1215`  — 引用行偏正向/匹配
    ```
            or _ADDRESS_NUMBER_PATTERN.search(compact)
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1223`  — 引用行偏正向/匹配
    ```
        if _ADDRESS_NUMBER_PATTERN.search(compact):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1242`  — 引用行偏正向/匹配
    ```
        if _ADDRESS_NUMBER_PATTERN.search(cleaned):
    ```

## `_STANDALONE_ADDRESS_FRAGMENT_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1180` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _STANDALONE_ADDRESS_FRAGMENT_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1244`  — 引用行偏正向/匹配
    ```
        if _STANDALONE_ADDRESS_FRAGMENT_PATTERN.fullmatch(cleaned):
    ```

## `_SHORT_ADDRESS_TOKEN_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1184` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _SHORT_ADDRESS_TOKEN_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:1246`  — 引用行偏正向/匹配
    ```
        if _SHORT_ADDRESS_TOKEN_PATTERN.fullmatch(cleaned):
    ```

## `_GENERIC_GEO_FRAGMENT_PATTERNS`
- **主要角色**: 正向为主
- **出现次数**: 共 1 处（本文件外 0 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1187` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _GENERIC_GEO_FRAGMENT_PATTERNS = (
    ```

## `_GENERIC_NUMBER_PATTERN`
- **主要角色**: 正向为主
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_collectors.py:334`  — 引用行偏正向/匹配
    ```
        for match in _GENERIC_NUMBER_PATTERN.finditer(raw_text):
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1193` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _GENERIC_NUMBER_PATTERN = re.compile(r"(?<!\d)(?:\d(?:[\s\-－—_.,，。·•]?\d){3,})(?!\d)")
    ```

## `_LEADING_ADDRESS_NOISE_PATTERN`
- **主要角色**: 结构/前处理（中性，或剥离噪声）
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1194` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _LEADING_ADDRESS_NOISE_PATTERN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:234`  — 引用行中性/配置传递
    ```
        cleaned = _LEADING_ADDRESS_NOISE_PATTERN.sub("", cleaned)
    ```

## `_LEADING_ADDRESS_NOISE_PATTERN_EN`
- **主要角色**: 结构/前处理（中性，或剥离噪声）
- **出现次数**: 共 2 处（本文件外 1 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1197` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _LEADING_ADDRESS_NOISE_PATTERN_EN = re.compile(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:235`  — 引用行中性/配置传递
    ```
        cleaned = _LEADING_ADDRESS_NOISE_PATTERN_EN.sub("", cleaned)
    ```

## `_ORGANIZATION_STRONG_SUFFIXES`
- **主要角色**: 正向为主
- **出现次数**: 共 6 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:19`  — 引用行中性/配置传递
    ```
        _ORGANIZATION_STRONG_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:27`  — 引用行中性/配置传递
    ```
                *_ORGANIZATION_STRONG_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1201` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ORGANIZATION_STRONG_SUFFIXES = _tuple_org_suffixes_minus_address_keywords(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1293` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})$"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1296` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES))})$"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1304` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
            rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})"
    ```

## `_EN_ORGANIZATION_STRONG_SUFFIXES`
- **主要角色**: 正向为主
- **出现次数**: 共 7 处（本文件外 5 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:17`  — 引用行中性/配置传递
    ```
        _EN_ORGANIZATION_STRONG_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:29`  — 引用行中性/配置传递
    ```
                *_EN_ORGANIZATION_STRONG_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1234` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_ORGANIZATION_STRONG_SUFFIXES = _tuple_org_suffixes_minus_address_keywords(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1310` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
            rf"(?:{'\|'.join(map(re.escape, _EN_ORGANIZATION_STRONG_SUFFIXES + _EN_ORGANIZATION_WEAK_SUFFIXES))})\b",
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:475`  — 引用行偏负向/过滤
    ```
            token.rstrip(".") in {suffix.rstrip(".").lower() for suffix in (*_EN_ORGANIZATION_STRONG_SUFFIXES, *_EN_ORGANIZATION_WEAK_SUFFIXES)}
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:900`  — 引用行偏负向/过滤
    ```
                token.lower().rstrip(".") in {suffix.rstrip(".").lower() for suffix in (*_EN_ORGANIZATION_STRONG_SUFFIXES, *_EN_ORGANIZATION_WEA
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:979`  — 引用行中性/配置传递
    ```
        for suffix in _EN_ORGANIZATION_STRONG_SUFFIXES:
    ```

## `_EN_ORGANIZATION_WEAK_SUFFIXES`
- **主要角色**: 正向为主
- **出现次数**: 共 7 处（本文件外 5 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:18`  — 引用行中性/配置传递
    ```
        _EN_ORGANIZATION_WEAK_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:30`  — 引用行中性/配置传递
    ```
                *_EN_ORGANIZATION_WEAK_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1263` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _EN_ORGANIZATION_WEAK_SUFFIXES = _tuple_org_suffixes_minus_address_keywords(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1310` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
            rf"(?:{'\|'.join(map(re.escape, _EN_ORGANIZATION_STRONG_SUFFIXES + _EN_ORGANIZATION_WEAK_SUFFIXES))})\b",
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:475`  — 引用行偏负向/过滤
    ```
            token.rstrip(".") in {suffix.rstrip(".").lower() for suffix in (*_EN_ORGANIZATION_STRONG_SUFFIXES, *_EN_ORGANIZATION_WEAK_SUFFIXES)}
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:900`  — 引用行偏负向/过滤
    ```
                token.lower().rstrip(".") in {suffix.rstrip(".").lower() for suffix in (*_EN_ORGANIZATION_STRONG_SUFFIXES, *_EN_ORGANIZATION_WEA
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_validation.py:984`  — 引用行中性/配置传递
    ```
            for suffix in _EN_ORGANIZATION_WEAK_SUFFIXES:
    ```

## `_ORGANIZATION_WEAK_SUFFIXES`
- **主要角色**: 正向为主
- **出现次数**: 共 6 处（本文件外 2 处）
- **引用位置**:
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:20`  — 引用行中性/配置传递
    ```
        _ORGANIZATION_WEAK_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/address/event_stream_scanner.py:28`  — 引用行中性/配置传递
    ```
                *_ORGANIZATION_WEAK_SUFFIXES,
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1279` 【本文件定义/拼合】 — 引用行偏正向/匹配
    ```
    _ORGANIZATION_WEAK_SUFFIXES = _tuple_org_suffixes_minus_address_keywords(
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1293` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})$"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1299` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
        rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_WEAK_SUFFIXES))})$"
    ```
  - `privacyguard/infrastructure/pii/rule_based_detector_shared.py:1304` 【本文件定义/拼合】 — 引用行中性/配置传递
    ```
            rf"(?:{'\|'.join(map(re.escape, _ORGANIZATION_STRONG_SUFFIXES + _ORGANIZATION_WEAK_SUFFIXES))})"
    ```
