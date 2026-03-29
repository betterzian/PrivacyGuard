# Detector Clue Schema Refactor Plan

## 目标

本次重构将 detector 的 `Clue` 从“字符串协议”改成“显式字段协议”。

重构后：

- 保留 `family` 作为 parser 路由入口
- 删除 `kind` 字符串编码
- 删除 `hard: bool`
- 删除 `payload` 杂物箱
- 保留 `label_clue_ids / handled_label_clue_ids` 绑定链
- `ClueBundle` 只保留 `all_clues`，`label_clues` 变成派生属性

## 目标结构

```python
class ClueRole(str, Enum):
    HARD = "hard"
    LABEL = "label"
    KEY = "key"
    VALUE = "value"
    START = "start"
    SURNAME = "surname"
    SUFFIX = "suffix"
    BREAK = "break"


class AddressComponentType(str, Enum):
    PROVINCE = "province"
    CITY = "city"
    DISTRICT = "district"
    STREET_ADMIN = "street_admin"
    TOWN = "town"
    VILLAGE = "village"
    ROAD = "road"
    STREET = "street"
    COMPOUND = "compound"
    BUILDING = "building"
    UNIT = "unit"
    FLOOR = "floor"
    ROOM = "room"
    STATE = "state"
    POSTAL_CODE = "postal_code"


class BreakType(str, Enum):
    OCR = "ocr"
    PUNCT = "punct"
    NEWLINE = "newline"


class NameComponentHint(str, Enum):
    FULL = "full"
    FAMILY = "family"
    GIVEN = "given"
    MIDDLE = "middle"


@dataclass(frozen=True, slots=True)
class Clue:
    clue_id: str
    family: ClueFamily
    role: ClueRole
    attr_type: PIIAttributeType | None
    start: int
    end: int
    text: str
    priority: int
    source_kind: str
    component_type: AddressComponentType | None = None
    component_hint: NameComponentHint | None = None
    break_type: BreakType | None = None
    hard_source: str | None = None
    placeholder: str | None = None
    ocr_source_kind: str | None = None
    source_metadata: dict[str, list[str]] = field(default_factory=dict)
```

## 约束

- 不保留旧 `kind` 兼容层
- 不保留旧 `payload.get(...)` 读取路径
- 不保留 `clue.hard`
- `CandidateDraft` 保留 `matched_by` 字段，避免扩大本轮重构面
- `CandidateDraft` 新增 `label_driven`

## 逐文件改造

### `privacyguard/infrastructure/pii/detector/models.py`

- 新增 `ClueRole`、`AddressComponentType`、`BreakType`、`NameComponentHint`
- 改写 `LabelSpec`
- 改写 `Clue`
- `CandidateDraft` 增加 `label_driven`
- `ClueBundle` 只保留 `all_clues`，增加 `label_clues` property

### `privacyguard/infrastructure/pii/detector/labels.py`

- `LabelSpec` 数据声明改为显式 `family`
- `component_hint` 使用 `NameComponentHint`

### `privacyguard/infrastructure/pii/detector/scanner.py`

- 所有 clue 构造改为新 schema
- `_scan_hard_patterns()` / `_scan_dictionary_hard_clues()` 发 `role=HARD`
- `_scan_label_clues()` 发 `role=LABEL`
- 地址 clues 发 `role=KEY/VALUE` 并显式写 `component_type`
- `_resolve_hard_conflicts()`、`_build_shadow_text()` 改读显式字段
- `_dedupe_clues()` 改为基于 `role/component_type/family`
- 删除 `_address_component_type()`

### `privacyguard/infrastructure/pii/detector/stacks.py`

- 所有基于 `kind` 的判断改为基于 `role`
- 所有基于 `payload` 的读取改为显式字段
- `StackManager.score()` 改为读 `candidate.label_driven`
- 删除 `_candidate_is_label_driven()`

### `privacyguard/infrastructure/pii/detector/ocr.py`

- 读取 `event.ocr_source_kind`、`event.component_hint`
- `bundle.label_clues` 改为 property 访问

### `privacyguard/infrastructure/pii/detector/parser.py`

- 逻辑基本不变
- 保持 `handled_label_clue_ids` 聚合链

### `tests/test_detector_conflict_rules.py`

- 更新直接构造的 `Clue(...)`
- 新增对 `label_clues` property、`label_driven` 评分、`_dedupe_clues()` 的回归测试

## 执行顺序

1. 先改 `models.py` 与 `labels.py`
2. 再改 `scanner.py`
3. 再改 `stacks.py` 与 `ocr.py`
4. 最后修 `parser.py` 与测试

## 验收

- 不再出现 `kind.startswith` / `kind.endswith`
- 不再出现 `clue.hard`
- 不再出现 `payload.get(...)`
- detector 相关测试通过
