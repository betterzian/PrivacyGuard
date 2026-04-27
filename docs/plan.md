# Plan: STRUCTURED 彻底去 label + 分档 validator + persona 独占弱形态 PII

## Context

用户核心原则：**可接受 NUMERIC/ALNUM 通用类型兜底，不可接受类型错识别**。

现状两个伤口：
1. **inspire 机制漂移**：`_try_inspire_promote`（[parser.py:701](privacyguard/infrastructure/pii/detector/parser.py:701)）对称 ±15 unit 窗口硬覆写 attr_type，在对话场景把数字误识为姓名等。
2. **structured label 不可靠**：phone/id/bank/passport/driver_license 的 label（`labels.json` 共 82 条）只要附近有数字就漂移，误分类率高；而这些类型要么能靠 validator 独立成立，要么能靠 persona 本地库精确匹配，label 没有实际贡献。

本次最终决策：

1. **精简 PII 类型集**：detector 主路径只输出 13 类 + persona 可额外输出 2 类。
   - 保留（detector + persona 共用）：`NAME, PHONE, BANK_NUMBER, ID_NUMBER, LICENSE_PLATE, EMAIL, ADDRESS, DETAILS, ORGANIZATION, TIME, AMOUNT, NUMERIC, ALNUM`
   - **保留但仅 persona 出口**：`PASSPORT_NUMBER, DRIVER_LICENSE`（美式驾照）
   - 移除：`TEXTUAL, OTHER`
2. **彻底移除 inspire 机制**：InspireEntry / InspireIndex / `_try_inspire_promote` 删除。未满足 `_has_label_boundary` 的 label 直接丢弃为普通文字。
3. **labels.json 全部保留**，但 **H 档 / persona 独占类 label 不再改 attr_type**：
   - `phone / id_number / bank_number / passport_number / driver_license` 的 label 仍作为 boundary 与 seed 切分信号留在流里；**不能**把 NUMERIC/ALNUM promote 为这些类型。
   - `email / license_plate` 的 label 作为独立 stack / strong-form 类型的入口提示，保留原有 promote 能力（形态极强，误分类风险低）。
   - 语义类 label（`name / organization / address / details` 等）保持现状，驱动对应 stack seed。
4. **H 档 validator 独立成立**：phone_cn / phone_us（白名单）/ id_cn / bank_luhn+IIN → `attr_locked=True`。
5. **弱形态 PII 的唯一来源是 persona**：PASSPORT_NUMBER / DRIVER_LICENSE 只通过 persona 本地词典的精确字符串匹配产出。detector 主路径（regex / validator / label）**不会**输出这两类。

带来的预期：STRUCTURED label 引发的类型错分归零；persona 用户自填的隐私字段仍能以原类型精确屏蔽；NUMERIC/ALNUM 兜底比例上升。

## 核心改动文件

- [enums.py](privacyguard/domain/enums.py) — 删除 TEXTUAL / OTHER
- [data/scanner_lexicons/labels.json](data/scanner_lexicons/labels.json) — **不改动**，所有词条保留
- [structured.py](privacyguard/infrastructure/pii/detector/stacks/structured.py) — validator 排序 + IIN 白名单；**`_try_label_bind` 重写**：按 label.attr_type 分档，H 档/persona 独占类禁止改 attr_type；EMAIL 保留原 promote；清理 passport/driver_license 占位符
- [parser.py](privacyguard/infrastructure/pii/detector/parser.py) — 删除 `_try_inspire_promote` 及 `_INSPIRE_*` 常量；StackContext 删除 inspire_index
- [models.py](privacyguard/infrastructure/pii/detector/models.py) — 删除 InspireEntry / InspireIndex / 相关函数；ClueBundle.inspire_index 字段删除；CandidateDraft 新增 `attr_locked: bool`
- [scanner.py](privacyguard/infrastructure/pii/detector/scanner.py) — `_sweep_pass1` 删除 inspire 降级分支；未满足 boundary 的 label 直接丢弃；`_sweep_resolve` 返回 `list[Clue]`；placeholder 表清理
- [stacks/base.py](privacyguard/infrastructure/pii/detector/stacks/base.py) — 删除 StackContext.inspire_index
- [stacks/organization_base.py](privacyguard/infrastructure/pii/detector/stacks/organization_base.py) — 删除 `_OrgEvidence.has_inspire` 分支
- [rule_based.py](privacyguard/infrastructure/pii/detector/rule_based.py) — persona slots 的 `passport_number` / `driver_license` 入口**保持原 attr_type**（persona 专用出口）；bank_number 不变
- [normalized_pii.py](privacyguard/utils/normalized_pii.py) / [generic_placeholder.py](privacyguard/domain/policies/generic_placeholder.py) / [pii_value.py](privacyguard/utils/pii_value.py) / [schemas.py](privacyguard/app/schemas.py) — 删除 TEXTUAL / OTHER 分支；PASSPORT / DRIVER_LICENSE 保留
- [de_model_runtime.py](privacyguard/infrastructure/decision/de_model_runtime.py) / [label_persona_mixed_engine.py](privacyguard/infrastructure/decision/label_persona_mixed_engine.py) — 同步删除 TEXTUAL / OTHER
- 评估脚本：加 `_normalize_attr_type` 映射层（TEXTUAL/OTHER → ALNUM），数据集文件不改
- 测试：新增 + 修改

## 规则矩阵

```
来源                  | attr_type                        | attr_locked
---------------------|----------------------------------|-------------
CN phone validator   | PHONE                            | True
US phone validator (白名单+N11+555 过滤) | PHONE         | True
CN ID 18/15 validator| ID_NUMBER                        | True
Luhn 13-19 + IIN 白名单| BANK_NUMBER                     | True
Luhn 无 IIN / 12-22  | NUMERIC                          | False   （宽 Luhn 分支删除）
独立 regex stack     | EMAIL / LICENSE_PLATE / TIME / AMOUNT | True
语义 label stack     | NAME / ORGANIZATION / ADDRESS / DETAILS | True
Persona 精匹配       | 原始 attr_type（含 PASSPORT/DRIVER） | True   （persona 出口豁免）
其他                 | NUMERIC / ALNUM                  | False
```

Label 处理规则（按 label.attr_type 分档）：

| label.attr_type 分组 | 对 NUMERIC/ALNUM candidate 的作用 | 对 attr_locked candidate | boundary 作用 |
|---|---|---|---|
| `{PHONE, ID_NUMBER, BANK_NUMBER}`（H 档） | **不改 attr_type**，只加 `label_clue_ids` + metadata `label_hint_attr` | 同 attr 记信号；异 attr 记 mismatch | 保留 |
| `{PASSPORT_NUMBER, DRIVER_LICENSE}`（persona 独占） | **不改 attr_type**，只加 metadata `label_hint_attr`（不附加 label_clue_ids 避免下游误绑） | 不应出现在 detector 主路径 | 保留 |
| `{EMAIL}` | 走现有 `_try_label_bind` promote 路径（形态含 @，误分类风险可忽略） | — | 保留 |
| `{LICENSE_PLATE}` | family=LICENSE_PLATE，由独立 LicensePlateStack 处理（非 StructuredStack） | — | 保留 |
| `{NAME, ORGANIZATION, ADDRESS, DETAILS}` | 走对应 stack seed 路径（现状保留） | — | 保留 |
| `{TIME, AMOUNT}` | 由独立 stack / regex 识别；label 若附带 attr_type 可作信号 | — | 保留 |
| `attr_type is None`（仅 boundary 词） | 不驱动任何 promote | — | 保留 |

## 实现步骤

### Step 1: Enum 精简（enums.py）

[enums.py:47-77](privacyguard/domain/enums.py:47) 仅删除：
```
TEXTUAL = "textual"   # 删
OTHER = "other"       # 删
```

保留 PASSPORT_NUMBER / DRIVER_LICENSE（供 persona 使用）。保留 BANK_NUMBER（validator 可产出）。

定义白名单：
```
# structured.py 顶部
ALLOWED_DETECTOR_OUTPUT_ATTRS = frozenset({
    NAME, PHONE, BANK_NUMBER, ID_NUMBER, LICENSE_PLATE, EMAIL,
    ADDRESS, DETAILS, ORGANIZATION, TIME, AMOUNT, NUMERIC, ALNUM,
})
PERSONA_ONLY_ATTRS = frozenset({PASSPORT_NUMBER, DRIVER_LICENSE})
```

`_commit_candidate`（[parser.py:718](privacyguard/infrastructure/pii/detector/parser.py:718)）加 assertion：
```
if candidate.source_kind not in _PERSONA_SOURCE_KINDS:
    assert candidate.attr_type in ALLOWED_DETECTOR_OUTPUT_ATTRS, \
        f"detector 主路径产出非法 attr_type: {candidate.attr_type}"
```
`_PERSONA_SOURCE_KINDS` 根据现有 persona 产出的 `source_kind` 值确定（搜 `rule_based.py` 中 `_scalar_slot_entries` 调用的 `matched_by` 常量）。

形态兜底分类器（[pii_value.py](privacyguard/utils/pii_value.py) 附近）的 TEXTUAL / OTHER 分支改为"不产生 candidate"（调用侧 skip）。

### Step 2: CandidateDraft.attr_locked（models.py）

```
@dataclass(slots=True)
class CandidateDraft:
    ...（现有字段保留）
    attr_locked: bool = False
```

删除：
- `InspireEntry` / `InspireIndex` / `build_inspire_index` / `_get_empty_inspire_index` / `_EMPTY_INSPIRE_INDEX`（[models.py:354-438](privacyguard/infrastructure/pii/detector/models.py:354)）
- `ClueBundle.inspire_index` 字段（[models.py:449](privacyguard/infrastructure/pii/detector/models.py:449)）

### Step 3: Validator 重排与加强（structured.py）

常量：
```
HIGH_TRUST_ATTRS = {PHONE, ID_NUMBER, BANK_NUMBER}

BANK_IIN_WHITELIST = [
    ("4",  (13, 19)),                                                     # Visa
    ("51", (16, 16)), ("52", (16, 16)), ("53", (16, 16)), ("54", (16, 16)), ("55", (16, 16)),
    *[(str(p), (16, 16)) for p in range(2221, 2721)],                     # Master 新段
    ("34", (15, 15)), ("37", (15, 15)),                                   # Amex
    ("62", (16, 19)),                                                     # UnionPay
    ("6011", (16, 16)), ("65", (16, 16)),                                 # Discover
    *[(str(p), (16, 16)) for p in range(3528, 3590)],                     # JCB
]

US_NANP_INVALID_NPA = {"211","311","411","511","611","711","811","911"}
US_NANP_INVALID_NXX_PREFIX = "555"
```

`_route_validators` 按 phone → id → luhn 顺序（[structured.py:108](privacyguard/infrastructure/pii/detector/stacks/structured.py:108)）：
```
def _route_validators(*, digits, text, fragment_type) -> tuple[attr_type, source_kind] | None:
    if fragment_type == "NUM" and len(digits) == 11 and _validate_cn_phone(digits):
        return (PHONE, "validated_phone_cn")
    if fragment_type == "NUM" and len(digits) == 10 and _validate_us_phone_strict(digits):
        return (PHONE, "validated_phone_us")
    if (len(digits) == 18 or is_cn_id_alnum) and _validate_cn_id_18(...):
        return (ID_NUMBER, "validated_id_cn_18")
    if len(digits) == 15 and _validate_cn_id_15(digits):
        return (ID_NUMBER, "validated_id_cn_15")
    if fragment_type == "NUM" and 13 <= len(digits) <= 19 and _luhn_valid(digits) and _match_bank_iin(digits):
        return (BANK_NUMBER, "validated_bank_number_pan")
    return None   # 宽 Luhn 分支彻底删除
```

删除 `_luhn_valid_wide` 函数及调用；`_LOOKUP_PLACEHOLDER_BY_ATTR`（[structured.py:14-23](privacyguard/infrastructure/pii/detector/stacks/structured.py:14)）里的 PASSPORT / DRIVER_LICENSE 两项删除（因为 detector 不会产出这两类）。

辅助：
```
def _validate_us_phone_strict(digits: str) -> bool:
    if len(digits) != 10 or digits[0] in "01":
        return False
    npa = digits[:3]
    nxx = digits[3:6]
    if npa in US_NANP_INVALID_NPA:
        return False
    if nxx.startswith(US_NANP_INVALID_NXX_PREFIX):
        return False
    return True

def _match_bank_iin(digits: str) -> bool:
    for prefix, (lo, hi) in BANK_IIN_WHITELIST:
        if digits.startswith(prefix) and lo <= len(digits) <= hi:
            return True
    return False
```

### Step 4: `_try_label_bind` 分档重写（structured.py）

[structured.py:199-239](privacyguard/infrastructure/pii/detector/stacks/structured.py:199) 保留方法，但 217-225 行的硬覆写按 label.attr_type 分档：

```
HIGH_TRUST_LABEL_ATTRS = {PHONE, ID_NUMBER, BANK_NUMBER}
PERSONA_ONLY_LABEL_ATTRS = {PASSPORT_NUMBER, DRIVER_LICENSE}
LABEL_PROMOTE_ALLOWED = {EMAIL}  # 形态强、label 误绑风险低

# 在识别到 candidate (value 类 clue) 后：
target_attr = self.clue.attr_type

if candidate.attr_type in {NUMERIC, ALNUM}:
    if target_attr in HIGH_TRUST_LABEL_ATTRS:
        # H 档：绝不改 attr_type；只记 hint
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata,
            {"label_hint_attr": [target_attr.value]})
    elif target_attr in PERSONA_ONLY_LABEL_ATTRS:
        # persona 独占：不改 attr_type，也不绑 label_clue_ids（避免下游误判为 PII 实体）
        candidate.metadata = merge_metadata(candidate.metadata,
            {"label_hint_attr": [target_attr.value]})
    elif target_attr in LABEL_PROMOTE_ALLOWED:
        # EMAIL 等强形态：保留原 promote
        candidate.attr_type = target_attr
        candidate.attr_locked = True
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata,
            {"assigned_by_label_attr": [target_attr.value]})
    # 其余 attr_type 的 label 不应进入 StructuredStack（family 路由不同），忽略

elif candidate.attr_locked:
    if target_attr == candidate.attr_type:
        candidate.label_clue_ids.add(self.clue.clue_id)
        candidate.metadata = merge_metadata(candidate.metadata,
            {"bound_label_clue_ids": [self.clue.clue_id]})
    elif target_attr is not None:
        candidate.metadata = merge_metadata(candidate.metadata,
            {"label_attr_mismatch": [target_attr.value]})
```

labels.json **不改动**；EMAIL label 仍走 `family=STRUCTURED` → StructuredStack → 命中 `LABEL_PROMOTE_ALLOWED` 分支；其他 H 档 / persona 独占类 label 仍进入 `_try_label_bind`，但被分档拦住不改 attr_type。

### Step 5: 彻底移除 inspire 机制

1. **scanner.py**
   - `_sweep_pass1`（[scanner.py:2417](privacyguard/infrastructure/pii/detector/scanner.py:2417)）：删除 `inspire_entries` 收集；未满足 `_has_label_boundary` 的 label 直接 `continue`
   - `_sweep_resolve`（[scanner.py:2360](privacyguard/infrastructure/pii/detector/scanner.py:2360)）：返回值改为 `list[Clue]`
   - 删除 InspireEntry 相关 import / build_inspire_index 调用
   - `_LOOKUP_PLACEHOLDER_BY_ATTR`（[scanner.py:102-103](privacyguard/infrastructure/pii/detector/scanner.py:102)）删除 `PASSPORT_NUMBER` / `DRIVER_LICENSE` 两项（detector 不产出）；persona 路径自带 placeholder
2. **parser.py**
   - 删除 `_try_inspire_promote`、`_INSPIRE_PROMOTABLE_TYPES`、`_INSPIRE_TARGET_TYPES`（[parser.py:690-709](privacyguard/infrastructure/pii/detector/parser.py:690)）
   - `_commit_run` 删除 `self._try_inspire_promote(...)` 调用（[parser.py:714](privacyguard/infrastructure/pii/detector/parser.py:714)）
   - `StackContext.inspire_index` 字段删除（[parser.py:262](privacyguard/infrastructure/pii/detector/parser.py:262)）
   - `parse()` 构造 StackContext 时删除 `inspire_index=...`（[parser.py:363](privacyguard/infrastructure/pii/detector/parser.py:363)）
3. **stacks/base.py**：删除 `StackContext.inspire_index` 字段（[stacks/base.py:31](privacyguard/infrastructure/pii/detector/stacks/base.py:31)）
4. **stacks/organization_base.py**
   - 删除 `_OrgEvidence.has_inspire`
   - `_build_org_evidence`（[organization_base.py:361](privacyguard/infrastructure/pii/detector/stacks/organization_base.py:361)）删除 `has_inspire = ...`
   - `_meets_org_commit_threshold`（[organization_base.py:398](privacyguard/infrastructure/pii/detector/stacks/organization_base.py:398)）含 `has_inspire` 的两分支改写：
     - `suffix_only + SOFT + zh + BALANCED` 原需 has_inspire → 改为仅 STRONG 通过
     - `suffix_only + WEAK + en + STRONG` 原需 has_inspire → 改为拒绝
5. **models.py**：删除 InspireIndex 相关定义（Step 2 已列）

### Step 6: Persona 路径保持弱形态 PII 出口

[rule_based.py:124-125](privacyguard/infrastructure/pii/detector/rule_based.py:124) 不改动：
```
entries.extend(self._scalar_slot_entries(PIIAttributeType.PASSPORT_NUMBER, slots.passport_number, persona.persona_id))
entries.extend(self._scalar_slot_entries(PIIAttributeType.DRIVER_LICENSE, slots.driver_license, persona.persona_id))
```

persona 匹配出口 `source_kind` 设为 `persona` / `dictionary_session`（复核现有命名）。此 source_kind 加入 `_PERSONA_SOURCE_KINDS` 白名单，豁免 Step 1 的 assertion。

`persona.bank_number` 仍允许，匹配出口 `attr_type=BANK_NUMBER`，`attr_locked=True`。

### Step 7: 决策层 / 序列化层同步

- [normalized_pii.py:162](privacyguard/utils/normalized_pii.py:162)：删除 TEXTUAL / OTHER 分支；PASSPORT / DRIVER_LICENSE 保留
- [generic_placeholder.py:22,42](privacyguard/domain/policies/generic_placeholder.py:22)：删除 TEXTUAL / OTHER 项
- [schemas.py:25](privacyguard/app/schemas.py:25)：删除 TEXTUAL / OTHER 键
- [pii_value.py](privacyguard/utils/pii_value.py) / [de_model_runtime.py](privacyguard/infrastructure/decision/de_model_runtime.py) / [label_persona_mixed_engine.py](privacyguard/infrastructure/decision/label_persona_mixed_engine.py)：删除 TEXTUAL / OTHER 分支

### Step 8: 评估脚本映射层

评估数据集 [data/dataset/*.json](data/dataset/) 不改。评估脚本入口加：
```
_ATTR_NORMALIZE = {"textual": "alnum", "other": "alnum"}
def _normalize_attr_type(attr: str) -> str:
    return _ATTR_NORMALIZE.get(attr, attr)
```
ground truth 和 prediction 双侧对称映射。PASSPORT / DRIVER / BANK 不映射（仍按原类型对比）。

## 关键现成工具（可复用）

- `_resolve_fragment_candidate` — [structured.py:165](privacyguard/infrastructure/pii/detector/stacks/structured.py:165)
- `_try_convert_label_to_start` — [scanner.py:1796](privacyguard/infrastructure/pii/detector/scanner.py:1796)（保留）
- `_has_label_boundary` — [scanner.py:1772](privacyguard/infrastructure/pii/detector/scanner.py:1772)（保留）
- `_char_span_to_unit_span` — [scanner.py:1766](privacyguard/infrastructure/pii/detector/scanner.py:1766)
- `merge_metadata` — [metadata.py](privacyguard/infrastructure/pii/detector/metadata.py)
- `_scalar_slot_entries`（persona 出口）— [rule_based.py](privacyguard/infrastructure/pii/detector/rule_based.py)

## Verification

1. **Validator 收敛单测** — 新增 `tests/test_structured_validators_tightened.py`：
   - CN phone 138/199 通过；"12345678901" 拒绝
   - US phone "415-555-0199" 拒绝（555 交换码）；"211-xxx-xxxx" 拒绝（N11）；"415-555-2671"（非 555 交换码但 NPA 合法）中拒绝 555；"646-555-0199" 拒绝
   - CN ID 18 位校验位对 / 错
   - Luhn 16 位 "4111..." 通过（Visa IIN）；"9999 Luhn-过 16 位" 返回 None（保持 NUMERIC）
   - 12 位 Luhn、20 位 Luhn → 统一 NUMERIC（宽 Luhn 分支不复存在）

2. **STRUCTURED label 分档回归** — 新增 `tests/test_structured_label_bind_tiers.py`：
   - "手机: 13812345678" → PHONE（validator 命中）；label "手机" 进 `label_clue_ids`，但 attr_type 不由 label 决定
   - "手机: 1234"（4 位数字）→ **NUMERIC+LEN=4**；metadata 含 `label_hint_attr=phone`，attr_type 不被 promote
   - "身份证: 12345"（5 位）→ **NUMERIC+LEN=5**；label 不 promote
   - "银行卡: 4111111111111111" → BANK_NUMBER（validator + IIN）；label 同 attr 记信号
   - "银行卡: 4111111111111110"（Luhn 错）→ NUMERIC+LEN=16；label 不 promote
   - "护照号: E12345678"（无 persona）→ **ALNUM+LEN=9**；label 不 promote（persona 独占类）
   - Persona 配置 passport_number=`E12345678` 后再跑 → PASSPORT_NUMBER（persona 出口）
   - "邮箱: user@example.com" → EMAIL（EMAIL label 仍允许 promote，但形态本身含 `@` 锁死）
   - "订单号 4111111111111111"（恰好 Luhn + Visa IIN 前缀）→ BANK_NUMBER（已知限制，见风险 5）

3. **Inspire 移除回归** — 修改 `tests/test_stack_registry.py`：
   - 删除所有 `InspireIndex` / `InspireEntry` import；旧"label 降级为 inspire"用例改为"直接丢弃"
   - "B 说不回答姓名，电话是 13812345678" → 手机号识别为 PHONE；无漂移

4. **Persona 出口** — 新增 `tests/test_persona_only_attrs.py`：
   - Persona 配置 `passport_number="E12345678"` → 文本出现该字符串时输出 PASSPORT_NUMBER（不是 ALNUM）
   - 无 persona 配置时，文本中独立出现 "E12345678" → ALNUM（detector 主路径不识别护照）
   - Persona 配置 `driver_license="D12345678"` → 精匹配输出 DRIVER_LICENSE
   - Persona 配置 `bank_number="..."` → 原形态 validator 路径仍可独立匹配；persona 精匹配优先

5. **Enum 最小输出** — 新增 `tests/test_enum_minimal_outputs.py`：
   - 跑一组代表性输入，`{c.attr_type for c in candidates}` ⊆ `ALLOWED_DETECTOR_OUTPUT_ATTRS ∪ PERSONA_ONLY_ATTRS`
   - 无 persona 时 `⊆ ALLOWED_DETECTOR_OUTPUT_ATTRS`

6. **Organization 阈值回归** — 新增 `tests/test_org_threshold_no_inspire.py`：
   - 中文 `suffix_only SOFT BALANCED` → 拒绝
   - 英文 `suffix_only WEAK STRONG` → 拒绝
   - HARD suffix / VALUE+suffix / LABEL seed / STRONG 级别其他组合 → 不变

7. **评估映射** — 新增 `tests/test_eval_attr_normalize.py`：
   - `_normalize_attr_type("textual") == "alnum"`；`_normalize_attr_type("phone") == "phone"`
   - ground truth / prediction 双侧映射后指标可比

8. **端到端**：
   ```
   C:\Users\vis\.conda\envs\paddle\python.exe -m pytest tests/ -v
   ```
   手动抽样对比旧版 detector：类型错分用例数显著下降；NUMERIC/ALNUM 兜底比例上升；STRUCTURED label 相关 candidate 消失。

## 已知风险 / 潜在 BUG（本次不修，集中反馈）

1. `_try_convert_label_to_start` 仅识别 `是/is`，未覆盖 `叫/名叫/my name is/I'm/为`。词表扩充单独 PR。
2. `build_prompt_stream` 无 speaker/turn 切分；对话跨 turn 时语义类 label（NAME/ORG/ADDR/DETAILS）仍可能漂移。本次不处理。
3. 移除 inspire 后 Organization 召回下降（两个 suffix_only 分支）。若过低应扩 suffix 词典 / 加强 VALUE 共证，禁止恢复 inspire。
4. IIN 白名单为静态模块常量。号段变化需维护，后续抽到 data/ JSON。
5. **订单号/会员号恰好过 Luhn + IIN**：例如"4111 1111 1111 1111"作为订单号被识别为 BANK_NUMBER。因为移除了 label 通道，detector 无法区分"订单号"与"银行卡"。这是"不接受类型错识别"的边界：**属于形态高可信的误判**，非 label 漂移。若业务侧需要区分，可在下游按 `bound_label_clue_ids` / 上下文做二次标签（但不能回退到主路径 label 绑定）。
6. labels.json 全部保留，EMAIL / LICENSE_PLATE label 作为各自 stack 的入口提示；`_try_label_bind` 通过分档拦截 H 档 / persona 独占类的 promote，仍保留 EMAIL 的绑定路径。若未来新增"强形态、可 label 驱动"的类型，需同步扩 `LABEL_PROMOTE_ALLOWED`。
7. Persona 精匹配输出 PASSPORT / DRIVER 时必须带 `source_kind` 白名单，避免被 Step 1 的 assertion 误拦。实现时需核实现有 `_scalar_slot_entries` 产出的 source_kind 具体值。
8. 宽 Luhn `_luhn_valid_wide` 彻底删除；"非标银行账号 20 位"等场景一律 NUMERIC。若业务需要，后续在下游细分标签器做，禁止恢复宽 Luhn。
9. 评估映射仅处理 TEXTUAL/OTHER；PASSPORT/DRIVER 未在映射表中，意味着"旧版 detector 产出的 PASSPORT/DRIVER vs 新版 persona 产出的 PASSPORT/DRIVER"对比结果会因召回来源不同而变化。这是预期行为（召回从"form/label 猜测"转为"精确匹配"），但需在评估报告里说明。
10. `attr_locked` 必须覆盖所有 H 档 promote 分支与 persona 出口。`_commit_candidate` 的 assertion 保证 detector 主路径合法；persona 路径需在 `_scalar_slot_entries` 中显式设置 `attr_locked=True`。
11. `details` 词条若在 labels.json 存在需保留（语义类 DETAILS 依赖 label 启动）；实现前 grep 确认。