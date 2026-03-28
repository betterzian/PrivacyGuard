# Detector Rewrite Plan

## Goal

重写当前 rule-based detector，实现新的分层架构：

1. `prompt / ocr` 统一预处理为 `StreamInput`
2. `stream` 层只负责事件构建、claim 管理、左到右调度
3. 各属性独立为栈类：`AddressStack` / `OrganizationStack` / `NameStack` / `StructuredValueStack`
4. OCR 几何归位与标签绑定放在文本解析之后

本次重写遵循：

- 旧 detector 代码整体归档到 `privacyguard/infrastructure/pii/detector.old/`
- 新代码全部生成在 `privacyguard/infrastructure/pii/detector/`
- 新实现可以参考旧思路，但不直接复用旧 detector 代码
- 保留当前对外入口：`privacyguard.infrastructure.pii.rule_based_detector.RuleBasedPIIDetector`

## New Directory Layout

```text
privacyguard/infrastructure/pii/
  detector.old/              # 旧实现归档
  detector/
    __init__.py
    models.py
    preprocess.py
    events.py
    stacks.py
    parser.py
    ocr.py
    rule_based.py
  rule_based_detector.py     # 薄包装，指向新 detector/rule_based.py
```

## Architecture

### 1. Preprocess Layer

职责：

- `prompt` 直接转换为 `StreamInput`
- `ocr_blocks` 重组为阅读序文字流
- 保留 `raw_text -> block_id / bbox` 映射

不负责：

- 属性识别
- 候选产出
- 几何裁决

### 2. Event Layer

事件类型：

- `HARD_VALUE`
- `LABEL`
- `ANCHOR`

职责：

- 产出强 regex 命中
- 产出标签事件
- 产出地址/组织/姓名 anchor 事件
- 产出 session/local dictionary 事件

不直接产出最终 candidate。

### 3. Stream Layer

职责：

- 维护游标
- 管理 `hard claim / soft claim`
- 开栈 / 切栈 / 回退 / finalize

输出：

- 文本层 `TextCandidate[]`

### 4. Stack Layer

#### StructuredValueStack

负责：

- 手机号
- 身份证号
- 邮箱
- 卡号 / 账号
- 护照 / 驾照

特点：

- span 固定
- 打开快
- finalize 快

#### AddressStack

负责：

- address label 右值读取
- 地址 anchor 连续生长
- building/unit/floor/room 等细节吸收

#### OrganizationStack

负责：

- organization label 右值
- suffix 触发左扩
- 与地址/姓名竞争

#### NameStack

负责：

- 姓名标签
- 自报前缀
- 敬称
- 姓氏启发式

### 5. OCR Layer

职责：

- 文本 span remap 回 block / bbox
- unresolved OCR label 几何绑定
- 同行右侧 / 下方 / continuation 搜索
- 多 block 候选合并

## Migration Steps

1. 归档旧 detector 文件到 `detector.old/`
2. 新建 `detector/` 包与基础模型
3. 实现 preprocess
4. 实现 event builder
5. 实现 stack classes
6. 实现 stream parser
7. 实现 OCR geometry post-pass
8. 用新 `RuleBasedPIIDetector` 接管入口
9. 编译与最小 smoke 验证

## Acceptance

至少满足：

- `prompt` 能识别基础 `phone / email / name / address`
- OCR 能走 `preprocess -> stream -> remap -> geometry bind`
- `RuleBasedPIIDetector.detect()` 可正常返回候选
- 旧 `_scan_text / _scan_ocr_page / old collectors` 不再参与主链

## Known Non-goals In This Rewrite

- 不追求旧行为完全兼容
- 不在本轮修所有误检 / 漏检
- 不保留旧 helper 双轨实现
