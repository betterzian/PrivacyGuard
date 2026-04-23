# 地址 Label / Prefix-Key 收口重构方案

## Summary
- 地址字段标签与 prefix-key 完全分流。
- 严格字段写法里的地址 key 在 scanner 中升级为**地址专用 derived label**；升级后不再作为 `KEY`，而是 `LABEL direct`。
- 普通 prefix-key 不再走 shortcut，统一改为链式 flush；先校验右值 shape，再按 key 分类做 `hard/soft` 提升。
- 地址 `label` 自身不承载强度；它只把**后面首个真正起始并成功提交的地址段**提升到 `hard`。
- 删除旧兼容路径、冗余实现和死代码，不保留双轨。

## Key Changes
- Scanner 新增“地址 key -> derived label”专用派生规则，且判定比普通 direct 更严格。
  - 不复用通用 `_has_label_direct_seed_break_after`。
  - 只有满足地址专用边界时才升级。
  - `ocr_break` / `inline_gap` 路径：左右两边都必须紧邻 `ocr_break` 或 `inline_gap` 之一，允许混搭。
  - 空格路径：左右两边都必须是连续双空格。
  - 升级后的 clue 直接产出 `ClueRole.LABEL`，不再并存 `KEY`。
  - derived label 写入 `component_type/component_levels`，表示 label 后首段的期望层级；普通 label 保持 `None / ()`。
- 地址 stack 的 label-seed 路径新增“expected first component”入口。
  - label 后如果已有匹配的 ADDRESS clue，优先消费该 clue。
  - 没有 ADDRESS clue 时，只直接吸收第一个合法值。
  - 由 label 启动并成功提交的首个地址段，强度下限提升为 `hard`。
  - 这个 `hard floor` 只作用于首段；首段提交后立即清除，不向后续组件传播。
- 英文 prefix-key 去 shortcut，改成链式 flush。
  - 去掉 `is_prefix_en_key(...) -> _build_prefix_key_component(...) -> 直接 commit` 主路径。
  - 新增 `flush_chain_as_prefix_key`，让 prefix-key 也走统一的 flush / commit / rollback / occupancy / metadata 语义。
  - 为 prefix-key 增加 pending 右值状态，不再靠 raw text 宽切片直接构组件。
  - prefix-key 组件必须写入真实证据链，不再允许 `raw_chain` 为空。
- prefix-key 的 right-value 先做 shape 限制，再提强。
  - 不跨任何符号吸值。
  - 只看右边第一个实质 unit。
  - 只接受单段合法 `num/alnum`，以及受控的单段 `digit_run`。
  - 不接受内部空格拼接后的多段 numberish。
- 提强按 key 分类。
  - `apt/suite/rm/#` 等低歧义 key：合法单段值时可提升到 `hard`。
  - `unit` 等泛词：合法单段值时最多提升到 `soft`。
- 拆开 connector 规则。
  - `label connector` 继续允许字段连接符。
  - EN prefix-key 取值不再复用 `_skip_separators`，改为专用“无符号跨越”规则。
- 逗号语义共享化。
  - 出现逗号时强制 flush 当前 component。
  - 中文保留现有逗号 checkpoint / rollback。
  - 英文新增轻量逗号 prehandle，只负责切段和重置段内状态，不搬中文整套尾行政逻辑。
- 删除旧实现与死代码。
  - 删除 prefix-key shortcut 相关主路径。
  - 删除仅为旧 shortcut 服务、改造后不再使用的 helper / 分支 / 兼容判断。
  - 删除共享但语义过宽、改造后已无调用方的旧 separator 复用路径。
  - 测试同步移除旧行为假设，不保留兼容断言。

## Test Plan
- Derived label 升级条件。
  - 满足严格字段边界时，地址 key 能升级为 derived label。
  - 单侧 `ocr_break/inline_gap`、单空格、非双空格场景不得升级。
  - 普通 `Apt 8X` 不得误升为 label。
- Label 首段 hard floor。
  - `收货地址：上海` 输出 `address/hard`。
  - `上海` 无 label 时仍为 `soft`。
  - `收货地址：北京市朝阳区建国路88号` 保持 `hard`，且只把首段视为 label 驱动。
- Prefix-key 行为。
  - `Apt 8X`、`Suite 732` 能形成独立地址段。
  - `unit: Apt 8X` 不允许把 `Apt` 当值吸收。
  - `Suite 732 815 Madison Ave` 不得生成 `732815` 这类拼接值。
  - `unit 5B` 允许识别，但强度最多 `soft`。
- 逗号切段。
  - `Apt 8X, New York, NY 10003` 逗号前组件必须先提交。
  - 无逗号时仍允许继续向后接组件。
- 回归保护。
  - `景明路187号`、`住址道路：景明路187号。` 继续为 `hard`。
  - 中文逗号尾行政、英文 number promotion、现有负向修复能力不回退。

## Assumptions
- “label 对后面 start 位置的 unit 提升为 hard”按现有模型实现为：**label 启动的首个已提交地址段具有 `hard` 下限**，不新增独立 unit-strength 结构。
- `unit` 归入高歧义类，合法值时最多到 `soft`。
- 本次按开发版原则清理旧路径，不保留兼容分支或冗余 helper。
