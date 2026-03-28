# Address Stack Migration Plan

## Goal

将当前新主链里的地址处理，改成以旧地址流实现为准。

这里的“以旧地址流为准”指的是：

1. 地址扫描先产出细粒度地址事件，而不是只产一个泛 `address anchor`
2. 地址栈内部按旧地址流的方式确定左边界、右边界、回退与截止
3. 地址 span 成功后，再按旧地址流的组件解析逻辑拆成省、市、区、路、小区、楼栋、房间等
4. 当前实现里凡与旧地址流冲突的地方，以旧地址流行为覆盖当前实现

## Current Problems

当前地址主链还有这几个核心问题：

1. 地址事件过粗，只有 `label` 和泛 `anchor`
2. `AddressStack` 仍然是事件触发式抽取，不是旧地址流那种组件驱动
3. 地址边界主要依赖局部窗口和轻量 plausibility，不是旧地址流的组件栈推进
4. 地址组件拆分不完整，更多是简化版 `ADDRESS + DETAILS`

## Target Architecture

地址处理改成三层：

1. 地址事件层
2. 地址栈层
3. 地址组件发射层

### 1. 地址事件层

输入原始文字流，先标出三类地址事件：

- `address_label`
  - 如 `地址:`、`家庭住址:`、`联系地址:`
- `address_component_name`
  - 如 `四川省`、`成都市`、`浦东新区`、`世纪大道`、`阳光小区`、`14栋`、`103室`
- `address_component_attr`
  - 弱后缀或弱组件触发位，作为左扩张起点

事件 payload 至少包含：

- `component_type`
- `component_strength`
- `trigger_kind`

### 2. 地址栈层

地址栈按旧地址流思路运行，但仍挂在当前 parser 下。

起栈分三类：

1. `label`
   - 从 label 右边开始
   - label 不进入地址值
2. `component_name`
   - 从当前组件位置开始
   - 视为已经命中真实地址组件
3. `component_attr`
   - 先做左边界扩张
   - 左边界扩张遵循旧地址流的硬停止、软停止和关键词校准

地址栈内部执行顺序：

1. 确定局部文本段
2. 调旧地址组件提取
3. 调旧地址事件流扫描构 span
4. 做旧地址尾部回退与右边界校准
5. 生成最终地址 span

### 3. 地址组件发射层

地址 span 成功后，走旧地址组件解析：

- `province`
- `city`
- `district`
- `street_admin`
- `town`
- `village`
- `street`
- `road`
- `compound`
- `building`
- `unit`
- `floor`
- `room`
- `postal_code`

然后映射成当前主链的 draft：

- 主地址段发 `ADDRESS`
- 细粒度楼栋/单元/楼层/房间发 `DETAILS`
- 其余组件发细粒度 `ADDRESS`

## File Changes

### `privacyguard/infrastructure/pii/detector/events.py`

要做的事：

1. 移除当前泛地址 anchor 扫描主路径
2. 接入旧地址组件扫描，生成细粒度地址事件
3. 地址 label 保留，但 payload 增加 `trigger_kind=label`
4. 地址组件事件 payload 增加：
   - `trigger_kind`
   - `component_type`
   - `component_strength`

### `privacyguard/infrastructure/pii/detector/stacks.py`

要做的事：

1. `AddressStack` 不再走轻量 `_expand_anchor_region + _is_plausible_address`
2. `AddressStack` 改成：
   - label 分支
   - component_name 分支
   - component_attr 分支
3. 地址 span 生成统一走旧地址流：
   - `build_text_input`
   - `collect_component_matches`
   - `scan_address_and_organization`
   - `parse_results_from_spans`
4. 仅复用旧地址 span 与组件逻辑
   - 不复用旧组织直接入库逻辑

### `privacyguard/infrastructure/pii/address/*`

保持旧地址流作为地址语义源，但修正被新主链清理时打断的共享依赖。

### `privacyguard/infrastructure/pii/detector/parser.py`

第一阶段不重写 parser 主框架，仍使用当前 `current/challenger` 两栈框架。

但地址 proposal 的来源改为：

- 由细粒度地址事件驱动
- 地址 span 内部按旧地址流生成

后续第二阶段再把地址栈进一步改成真正逐位置推进的活跃栈。

## Migration Order

1. 修复旧地址流在新主链下的依赖链
2. 重做地址事件层
3. 重做 `AddressStack`
4. 对齐地址组件发射
5. 跑地址相关冲突测试
6. 再补中文详细地址 smoke 与 OCR smoke

## Validation

至少验证这些场景：

1. `手机号码：13800138000`
   - 不能误打成地址
2. `家庭住址：上海市浦东新区世纪大道100号 13800138000`
   - 地址应在 phone 前硬停止
3. `四川省成都市阳光小区14栋103室`
   - 需要拆出主地址和细粒度 details
4. `Address: 123 Main St Apt 4B, Springfield, IL 62704`
   - 需要保留主地址与 `Apt 4B`
5. `浦东新区阳光科技有限公司`
   - 地址与组织冲突仍由当前冲突裁决处理

## Non-goals In This Step

这一轮不做：

1. 重写整个 parser 成逐字符地址活跃栈
2. 重写 OCR 纯距离归属
3. 对 name / organization / structured 栈做同等级别迁移

这一步只把地址栈迁到“旧地址流优先”的实现方式。
