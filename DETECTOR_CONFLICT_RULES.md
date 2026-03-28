# Detector Conflict Rules

## 目标

本文件定义新 `detector/` 主链在文字流与 OCR 后处理阶段的冲突处理规则。

设计约束：

1. 不保留旧 detector 双轨兼容。
2. `prompt` 与 `ocr` 统一走同一套文字流主链。
3. 冲突尽量前置解决；只有必须依赖流式边界与栈状态的冲突才进入 parser。
4. OCR 几何归属只处理一维文字流结束后仍未解决的 ownership 冲突。

---

## 总体分层

### A. 预标注层

- `label-label`
- `hard-hard`

### B. 流边界层

- `hard-soft`
- `same-attr`

### C. 栈间让渡层

- `address-organization`
- `name-organization`
- `name-address`

### D. OCR ownership 层

- `ocr-geometry ownership`

---

## 1. label-label

### 规则

1. 所有 label 关键字预先按“字数/字符数降序”排序。
2. 同一位置只允许绑定一个 label。
3. 长 label 命中后，其 span 内不再允许短 label 再命中。
4. `label-label` 不进入 parser，不允许保留冲突状态。

### 例子

- `邮箱地址` 命中后，`地址` 不再命中。
- `company name` 命中后，`name` 不再命中。
- `家庭住址` 命中后，`住址` 与 `地址` 都不再命中。

### 实现层

- `detector/events.py`

---

## 2. hard-hard

### 定义

`hard` 只指强结构或强字典值：

- `session`
- `local`
- `prompt`
- `regex`

### 优先级

`session > local > prompt > regex`

### 规则

1. 后者不能占用前者。
2. 只有“后者规范化后更长”时，才允许替换前者。
3. 同源同位置重复命中时，保留更长的值。
4. `hard-hard` 在事件层完成，不进入多栈竞争。

### 说明

这里的 `prompt` 表示已经通过确定性方式从当前文字流中直接取出的强值，不是普通 soft label 提值。

### 实现层

- `detector/events.py`

---

## 3. hard-soft 边界冲突

### 定义

soft 栈在右扩或左扩过程中，碰到 hard claim。

### 规则

1. hard claim 是硬截止。
2. soft 栈碰到 hard claim 后必须立即停止扩张。
3. 停止后执行本栈的边界合规检查。
4. 第一版边界合规检查参考旧地址流的右边界处理思想：
   - OCR break 停止。
   - 新字段 label 停止。
   - email / phone / time / order / 价格类硬停停止。
   - 强断句符停止。

### 例子

文本：

```text
家庭住址：上海市浦东新区世纪大道100号 13800138000
```

处理：

1. 地址栈向右读取。
2. 读到手机号 hard claim。
3. 地址右边界硬截止在手机号前。
4. 地址再做一次右边界合规检查。

### 实现层

- `detector/parser.py`
- `detector/stacks.py`

---

## 4. same-attr 粒度冲突

### 定义

同一属性出现多个不同粒度的候选，彼此重叠，但不是语义打架。

### 子类型

#### 4.1 粗粒度 vs 细粒度

例子：

```text
家庭住址：123 Main St Apt 4B, Springfield, IL 62704
```

可同时得到：

- `ADDRESS = 123 Main St Apt 4B, Springfield, IL 62704`
- `ADDRESS = 123 Main St`
- `DETAILS = Apt 4B`

规则：

1. 最大合法 span 是主拥有者。
2. 细粒度组件可以保留，但不反抢主 span。
3. 细粒度只作为组件证据或子结果存在。

#### 4.2 组件合成更大主段

例子：

```text
姓 Foster 名 Brian
```

可同时得到：

- `NAME/family = Foster`
- `NAME/given = Brian`
- 合成 `NAME/full = Brian Foster`

规则：

1. `family/given/middle` 作为组件保留。
2. `full` 作为主结果。
3. 组件不和 full 抢 owner。

### 实现层

- `detector/parser.py`
- `detector/stacks.py`

---

## 5. address-organization 语义冲突

### 规则

1. 直接借鉴旧地址流思想，但重新实现。
2. 地址先按地址栈规则扩张。
3. 一旦组织后缀事件可触发 organization 左扩，就启动 organization 栈。
4. organization 左扩时允许地址让渡左边或尾部的一部分 span。
5. address 是否回退，取决于：
   - gap 是否允许。
   - 后缀是否足够强。
   - 当前地址尾组件类型。
   - 左扩后 organization 左边界是否合规。

### 典型例子

```text
浦东新区阳光科技有限公司
```

处理：

1. 地址先拿到 `浦东新区`。
2. `有限公司` 触发 organization 栈。
3. organization 向左扩张到 `阳光科技有限公司` 或更大合法 span。
4. 若左扩要求吞掉地址尾部，则地址回退让渡。

### 实现层

- `detector/stacks.py`
- `detector/parser.py`

---

## 6. name-organization 语义冲突

### 优先级

`name > organization`

### 规则

1. name 先进入硬阶段。
2. name 先做右边界合规检查。
3. 如果 name 在右边界上退回了某个尾部片段，则允许 organization 以该片段为起点做左扩。
4. organization 左扩后，再做左边界合规检查。

### 例子

```text
王伟工作室
```

处理：

1. name 先拿 `王伟工作室` 候选。
2. name 右边界检查发现 `工作室` 更像组织后缀，name 回退为 `王伟`。
3. organization 从 `工作室` 左扩，得到 `王伟工作室` 或 `工作室`。
4. organization 再做左边界合规检查。

### 实现层

- `detector/stacks.py`
- `detector/parser.py`

---

## 7. name-address 语义冲突

### 优先级

`address > name`

### 规则

1. 初始时 name 可先识别，但一旦与 address 冲突，name 必须先退回。
2. address 进行左边界扩张。
3. 若 address 左扩后继续覆盖 name，则 name 继续退回。
4. address 再继续左扩。
5. 直到 address 左边界停止扩张。
6. 如果 name 被多退了，允许 name 再做一次右边界恢复扩张。
7. name 恢复后必须重新做右边界合规检查。

### 例子

```text
朝阳路张三
```

处理目标：

1. address 先稳定成合法地址左段。
2. name 再尝试恢复成合法右段。
3. 两者边界最终不重叠。

### 实现层

- `detector/stacks.py`
- `detector/parser.py`

---

## 8. ocr-geometry ownership

### 规则

一个标签只归属一个值。

优先级顺序：

1. 若上方 label 已经有绑定值，则当前候选值优先归属另一个未绑定 label。
2. 若两个 label 都没有绑定值，则优先看当前 block 的属性段归属。
3. 若属性段归属也无法区分，再看几何距离。
4. 距离裁决函数第一版可以留空，只保留接口。

### 示例

场景：

- 上方是 `姓名`
- 下方是 `公司名称`
- 当前 block 为 `阳光工作室`

处理：

1. 若 `姓名` 已绑定其它值，则当前 block 归 `公司名称`。
2. 若都没绑定，则看当前 block 内属性线索。
3. `工作室` 是组织线索，因此归 `公司名称`。
4. 若既无线索又都未绑定，才进入距离函数。

### 实现层

- `detector/ocr.py`

---

## 代码落地顺序

1. 重构 `label-label` 与 `hard-hard`，让冲突前置消解。
2. 让 structured stack 支持 label 驱动的强值读取。
3. 在 parser 中加入 `hard-soft` 截止和同属性粒度保留规则。
4. 加入 `address-organization / name-organization / name-address` 的回退让渡接口。
5. 最后补 `ocr ownership` 的已绑定优先和属性段归属规则。

---

## 当前允许的非目标

1. 不要求本轮完全复刻旧 detector 行为。
2. 不要求本轮把距离函数做完。
3. 不要求本轮把所有英文 narrative label 误触发全部修净。
