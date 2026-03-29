# Address Event Stream Plan

## 目标

把当前地址主链改成真正的“扫描层只产地址事件，`AddressStack` 负责把事件长成地址”。

这版以以下规则为准：

1. 扫描层不提前产完整地址结果。
2. 扫描层不提前把 `103` 这类数字定性成 `room_name`。
3. 扫描层只产三类地址事件：
   - `label`
   - `geo name`
   - `geo attr`
4. `AddressStack` 负责：
   - 起栈
   - 左边界确定
   - 右边界扩张
   - 右边界回退
   - 组件写入 metadata
5. 主输出只有一个主 `ADDRESS`，组件只挂在 metadata。

## 扫描层

### 1. label

地址标签只负责给出“右侧应该启动地址栈”的信号。

示例：

- `地址`
- `家庭住址`
- `联系地址`

### 2. geo name

只对真正有独立地理语义的名称发 `name` 事件。

示例：

- `四川`
- `成都`
- `浦东`
- `世纪`

当前优先保留：

- `province`
- `city`
- `district`
- `street_admin`
- `town`
- `village`
- `road`

### 3. geo attr

对地址后缀属性词发 `attr` 事件。

示例：

- `省`
- `市`
- `区`
- `街道`
- `镇`
- `乡`
- `路`
- `大道`
- `小区`
- `栋`
- `单元`
- `层`
- `室`

### 禁止项

扫描层不直接发：

- `building_name = 14`
- `unit_name = 3`
- `room_name = 103`

这类值应由 `AddressStack` 在边界扩张后，从完整组件片段中解析得到。

## AddressStack

### 起栈

1. `label`
   - 从 label 右边开始
   - label 自身不进地址

2. `geo name`
   - 从当前组件起点开始
   - 这是一个显式地址起点

3. `geo attr`
   - 以当前组件为锚点起栈
   - 组件本身已经提供完整 span
   - 不把 `attr` 当作“反向取值器”

### 扩张

地址栈的主逻辑是按组件事件连续向右扩张。

判断是否继续吸收下一个组件时，只看：

1. 下一个组件是否是合法后继
2. 中间 gap 是否可桥接
3. 中间是否存在硬停止
4. 是否越过上层边界

一旦扩张到某个组件，就在栈内部同步写组件 metadata。

## 组件 metadata

对文本：

`四川省成都市阳光小区14栋103室`

主地址应为：

- `四川省成都市阳光小区14栋103室`

组件 metadata 应为：

- `province = 四川省`
- `city = 成都市`
- `compound = 阳光小区`
- `building = 14`
- `room = 103`

其中：

- 行政区、道路、小区这类组件保存完整组件文本
- `building/unit/floor/room` 这类精细位置保存规范化值

## 当前实现要调整的点

1. 地址扫描层不再对 `building/unit/floor/room` 发 `name` 事件，只发 `attr` 事件。
2. `compound` 默认只需要 `attr` 事件，不强制发 `name` 事件。
3. `AddressStack` 继续使用完整组件 span 做右扩张，但 metadata 取值规则要改成：
   - `province/city/district/street_admin/town/village/road/compound/postal_code/state/street` 记完整组件文本
   - `building/unit/floor/room` 记规范化值
4. 主地址仍然只输出一个 `ADDRESS` 候选。
