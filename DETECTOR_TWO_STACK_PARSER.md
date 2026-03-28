# Detector Two-Stack Parser

## 目标

将当前 `detector/` 主链中的 parser 从“事件到候选的即时候选池裁决”改为“两栈流式状态机”。

第一版实现约束：

1. 任意时刻最多只有两个活跃栈。
2. `current_stack.start` 之前的内容都已经提交，不再回退。
3. 新属性点与当前栈属性不同，才允许开第二个挑战栈。
4. 挑战栈先按自身规则完成左边界扩张，再决定是否与当前栈发生裁决。
5. OCR 后处理仍放在文字流解析之后，不进入本状态机。

---

## 现状问题

当前 parser 的核心问题是：

1. 每个事件一到就立刻起栈、立刻 `extract()`、立刻进全局候选池。
2. 候选池里的 overlap 通过统一打分当场裁决。
3. 已扫描区域不是稳定状态，后续候选仍会回头删改更早候选。
4. 没有明确的 `commit_cursor / current_stack / challenger_stack`。

这不符合“流指针走到哪，当前栈之前的信息已经稳定提交”的目标。

---

## 新状态机

### 全局状态

- `commit_cursor`
- `current_stack`
- `challenger_stack`
- `committed_candidates`
- `pending_components`

其中：

- `commit_cursor` 左边的文本已经稳定提交。
- `current_stack` 表示当前拥有未决窗口的主栈。
- `challenger_stack` 只在异属性事件出现时临时存在。
- `pending_components` 用于保存随主结果一起提交的嵌套组件，如 `ADDRESS + DETAILS`。

### 活跃栈对象

活跃栈至少包含：

- `stack_id`
- `attr_type`
- `event`
- `primary`
- `nested`
- `start`
- `end`
- `safe_commit_end`
- `state`

字段含义：

- `primary` 是当前栈的主候选。
- `nested` 是允许嵌套保留的子候选。
- `start/end` 是当前栈的未决窗口。
- `safe_commit_end` 表示当前窗口内已经不会被未来挑战者改写的最右边界。第一版可保守取 `start`。

---

## 输入与输出

### 输入

parser 接收：

- `StreamInput`
- `EventBundle`

事件仍由 `events.py` 统一生成。

### 输出

parser 输出：

- 已提交的 `CandidateDraft`
- `Claim`
- `handled_label_ids`

但提交方式不再是“谁先来谁先进全局池”，而是：

1. 先进入活跃栈窗口。
2. 经由 `current/challenger` 裁决。
3. 当前栈稳定后再统一提交。

---

## 栈提案

第一版保留现有栈类的 `extract()` 能力，但不再直接把其输出 candidate 放进全局候选池。

改为：

1. `stack.extract()` 先返回候选列表。
2. parser 将这批候选包装成 `StackProposal`。
3. `StackProposal` 拆成：
   - `primary`
   - `nested`

规则：

1. `primary` 优先选最长的非 `DETAILS` 候选。
2. `nested` 保留与 `primary` 同事件、允许嵌套的其余候选。
3. 一个事件最多生成一个主提案；其余作为附属组件。

这保证 parser 始终只在“栈窗口”级别裁决，而不是在候选碎片级别乱打架。

---

## 运行时序

### 1. 没有当前栈

当没有 `current_stack` 时：

1. 读取下一个事件。
2. 若事件可生成 `StackProposal`，则直接设为 `current_stack`。
3. `commit_cursor` 保持不变。

### 2. 同属性事件

若新提案与 `current_stack.attr_type` 相同：

1. 不开挑战栈。
2. 直接尝试并入当前栈。
3. 允许：
   - same-attr 主 span 替换
   - 组件嵌套保留
   - 主 span 扩大

### 3. 异属性事件

若新提案属性与 `current_stack` 不同：

1. 新建 `challenger_stack`
2. `challenger_stack` 使用其自身左扩结果作为 `start`
3. 若 `challenger.start >= current.end`，说明只是顺序相邻，不冲突：
   - 先提交 `current_stack`
   - 再把 challenger 升为新的 `current_stack`
4. 若 `challenger.start < current.end`，说明发生边界重叠：
   - 进入冲突裁决

### 4. 提交当前栈

提交条件：

1. 已遇到下一个非重叠提案。
2. 当前栈被更强挑战者击败并收缩完毕。
3. 事件流结束。

提交内容：

1. `primary`
2. 允许嵌套保留的 `nested`
3. 对应 `Claim`

提交后：

- `commit_cursor = current_stack.end`
- `current_stack = None` 或切换为 challenger

---

## 冲突裁决

### A. hard-hard

规则不变：

- `session > local > prompt > regex`
- 仅当后者更长时才允许替换前者

处理方式：

1. 若 `current` 与 `challenger` 都是 hard：
2. 先比规范化长度
3. 长度相等再比 hard source rank

### B. hard-soft

规则：

1. hard 是 soft 的硬截止。
2. soft 栈被截断后要重新做本属性边界合规检查。

处理方式：

1. 若 `current` 是 soft，`challenger` 是 hard：
   - 截断 `current`
   - hard 成为新的拥有者
2. 若 `current` 是 hard，`challenger` 是 soft：
   - soft 只能保留 hard 区域外的合法部分

### C. same-attr

规则：

1. 同属性但不同粒度时，优先保留主 span。
2. 组件级候选可以作为 `nested` 共存。

处理方式：

1. 若可嵌套，则并入 `current_stack.nested`
2. 若不可嵌套，则由更完整主 span 替换主候选

### D. address-organization

规则：

1. organization 后缀足够强时，允许对 address 尾部发起挑战。
2. 地址只退当前未决窗口，不影响 `commit_cursor` 左边已提交部分。

处理方式：

1. `challenger` 为 organization 时，先看后缀强度。
2. 若 organization 左扩撞进 address 尾部：
   - address 尝试截掉重叠尾巴
   - organization 保留自身主 span
3. 若 address 截断后无合法剩余，则整段让渡

### E. name-organization

规则：

1. `name > organization`
2. 但当 organization 后缀明确时，name 需要先做右边界回退。

处理方式：

1. `current` 为 name，`challenger` 为 organization
2. 先把 name 截到组织后缀起点之前
3. 若 name 仍合法，则两者共存
4. 否则整段让给 organization

### F. name-address

规则：

1. `address > name`
2. address 可以持续吸收名称误判尾巴

处理方式：

1. `current` 为 address，`challenger` 为 name：
   - name 只能保留 address 外的合法残段
2. `current` 为 name，`challenger` 为 address：
   - 先裁 name
   - address 保留完整主 span

---

## 关键不变量

1. `commit_cursor` 左边永不回退。
2. 活跃栈最多两个。
3. 真正提交的对象只能来自 `current_stack`。
4. `challenger_stack` 不直接提交，只能：
   - 被丢弃
   - 升为新的 `current_stack`
   - 与 `current_stack` 在裁决后顺序共存

---

## 与当前栈接口的关系

第一版不强制把各属性栈重写成逐字符 `tick()`。

而是采用折中实现：

1. 栈仍按事件触发生成候选窗口。
2. parser 把候选窗口当成“栈提案”。
3. 两栈状态机管理的是“窗口竞争与提交”，不是“字符级别运行时”。

这样可以先把主链重构成正确的提交模型，再决定是否继续把各属性栈升级成真正的增量栈。

---

## 第一版实现步骤

1. 新增 `StackProposal` 与 `ActiveStackState`
2. 把现有 `stack.extract()` 结果包装成 proposal
3. 删除“直接把每个 candidate 提交到全局候选池”的 parser 主循环
4. 改成：
   - 事件 -> proposal
   - proposal -> current/challenger
   - 裁决 -> commit
5. 保留现有冲突规则函数，但改成面向 `current/challenger` 使用
6. 末尾 flush 最后一个 `current_stack`

---

## 验证重点

1. 已提交区域不会被后续事件改写
2. `hard-hard` 不再因 identical merge 提前短路
3. `ADDRESS + DETAILS` 仍能嵌套共存
4. `address-organization`
5. `name-organization`
6. `name-address`
7. OCR ownership 不受 parser 提交方式改变影响
