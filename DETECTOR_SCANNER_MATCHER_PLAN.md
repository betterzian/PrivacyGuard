# Detector Scanner Matcher 方案

## 目标

降低 scanner 在重复 `re.finditer` 循环上的耗时，同时修复 soft clue 扫描会看到 placeholder 的问题。

这份方案只改 scanner 层，不改 parser 和 stack 的行为。

## 当前问题

### 1. 整段文本被重复扫描

当前 scanner 的模式是“每个关键词扫一遍全文”。涉及：

- label
- name start 关键词
- family name
- company suffix
- 中文 geo value
- 中文 address key
- 英文 geo value
- 英文 address key

这是当前最主要的热点。

### 2. Placeholder 泄漏

soft clue 现在是扫 `shadow_text`，而 `shadow_text` 里会把 hard span 替换成可见 placeholder，比如 `<bank>`、`<email>`。

这样会让 soft scanner 在 placeholder 里再次命中，产生假的 clue，例如：

- `<bank>` 被扫成 `company_suffix(bank)`
- `<id>` 被扫出英文地址 / 州缩写碎片

### 3. Dynamic literal 重复编译

dictionary hard clue 目前在一次扫描里仍然会重复编译 literal regex。

## 目标设计

### 1. 先 hard clues，再做 hard-gap 分段

保留现有 hard clue pass：

- regex hard patterns
- session dictionary hard clues
- local dictionary hard clues

hard clue resolve 完成后，不再构造对 soft scan 可见的 placeholder 文本，而是把原始文本切成不包含 hard span 的若干 segment。

soft scanner 只在这些 segment 上运行。

效果：

- soft scanner 看不到 hard value
- 不再有 placeholder leakage
- 也不会因为“删掉 hard span 再拼回去”制造假的新邻接

### 2. 静态 label / keyword 词表改用 Aho-Corasick

引入一个可复用的 Aho-Corasick 多模式 matcher。

应用范围：

- label
- name-start 关键词
- family name
- company suffix
- 中文 geo value
- 中文 address key
- 英文 geo value
- 英文 address key

实现细节：

- 保留一套 exact matcher，处理原样 Unicode 字面匹配
- 保留一套 ASCII-boundary matcher，处理大小写不敏感的 token 匹配
- 两者都走统一的 `AhoMatcher` 抽象

### 3. 边界模型

`label` 和 `keyword` 在底层匹配规则上统一：

- ASCII 边界词：按 `[A-Za-z0-9]` 做 token boundary check
- 非 ASCII 词：直接字面匹配

差别只在 `ascii_boundary` 的来源：

- label：从 `LabelSpec` 显式读取
- keyword：按 keyword 的词面形态推断

### 4. Literal 策略

`literal` 不进入 Aho-Corasick 路径。

原因：

- 它是请求期动态数据
- 它承载 user/session value
- 它的边界字符集比 `label/keyword` 更宽

因此 `literal` 继续走 regex，但改成单次 `build_clue_bundle()` 生命周期内共享的 request-local cache，供 session/local dictionary 共用。

## 改造后的 Scanner 流程

```text
raw text
-> hard regex + dictionary literal scan
-> hard conflict resolve
-> 切成 non-hard scan segments
-> Aho-Corasick 扫静态 label/keyword families
-> regex 扫 break/postal 这类少量规则
-> merge + dedupe + sort clues
```

## 预期效果

### 正确性

- soft clue 不会再扫进 `<phone>`、`<email>`、`<bank>` 这类 hard placeholder
- 不再出现 `company_suffix(bank)` 这种 placeholder 派生假 clue
- label / keyword 的边界处理统一收敛到同一套 matcher 抽象

### 性能

- 把 `O(keyword_count * text_length)` 的逐词全文扫描，替换成按 family 的 `O(text_length + match_count)` matcher pass
- 静态 label / keyword 不再重复编译 regex
- dynamic literal 的编译成本被限制在单次扫描内

## 实现范围

### 新模块

- `privacyguard/infrastructure/pii/detector/matcher.py`

职责：

- trie 构建
- failure link 构建
- exact match 扫描
- ASCII-boundary 扫描
- boundary 过滤

### Scanner 改动

- 不再构造 soft scan 用的 `shadow_text`
- 从 raw text 构造 hard-gap scan segments
- 把逐关键词循环替换成 family 级 matcher 调用
- hard clue 对象保持不变
- break / postal 这类少量 regex 规则保持 regex 路径

### 测试

补 scanner 聚焦测试，覆盖：

- placeholder leakage 不再产出 company suffix 假 clue
- ASCII keyword 仍然保持大小写不敏感匹配
- label + hard structured 的绑定路径仍然正常

## 非目标

- 不改 parser
- 不调 priority
- 不改 candidate scoring
- 不引入外部依赖，比如 `pyahocorasick`
