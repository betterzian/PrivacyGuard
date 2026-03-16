# 第 3 轮：Persona 仓库与会话映射

## 可直接粘贴到 Cursor 的简短提示词

请只实现 **Persona Repository** 和 **Local Mapping Table / Session Binding** 相关能力，目标是支持会话级 persona 绑定与可恢复映射记录。  
不要提前实现完整决策引擎和渲染逻辑，只把仓库、存储、查询、写入、会话状态维护做好。

---

## 本轮目标

让系统具备以下能力：

- 可以从本地 JSON 读取 persona profile；
- 可以按 `persona_id + attr_type` 取槽位值；
- 可以保存会话级 `active_persona`；
- 可以按 `session_id / turn_id` 保存替换记录；
- 可以为后续 `API_2` 恢复过程提供查询依据。

---

## 必须遵守的约束

1. Persona Repository 只管理 persona 数据，不承担策略逻辑；
2. Mapping Store 只管理映射记录，不生成新 persona；
3. 同一会话只维护一个显式 `active_persona`，除非后续接口允许扩展；
4. 不允许出现不可恢复的自由替换记录；
5. 默认使用轻量存储：
   - persona：JSON 文件
   - mapping：in-memory + 可选 JSON 落盘

---

## 建议创建/修改的文件

- `src/privacyguard/infrastructure/persona/json_persona_repository.py`
- `src/privacyguard/infrastructure/mapping/in_memory_mapping_store.py`
- `src/privacyguard/infrastructure/mapping/json_mapping_store.py`
- `src/privacyguard/application/services/session_service.py`
- `data/personas.sample.json`

- `tests/unit/test_json_persona_repository.py`
- `tests/unit/test_in_memory_mapping_store.py`
- `tests/unit/test_session_service.py`

---

## Persona 数据结构要求

建议支持如下结构：

```json
[
  {
    "persona_id": "zhangsan",
    "profile": {
      "name": "张三",
      "phone": "13900001111",
      "address": "上海市浦东新区世纪大道100号",
      "email": "zhangsan@example.com"
    },
    "stats": {
      "exposure_count": 0,
      "last_exposed_session_id": null,
      "last_exposed_turn_id": null
    }
  }
]
```

### 实现要求

- 读取时转换为强类型 `PersonaProfile`
- 槽位访问采用统一 attr_type，不要散落字符串判断
- 对不存在的 persona_id / attr_type 要返回明确结果或异常

---

## Mapping Store 要求

至少支持以下能力：

1. 保存某一轮替换记录
2. 查询某个 session 的全部替换记录
3. 查询某个 session 某一轮的替换记录
4. 保存 / 获取会话绑定 `SessionBinding`
5. 允许按 replacement_text 或 source_text 做恢复查询（如你认为需要）

### in-memory 版本
- 用于默认开发和单元测试
- 生命周期跟随进程

### json 版本
- 用于本地调试持久化
- 结构清晰，不追求高性能

---

## session_service 要求

请单独做一个会话服务，不要把会话状态管理分散到 facade 或 decision 中。

建议方法包括：

- `get_active_persona(session_id)`
- `bind_active_persona(session_id, persona_id, turn_id)`
- `get_or_create_binding(session_id)`
- `append_turn_replacements(session_id, turn_id, records)`

### 原则
- 会话服务是对 repository/store 的薄封装；
- 不做替换决策；
- 不做图像/文本处理；
- 主要负责“会话状态读写的一致入口”。

---

## 最小字段设计建议

### SessionBinding
- `session_id`
- `active_persona_id`
- `created_at`
- `updated_at`
- `last_turn_id`

### ReplacementRecord
至少补足：
- `replacement_id`
- `session_id`
- `turn_id`
- `candidate_id`
- `attr_type`
- `source_text`
- `replacement_text`
- `action_type`
- `persona_id`
- `source`
- `bbox`
- `metadata`

---

## 数据一致性要求

请实现以下防御：

1. `save_replacements` 时校验 `session_id`、`turn_id` 必填；
2. 若 `action_type = PERSONA_SLOT`，则 `persona_id` 不可为空；
3. 若 `action_type = KEEP`，可以选择不写入映射，或写入标记记录，但全项目要统一；
4. 同一 `session_id + turn_id + candidate_id` 不应重复插入多条冲突记录；
5. 写入 JSON 时注意原子性，避免写坏文件。

---

## 测试要求

至少覆盖：

### Persona Repository
- 能加载样例 persona 文件
- 能正确读取指定 persona 槽位
- 不存在的 persona / attr_type 处理合理

### Mapping Store
- 可保存并读回替换记录
- 可保存并读回 session binding
- 可按 session / turn 过滤查询

### Session Service
- 能创建绑定
- 能更新 active_persona
- 能追加某轮替换记录

---

## 禁止事项

- 不要在 repository 里写硬编码 persona；
- 不要把 mapping 查询逻辑写在测试文件里代替正式实现；
- 不要把 session 状态做成到处共享的全局变量；
- 不要在这一轮引入 Decision 规则判断。

---

## 完成后的自检输出

请说明：

1. persona JSON 的最终格式；
2. mapping store 当前支持哪些查询；
3. `KEEP` 动作是否写入 mapping；
4. 当前会话绑定的生命周期设计是什么。
