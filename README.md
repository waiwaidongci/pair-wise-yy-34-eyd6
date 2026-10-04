# 工伤事故调查与纠正措施

记录工伤经过、伤害、现场和证人，维护调查、纠正措施、验证与关闭流程。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：事件存储、当前视图（事故/措施投影）、操作号、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、操作号重放、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败、事件溯源与迁移测试。

## 事件溯源模型

- **先追加事件，再整理当前视图**：登记、加措施、状态推进都先向 `incident_events` 追加带 `op_no`（操作号）的事件，再由事件折叠出事故与措施当前视图（`incidents`/`measures`）。事件是唯一事实来源，当前状态不能手改。
- **操作号幂等**：写操作可在请求体 `op_no` 字段或 `X-Op-Id` 请求头携带操作号；同一操作号重放沿用首次结果，不重复落账。操作号张冠李戴（别的事故或别的操作类型）返回冲突；未携带时由服务端生成。
- **状态推进并发**：`transition` 必须带 `expected_version`；两人同时推进同一事故时以先落账者为准，后提交者收到 `409` 及 `current_version`，取到新版本后重新办理。加措施不推进状态版本。
- **失败恢复**：每次写操作在单事务内完成“追加事件+审计+更新投影”，失败整体回滚；重启或视图可疑时从原事件清空重建当前视图（`Repository.restore_views()`），审计链不动，篡改的状态会被事件覆盖回来。
- **旧数据迁移**：检测到旧表（`items`/`records`）时，在启动事务内迁移成事故、措施和状态推进的首版事件；原审计链逐条保留并追加一条 `migrate` 标记，随后删除旧表；迁移失败则整笔回滚、旧数据原样保留。原有查询接口与字段（包括记录上的 `item_id`）照旧可用。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8311
```

默认端口为`8311`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

写接口（登记/加措施/状态推进）支持以请求体 `op_no` 或请求头 `X-Op-Id` 携带操作号实现幂等重放。状态版本冲突返回 `409`，响应体含 `current_version` 供调用方刷新后重新办理。

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
