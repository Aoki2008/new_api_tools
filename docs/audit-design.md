# 审计系统设计（基于 `docs/audit-webhook.md`）

本文档用于把 `docs/audit-webhook.md` 中的“外部审计 Webhook 协议”落地为一套可部署、可查询、可审查的审计系统，并说明如何在 **NewAPI-Tool** 中接入“日志审计”能力。

## 1. 目标与边界

### 目标（What）

- **接收** new-api Relay 侧投递的 `AuditEvent`（HTTP Webhook）。
- **验证**（可选）签名与时间戳偏移，拒绝伪造/重放。
- **落库**保存审计事件元数据 + 请求体“截断预览”（不会保存完整请求体）。
- **查询/审查**：提供列表/详情 UI 与 JSON API（用于集成到 NewAPI-Tool）。
- **可运维**：默认复用 NewAPI-Tool 的数据库（MySQL/PostgreSQL），支持限流/大小限制/日志告警。

### 边界（What not）

- 不做“全量请求体归档”；仅保存 `request_body` 预览（由发送端截断）。
- 不对 multipart/form-data 做原文导出（发送端已跳过）。
- 审计系统不反向控制 new-api 的转发/放行（审计是旁路、fail-open）。

## 2. 角色与数据流

### 组件

1) **new-api（发送端）**
- 在 `运营设置 -> 日志设置` 开启：
  - `LogRequestBodyEnabled = true`
  - `LogRequestBodyMaxBytes = 8192`（示例）
  - `AuditWebhookUrl = http://<newapi-tools>:1145/webhook/newapi`
  - `AuditWebhookSecret = <同 AUDIT_WEBHOOK_SECRET>`
  - `AuditWebhookTimeoutSeconds = 5`
- 异步投递：失败不阻断主请求，只记录错误日志（fail-open）。

2) **NewAPI-Tool（接收端 + 查看端，本仓库）**
- `POST /webhook/newapi`：接收并验证 webhook（可选验签），写入 `audit_events` 表。
- `GET /api/events`、`GET /api/events/{id}`：审计事件查询 API（需 NewAPI-Tool 管理后台登录）。
- 前端：顶部导航 **日志审计**（Tab：`audit`）内置列表/详情页。

### 数据流（简化）

`Client -> new-api -> (async) POST webhook -> newapi-tools -> DB -> UI -> Admin`

## 3. 接口设计（严格对齐协议）

### 3.1 Webhook 接收端

- `POST /webhook/newapi`
- Header：
  - `X-NewAPI-Audit-Timestamp: <unix_seconds>`
  - `X-NewAPI-Request-Id: <request_id>`（可选）
  - `X-NewAPI-Audit-Signature: sha256=<hex>`（当启用 secret 时才会携带）
- Body：`AuditEvent` JSON（字段见 `docs/audit-webhook.md`）

**验签规则：**
- 当 `AUDIT_WEBHOOK_SECRET` 配置时：
  - 取 header 的 `timestamp` 字符串 + `.` + **原始 body bytes**
  - `HMAC-SHA256(secret, timestamp+"."+raw_json_payload)`
  - 与 `X-NewAPI-Audit-Signature` 比较（常量时间比较）
- 必须校验时间偏移：`abs(now - timestamp) <= AUDIT_MAX_SKEW_SECONDS`（默认 300）
- body 大小限制：`AUDIT_MAX_BODY_BYTES`（默认 2MB）

### 3.2 查询 API（给 NewAPI-Tool/自动化）

- `GET /api/events`
  - Query（最小集）：`limit`、`before_id`、`request_id`、`path`、`user_id`、`status_code`
  - 建议扩展（可选）：`method`、`model`、`token_id`、`channel_id`、`from_ts`、`to_ts`
- `GET /api/events/{id}`
  - 返回完整事件（含 `request_body` / `encoding` / `truncated`）

## 4. 数据模型（建议）

表：`audit_events`

- `id`（bigint/serial，主键）
- `created_at`（接收端落库时间，索引）
- `event_timestamp`（事件时间，来自 payload 的 `timestamp`，索引）
- `request_id`（索引）
- `method`、`path`（path 索引）
- `status_code`（索引）
- `duration_ms`
- `user_id`（索引）、`username`
- `token_id`、`token_name`
- `group`
- `channel_id`、`channel_name`、`channel_type`
- `model`
- `content_type`
- `request_body`（TEXT/BLOB，保存“预览”）
- `request_body_encoding`（`utf8`/`base64`）
- `request_body_bytes`、`request_body_truncated`
- `raw_event_json`（JSON/TEXT，可选：用于未来字段扩展与调试）
- `signature_valid`（bool，可选）

索引建议：
- `(id DESC)`（分页）
- `(request_id)`、`(user_id, id DESC)`、`(path, id DESC)`、`(status_code, id DESC)`、`(event_timestamp)`

## 5. 鉴权与安全

### 5.1 访问鉴权（UI/API）

- `POST /webhook/newapi`：不走 NewAPI-Tool 的 JWT 登录（便于 new-api 服务器投递），建议通过 `AUDIT_WEBHOOK_SECRET` 验签保护。
- `GET /api/events*`：走 NewAPI-Tool 管理后台登录（JWT），仅管理员可查看。

### 5.2 数据安全（必须考虑）

`request_body` 可能包含敏感信息（PII、密钥、提示词等）：
- **最小化**：发送端严格截断，接收端不再扩展采集。
- **存储策略**：明确保留期（如 7/14/30 天）+ 定期清理任务。
- **传输安全**：生产建议 HTTPS；配置 `AUDIT_WEBHOOK_SECRET` 验签。
- **访问控制**：审计系统独立鉴权；建议放在内网 + 反代二次鉴权。
- **展示脱敏（可选增强）**：对常见字段（Authorization、api_key、password）做 UI 级遮盖。

## 6. NewAPI-Tool（本仓库）“日志审计”页面设计

### 6.1 集成式（本项目实现）

在 NewAPI-Tool 内实现审计列表/详情页，直接调用本项目提供的 JSON API：

- 顶部过滤：`request_id`、`path`、`user_id`、`status_code`、时间范围
- 列表表格：ID、Time、Method、Path、Status、User、Model、Body bytes、Truncated
- 详情抽屉/弹窗：
  - 元信息分组展示（Request / User / Token / Channel / Model）
  - `request_body`：
    - `utf8`：支持 JSON pretty print
    - `base64`：提供“解码预览/复制原文”
  - 快捷动作：复制 `request_id` / 打开审计原生详情页

**集成要点：**
- Webhook 接收端建议启用 `AUDIT_WEBHOOK_SECRET` 验签，避免伪造/重放。
- 注意 `request_body` 可能包含敏感信息，建议配合 HTTPS、最小化截断与保留期清理策略。

## 7. 部署与运维建议

### NewAPI-Tool 审计环境变量（对齐文档）

- `AUDIT_WEBHOOK_SECRET=...`（建议必配）
- `AUDIT_MAX_BODY_BYTES=2097152`
- `AUDIT_MAX_SKEW_SECONDS=300`
- `AUDIT_RETENTION_DAYS=30`（审计事件保留天数；设置为 `0` 可关闭自动清理）

### 监控/告警（建议）

- 监控：
  - `POST /webhook/newapi` 的 2xx/4xx/5xx 比例
  - DB 写入延迟与失败率
- 告警：
  - 验签失败持续增长（可能被攻击/secret 不一致）
  - webhook 4xx/5xx 持续（new-api 配置错误或审计服务故障）

## 8. 里程碑（建议落地顺序）

1) 部署/升级 NewAPI-Tool，打通 new-api -> webhook -> 落库
2) 在 NewAPI-Tool 中使用“日志审计”入口查看事件（列表/详情/过滤，走 `/api/events`）
3) 加固：验签/时间偏移、保留期清理、脱敏策略、告警
