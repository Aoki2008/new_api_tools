# 外部审计 Webhook（请求原始数据导出）

本项目支持将 Relay 请求的审计事件通过 **HTTP Webhook** 外置发送到独立审计系统，用于审查与审计。

> 具体落地设计与 NewAPI-Tool 接入方式见：`docs/audit-design.md`

特性与约束：
- **仅外置**：本项目不会将请求体写入数据库用于“查看原文”。
- **异步 fail-open**：投递失败不会阻断主请求，只会记录错误日志。
- **截断预览**：仅导出请求体前 N 字节（可配置），避免超大请求导致审计侧压力过大。
- **跳过 multipart**：`multipart/form-data`（文件上传）请求体不导出（避免二进制文件内容进入审计）。

## 快速开始：外部审计接收端（NewAPI-Tool 内置）

审计接收端已**内置在本项目（NewAPI-Tool）**中：通过 `POST /webhook/newapi` 接收 new-api 投递的审计事件，并在前端 **日志审计** 页面中查看列表与详情。

### 1) 启动 NewAPI-Tool（本项目）

确保 NewAPI-Tool 已部署并可访问（例如 `http://<newapi-tools>:1145`）。

> Webhook 接收地址为：`http://<newapi-tools>:1145/webhook/newapi`

常用环境变量（NewAPI-Tool）：

- `AUDIT_WEBHOOK_SECRET`：Webhook 验签密钥（建议设置；需与 new-api 的 `AuditWebhookSecret` 一致）
- `AUDIT_MAX_BODY_BYTES`：Webhook payload 最大接收大小（默认 `2097152`）
- `AUDIT_MAX_SKEW_SECONDS`：允许的时间戳偏移（默认 `300`）

启用后，可在 NewAPI-Tool 顶部导航进入 **日志审计** 查看事件列表与详情。

### 2) 配置 new-api 发送到 NewAPI-Tool

在 new-api 管理后台：`运营设置 -> 日志设置` 中启用并填写：

- `LogRequestBodyEnabled = true`
- `LogRequestBodyMaxBytes = 8192`（按需调整）
- `AuditWebhookUrl = http://<newapi-tools>:1145/webhook/newapi`
- `AuditWebhookSecret = <同 AUDIT_WEBHOOK_SECRET>`
- `AuditWebhookTimeoutSeconds = 5`

## 配置项（运营设置 -> 日志设置）

- `LogRequestBodyEnabled`：是否启用外部审计导出（默认 `false`）
- `LogRequestBodyMaxBytes`：请求体导出上限（bytes，默认 `8192`，后端硬上限 `1MB`）
- `AuditWebhookUrl`：审计 Webhook 地址（`http/https`）
- `AuditWebhookSecret`：可选，用于签名验签（不会从 `/api/option/` 回显）
- `AuditWebhookTimeoutSeconds`：Webhook 请求超时（秒，默认 `5`，限制 `1~60`）

> 注意：Webhook URL 会按系统的 Fetch/SSRF 设置进行校验；如被拦截，请检查并调整相关允许列表。

## Webhook 协议

### 请求

- Method：`POST`
- Content-Type：`application/json; charset=utf-8`
- Body：`AuditEvent` JSON（见下文）

### Header

- `X-NewAPI-Audit-Timestamp: <unix_seconds>`
- `X-NewAPI-Request-Id: <request_id>`（可选）
- `X-NewAPI-Audit-Signature: sha256=<hex>`（当配置 `AuditWebhookSecret` 时才会携带）

### 签名算法

当配置 `AuditWebhookSecret` 时，签名计算方式为：

`HMAC-SHA256(secret, timestamp + "." + raw_json_payload)`

其中：
- `timestamp` 为 Header `X-NewAPI-Audit-Timestamp` 的字符串值
- `raw_json_payload` 为 HTTP Body 的**原始字节**（即完整 JSON payload bytes）

Go 端验签示例（伪代码）：

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(timestamp))
mac.Write([]byte("."))
mac.Write(payloadBytes)
expected := hex.EncodeToString(mac.Sum(nil))
```

## AuditEvent 字段

```json
{
  "type": "request_audit",
  "timestamp": 1700000000,
  "request_id": "xxx",
  "method": "POST",
  "path": "/v1/chat/completions",
  "status_code": 200,
  "duration_ms": 123,
  "user_id": 1,
  "username": "alice",
  "token_id": 2,
  "token_name": "my-token",
  "group": "default",
  "channel_id": 3,
  "channel_name": "openai-main",
  "channel_type": 1,
  "model": "gpt-4o-mini",
  "content_type": "application/json",
  "request_body": "{...}",
  "request_body_encoding": "utf8",
  "request_body_bytes": 8192,
  "request_body_truncated": true
}
```

字段说明：
- `request_body`：请求体预览（前 N 字节）；如果不是 UTF-8，则会以 base64 编码。
- `request_body_encoding`：`utf8` 或 `base64`
- `request_body_bytes`：预览字节数（截断后实际导出的字节数）
- `request_body_truncated`：是否因超过 `LogRequestBodyMaxBytes` 而被截断

## 可靠性建议（审计系统侧）

- Webhook 为 best-effort 异步投递，建议审计系统侧做落库与告警。
- 建议按 `X-NewAPI-Request-Id` 或 `request_id` 做幂等去重（如需）。
- 建议使用 HTTPS，并配置 `AuditWebhookSecret` 验签。
