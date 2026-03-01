package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/new-api-tools/backend/internal/cache"
	"github.com/new-api-tools/backend/internal/config"
	"github.com/new-api-tools/backend/internal/database"
)

// AuditEventPayload matches docs/audit-webhook.md AuditEvent.
type AuditEventPayload struct {
	Type                 string `json:"type"`
	Timestamp            int64  `json:"timestamp"`
	RequestID            string `json:"request_id"`
	Method               string `json:"method"`
	Path                 string `json:"path"`
	StatusCode           int    `json:"status_code"`
	DurationMs           int    `json:"duration_ms"`
	UserID               int64  `json:"user_id"`
	Username             string `json:"username"`
	TokenID              int64  `json:"token_id"`
	TokenName            string `json:"token_name"`
	Group                string `json:"group"`
	ChannelID            int64  `json:"channel_id"`
	ChannelName          string `json:"channel_name"`
	ChannelType          int    `json:"channel_type"`
	Model                string `json:"model"`
	ContentType          string `json:"content_type"`
	RequestBody          string `json:"request_body"`
	RequestBodyEncoding  string `json:"request_body_encoding"`
	RequestBodyBytes     int    `json:"request_body_bytes"`
	RequestBodyTruncated bool   `json:"request_body_truncated"`
}

type AuditEventListItem struct {
	ID                   int64  `json:"id" db:"id"`
	ReceivedAt           int64  `json:"received_at" db:"received_at"`
	EventTimestamp       int64  `json:"event_timestamp" db:"event_timestamp"`
	RequestID            string `json:"request_id" db:"request_id"`
	Method               string `json:"method" db:"method"`
	Path                 string `json:"path" db:"path"`
	StatusCode           int    `json:"status_code" db:"status_code"`
	UserID               int64  `json:"user_id" db:"user_id"`
	Username             string `json:"username" db:"username"`
	Model                string `json:"model" db:"model"`
	RequestBodyBytes     int    `json:"request_body_bytes" db:"request_body_bytes"`
	RequestBodyTruncated bool   `json:"request_body_truncated" db:"request_body_truncated"`
}

type AuditEventDetail struct {
	ID                   int64  `json:"id" db:"id"`
	ReceivedAt           int64  `json:"received_at" db:"received_at"`
	EventType            string `json:"type" db:"event_type"`
	EventTimestamp       int64  `json:"timestamp" db:"event_timestamp"`
	RequestID            string `json:"request_id" db:"request_id"`
	Method               string `json:"method" db:"method"`
	Path                 string `json:"path" db:"path"`
	StatusCode           int    `json:"status_code" db:"status_code"`
	DurationMs           int    `json:"duration_ms" db:"duration_ms"`
	UserID               int64  `json:"user_id" db:"user_id"`
	Username             string `json:"username" db:"username"`
	TokenID              int64  `json:"token_id" db:"token_id"`
	TokenName            string `json:"token_name" db:"token_name"`
	GroupName            string `json:"group" db:"group_name"`
	ChannelID            int64  `json:"channel_id" db:"channel_id"`
	ChannelName          string `json:"channel_name" db:"channel_name"`
	ChannelType          int    `json:"channel_type" db:"channel_type"`
	Model                string `json:"model" db:"model"`
	ContentType          string `json:"content_type" db:"content_type"`
	RequestBody          string `json:"request_body" db:"request_body"`
	RequestBodyEncoding  string `json:"request_body_encoding" db:"request_body_encoding"`
	RequestBodyBytes     int    `json:"request_body_bytes" db:"request_body_bytes"`
	RequestBodyTruncated bool   `json:"request_body_truncated" db:"request_body_truncated"`
	SignatureValid       bool   `json:"signature_valid" db:"signature_valid"`
}

type AuditListParams struct {
	Limit      int
	BeforeID   int64
	RequestID  string
	Path       string
	UserID     int64
	StatusCode int
}

type AuditListResult struct {
	Items        []AuditEventListItem `json:"items"`
	NextBeforeID int64                `json:"next_before_id,omitempty"`
}

var auditSchemaOnce sync.Once
var auditSchemaErr error

func ensureAuditSchema() error {
	auditSchemaOnce.Do(func() {
		db := database.Get()
		auditSchemaErr = db.EnsureAuditSchema(false)
	})
	return auditSchemaErr
}

func VerifyAuditSignature(secret string, timestampHeader string, rawBody []byte, signatureHeader string) bool {
	if strings.TrimSpace(secret) == "" {
		return true
	}

	signatureHeader = strings.TrimSpace(signatureHeader)
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	givenHex := strings.TrimPrefix(signatureHeader, "sha256=")
	given, err := hex.DecodeString(givenHex)
	if err != nil || len(given) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestampHeader))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)
	return hmac.Equal(given, expected)
}

func ValidateAuditTimestamp(ts int64) error {
	cfg := config.Get()
	maxSkew := int64(cfg.AuditMaxSkewSeconds)
	if maxSkew <= 0 {
		return nil
	}

	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > maxSkew {
		return fmt.Errorf("timestamp skew too large (diff=%ds, max=%ds)", diff, maxSkew)
	}
	return nil
}

func InsertAuditEvent(payload AuditEventPayload, signatureValid bool) error {
	if err := ensureAuditSchema(); err != nil {
		return err
	}
	db := database.Get()

	receivedAt := time.Now().Unix()

	insertSQL := `INSERT INTO audit_events (
received_at, event_type, event_timestamp, request_id, method, path, status_code, duration_ms,
user_id, username, token_id, token_name, group_name, channel_id, channel_name, channel_type,
model, content_type, request_body, request_body_encoding, request_body_bytes, request_body_truncated, signature_valid
) VALUES (
?, ?, ?, ?, ?, ?, ?, ?,
?, ?, ?, ?, ?, ?, ?, ?,
?, ?, ?, ?, ?, ?, ?
)`
	insertSQL = db.RebindQuery(insertSQL)

	_, err := db.DB.Exec(
		insertSQL,
		receivedAt,
		payload.Type,
		payload.Timestamp,
		payload.RequestID,
		payload.Method,
		payload.Path,
		payload.StatusCode,
		payload.DurationMs,
		payload.UserID,
		payload.Username,
		payload.TokenID,
		payload.TokenName,
		payload.Group,
		payload.ChannelID,
		payload.ChannelName,
		payload.ChannelType,
		payload.Model,
		payload.ContentType,
		payload.RequestBody,
		payload.RequestBodyEncoding,
		payload.RequestBodyBytes,
		payload.RequestBodyTruncated,
		signatureValid,
	)
	if err != nil {
		return fmt.Errorf("insert audit event failed: %w", err)
	}
	return nil
}

func ListAuditEvents(params AuditListParams) (*AuditListResult, error) {
	if err := ensureAuditSchema(); err != nil {
		return nil, err
	}
	db := database.Get()

	limit := params.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	fetchLimit := limit + 1

	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if params.BeforeID > 0 {
		where = append(where, fmt.Sprintf("id < %s", db.Placeholder(argIdx)))
		args = append(args, params.BeforeID)
		argIdx++
	}
	if strings.TrimSpace(params.RequestID) != "" {
		where = append(where, fmt.Sprintf("request_id = %s", db.Placeholder(argIdx)))
		args = append(args, strings.TrimSpace(params.RequestID))
		argIdx++
	}
	if strings.TrimSpace(params.Path) != "" {
		where = append(where, fmt.Sprintf("path LIKE %s", db.Placeholder(argIdx)))
		args = append(args, "%"+strings.TrimSpace(params.Path)+"%")
		argIdx++
	}
	if params.UserID > 0 {
		where = append(where, fmt.Sprintf("user_id = %s", db.Placeholder(argIdx)))
		args = append(args, params.UserID)
		argIdx++
	}
	if params.StatusCode > 0 {
		where = append(where, fmt.Sprintf("status_code = %s", db.Placeholder(argIdx)))
		args = append(args, params.StatusCode)
		argIdx++
	}

	whereSQL := strings.Join(where, " AND ")
	query := fmt.Sprintf(`
SELECT id, received_at, event_timestamp, request_id, method, path, status_code,
       COALESCE(user_id, 0) AS user_id, COALESCE(username, '') AS username,
       COALESCE(model, '') AS model,
       COALESCE(request_body_bytes, 0) AS request_body_bytes,
       request_body_truncated
FROM audit_events
WHERE %s
ORDER BY id DESC
LIMIT %s`, whereSQL, db.Placeholder(argIdx))
	args = append(args, fetchLimit)

	var items []AuditEventListItem
	if err := db.DB.Select(&items, query, args...); err != nil {
		return nil, fmt.Errorf("list audit events failed: %w", err)
	}

	var nextBeforeID int64
	if len(items) > limit {
		items = items[:limit]
		nextBeforeID = items[len(items)-1].ID
	}

	return &AuditListResult{
		Items:        items,
		NextBeforeID: nextBeforeID,
	}, nil
}

func GetAuditEventByID(id int64) (*AuditEventDetail, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid id")
	}

	if err := ensureAuditSchema(); err != nil {
		return nil, err
	}
	db := database.Get()

	query := `SELECT
id, received_at, event_type, event_timestamp, request_id, method, path, status_code, duration_ms,
COALESCE(user_id, 0) AS user_id, COALESCE(username, '') AS username,
COALESCE(token_id, 0) AS token_id, COALESCE(token_name, '') AS token_name,
COALESCE(group_name, '') AS group_name,
COALESCE(channel_id, 0) AS channel_id, COALESCE(channel_name, '') AS channel_name, COALESCE(channel_type, 0) AS channel_type,
COALESCE(model, '') AS model,
COALESCE(content_type, '') AS content_type,
COALESCE(request_body, '') AS request_body,
COALESCE(request_body_encoding, '') AS request_body_encoding,
COALESCE(request_body_bytes, 0) AS request_body_bytes,
request_body_truncated,
signature_valid
FROM audit_events
WHERE id = ?`
	query = db.RebindQuery(query)

	var event AuditEventDetail
	if err := db.DB.Get(&event, query, id); err != nil {
		return nil, err
	}

	return &event, nil
}

func ParseAuditEventPayload(rawBody []byte) (AuditEventPayload, error) {
	var payload AuditEventPayload
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err == nil {
		return payload, nil
	}
	// fallback: allow forward-compatible fields
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return AuditEventPayload{}, err
	}
	return payload, nil
}

const auditRuntimeConfigHashKey = "app:config"
const auditRetentionDaysRuntimeConfigKey = "audit_retention_days"

func parseInt64ConfigValue(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return v, true
	}

	var decoded interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return 0, false
	}
	switch t := decoded.(type) {
	case float64:
		return int64(t), true
	case string:
		v, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

// GetAuditRetentionDaysWithSource returns the effective retention days and its source.
// Source is "runtime" when overridden via /api/audit/config, otherwise "env".
func GetAuditRetentionDaysWithSource() (int64, string) {
	cfg := config.Get()
	days := cfg.AuditRetentionDays
	source := "env"

	cm := cache.Get()
	raw, err := cm.HashGet(auditRuntimeConfigHashKey, auditRetentionDaysRuntimeConfigKey)
	if err != nil {
		return days, source
	}
	if v, ok := parseInt64ConfigValue(raw); ok {
		days = v
		source = "runtime"
	}

	return days, source
}

func GetAuditRetentionDays() int64 {
	days, _ := GetAuditRetentionDaysWithSource()
	return days
}

// CleanupExpiredAuditEvents deletes audit_events older than AUDIT_RETENTION_DAYS (based on received_at).
// If AUDIT_RETENTION_DAYS <= 0, cleanup is disabled.
func CleanupExpiredAuditEvents() (int64, error) {
	days := GetAuditRetentionDays()
	if days <= 0 {
		return 0, nil
	}

	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	return DeleteAuditEventsBefore(cutoff, 5000, 200)
}

// DeleteAuditEventsBefore deletes audit events in batches to reduce long locks.
// cutoffTs is unix seconds in received_at.
func DeleteAuditEventsBefore(cutoffTs int64, batchSize int, maxBatches int) (int64, error) {
	if cutoffTs <= 0 {
		return 0, fmt.Errorf("invalid cutoffTs")
	}

	if err := ensureAuditSchema(); err != nil {
		return 0, err
	}
	db := database.Get()

	if batchSize <= 0 {
		batchSize = 5000
	}
	if batchSize > 50000 {
		batchSize = 50000
	}
	if maxBatches <= 0 {
		maxBatches = 200
	}
	if maxBatches > 2000 {
		maxBatches = 2000
	}

	var total int64
	for i := 0; i < maxBatches; i++ {
		var query string
		if db.IsPG {
			// PostgreSQL doesn't support DELETE ... LIMIT; delete by selecting ids.
			query = `DELETE FROM audit_events WHERE id IN (
  SELECT id FROM audit_events WHERE received_at < ? ORDER BY id LIMIT ?
)`
		} else {
			query = `DELETE FROM audit_events WHERE received_at < ? LIMIT ?`
		}

		query = db.RebindQuery(query)
		res, err := db.DB.Exec(query, cutoffTs, batchSize)
		if err != nil {
			return total, fmt.Errorf("delete audit events failed: %w", err)
		}
		affected, _ := res.RowsAffected()
		total += affected
		if affected < int64(batchSize) {
			break
		}
	}

	return total, nil
}
