package database

import (
	"fmt"

	"github.com/new-api-tools/backend/internal/logger"
)

// EnsureAuditSchema creates audit_events table and indexes if missing.
// This schema stores external audit webhook payloads from new-api.
func (m *Manager) EnsureAuditSchema(logProgress bool) error {
	const table = "audit_events"

	tableExists, err := m.TableExists(table)
	if err != nil {
		return err
	}

	if !tableExists {
		if logProgress {
			logger.L.System("初始化审计表: audit_events")
		}

		var createSQL string
		if m.IsPG {
			createSQL = `
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  received_at BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  event_timestamp BIGINT NOT NULL,
  request_id TEXT,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INT NOT NULL,
  duration_ms INT NOT NULL,
  user_id BIGINT,
  username TEXT,
  token_id BIGINT,
  token_name TEXT,
  group_name TEXT,
  channel_id BIGINT,
  channel_name TEXT,
  channel_type INT,
  model TEXT,
  content_type TEXT,
  request_body TEXT,
  request_body_encoding TEXT,
  request_body_bytes INT,
  request_body_truncated BOOLEAN NOT NULL DEFAULT false,
  signature_valid BOOLEAN NOT NULL DEFAULT false
);`
		} else {
			createSQL = `
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT NOT NULL AUTO_INCREMENT,
  received_at BIGINT NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  event_timestamp BIGINT NOT NULL,
  request_id VARCHAR(128) NULL,
  method VARCHAR(16) NOT NULL,
  path VARCHAR(512) NOT NULL,
  status_code INT NOT NULL,
  duration_ms INT NOT NULL,
  user_id BIGINT NULL,
  username VARCHAR(255) NULL,
  token_id BIGINT NULL,
  token_name VARCHAR(255) NULL,
  group_name VARCHAR(255) NULL,
  channel_id BIGINT NULL,
  channel_name VARCHAR(255) NULL,
  channel_type INT NULL,
  model VARCHAR(255) NULL,
  content_type VARCHAR(255) NULL,
  request_body MEDIUMTEXT NULL,
  request_body_encoding VARCHAR(16) NULL,
  request_body_bytes INT NULL,
  request_body_truncated TINYINT(1) NOT NULL DEFAULT 0,
  signature_valid TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
		}

		if m.IsPG {
			if err := m.ExecuteDDL(createSQL); err != nil {
				return fmt.Errorf("create audit_events table failed: %w", err)
			}
		} else {
			if _, err := m.Execute(createSQL); err != nil {
				return fmt.Errorf("create audit_events table failed: %w", err)
			}
		}
	}

	indexes := []IndexDef{
		{"idx_audit_events_received_at", table, []string{"received_at"}},
		{"idx_audit_events_request_id", table, []string{"request_id"}},
		{"idx_audit_events_user_id", table, []string{"user_id"}},
		{"idx_audit_events_path", table, []string{"path"}},
		{"idx_audit_events_status_code", table, []string{"status_code"}},
	}

	for _, idx := range indexes {
		exists, err := m.indexExists(idx.Name, table)
		if err != nil {
			continue
		}
		if exists {
			continue
		}

		col := idx.Columns[0]
		var createIndexSQL string
		if m.IsPG {
			createIndexSQL = fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS "%s" ON %s (%s)`, idx.Name, table, col)
			if err := m.ExecuteDDL(createIndexSQL); err != nil {
				if logProgress {
					logger.L.Warn(fmt.Sprintf("创建审计索引失败 %s: %v", idx.Name, err), logger.CatDatabase)
				}
				continue
			}
		} else {
			createIndexSQL = fmt.Sprintf("CREATE INDEX `%s` ON %s (%s)", idx.Name, table, col)
			if _, err := m.Execute(createIndexSQL); err != nil {
				if logProgress {
					logger.L.Warn(fmt.Sprintf("创建审计索引失败 %s: %v", idx.Name, err), logger.CatDatabase)
				}
				continue
			}
		}
	}

	return nil
}
