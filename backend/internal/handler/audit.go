package handler

import (
	"database/sql"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/new-api-tools/backend/internal/cache"
	"github.com/new-api-tools/backend/internal/config"
	"github.com/new-api-tools/backend/internal/logger"
	"github.com/new-api-tools/backend/internal/models"
	"github.com/new-api-tools/backend/internal/service"
)

// RegisterAuditWebhookRoutes registers webhook receiver endpoints (no auth).
func RegisterAuditWebhookRoutes(r *gin.Engine) {
	r.POST("/webhook/newapi", ReceiveNewAPIAuditWebhook)
}

// RegisterAuditRoutes registers /api/events endpoints (auth required).
func RegisterAuditRoutes(r *gin.RouterGroup) {
	g := r.Group("/events")
	{
		g.GET("", ListAuditEvents)
		g.GET("/:id", GetAuditEvent)
	}

	a := r.Group("/audit")
	{
		a.GET("/config", GetAuditConfig)
		a.PUT("/config", SetAuditConfig)
		a.POST("/cleanup", CleanupAuditEvents)
	}
}

// POST /webhook/newapi
func ReceiveNewAPIAuditWebhook(c *gin.Context) {
	cfg := config.Get()

	// 1) Timestamp header (required)
	tsHeader := strings.TrimSpace(c.GetHeader("X-NewAPI-Audit-Timestamp"))
	if tsHeader == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_TIMESTAMP", "Missing X-NewAPI-Audit-Timestamp header", ""))
		return
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil || ts <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_TIMESTAMP", "Invalid X-NewAPI-Audit-Timestamp header", ""))
		return
	}
	if err := service.ValidateAuditTimestamp(ts); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_TIMESTAMP", "Timestamp out of allowed skew window", err.Error()))
		return
	}

	// 2) Read raw body with size limit
	maxBytes := int64(cfg.AuditMaxBodyBytes)
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
	rawBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, models.ErrorResp("PAYLOAD_TOO_LARGE", "Failed to read request body", err.Error()))
		return
	}
	if len(rawBody) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_BODY", "Empty request body", ""))
		return
	}

	// 3) Verify signature (optional but recommended)
	secret := strings.TrimSpace(cfg.AuditWebhookSecret)
	signatureHeader := c.GetHeader("X-NewAPI-Audit-Signature")
	signatureValid := false
	if secret != "" {
		signatureValid = service.VerifyAuditSignature(secret, tsHeader, rawBody, signatureHeader)
		if !signatureValid {
			logger.L.Warn("审计 webhook 验签失败", logger.CatSecurity)
			c.JSON(http.StatusUnauthorized, models.ErrorResp("INVALID_SIGNATURE", "Invalid audit signature", ""))
			return
		}
	}

	// 4) Parse payload
	payload, err := service.ParseAuditEventPayload(rawBody)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_BODY", "Invalid JSON payload", err.Error()))
		return
	}

	// Header request id is optional; payload has request_id.
	if strings.TrimSpace(payload.RequestID) == "" {
		payload.RequestID = strings.TrimSpace(c.GetHeader("X-NewAPI-Request-Id"))
	}

	// 5) Insert
	if err := service.InsertAuditEvent(payload, signatureValid); err != nil {
		logger.L.Error("审计 webhook 落库失败: "+err.Error(), logger.CatDatabase)
		c.JSON(http.StatusInternalServerError, models.ErrorResp("DB_ERROR", "Failed to store audit event", err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GET /api/events
func ListAuditEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	beforeID, _ := strconv.ParseInt(c.DefaultQuery("before_id", "0"), 10, 64)
	userID, _ := strconv.ParseInt(c.Query("user_id"), 10, 64)
	statusCode, _ := strconv.Atoi(c.Query("status_code"))

	params := service.AuditListParams{
		Limit:      limit,
		BeforeID:   beforeID,
		RequestID:  c.Query("request_id"),
		Path:       c.Query("path"),
		UserID:     userID,
		StatusCode: statusCode,
	}

	result, err := service.ListAuditEvents(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("AUDIT_LIST_FAILED", "Failed to list audit events", err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": result})
}

// GET /api/events/:id
func GetAuditEvent(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	event, err := service.GetAuditEventByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, models.ErrorResp("NOT_FOUND", "Audit event not found", ""))
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResp("AUDIT_GET_FAILED", "Failed to get audit event", err.Error()))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": event})
}

// GET /api/audit/config
func GetAuditConfig(c *gin.Context) {
	days, source := service.GetAuditRetentionDaysWithSource()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"retention_days":        days,
			"retention_days_source": source,
		},
	})
}

// PUT /api/audit/config
func SetAuditConfig(c *gin.Context) {
	var req struct {
		RetentionDays int64 `json:"retention_days" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_PARAMS", "Invalid request body", err.Error()))
		return
	}

	if req.RetentionDays < 0 || req.RetentionDays > 3650 {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_PARAMS", "retention_days out of range (0~3650)", ""))
		return
	}

	if !cache.Available() {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResp("CACHE_UNAVAILABLE", "Redis is not available, cannot persist runtime config", ""))
		return
	}

	cm := cache.Get()
	if err := cm.HashSet("app:config", "audit_retention_days", req.RetentionDays); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("STORAGE_ERROR", "Failed to save audit config", err.Error()))
		return
	}

	days, source := service.GetAuditRetentionDaysWithSource()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Audit config saved",
		"data": gin.H{
			"retention_days":        days,
			"retention_days_source": source,
		},
	})
}

// POST /api/audit/cleanup
func CleanupAuditEvents(c *gin.Context) {
	days, source := service.GetAuditRetentionDaysWithSource()
	if days <= 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"deleted":               0,
				"retention_days":        days,
				"retention_days_source": source,
				"message":               "Cleanup disabled (retention_days<=0)",
			},
		})
		return
	}

	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	deleted, err := service.DeleteAuditEventsBefore(cutoff, 5000, 200)
	if err != nil {
		logger.L.TaskError("审计日志清理失败: " + err.Error())
		c.JSON(http.StatusInternalServerError, models.ErrorResp("AUDIT_CLEANUP_FAILED", "Failed to cleanup audit events", err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"deleted":               deleted,
			"cutoff_received_at":    cutoff,
			"retention_days":        days,
			"retention_days_source": source,
		},
	})
}
