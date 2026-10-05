package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/authcenter/authcenter/internal/service"
)

// settingsHandlers 系统设置 handlers（need01 01 §5，全部需 RequireAdmin）。
type settingsHandlers struct {
	settings  *service.SettingsService
	retention *service.AuditRetentionService
	runner    *service.MaintenanceRunner
}

// handleGetSettings GET /api/v1/settings：白名单 + 用量（绝不返回 jwt_secret）。
func (h *settingsHandlers) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.settings.LoadConfig(r.Context())
	if err != nil {
		failService(w, err)
		return
	}
	total, oldest, err := h.retention.Usage(r.Context())
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{
		"settings": map[string]any{
			"audit_retention_days":         cfg.Days,
			"audit_cleanup_interval_hours": cfg.IntervalHours,
			"audit_min_keep_rows":          cfg.MinKeepRows,
			"audit_last_cleanup_at":        cfg.LastCleanupAt,
			"audit_last_cleanup_rows":      cfg.LastCleanupRows,
			"schema_version":               h.retention.SchemaVersion(),
		},
		"usage": map[string]any{
			"total_rows":        total,
			"oldest_event_time": oldest,
		},
	})
}

// handleUpdateSettings PUT /api/v1/settings：部分更新。
func (h *settingsHandlers) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RetDays   *int `json:"audit_retention_days"`
		IntervalH *int `json:"audit_cleanup_interval_hours"`
		MinKeep   *int `json:"audit_min_keep_rows"`
	}
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	cfg, err := h.retention.UpdateConfig(r.Context(), currentUser(r), req.RetDays, req.IntervalH, req.MinKeep, clientIP(r))
	if err != nil {
		if errors.Is(err, service.ErrInvalidParameter) {
			fail(w, http.StatusBadRequest, CodeInvalidParam, err.Error())
			return
		}
		failService(w, err)
		return
	}
	ok(w, map[string]any{
		"settings": map[string]any{
			"audit_retention_days":         cfg.Days,
			"audit_cleanup_interval_hours": cfg.IntervalHours,
			"audit_min_keep_rows":          cfg.MinKeepRows,
			"audit_last_cleanup_at":        cfg.LastCleanupAt,
			"audit_last_cleanup_rows":      cfg.LastCleanupRows,
		},
	})
}

// handleCleanupNow POST /api/v1/settings/audit/cleanup-now：手动立即执行一轮。
func (h *settingsHandlers) handleCleanupNow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	var (
		res    service.Result
		cutoff string
		err    error
	)
	if h.runner != nil {
		res, err = h.runner.RunNow(ctx, "audit_cleanup")
		if err == nil {
			if v, ok := res.Detail["cutoff"].(string); ok {
				cutoff = v
			}
		}
	} else {
		var c string
		res, _, c, err = h.retention.RunManual(ctx)
		cutoff = c
	}
	if err != nil {
		if errors.Is(err, service.ErrJobRunning) {
			fail(w, http.StatusConflict, CodeStateConflict, "已有清理在运行，请稍后再试")
			return
		}
		failService(w, err)
		return
	}
	cfg, _ := h.settings.LoadConfig(ctx)
	msg := "ok"
	if cfg.Days == 0 {
		msg = "当前设置为永久保留，未执行删除"
	}
	writeJSON(w, http.StatusOK, response{Code: 0, Message: msg, Data: map[string]any{
		"deleted_rows": res.Affected,
		"duration_ms":  time.Since(start).Milliseconds(),
		"cutoff":       cutoff,
	}})
}

// handleCheckpoint POST /api/v1/settings/audit/checkpoint：PRAGMA wal_checkpoint(TRUNCATE)。
func (h *settingsHandlers) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if err := h.retention.Checkpoint(r.Context()); err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"truncated": true, "wal_bytes": 0})
}
