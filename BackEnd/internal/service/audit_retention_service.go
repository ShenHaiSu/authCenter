package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// 分批删除常量（need01 01 §4.3：不长时间占写锁）。
const (
	cleanupBatchSize  = 1000
	cleanupBatchPause = 5 * time.Millisecond
	maxCleanupBatches = 1000
)

// AuditRetentionService 审计保留策略后台任务，实现 service.Job（need01 01 §4）。
type AuditRetentionService struct {
	store    *store.Store
	settings *SettingsService
	audit    *AuditService
	logger   *slog.Logger

	interval atomic.Int64 // 纳秒，默认 24h；SyncInterval 后刷新
	running  atomic.Bool  // service 内互斥（Runner 互斥之外再兜底）
}

// NewAuditRetentionService 构造保留策略服务。
func NewAuditRetentionService(st *store.Store, audit *AuditService, logger *slog.Logger) *AuditRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	s := &AuditRetentionService{
		store:    st,
		settings: NewSettingsService(st, audit, logger),
		audit:    audit,
		logger:   logger,
	}
	s.interval.Store(int64(24 * time.Hour))
	return s
}

// Name 任务名（日志/审计用）。
func (s *AuditRetentionService) Name() string { return "audit_cleanup" }

// Interval 定时周期；SyncInterval 后为 settings 配置值。
func (s *AuditRetentionService) Interval() time.Duration {
	return time.Duration(s.interval.Load())
}

// SyncInterval 从 settings 刷新定时周期（main 装配后调用一次，每轮 Run 亦刷新）。
func (s *AuditRetentionService) SyncInterval(ctx context.Context) {
	cfg, err := s.settings.LoadConfig(ctx)
	if err != nil {
		s.logger.Warn("刷新清理间隔失败，保持当前值", "err", err)
		return
	}
	s.interval.Store(int64(time.Duration(cfg.IntervalHours) * time.Hour))
}

// Config 返回当前保留策略。
func (s *AuditRetentionService) Config(ctx context.Context) (RetentionConfig, error) {
	return s.settings.LoadConfig(ctx)
}

// UpdateConfig 校验 + 落 settings + 审计，并刷新 Interval。
func (s *AuditRetentionService) UpdateConfig(ctx context.Context, actor *model.AdminUser, days, intervalHours, minKeep *int, ip string) (RetentionConfig, error) {
	cfg, err := s.settings.UpdateConfig(ctx, actor, days, intervalHours, minKeep, ip)
	if err != nil {
		return cfg, err
	}
	s.interval.Store(int64(time.Duration(cfg.IntervalHours) * time.Hour))
	return cfg, nil
}

// Run 执行一轮清理。trigger 由 MaintenanceRunner 经 context 注入（timer/manual）。
func (s *AuditRetentionService) Run(ctx context.Context) (Result, error) {
	trigger := TriggerFrom(ctx)
	if !s.running.CompareAndSwap(false, true) {
		return Result{}, ErrJobRunning
	}
	defer s.running.Store(false)

	cfg, err := s.settings.LoadConfig(ctx)
	if err != nil {
		s.logger.Error("读取保留策略失败", "err", err)
		s.writeCleanupAudit(ctx, trigger, "", 0, 0, 0, err, "")
		return Result{}, err
	}
	s.interval.Store(int64(time.Duration(cfg.IntervalHours) * time.Hour))
	now := timeNowUTC()

	// 心跳幂等：定时触发且距上次清理不足一个周期 → 跳过；手动强制执行。
	if trigger == "timer" && cfg.LastCleanupAt != "" {
		if last, err := time.Parse(time.RFC3339, cfg.LastCleanupAt); err == nil {
			if now.Sub(last) < time.Duration(cfg.IntervalHours)*time.Hour {
				return Result{Affected: 0, Detail: map[string]any{"reason": "heartbeat_skip"}}, nil
			}
		}
	}

	// 永久保留：只更新心跳，不删数据。
	if cfg.Days == 0 {
		if err := s.markCleanup(ctx, now, 0); err != nil {
			s.logger.Error("更新清理心跳失败", "err", err)
		}
		s.writeCleanupAudit(ctx, trigger, "", 0, 0, 0, nil, "retention_disabled")
		return Result{Affected: 0, Detail: map[string]any{"reason": "retention_disabled"}}, nil
	}

	// 保底行数保护：删除前查一次总数。
	total, err := s.store.CountAudits(ctx)
	if err != nil {
		s.writeCleanupAudit(ctx, trigger, "", 0, 0, 0, err, "")
		return Result{}, err
	}
	if cfg.MinKeepRows > 0 && total <= int64(cfg.MinKeepRows) {
		if err := s.markCleanup(ctx, now, 0); err != nil {
			s.logger.Error("更新清理心跳失败", "err", err)
		}
		s.writeCleanupAudit(ctx, trigger, "", 0, 0, 0, nil, "min_keep_guard")
		return Result{Affected: 0, Detail: map[string]any{"reason": "min_keep_guard"}}, nil
	}
	maxDeletable := total
	if cfg.MinKeepRows > 0 {
		maxDeletable = total - int64(cfg.MinKeepRows)
	}

	cutoff := now.Add(-time.Duration(cfg.Days) * 24 * time.Hour)
	cutoffStr := database.FormatTime(cutoff)
	var deleted, batches int64
	start := time.Now()
	for i := 0; i < maxCleanupBatches; i++ {
		// 保底上限：已删够即停。
		limit := cleanupBatchSize
		if cfg.MinKeepRows > 0 && deleted >= maxDeletable {
			break
		}
		if cfg.MinKeepRows > 0 && deleted+int64(limit) > maxDeletable {
			limit = int(maxDeletable - deleted)
			if limit <= 0 {
				break
			}
		}
		n, err := s.store.DeleteAuditsBefore(ctx, cutoffStr, limit)
		if err != nil {
			s.writeCleanupAudit(ctx, trigger, cutoffStr, deleted, batches, time.Since(start), err, "")
			return Result{Affected: deleted}, err
		}
		deleted += n
		batches++
		if n < int64(limit) {
			break
		}
		select {
		case <-ctx.Done():
			s.writeCleanupAudit(ctx, trigger, cutoffStr, deleted, batches, time.Since(start), ctx.Err(), "")
			return Result{Affected: deleted}, ctx.Err()
		case <-time.After(cleanupBatchPause):
		}
	}
	if deleted >= int64(cleanupBatchSize) && batches >= maxCleanupBatches {
		s.logger.Warn("清理触及单轮上限", "deleted", deleted, "max_batches", maxCleanupBatches)
	}
	_ = s.store.CheckpointTruncate(ctx)
	if err := s.markCleanup(ctx, now, deleted); err != nil {
		s.logger.Error("更新清理心跳失败", "err", err)
	}
	s.writeCleanupAudit(ctx, trigger, cutoffStr, deleted, batches, time.Since(start), nil, "")
	return Result{Affected: deleted, Detail: map[string]any{
		"deleted_rows": deleted,
		"batch_count":  batches,
		"cutoff":       cutoffStr,
		"trigger":      trigger,
	}}, nil
}

// RunManual 手动触发一轮（供 handler 在无 Runner 时使用；有 Runner 时走 RunNow）。
func (s *AuditRetentionService) RunManual(ctx context.Context) (Result, int64, string, error) {
	res, err := s.Run(withTrigger(ctx, "manual"))
	if err != nil {
		return res, 0, "", err
	}
	cfg, _ := s.settings.LoadConfig(ctx)
	cutoff := ""
	if cfg.Days > 0 {
		cutoff = database.FormatTime(timeNowUTC().Add(-time.Duration(cfg.Days) * 24 * time.Hour))
	}
	return res, res.Affected, cutoff, nil
}

// Checkpoint 执行 WAL checkpoint（供管理端手动回收空间）。
func (s *AuditRetentionService) Checkpoint(ctx context.Context) error {
	return s.store.CheckpointTruncate(ctx)
}

// Usage 返回审计用量（总行数 + 最早事件时间，供 GET /settings）。
func (s *AuditRetentionService) Usage(ctx context.Context) (int64, string, error) {
	total, err := s.store.CountAudits(ctx)
	if err != nil {
		return 0, "", err
	}
	oldest, err := s.store.OldestAuditTime(ctx)
	if err != nil {
		return 0, "", err
	}
	return total, oldest, nil
}

// SchemaVersion 返回当前库 schema 版本（供 GET /settings 只读展示）。
func (s *AuditRetentionService) SchemaVersion() int {
	v, err := database.SchemaVersion(s.store.DB())
	if err != nil {
		return 0
	}
	return v
}
func (s *AuditRetentionService) markCleanup(ctx context.Context, now time.Time, deleted int64) error {
	if err := s.store.SetSetting(ctx, model.SettingAuditLastCleanupAt, database.FormatTime(now)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, model.SettingAuditLastCleanupRows, strconv.FormatInt(deleted, 10)); err != nil {
		return err
	}
	return nil
}

func (s *AuditRetentionService) writeCleanupAudit(ctx context.Context, trigger, cutoff string, deleted, batches int64, dur time.Duration, runErr error, reason string) {
	result := model.ResultSuccess
	detail := fmt.Sprintf(`{"deleted_rows":%d,"cutoff":%q,"duration_ms":%d,"batch_count":%d,"trigger":%q`,
		deleted, cutoff, dur.Milliseconds(), batches, trigger)
	if reason != "" {
		detail += fmt.Sprintf(`,"reason":%q`, reason)
	}
	if runErr != nil {
		result = model.ResultFailure
		detail += fmt.Sprintf(`,"error":%q`, runErr.Error())
	}
	detail += `}`
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventSystemAuditCleanup, ActorType: model.ActorTypeSystem,
		ActorName: "authcenter", TargetType: model.TargetTypeAudit,
		Result: result, Detail: detail,
		RequestID: requestIDFrom(ctx),
	})
}
