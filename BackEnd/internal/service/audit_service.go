package service

import (
	"context"
	"log/slog"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// AuditService 审计写入与查询（文档 04 §1 service 层）。
// 其他 service 注入本实例统一写审计；失败仅记日志不阻断业务（脱敏红线，06 §6）。
type AuditService struct {
	store  *store.Store
	logger *slog.Logger
}

// NewAuditService 构造 AuditService。
func NewAuditService(st *store.Store, logger *slog.Logger) *AuditService {
	return &AuditService{store: st, logger: logger}
}

// Write 写入一条审计记录；EventTime 未设置时自动填充当前 UTC。
func (s *AuditService) Write(ctx context.Context, e *model.AuditLog) error {
	if e.EventTime.IsZero() {
		e.EventTime = timeNowUTC()
	}
	return s.store.InsertAudit(ctx, e)
}

// Log 写入审计，失败仅记日志；EventTime 未设置时自动填充当前 UTC。
func (s *AuditService) Log(ctx context.Context, e *model.AuditLog) {
	if e.EventTime.IsZero() {
		e.EventTime = timeNowUTC()
	}
	if err := s.store.InsertAudit(ctx, e); err != nil {
		s.logger.Error("写入审计失败", "err", err, "event_type", e.EventType)
	}
}

// List 分页查询审计（文档 05 §4.4）。
func (s *AuditService) List(ctx context.Context, f store.AuditFilter, page, size int) ([]model.AuditLog, int, error) {
	return s.store.ListAudits(ctx, f, page, size)
}
