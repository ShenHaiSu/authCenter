// key_hash_backfill_service.go — F-021 存量密钥 key_hash 分批回填后台任务
// （need01 03 §3.2 / 06 §4、§6）。
//
// 为什么是后台 job 而不是启动路径：回填耗时与密钥条数成正比，放启动路径会拖慢重启
// （06 §4 修订）。启动只做 DDL 与状态自检；本 job 由 MaintenanceRunner 托管，
// Interval=0（不自动周期执行），启动后异步触发一次，也支持 RunNow 重跑。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// 回填批参数（与 F-019 分批思路一致，避免长事务）。
const (
	hashBackfillBatchSize  = 1000
	hashBackfillBatchPause = 2 * time.Millisecond
	maxHashBackfillBatches = 100000
)

// KeyHashBackfillService key_hash 回填任务，实现 service.Job。
type KeyHashBackfillService struct {
	store  *store.Store
	audit  *AuditService
	logger *slog.Logger

	running atomic.Bool
	onDone  atomic.Value // func()
}

// NewKeyHashBackfillService 构造回填任务。
func NewKeyHashBackfillService(st *store.Store, audit *AuditService, logger *slog.Logger) *KeyHashBackfillService {
	if logger == nil {
		logger = slog.Default()
	}
	return &KeyHashBackfillService{store: st, audit: audit, logger: logger}
}

// SetOnDone 注册完成回调（用于失效 ApiKeyService 的回填状态缓存）。
func (s *KeyHashBackfillService) SetOnDone(fn func()) {
	if fn != nil {
		s.onDone.Store(fn)
	}
}

// Name 任务名（日志/审计用）。
func (s *KeyHashBackfillService) Name() string { return "key_hash_backfill" }

// Interval 不自动周期执行（0 = 只允许手动/启动触发一次）。
func (s *KeyHashBackfillService) Interval() time.Duration { return 0 }

// State 读取当前回填状态（settings.key_hash_backfill_state）。
func (s *KeyHashBackfillService) State(ctx context.Context) (string, error) {
	return s.store.GetSetting(ctx, model.SettingKeyHashBackfillState)
}

// Run 执行一轮回填：分批算 SHA-256 并写回 key_hash，完成后写状态键与审计。
// 幂等：条件 key_hash IS NULL 不再命中即结束，重复运行安全。
func (s *KeyHashBackfillService) Run(ctx context.Context) (Result, error) {
	if !s.running.CompareAndSwap(false, true) {
		return Result{}, ErrJobRunning
	}
	defer s.running.Store(false)

	trigger := TriggerFrom(ctx)
	state, err := s.State(ctx)
	if err != nil {
		return Result{}, err
	}
	pending, err := s.store.CountKeysWithoutHash(ctx)
	if err != nil {
		return Result{}, err
	}
	// 已完成且无待回填行：幂等跳过（重启不重复回填）。
	if state == model.BackfillDone && pending == 0 {
		return Result{Affected: 0, Detail: map[string]any{
			"rows": 0, "mode": "backfill_hash", "state": model.BackfillDone, "reason": "already_done",
		}}, nil
	}
	if pending == 0 {
		if err := s.markDone(ctx); err != nil {
			return Result{}, err
		}
		return Result{Affected: 0, Detail: map[string]any{
			"rows": 0, "mode": "backfill_hash", "state": model.BackfillDone, "reason": "nothing_to_do",
		}}, nil
	}

	if err := s.store.SetSetting(ctx, model.SettingKeyHashBackfillState, model.BackfillRunning); err != nil {
		return Result{}, err
	}
	s.invalidate()
	start := time.Now()
	var filled, batches int64
	for i := 0; i < maxHashBackfillBatches; i++ {
		rows, err := s.store.ListKeysWithoutHash(ctx, hashBackfillBatchSize)
		if err != nil {
			s.writeAudit(ctx, trigger, filled, batches, time.Since(start), err, "")
			return Result{Affected: filled}, err
		}
		if len(rows) == 0 {
			break
		}
		for j := range rows {
			// 密文行缺 hash 属数据异常：不回填（会把密文当明文算 hash），停止并告警。
			if rows[j].KeyValueEnc != model.KeyEncPlain {
				err := fmt.Errorf("密钥 id=%d 为密文模式但缺少 key_hash，需人工核查", rows[j].ID)
				s.writeAudit(ctx, trigger, filled, batches, time.Since(start), err, "mixed_mode")
				return Result{Affected: filled}, err
			}
			if err := s.store.UpdateKeyHash(ctx, rows[j].ID, HashKey(rows[j].KeyValue)); err != nil {
				if errors.Is(err, store.ErrConflict) {
					// hash 碰撞：该批停止、写 failure 审计并告警，绝不静默跳过。
					s.writeAudit(ctx, trigger, filled, batches, time.Since(start), err, "hash_conflict")
					return Result{Affected: filled}, err
				}
				s.writeAudit(ctx, trigger, filled, batches, time.Since(start), err, "")
				return Result{Affected: filled}, err
			}
			filled++
		}
		batches++
		if len(rows) < hashBackfillBatchSize {
			break
		}
		select {
		case <-ctx.Done():
			s.writeAudit(ctx, trigger, filled, batches, time.Since(start), ctx.Err(), "canceled")
			return Result{Affected: filled}, ctx.Err()
		case <-time.After(hashBackfillBatchPause):
		}
	}

	if err := s.markDone(ctx); err != nil {
		return Result{Affected: filled}, err
	}
	s.writeAudit(ctx, trigger, filled, batches, time.Since(start), nil, "")
	s.logger.Info("key_hash 回填完成", "rows", filled, "batch_count", batches)
	return Result{Affected: filled, Detail: map[string]any{
		"rows": filled, "batch_count": batches, "mode": "backfill_hash", "state": model.BackfillDone,
	}}, nil
}

// markDone 写回填完成状态与完成时间，并失效认证路径的进程内缓存。
func (s *KeyHashBackfillService) markDone(ctx context.Context) error {
	if err := s.store.SetSetting(ctx, model.SettingKeyHashBackfillState, model.BackfillDone); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, model.SettingKeyHashBackfillDoneAt, database.FormatTime(timeNowUTC())); err != nil {
		return err
	}
	s.invalidate()
	return nil
}

// invalidate 通知 ApiKeyService 丢弃回填状态缓存（状态已变更）。
func (s *KeyHashBackfillService) invalidate() {
	if fn, ok := s.onDone.Load().(func()); ok && fn != nil {
		fn()
	}
}

// writeAudit 写回填审计（system.key_encryption_migrated，mode=backfill_hash）；
// detail 只含行数/批数/原因，绝不含密钥内容（05 §2 脱敏红线）。
func (s *KeyHashBackfillService) writeAudit(ctx context.Context, trigger string, filled, batches int64, dur time.Duration, runErr error, reason string) {
	result := model.ResultSuccess
	detail := fmt.Sprintf(`{"to_encrypted":false,"rows":%d,"mode":"backfill_hash","batch_count":%d,"duration_ms":%d,"trigger":%q`,
		filled, batches, dur.Milliseconds(), trigger)
	if reason != "" {
		detail += fmt.Sprintf(`,"reason":%q`, reason)
	}
	if runErr != nil {
		result = model.ResultFailure
		detail += fmt.Sprintf(`,"error":%q`, runErr.Error())
	}
	detail += `}`
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventSystemKeyEncryptionMigrated, ActorType: model.ActorTypeSystem,
		ActorName: "authcenter", TargetType: model.TargetTypeSystem,
		Result: result, Detail: detail,
		RequestID: requestIDFrom(ctx),
	})
}
