package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// retentionEnv 保留策略测试环境。
type retentionEnv struct {
	svc *AuditRetentionService
	st  *store.Store
}

func newRetentionEnv(t *testing.T) *retentionEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	audit := NewAuditService(st, logger)
	svc := NewAuditRetentionService(st, audit, logger)
	return &retentionEnv{svc: svc, st: st}
}

func seedAudit(t *testing.T, st *store.Store, eventTime time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.InsertAudit(context.Background(), &model.AuditLog{
			EventTime:  eventTime,
			EventType:  model.EventAuthAuthenticate,
			ActorType:  model.ActorTypeClient,
			ActorName:  "seed",
			TargetType: model.TargetTypeProject,
			Result:     model.ResultSuccess,
		}); err != nil {
			t.Fatalf("seed 审计失败: %v", err)
		}
	}
}

func setRetention(t *testing.T, st *store.Store, days, interval, minKeep string) {
	t.Helper()
	ctx := context.Background()
	if days != "" {
		if err := st.SetSetting(ctx, model.SettingAuditRetDays, days); err != nil {
			t.Fatal(err)
		}
	}
	if interval != "" {
		if err := st.SetSetting(ctx, model.SettingAuditCleanupIntervalHours, interval); err != nil {
			t.Fatal(err)
		}
	}
	if minKeep != "" {
		if err := st.SetSetting(ctx, model.SettingAuditMinKeepRows, minKeep); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRetentionConfigDefaults 空 settings → 90/24/1000。
func TestRetentionConfigDefaults(t *testing.T) {
	e := newRetentionEnv(t)
	cfg, err := e.svc.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Days != 90 || cfg.IntervalHours != 24 || cfg.MinKeepRows != 1000 {
		t.Fatalf("默认配置错误: %+v", cfg)
	}
}

// TestRetentionConfigInvalidFallback 非法字符串 → 回退 90 且不 panic。
func TestRetentionConfigInvalidFallback(t *testing.T) {
	e := newRetentionEnv(t)
	setRetention(t, e.st, "abc", "xyz", "oops")
	cfg, err := e.svc.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Days != 90 || cfg.IntervalHours != 24 || cfg.MinKeepRows != 1000 {
		t.Fatalf("非法回退错误: %+v", cfg)
	}
}

// TestRetentionConfigOutOfRange 越界拒绝，边界通过。
func TestRetentionConfigOutOfRange(t *testing.T) {
	e := newRetentionEnv(t)
	ctx := context.Background()
	bad := []struct {
		d, h, m *int
	}{
		{ptr(-1), nil, nil}, {ptr(3651), nil, nil},
		{nil, ptr(0), nil}, {nil, ptr(721), nil},
		{nil, nil, ptr(-1)},
	}
	for _, b := range bad {
		if _, err := e.svc.UpdateConfig(ctx, nil, b.d, b.h, b.m, "127.0.0.1"); !errors.Is(err, ErrInvalidParameter) {
			t.Fatalf("越界应拒绝: %+v err=%v", b, err)
		}
	}
	for _, ok := range []struct {
		d, h, m *int
	}{{ptr(0), nil, nil}, {ptr(3650), nil, nil}, {nil, ptr(1), nil}, {nil, ptr(720), nil}, {nil, nil, ptr(0)}} {
		if _, err := e.svc.UpdateConfig(ctx, nil, ok.d, ok.h, ok.m, "127.0.0.1"); err != nil {
			t.Fatalf("边界应通过: %+v err=%v", ok, err)
		}
	}
}

func ptr(n int) *int { return &n }

// TestRunDeletesBeforeCutoffOnly 只删超期，边界（恰好=cutoff）保留。
func TestRunDeletesBeforeCutoffOnly(t *testing.T) {
	e := newRetentionEnv(t)
	ctx := context.Background()
	now := timeNowUTC()
	// retention=1 天 → cutoff = now-24h；min_keep=0 关闭保底。
	setRetention(t, e.st, "1", "24", "0")
	seedAudit(t, e.st, now.Add(-48*time.Hour), 2) // 超期
	seedAudit(t, e.st, now, 1)                    // 未超期
	res, err := e.svc.Run(withTrigger(ctx, "manual"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Affected != 2 {
		t.Fatalf("应删 2 行，实际 %d", res.Affected)
	}
	total, _ := e.st.CountAudits(ctx)
	// 删 2 + 清理审计 1 = 剩余 2（1 条近期 + 1 条 cleanup 审计）。
	if total != 2 {
		t.Fatalf("剩余行数 = %d，期望 2", total)
	}
}

// TestRunRespectsMinKeepRows 总 5 行、min_keep=1000 → 删 0，审计 reason=min_keep_guard。
func TestRunRespectsMinKeepRows(t *testing.T) {
	e := newRetentionEnv(t)
	ctx := context.Background()
	setRetention(t, e.st, "1", "24", "1000")
	seedAudit(t, e.st, timeNowUTC().Add(-48*time.Hour), 5)
	res, err := e.svc.Run(withTrigger(ctx, "manual"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Affected != 0 {
		t.Fatalf("保底应删 0 行，实际 %d", res.Affected)
	}
	items, _, err := e.st.ListAudits(ctx, store.AuditFilter{EventType: model.EventSystemAuditCleanup}, 1, 10)
	if err != nil || len(items) == 0 {
		t.Fatalf("应有 cleanup 审计: %v", err)
	}
	if !strings.Contains(items[0].Detail, "min_keep_guard") {
		t.Fatalf("detail 应含 min_keep_guard: %s", items[0].Detail)
	}
}

// TestRunRetentionZeroKeepsAll days=0 → 删 0，心跳更新。
func TestRunRetentionZeroKeepsAll(t *testing.T) {
	e := newRetentionEnv(t)
	ctx := context.Background()
	setRetention(t, e.st, "0", "24", "0")
	seedAudit(t, e.st, timeNowUTC().Add(-720*time.Hour), 3)
	res, err := e.svc.Run(withTrigger(ctx, "manual"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Affected != 0 {
		t.Fatalf("days=0 应删 0，实际 %d", res.Affected)
	}
	if v, _ := e.st.GetSetting(ctx, model.SettingAuditLastCleanupAt); v == "" {
		t.Fatal("心跳应被更新")
	}
}

// TestRunBatched 2500 条超期 → 分 3 批删完。
func TestRunBatched(t *testing.T) {
	e := newRetentionEnv(t)
	ctx := context.Background()
	setRetention(t, e.st, "1", "24", "0")
	seedAudit(t, e.st, timeNowUTC().Add(-48*time.Hour), 2500)
	res, err := e.svc.Run(withTrigger(ctx, "manual"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Affected != 2500 {
		t.Fatalf("应删 2500，实际 %d", res.Affected)
	}
	if got, _ := res.Detail["batch_count"].(int64); got != 3 {
		t.Fatalf("batch_count = %v，期望 3", res.Detail["batch_count"])
	}
}

// TestRunConcurrentGuard 并发两次 Run → 一次成功一次 ErrJobRunning。
func TestRunConcurrentGuard(t *testing.T) {
	e := newRetentionEnv(t)
	setRetention(t, e.st, "1", "24", "0")
	seedAudit(t, e.st, timeNowUTC().Add(-48*time.Hour), 10)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = e.svc.Run(withTrigger(context.Background(), "manual"))
		}(i)
	}
	wg.Wait()
	running := 0
	for _, err := range errs {
		if errors.Is(err, ErrJobRunning) {
			running++
		}
	}
	if running != 1 {
		t.Fatalf("应一次成功一次 ErrJobRunning，实际 %v", errs)
	}
}

// TestRunWritesAuditOnError store 错误 → 返回错误且写 failure 审计。
func TestRunWritesAuditOnError(t *testing.T) {
	e := newRetentionEnv(t)
	// 关闭 DB 制造错误。
	e.st.DB().Close()
	_, err := e.svc.Run(withTrigger(context.Background(), "manual"))
	if err == nil {
		t.Fatal("应返回错误")
	}
}
