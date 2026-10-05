package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/authcenter/authcenter/internal/store"
)

// ErrJobRunning 任务已在运行（映射 409/20202，need01 01 §5.3 / 05 §3）。
var ErrJobRunning = errors.New("job running")

// ErrStateConflict 状态不允许（映射 409/20202，need01 05 §3）。
var ErrStateConflict = errors.New("state conflict")

// ErrForbidden 无权限（映射 403/20104，need01 05 §3）。
var ErrForbidden = errors.New("forbidden")

// Result 维护任务单轮结果。
type Result struct {
	Affected int64
	Detail   map[string]any
}

// Job 维护任务：可重复执行、可分批、可被手动触发（need01 06 §4）。
type Job interface {
	Name() string
	Interval() time.Duration
	Run(ctx context.Context) (Result, error)
}

// triggerCtxKey 触发来源上下文键（timer / manual，由 Runner 注入）。
type triggerCtxKey struct{}

// TriggerFrom 从上下文读取触发来源，缺省为 timer。
func TriggerFrom(ctx context.Context) string {
	if v, ok := ctx.Value(triggerCtxKey{}).(string); ok && v != "" {
		return v
	}
	return "timer"
}

func withTrigger(ctx context.Context, trigger string) context.Context {
	return context.WithValue(ctx, triggerCtxKey{}, trigger)
}

// MaintenanceRunner 维护任务运行器：单一入口托管 ticker 与互斥。
type MaintenanceRunner struct {
	store  *store.Store
	audit  *AuditService
	logger *slog.Logger

	mu   sync.Mutex
	jobs map[string]Job

	runFlags map[string]*atomic.Bool

	wg     sync.WaitGroup
	stopCh chan struct{}
	once   sync.Once
}

// NewMaintenanceRunner 构造运行器（签名对齐 need01 06 §4装配顺序）。
func NewMaintenanceRunner(st *store.Store, audit *AuditService, logger *slog.Logger) *MaintenanceRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &MaintenanceRunner{
		store:    st,
		audit:    audit,
		logger:   logger,
		jobs:     make(map[string]Job),
		runFlags: make(map[string]*atomic.Bool),
		stopCh:   make(chan struct{}),
	}
}

// Register 注册任务（链式），同名覆盖。
func (r *MaintenanceRunner) Register(j Job) *MaintenanceRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs[j.Name()] = j
	if _, ok := r.runFlags[j.Name()]; !ok {
		r.runFlags[j.Name()] = &atomic.Bool{}
	}
	return r
}

// Start 为每个 Interval>0 的任务起独立计时器，随 ctx 取消停止。
func (r *MaintenanceRunner) Start(ctx context.Context) {
	r.mu.Lock()
	snapshot := make(map[string]Job, len(r.jobs))
	for n, j := range r.jobs {
		snapshot[n] = j
	}
	r.mu.Unlock()
	for name, j := range snapshot {
		interval := j.Interval()
		if interval <= 0 {
			continue
		}
		r.wg.Add(1)
		go r.loop(ctx, name, j, interval)
	}
}

func (r *MaintenanceRunner) loop(ctx context.Context, name string, j Job, interval time.Duration) {
	defer r.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-t.C:
			if err := r.runJob(ctx, name, j, "timer"); err != nil {
				// runJob 内部已记日志；此处不阻断其他任务。
				_ = err
			}
		}
	}
}

func (r *MaintenanceRunner) runJob(ctx context.Context, name string, j Job, trigger string) error {
	flag := r.flagFor(name)
	if !flag.CompareAndSwap(false, true) {
		r.logger.Warn("维护任务跳过：上一轮仍在运行", "job", name, "trigger", trigger)
		return ErrJobRunning
	}
	defer flag.Store(false)
	_, err := j.Run(withTrigger(ctx, trigger))
	if err != nil {
		r.logger.Error("维护任务失败", "job", name, "trigger", trigger, "err", err)
		return err
	}
	return nil
}

func (r *MaintenanceRunner) flagFor(name string) *atomic.Bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.runFlags[name]
	if !ok {
		f = &atomic.Bool{}
		r.runFlags[name] = f
	}
	return f
}

// RunNow 手动触发某任务（跳过心跳检查，互斥仍生效）。
func (r *MaintenanceRunner) RunNow(ctx context.Context, name string) (Result, error) {
	r.mu.Lock()
	j, ok := r.jobs[name]
	r.mu.Unlock()
	if !ok {
		return Result{}, errors.New("unknown job: " + name)
	}
	flag := r.flagFor(name)
	if !flag.CompareAndSwap(false, true) {
		return Result{}, ErrJobRunning
	}
	defer flag.Store(false)
	return j.Run(withTrigger(ctx, "manual"))
}

// Stop 停止所有计时器并等待退出（优雅关闭）。
func (r *MaintenanceRunner) Stop() {
	r.once.Do(func() { close(r.stopCh) })
	r.wg.Wait()
}
