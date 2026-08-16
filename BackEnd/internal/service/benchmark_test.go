package service

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// BenchmarkArgon2Hash 测 argon2id 密码哈希耗时（admin 初始化核心成本，文档 06 §3.1 参数）。
func BenchmarkArgon2Hash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashPassword("benchmark-password-123"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRandomString30 测 30 位随机密码生成耗时（admin 初始化）。
func BenchmarkRandomString30(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := RandomString(30); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditInsert 测单条审计写入耗时（SQLite WAL，system.* 事件写路径）。
func BenchmarkAuditInsert(b *testing.B) {
	dir := b.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	st := store.New(db)
	ctx := context.Background()
	_ = slog.Default() // 预热 slog 路径

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := st.InsertAudit(ctx, &model.AuditLog{
			EventTime:  database.NowUTC(),
			EventType:  model.EventSystemStartup,
			ActorType:  model.ActorTypeSystem,
			ActorName:  "authcenter",
			TargetType: model.TargetTypeSystem,
			Result:     model.ResultSuccess,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnsureAdminExisting 测幂等检查路径（admin 已存在时的开销，每次启动执行）。
func BenchmarkEnsureAdminExisting(b *testing.B) {
	dir := b.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	st := store.New(db)
	svc := NewAdminService(st, slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
	ctx := context.Background()
	if _, _, err := svc.EnsureAdmin(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		created, _, err := svc.EnsureAdmin(ctx)
		if err != nil || created {
			b.Fatalf("幂等检查异常: created=%v err=%v", created, err)
		}
	}
}

// BenchmarkEnsureAdminFirstRun 测首次初始化完整成本（argon2 哈希 + 写库 + auth.log 落盘）。
// 仅在首次启动执行一次；衡量 M1 启动自检的可接受耗时。
// 每次迭代重置 admin 行与 auth.log，保持「首次」语义可重复。
func BenchmarkEnsureAdminFirstRun(b *testing.B) {
	dir := b.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	st := store.New(db)
	svc := NewAdminService(st, slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Exec(`DELETE FROM admin_user`); err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(filepath.Join(dir, AuthLogFileName))
		created, _, err := svc.EnsureAdmin(ctx)
		if err != nil || !created {
			b.Fatalf("首次初始化异常: created=%v err=%v", created, err)
		}
	}
}

// BenchmarkAuthenticateSuccess 测认证主路径（M3 核心：项目/密钥查询 + 审计写入）。
// 单请求 ≈ 2 次索引查询 + 1 次审计写入（WAL fsync）；last_used 60s 窗口内只更新一次。
// 限流阈值调高避免 benchmark 触发（默认 100/min）。
func BenchmarkAuthenticateSuccess(b *testing.B) {
	dir := b.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	st := store.New(db)
	ctx := context.Background()
	if err := st.SetSetting(ctx, model.SettingJWTSecret, "bench-secret-0123456789abcdef"); err != nil {
		b.Fatal(err)
	}
	if err := st.SetSetting(ctx, model.SettingRateLimitAuthPerMin, "1000000"); err != nil {
		b.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	audit := NewAuditService(st, logger)
	tokenSvc, err := NewTokenService(ctx, st)
	if err != nil {
		b.Fatal(err)
	}
	svc := NewAuthService(ctx, st, audit, tokenSvc, logger)

	now := timeNowUTC()
	p := &model.Project{Name: "bench", CurrentVersion: "1.0.0", IsActive: true, CreatedAt: now, UpdatedAt: now}
	pid, err := st.CreateProject(ctx, p)
	if err != nil {
		b.Fatal(err)
	}
	plain, err := RandomString(KeyValueLen)
	if err != nil {
		b.Fatal(err)
	}
	k := &model.APIKey{ProjectID: pid, Name: "k1", KeyValue: plain, IsActive: true, CreatedAt: now}
	if _, err := st.CreateKey(ctx, k); err != nil {
		b.Fatal(err)
	}
	req := AuthenticateRequest{ProjectName: "bench", Version: "1.0.0", Fingerprint: "fp-bench", Key: plain}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Authenticate(ctx, req, "127.0.0.1"); err != nil {
			b.Fatal(err)
		}
	}
}
