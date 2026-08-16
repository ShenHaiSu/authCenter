package service

import (
	"context"
	"io"
	"log/slog"
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
