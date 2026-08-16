package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// startupResult 记录一次「启动初始化」的结果（08 §3 第一条场景）。
type startupResult struct {
	adminCreated bool
	plain        string
	jwtSecret    string
}

// startupInit 模拟 main.go 的初始化序列（文档 02 §6 第 3/5/6 步）：
// Open → store → EnsureAdmin → ensureJWTSecret。不启动 HTTP 服务。
func startupInit(t *testing.T, dir, envSecret string) startupResult {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	created, plain, err := service.NewAdminService(st, logger, dir).EnsureAdmin(ctx)
	if err != nil {
		t.Fatalf("EnsureAdmin 失败: %v", err)
	}
	if err := ensureJWTSecret(ctx, st, envSecret, logger); err != nil {
		t.Fatalf("ensureJWTSecret 失败: %v", err)
	}
	secret, err := st.GetSetting(ctx, model.SettingJWTSecret)
	if err != nil {
		t.Fatalf("读取 jwt_secret 失败: %v", err)
	}
	return startupResult{adminCreated: created, plain: plain, jwtSecret: secret}
}

// TestStartupInitFirstRun 首次启动：无 admin 时创建（30 位随机密码）、
// JWT secret 生成、auth.log 落盘一次（08 §3「启动初始化」）。
func TestStartupInitFirstRun(t *testing.T) {
	dir := t.TempDir()
	r := startupInit(t, dir, "")

	if !r.adminCreated {
		t.Fatal("首次启动应创建 admin")
	}
	if len(r.plain) != 30 || !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(r.plain) {
		t.Errorf("初始密码不符合 30 位 A-Za-z0-9: %q", r.plain)
	}
	if len(r.jwtSecret) == 0 {
		t.Error("JWT secret 应已生成")
	}
	content, err := os.ReadFile(filepath.Join(dir, service.AuthLogFileName))
	if err != nil {
		t.Fatalf("读取 auth.log 失败: %v", err)
	}
	if !strings.Contains(string(content), r.plain) {
		t.Error("auth.log 应包含初始密码")
	}
}

// TestStartupInitRestartIdempotent 重启：admin 不重建（密码不变）、
// JWT secret 复用、auth.log 不追加（08 §3「启动初始化」+ M1 验收出口）。
func TestStartupInitRestartIdempotent(t *testing.T) {
	dir := t.TempDir()

	r1 := startupInit(t, dir, "")
	r2 := startupInit(t, dir, "")

	if r2.adminCreated {
		t.Error("重启后不应重新创建 admin")
	}
	if r2.plain != "" {
		t.Error("重启后不应返回新密码")
	}
	if r2.jwtSecret != r1.jwtSecret {
		t.Errorf("重启后 JWT secret 应复用（历史令牌可校验）：%q != %q", r2.jwtSecret, r1.jwtSecret)
	}
	// auth.log 中密码恰好出现一次（幂等交付，D3）。
	content, err := os.ReadFile(filepath.Join(dir, service.AuthLogFileName))
	if err != nil {
		t.Fatalf("读取 auth.log 失败: %v", err)
	}
	if strings.Count(string(content), r1.plain) != 1 {
		t.Errorf("auth.log 中密码应恰好出现一次，实际 %d 次", strings.Count(string(content), r1.plain))
	}
}

// TestEnsureJWTSecretEnvOverride env AUTHCENTER_JWT_SECRET 优先于 settings（文档 06 §3.4）。
func TestEnsureJWTSecretEnvOverride(t *testing.T) {
	dir := t.TempDir()
	const envSecret = "my-env-secret-32bytes-0123456789abcdef"

	// 首次启动带 env：secret = env 值且写入 settings。
	r := startupInit(t, dir, envSecret)
	if r.jwtSecret != envSecret {
		t.Errorf("env 覆盖后 secret = %q, 期望 %q", r.jwtSecret, envSecret)
	}

	// 重启后不带 env：应复用 settings 中的 env 值（幂等，不重新生成）。
	r2 := startupInit(t, dir, "")
	if r2.jwtSecret != envSecret {
		t.Errorf("重启后 secret = %q, 期望沿用 env 写入值 %q", r2.jwtSecret, envSecret)
	}
}

// TestEnsureJWTSecretPersistAcrossRestart 无 env 时随机生成并持久化，
// 重启后沿用（文档 02 §6 第 6 步：保证历史令牌仍可校验）。
func TestEnsureJWTSecretPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	r1 := startupInit(t, dir, "")
	r2 := startupInit(t, dir, "")
	if r1.jwtSecret == "" || r1.jwtSecret != r2.jwtSecret {
		t.Errorf("JWT secret 应生成且重启不变: %q -> %q", r1.jwtSecret, r2.jwtSecret)
	}
}
