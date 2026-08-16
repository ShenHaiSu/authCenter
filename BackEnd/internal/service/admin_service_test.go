package service

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/store"
)

// newTestEnv 构造临时数据目录 + Store + AdminService（每次测试独立）。
func newTestEnv(t *testing.T) (*AdminService, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewAdminService(st, logger, dir), st, dir
}

// TestEnsureAdminFirstRun 首次运行：创建 admin、返回 30 位密码、auth.log 落盘一次。
func TestEnsureAdminFirstRun(t *testing.T) {
	svc, st, dir := newTestEnv(t)
	created, plain, err := svc.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("EnsureAdmin 出错: %v", err)
	}
	if !created {
		t.Fatal("首次运行应创建 admin")
	}
	if len(plain) != 30 || !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(plain) {
		t.Errorf("初始密码不符合 30 位 A-Za-z0-9: %q", plain)
	}

	// 入库校验：argon2id 哈希可验证（文档 06 §3.1）。
	admin, err := st.GetAdminByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("查询 admin 失败: %v", err)
	}
	if !VerifyPassword(admin.PasswordHash, plain) {
		t.Error("库中哈希应能校验初始密码")
	}

	// auth.log 落盘且内容含密码（D3）。
	content, err := os.ReadFile(filepath.Join(dir, AuthLogFileName))
	if err != nil {
		t.Fatalf("读取 auth.log 失败: %v", err)
	}
	if !strings.Contains(string(content), plain) {
		t.Errorf("auth.log 应包含初始密码明文")
	}
	// 文件权限 0600（POSIX 有效；Windows 依赖用户目录 ACL，文档 06 §8）。
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, AuthLogFileName)); err == nil {
			if perm := fi.Mode().Perm(); perm != fs.FileMode(0o600) {
				t.Errorf("auth.log 权限 = %o, 期望 600", perm)
			}
		}
	}
}

// TestEnsureAdminIdempotent 幂等（文档 08 §7 M1 验收出口）：
// 第二次调用不创建、不返回密码、auth.log 不追加。
func TestEnsureAdminIdempotent(t *testing.T) {
	svc, _, dir := newTestEnv(t)
	ctx := context.Background()

	_, plain1, err := svc.EnsureAdmin(ctx)
	if err != nil {
		t.Fatalf("第一次 EnsureAdmin 出错: %v", err)
	}
	created2, plain2, err := svc.EnsureAdmin(ctx)
	if err != nil {
		t.Fatalf("第二次 EnsureAdmin 出错: %v", err)
	}
	if created2 {
		t.Error("第二次应跳过（幂等）")
	}
	if plain2 != "" {
		t.Errorf("第二次不应返回密码，实际 %q", plain2)
	}

	// auth.log 内容与第一次一致（仅一次交付）。
	content, err := os.ReadFile(filepath.Join(dir, AuthLogFileName))
	if err != nil {
		t.Fatalf("读取 auth.log 失败: %v", err)
	}
	if strings.Count(string(content), plain1) != 1 {
		t.Errorf("auth.log 中密码应恰好出现一次，实际出现 %d 次", strings.Count(string(content), plain1))
	}
}

// TestEnsureAdminRestartKeepsPassword 模拟重启（同一数据目录重新 Open）：
// admin 密码不变（幂等 + settings.jwt_secret 复用）。
func TestEnsureAdminRestartKeepsPassword(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// 第一次“启动”。
	db1, err := database.Open(dir)
	if err != nil {
		t.Fatalf("第一次 Open 失败: %v", err)
	}
	st1 := store.New(db1)
	svc1 := NewAdminService(st1, slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
	_, plain1, err := svc1.EnsureAdmin(ctx)
	if err != nil {
		t.Fatalf("第一次 EnsureAdmin 失败: %v", err)
	}
	db1.Close()

	// 第二次“启动”（重启）。
	db2, err := database.Open(dir)
	if err != nil {
		t.Fatalf("第二次 Open 失败: %v", err)
	}
	defer db2.Close()
	st2 := store.New(db2)
	svc2 := NewAdminService(st2, slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
	created, plain2, err := svc2.EnsureAdmin(ctx)
	if err != nil {
		t.Fatalf("第二次 EnsureAdmin 失败: %v", err)
	}
	if created {
		t.Error("重启后不应重新创建 admin")
	}
	if plain2 != "" {
		t.Error("重启后不应返回新密码")
	}
	admin, err := st2.GetAdminByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("查询 admin 失败: %v", err)
	}
	if !VerifyPassword(admin.PasswordHash, plain1) {
		t.Error("重启后 admin 密码哈希应仍能校验首次密码（密码不变）")
	}
}

// TestEnsureAdminWriteAuthLogSkipWhenExists auth.log 已存在时不覆盖（防止二次交付覆盖）。
func TestEnsureAdminWriteAuthLogSkipWhenExists(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, AuthLogFileName)
	pre := "已有内容，不应被覆盖"
	if err := os.WriteFile(authPath, []byte(pre), 0o600); err != nil {
		t.Fatalf("预置 auth.log 失败: %v", err)
	}

	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer db.Close()
	svc := NewAdminService(store.New(db), slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
	created, _, err := svc.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("EnsureAdmin 失败: %v", err)
	}
	if !created {
		t.Fatal("应创建 admin")
	}
	content, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("读取 auth.log 失败: %v", err)
	}
	if string(content) != pre {
		t.Errorf("auth.log 被覆盖：%q", string(content))
	}
}
