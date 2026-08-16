package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// newSessionTestEnv 会话测试环境：独立 SQLite + 一个 admin 用户（密码 test-Pass-1234）。
func newSessionTestEnv(t *testing.T) (*SessionService, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	ctx := context.Background()
	const password = "test-Pass-1234"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	if err := st.CreateAdmin(ctx, &model.AdminUser{
		Username: "admin", PasswordHash: hash, CreatedAt: timeNowUTC(),
	}); err != nil {
		t.Fatalf("创建 admin 失败: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewSessionService(st, logger), st, password
}

// assertAuditEventTimeNotZero 断言某事件最新一条审计的 event_time 非零值
// （回归：SessionService.writeAudit 曾漏设 EventTime，导致写入 0001-01-01T00:00:00Z）。
func assertAuditEventTimeNotZero(t *testing.T, st *store.Store, eventType string) {
	t.Helper()
	var raw string
	if err := st.DB().QueryRow(
		`SELECT event_time FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`,
		eventType).Scan(&raw); err != nil {
		t.Fatalf("查询审计 %s 失败: %v", eventType, err)
	}
	if raw == "0001-01-01T00:00:00Z" {
		t.Fatalf("审计 %s 的 event_time 为零值 %q，应为真实时间", eventType, raw)
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("解析审计 %s 时间失败: %v", eventType, err)
	}
	if ts.IsZero() {
		t.Fatalf("审计 %s 的 event_time 解析后仍为零值", eventType)
	}
}

// TestAdminLoginAuditTime 登录成功写的 admin.login 审计时间必须非零；
// 且 target_id 必须等于会话 id（回归：CreateSession 曾不回填 sess.ID，
// 导致审计 target_id 恒为 NULL）。
func TestAdminLoginAuditTime(t *testing.T) {
	svc, st, password := newSessionTestEnv(t)
	ctx := context.Background()

	user, token, err := svc.Login(ctx, "admin", password, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if user == nil {
		t.Fatal("登录返回空用户")
	}
	assertAuditEventTimeNotZero(t, st, model.EventAdminLogin)

	sum := sha256.Sum256([]byte(token))
	sess, err := st.GetSessionByTokenHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("查询会话失败: %v", err)
	}
	var tid sql.NullInt64
	if err := st.DB().QueryRow(
		`SELECT target_id FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`,
		model.EventAdminLogin).Scan(&tid); err != nil {
		t.Fatalf("查询审计 target_id 失败: %v", err)
	}
	if !tid.Valid || tid.Int64 != sess.ID {
		t.Fatalf("admin.login 审计 target_id=%v 应等于会话 id=%d", tid, sess.ID)
	}
}

// TestAdminLoginFailedAuditTime 登录失败写的 admin.login_failed 审计时间必须非零。
func TestAdminLoginFailedAuditTime(t *testing.T) {
	svc, st, _ := newSessionTestEnv(t)
	ctx := context.Background()

	if _, _, err := svc.Login(ctx, "admin", "wrong-pass-1234", "127.0.0.1", "test-agent"); err == nil {
		t.Fatal("错误密码登录应失败")
	}
	assertAuditEventTimeNotZero(t, st, model.EventAdminLoginFailed)
}

// TestAdminLogoutAuditTime 登出写的 admin.logout 审计时间必须非零。
func TestAdminLogoutAuditTime(t *testing.T) {
	svc, st, password := newSessionTestEnv(t)
	ctx := context.Background()

	user, token, err := svc.Login(ctx, "admin", password, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	sess, err := st.GetSessionByTokenHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("查询会话失败: %v", err)
	}
	if err := svc.Logout(ctx, sess, user, "127.0.0.1"); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	assertAuditEventTimeNotZero(t, st, model.EventAdminLogout)
}
