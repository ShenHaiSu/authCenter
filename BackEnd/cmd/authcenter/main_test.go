package main

import (
	"context"
	"encoding/base64"
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

// ================= F-021 启动自检（need01 03 §4.7 / §7.2） =================

// testMasterKeyB64 32 字节主密钥的 base64（测试固定值，非生产密钥）。
func testMasterKeyB64(seed byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// newKeyEncEnv 构造「已迁移的库 + store + 指定主密钥」的自检环境。
func newKeyEncEnv(t *testing.T, masterB64 string) (*store.Store, service.Cipher, *slog.Logger) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	c, err := service.NewCipherFromEnv(masterB64)
	if err != nil {
		t.Fatalf("装配 Cipher 失败: %v", err)
	}
	return st, c, slog.New(slog.NewTextHandler(io.Discard, nil))
}

// countAuditEvent 统计审计事件条数。
func countAuditEvent(t *testing.T, st *store.Store, event string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, event).Scan(&n); err != nil {
		t.Fatalf("统计审计失败: %v", err)
	}
	return n
}

// TestStartupFailsWithoutMasterKeyWhenEnabled key_encryption_enabled=1 + 无 env → 启动失败
// （绝不静默明文运行）+ 写 system.key_encryption_verify_failed。
func TestStartupFailsWithoutMasterKeyWhenEnabled(t *testing.T) {
	ctx := context.Background()
	st, c, logger := newKeyEncEnv(t, "")
	if err := st.SetSetting(ctx, model.SettingKeyEncryptionEnabled, "1"); err != nil {
		t.Fatal(err)
	}
	err := ensureKeyEncryptionReady(ctx, st, c, logger)
	if err == nil {
		t.Fatal("已启用加密但无主密钥应启动失败")
	}
	if countAuditEvent(t, st, model.EventSystemKeyEncryptionVerifyFailed) == 0 {
		t.Error("应写 system.key_encryption_verify_failed 审计")
	}
}

// insertEncryptedKey 造一条密文模式密钥行（模拟已启用加密的库）。
func insertEncryptedKey(t *testing.T, st *store.Store, ct, hash string) {
	t.Helper()
	if _, err := st.DB().Exec(
		`INSERT INTO project (name, description, current_version, is_active, created_at, updated_at)
		 VALUES ('p-enc', '', '1.0.0', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(
		`INSERT INTO api_key (project_id, name, key_value, key_value_enc, key_hash, is_active, created_at)
		 VALUES (1, 'k', ?, 1, ?, 1, '2026-01-01T00:00:00Z')`, ct, hash); err != nil {
		t.Fatal(err)
	}
}

// TestStartupFailsWithWrongMasterKey 库中已有密文 + env 错主密钥 → 启动失败 + 审计
// （fail-fast：绝不带病启动后认证全断）。
func TestStartupFailsWithWrongMasterKey(t *testing.T) {
	ctx := context.Background()
	st, right, logger := newKeyEncEnv(t, testMasterKeyB64(0x10))
	// 正确主密钥首启：写入自检密文；再造一条密文行。
	if err := ensureKeyEncryptionReady(ctx, st, right, logger); err != nil {
		t.Fatalf("正确主密钥应通过自检: %v", err)
	}
	if v, _ := st.GetSetting(ctx, model.SettingKeyEncryptionCheck); v == "" {
		t.Fatal("首启应写入自检密文")
	}
	insertEncryptedKey(t, st, "BASE64CIPHERTEXT", "somehash")

	// 错误主密钥重启 → 失败。
	wrong, err := service.NewCipherFromEnv(testMasterKeyB64(0x80))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureKeyEncryptionReady(ctx, st, wrong, logger); err == nil {
		t.Fatal("错误主密钥应启动失败（fail-fast）")
	}
	if countAuditEvent(t, st, model.EventSystemKeyEncryptionVerifyFailed) == 0 {
		t.Error("应写 system.key_encryption_verify_failed 审计")
	}
	// 审计与错误信息都不得包含主密钥内容。
	rows, err := st.DB().Query(`SELECT detail FROM audit_log WHERE event_type = ?`,
		model.EventSystemKeyEncryptionVerifyFailed)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, testMasterKeyB64(0x10)) || strings.Contains(detail, testMasterKeyB64(0x80)) {
			t.Errorf("审计不得包含主密钥: %s", detail)
		}
	}
	// 正确主密钥仍可启动（幂等）。
	if err := ensureKeyEncryptionReady(ctx, st, right, logger); err != nil {
		t.Errorf("正确主密钥应始终通过自检: %v", err)
	}
}

// TestStartupSelfHealsCheckBlobWhenNoCiphertext 库中无密文时换主密钥不算错误：
// 自检密文按当前主密钥重写（自愈），服务不被锁死。
func TestStartupSelfHealsCheckBlobWhenNoCiphertext(t *testing.T) {
	ctx := context.Background()
	st, first, logger := newKeyEncEnv(t, testMasterKeyB64(0x30))
	if err := ensureKeyEncryptionReady(ctx, st, first, logger); err != nil {
		t.Fatal(err)
	}
	blob1, _ := st.GetSetting(ctx, model.SettingKeyEncryptionCheck)
	if blob1 == "" {
		t.Fatal("首启应写自检密文")
	}

	// 换主密钥（库中仍无密文）→ 允许启动，且自检密文被重写。
	second, err := service.NewCipherFromEnv(testMasterKeyB64(0x40))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureKeyEncryptionReady(ctx, st, second, logger); err != nil {
		t.Fatalf("无密文时换主密钥应允许启动（自愈）: %v", err)
	}
	blob2, _ := st.GetSetting(ctx, model.SettingKeyEncryptionCheck)
	if blob2 == blob1 {
		t.Error("自检密文应被重写为新主密钥的密文")
	}
	if _, err := second.Open(blob2, "authcenter:key-encryption:self-check:v1"); err != nil {
		t.Errorf("重写后的自检密文应能用新主密钥解开: %v", err)
	}
	// 再次用第二个主密钥启动：一致，无副作用。
	if err := ensureKeyEncryptionReady(ctx, st, second, logger); err != nil {
		t.Errorf("同一主密钥应稳定通过: %v", err)
	}
	// 新主密钥下写入的密文行 + 换回旧主密钥 → fail-fast。
	insertEncryptedKey(t, st, "BASE64CIPHERTEXT2", "somehash2")
	if err := ensureKeyEncryptionReady(ctx, st, first, logger); err == nil {
		t.Error("有密文时换主密钥应启动失败")
	}
}

// TestStartupFailsOnEncryptedRowsWithoutMasterKey 库中有密文行但无主密钥 → 启动失败。
func TestStartupFailsOnEncryptedRowsWithoutMasterKey(t *testing.T) {
	ctx := context.Background()
	st, c, logger := newKeyEncEnv(t, "")
	// 造一条密文行（模拟曾启用过加密的库）。
	insertEncryptedKey(t, st, "BASE64CIPHERTEXT", "somehash")
	if err := ensureKeyEncryptionReady(ctx, st, c, logger); err == nil {
		t.Fatal("库中有密文但无主密钥应启动失败")
	}
	if countAuditEvent(t, st, model.EventSystemKeyEncryptionVerifyFailed) == 0 {
		t.Error("应写 system.key_encryption_verify_failed 审计")
	}
}

// TestStartupInitializesBackfillState 启动自检初始化 key_hash_backfill_state=pending，
// 且已完成过则保持 done（幂等，不重复回填）。
func TestStartupInitializesBackfillState(t *testing.T) {
	ctx := context.Background()
	st, c, logger := newKeyEncEnv(t, testMasterKeyB64(0x20))
	if err := ensureKeyEncryptionReady(ctx, st, c, logger); err != nil {
		t.Fatal(err)
	}
	state, _ := st.GetSetting(ctx, model.SettingKeyHashBackfillState)
	if state != model.BackfillPending {
		t.Errorf("首启应写 pending，实际 %q", state)
	}
	if err := st.SetSetting(ctx, model.SettingKeyHashBackfillState, model.BackfillDone); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeyEncryptionReady(ctx, st, c, logger); err != nil {
		t.Fatal(err)
	}
	if state, _ := st.GetSetting(ctx, model.SettingKeyHashBackfillState); state != model.BackfillDone {
		t.Errorf("已完成过应保持 done，实际 %q", state)
	}
}

// TestStartupPlainModeWithoutMasterKey 未配置主密钥且库无密文 → 允许启动（明文模式）。
func TestStartupPlainModeWithoutMasterKey(t *testing.T) {
	ctx := context.Background()
	st, c, logger := newKeyEncEnv(t, "")
	if err := ensureKeyEncryptionReady(ctx, st, c, logger); err != nil {
		t.Fatalf("未配置主密钥的明文库应允许启动: %v", err)
	}
	if v, _ := st.GetSetting(ctx, model.SettingKeyEncryptionCheck); v != "" {
		t.Error("明文模式不应写入自检密文")
	}
}

// TestNewCipherFromEnvBadLength 主密钥长度非法 → 启动期报错（不静默降级）。
func TestNewCipherFromEnvBadLength(t *testing.T) {
	bad := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := service.NewCipherFromEnv(bad); err == nil {
		t.Error("16 字节主密钥应报错")
	}
}
