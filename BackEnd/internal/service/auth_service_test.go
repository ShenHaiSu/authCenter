package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// authEnv 认证测试环境：独立 SQLite + AuthService + 一个项目/密钥。
type authEnv struct {
	svc      *AuthService
	st       *store.Store
	proj     model.Project
	key      model.APIKey
	keyValue string // 密钥明文（测试内可用，勿写审计/日志）
}

// newAuthTestEnv 构造认证测试环境（08 §2 service/auth）：
// 默认创建启用项目 svc-test（current_version=1.2.3）与启用密钥；
// setSettings 可在创建 AuthService 前覆盖 settings（require_fingerprint / rate_limit 等）。
func newAuthTestEnv(t *testing.T, setSettings func(context.Context, *store.Store)) *authEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	ctx := context.Background()
	if err := st.SetSetting(ctx, model.SettingJWTSecret, "test-secret-0123456789abcdef"); err != nil {
		t.Fatalf("写入 jwt_secret 失败: %v", err)
	}
	if setSettings != nil {
		setSettings(ctx, st)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	audit := NewAuditService(st, logger)
	tokenSvc, err := NewTokenService(ctx, st)
	if err != nil {
		t.Fatalf("NewTokenService 失败: %v", err)
	}
	svc := NewAuthService(ctx, st, audit, tokenSvc, logger)

	now := timeNowUTC()
	p := &model.Project{Name: "svc-test", CurrentVersion: "1.2.3", IsActive: true, CreatedAt: now, UpdatedAt: now}
	pid, err := st.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	p.ID = pid
	plain, err := RandomString(KeyValueLen)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	k := &model.APIKey{ProjectID: pid, Name: "k1", KeyValue: plain, IsActive: true, CreatedAt: now}
	kid, err := st.CreateKey(ctx, k)
	if err != nil {
		t.Fatalf("创建密钥失败: %v", err)
	}
	k.ID = kid
	return &authEnv{svc: svc, st: st, proj: *p, key: *k, keyValue: plain}
}

// req 便捷构造认证请求。
func (e *authEnv) req(version, fingerprint, key string) AuthenticateRequest {
	return AuthenticateRequest{ProjectName: "svc-test", Version: version, Fingerprint: fingerprint, Key: key}
}

// updateKey 按修改后的字段全量更新密钥（UpdateKey 为全量语义）。
func (e *authEnv) updateKey(t *testing.T, k *model.APIKey) {
	t.Helper()
	ctx := context.Background()
	if err := e.st.UpdateKey(ctx, k); err != nil {
		t.Fatalf("更新密钥失败: %v", err)
	}
}

// ================= 校验链各分支（文档 08 §2 service/auth） =================

// TestAuthenticateSuccess 校验链全通过：authenticated=true + 项目信息（08 §2 成功分支）。
func TestAuthenticateSuccess(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	res, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	if !res.Authenticated {
		t.Error("应认证成功")
	}
	if res.ProjectName != "svc-test" || res.CurrentVersion != "1.2.3" {
		t.Errorf("项目信息不正确: %+v", res)
	}
	if res.Token != "" {
		t.Error("默认不应签发 token")
	}
}

// TestAuthenticateProjectNotFound 项目不存在 → project_not_found（10001）。
func TestAuthenticateProjectNotFound(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	req := e.req("1.2.3", "fp-1", e.keyValue)
	req.ProjectName = "no-such-project"
	_, err := e.svc.Authenticate(context.Background(), req, "127.0.0.1")
	if !errors.Is(err, ErrProjectNotFound) {
		t.Errorf("期望 ErrProjectNotFound, 实际 %v", err)
	}
}

// TestAuthenticateProjectDisabled 项目停用 → project_disabled（10002）。
func TestAuthenticateProjectDisabled(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	ctx := context.Background()
	upd := e.proj
	upd.IsActive = false
	if err := e.st.UpdateProject(ctx, &upd); err != nil {
		t.Fatalf("停用项目失败: %v", err)
	}
	_, err := e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrProjectDisabled) {
		t.Errorf("期望 ErrProjectDisabled, 实际 %v", err)
	}
}

// TestAuthenticateVersionTooOld 版本低于 min_version → version_too_old（10003）。
func TestAuthenticateVersionTooOld(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	ctx := context.Background()
	upd := e.proj
	minV := "2.0.0"
	upd.MinVersion = &minV
	if err := e.st.UpdateProject(ctx, &upd); err != nil {
		t.Fatalf("设置 min_version 失败: %v", err)
	}
	_, err := e.svc.Authenticate(ctx, e.req("1.9.9", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrVersionTooOld) {
		t.Errorf("期望 ErrVersionTooOld, 实际 %v", err)
	}
}

// TestAuthenticateVersionOK 版本达到 min_version 通过（缺省段补 0：1.2 >= 1.2.0）。
func TestAuthenticateVersionOK(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	ctx := context.Background()
	upd := e.proj
	minV := "1.2.0"
	upd.MinVersion = &minV
	if err := e.st.UpdateProject(ctx, &upd); err != nil {
		t.Fatalf("设置 min_version 失败: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, e.req("1.2", "fp-1", e.keyValue), "127.0.0.1"); err != nil {
		t.Errorf("1.2 应不低于 1.2.0: %v", err)
	}
}

// TestAuthenticateKeyNotFound 密钥值不存在 → key_not_found（10004）。
func TestAuthenticateKeyNotFound(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", "WRONG-KEY-VALUE-00000000000000000000000000"), "127.0.0.1")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("期望 ErrKeyNotFound, 实际 %v", err)
	}
}

// TestAuthenticateKeyMismatch 密钥属于其他项目 → 对外按 key_not_found（不泄露归属）。
func TestAuthenticateKeyMismatch(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	ctx := context.Background()
	// 另一个项目 + 密钥。
	p2 := &model.Project{Name: "svc-other", IsActive: true, CreatedAt: timeNowUTC(), UpdatedAt: timeNowUTC()}
	pid2, err := e.st.CreateProject(ctx, p2)
	if err != nil {
		t.Fatalf("创建第二个项目失败: %v", err)
	}
	plain2, _ := RandomString(KeyValueLen)
	k2 := &model.APIKey{ProjectID: pid2, Name: "k2", KeyValue: plain2, IsActive: true, CreatedAt: timeNowUTC()}
	if _, err := e.st.CreateKey(ctx, k2); err != nil {
		t.Fatalf("创建第二个密钥失败: %v", err)
	}
	// 用 svc-test 的项目名 + 其他项目的密钥。
	_, err = e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", plain2), "127.0.0.1")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("期望 ErrKeyNotFound（key_mismatch 对外不区分）, 实际 %v", err)
	}
}

// TestAuthenticateKeyDisabled 密钥停用 → key_disabled（10005）。
func TestAuthenticateKeyDisabled(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	upd := e.key
	upd.IsActive = false
	e.updateKey(t, &upd)
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrKeyDisabled) {
		t.Errorf("期望 ErrKeyDisabled, 实际 %v", err)
	}
}

// TestAuthenticateKeyExpired 密钥过期（expires_at 在过去）→ key_expired（10006）。
func TestAuthenticateKeyExpired(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	expired := timeNowUTC().Add(-time.Hour)
	upd := e.key
	upd.ExpiresAt = &expired
	e.updateKey(t, &upd)
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrKeyExpired) {
		t.Errorf("期望 ErrKeyExpired, 实际 %v", err)
	}
}

// TestAuthenticateKeyNotExpiredAtBoundary 恰好等于 expires_at 时刻视为已过期
// （文档 08 §2：边界：恰好在 expires_at 时刻）。
func TestAuthenticateKeyNotExpiredAtBoundary(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	boundary := timeNowUTC()
	upd := e.key
	upd.ExpiresAt = &boundary
	e.updateKey(t, &upd)
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrKeyExpired) {
		t.Errorf("expires_at 等于当前时刻应视为已过期（!After）, 实际 %v", err)
	}
}

// TestAuthenticateFingerprintMismatch 绑定指纹但提交不符 → fingerprint_mismatch（10007）。
func TestAuthenticateFingerprintMismatch(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	fp := "fingerprint-A"
	upd := e.key
	upd.Fingerprint = &fp
	e.updateKey(t, &upd)
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fingerprint-B", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("期望 ErrFingerprintMismatch, 实际 %v", err)
	}
}

// TestAuthenticateNoFingerprintPasses 未绑定指纹 → 任意指纹可认证（默认 require_fingerprint=0）。
func TestAuthenticateNoFingerprintPasses(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	res, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "any-fp", e.keyValue), "127.0.0.1")
	if err != nil || !res.Authenticated {
		t.Errorf("未绑定指纹应通过: err=%v res=%+v", err, res)
	}
}

// TestAuthenticateFingerprintRequired require_fingerprint=1 且密钥未绑定 → fingerprint_required（10008）。
func TestAuthenticateFingerprintRequired(t *testing.T) {
	e := newAuthTestEnv(t, func(ctx context.Context, st *store.Store) {
		if err := st.SetSetting(ctx, model.SettingRequireFp, "1"); err != nil {
			t.Fatalf("设置 require_fingerprint 失败: %v", err)
		}
	})
	_, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1")
	if !errors.Is(err, ErrFingerprintRequired) {
		t.Errorf("期望 ErrFingerprintRequired, 实际 %v", err)
	}
	// 绑定指纹后可认证。
	fp := "fp-1"
	upd := e.key
	upd.Fingerprint = &fp
	e.updateKey(t, &upd)
	if _, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1"); err != nil {
		t.Errorf("绑定匹配指纹应通过: %v", err)
	}
}

// TestAuthenticateRateLimited 限流：rate_limit_auth_per_min=2 时第 3 次被拒（10009）。
func TestAuthenticateRateLimited(t *testing.T) {
	e := newAuthTestEnv(t, func(ctx context.Context, st *store.Store) {
		if err := st.SetSetting(ctx, model.SettingRateLimitAuthPerMin, "2"); err != nil {
			t.Fatalf("设置限流失败: %v", err)
		}
	})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", e.keyValue), "10.0.0.1"); err != nil {
			t.Fatalf("第 %d 次应通过限流: %v", i+1, err)
		}
	}
	if _, err := e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", e.keyValue), "10.0.0.1"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("第 3 次应触发限流, 实际 %v", err)
	}
}

// TestAuthenticateIssueToken issue_token=true 时返回可校验的 JWT（决策 D1 / F-013）。
func TestAuthenticateIssueToken(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	req := e.req("1.2.3", "fp-1", e.keyValue)
	req.IssueToken = true
	res, err := e.svc.Authenticate(context.Background(), req, "127.0.0.1")
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	if res.Token == "" || res.TokenExpiresAt == nil {
		t.Fatal("issue_token=true 应返回 token 与过期时间")
	}
	// 本地校验（文档 04 §3.3：客户端自持 secret 校验）。
	tokenSvc, err := NewTokenService(context.Background(), e.st)
	if err != nil {
		t.Fatalf("NewTokenService 失败: %v", err)
	}
	claims, err := tokenSvc.Verify(res.Token)
	if err != nil {
		t.Fatalf("校验返回的 token 失败: %v", err)
	}
	if claims.Subject != "project:svc-test" || claims.Ver != "1.2.3" || claims.PID != e.proj.ID || claims.KID != e.key.ID {
		t.Errorf("token claims 不正确: %+v", claims)
	}
}

// TestAuthenticateAudit 成功写 auth.authenticate；失败写 auth.authenticate_failed（D2/08 §3 审计）。
func TestAuthenticateAudit(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	ctx := context.Background()

	if _, err := e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", e.keyValue), "127.0.0.1"); err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, e.req("1.2.3", "fp-1", "BAD-KEY"), "127.0.0.2"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("期望失败: %v", err)
	}

	var okCount, failCount int
	if err := e.st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, model.EventAuthAuthenticate).Scan(&okCount); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, model.EventAuthAuthenticateFailed).Scan(&failCount); err != nil {
		t.Fatal(err)
	}
	if okCount < 1 || failCount < 1 {
		t.Errorf("审计事件缺失: auth.authenticate=%d auth.authenticate_failed=%d", okCount, failCount)
	}
	// 脱敏红线：审计 detail 不应含密钥明文（06 §6）。
	var details []string
	rows, err := e.st.DB().Query(`SELECT detail FROM audit_log WHERE event_type LIKE 'auth.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		details = append(details, d)
	}
	for _, d := range details {
		if d != "" && strings.Contains(d, e.keyValue) {
			t.Error("审计 detail 泄露密钥明文（脱敏红线）")
		}
	}
	// 失败审计 detail 应含 reason。
	var failDetail string
	if err := e.st.DB().QueryRow(`SELECT detail FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`,
		model.EventAuthAuthenticateFailed).Scan(&failDetail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(failDetail, "key_not_found") {
		t.Errorf("失败审计 detail 应含 reason=key_not_found: %s", failDetail)
	}
}

// TestAuthenticateLastUsed 认证成功后更新 last_used_at / last_used_ip。
func TestAuthenticateLastUsed(t *testing.T) {
	e := newAuthTestEnv(t, nil)
	if _, err := e.svc.Authenticate(context.Background(), e.req("1.2.3", "fp-1", e.keyValue), "203.0.113.7"); err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	key, err := e.st.GetKeyByID(context.Background(), e.key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if key.LastUsedAt == nil {
		t.Error("认证后 last_used_at 应已更新")
	}
	if key.LastUsedIP != "203.0.113.7" {
		t.Errorf("last_used_ip = %q, 期望 203.0.113.7", key.LastUsedIP)
	}
}
